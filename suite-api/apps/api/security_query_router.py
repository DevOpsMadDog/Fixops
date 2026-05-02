"""Security Query Language Router — ALDECI GAP-024.

Exposes the security_query_language_engine as a REST API.

Prefix: /api/v1/sql
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/sql/compile                compile_query
  POST   /api/v1/sql/execute                execute_query
  POST   /api/v1/sql/save                   save_query
  GET    /api/v1/sql/queries                list_queries
  DELETE /api/v1/sql/queries/{query_id}     delete_query
  GET    /api/v1/sql/schema                 get_schema
  GET    /api/v1/sql/stats                  stats
  GET    /api/v1/sql/history                list_history
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from core.security_query_language_engine import (
    SQLPlanError,
    SQLSyntaxError,
    SQLTypeError,
    get_engine,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sql",
    tags=["Security Query Language"],
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CompileRequest(BaseModel):
    dsl: str = Field(..., description="DSL query text")


class ExecuteRequest(BaseModel):
    dsl: str = Field(..., description="DSL query text")
    org_id: str = Field(..., description="Tenant identifier")
    provider: str = Field(default="memory", description="memory | sqlite")
    query_id: Optional[str] = Field(default=None, description="Optional saved query id")


class SaveRequest(BaseModel):
    org_id: str = Field(..., description="Tenant identifier")
    name: str = Field(..., description="Human-readable saved query name")
    dsl: str = Field(..., description="DSL query text")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_http(exc: Exception) -> HTTPException:
    if isinstance(exc, SQLSyntaxError):
        return HTTPException(status_code=400, detail={"type": "syntax_error", "message": str(exc)})
    if isinstance(exc, SQLTypeError):
        return HTTPException(status_code=422, detail={"type": "type_error", "message": str(exc)})
    if isinstance(exc, SQLPlanError):
        return HTTPException(status_code=422, detail={"type": "plan_error", "message": str(exc)})
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail={"type": "value_error", "message": str(exc)})
    return HTTPException(status_code=500, detail={"type": "internal_error", "message": str(exc)})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/compile", dependencies=[Depends(api_key_auth)])
async def compile_query(payload: CompileRequest) -> Dict[str, Any]:
    """Compile a DSL query into a validated plan without executing it."""
    try:
        compiled = get_engine().compile_query(payload.dsl)
        return {"ok": True, "compiled": compiled.to_dict()}
    except Exception as exc:  # noqa: BLE001
        raise _to_http(exc) from exc


@router.post("/execute", dependencies=[Depends(api_key_auth)])
async def execute_query(payload: ExecuteRequest) -> Dict[str, Any]:
    """Compile + execute a DSL query against the requested provider."""
    try:
        result = get_engine().execute_query(
            org_id=payload.org_id,
            dsl=payload.dsl,
            provider=payload.provider,
            query_id=payload.query_id,
        )
        return {"ok": True, **result}
    except Exception as exc:  # noqa: BLE001
        raise _to_http(exc) from exc


@router.post("/save", dependencies=[Depends(api_key_auth)])
async def save_query(payload: SaveRequest) -> Dict[str, Any]:
    try:
        saved = get_engine().save_query(
            org_id=payload.org_id, name=payload.name, dsl=payload.dsl
        )
        return {"ok": True, "query": saved}
    except Exception as exc:  # noqa: BLE001
        raise _to_http(exc) from exc


@router.get("/queries", dependencies=[Depends(api_key_auth)])
async def list_queries(org_id: str = Query(..., description="Tenant identifier")) -> Dict[str, Any]:
    try:
        queries = get_engine().list_queries(org_id=org_id)
        return {"ok": True, "org_id": org_id, "queries": queries, "count": len(queries)}
    except Exception as exc:  # noqa: BLE001
        raise _to_http(exc) from exc


@router.delete("/queries/{query_id}", dependencies=[Depends(api_key_auth)])
async def delete_query(
    query_id: str,
    org_id: str = Query(..., description="Tenant identifier"),
) -> Dict[str, Any]:
    try:
        ok = get_engine().delete_query(org_id=org_id, query_id=query_id)
        if not ok:
            raise HTTPException(status_code=404, detail={"type": "not_found", "message": "query not found"})
        return {"ok": True, "deleted": query_id}
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _to_http(exc) from exc


@router.get("/schema", dependencies=[Depends(api_key_auth)])
async def get_schema() -> Dict[str, Any]:
    schema = get_engine().get_schema()
    return {
        "ok": True,
        "entity_count": len(schema),
        "entities": sorted(schema.keys()),
        "schema": schema,
    }


@router.get("/stats", dependencies=[Depends(api_key_auth)])
async def get_stats(org_id: str = Query(..., description="Tenant identifier")) -> Dict[str, Any]:
    try:
        return {"ok": True, **get_engine().stats(org_id=org_id)}
    except Exception as exc:  # noqa: BLE001
        raise _to_http(exc) from exc


@router.get("/history", dependencies=[Depends(api_key_auth)])
async def list_history(
    org_id: str = Query(..., description="Tenant identifier"),
    limit: int = Query(default=50, ge=1, le=1000),
) -> Dict[str, Any]:
    try:
        rows = get_engine().list_history(org_id=org_id, limit=limit)
        return {"ok": True, "org_id": org_id, "history": rows, "count": len(rows)}
    except Exception as exc:  # noqa: BLE001
        raise _to_http(exc) from exc
