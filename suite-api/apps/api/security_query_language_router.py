"""Security Query Language (SQL/RQL) API Router — ALDECI GAP-024.

Endpoints under /api/v1/sql:
  POST   /execute          — compile and run a DSL query
  POST   /queries          — save a named query
  GET    /queries          — list saved queries
  GET    /queries/{id}     — get saved query
  DELETE /queries/{id}     — delete saved query
  GET    /history          — execution history
  GET    /schema           — entity/field schema
  GET    /stats            — engine statistics

Auth: api_key_auth dependency on all routes.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sql",
    tags=["security-query-language"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_query_language_engine import SecurityQueryLanguageEngine
        _engine = SecurityQueryLanguageEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ExecuteQueryRequest(BaseModel):
    dsl: str = Field(..., min_length=1, description="RQL/SQL DSL query string")
    org_id: str = Field("default", description="Organisation ID")
    provider: str = Field("sqlite", description="Data provider: sqlite or memory")
    limit: int = Field(1000, ge=1, le=10000, description="Max rows returned")


class SaveQueryRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Query name")
    dsl: str = Field(..., min_length=1, description="RQL/SQL DSL query string")
    org_id: str = Field("default", description="Organisation ID")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/execute", summary="Execute a Security Query Language query")
def execute_query(req: ExecuteQueryRequest) -> Dict[str, Any]:
    """
    Compile and run a DSL query over ALDECI's security data (findings, assets,
    IAM, cloud posture, network flows).

    Example DSL:
        FROM aws.ec2.instance WHERE public = true RETURN asset_id, blast_radius
    """
    eng = _get_engine()
    try:
        result = eng.execute_query(
            org_id=req.org_id,
            dsl=req.dsl,
            provider=req.provider,
        )
        # Trim rows to requested limit
        if "rows" in result and isinstance(result["rows"], list):
            result["rows"] = result["rows"][: req.limit]
            result["row_count"] = len(result["rows"])
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("execute_query failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/queries", status_code=201, summary="Save a named query")
def save_query(req: SaveQueryRequest) -> Dict[str, Any]:
    """Persist a named DSL query for later reuse."""
    eng = _get_engine()
    try:
        return eng.save_query(org_id=req.org_id, name=req.name, dsl=req.dsl)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("save_query failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/queries", summary="List saved queries")
def list_queries(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """Return all saved DSL queries for an org."""
    try:
        return _get_engine().list_queries(org_id=org_id)
    except Exception as exc:
        _logger.exception("list_queries failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/queries/{query_id}", summary="Get a saved query")
def get_query(query_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Retrieve a single saved query by ID."""
    result = _get_engine().get_query(org_id=org_id, query_id=query_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Query '{query_id}' not found")
    return result


@router.delete("/queries/{query_id}", summary="Delete a saved query")
def delete_query(query_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Remove a saved query."""
    deleted = _get_engine().delete_query(org_id=org_id, query_id=query_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Query '{query_id}' not found")
    return {"deleted": True, "query_id": query_id}


@router.get("/history", summary="Execution history")
def list_history(
    org_id: str = Query("default"),
    limit: int = Query(100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """Return recent DSL execution history for the org."""
    try:
        return _get_engine().list_history(org_id=org_id, limit=limit)
    except Exception as exc:
        _logger.exception("list_history failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/schema", summary="Entity and field schema")
def get_schema() -> Dict[str, Any]:
    """Return the full SQL entity/field schema available for querying."""
    try:
        return _get_engine().get_schema()
    except Exception as exc:
        _logger.exception("get_schema failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", summary="Engine statistics")
def get_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregate statistics for the SQL engine (queries run, saved, history depth)."""
    try:
        return _get_engine().stats(org_id=org_id)
    except Exception as exc:
        _logger.exception("get_stats failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
