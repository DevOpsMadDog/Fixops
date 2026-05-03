"""Wiz CNAPP/CSPM Router — ALDECI.

Prefix: /api/v1/wiz
Scope:  read:scans (mounted via platform_app)

Routes:
  GET   /                            capability summary
  POST  /graphql                     raw GraphQL passthrough
  GET   /issues                      list issues (filtered)
  GET   /inventory                   list cloud resources / inventory
  GET   /vulnerabilities             list vulnerability findings
  GET   /threats                     list threat-detection signals

Returns 503 on lookup endpoints when WIZ_CLIENT_ID/WIZ_CLIENT_SECRET/
WIZ_API_URL unset. NO MOCKS — engine raises RuntimeError → mapped to 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/wiz", tags=["Wiz CNAPP"])


def _engine():
    from core.wiz_cnapp_engine import get_wiz_cnapp_engine
    return get_wiz_cnapp_engine()


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class GraphQLRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=64 * 1024, description="GraphQL query")
    variables: Optional[Dict[str, Any]] = Field(default=None, description="GraphQL variables")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _handle_engine_call(callable_):
    """Invoke an engine call and translate errors to HTTPException."""
    try:
        return callable_()
    except RuntimeError as exc:
        # NO MOCKS — when env not set
        raise HTTPException(status_code=503, detail=f"wiz unavailable: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(status_code=status, detail=f"wiz error: {exc}") from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(status_code=502, detail=f"wiz transport error: {exc}") from exc


def _split_csv(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Wiz integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# Raw GraphQL
# ---------------------------------------------------------------------------


@router.post("/graphql")
def graphql(req: GraphQLRequest) -> Dict[str, Any]:
    """Raw GraphQL passthrough — POST {query, variables?} → {data, errors?}."""
    eng = _engine()
    payload = _handle_engine_call(lambda: eng.graphql(req.query, req.variables))
    out: Dict[str, Any] = {"data": payload.get("data") or {}}
    if payload.get("errors"):
        out["errors"] = payload["errors"]
    return out


# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------


@router.get("/issues")
def list_issues(
    status: str = Query(default="OPEN", max_length=64),
    severity: Optional[str] = Query(
        default="CRITICAL,HIGH",
        description="Comma-separated list, e.g. CRITICAL,HIGH",
        max_length=256,
    ),
    projectId: Optional[str] = Query(default=None, max_length=256),  # noqa: N803
    first: int = Query(default=50, ge=1, le=500),
    after: Optional[str] = Query(default=None, max_length=2048),
) -> Dict[str, Any]:
    """List Wiz issues, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_issues(
            status=status,
            severity=_split_csv(severity),
            project_id=projectId,
            first=first,
            after=after,
        )
    )


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


@router.get("/inventory")
def list_inventory(
    type: Optional[str] = Query(  # noqa: A002
        default=None,
        description="Comma-separated list, e.g. CONTAINER_IMAGE,VIRTUAL_MACHINE",
        max_length=512,
    ),
    projectId: Optional[str] = Query(default=None, max_length=256),  # noqa: N803
    first: int = Query(default=50, ge=1, le=500),
    after: Optional[str] = Query(default=None, max_length=2048),
) -> Dict[str, Any]:
    """List Wiz cloud-resource inventory, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_inventory(
            types=_split_csv(type),
            project_id=projectId,
            first=first,
            after=after,
        )
    )


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


@router.get("/vulnerabilities")
def list_vulnerabilities(
    severity: Optional[str] = Query(
        default="CRITICAL,HIGH",
        description="Comma-separated list",
        max_length=256,
    ),
    first: int = Query(default=50, ge=1, le=500),
    after: Optional[str] = Query(default=None, max_length=2048),
) -> Dict[str, Any]:
    """List Wiz vulnerability findings, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_vulnerabilities(
            severity=_split_csv(severity),
            first=first,
            after=after,
        )
    )


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------


@router.get("/threats")
def list_threats(
    first: int = Query(default=50, ge=1, le=500),
    after: Optional[str] = Query(default=None, max_length=2048),
) -> Dict[str, Any]:
    """List Wiz threat-detection signals, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_threats(first=first, after=after)
    )
