"""ALDECI Workday HCM API Router.

Direct pass-through to the Workday Staffing REST API
(`/ccx/api/staffing/v6/{tenant}/...`) for Workers, Positions,
Organizations, and Org Charts.

Endpoints (mounted at ``/api/v1/workday``)
------------------------------------------
GET  /                                                                           — capability summary
GET  /ccx/api/staffing/v6/{tenant}/workers                                       — list workers
GET  /ccx/api/staffing/v6/{tenant}/workers/{wid}                                 — single worker
GET  /ccx/api/staffing/v6/{tenant}/workers/{wid}/historyChange                   — change history
GET  /ccx/api/staffing/v6/{tenant}/positions                                     — list positions
GET  /ccx/api/staffing/v6/{tenant}/organizations                                 — list organizations
GET  /ccx/api/staffing/v6/{tenant}/orgChart/{org_id}                             — org chart node + descendants
GET  /ccx/api/staffing/v6/{tenant}/orgChart/{org_id}/managementChain             — management chain up

When ``WORKDAY_TENANT`` / ``WORKDAY_BASE_URL`` / ``WORKDAY_USERNAME`` /
``WORKDAY_PASSWORD`` are unset, the capability summary reports
``status="unavailable"`` and the lookup endpoints respond with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/workday",
    tags=["workday-hcm"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.workday_engine import get_workday_engine

    return get_workday_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    workday_tenant_present: bool
    workday_base_url_present: bool
    workday_username_present: bool
    workday_password_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "workday_unavailable",
            "message": (
                "WORKDAY_TENANT, WORKDAY_BASE_URL, WORKDAY_USERNAME, and "
                "WORKDAY_PASSWORD environment variables are not configured"
            ),
        },
    )


def _map_workday_error(exc: Exception) -> HTTPException:
    """Translate a WorkdayHTTPError (or unavailable) into an HTTPException."""
    from core.workday_engine import WorkdayHTTPError, WorkdayUnavailable

    if isinstance(exc, WorkdayUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "workday_unavailable", "message": str(exc)},
        )
    if isinstance(exc, WorkdayHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "workday_upstream_error",
                "upstream_status": exc.status_code,
                "message": str(exc),
                "payload": exc.payload,
            },
        )
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="Workday HCM capability summary",
)
def capability_summary() -> CapabilitySummary:
    """Return service identity, exposed endpoints, and configuration status."""
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


# --------------------------------------------------------------- workers


@router.get(
    "/ccx/api/staffing/v6/{tenant}/workers",
    summary="List Workday workers",
)
def list_workers(
    tenant: str,
    limit: Optional[int] = Query(None, ge=1, le=1000, description="Page size"),
    offset: Optional[int] = Query(None, ge=0, description="Page offset"),
    search: Optional[str] = Query(None, description="Free-text search"),
    inactiveAndTerminated: Optional[bool] = Query(
        None, description="Include inactive/terminated workers"
    ),
    supervisoryOrganization: Optional[str] = Query(
        None, description="Filter by supervisory organization reference id"
    ),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_workers(
            tenant,
            limit=limit,
            offset=offset,
            search=search,
            inactiveAndTerminated=inactiveAndTerminated,
            supervisoryOrganization=supervisoryOrganization,
        )
    except Exception as exc:
        raise _map_workday_error(exc) from exc


@router.get(
    "/ccx/api/staffing/v6/{tenant}/workers/{wid}",
    summary="Get a single Workday worker",
)
def get_worker(tenant: str, wid: str) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_worker(tenant, wid)
    except Exception as exc:
        raise _map_workday_error(exc) from exc


@router.get(
    "/ccx/api/staffing/v6/{tenant}/workers/{wid}/historyChange",
    summary="Get a Workday worker change history",
)
def get_worker_history(
    tenant: str,
    wid: str,
    limit: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[int] = Query(None, ge=0),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_worker_history(tenant, wid, limit=limit, offset=offset)
    except Exception as exc:
        raise _map_workday_error(exc) from exc


# --------------------------------------------------------------- positions


@router.get(
    "/ccx/api/staffing/v6/{tenant}/positions",
    summary="List Workday positions",
)
def list_positions(
    tenant: str,
    limit: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[int] = Query(None, ge=0),
    search: Optional[str] = Query(None, description="Free-text search"),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_positions(tenant, limit=limit, offset=offset, search=search)
    except Exception as exc:
        raise _map_workday_error(exc) from exc


# --------------------------------------------------------------- organizations


@router.get(
    "/ccx/api/staffing/v6/{tenant}/organizations",
    summary="List Workday organizations",
)
def list_organizations(
    tenant: str,
    limit: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[int] = Query(None, ge=0),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_organizations(tenant, limit=limit, offset=offset)
    except Exception as exc:
        raise _map_workday_error(exc) from exc


# --------------------------------------------------------------- orgChart


@router.get(
    "/ccx/api/staffing/v6/{tenant}/orgChart/{org_id}",
    summary="Get a Workday org chart node + descendants",
)
def get_org_chart(tenant: str, org_id: str) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_org_chart(tenant, org_id)
    except Exception as exc:
        raise _map_workday_error(exc) from exc


@router.get(
    "/ccx/api/staffing/v6/{tenant}/orgChart/{org_id}/managementChain",
    summary="Get a Workday management chain up from an organization",
)
def get_management_chain(tenant: str, org_id: str) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_management_chain(tenant, org_id)
    except Exception as exc:
        raise _map_workday_error(exc) from exc
