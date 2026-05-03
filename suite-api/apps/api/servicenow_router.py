"""ALDECI ServiceNow ITSM API Router.

Direct pass-through to the ServiceNow Table API (`/api/now/table/`) for ITSM
core records — distinct from the bidirectional finding-sync layer in
``servicenow_sync_router.py``.

Endpoints (mounted at ``/api/v1/servicenow``)
---------------------------------------------
GET     /                                            — capability summary
GET     /api/now/table/incident                      — list incidents
POST    /api/now/table/incident                      — create incident
PATCH   /api/now/table/incident/{sys_id}             — partial update incident
DELETE  /api/now/table/incident/{sys_id}             — delete incident (204)
GET     /api/now/table/change_request                — list change requests
GET     /api/now/table/task                          — list generic tasks
GET     /api/now/table/sys_user                      — list users
GET     /api/now/table/cmdb_ci                       — list CMDB CIs

When ``SERVICENOW_URL`` / ``SERVICENOW_USER`` / ``SERVICENOW_PASSWORD`` are
unset the capability summary reports ``status="unavailable"`` and the lookup
endpoints respond with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/servicenow",
    tags=["servicenow-itsm"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.servicenow_itsm_engine import get_servicenow_itsm_engine

    return get_servicenow_itsm_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    servicenow_url_present: bool
    servicenow_user_present: bool
    servicenow_password_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class IncidentCreateRequest(BaseModel):
    """Mirror of the ServiceNow incident table POST body shape."""

    short_description: str = Field(
        ..., min_length=1, description="Brief one-line summary of the incident"
    )
    description: Optional[str] = Field(None, description="Long-form description")
    urgency: Optional[int] = Field(
        None, ge=1, le=3, description="1=High, 2=Medium, 3=Low"
    )
    impact: Optional[int] = Field(
        None, ge=1, le=3, description="1=High, 2=Medium, 3=Low"
    )
    caller_id: Optional[str] = Field(None, description="sys_id of the caller user")
    category: Optional[str] = Field(None, description="Incident category")
    subcategory: Optional[str] = Field(None, description="Incident subcategory")
    assignment_group: Optional[str] = Field(
        None, description="sys_id (or name) of the assignment group"
    )
    work_notes: Optional[str] = Field(None, description="Internal work notes")
    contact_type: Optional[str] = Field(
        None,
        description="phone | email | self-service | chat | walk-in",
    )

    def to_servicenow_fields(self) -> Dict[str, Any]:
        return {k: v for k, v in self.model_dump().items() if v is not None}


class IncidentUpdateRequest(BaseModel):
    """Partial update body — all fields optional."""

    state: Optional[int] = Field(
        None,
        description="1=New, 2=In Progress, 3=On Hold, 6=Resolved, 7=Closed, 8=Canceled",
    )
    work_notes: Optional[str] = None
    assignment_group: Optional[str] = None
    resolved_by: Optional[str] = None
    resolution_code: Optional[str] = None
    resolution_notes: Optional[str] = None

    def to_servicenow_fields(self) -> Dict[str, Any]:
        return {k: v for k, v in self.model_dump().items() if v is not None}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "servicenow_unavailable",
            "message": (
                "SERVICENOW_URL, SERVICENOW_USER, and SERVICENOW_PASSWORD "
                "environment variables are not configured"
            ),
        },
    )


def _map_servicenow_error(exc: Exception) -> HTTPException:
    """Translate a ServiceNowHTTPError (or unavailable) into an HTTPException."""
    from core.servicenow_itsm_engine import (
        ServiceNowHTTPError,
        ServiceNowUnavailable,
    )

    if isinstance(exc, ServiceNowUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "servicenow_unavailable", "message": str(exc)},
        )
    if isinstance(exc, ServiceNowHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "servicenow_upstream_error",
                "upstream_status": exc.status_code,
                "message": str(exc),
                "payload": exc.payload,
            },
        )
    return HTTPException(status_code=500, detail=str(exc))


def _common_query_params(
    sysparm_query: Optional[str],
    sysparm_fields: Optional[str],
    sysparm_limit: Optional[int],
    sysparm_offset: Optional[int],
    sysparm_display_value: Optional[str],
) -> Dict[str, Any]:
    return {
        "sysparm_query": sysparm_query,
        "sysparm_fields": sysparm_fields,
        "sysparm_limit": sysparm_limit,
        "sysparm_offset": sysparm_offset,
        "sysparm_display_value": sysparm_display_value,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="ServiceNow ITSM capability summary",
)
def capability_summary() -> CapabilitySummary:
    """Return service identity, exposed endpoints, and configuration status."""
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


# --------------------------------------------------------------- incident


@router.get(
    "/api/now/table/incident",
    summary="List ServiceNow incidents",
)
def list_incidents(
    sysparm_query: Optional[str] = Query(None, description="Encoded ServiceNow query"),
    sysparm_fields: Optional[str] = Query(
        None, description="CSV of fields to return"
    ),
    sysparm_limit: Optional[int] = Query(
        None, ge=1, le=10000, description="Page size"
    ),
    sysparm_offset: Optional[int] = Query(None, ge=0, description="Page offset"),
    sysparm_display_value: Optional[str] = Query(
        None,
        description="true | false | all — return display values vs. raw values",
    ),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_incidents(
            **_common_query_params(
                sysparm_query,
                sysparm_fields,
                sysparm_limit,
                sysparm_offset,
                sysparm_display_value,
            )
        )
    except Exception as exc:
        raise _map_servicenow_error(exc) from exc


@router.post(
    "/api/now/table/incident",
    summary="Create a ServiceNow incident",
)
def create_incident(req: IncidentCreateRequest) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.create_incident(req.to_servicenow_fields())
    except Exception as exc:
        raise _map_servicenow_error(exc) from exc


@router.patch(
    "/api/now/table/incident/{sys_id}",
    summary="Partially update a ServiceNow incident",
)
def update_incident(sys_id: str, req: IncidentUpdateRequest) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.update_incident(sys_id, req.to_servicenow_fields())
    except Exception as exc:
        raise _map_servicenow_error(exc) from exc


@router.delete(
    "/api/now/table/incident/{sys_id}",
    status_code=204,
    summary="Delete a ServiceNow incident",
)
def delete_incident(sys_id: str) -> Response:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        engine.delete_incident(sys_id)
    except Exception as exc:
        raise _map_servicenow_error(exc) from exc
    return Response(status_code=204)


# --------------------------------------------------------------- change_request


@router.get(
    "/api/now/table/change_request",
    summary="List ServiceNow change requests",
)
def list_change_requests(
    sysparm_query: Optional[str] = Query(None),
    sysparm_fields: Optional[str] = Query(None),
    sysparm_limit: Optional[int] = Query(None, ge=1, le=10000),
    sysparm_offset: Optional[int] = Query(None, ge=0),
    sysparm_display_value: Optional[str] = Query(None),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_change_requests(
            **_common_query_params(
                sysparm_query,
                sysparm_fields,
                sysparm_limit,
                sysparm_offset,
                sysparm_display_value,
            )
        )
    except Exception as exc:
        raise _map_servicenow_error(exc) from exc


# --------------------------------------------------------------- task


@router.get(
    "/api/now/table/task",
    summary="List generic ServiceNow tasks",
)
def list_tasks(
    sysparm_query: Optional[str] = Query(None),
    sysparm_fields: Optional[str] = Query(None),
    sysparm_limit: Optional[int] = Query(None, ge=1, le=10000),
    sysparm_offset: Optional[int] = Query(None, ge=0),
    sysparm_display_value: Optional[str] = Query(None),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_tasks(
            **_common_query_params(
                sysparm_query,
                sysparm_fields,
                sysparm_limit,
                sysparm_offset,
                sysparm_display_value,
            )
        )
    except Exception as exc:
        raise _map_servicenow_error(exc) from exc


# --------------------------------------------------------------- sys_user


@router.get(
    "/api/now/table/sys_user",
    summary="Lookup ServiceNow users",
)
def list_users(
    sysparm_query: Optional[str] = Query(None),
    sysparm_fields: Optional[str] = Query(None),
    sysparm_limit: Optional[int] = Query(None, ge=1, le=10000),
    sysparm_offset: Optional[int] = Query(None, ge=0),
    sysparm_display_value: Optional[str] = Query(None),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_users(
            **_common_query_params(
                sysparm_query,
                sysparm_fields,
                sysparm_limit,
                sysparm_offset,
                sysparm_display_value,
            )
        )
    except Exception as exc:
        raise _map_servicenow_error(exc) from exc


# --------------------------------------------------------------- cmdb_ci


@router.get(
    "/api/now/table/cmdb_ci",
    summary="List ServiceNow CMDB configuration items",
)
def list_cmdb_cis(
    sysparm_query: Optional[str] = Query(None),
    sysparm_fields: Optional[str] = Query(None),
    sysparm_limit: Optional[int] = Query(None, ge=1, le=10000),
    sysparm_offset: Optional[int] = Query(None, ge=0),
    sysparm_display_value: Optional[str] = Query(None),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_cmdb_cis(
            **_common_query_params(
                sysparm_query,
                sysparm_fields,
                sysparm_limit,
                sysparm_offset,
                sysparm_display_value,
            )
        )
    except Exception as exc:
        raise _map_servicenow_error(exc) from exc
