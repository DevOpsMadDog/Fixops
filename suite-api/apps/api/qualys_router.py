"""Qualys VMDR Router - ALDECI.

REST surface under prefix ``/api/v1/qualys`` wrapping ``core.qualys_engine``.

Endpoints
---------
* GET  /                                                       - capability summary
* GET  /api/2.0/fo/asset/host/?action=list                     - host inventory
* GET  /api/2.0/fo/asset/host/vm/detection/?action=list        - host vuln detections
* GET  /api/2.0/fo/scan/?action=list                           - scan list
* POST /api/2.0/fo/scan/?action=launch                         - launch a scan
* GET  /api/2.0/fo/compliance/policy/?action=list              - PC policy list
* GET  /api/2.0/fo/report/?action=list                         - report list

Auth
----
api_key_auth dependency (mount layer adds scope checks - read:scans).

NO MOCKS rule
-------------
* When QUALYS_USERNAME/QUALYS_PASSWORD/QUALYS_API_BASE is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads. Some endpoints may surface raw XML envelopes when
  upstream does not honour the JSON output_format.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/qualys",
    tags=["Qualys VMDR"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.qualys_engine import get_qualys_engine

    return get_qualys_engine()


def _serve(callable_):
    """Run a Qualys call, translating engine errors to HTTP responses."""
    from core.qualys_engine import QualysUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except QualysUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    qualys_username_present: bool
    qualys_password_present: bool
    qualys_api_base_present: bool
    status: str  # ok | unavailable


class HostsResponse(BaseModel):
    """Raw HOST_LIST_OUTPUT envelope as returned by Qualys (JSON or
    ``{xml: ...}`` fallback)."""

    payload: Dict[str, Any] = Field(default_factory=dict)


class DetectionsResponse(BaseModel):
    """Raw HOST_LIST_VM_DETECTION_OUTPUT envelope."""

    payload: Dict[str, Any] = Field(default_factory=dict)


class ScansResponse(BaseModel):
    """Raw SCAN_LIST_OUTPUT envelope."""

    payload: Dict[str, Any] = Field(default_factory=dict)


class PoliciesResponse(BaseModel):
    """Raw POLICY_LIST_OUTPUT envelope."""

    payload: Dict[str, Any] = Field(default_factory=dict)


class ReportsResponse(BaseModel):
    """Raw REPORT_LIST_OUTPUT envelope."""

    payload: Dict[str, Any] = Field(default_factory=dict)


class LaunchScanRequest(BaseModel):
    scan_title: str = Field(..., description="Title to assign to the new scan")
    ip: Optional[str] = Field(
        default=None, description="IP/IP-range/CSV to scan"
    )
    asset_groups: Optional[str] = Field(
        default=None, description="Asset group titles (CSV)"
    )
    asset_group_ids: Optional[str] = Field(
        default=None, description="Asset group IDs (CSV)"
    )
    option_id: Optional[int] = Field(
        default=None, description="Option profile id"
    )
    option_title: Optional[str] = Field(
        default=None, description="Option profile title"
    )
    iscanner_id: Optional[int] = Field(
        default=None, description="Internal scanner id"
    )
    iscanner_name: Optional[str] = Field(
        default=None, description="Internal scanner appliance name"
    )


class LaunchScanResponse(BaseModel):
    """Raw SIMPLE_RETURN envelope (or ``{xml: ...}`` fallback)."""

    payload: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="Qualys VMDR capability summary",
)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary - safe to call without credentials."""
    eng = _engine()
    u = eng.username_present()
    p = eng.password_present()
    b = eng.api_base_present()
    status = "ok" if (u and p and b) else "unavailable"
    return CapabilityResponse(
        service="Qualys VMDR",
        endpoints=[
            "/api/2.0/fo/asset/host/?action=list",
            "/api/2.0/fo/asset/host/vm/detection/?action=list",
            "/api/2.0/fo/scan/?action=list",
            "/api/2.0/fo/scan/?action=launch",
            "/api/2.0/fo/compliance/policy/?action=list",
            "/api/2.0/fo/report/?action=list",
        ],
        qualys_username_present=u,
        qualys_password_present=p,
        qualys_api_base_present=b,
        status=status,
    )


@router.get(
    "/api/2.0/fo/asset/host/",
    response_model=HostsResponse,
    summary="List Qualys host inventory",
)
async def list_hosts(
    action: str = Query(default="list", description="Always ``list``"),
    truncation_limit: Optional[int] = Query(default=None, ge=0),
    id_min: Optional[int] = Query(default=None),
    ids: Optional[str] = Query(default=None, description="Host ID CSV"),
    details: Optional[str] = Query(
        default=None, description="All|Basic|None"
    ),
) -> HostsResponse:
    if action != "list":
        raise HTTPException(
            status_code=422, detail="action must be 'list'"
        )
    eng = _engine()
    data = _serve(
        lambda: eng.list_hosts(
            truncation_limit=truncation_limit,
            id_min=id_min,
            ids=ids,
            details=details,
        )
    )
    return HostsResponse(payload=data)


@router.get(
    "/api/2.0/fo/asset/host/vm/detection/",
    response_model=DetectionsResponse,
    summary="List Qualys host vulnerability detections",
)
async def list_host_detections(
    action: str = Query(default="list", description="Always ``list``"),
    truncation_limit: Optional[int] = Query(default=None, ge=0),
    qids: Optional[str] = Query(default=None, description="QID CSV"),
    severities: Optional[str] = Query(
        default=None, description="Severity CSV (1..5)"
    ),
    ids: Optional[str] = Query(default=None, description="Host ID CSV"),
    include_search_list_titles: Optional[bool] = Query(default=None),
    output_format: str = Query(
        default="JSON", description="JSON|XML|CSV"
    ),
) -> DetectionsResponse:
    if action != "list":
        raise HTTPException(
            status_code=422, detail="action must be 'list'"
        )
    eng = _engine()
    data = _serve(
        lambda: eng.list_host_detections(
            truncation_limit=truncation_limit,
            qids=qids,
            severities=severities,
            ids=ids,
            include_search_list_titles=include_search_list_titles,
            output_format=output_format,
        )
    )
    return DetectionsResponse(payload=data)


@router.get(
    "/api/2.0/fo/scan/",
    response_model=ScansResponse,
    summary="List Qualys scans",
)
async def list_scans(
    action: str = Query(default="list", description="Always ``list``"),
    launched_after_datetime: Optional[str] = Query(default=None),
    launched_before_datetime: Optional[str] = Query(default=None),
    state: Optional[str] = Query(
        default=None,
        description="Submitted|Running|Finished|Cancelled|Error|Paused",
    ),
    processed: Optional[int] = Query(default=None, ge=0, le=1),
    type: Optional[str] = Query(
        default=None,
        alias="type",
        description="Vulnerability|Compliance|Discovery|VM|PC",
    ),
    output_format: str = Query(default="JSON", description="JSON|XML"),
) -> ScansResponse:
    if action != "list":
        raise HTTPException(
            status_code=422, detail="action must be 'list'"
        )
    eng = _engine()
    data = _serve(
        lambda: eng.list_scans(
            launched_after_datetime=launched_after_datetime,
            launched_before_datetime=launched_before_datetime,
            state=state,
            processed=processed,
            scan_type=type,
            output_format=output_format,
        )
    )
    return ScansResponse(payload=data)


@router.post(
    "/api/2.0/fo/scan/",
    response_model=LaunchScanResponse,
    summary="Launch a Qualys scan",
)
async def launch_scan(
    action: str = Query(..., description="Must be 'launch'"),
    body: LaunchScanRequest = Body(...),
) -> LaunchScanResponse:
    if action != "launch":
        raise HTTPException(
            status_code=422, detail="action must be 'launch'"
        )
    eng = _engine()
    data = _serve(
        lambda: eng.launch_scan(
            scan_title=body.scan_title,
            ip=body.ip,
            asset_groups=body.asset_groups,
            asset_group_ids=body.asset_group_ids,
            option_id=body.option_id,
            option_title=body.option_title,
            iscanner_id=body.iscanner_id,
            iscanner_name=body.iscanner_name,
        )
    )
    return LaunchScanResponse(payload=data)


@router.get(
    "/api/2.0/fo/compliance/policy/",
    response_model=PoliciesResponse,
    summary="List Qualys PC compliance policies",
)
async def list_compliance_policies(
    action: str = Query(default="list", description="Always ``list``"),
    id: Optional[int] = Query(
        default=None, alias="id", description="Filter by policy ID"
    ),
    output_format: str = Query(default="JSON", description="JSON|XML"),
) -> PoliciesResponse:
    if action != "list":
        raise HTTPException(
            status_code=422, detail="action must be 'list'"
        )
    eng = _engine()
    data = _serve(
        lambda: eng.list_compliance_policies(
            policy_id=id,
            output_format=output_format,
        )
    )
    return PoliciesResponse(payload=data)


@router.get(
    "/api/2.0/fo/report/",
    response_model=ReportsResponse,
    summary="List Qualys reports",
)
async def list_reports(
    action: str = Query(default="list", description="Always ``list``"),
    id: Optional[int] = Query(
        default=None, alias="id", description="Filter by report ID"
    ),
    state: Optional[str] = Query(
        default=None,
        description="Running|Finished|Submitted|Canceled|Errors",
    ),
    user_login: Optional[str] = Query(default=None),
    expires_before: Optional[str] = Query(default=None),
    expires_after: Optional[str] = Query(default=None),
) -> ReportsResponse:
    if action != "list":
        raise HTTPException(
            status_code=422, detail="action must be 'list'"
        )
    eng = _engine()
    data = _serve(
        lambda: eng.list_reports(
            report_id=id,
            state=state,
            user_login=user_login,
            expires_before=expires_before,
            expires_after=expires_after,
        )
    )
    return ReportsResponse(payload=data)


__all__ = ["router"]
