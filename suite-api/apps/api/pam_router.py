"""
Privileged Access Management (PAM) API Router.

Endpoints:
    POST   /api/v1/pam/requests              -- Request privilege elevation
    POST   /api/v1/pam/requests/{id}/approve -- Approve a pending request
    POST   /api/v1/pam/requests/{id}/deny    -- Deny a pending request
    POST   /api/v1/pam/requests/{id}/revoke  -- Immediately revoke an approved elevation
    GET    /api/v1/pam/check/{user_email}    -- Check current privilege level
    GET    /api/v1/pam/elevations            -- List all active elevations for an org
    GET    /api/v1/pam/history               -- Audit trail for an org
    GET    /api/v1/pam/stats                 -- PAM statistics for an org
    POST   /api/v1/pam/break-glass           -- Emergency break-glass (auto-approve)

Security:
    - All endpoints require API key
    - Pydantic validation on all request bodies
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.dependencies import get_org_id
from core.pam import (
    AccessRequest,
    PAMManager,
    PrivilegeLevel,
    RequestStatus,
    get_pam_manager,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/pam", tags=["pam"])

# Shared singleton
_pam = get_pam_manager()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ElevationRequestBody(BaseModel):
    user_email: str = Field(..., description="Email of the user requesting elevation")
    requested_level: PrivilegeLevel = Field(..., description="Target privilege level")
    justification: str = Field(..., min_length=10, description="Business justification")
    duration_minutes: int = Field(..., gt=0, le=480, description="Duration (max 480 min)")


class ApproveRequestBody(BaseModel):
    approver: str = Field(..., description="Email of the approver")


class DenyRequestBody(BaseModel):
    reviewer: str = Field(..., description="Email of the reviewer")
    reason: str = Field(..., min_length=5, description="Reason for denial")


class BreakGlassBody(BaseModel):
    user_email: str = Field(..., description="Email of the user invoking break-glass")
    justification: str = Field(..., min_length=10, description="Emergency justification")


class PrivilegeCheckResponse(BaseModel):
    user_email: str
    privilege_level: PrivilegeLevel
    org_id: str


class ActiveElevationsResponse(BaseModel):
    org_id: str
    count: int
    elevations: List[AccessRequest]


class HistoryResponse(BaseModel):
    org_id: str
    total: int
    limit: int
    offset: int
    requests: List[AccessRequest]


class PAMStatsResponse(BaseModel):
    org_id: str
    total_requests: int
    by_status: Dict[str, int]
    avg_approved_duration_minutes: float
    top_requesters: List[Dict[str, Any]]
    break_glass_count: int
    post_review_pending: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/requests", response_model=AccessRequest, status_code=201)
def create_elevation_request(
    body: ElevationRequestBody,
    org_id: str = Depends(get_org_id),
) -> AccessRequest:
    """Create a privilege elevation request (status: pending)."""
    try:
        return _pam.request_access(
            user_email=body.user_email,
            requested_level=body.requested_level,
            justification=body.justification,
            duration_minutes=body.duration_minutes,
            org_id=org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/requests/{request_id}/approve", response_model=AccessRequest)
def approve_elevation_request(
    request_id: str,
    body: ApproveRequestBody,
    org_id: str = Depends(get_org_id),
) -> AccessRequest:
    """Approve a pending elevation request with time-bound access."""
    try:
        return _pam.approve_request(request_id=request_id, approver=body.approver)
    except ValueError as exc:
        status_code = 404 if "not found" in str(exc).lower() else 409
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.post("/requests/{request_id}/deny", response_model=AccessRequest)
def deny_elevation_request(
    request_id: str,
    body: DenyRequestBody,
    org_id: str = Depends(get_org_id),
) -> AccessRequest:
    """Deny a pending elevation request with a reason."""
    try:
        return _pam.deny_request(
            request_id=request_id,
            reviewer=body.reviewer,
            reason=body.reason,
        )
    except ValueError as exc:
        status_code = 404 if "not found" in str(exc).lower() else 409
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.post("/requests/{request_id}/revoke", response_model=AccessRequest)
def revoke_elevation(
    request_id: str,
    org_id: str = Depends(get_org_id),
) -> AccessRequest:
    """Immediately revoke an approved elevation."""
    try:
        return _pam.revoke_access(request_id=request_id)
    except ValueError as exc:
        status_code = 404 if "not found" in str(exc).lower() else 409
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.get("/check/{user_email}", response_model=PrivilegeCheckResponse)
def check_privilege(
    user_email: str,
    org_id: str = Depends(get_org_id),
) -> PrivilegeCheckResponse:
    """Return the current effective privilege level for a user."""
    level = _pam.check_privilege(user_email=user_email, org_id=org_id)
    return PrivilegeCheckResponse(
        user_email=user_email,
        privilege_level=level,
        org_id=org_id,
    )


@router.get("/elevations", response_model=ActiveElevationsResponse)
def get_active_elevations(
    org_id: str = Depends(get_org_id),
) -> ActiveElevationsResponse:
    """List all currently active elevated access sessions for the org."""
    elevations = _pam.get_active_elevations(org_id=org_id)
    return ActiveElevationsResponse(
        org_id=org_id,
        count=len(elevations),
        elevations=elevations,
    )


@router.get("/history", response_model=HistoryResponse)
def get_request_history(
    org_id: str = Depends(get_org_id),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> HistoryResponse:
    """Return the full PAM audit trail for the org."""
    history = _pam.get_request_history(org_id=org_id, limit=limit, offset=offset)
    return HistoryResponse(
        org_id=org_id,
        total=len(history),
        limit=limit,
        offset=offset,
        requests=history,
    )


@router.get("/stats", response_model=PAMStatsResponse)
def get_pam_stats(
    org_id: str = Depends(get_org_id),
) -> PAMStatsResponse:
    """Return aggregated PAM statistics for the org."""
    stats = _pam.get_pam_stats(org_id=org_id)
    return PAMStatsResponse(**stats)


@router.post("/break-glass", response_model=AccessRequest, status_code=201)
def break_glass(
    body: BreakGlassBody,
    org_id: str = Depends(get_org_id),
) -> AccessRequest:
    """Emergency break-glass: auto-approve EMERGENCY elevation with mandatory post-review."""
    try:
        req = _pam.break_glass(
            user_email=body.user_email,
            justification=body.justification,
            org_id=org_id,
        )
        logger.warning(
            "BREAK-GLASS invoked via API: user=%s org=%s req=%s",
            body.user_email, org_id, req.id,
        )
        return req
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
