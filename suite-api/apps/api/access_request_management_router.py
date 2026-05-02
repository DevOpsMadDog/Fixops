"""Access Request Management Router — ALDECI.

Manages the privileged access request lifecycle.

Prefix: /api/v1/access-requests
Auth: api_key_auth dependency

Routes:
  POST /api/v1/access-requests/requests                      create_request
  GET  /api/v1/access-requests/requests                      list_requests
  GET  /api/v1/access-requests/requests/{request_id}         get_request
  POST /api/v1/access-requests/requests/{request_id}/approve approve_request
  POST /api/v1/access-requests/requests/{request_id}/reject  reject_request
  POST /api/v1/access-requests/requests/{request_id}/revoke  revoke_access
  GET  /api/v1/access-requests/stats                         get_access_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/access-requests",
    tags=["Access Request Management"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.access_request_management_engine import AccessRequestManagementEngine
        _engine = AccessRequestManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class CreateAccessRequestBody(BaseModel):
    requester: str = Field(..., description="User making the request")
    resource_id: str = Field(default="", description="Target resource identifier")
    resource_name: str = Field(default="", description="Human-readable resource name")
    resource_type: str = Field(
        default="application",
        description="database | application | server | network | cloud_resource | file_share | api",
    )
    access_type: str = Field(
        default="read",
        description="read | write | admin | execute | delete | full_control",
    )
    justification: str = Field(default="", description="Business justification")
    priority: str = Field(default="normal", description="urgent | high | normal | low")
    duration_days: int = Field(default=30, description="Access duration in days")


class ApproveRequestBody(BaseModel):
    approver: str = Field(..., description="Approver user ID")
    notes: str = Field(default="", description="Optional approval notes")


class RejectRequestBody(BaseModel):
    approver: str = Field(..., description="Approver user ID")
    reason: str = Field(..., description="Rejection reason")


class RevokeAccessBody(BaseModel):
    reason: str = Field(..., description="Revocation reason")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/requests", dependencies=[Depends(api_key_auth)])
def create_request(body: CreateAccessRequestBody, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Create a new access request."""
    try:
        return _get_engine().create_request(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/requests", dependencies=[Depends(api_key_auth)])
def list_requests(
    org_id: str = Query(default="default"),
    access_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    resource_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """List access requests (canonical envelope, batch-6).

    Class-c contract: empty IS correct for fresh tenants — access requests
    are a user-driven workflow that populates only after end-users submit
    privileged access requests. Always returns full envelope with pagination
    context + filters echo + actionable hint when empty.
    """
    rows = _get_engine().list_requests(
        org_id,
        access_type=access_type,
        status=status,
        resource_type=resource_type,
    ) or []
    paged = rows[offset : offset + limit] if offset else rows[:limit]
    envelope = {
        "items": paged,
        "requests": paged,  # legacy key preserved
        "total": len(rows),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
        "filters_applied": {
            "access_type": access_type,
            "status": status,
            "resource_type": resource_type,
        },
    }
    if not rows:
        envelope["hint"] = (
            "Submit POST /api/v1/access-requests/requests to create a privileged "
            "access request. This is a user-driven workflow; empty IS the correct "
            "response for a fresh tenant."
        )
    return envelope


@router.get("/requests/{request_id}", dependencies=[Depends(api_key_auth)])
def get_request(request_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Fetch a single access request."""
    result = _get_engine().get_request(org_id, request_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Request not found")
    return result


@router.post("/requests/{request_id}/approve", dependencies=[Depends(api_key_auth)])
def approve_request(
    request_id: str,
    body: ApproveRequestBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Approve an access request."""
    try:
        return _get_engine().approve_request(org_id, request_id, body.approver, body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/requests/{request_id}/reject", dependencies=[Depends(api_key_auth)])
def reject_request(
    request_id: str,
    body: RejectRequestBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Reject an access request."""
    try:
        return _get_engine().reject_request(org_id, request_id, body.approver, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/requests/{request_id}/revoke", dependencies=[Depends(api_key_auth)])
def revoke_access(
    request_id: str,
    body: RevokeAccessBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Revoke access for an approved request."""
    try:
        return _get_engine().revoke_access(org_id, request_id, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_access_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate stats for access requests."""
    return _get_engine().get_access_stats(org_id)
