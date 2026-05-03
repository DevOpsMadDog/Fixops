"""MFA Management Router — ALDECI.

Endpoints for the MFA Management engine.

Prefix: /api/v1/mfa
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/mfa/enrollments                         enroll_user
  GET   /api/v1/mfa/enrollments                         list_enrollments
  GET   /api/v1/mfa/enrollments/{enrollment_id}         get_enrollment
  PUT   /api/v1/mfa/enrollments/{enrollment_id}/activate activate_enrollment
  PUT   /api/v1/mfa/enrollments/{enrollment_id}/disable  disable_enrollment
  POST  /api/v1/mfa/events                              record_mfa_event
  GET   /api/v1/mfa/events                              get_mfa_events
  POST  /api/v1/mfa/policies                            create_policy
  GET   /api/v1/mfa/policies                            list_policies
  GET   /api/v1/mfa/stats                               get_mfa_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/mfa",
    tags=["MFA Management"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.mfa_management_engine import MFAManagementEngine
        _engine = MFAManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EnrollmentCreate(BaseModel):
    user_id: str
    mfa_type: str
    backup_codes_count: int = 0


class MFAEventCreate(BaseModel):
    user_id: str
    event_type: str
    mfa_type: str = ""
    success: bool
    ip_address: str = ""


class PolicyCreate(BaseModel):
    policy_name: str
    required_mfa_types: List[str] = []
    enforcement: str = "optional"
    grace_period_days: int = 7


class PolicyEnforceRequest(BaseModel):
    user_id: str


# ---------------------------------------------------------------------------
# Enrollments
# ---------------------------------------------------------------------------

@router.post("/enrollments", dependencies=[Depends(api_key_auth)], status_code=201)
def enroll_user(body: EnrollmentCreate, org_id: str = Query(default="default")):
    """Create a new MFA enrollment (status=pending)."""
    try:
        return _get_engine().enroll_user(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/enrollments", dependencies=[Depends(api_key_auth)])
def list_enrollments(
     org_id: str = Query(default="default"),
    user_id: Optional[str] = Query(None),
    mfa_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List MFA enrollments with optional filters."""
    return _get_engine().list_enrollments(org_id, user_id=user_id, mfa_type=mfa_type, status=status)


@router.get("/enrollments/{enrollment_id}", dependencies=[Depends(api_key_auth)])
def get_enrollment(enrollment_id: str, org_id: str = Query(default="default")):
    """Get a single enrollment by ID."""
    result = _get_engine().get_enrollment(org_id, enrollment_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Enrollment not found")
    return result


@router.put("/enrollments/{enrollment_id}/activate", dependencies=[Depends(api_key_auth)])
def activate_enrollment(enrollment_id: str, org_id: str = Query(default="default")):
    """Activate a pending MFA enrollment."""
    result = _get_engine().activate_enrollment(org_id, enrollment_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Enrollment not found")
    return result


@router.put("/enrollments/{enrollment_id}/disable", dependencies=[Depends(api_key_auth)])
def disable_enrollment(enrollment_id: str, org_id: str = Query(default="default")):
    """Disable an active MFA enrollment."""
    result = _get_engine().disable_enrollment(org_id, enrollment_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Enrollment not found")
    return result


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@router.post("/events", dependencies=[Depends(api_key_auth)], status_code=201)
def record_mfa_event(body: MFAEventCreate, org_id: str = Query(default="default")):
    """Record an MFA authentication event."""
    try:
        return _get_engine().record_mfa_event(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/events", dependencies=[Depends(api_key_auth)])
def get_mfa_events(
     org_id: str = Query(default="default"),
    user_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(50),
):
    """List MFA events with optional filters."""
    return _get_engine().get_mfa_events(org_id, user_id=user_id, event_type=event_type, limit=limit)


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@router.post("/policies", dependencies=[Depends(api_key_auth)], status_code=201)
def create_policy(body: PolicyCreate, org_id: str = Query(default="default")):
    """Create an MFA enforcement policy."""
    try:
        return _get_engine().create_policy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/policies", dependencies=[Depends(api_key_auth)])
def list_policies(org_id: str = Query(default="default")):
    """List all MFA policies for an org."""
    return _get_engine().list_policies(org_id)


@router.post("/policies/{policy_id}/enforce", dependencies=[Depends(api_key_auth)])
def enforce_policy(
    policy_id: str,
    body: PolicyEnforceRequest,
    org_id: str = Query(default="default"),
):
    """Evaluate whether a user satisfies an MFA enforcement policy.

    Returns compliance status, active MFA types, missing required types,
    and the grace period window from the policy.
    """
    try:
        return _get_engine().enforce_policy(org_id, policy_id, body.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_mfa_stats(org_id: str = Query(default="default")):
    """Return aggregated MFA statistics."""
    return _get_engine().get_mfa_stats(org_id)
