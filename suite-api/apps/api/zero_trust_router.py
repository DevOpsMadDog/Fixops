"""
Zero-Trust Policy Engine API Router.

Endpoints:
    POST   /api/v1/zero-trust/evaluate         -- Full access evaluation
    POST   /api/v1/zero-trust/devices          -- Register a device
    GET    /api/v1/zero-trust/devices/{id}     -- Get device trust score
    POST   /api/v1/zero-trust/mfa/check        -- Check MFA requirement
    POST   /api/v1/zero-trust/geo/check        -- Geographic restriction check
    POST   /api/v1/zero-trust/time/check       -- Time-window restriction check
    GET    /api/v1/zero-trust/sessions/{id}    -- Continuous auth status
    GET    /api/v1/zero-trust/stats            -- Policy evaluation statistics

Security: All endpoints require API key authentication.
Compliance: NIST SP 800-207 Zero Trust Architecture.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from core.zero_trust import (
        AccessDecision,
        DevicePosture,
        TrustLevel,
        ZeroTrustEngine,
        create_zero_trust_engine,
    )
    _engine: ZeroTrustEngine = create_zero_trust_engine()
except ImportError as _e:
    import logging as _logging
    _logging.getLogger(__name__).warning(
        "zero_trust_router: core.zero_trust not available: %s", _e
    )
    _engine = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/zero-trust", tags=["zero-trust"])


# ============================================================================
# Request / Response models
# ============================================================================


class EvaluateAccessRequest(BaseModel):
    """Request body for a zero-trust access evaluation."""

    user: str = Field(..., description="User identifier")
    resource: str = Field(..., description="Resource being accessed (e.g. 'admin/users')")
    device: DevicePosture
    context: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Extra context: ip, org_id, mfa_verified, allowed_regions, …",
    )


class RegisterDeviceRequest(BaseModel):
    """Request body for device registration."""

    device: DevicePosture


class MFACheckRequest(BaseModel):
    user: str
    resource: str


class MFACheckResponse(BaseModel):
    user: str
    resource: str
    mfa_required: bool


class GeoCheckRequest(BaseModel):
    ip: str
    allowed_regions: Optional[List[str]] = None


class GeoCheckResponse(BaseModel):
    ip: str
    allowed: bool
    reason: str


class TimeCheckRequest(BaseModel):
    user: str
    resource: str
    org_id: str = "default"


class TimeCheckResponse(BaseModel):
    user: str
    resource: str
    allowed: bool
    reason: str


# ============================================================================
# Helpers
# ============================================================================


def _require_engine() -> ZeroTrustEngine:
    if _engine is None:
        raise HTTPException(status_code=503, detail="ZeroTrustEngine unavailable")
    return _engine


# ============================================================================
# Endpoints
# ============================================================================


@router.post("/evaluate", response_model=Dict[str, Any])
async def evaluate_access(body: EvaluateAccessRequest) -> Dict[str, Any]:
    """
    Evaluate a zero-trust access request.

    Runs all built-in policies: device posture, geo-fencing, time windows,
    resource trust requirements, and MFA escalation.
    Returns an AccessDecision with allow/deny, trust level, and conditions.
    """
    engine = _require_engine()
    try:
        decision = engine.evaluate_access(
            user=body.user,
            resource=body.resource,
            device_posture=body.device,
            context=body.context,
        )
        return decision.to_dict()
    except Exception as exc:
        logger.exception("evaluate_access failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/devices", response_model=Dict[str, Any])
async def register_device(body: RegisterDeviceRequest) -> Dict[str, Any]:
    """
    Register or update a device and compute its posture trust score.

    The engine calculates a trust_score based on encryption, firewall,
    antivirus, and patch-level attributes.
    """
    engine = _require_engine()
    try:
        posture = engine.register_device(body.device)
        return {
            "registered": True,
            "device": posture.to_dict(),
        }
    except Exception as exc:
        logger.exception("register_device failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/devices/{device_id}", response_model=Dict[str, Any])
async def get_device_trust(device_id: str) -> Dict[str, Any]:
    """Return the current trust score for a registered device."""
    engine = _require_engine()
    trust_score = engine.get_device_trust(device_id)
    if trust_score is None:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found")
    return {
        "device_id": device_id,
        "trust_score": trust_score,
        "trust_level": _trust_level_label(trust_score),
    }


@router.post("/mfa/check", response_model=MFACheckResponse)
async def check_mfa(body: MFACheckRequest) -> MFACheckResponse:
    """Check whether MFA is required for a given user and resource."""
    engine = _require_engine()
    required = engine.enforce_mfa(body.user, body.resource)
    return MFACheckResponse(
        user=body.user,
        resource=body.resource,
        mfa_required=required,
    )


@router.post("/geo/check", response_model=GeoCheckResponse)
async def check_geo(body: GeoCheckRequest) -> GeoCheckResponse:
    """Evaluate geographic access control for an IP address."""
    engine = _require_engine()
    allowed, reason = engine.check_geo_restriction(body.ip, body.allowed_regions)
    return GeoCheckResponse(ip=body.ip, allowed=allowed, reason=reason)


@router.post("/time/check", response_model=TimeCheckResponse)
async def check_time(body: TimeCheckRequest) -> TimeCheckResponse:
    """Check whether the current UTC time falls within the allowed access window."""
    engine = _require_engine()
    allowed, reason = engine.check_time_restriction(
        body.user, body.resource, body.org_id
    )
    return TimeCheckResponse(
        user=body.user,
        resource=body.resource,
        allowed=allowed,
        reason=reason,
    )


@router.get("/sessions/{session_id}", response_model=Dict[str, Any])
async def get_continuous_auth_status(session_id: str) -> Dict[str, Any]:
    """
    Return the continuous authentication risk score for a session.

    Risk increases with session age; sessions older than ~7 hours will
    be flagged as requiring re-authentication.
    """
    engine = _require_engine()
    return engine.get_continuous_auth_status(session_id)


@router.get("/stats", response_model=Dict[str, Any])
async def get_zero_trust_stats(
    org_id: str = Query(default="default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregated policy evaluation statistics."""
    engine = _require_engine()
    return engine.get_zero_trust_stats(org_id=org_id)


# ============================================================================
# Internal helpers
# ============================================================================


def _trust_level_label(score: float) -> str:
    if score >= 0.90:
        return TrustLevel.VERIFIED.value
    if score >= 0.70:
        return TrustLevel.HIGH.value
    if score >= 0.50:
        return TrustLevel.MEDIUM.value
    if score >= 0.30:
        return TrustLevel.LOW.value
    return TrustLevel.NONE.value
