"""
Zero-Trust Policy Engine API Router.

Endpoints:
    POST   /api/v1/zero-trust/evaluate                  -- Full access evaluation
    POST   /api/v1/zero-trust/devices                   -- Register a device
    GET    /api/v1/zero-trust/devices/{id}              -- Get device trust score
    POST   /api/v1/zero-trust/mfa/check                 -- Check MFA requirement
    POST   /api/v1/zero-trust/geo/check                 -- Geographic restriction check
    POST   /api/v1/zero-trust/time/check                -- Time-window restriction check
    GET    /api/v1/zero-trust/sessions/{id}             -- Continuous auth status
    GET    /api/v1/zero-trust/stats                     -- Policy evaluation statistics

    -- ZeroTrustEngine endpoints (ALLOW/DENY/CHALLENGE model) --
    POST   /api/v1/zero-trust/engine/evaluate           -- Evaluate access request
    POST   /api/v1/zero-trust/policy                    -- Create access policy
    GET    /api/v1/zero-trust/policies                  -- List all policies
    POST   /api/v1/zero-trust/lateral-movement/detect   -- Detect lateral movement
    GET    /api/v1/zero-trust/trust-scores              -- Trust scores for all entities

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

try:
    from core.zero_trust_engine import (
        AccessRequest as EngineAccessRequest,
        ZeroTrustEngine as NewZeroTrustEngine,
        create_zero_trust_engine as create_new_engine,
    )
    _new_engine: NewZeroTrustEngine = create_new_engine()
except ImportError as _e2:
    import logging as _logging2
    _logging2.getLogger(__name__).warning(
        "zero_trust_router: core.zero_trust_engine not available: %s", _e2
    )
    _new_engine = None  # type: ignore[assignment]

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


# ============================================================================
# ZeroTrustEngine endpoints (ALLOW / DENY / CHALLENGE model)
# ============================================================================


def _require_new_engine() -> "NewZeroTrustEngine":
    if _new_engine is None:
        raise HTTPException(status_code=503, detail="ZeroTrustEngine (new) unavailable")
    return _new_engine


class EngineEvaluateRequest(BaseModel):
    """Request body for the new engine access evaluation."""

    user_id: str
    device_id: str
    resource: str
    action: str = "read"
    location: str = ""
    timestamp: Optional[str] = None
    mfa_verified: bool = False
    device_trust_score: Optional[float] = None
    behaviour_score: Optional[float] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class CreatePolicyRequest(BaseModel):
    """Request body for creating a zero-trust access policy."""

    resource: str
    rules: List[Dict[str, Any]] = Field(default_factory=list)


class LateralMovementRequest(BaseModel):
    """Request body for lateral movement detection."""

    network_events: List[Dict[str, Any]]


@router.post("/engine/evaluate", response_model=Dict[str, Any])
async def engine_evaluate_access(body: EngineEvaluateRequest) -> Dict[str, Any]:
    """
    Evaluate an access request using the ALLOW / DENY / CHALLENGE engine.

    Factors: identity, device posture, network location, behaviour baseline,
    time of access, resource sensitivity.
    """
    engine = _require_new_engine()
    try:
        from core.zero_trust_engine import AccessRequest as _AR
        req = _AR(
            user_id=body.user_id,
            device_id=body.device_id,
            resource=body.resource,
            action=body.action,
            location=body.location,
            mfa_verified=body.mfa_verified,
            device_trust_score=body.device_trust_score,
            behaviour_score=body.behaviour_score,
            extra=body.extra,
            **({"timestamp": body.timestamp} if body.timestamp else {}),
        )
        decision = engine.evaluate_access_request(req)
        return decision.to_dict()
    except Exception as exc:
        logger.exception("engine_evaluate_access failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/policy", response_model=Dict[str, Any])
async def create_policy(body: CreatePolicyRequest) -> Dict[str, Any]:
    """
    Create or replace a zero-trust access policy for a resource.

    Rules are evaluated in order; first match wins.
    Each rule may contain: user_id, action, min_trust_score,
    require_mfa, decision (ALLOW/DENY/CHALLENGE).
    """
    engine = _require_new_engine()
    try:
        policy = engine.create_access_policy(
            resource=body.resource,
            rules=body.rules,
        )
        return policy.to_dict()
    except Exception as exc:
        logger.exception("create_policy failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/policies", response_model=List[Dict[str, Any]])
async def list_policies() -> List[Dict[str, Any]]:
    """List all stored zero-trust access policies."""
    engine = _require_new_engine()
    try:
        return engine.list_policies()
    except Exception as exc:
        logger.exception("list_policies failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/lateral-movement/detect", response_model=Dict[str, Any])
async def detect_lateral_movement(body: LateralMovementRequest) -> Dict[str, Any]:
    """
    Detect lateral movement patterns in network traffic events.

    Patterns: port scanning, host enumeration, off-hours external access,
    impossible travel, brute-force auth attempts, unusual protocols.
    """
    engine = _require_new_engine()
    try:
        alerts = engine.detect_lateral_movement(body.network_events)
        return {
            "total_events": len(body.network_events),
            "alerts_raised": len(alerts),
            "alerts": [a.to_dict() for a in alerts],
        }
    except Exception as exc:
        logger.exception("detect_lateral_movement failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/trust-scores", response_model=Dict[str, Any])
async def get_trust_scores() -> Dict[str, Any]:
    """Return trust scores for all known entities (users, devices, services)."""
    engine = _require_new_engine()
    try:
        scores = engine.get_all_trust_scores()
        return {
            "total": len(scores),
            "entities": scores,
        }
    except Exception as exc:
        logger.exception("get_trust_scores failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
