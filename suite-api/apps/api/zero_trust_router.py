"""
Zero-Trust Policy Engine API Router.

Prefix: /api/v1/zero-trust

Endpoints:
    POST   /policies              -- Create a zero-trust policy
    GET    /policies              -- List policies
    GET    /policies/{policy_id}  -- Get a single policy
    PUT    /policies/{policy_id}  -- Update a policy
    DELETE /policies/{policy_id}  -- Delete a policy
    POST   /evaluate              -- Evaluate an access request
    POST   /trust-score           -- Compute trust score only
    GET    /access-log            -- Query access log
    GET    /analytics             -- Trust analytics

Compliance: NIST SP 800-207 Zero Trust Architecture.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import structlog
from core.zero_trust_engine import ZeroTrustEngine, get_zero_trust_engine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1/zero-trust-legacy", tags=["zero-trust-legacy"])


def _engine() -> ZeroTrustEngine:
    return get_zero_trust_engine()


# ============================================================================
# Request / Response models
# ============================================================================


class CreatePolicyRequest(BaseModel):
    name: str = Field(..., description="Human-readable policy name")
    conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Policy conditions: min_trust_level, require_mfa, allowed_networks, "
            "allowed_time_ranges, require_compliant_device, max_risk_score"
        ),
    )
    action: str = Field(
        ..., description="allow | deny | step_up_auth | quarantine | monitor"
    )
    priority: int = Field(50, ge=0, le=1000, description="Lower = higher priority")
    org_id: str = Field("default", description="Organisation identifier")


class UpdatePolicyRequest(BaseModel):
    name: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    action: Optional[str] = None
    priority: Optional[int] = Field(None, ge=0, le=1000)
    active: Optional[bool] = None


class EvaluateRequest(BaseModel):
    user_id: str
    org_id: str = "default"
    resource: str = ""
    device_id: str = ""
    device_compliant: bool = False
    network_ip: str = ""
    mfa_verified: bool = False
    user_risk_score: float = Field(0.0, ge=0.0, le=100.0)
    timestamp: Optional[str] = None


class TrustScoreRequest(BaseModel):
    user_id: str = ""
    device_compliant: bool = False
    mfa_verified: bool = False
    user_risk_score: float = Field(0.0, ge=0.0, le=100.0)


# ============================================================================
# Endpoints — policy CRUD
# ============================================================================


@router.post("/policies", response_model=Dict[str, Any], status_code=201)
async def create_policy(body: CreatePolicyRequest) -> Dict[str, Any]:
    """Create a zero-trust access policy."""
    try:
        return _engine().create_policy(
            name=body.name,
            conditions=body.conditions,
            action=body.action,
            priority=body.priority,
            org_id=body.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("create_policy failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/policies", response_model=List[Dict[str, Any]])
async def list_policies(
    org_id: str = Query("default"),
    active_only: bool = Query(True),
) -> List[Dict[str, Any]]:
    """List zero-trust policies."""
    return _engine().list_policies(org_id=org_id, active_only=active_only)


@router.get("/policies/{policy_id}", response_model=Dict[str, Any])
async def get_policy(policy_id: str) -> Dict[str, Any]:
    """Get a single zero-trust policy by ID."""
    policy = _engine().get_policy(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")
    return policy


@router.put("/policies/{policy_id}", response_model=Dict[str, Any])
async def update_policy(policy_id: str, body: UpdatePolicyRequest) -> Dict[str, Any]:
    """Update a zero-trust policy."""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        return _engine().update_policy(policy_id, **updates)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("update_policy failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete("/policies/{policy_id}", response_model=Dict[str, Any])
async def delete_policy(policy_id: str) -> Dict[str, Any]:
    """Delete a zero-trust policy."""
    deleted = _engine().delete_policy(policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")
    return {"deleted": True, "policy_id": policy_id}


# ============================================================================
# Endpoints — access evaluation
# ============================================================================


@router.post("/evaluate", response_model=Dict[str, Any])
async def evaluate_access(body: EvaluateRequest) -> Dict[str, Any]:
    """Evaluate an access request against all active zero-trust policies."""
    from datetime import datetime, timezone

    request_dict = body.model_dump()
    if request_dict.get("timestamp") is None:
        request_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    try:
        return _engine().evaluate_access(request_dict)
    except Exception as exc:
        _logger.exception("evaluate_access failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/trust-score", response_model=Dict[str, Any])
async def compute_trust_score(body: TrustScoreRequest) -> Dict[str, Any]:
    """Compute trust score for a context without recording an access decision."""
    return _engine().compute_trust_score(body.model_dump())


# ============================================================================
# Endpoints — access log & analytics
# ============================================================================


@router.get("/access-log", response_model=List[Dict[str, Any]])
async def get_access_log(
    user_id: Optional[str] = Query(None),
    org_id: str = Query("default"),
    decision: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """Query the zero-trust access evaluation log."""
    return _engine().get_access_log(
        user_id=user_id, org_id=org_id, decision=decision, limit=limit
    )


@router.get("/analytics", response_model=Dict[str, Any])
async def get_analytics(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return trust analytics: rates, averages, decision breakdown."""
    return _engine().get_trust_analytics(org_id=org_id)


@router.get("/trust-score/{subject_id}", response_model=Dict[str, Any])
async def get_trust_score(
    subject_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get trust score and factor breakdown for a subject (user or device)."""
    return _engine().get_trust_score(subject_id=subject_id, org_id=org_id)


@router.get("/stats", response_model=Dict[str, Any])
async def get_policy_stats(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return policy effectiveness stats: allows/denies/challenges today, top denied resources."""
    return _engine().get_policy_stats(org_id=org_id)


@router.get("/segments", response_model=Dict[str, Any])
async def get_micro_segmentation_map(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return network zone micro-segmentation map with allowed paths."""
    return _engine().get_micro_segmentation_map(org_id=org_id)
