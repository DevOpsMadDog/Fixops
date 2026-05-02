"""Zero Trust Enforcement Router — ALDECI.

Prefix: /api/v1/zero-trust
Auth: api_key_auth dependency (lazy singleton engine)

Endpoints:
  GET    /policies                     list_policies
  POST   /policies                     create_policy
  GET    /policies/{id}                get_policy
  PATCH  /policies/{id}                update_policy
  POST   /evaluate                     evaluate_access
  GET    /trust-scores                 list_trust_scores
  POST   /trust-scores                 set_trust_score
  GET    /trust-scores/{entity_id}     get_trust_score
  GET    /sessions                     list_sessions
  POST   /sessions                     create_session
  POST   /sessions/{id}/revoke         revoke_session
  GET    /access-log                   list_access_requests
  GET    /stats                        get_stats

Compliance: NIST SP 800-207 Zero Trust Architecture
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/zero-trust",
    tags=["Zero Trust Enforcement"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.zero_trust_enforcement_engine import get_zero_trust_enforcement_engine
        _engine = get_zero_trust_enforcement_engine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class PolicyConditions(BaseModel):
    min_trust_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    require_mfa: Optional[bool] = None
    allowed_locations: Optional[List[str]] = None
    allowed_device_types: Optional[List[str]] = None
    time_restrictions: Optional[Dict[str, Any]] = None


class CreatePolicyRequest(BaseModel):
    policy_name: str = Field(..., description="Human-readable policy name")
    resource_type: str = Field(
        "application",
        description="application | api | database | network_segment | cloud_service",
    )
    action: str = Field(
        ...,
        description="allow | deny | mfa_required | device_check_required",
    )
    principal_type: str = Field(
        "user",
        description="user | group | service_account | device",
    )
    conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Conditions: min_trust_score, require_mfa, allowed_locations, "
                    "allowed_device_types, time_restrictions",
    )
    priority: int = Field(50, ge=1, le=100, description="1=highest, 100=lowest")


class UpdatePolicyRequest(BaseModel):
    policy_name: Optional[str] = None
    resource_type: Optional[str] = None
    action: Optional[str] = None
    principal_type: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    priority: Optional[int] = Field(None, ge=1, le=100)
    enabled: Optional[bool] = None


class EvaluateAccessRequest(BaseModel):
    principal_id: str
    principal_type: str = "user"
    resource_id: str
    resource_type: str = "application"
    action_requested: str = "read"
    source_ip: str = ""
    device_trust_score: float = Field(50.0, ge=0.0, le=100.0)
    user_trust_score: float = Field(50.0, ge=0.0, le=100.0)
    mfa_verified: bool = False
    location: str = ""
    device_type: str = ""


class SetTrustScoreRequest(BaseModel):
    entity_id: str
    entity_type: str = Field("user", description="user | device | service")
    trust_score: float = Field(..., ge=0.0, le=100.0)
    score_factors: Dict[str, Any] = Field(default_factory=dict)


class CreateSessionRequest(BaseModel):
    principal_id: str
    resource_id: str
    duration_hours: int = Field(8, ge=1, le=72)


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@router.get("/policies", response_model=List[Dict[str, Any]])
async def list_policies(
    org_id: str = Query("default"),
    resource_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List Zero Trust policies with optional filters."""
    return _get_engine().list_policies(
        org_id=org_id, resource_type=resource_type, enabled=enabled
    )


@router.post("/policies", response_model=Dict[str, Any], status_code=201)
async def create_policy(
    body: CreatePolicyRequest,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Create a new Zero Trust access policy."""
    try:
        return _get_engine().create_policy(org_id=org_id, data=body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("create_policy failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/policies/{policy_id}", response_model=Dict[str, Any])
async def get_policy(
    policy_id: str,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get a single Zero Trust policy by ID."""
    policy = _get_engine().get_policy(org_id=org_id, policy_id=policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")
    return policy


@router.patch("/policies/{policy_id}", response_model=Dict[str, Any])
async def update_policy(
    policy_id: str,
    body: UpdatePolicyRequest,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Update a Zero Trust policy."""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        return _get_engine().update_policy(
            org_id=org_id, policy_id=policy_id, updates=updates
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("update_policy failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete("/policies/{policy_id}", response_model=Dict[str, Any])
async def delete_policy(
    policy_id: str,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Delete a Zero Trust policy."""
    deleted = _get_engine().delete_policy(org_id=org_id, policy_id=policy_id)
    if not deleted:
        raise HTTPException(
            status_code=404, detail=f"Policy {policy_id!r} not found"
        )
    return {"deleted": True, "policy_id": policy_id}


# ---------------------------------------------------------------------------
# Access evaluation
# ---------------------------------------------------------------------------

@router.post("/evaluate", response_model=Dict[str, Any])
async def evaluate_access(
    body: EvaluateAccessRequest,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Evaluate an access request against all active Zero Trust policies."""
    try:
        return _get_engine().evaluate_access(org_id=org_id, data=body.model_dump())
    except Exception as exc:
        _logger.exception("evaluate_access failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Trust scores
# ---------------------------------------------------------------------------

@router.get("/trust-scores", response_model=List[Dict[str, Any]])
async def list_trust_scores(
    org_id: str = Query("default"),
    entity_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List trust scores with optional filters."""
    return _get_engine().list_trust_scores(
        org_id=org_id, entity_type=entity_type, status=status
    )


@router.post("/trust-scores", response_model=Dict[str, Any], status_code=201)
async def set_trust_score(
    body: SetTrustScoreRequest,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Create or update a trust score for an entity."""
    try:
        return _get_engine().set_trust_score(
            org_id=org_id,
            entity_id=body.entity_id,
            entity_type=body.entity_type,
            score=body.trust_score,
            factors=body.score_factors,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("set_trust_score failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/trust-scores/{entity_id}", response_model=Dict[str, Any])
async def get_trust_score(
    entity_id: str,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get trust score for a specific entity."""
    score = _get_engine().get_trust_score(org_id=org_id, entity_id=entity_id)
    if score is None:
        raise HTTPException(
            status_code=404, detail=f"Trust score for entity {entity_id!r} not found"
        )
    return score


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

@router.get("/sessions", response_model=List[Dict[str, Any]])
async def list_sessions(
    org_id: str = Query("default"),
    principal_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List Zero Trust sessions with optional filters."""
    return _get_engine().list_sessions(
        org_id=org_id, principal_id=principal_id, status=status
    )


@router.post("/sessions", response_model=Dict[str, Any], status_code=201)
async def create_session(
    body: CreateSessionRequest,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Create a new Zero Trust session."""
    try:
        return _get_engine().create_session(
            org_id=org_id,
            principal_id=body.principal_id,
            resource_id=body.resource_id,
            duration_hours=body.duration_hours,
        )
    except Exception as exc:
        _logger.exception("create_session failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/sessions/{session_id}/revoke", response_model=Dict[str, Any])
async def revoke_session(
    session_id: str,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Revoke an active session."""
    revoked = _get_engine().revoke_session(org_id=org_id, session_id=session_id)
    if not revoked:
        raise HTTPException(
            status_code=404,
            detail=f"Session {session_id!r} not found or already revoked",
        )
    return {"revoked": True, "session_id": session_id}


# ---------------------------------------------------------------------------
# Access log
# ---------------------------------------------------------------------------

@router.get("/access-log", response_model=List[Dict[str, Any]])
async def list_access_requests(
    org_id: str = Query("default"),
    decision: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """Query the Zero Trust access evaluation log."""
    return _get_engine().list_access_requests(
        org_id=org_id,
        decision=decision,
        resource_type=resource_type,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# Stats & compliance
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
async def get_stats(
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return Zero Trust stats: request rates, active sessions, trust scores."""
    return _get_engine().get_stats(org_id=org_id)


@router.get("/compliance", response_model=Dict[str, Any])
async def get_compliance_posture(
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return Zero Trust maturity score, pillar breakdown, and recommendations.

    Scores each ZT pillar (identity, device, network, application, data) based on
    active policy coverage and entity trust health. Aligned with NIST SP 800-207.
    """
    return _get_engine().get_compliance_posture(org_id=org_id)
