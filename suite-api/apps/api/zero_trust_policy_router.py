"""Zero Trust Policy Router — ALDECI.

Prefix: /api/v1/zero-trust-policy
Auth: api_key_auth dependency

Endpoints:
  GET    /policies                    list_policies
  POST   /policies                    create_policy
  GET    /policies/{policy_id}        get_policy
  PUT    /policies/{policy_id}        update_policy
  DELETE /policies/{policy_id}        delete_policy
  POST   /evaluate                    evaluate_access
  GET    /access-events               list_access_events
  POST   /access-events               record_access_event
  GET    /stats                       get_policy_stats
  GET    /compliance                  get_compliance_posture
"""
from __future__ import annotations

from typing import Annotated, Any, Dict, List, Literal, Optional

import structlog
from apps.api.auth_deps import api_key_auth
from core.zero_trust_policy_engine import (
    ZeroTrustPolicyEngine,
    get_zero_trust_policy_engine,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1/zero-trust-policy", tags=["zero-trust-policy"])

# ---------------------------------------------------------------------------
# Reusable annotated types — constraints are enforced by Pydantic at parse time
# ---------------------------------------------------------------------------
_PolicyName = Annotated[str, Field(min_length=1, max_length=255)]
_Description = Annotated[str, Field(max_length=2000)]
_PolicyType = Annotated[
    Literal["network", "identity", "device", "application"],
    Field(description="network | identity | device | application"),
]
_Action = Annotated[
    Literal["allow", "deny", "mfa_required"],
    Field(description="allow | deny | mfa_required"),
]
_Decision = Annotated[
    Literal["allow", "deny", "mfa_required"],
    Field(description="allow | deny | mfa_required"),
]
_OrgId = Annotated[str, Field(min_length=1, max_length=128)]
_UserId = Annotated[str, Field(max_length=255)]
_IpAddr = Annotated[str, Field(max_length=45, pattern=r"^$|^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$|^[0-9a-fA-F:]+(/\d{1,3})?$")]
_Resource = Annotated[str, Field(max_length=2048)]


def _engine() -> ZeroTrustPolicyEngine:
    return get_zero_trust_policy_engine()


# ============================================================================
# Request / Response models
# ============================================================================


class CreatePolicyRequest(BaseModel):
    name: _PolicyName = Field(..., description="Human-readable policy name")
    description: _Description = Field("", description="Optional description")
    policy_type: _PolicyType = Field("network", description="network | identity | device | application")
    action: _Action = Field("deny", description="allow | deny | mfa_required")
    source_conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Source-side match conditions (user, device, source_ip)",
    )
    destination_conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Destination-side match conditions (resource, destination)",
    )
    priority: int = Field(50, ge=0, le=1000, description="Lower = higher priority")
    enabled: bool = Field(True, description="Whether this policy is active")


class UpdatePolicyRequest(BaseModel):
    name: Optional[_PolicyName] = None
    description: Optional[_Description] = None
    policy_type: Optional[_PolicyType] = None
    action: Optional[_Action] = None
    source_conditions: Optional[Dict[str, Any]] = None
    destination_conditions: Optional[Dict[str, Any]] = None
    priority: Optional[int] = Field(None, ge=0, le=1000)
    enabled: Optional[bool] = None


class EvaluateAccessRequest(BaseModel):
    user: _UserId = Field("", description="User identifier")
    device: _UserId = Field("", description="Device identifier")
    source_ip: _IpAddr = Field("", description="Source IP address (IPv4/IPv6/CIDR or blank)")
    destination: _Resource = Field("", description="Destination resource or host")
    resource: _Resource = Field("", description="Resource being accessed")
    org_id: _OrgId = Field("default", description="Organisation identifier")


class RecordAccessEventRequest(BaseModel):
    user: _UserId = Field("", description="User identifier")
    device: _UserId = Field("", description="Device identifier")
    resource: _Resource = Field("", description="Resource accessed")
    decision: _Decision = Field("allow", description="allow | deny | mfa_required")
    policy_id: Optional[str] = Field(None, max_length=128, description="Policy that matched")
    source_ip: _IpAddr = Field("", description="Source IP address (IPv4/IPv6/CIDR or blank)")
    org_id: _OrgId = Field("default", description="Organisation identifier")


# ============================================================================
# Root summary
# ============================================================================


@router.get("/", response_model=Dict[str, Any])
async def get_summary(
    org_id: str = Query("default"),
    _auth: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return a top-level summary of Zero Trust policy state for an org."""
    eng = _engine()
    stats = eng.get_policy_stats(org_id=org_id)
    posture = eng.get_compliance_posture(org_id=org_id)
    return {
        "service": "zero-trust-policy",
        "org_id": org_id,
        "total_policies": stats["total_policies"],
        "enabled_policies": stats["enabled_policies"],
        "access_events_24h": stats["access_events_24h"],
        "zt_maturity_score": posture["zt_maturity_score"],
        "top_recommendation": posture["recommendations"][0] if posture["recommendations"] else None,
    }


# ============================================================================
# Policy CRUD
# ============================================================================


@router.get("/policies", response_model=List[Dict[str, Any]])
async def list_policies(
    org_id: str = Query("default"),
    policy_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    _auth: Any = Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List Zero Trust policies for an org."""
    return _engine().list_policies(org_id=org_id, policy_type=policy_type, enabled=enabled)


@router.post("/policies", response_model=Dict[str, Any], status_code=201)
async def create_policy(
    body: CreatePolicyRequest,
    org_id: str = Query("default"),
    _auth: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Create a Zero Trust policy."""
    try:
        return _engine().create_policy(org_id=org_id, data=body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("create_policy failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/policies/{policy_id}", response_model=Dict[str, Any])
async def get_policy(
    policy_id: str,
    org_id: str = Query("default"),
    _auth: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get a single Zero Trust policy by ID."""
    policy = _engine().get_policy(org_id=org_id, policy_id=policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")
    return policy


@router.put("/policies/{policy_id}", response_model=Dict[str, Any])
async def update_policy(
    policy_id: str,
    body: UpdatePolicyRequest,
    org_id: str = Query("default"),
    _auth: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Update a Zero Trust policy."""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        return _engine().update_policy(org_id=org_id, policy_id=policy_id, updates=updates)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("update_policy failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete("/policies/{policy_id}", response_model=Dict[str, Any])
async def delete_policy(
    policy_id: str,
    org_id: str = Query("default"),
    _auth: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Delete a Zero Trust policy."""
    deleted = _engine().delete_policy(org_id=org_id, policy_id=policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")
    return {"deleted": True, "policy_id": policy_id}


# ============================================================================
# Access evaluation
# ============================================================================


@router.post("/evaluate", response_model=Dict[str, Any])
async def evaluate_access(
    body: EvaluateAccessRequest,
    _auth: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Evaluate an access request against active Zero Trust policies."""
    try:
        return _engine().evaluate_access(
            org_id=body.org_id,
            request=body.model_dump(exclude={"org_id"}),
        )
    except Exception as exc:
        _logger.exception("evaluate_access failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# Access events
# ============================================================================


@router.get("/access-events", response_model=List[Dict[str, Any]])
async def list_access_events(
    org_id: str = Query("default"),
    decision: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    _auth: Any = Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List access events for an org."""
    return _engine().list_access_events(org_id=org_id, decision=decision, limit=limit)


@router.post("/access-events", response_model=Dict[str, Any], status_code=201)
async def record_access_event(
    body: RecordAccessEventRequest,
    _auth: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Record an access event manually."""
    return _engine().record_access_event(
        org_id=body.org_id,
        data=body.model_dump(exclude={"org_id"}),
    )


# ============================================================================
# Statistics & compliance
# ============================================================================


@router.get("/stats", response_model=Dict[str, Any])
async def get_policy_stats(
    org_id: str = Query("default"),
    _auth: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return policy and access event statistics."""
    return _engine().get_policy_stats(org_id=org_id)


@router.get("/compliance", response_model=Dict[str, Any])
async def get_compliance_posture(
    org_id: str = Query("default"),
    _auth: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return Zero Trust maturity score, pillar breakdown, and recommendations."""
    return _engine().get_compliance_posture(org_id=org_id)
