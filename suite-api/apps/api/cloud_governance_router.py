"""Cloud Governance Router — ALDECI.

Multi-cloud governance policy and violation management endpoints.

Prefix: /api/v1/cloud-governance
Auth:   api_key_auth dependency

Routes:
  POST   /policies                              create_governance_policy
  GET    /policies                              list_governance_policies
  GET    /policies/{policy_id}                  get_governance_policy
  POST   /violations                            record_violation
  GET    /violations                            list_violations
  PUT    /violations/{violation_id}/remediate   remediate_violation
  GET    /stats                                 get_governance_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-governance",
    tags=["cloud-governance"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------
_engine_cache: Dict[str, Any] = {}


def _get_engine(org_id: str):
    if org_id not in _engine_cache:
        from core.cloud_governance_engine import get_engine
        _engine_cache[org_id] = get_engine(org_id)
    return _engine_cache[org_id]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class PolicyCreate(BaseModel):
    name: str
    policy_type: str = Field(..., description="access/cost/security/compliance/resource/tagging")
    cloud_provider: str = Field("multi_cloud", description="aws/azure/gcp/multi_cloud/on_premise")
    enforcement: str = Field("advisory", description="advisory/warning/blocking")
    description: str = ""


class ViolationCreate(BaseModel):
    policy_id: str
    resource_id: str
    resource_type: str
    violation_details: str = ""
    severity: str = Field("medium", description="low/medium/high/critical")


class RemediateRequest(BaseModel):
    remediated_by: str
    action_taken: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/policies", response_model=Dict[str, Any], status_code=201)
def create_governance_policy(
    body: PolicyCreate,
    org_id: str = Query("default", description="Organisation ID"),
):
    """Create a new cloud governance policy."""
    try:
        return _get_engine(org_id).create_governance_policy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/policies")
def list_governance_policies(
    org_id: str = Query("default"),
    policy_type: Optional[str] = Query(None, description="Filter by policy_type"),
    cloud_provider: Optional[str] = Query(None, description="Filter by cloud_provider"),
    enforcement: Optional[str] = Query(None, description="Filter by enforcement"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List governance policies (canonical envelope, batch-6).

    Class-c contract: empty IS correct for fresh tenants — cloud governance
    policies are manually authored by org compliance teams, not auto-derived
    from a public catalog. Always returns full envelope with pagination
    context + filters echo + actionable hint when empty.
    """
    rows = _get_engine(org_id).list_governance_policies(
        org_id,
        policy_type=policy_type,
        cloud_provider=cloud_provider,
        enforcement=enforcement,
    ) or []
    paged = rows[offset : offset + limit] if offset else rows[:limit]
    envelope = {
        "items": paged,
        "policies": paged,  # legacy key preserved
        "total": len(rows),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
        "filters_applied": {
            "policy_type": policy_type,
            "cloud_provider": cloud_provider,
            "enforcement": enforcement,
        },
    }
    if not rows:
        envelope["hint"] = (
            "Create governance policies via POST /api/v1/cloud-governance/policies "
            "(manual policy authoring). Empty IS the correct response for a fresh "
            "tenant — no public source exists."
        )
    return envelope


@router.get("/policies/{policy_id}", response_model=Dict[str, Any])
def get_governance_policy(
    policy_id: str,
    org_id: str = Query("default"),
):
    """Return a single governance policy."""
    result = _get_engine(org_id).get_governance_policy(org_id, policy_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Policy not found.")
    return result


@router.post("/violations", response_model=Dict[str, Any], status_code=201)
def record_violation(
    body: ViolationCreate,
    org_id: str = Query("default"),
):
    """Record a new policy violation."""
    try:
        return _get_engine(org_id).record_violation(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/violations", response_model=List[Dict[str, Any]])
def list_violations(
    org_id: str = Query("default"),
    policy_id: Optional[str] = Query(None, description="Filter by policy_id"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
):
    """List violations with optional filters."""
    return _get_engine(org_id).list_violations(
        org_id,
        policy_id=policy_id,
        severity=severity,
        status=status,
    )


@router.put("/violations/{violation_id}/remediate", response_model=Dict[str, Any])
def remediate_violation(
    violation_id: str,
    body: RemediateRequest,
    org_id: str = Query("default"),
):
    """Mark a violation as remediated."""
    result = _get_engine(org_id).remediate_violation(
        org_id, violation_id, body.remediated_by, body.action_taken
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Violation not found.")
    return result


@router.get("/stats", response_model=Dict[str, Any])
def get_governance_stats(
    org_id: str = Query("default"),
):
    """Return aggregated cloud governance statistics."""
    return _get_engine(org_id).get_governance_stats(org_id)
