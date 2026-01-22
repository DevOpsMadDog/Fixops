"""
Policy management API endpoints.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.dependencies import get_org_id
from core.policy_db import PolicyDB
from core.policy_models import Policy, PolicyStatus

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])
db = PolicyDB()


class PolicyCreate(BaseModel):
    """Request model for creating a policy."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str
    policy_type: str = Field(
        ..., description="Policy type (guardrail, compliance, custom)"
    )
    status: PolicyStatus = PolicyStatus.DRAFT
    rules: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PolicyUpdate(BaseModel):
    """Request model for updating a policy."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    policy_type: Optional[str] = None
    status: Optional[PolicyStatus] = None
    rules: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class PolicyResponse(BaseModel):
    """Response model for a policy."""

    id: str
    name: str
    description: str
    policy_type: str
    status: str
    rules: Dict[str, Any]
    metadata: Dict[str, Any]
    created_by: Optional[str]
    created_at: str
    updated_at: str


class PaginatedPolicyResponse(BaseModel):
    """Paginated policy response."""

    items: List[PolicyResponse]
    total: int
    limit: int
    offset: int


@router.get("", response_model=PaginatedPolicyResponse)
async def list_policies(
    org_id: str = Depends(get_org_id),
    policy_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all policies with optional filtering."""
    policies = db.list_policies(policy_type=policy_type, limit=limit, offset=offset)
    return {
        "items": [PolicyResponse(**p.to_dict()) for p in policies],
        "total": len(policies),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(policy_data: PolicyCreate):
    """Create a new policy."""
    policy = Policy(
        id="",
        name=policy_data.name,
        description=policy_data.description,
        policy_type=policy_data.policy_type,
        status=policy_data.status,
        rules=policy_data.rules,
        metadata=policy_data.metadata,
    )
    created_policy = db.create_policy(policy)
    return PolicyResponse(**created_policy.to_dict())


@router.get("/{id}", response_model=PolicyResponse)
async def get_policy(id: str):
    """Get policy details by ID."""
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return PolicyResponse(**policy.to_dict())


@router.put("/{id}", response_model=PolicyResponse)
async def update_policy(id: str, policy_data: PolicyUpdate):
    """Update a policy."""
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if policy_data.name is not None:
        policy.name = policy_data.name
    if policy_data.description is not None:
        policy.description = policy_data.description
    if policy_data.policy_type is not None:
        policy.policy_type = policy_data.policy_type
    if policy_data.status is not None:
        policy.status = policy_data.status
    if policy_data.rules is not None:
        policy.rules = policy_data.rules
    if policy_data.metadata is not None:
        policy.metadata = policy_data.metadata

    updated_policy = db.update_policy(policy)
    return PolicyResponse(**updated_policy.to_dict())


@router.delete("/{id}", status_code=204)
async def delete_policy(id: str):
    """Delete a policy."""
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete_policy(id)
    return None


@router.post("/{id}/validate")
async def validate_policy(id: str):
    """Validate policy syntax and rules."""
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    errors = []
    if not policy.rules:
        errors.append("Policy rules cannot be empty")

    return {
        "policy_id": id,
        "valid": len(errors) == 0,
        "errors": errors,
    }


@router.post("/{id}/test")
async def test_policy(id: str, test_data: Dict[str, Any]):
    """Test policy against sample data."""
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return {
        "policy_id": id,
        "test_result": "passed",
        "message": "Policy test not yet implemented",
    }


@router.get("/{id}/violations")
async def get_policy_violations(id: str, limit: int = Query(100, ge=1, le=1000)):
    """Get policy violations."""
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return {
        "policy_id": id,
        "violations": [],
        "total": 0,
    }
