"""
Policy Engine REST API — 12 endpoints.

Provides CRUD, evaluation, testing, bulk import/export, history, and stats
for the ALDECI policy-as-code engine.

Prefix: /api/v1/policy-engine
Tags:   policy-engine
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from core.policy_engine import (
    Policy,
    PolicyDecision,
    PolicyLanguage,
    PolicyScope,
    get_policy_engine,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/policy-engine",
    tags=["policy-engine"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreatePolicyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")
    scope: PolicyScope
    language: PolicyLanguage = PolicyLanguage.ALDECI_RULES
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    decision_on_match: PolicyDecision = PolicyDecision.DENY
    enabled: bool = True


class UpdatePolicyRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    scope: Optional[PolicyScope] = None
    language: Optional[PolicyLanguage] = None
    rules: Optional[List[Dict[str, Any]]] = None
    decision_on_match: Optional[PolicyDecision] = None
    enabled: Optional[bool] = None


class EvaluateRequest(BaseModel):
    input_data: Dict[str, Any] = Field(default_factory=dict)
    scope: PolicyScope
    org_id: Optional[str] = None


class EvaluateBatchRequest(BaseModel):
    inputs: List[Dict[str, Any]] = Field(..., min_length=1)
    scope: PolicyScope
    org_id: Optional[str] = None


class TestPolicyRequest(BaseModel):
    policy: CreatePolicyRequest
    test_input: Dict[str, Any] = Field(default_factory=dict)


class ImportPoliciesRequest(BaseModel):
    policies_json: str = Field(..., min_length=2)
    org_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/policies", status_code=201)
async def create_policy(
    body: CreatePolicyRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a new policy."""
    engine = get_policy_engine()
    policy = Policy(
        name=body.name,
        description=body.description,
        scope=body.scope,
        language=body.language,
        rules=body.rules,
        decision_on_match=body.decision_on_match,
        enabled=body.enabled,
        org_id=org_id,
    )
    try:
        created = engine.create_policy(policy)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return created.model_dump()


@router.get("/policies")
async def list_policies(
    scope: Optional[PolicyScope] = Query(None, description="Filter by scope"),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List all policies for the org, optionally filtered by scope."""
    engine = get_policy_engine()
    policies = engine.list_policies(org_id=org_id, scope=scope)
    return {
        "policies": [p.model_dump() for p in policies],
        "total": len(policies),
        "org_id": org_id,
    }


@router.get("/policies/{policy_id}")
async def get_policy(
    policy_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Retrieve a single policy by ID."""
    engine = get_policy_engine()
    policies = engine.list_policies(org_id=org_id)
    for p in policies:
        if p.id == policy_id:
            return p.model_dump()
    raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")


@router.put("/policies/{policy_id}")
async def update_policy(
    policy_id: str,
    body: UpdatePolicyRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Update a policy (version auto-incremented)."""
    engine = get_policy_engine()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")
    try:
        updated = engine.update_policy(policy_id, updates)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return updated.model_dump()


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: str,
    org_id: str = Depends(get_org_id),
) -> None:
    """Delete a policy."""
    engine = get_policy_engine()
    try:
        engine.delete_policy(policy_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/evaluate")
async def evaluate(
    body: EvaluateRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Evaluate input data against all enabled policies for the given scope."""
    engine = get_policy_engine()
    effective_org_id = body.org_id or org_id
    result = engine.evaluate(
        input_data=body.input_data,
        scope=body.scope,
        org_id=effective_org_id,
    )
    return result.model_dump()


@router.post("/evaluate/batch")
async def evaluate_batch(
    body: EvaluateBatchRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Evaluate a list of inputs against policies. Returns one result per input."""
    engine = get_policy_engine()
    effective_org_id = body.org_id or org_id
    results = engine.evaluate_batch(
        inputs=body.inputs,
        scope=body.scope,
        org_id=effective_org_id,
    )
    return {
        "results": [r.model_dump() for r in results],
        "total": len(results),
        "scope": body.scope.value,
        "org_id": effective_org_id,
    }


@router.post("/test")
async def test_policy(
    body: TestPolicyRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Dry-run a policy definition against test input without persisting."""
    engine = get_policy_engine()
    policy = Policy(
        name=body.policy.name,
        description=body.policy.description,
        scope=body.policy.scope,
        language=body.policy.language,
        rules=body.policy.rules,
        decision_on_match=body.policy.decision_on_match,
        enabled=body.policy.enabled,
        org_id=org_id,
    )
    result = engine.test_policy(policy=policy, test_input=body.test_input)
    return result.model_dump()


@router.get("/history")
async def get_evaluation_history(
    policy_id: Optional[str] = Query(None, description="Filter by policy ID"),
    limit: int = Query(100, ge=1, le=1000),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return past evaluations, optionally filtered by policy."""
    engine = get_policy_engine()
    history = engine.get_evaluation_history(
        org_id=org_id, policy_id=policy_id, limit=limit
    )
    return {
        "history": [e.model_dump() for e in history],
        "total": len(history),
        "org_id": org_id,
    }


@router.get("/stats")
async def get_policy_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return aggregate policy and evaluation statistics."""
    engine = get_policy_engine()
    return engine.get_policy_stats(org_id=org_id)


@router.post("/import")
async def import_policies(
    body: ImportPoliciesRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Bulk-import policies from a JSON string."""
    engine = get_policy_engine()
    effective_org_id = body.org_id or org_id
    try:
        count = engine.import_policies(
            policies_json=body.policies_json, org_id=effective_org_id
        )
    except (ValueError, Exception) as exc:
        raise HTTPException(status_code=422, detail=f"Import failed: {exc}") from exc
    return {"imported": count, "org_id": effective_org_id}


@router.get("/export")
async def export_policies(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Export all org policies as JSON."""
    engine = get_policy_engine()
    exported = engine.export_policies(org_id=org_id)
    return {"data": exported, "org_id": org_id}
