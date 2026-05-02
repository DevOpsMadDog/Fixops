"""Policy Router — ALDECI.

Endpoints for the Policy-as-Code engine (Zero Trust policy evaluation).

Prefix: /api/v1/policies
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/policies                    list_policies
  POST   /api/v1/policies                    create_policy
  GET    /api/v1/policies/{policy_id}         get_policy
  PATCH  /api/v1/policies/{policy_id}         update_policy
  DELETE /api/v1/policies/{policy_id}         delete_policy
  POST   /api/v1/policies/evaluate            evaluate
  POST   /api/v1/policies/evaluate/batch      evaluate_batch
  GET    /api/v1/policies/stats               get_stats
  GET    /api/v1/policies/history             get_history
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/policies",
    tags=["Policy Engine"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.policy_engine import get_policy_engine
        _engine = get_policy_engine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    scope: str  # PolicyScope value e.g. "findings", "deployments"
    language: str = "aldeci_rules"
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    decision_on_match: str = "deny"
    enabled: bool = True
    org_id: str = "default"


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scope: Optional[str] = None
    language: Optional[str] = None
    rules: Optional[List[Dict[str, Any]]] = None
    decision_on_match: Optional[str] = None
    enabled: Optional[bool] = None


class EvaluateRequest(BaseModel):
    input_data: Dict[str, Any]
    scope: str  # PolicyScope value
    org_id: str = "default"


class BatchEvaluateRequest(BaseModel):
    requests: List[EvaluateRequest]


# ---------------------------------------------------------------------------
# Routes — fixed paths before parameterised ones
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate policy and evaluation statistics."""
    return _get_engine().get_policy_stats(org_id=org_id)


@router.get("/history", dependencies=[Depends(api_key_auth)])
def get_history(
    org_id: str = Query(default="default"),
    policy_id: Optional[str] = Query(None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """Return evaluation history for the org."""
    evals = _get_engine().get_evaluation_history(
        org_id=org_id, policy_id=policy_id, limit=limit
    )
    return [e.model_dump() for e in evals]


@router.post("/evaluate", dependencies=[Depends(api_key_auth)])
def evaluate_policy(body: EvaluateRequest):
    """Evaluate input data against all enabled policies for the given scope."""
    from core.policy_engine import PolicyScope
    try:
        scope = PolicyScope(body.scope)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scope '{body.scope}'. Valid: {[s.value for s in PolicyScope]}",
        )
    result = _get_engine().evaluate(
        input_data=body.input_data,
        scope=scope,
        org_id=body.org_id,
    )
    return result.model_dump()


@router.post("/evaluate/batch", dependencies=[Depends(api_key_auth)])
def evaluate_batch(body: BatchEvaluateRequest):
    """Evaluate multiple inputs. Returns one evaluation per input."""
    from core.policy_engine import PolicyScope
    results = []
    for req in body.requests:
        try:
            scope = PolicyScope(req.scope)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scope '{req.scope}'. Valid: {[s.value for s in PolicyScope]}",
            )
        result = _get_engine().evaluate(
            input_data=req.input_data,
            scope=scope,
            org_id=req.org_id,
        )
        results.append(result.model_dump())
    return results


@router.get("", dependencies=[Depends(api_key_auth)])
def list_policies(
    org_id: str = Query(default="default"),
    scope: Optional[str] = Query(None),
):
    """List policies for an org, optionally filtered by scope."""
    from core.policy_engine import PolicyScope
    scope_enum = None
    if scope:
        try:
            scope_enum = PolicyScope(scope)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scope '{scope}'. Valid: {[s.value for s in PolicyScope]}",
            )
    policies = _get_engine().list_policies(org_id=org_id, scope=scope_enum)
    return [p.model_dump() for p in policies]


@router.post("", dependencies=[Depends(api_key_auth)], status_code=201)
def create_policy(body: PolicyCreate):
    """Create a new policy."""
    from core.policy_engine import Policy, PolicyDecision, PolicyLanguage, PolicyScope
    try:
        policy = Policy(
            name=body.name,
            description=body.description,
            scope=PolicyScope(body.scope),
            language=PolicyLanguage(body.language),
            rules=body.rules,
            decision_on_match=PolicyDecision(body.decision_on_match),
            enabled=body.enabled,
            org_id=body.org_id,
        )
        result = _get_engine().create_policy(policy)
        return result.model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{policy_id}", dependencies=[Depends(api_key_auth)])
def get_policy(policy_id: str, org_id: str = Query(default="default")):
    """Get a single policy by ID."""
    policies = _get_engine().list_policies(org_id=org_id)
    match = next((p for p in policies if p.id == policy_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="Policy not found")
    return match.model_dump()


@router.patch("/{policy_id}", dependencies=[Depends(api_key_auth)])
def update_policy(policy_id: str, body: PolicyUpdate):
    """Update fields on an existing policy."""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        result = _get_engine().update_policy(policy_id, updates)
        return result.model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/{policy_id}", dependencies=[Depends(api_key_auth)])
def delete_policy(policy_id: str):
    """Delete a policy by ID."""
    try:
        _get_engine().delete_policy(policy_id)
        return {"deleted": True}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
