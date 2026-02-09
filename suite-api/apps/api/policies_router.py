"""
Policy management API endpoints.

Advanced features: policy-as-code engine with rule evaluation,
auto-enforcement against findings, policy simulation/dry-run,
conflict detection between overlapping policies, and OPA-style
rule evaluation with severity/threshold/pattern matching.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.dependencies import get_org_id
from core.policy_db import PolicyDB
from core.policy_models import Policy, PolicyStatus

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])
db = PolicyDB()

# In-memory violation store (prod would be DB-backed)
_violation_store: Dict[str, List[Dict[str, Any]]] = {}  # policy_id -> violations


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


# ---------------------------------------------------------------------------
# Policy-as-code engine helpers
# ---------------------------------------------------------------------------

_VALID_RULE_KEYS = {"condition", "action", "severity", "threshold", "pattern", "field", "operator", "value"}
_VALID_OPERATORS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "matches", "contains"}
_VALID_ACTIONS = {"block", "warn", "notify", "auto_remediate", "quarantine", "escalate"}


def _validate_rules(rules: Dict[str, Any]) -> List[str]:
    """Deep-validate policy rules structure."""
    errors: List[str] = []
    if not rules:
        errors.append("Policy rules cannot be empty")
        return errors
    conditions = rules.get("conditions", [])
    if not isinstance(conditions, list):
        errors.append("rules.conditions must be a list")
        return errors
    for i, cond in enumerate(conditions):
        if not isinstance(cond, dict):
            errors.append(f"conditions[{i}] must be an object")
            continue
        if "field" not in cond:
            errors.append(f"conditions[{i}] missing 'field'")
        op = cond.get("operator", "")
        if op and op not in _VALID_OPERATORS:
            errors.append(f"conditions[{i}] invalid operator '{op}' — must be one of {sorted(_VALID_OPERATORS)}")
        if "value" not in cond and op not in ("matches",):
            errors.append(f"conditions[{i}] missing 'value'")
    actions = rules.get("actions", [])
    if not isinstance(actions, list):
        errors.append("rules.actions must be a list")
    else:
        for i, act in enumerate(actions):
            atype = act.get("type", "") if isinstance(act, dict) else act
            if atype not in _VALID_ACTIONS:
                errors.append(f"actions[{i}] invalid type '{atype}' — must be one of {sorted(_VALID_ACTIONS)}")
    return errors


def _evaluate_condition(cond: Dict[str, Any], data: Dict[str, Any]) -> bool:
    """Evaluate a single policy condition against data."""
    field = cond.get("field", "")
    op = cond.get("operator", "eq")
    expected = cond.get("value")
    actual = data.get(field)
    if actual is None:
        return False
    try:
        if op == "eq":
            return str(actual).lower() == str(expected).lower()
        elif op == "ne":
            return str(actual).lower() != str(expected).lower()
        elif op == "gt":
            return float(actual) > float(expected)
        elif op == "gte":
            return float(actual) >= float(expected)
        elif op == "lt":
            return float(actual) < float(expected)
        elif op == "lte":
            return float(actual) <= float(expected)
        elif op == "in":
            return str(actual).lower() in [str(v).lower() for v in (expected if isinstance(expected, list) else [expected])]
        elif op == "not_in":
            return str(actual).lower() not in [str(v).lower() for v in (expected if isinstance(expected, list) else [expected])]
        elif op == "matches":
            return bool(re.search(str(expected), str(actual), re.IGNORECASE))
        elif op == "contains":
            return str(expected).lower() in str(actual).lower()
    except (ValueError, TypeError):
        return False
    return False


def _evaluate_policy(policy: Policy, data_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Evaluate a policy against a list of data items. Returns violations."""
    conditions = policy.rules.get("conditions", [])
    logic = policy.rules.get("logic", "all")  # all = AND, any = OR
    violations: List[Dict[str, Any]] = []
    for item in data_items:
        results = [_evaluate_condition(c, item) for c in conditions]
        triggered = all(results) if logic == "all" else any(results)
        if triggered:
            violations.append({
                "id": str(uuid.uuid4()),
                "policy_id": policy.id,
                "policy_name": policy.name,
                "item": item,
                "matched_conditions": [c for c, r in zip(conditions, results) if r],
                "actions": policy.rules.get("actions", []),
                "severity": policy.rules.get("severity", "medium"),
                "detected_at": datetime.now(timezone.utc).isoformat(),
            })
    return violations


@router.post("/{id}/validate")
async def validate_policy(id: str):
    """Validate policy syntax and rules.

    Deep-validates conditions, operators, actions, and structure.
    """
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    errors = _validate_rules(policy.rules)
    return {
        "policy_id": id,
        "valid": len(errors) == 0,
        "errors": errors,
        "rules_summary": {
            "conditions_count": len(policy.rules.get("conditions", [])),
            "actions_count": len(policy.rules.get("actions", [])),
            "logic": policy.rules.get("logic", "all"),
        },
    }


@router.post("/{id}/test")
async def test_policy(id: str, test_data: Dict[str, Any]):
    """Test policy against sample data (dry-run).

    Provide {"items": [...]} to evaluate the policy conditions.
    """
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    items = test_data.get("items", [test_data] if test_data else [])
    violations = _evaluate_policy(policy, items)
    return {
        "policy_id": id,
        "test_result": "violated" if violations else "passed",
        "items_tested": len(items),
        "violations_found": len(violations),
        "violations": violations[:50],
    }


@router.get("/{id}/violations")
async def get_policy_violations(id: str, limit: int = Query(100, ge=1, le=1000)):
    """Get recorded policy violations."""
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    violations = _violation_store.get(id, [])[:limit]
    return {"policy_id": id, "violations": violations, "total": len(_violation_store.get(id, []))}


# ---------------------------------------------------------------------------
# Advanced: Auto-enforce, simulate, conflict detection
# ---------------------------------------------------------------------------


@router.post("/{id}/enforce")
async def enforce_policy(id: str):
    """Auto-enforce a policy against current findings.

    Evaluates the policy against all open findings and records violations.
    """
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if policy.status != PolicyStatus.ACTIVE:
        raise HTTPException(status_code=400, detail="Only active policies can be enforced")

    # Fetch findings from the findings DB
    findings_data: List[Dict[str, Any]] = []
    try:
        from core.findings_db import FindingsDB
        fdb = FindingsDB()
        findings = fdb.list_findings(limit=10000)
        for f in findings:
            findings_data.append(f.to_dict() if hasattr(f, "to_dict") else {"id": str(f)})
    except Exception:
        pass

    violations = _evaluate_policy(policy, findings_data)
    _violation_store.setdefault(id, []).extend(violations)

    return {
        "policy_id": id,
        "findings_evaluated": len(findings_data),
        "violations_found": len(violations),
        "actions_triggered": [v.get("actions") for v in violations[:10]],
        "enforced_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/simulate")
async def simulate_policies(test_data: Dict[str, Any]):
    """Simulate ALL active policies against test data (bulk dry-run).

    Provide {"items": [...]} to evaluate all active policies.
    """
    items = test_data.get("items", [test_data] if test_data else [])
    policies = db.list_policies(limit=10000)
    active_policies = [p for p in policies if p.status == PolicyStatus.ACTIVE]

    results: List[Dict[str, Any]] = []
    total_violations = 0
    for policy in active_policies:
        violations = _evaluate_policy(policy, items)
        total_violations += len(violations)
        results.append({
            "policy_id": policy.id,
            "policy_name": policy.name,
            "violations": len(violations),
            "details": violations[:5],
        })

    return {
        "policies_evaluated": len(active_policies),
        "items_tested": len(items),
        "total_violations": total_violations,
        "results": results,
    }


@router.get("/conflicts")
async def detect_conflicts():
    """Detect conflicts between overlapping policies.

    Finds policies whose conditions overlap on the same fields with
    contradictory actions (e.g., one blocks, another allows).
    """
    policies = db.list_policies(limit=10000)
    active = [p for p in policies if p.status == PolicyStatus.ACTIVE]

    conflicts: List[Dict[str, Any]] = []
    for i, p1 in enumerate(active):
        for p2 in active[i + 1:]:
            p1_fields = {c.get("field") for c in p1.rules.get("conditions", []) if isinstance(c, dict)}
            p2_fields = {c.get("field") for c in p2.rules.get("conditions", []) if isinstance(c, dict)}
            overlap = p1_fields & p2_fields - {None}
            if not overlap:
                continue
            p1_actions = {(a.get("type") if isinstance(a, dict) else a) for a in p1.rules.get("actions", [])}
            p2_actions = {(a.get("type") if isinstance(a, dict) else a) for a in p2.rules.get("actions", [])}
            if p1_actions != p2_actions:
                conflicts.append({
                    "policy_a": {"id": p1.id, "name": p1.name, "actions": list(p1_actions)},
                    "policy_b": {"id": p2.id, "name": p2.name, "actions": list(p2_actions)},
                    "overlapping_fields": list(overlap),
                    "severity": "high" if {"block", "auto_remediate"} & (p1_actions | p2_actions) else "medium",
                })

    return {"conflicts": conflicts, "total": len(conflicts)}
