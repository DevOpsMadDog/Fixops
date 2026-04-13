"""
Policy management API endpoints.

Advanced features: policy-as-code engine with rule evaluation,
auto-enforcement against findings, policy simulation/dry-run,
conflict detection between overlapping policies, and OPA-style
rule evaluation with severity/threshold/pattern matching.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.persistent_store import get_persistent_store
from core.policy_db import PolicyDB
from core.policy_models import Policy, PolicyStatus
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])
db = PolicyDB()

# Persistent violation store
_violation_store = get_persistent_store(
    "policy_violations"
)  # policy_id -> violations


class PolicyCreate(BaseModel):
    """Request model for creating a policy."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., max_length=10000)
    policy_type: str = Field(
        ..., max_length=64, description="Policy type (guardrail, compliance, custom)"
    )
    status: PolicyStatus = PolicyStatus.DRAFT
    rules: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("rules")
    @classmethod
    def validate_rules_size(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(v, separators=(",", ":"))
        if len(serialized.encode("utf-8")) > 100 * 1024:
            raise ValueError("rules payload must not exceed 100KB when serialized")
        return v

    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(v, separators=(",", ":"))
        if len(serialized.encode("utf-8")) > 100 * 1024:
            raise ValueError("metadata payload must not exceed 100KB when serialized")
        return v


class PolicyUpdate(BaseModel):
    """Request model for updating a policy."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=10000)
    policy_type: Optional[str] = Field(None, max_length=64)
    status: Optional[PolicyStatus] = None
    rules: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("rules")
    @classmethod
    def validate_rules_size(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if v is not None:
            serialized = json.dumps(v, separators=(",", ":"))
            if len(serialized.encode("utf-8")) > 100 * 1024:
                raise ValueError("rules payload must not exceed 100KB when serialized")
        return v

    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if v is not None:
            serialized = json.dumps(v, separators=(",", ":"))
            if len(serialized.encode("utf-8")) > 100 * 1024:
                raise ValueError("metadata payload must not exceed 100KB when serialized")
        return v


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
    import sqlite3

    policy = Policy(
        id="",
        name=policy_data.name,
        description=policy_data.description,
        policy_type=policy_data.policy_type,
        status=policy_data.status,
        rules=policy_data.rules,
        metadata=policy_data.metadata,
    )
    try:
        created_policy = db.create_policy(policy)
    except (sqlite3.IntegrityError, Exception) as exc:
        if "UNIQUE" in str(exc) or "unique" in str(exc).lower():
            raise HTTPException(
                status_code=409,
                detail=f"Policy with name '{policy_data.name}' already exists",
            )
        raise
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

_VALID_RULE_KEYS = {
    "condition",
    "action",
    "severity",
    "threshold",
    "pattern",
    "field",
    "operator",
    "value",
}
_VALID_OPERATORS = {
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "matches",
    "contains",
}
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
            errors.append(
                f"conditions[{i}] invalid operator '{op}' — must be one of {sorted(_VALID_OPERATORS)}"
            )
        if "value" not in cond and op not in ("matches",):
            errors.append(f"conditions[{i}] missing 'value'")
    actions = rules.get("actions", [])
    if not isinstance(actions, list):
        errors.append("rules.actions must be a list")
    else:
        for i, act in enumerate(actions):
            atype = act.get("type", "") if isinstance(act, dict) else act
            if atype not in _VALID_ACTIONS:
                errors.append(
                    f"actions[{i}] invalid type '{atype}' — must be one of {sorted(_VALID_ACTIONS)}"
                )
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
            return str(actual).lower() in [
                str(v).lower()
                for v in (expected if isinstance(expected, list) else [expected])
            ]
        elif op == "not_in":
            return str(actual).lower() not in [
                str(v).lower()
                for v in (expected if isinstance(expected, list) else [expected])
            ]
        elif op == "matches":
            return bool(re.search(str(expected), str(actual), re.IGNORECASE))
        elif op == "contains":
            return str(expected).lower() in str(actual).lower()
    except (ValueError, TypeError):
        return False
    return False


def _evaluate_policy(
    policy: Policy, data_items: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Evaluate a policy against a list of data items. Returns violations."""
    conditions = policy.rules.get("conditions", [])
    logic = policy.rules.get("logic", "all")  # all = AND, any = OR
    violations: List[Dict[str, Any]] = []
    for item in data_items:
        results = [_evaluate_condition(c, item) for c in conditions]
        triggered = all(results) if logic == "all" else any(results)
        if triggered:
            violations.append(
                {
                    "id": str(uuid.uuid4()),
                    "policy_id": policy.id,
                    "policy_name": policy.name,
                    "item": item,
                    "matched_conditions": [c for c, r in zip(conditions, results) if r],
                    "actions": policy.rules.get("actions", []),
                    "severity": policy.rules.get("severity", "medium"),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                }
            )
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
    return {
        "policy_id": id,
        "violations": violations,
        "total": len(_violation_store.get(id, [])),
    }


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
        raise HTTPException(
            status_code=400, detail="Only active policies can be enforced"
        )

    # Fetch findings from the findings DB
    findings_data: List[Dict[str, Any]] = []
    try:
        from core.findings_db import FindingsDB

        fdb = FindingsDB()
        findings = fdb.list_findings(limit=10000)
        for f in findings:
            findings_data.append(
                f.to_dict() if hasattr(f, "to_dict") else {"id": str(f)}
            )
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass

    violations = _evaluate_policy(policy, findings_data)
    existing = _violation_store.get(id, [])
    existing.extend(violations)
    _violation_store[id] = existing  # write-through

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
        results.append(
            {
                "policy_id": policy.id,
                "policy_name": policy.name,
                "violations": len(violations),
                "details": violations[:5],
            }
        )

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
        for p2 in active[i + 1 :]:
            p1_fields = {
                c.get("field")
                for c in p1.rules.get("conditions", [])
                if isinstance(c, dict)
            }
            p2_fields = {
                c.get("field")
                for c in p2.rules.get("conditions", [])
                if isinstance(c, dict)
            }
            overlap = p1_fields & p2_fields - {None}
            if not overlap:
                continue
            p1_actions = {
                (a.get("type") if isinstance(a, dict) else a)
                for a in p1.rules.get("actions", [])
            }
            p2_actions = {
                (a.get("type") if isinstance(a, dict) else a)
                for a in p2.rules.get("actions", [])
            }
            if p1_actions != p2_actions:
                conflicts.append(
                    {
                        "policy_a": {
                            "id": p1.id,
                            "name": p1.name,
                            "actions": list(p1_actions),
                        },
                        "policy_b": {
                            "id": p2.id,
                            "name": p2.name,
                            "actions": list(p2_actions),
                        },
                        "overlapping_fields": list(overlap),
                        "severity": "high"
                        if {"block", "auto_remediate"} & (p1_actions | p2_actions)
                        else "medium",
                    }
                )

    return {"conflicts": conflicts, "total": len(conflicts)}


# ---------------------------------------------------------------------------
# Global violations list, evaluate, and enable/disable toggle
# ---------------------------------------------------------------------------


@router.get("/violations")
async def list_all_violations(
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
):
    """List all policy violations across all policies in the past N days."""
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    all_violations: List[Dict[str, Any]] = []
    for policy_id, violations in _violation_store.items():
        for v in violations:
            recorded_at = v.get("recorded_at", "")
            try:
                ts = datetime.fromisoformat(recorded_at).timestamp()
            except (ValueError, TypeError):
                ts = 0.0
            if ts >= cutoff:
                all_violations.append({**v, "policy_id": policy_id})
    all_violations.sort(key=lambda x: x.get("recorded_at", ""), reverse=True)
    return {
        "violations": all_violations[:limit],
        "total": len(all_violations),
        "days": days,
    }


class EvaluateContextRequest(BaseModel):
    """Request body for evaluating a context dict against all active policies."""
    context: Dict[str, Any] = Field(..., description="Arbitrary context to evaluate (finding, asset, user, etc.)")


@router.post("/evaluate")
async def evaluate_context(body: EvaluateContextRequest):
    """Evaluate a context dict against all active policies.

    Returns a list of violated policies and their configured actions.
    """
    policies = db.list_policies(limit=10000)
    active_policies = [p for p in policies if p.status == PolicyStatus.ACTIVE]
    violated: List[Dict[str, Any]] = []
    for policy in active_policies:
        violations = _evaluate_policy(policy, [body.context])
        if violations:
            violated.append(
                {
                    "policy_id": policy.id,
                    "policy_name": policy.name,
                    "violations": violations,
                    "actions": violations[0].get("actions", []) if violations else [],
                }
            )
    return {
        "context": body.context,
        "policies_evaluated": len(active_policies),
        "violated_policies": violated,
        "violation_count": len(violated),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


class EnableToggleRequest(BaseModel):
    enabled: bool = Field(..., description="True to enable, False to disable")


@router.put("/{id}/enable")
async def toggle_policy_enabled(id: str, body: EnableToggleRequest):
    """Enable or disable a policy without full update."""
    policy = db.get_policy(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    new_status = PolicyStatus.ACTIVE if body.enabled else PolicyStatus.DRAFT
    updated = db.update_policy(id, {"status": new_status.value})
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update policy status")
    return {
        "id": id,
        "enabled": body.enabled,
        "status": new_status.value,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
