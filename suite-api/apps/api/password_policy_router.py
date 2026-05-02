"""Password Policy Router — ALDECI.

Exposes the PasswordPolicyEngine via REST API.

Compliance: NIST SP 800-63B, CIS Controls v8 5.2, PCI DSS 4.0 req 8.3
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from core.password_policy_engine import PasswordPolicyEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/password-policy", tags=["password-policy"])

# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[PasswordPolicyEngine] = None


def get_password_policy_engine() -> PasswordPolicyEngine:
    global _engine
    if _engine is None:
        _engine = PasswordPolicyEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class PolicyBody(BaseModel):
    name: str = "Default Policy"
    min_length: int = 8
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_numbers: bool = False
    require_symbols: bool = False
    max_age_days: int = 90
    min_history: int = 5
    lockout_attempts: int = 5


class EvaluatePasswordBody(BaseModel):
    password_hash_hint: str


class ViolationBody(BaseModel):
    policy_id: str
    user_id: str
    violation_type: str
    severity: str = "medium"
    status: str = "open"


class AuditBody(BaseModel):
    policy_id: str
    users_audited: int
    violations_found: int
    compliance_rate: float


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.get("/policies")
def list_policies(
    org_id: str = Query(..., description="Organisation identifier"),
    engine: PasswordPolicyEngine = Depends(get_password_policy_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List all password policies for an org."""
    policies = engine.list_policies(org_id)
    return {"org_id": org_id, "count": len(policies), "policies": policies}


@router.post("/policies", status_code=201)
def create_policy(
    body: PolicyBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: PasswordPolicyEngine = Depends(get_password_policy_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Create a new password policy."""
    policy = engine.create_policy(org_id, body.model_dump())
    return policy


# ---------------------------------------------------------------------------
# Password Evaluation
# ---------------------------------------------------------------------------


@router.post("/policies/{policy_id}/evaluate")
def evaluate_password(
    policy_id: str,
    body: EvaluatePasswordBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: PasswordPolicyEngine = Depends(get_password_policy_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Evaluate a password hint against a specific policy.

    password_hash_hint format: 'length:12,upper:1,lower:1,digits:1,symbols:0,entropy:45'
    """
    result = engine.evaluate_password(org_id, policy_id, body.password_hash_hint)
    return {"policy_id": policy_id, **result}


# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------


@router.get("/violations")
def list_violations(
    org_id: str = Query(..., description="Organisation identifier"),
    status: Optional[str] = Query(None, description="Filter by status (open/remediated)"),
    engine: PasswordPolicyEngine = Depends(get_password_policy_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List policy violations for an org."""
    violations = engine.list_violations(org_id, status=status)
    return {"org_id": org_id, "count": len(violations), "violations": violations}


@router.post("/violations", status_code=201)
def create_violation(
    body: ViolationBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: PasswordPolicyEngine = Depends(get_password_policy_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Record a password policy violation."""
    violation = engine.create_violation(org_id, body.model_dump())
    return violation


@router.post("/violations/{violation_id}/remediate")
def remediate_violation(
    violation_id: str,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: PasswordPolicyEngine = Depends(get_password_policy_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Mark a violation as remediated."""
    updated = engine.remediate_violation(org_id, violation_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Violation not found or already remediated")
    return {"violation_id": violation_id, "status": "remediated"}


# ---------------------------------------------------------------------------
# Audits
# ---------------------------------------------------------------------------


@router.get("/audits")
def list_audits(
    org_id: str = Query(..., description="Organisation identifier"),
    engine: PasswordPolicyEngine = Depends(get_password_policy_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List audit records for an org."""
    audits = engine.list_audits(org_id)
    return {"org_id": org_id, "count": len(audits), "audits": audits}


@router.post("/audits", status_code=201)
def record_audit(
    body: AuditBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: PasswordPolicyEngine = Depends(get_password_policy_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Record a password audit run."""
    audit = engine.record_audit(
        org_id,
        body.policy_id,
        body.users_audited,
        body.violations_found,
        body.compliance_rate,
    )
    return audit


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(
    org_id: str = Query(..., description="Organisation identifier"),
    engine: PasswordPolicyEngine = Depends(get_password_policy_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return password policy statistics for an org."""
    return engine.get_policy_stats(org_id)
