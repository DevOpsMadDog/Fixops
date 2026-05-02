"""
CIEM (Cloud Infrastructure Entitlement Management) API endpoints.

Provides IAM policy analysis, privilege escalation detection,
least-privilege suggestions, and entitlement risk listing.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.ciem_engine import CIEMEngine, get_ciem_engine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/ciem", tags=["ciem"])


def _engine() -> CIEMEngine:
    return get_ciem_engine()


# ============================================================================
# Request / Response models
# ============================================================================


class AnalyzePolicyRequest(BaseModel):
    policy: Dict[str, Any] = Field(..., description="AWS IAM policy document JSON")
    principal: str = Field(..., description="IAM entity ARN or name this policy is attached to")


class AnalyzeAccountRequest(BaseModel):
    account_id: str = Field(..., description="AWS account ID (12-digit)")
    policies: List[Dict[str, Any]] = Field(
        ...,
        description="List of {principal: str, policy: dict} objects",
    )


class LeastPrivilegeRequest(BaseModel):
    policy: Dict[str, Any] = Field(..., description="AWS IAM policy document JSON")
    used_permissions: List[str] = Field(
        ...,
        description="Actions actually observed in CloudTrail / usage logs",
    )


class EscalationPathsRequest(BaseModel):
    policies: List[Dict[str, Any]] = Field(
        ...,
        description="List of {principal: str, policy: dict} objects",
    )


class AzureAnalyzeRequest(BaseModel):
    role_definition: Dict[str, Any] = Field(
        ..., description="Azure role definition or assignment JSON"
    )
    principal: str = Field(..., description="Azure object ID, UPN, or display name")


class RiskResponse(BaseModel):
    id: str
    severity: str
    type: str
    principal: str
    permission: str
    resource: str
    explanation: str
    remediation: str
    detected_at: str


# ============================================================================
# Endpoints
# ============================================================================


@router.post(
    "/analyze/policy",
    summary="Analyze a single AWS IAM policy",
    response_model=List[RiskResponse],
)
def analyze_policy(req: AnalyzePolicyRequest) -> List[RiskResponse]:
    """
    Analyze a single AWS IAM policy document for entitlement risks.

    Detects wildcard permissions, admin access, privilege escalation
    actions, cross-account trust without conditions, and toxic
    permission combinations.
    """
    try:
        risks = _engine().analyze_aws_iam_policy(req.policy, req.principal)
        return [RiskResponse(**r.to_dict()) for r in risks]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/analyze/account",
    summary="Analyze all IAM policies for an AWS account",
)
def analyze_account(req: AnalyzeAccountRequest) -> Dict[str, Any]:
    """
    Run a full entitlement analysis across all supplied policies for an account.

    Returns a summary with severity breakdown, type breakdown, average
    policy score, and the full list of risks.
    """
    try:
        return _engine().run_account_analysis(req.account_id, req.policies)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/suggest/least-privilege",
    summary="Suggest a least-privilege rewrite of an IAM policy",
)
def suggest_least_privilege(req: LeastPrivilegeRequest) -> Dict[str, Any]:
    """
    Return a trimmed IAM policy containing only the permissions that appear
    in the supplied used_permissions list.

    Wildcard Action statements are collapsed to only the observed actions.
    Unused statements are dropped entirely.
    """
    try:
        return _engine().suggest_least_privilege(req.policy, req.used_permissions)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/risks",
    summary="List persisted entitlement risks",
    response_model=List[RiskResponse],
)
def list_risks(
    principal: Optional[str] = Query(None, description="Filter by principal"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical/high/medium/low)"),
    limit: int = Query(200, ge=1, le=1000, description="Max results"),
) -> List[RiskResponse]:
    """Return previously identified entitlement risks from the local database."""
    try:
        rows = _engine().list_risks(principal=principal, severity=severity, limit=limit)
        return [RiskResponse(**r) for r in rows]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/escalation-paths",
    summary="Detect privilege escalation chains across multiple policies",
    response_model=List[RiskResponse],
)
def detect_escalation_paths(req: EscalationPathsRequest) -> List[RiskResponse]:
    """
    Analyse a set of principals + policies for privilege escalation paths.

    Identifies when a principal's combined permissions can be chained to
    gain administrative access (e.g. CreatePolicyVersion + AttachRolePolicy,
    or PassRole + EC2 launch).
    """
    try:
        risks = _engine().detect_privilege_escalation_paths(req.policies)
        return [RiskResponse(**r.to_dict()) for r in risks]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/analyze/azure",
    summary="Analyze an Azure role definition or assignment",
    response_model=List[RiskResponse],
)
def analyze_azure(req: AzureAnalyzeRequest) -> List[RiskResponse]:
    """
    Analyse an Azure role definition or assignment for entitlement risks.

    Detects admin built-in roles (Owner, Contributor, UAA), wildcard
    actions, and privilege escalation via Microsoft.Authorization.
    """
    try:
        risks = _engine().analyze_azure_role_assignment(req.role_definition, req.principal)
        return [RiskResponse(**r.to_dict()) for r in risks]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/score",
    summary="Score an IAM policy (0=over-privileged, 100=least-privilege)",
)
def score_policy(req: AnalyzePolicyRequest) -> Dict[str, Any]:
    """
    Return a numeric score for an IAM policy.

    100 = perfectly least-privilege.
    0   = AdministratorAccess (wildcard on everything).
    """
    try:
        score = _engine().score_policy(req.policy)
        return {
            "principal": req.principal,
            "score": score,
            "rating": (
                "excellent" if score >= 80
                else "good" if score >= 60
                else "poor" if score >= 30
                else "critical"
            ),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
