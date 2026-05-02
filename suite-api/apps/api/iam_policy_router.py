"""IAM Policy Analyzer Router — ALDECI.

Analyzes cloud IAM policies for least-privilege violations and toxic combinations.

Prefix: /api/v1/iam-policy
Auth:   api_key_auth dependency

Routes:
  GET    /policies                          list_policies
  POST   /policies                          add_policy
  GET    /policies/{policy_id}/analyze      analyze_policy
  POST   /analyze-all                       analyze_all
  GET    /access-reviews                    list_access_reviews
  POST   /access-reviews                    record_access_review
  GET    /stats                             get_iam_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/iam-policy",
    tags=["iam-policy"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy engine cache
# ---------------------------------------------------------------------------
_engine_cache: Dict[str, Any] = {}


def _get_engine(org_id: str):
    if org_id not in _engine_cache:
        from core.iam_policy_analyzer import IAMPolicyAnalyzerEngine
        _engine_cache[org_id] = IAMPolicyAnalyzerEngine()
    return _engine_cache[org_id]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class PolicyCreate(BaseModel):
    policy_name: str = Field(..., description="Human-readable policy name")
    policy_type: str = Field("aws_iam", description="aws_iam / azure_rbac / gcp_iam")
    principal_type: str = Field("user", description="user / group / service_account / role")
    principal_id: str = Field("", description="Principal identifier (ARN, email, etc.)")
    permissions: List[str] = Field(default_factory=list, description="List of permission actions")
    resources: List[str] = Field(default_factory=list, description="List of resource ARNs / URIs")
    conditions: Dict[str, Any] = Field(default_factory=dict, description="Policy conditions")
    is_managed: bool = Field(True, description="Whether this is a managed (vs inline) policy")


class AccessReviewCreate(BaseModel):
    policy_id: str = Field(..., description="Policy being reviewed")
    reviewer: str = Field(..., description="Reviewer identity")
    outcome: str = Field("approved", description="approved / revoked / modified")
    action_taken: str = Field("", description="Description of action taken")
    review_date: Optional[str] = Field(None, description="ISO 8601 review date (defaults to now)")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/policies")
def list_policies(
    org_id: str = Query("default", description="Organization ID"),
    policy_type: Optional[str] = Query(None),
    principal_type: Optional[str] = Query(None),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    policies = engine.list_policies(org_id, policy_type=policy_type, principal_type=principal_type)
    return {"policies": policies, "total": len(policies)}


@router.post("/policies", status_code=201)
def add_policy(
    body: PolicyCreate,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    policy = engine.add_policy(org_id, body.model_dump())
    return policy


@router.get("/policies/{policy_id}/analyze")
def analyze_policy(
    policy_id: str,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    result = engine.analyze_policy(org_id, policy_id)
    if not result.get("findings") and result.get("risk_score") == 0:
        # Check if policy exists
        policies = engine.list_policies(org_id)
        if not any(p["policy_id"] == policy_id for p in policies):
            raise HTTPException(status_code=404, detail="Policy not found")
    return result


@router.post("/analyze-all")
def analyze_all(
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    return engine.analyze_all(org_id)


@router.get("/access-reviews")
def list_access_reviews(
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    reviews = engine.list_access_reviews(org_id)
    return {"reviews": reviews, "total": len(reviews)}


@router.post("/access-reviews", status_code=201)
def record_access_review(
    body: AccessReviewCreate,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    data = body.model_dump()
    if data.get("review_date") is None:
        data.pop("review_date", None)
    return engine.record_access_review(org_id, data)


@router.get("/stats")
def get_iam_stats(
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    return engine.get_iam_stats(org_id)
