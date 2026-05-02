"""Identity Governance Router — ALDECI.

FastAPI router for user access reviews and entitlement management.
Prefix: /api/v1/identity-governance
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(
    prefix="/api/v1/identity-governance",
    tags=["identity-governance"],
    dependencies=[Depends(api_key_auth)],
)

# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.identity_governance_engine import IdentityGovernanceEngine
        _engine = IdentityGovernanceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ReviewIn(BaseModel):
    name: str
    review_type: str = "quarterly"
    reviewer_id: str = ""
    start_date: str = ""
    due_date: str = ""


class ReviewItemIn(BaseModel):
    identity_id: str
    identity_name: str = ""
    identity_type: str = "user"
    entitlement: str = ""
    entitlement_level: str = "read"
    last_used: Optional[str] = None
    risk_score: float = 0.0


class DecisionIn(BaseModel):
    decision: str
    reviewer_id: str
    notes: str = ""


class EntitlementIn(BaseModel):
    identity_id: str
    identity_name: str = ""
    identity_type: str = "user"
    entitlement: str = ""
    system: str = ""
    granted_date: str = ""
    last_used: Optional[str] = None
    is_orphaned: bool = False
    is_excessive: bool = False
    risk_score: float = 0.0


class PolicyIn(BaseModel):
    policy_name: str
    policy_type: str = "least_privilege"
    conditions: Dict[str, Any] = {}
    auto_remediate: bool = False
    enabled: bool = True


# ---------------------------------------------------------------------------
# Endpoints — Access Reviews
# ---------------------------------------------------------------------------

@router.post("/reviews", summary="Create an access review")
def create_review(org_id: str, body: ReviewIn) -> Dict[str, Any]:
    try:
        return _get_engine().create_review(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/reviews", summary="List access reviews")
def list_reviews(
    org_id: str,
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    return _get_engine().list_reviews(org_id, status=status)


@router.get("/reviews/{review_id}", summary="Get a review with item summary")
def get_review(org_id: str, review_id: str) -> Dict[str, Any]:
    result = _get_engine().get_review(org_id, review_id)
    if not result:
        raise HTTPException(status_code=404, detail="Review not found.")
    return result


@router.post("/reviews/{review_id}/items", summary="Add an item to a review")
def add_review_item(org_id: str, review_id: str, body: ReviewItemIn) -> Dict[str, Any]:
    try:
        return _get_engine().add_review_item(org_id, review_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/items/{item_id}/decision", summary="Submit a reviewer decision")
def submit_decision(org_id: str, item_id: str, body: DecisionIn) -> Dict[str, Any]:
    try:
        found = _get_engine().submit_decision(
            org_id, item_id, body.decision, body.reviewer_id, body.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if not found:
        raise HTTPException(status_code=404, detail="Review item not found.")
    return {"status": "decision_recorded", "item_id": item_id, "decision": body.decision}


@router.post("/reviews/{review_id}/complete", summary="Complete an access review")
def complete_review(org_id: str, review_id: str) -> Dict[str, Any]:
    result = _get_engine().complete_review(org_id, review_id)
    if not result:
        raise HTTPException(status_code=404, detail="Review not found.")
    return result


# ---------------------------------------------------------------------------
# Endpoints — Entitlements
# ---------------------------------------------------------------------------

@router.post("/entitlements", summary="Add an entitlement")
def add_entitlement(org_id: str, body: EntitlementIn) -> Dict[str, Any]:
    try:
        return _get_engine().add_entitlement(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/entitlements", summary="List entitlements")
def list_entitlements(
    org_id: str,
    identity_id: Optional[str] = Query(None),
    is_orphaned: Optional[bool] = Query(None),
    is_excessive: Optional[bool] = Query(None),
) -> List[Dict[str, Any]]:
    return _get_engine().list_entitlements(
        org_id,
        identity_id=identity_id,
        is_orphaned=is_orphaned,
        is_excessive=is_excessive,
    )


@router.post("/entitlements/flag-orphaned", summary="Flag all entitlements for an identity as orphaned")
def flag_orphaned(org_id: str, identity_id: str) -> Dict[str, Any]:
    count = _get_engine().flag_orphaned(org_id, identity_id)
    return {"flagged_count": count, "identity_id": identity_id}


# ---------------------------------------------------------------------------
# Endpoints — Policies
# ---------------------------------------------------------------------------

@router.post("/policies", summary="Create an access policy")
def create_policy(org_id: str, body: PolicyIn) -> Dict[str, Any]:
    try:
        return _get_engine().create_policy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/policies", summary="List access policies")
def list_policies(org_id: str) -> List[Dict[str, Any]]:
    return _get_engine().list_policies(org_id)


# ---------------------------------------------------------------------------
# Endpoints — Stats
# ---------------------------------------------------------------------------

@router.get("/stats", summary="Get identity governance statistics")
def get_governance_stats(org_id: str) -> Dict[str, Any]:
    return _get_engine().get_governance_stats(org_id)
