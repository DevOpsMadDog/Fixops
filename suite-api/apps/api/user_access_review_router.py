"""User Access Review Router — ALDECI.

Endpoints for the UserAccessReviewEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/access-reviews
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/access-reviews/reviews                              create_review
  GET   /api/v1/access-reviews/reviews                              list_reviews
  GET   /api/v1/access-reviews/reviews/{review_id}                  get_review
  POST  /api/v1/access-reviews/reviews/{review_id}/items            add_review_item
  POST  /api/v1/access-reviews/reviews/{review_id}/items/{item_id}/decide  make_decision
  GET   /api/v1/access-reviews/overdue                              get_overdue_reviews
  POST  /api/v1/access-reviews/campaigns                            create_campaign
  GET   /api/v1/access-reviews/campaigns/stats                      get_campaign_stats
  GET   /api/v1/access-reviews/summary                              get_review_summary
"""
from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/access-reviews",
    tags=["User Access Review"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.user_access_review_engine import UserAccessReviewEngine
            _engine = UserAccessReviewEngine()
        except Exception as exc:
            _logger.error("Failed to init UserAccessReviewEngine: %s", exc)
            raise HTTPException(status_code=503, detail="Engine unavailable")
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ReviewCreate(BaseModel):
    review_name: str
    review_type: str = "quarterly"
    reviewer_id: str = ""
    due_date: Optional[str] = None


class ReviewItemCreate(BaseModel):
    user_id: str
    resource_id: str
    resource_type: str = ""
    access_level: str = ""


class DecisionCreate(BaseModel):
    decision: str
    decision_reason: str = ""
    decided_by: str = ""


class CampaignCreate(BaseModel):
    campaign_name: str
    frequency: str = "quarterly"
    scope: str = ""


# ---------------------------------------------------------------------------
# Reviews
# ---------------------------------------------------------------------------

@router.post("/reviews", dependencies=[Depends(api_key_auth)], status_code=201)
def create_review(body: ReviewCreate, org_id: str = Query(default="default")):
    """Create a new access review."""
    try:
        return _get_engine().create_review(
            org_id=org_id,
            review_name=body.review_name,
            review_type=body.review_type,
            reviewer_id=body.reviewer_id,
            due_date=body.due_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/reviews", dependencies=[Depends(api_key_auth)])
def list_reviews(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
):
    """List access reviews, optionally filtered by status."""
    return _get_engine().list_reviews(org_id=org_id, status=status)


@router.get("/reviews/{review_id}", dependencies=[Depends(api_key_auth)])
def get_review(review_id: str, org_id: str = Query(default="default")):
    """Get a review with all its items."""
    result = _get_engine().get_review(review_id=review_id, org_id=org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return result


@router.post(
    "/reviews/{review_id}/items",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_review_item(review_id: str, body: ReviewItemCreate, org_id: str = Query(default="default")):
    """Add an item to an access review."""
    try:
        return _get_engine().add_review_item(
            review_id=review_id,
            org_id=org_id,
            user_id=body.user_id,
            resource_id=body.resource_id,
            resource_type=body.resource_type,
            access_level=body.access_level,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/reviews/{review_id}/items/{item_id}/decide",
    dependencies=[Depends(api_key_auth)],
)
def make_decision(
    review_id: str,
    item_id: str,
    body: DecisionCreate,
     org_id: str = Query(default="default"),
):
    """Record a certify/revoke/modify/defer decision on a review item."""
    try:
        return _get_engine().make_decision(
            review_id=review_id,
            item_id=item_id,
            org_id=org_id,
            decision=body.decision,
            decision_reason=body.decision_reason,
            decided_by=body.decided_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/overdue", dependencies=[Depends(api_key_auth)])
def get_overdue_reviews(org_id: str = Query(default="default")):
    """Get access reviews past their due date that are not completed."""
    return _get_engine().get_overdue_reviews(org_id=org_id)


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------

@router.post("/campaigns", dependencies=[Depends(api_key_auth)], status_code=201)
def create_campaign(body: CampaignCreate, org_id: str = Query(default="default")):
    """Create a review campaign."""
    try:
        return _get_engine().create_campaign(
            org_id=org_id,
            campaign_name=body.campaign_name,
            frequency=body.frequency,
            scope=body.scope,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/campaigns/stats", dependencies=[Depends(api_key_auth)])
def get_campaign_stats(org_id: str = Query(default="default")):
    """Get aggregated campaign stats."""
    return _get_engine().get_campaign_stats(org_id=org_id)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_review_summary(org_id: str = Query(default="default")):
    """Get total/pending/completed/overdue review counts."""
    return _get_engine().get_review_summary(org_id=org_id)


@router.get("", dependencies=[Depends(api_key_auth)])
def get_root(org_id: str = Query(default="default")):
    """Root endpoint — returns reviews list for dashboard health-checks."""
    return _get_engine().list_reviews(org_id=org_id)


@router.get("/health")
def access_review_health() -> Dict[str, Any]:
    """Health check for the user access review service."""
    try:
        summary = _get_engine().get_review_summary(org_id="default")
        return {"status": "healthy", "service": "aldeci-access-reviews", "version": "1.0.0",
                "total_reviews": summary.get("total", 0)}
    except Exception as exc:
        return {"status": "degraded", "service": "aldeci-access-reviews", "error": str(exc)}


@router.get("/status")
def access_review_status() -> Dict[str, Any]:
    """Status alias — delegates to /health."""
    return access_review_health()
