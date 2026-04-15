"""Identity Governance & Administration (IGA) Router — ALDECI.

9 endpoints:
  POST   /api/v1/iga/reviews                               create_access_review
  GET    /api/v1/iga/reviews                               list_access_reviews
  GET    /api/v1/iga/reviews/{review_id}/items             get_review_items
  POST   /api/v1/iga/reviews/{review_id}/items/{item_id}/certify  certify_access
  GET    /api/v1/iga/orphaned-accounts                     get_orphaned_accounts
  GET    /api/v1/iga/excessive-privileges                  get_excessive_privileges
  GET    /api/v1/iga/sod-violations                        get_sod_violations
  GET    /api/v1/iga/stats                                 get_certification_stats
  POST   /api/v1/iga/provisioning-check                    run_provisioning_check
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "iga_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.iga_engine import IGAEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/iga",
    tags=["iga"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance
_engine: Optional[IGAEngine] = None


def _get_engine() -> IGAEngine:
    global _engine
    if _engine is None:
        _engine = IGAEngine()
    return _engine


# ============================================================================
# Request / Response Models
# ============================================================================


class CreateReviewRequest(BaseModel):
    """Body for creating an access review campaign."""

    name: str = Field(..., description="Human-readable review campaign name")
    scope: str = Field("all", description="Scope description, e.g. 'Q2 privileged access review'")
    reviewer_id: str = Field(..., description="User ID of the reviewer")
    deadline: str = Field(..., description="ISO 8601 deadline, e.g. '2026-05-01T00:00:00Z'")
    access_type: str = Field(
        "all",
        description="Which accounts to include: 'privileged', 'service_accounts', or 'all'",
    )
    org_id: str = Field("default", description="Organisation ID")


class CreateReviewResponse(BaseModel):
    review_id: str
    message: str = "Access review created"


class CertifyRequest(BaseModel):
    """Body for submitting a certification decision."""

    decision: str = Field(
        ..., description="One of: 'certify', 'revoke', 'escalate'"
    )
    justification: str = Field("", description="Free-text reason for the decision")
    org_id: str = Field("default", description="Organisation ID")


class CertifyResponse(BaseModel):
    success: bool
    message: str


class ProvisioningCheckRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")


# ============================================================================
# Endpoints
# ============================================================================


@router.post("/reviews", response_model=CreateReviewResponse)
def create_access_review(body: CreateReviewRequest) -> CreateReviewResponse:
    """Create an access review campaign.

    Seeds review items automatically from the identity catalog based on access_type.
    """
    engine = _get_engine()
    try:
        review_id = engine.create_access_review(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return CreateReviewResponse(review_id=review_id)


@router.get("/reviews", response_model=List[Dict[str, Any]])
def list_access_reviews(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """List all access review campaigns for an organisation."""
    return _get_engine().list_access_reviews(org_id)


@router.get("/reviews/{review_id}/items", response_model=List[Dict[str, Any]])
def get_review_items(
    review_id: str,
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """Return all items to certify or revoke for a review campaign."""
    items = _get_engine().get_review_items(review_id, org_id)
    if not items:
        # Review might exist with no items yet — return empty list rather than 404
        return []
    return items


@router.post(
    "/reviews/{review_id}/items/{item_id}/certify",
    response_model=CertifyResponse,
)
def certify_access(
    review_id: str,
    item_id: str,
    body: CertifyRequest,
) -> CertifyResponse:
    """Submit a certification decision (certify / revoke / escalate) for a review item."""
    engine = _get_engine()
    try:
        success = engine.certify_access(
            review_id, item_id, body.org_id, body.decision, body.justification
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not success:
        raise HTTPException(status_code=404, detail="Review item not found")
    return CertifyResponse(success=True, message=f"Decision '{body.decision}' recorded")


@router.get("/orphaned-accounts", response_model=List[Dict[str, Any]])
def get_orphaned_accounts(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """Return accounts with no owner or from departed employees."""
    return _get_engine().get_orphaned_accounts(org_id)


@router.get("/excessive-privileges", response_model=List[Dict[str, Any]])
def get_excessive_privileges(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """Return users with more access than their role requires."""
    return _get_engine().get_excessive_privileges(org_id)


@router.get("/sod-violations", response_model=List[Dict[str, Any]])
def get_sod_violations(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """Return Segregation of Duties violations — conflicting roles held by the same user."""
    return _get_engine().get_segregation_violations(org_id)


@router.get("/stats", response_model=Dict[str, Any])
def get_certification_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return access certification statistics for the organisation."""
    return _get_engine().get_access_certification_stats(org_id)


@router.post("/provisioning-check", response_model=Dict[str, Any])
def run_provisioning_check(body: ProvisioningCheckRequest) -> Dict[str, Any]:
    """Run a Joiner / Mover / Leaver provisioning gap check against the HR roster."""
    return _get_engine().run_provisioning_check(body.org_id)
