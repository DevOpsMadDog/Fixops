"""Security Architecture Review Router — ALDECI.

Architecture review tracking and control gap analysis.

Prefix: /api/v1/arch-review
Auth: api_key_auth dependency

Routes:
  POST /api/v1/arch-review/reviews                          create_review
  GET  /api/v1/arch-review/reviews                          list_reviews
  GET  /api/v1/arch-review/reviews/{review_id}              get_review
  POST /api/v1/arch-review/reviews/{review_id}/findings     add_finding
  POST /api/v1/arch-review/reviews/{review_id}/controls     add_control
  POST /api/v1/arch-review/reviews/{review_id}/complete     complete_review
  GET  /api/v1/arch-review/control-gaps                     get_control_gaps
  GET  /api/v1/arch-review/summary                          get_summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/arch-review",
    tags=["Security Architecture Review"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_architecture_review_engine import (
            SecurityArchitectureReviewEngine,
        )
        _engine = SecurityArchitectureReviewEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class CreateReviewBody(BaseModel):
    review_name: str = Field(..., description="Name of this architecture review")
    system_name: str = Field(..., description="System or service being reviewed")
    review_type: str = Field(
        default="full",
        description="full | partial | threat-model | compliance | vendor",
    )
    reviewer: str = Field(default="", description="Reviewer name or ID")


class AddFindingBody(BaseModel):
    component: str = Field(..., description="Component with the finding")
    finding_type: str = Field(
        ...,
        description="design-flaw | missing-control | weak-implementation | configuration | dependency-risk | data-exposure",
    )
    title: str = Field(..., description="Short finding title")
    description: str = Field(default="", description="Detailed description")
    severity: str = Field(
        default="medium",
        description="critical | high | medium | low | info",
    )
    recommendation: str = Field(default="", description="Remediation recommendation")


class AddControlBody(BaseModel):
    control_name: str = Field(..., description="Control name or identifier")
    domain: str = Field(..., description="Security domain (e.g. IAM, Network, Crypto)")
    implementation_status: str = Field(
        default="not_implemented",
        description="implemented | partial | not_implemented | compensating",
    )
    effectiveness: float = Field(
        default=0.0,
        description="Effectiveness score 0–100",
    )
    gaps: str = Field(default="", description="Description of gaps")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/reviews", dependencies=[Depends(api_key_auth)])
def create_review(
    body: CreateReviewBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Create a new architecture review."""
    try:
        return _get_engine().create_review(
            org_id=org_id,
            review_name=body.review_name,
            system_name=body.system_name,
            review_type=body.review_type,
            reviewer=body.reviewer,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/reviews", dependencies=[Depends(api_key_auth)])
def list_reviews(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List architecture reviews, optionally filtered by status."""
    return _get_engine().list_reviews(org_id, status=status)


@router.get("/reviews/{review_id}", dependencies=[Depends(api_key_auth)])
def get_review(
    review_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Fetch a single architecture review with findings and controls."""
    result = _get_engine().get_review(review_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return result


@router.post("/reviews/{review_id}/findings", dependencies=[Depends(api_key_auth)])
def add_finding(
    review_id: str,
    body: AddFindingBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Add a finding to an architecture review."""
    try:
        return _get_engine().add_finding(
            review_id=review_id,
            org_id=org_id,
            component=body.component,
            finding_type=body.finding_type,
            title=body.title,
            description=body.description,
            severity=body.severity,
            recommendation=body.recommendation,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/reviews/{review_id}/controls", dependencies=[Depends(api_key_auth)])
def add_control(
    review_id: str,
    body: AddControlBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Add a control assessment to an architecture review."""
    try:
        return _get_engine().add_control(
            review_id=review_id,
            org_id=org_id,
            control_name=body.control_name,
            domain=body.domain,
            implementation_status=body.implementation_status,
            effectiveness=body.effectiveness,
            gaps=body.gaps,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/reviews/{review_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_review(
    review_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Complete an architecture review and compute the overall score."""
    try:
        return _get_engine().complete_review(review_id, org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/control-gaps", dependencies=[Depends(api_key_auth)])
def get_control_gaps(
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    """Return all unimplemented controls ordered by effectiveness ascending."""
    return _get_engine().get_control_gaps(org_id)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_summary(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return aggregate summary statistics for architecture reviews."""
    return _get_engine().get_summary(org_id)
