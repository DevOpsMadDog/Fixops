"""Security Posture Improvement Advisor API Router.

Provides AI-driven security posture recommendations and improvement roadmap.
Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.posture_advisor import (
    RECOMMENDATION_CATEGORIES,
    PRIORITY_LEVELS,
    get_posture_advisor,
)

router = APIRouter(prefix="/api/v1/posture-advisor", tags=["posture-advisor"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    """Request body for posture analysis."""

    posture_score: float = Field(50.0, ge=0.0, le=100.0, description="Current posture score 0-100")
    open_critical_vulns: int = Field(0, ge=0, description="Number of open critical vulnerabilities")
    avg_patch_time_days: float = Field(0.0, ge=0.0, description="Average patch time in days")
    mfa_coverage_pct: float = Field(100.0, ge=0.0, le=100.0, description="MFA coverage percentage")
    avg_mttd_hours: float = Field(0.0, ge=0.0, description="Average mean time to detect (hours)")
    unencrypted_databases: int = Field(0, ge=0, description="Number of unencrypted databases")
    wildcard_permissions_count: int = Field(0, ge=0, description="Number of wildcard IAM permissions")
    sla_compliance_pct: float = Field(100.0, ge=0.0, le=100.0, description="SLA compliance percentage")
    org_id: str = Field("default", min_length=1, description="Organisation identifier")


class AcceptRequest(BaseModel):
    owner: str = Field(..., min_length=1, description="Owner responsible for this recommendation")
    target_date: str = Field(..., min_length=1, description="ISO-8601 target completion date")


class CompleteRequest(BaseModel):
    completed_by: str = Field(..., min_length=1, description="Person who completed the recommendation")
    actual_improvement: float = Field(0.0, ge=0.0, description="Actual score improvement achieved")


class DismissRequest(BaseModel):
    reason: str = Field(..., min_length=1, description="Justification for dismissal")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/analyze", summary="Analyze security posture and generate recommendations")
def analyze_posture(req: AnalyzeRequest) -> Dict[str, Any]:
    """Analyze current security posture metrics and return prioritized recommendations."""
    advisor = get_posture_advisor()
    posture_data = req.model_dump(exclude={"org_id"})
    try:
        return advisor.analyze_posture(posture_data, org_id=req.org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/recommendations", summary="List posture improvement recommendations")
def list_recommendations(
    org_id: str = Query("default", description="Organisation identifier"),
    category: Optional[str] = Query(None, description="Filter by category"),
    priority: Optional[str] = Query(None, description="Filter by priority level"),
    status: Optional[str] = Query(None, description="Filter by status (open/accepted/completed/dismissed)"),
) -> List[Dict[str, Any]]:
    """Return recommendations with optional category/priority/status filters."""
    if category and category not in RECOMMENDATION_CATEGORIES:
        raise HTTPException(status_code=422, detail=f"Invalid category: {category}")
    if priority and priority not in PRIORITY_LEVELS:
        raise HTTPException(status_code=422, detail=f"Invalid priority: {priority}")
    advisor = get_posture_advisor()
    return advisor.list_recommendations(org_id=org_id, category=category, priority=priority, status=status)


@router.get("/recommendations/{rec_id}", summary="Get a single recommendation")
def get_recommendation(rec_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Retrieve a recommendation by ID."""
    advisor = get_posture_advisor()
    rec = advisor.get_recommendation(rec_id, org_id=org_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Recommendation not found: {rec_id}")
    return rec


@router.post("/recommendations/{rec_id}/accept", summary="Accept a recommendation")
def accept_recommendation(rec_id: str, req: AcceptRequest, org_id: str = Query("default")) -> Dict[str, Any]:
    """Accept a recommendation and assign an owner with a target completion date."""
    advisor = get_posture_advisor()
    try:
        return advisor.accept_recommendation(rec_id, owner=req.owner, target_date=req.target_date, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/recommendations/{rec_id}/complete", summary="Complete a recommendation")
def complete_recommendation(rec_id: str, req: CompleteRequest) -> Dict[str, Any]:
    """Mark a recommendation as completed with actual improvement achieved."""
    advisor = get_posture_advisor()
    try:
        return advisor.complete_recommendation(rec_id, completed_by=req.completed_by, actual_improvement=req.actual_improvement)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/recommendations/{rec_id}/dismiss", summary="Dismiss a recommendation")
def dismiss_recommendation(rec_id: str, req: DismissRequest, org_id: str = Query("default")) -> Dict[str, Any]:
    """Dismiss a recommendation with a justification reason."""
    advisor = get_posture_advisor()
    try:
        return advisor.dismiss_recommendation(rec_id, reason=req.reason, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/roadmap", summary="Get prioritized improvement roadmap")
def get_roadmap(org_id: str = Query("default", description="Organisation identifier")) -> Dict[str, Any]:
    """Generate a 3-phase prioritized security improvement roadmap."""
    advisor = get_posture_advisor()
    return advisor.get_roadmap(org_id=org_id)


@router.get("/stats", summary="Get advisor statistics")
def get_stats(org_id: str = Query("default", description="Organisation identifier")) -> Dict[str, Any]:
    """Return aggregate advisor stats: analyses run, recommendations accepted/completed, avg improvement."""
    advisor = get_posture_advisor()
    return advisor.get_advisor_stats(org_id=org_id)
