"""Security Gap Analysis Router — ALDECI.

Framework gap analysis, control coverage, and remediation planning endpoints.

Prefix: /api/v1/gap-analysis
Auth: api_key_auth dependency on ALL endpoints

Routes:
  POST /api/v1/gap-analysis/assessments                    create_assessment
  GET  /api/v1/gap-analysis/assessments                    list_assessments
  GET  /api/v1/gap-analysis/assessments/{id}               get_assessment_detail
  POST /api/v1/gap-analysis/assessments/{id}/gaps          add_control_gap
  PUT  /api/v1/gap-analysis/gaps/{id}/status               update_control_status
  POST /api/v1/gap-analysis/gaps/{id}/plans                add_remediation_plan
  PUT  /api/v1/gap-analysis/plans/{id}/complete            complete_remediation
  GET  /api/v1/gap-analysis/summary                        get_gap_summary
  GET  /api/v1/gap-analysis/overdue                        get_overdue_gaps
  GET  /api/v1/gap-analysis/framework-coverage             get_framework_coverage
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/gap-analysis",
    tags=["Security Gap Analysis"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_gap_analysis_engine import SecurityGapAnalysisEngine
        _engine = SecurityGapAnalysisEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateAssessmentRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    framework: str = Field(..., description="SOC2|ISO27001|PCI-DSS|HIPAA|NIST-CSF|NIST-800-53|CIS|FedRAMP|GDPR|SOX")
    assessment_name: str = Field(..., description="Assessment name")
    total_controls: int = Field(default=0, ge=0, description="Total control count")
    assessor: str = Field(default="", description="Assessor name")
    next_review: str = Field(default="", description="Next review date (ISO)")


class AddControlGapRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    control_id: str = Field(..., description="Control identifier")
    control_name: str = Field(..., description="Control name")
    domain: str = Field(default="", description="Domain/category")
    requirement: str = Field(default="", description="Requirement text")
    current_state: str = Field(default="", description="Current implementation state")
    gap_description: str = Field(default="", description="Gap description")
    risk_impact: str = Field(default="medium", description="critical|high|medium|low")
    effort: str = Field(default="medium", description="low|medium|high|very-high")
    priority: str = Field(default="medium", description="critical|high|medium|low")
    owner: str = Field(default="", description="Gap owner")
    due_date: str = Field(default="", description="Due date (ISO)")


class UpdateStatusRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    status: str = Field(..., description="open|in_progress|implemented|accepted")


class AddRemediationPlanRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    action: str = Field(..., description="Remediation action description")
    resource_required: str = Field(default="", description="Resources required")
    estimated_days: int = Field(default=0, ge=0, description="Estimated days to complete")


class CompleteRemediationRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    actual_days: int = Field(default=0, ge=0, description="Actual days taken")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/assessments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_assessment(req: CreateAssessmentRequest) -> Dict[str, Any]:
    """Create a new gap assessment for a compliance framework."""
    try:
        return _get_engine().create_assessment(
            org_id=req.org_id,
            framework=req.framework,
            assessment_name=req.assessment_name,
            total_controls=req.total_controls,
            assessor=req.assessor,
            next_review=req.next_review,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/assessments", dependencies=[Depends(api_key_auth)])
def list_assessments(
    org_id: str = Query(..., description="Organisation ID"),
    framework: Optional[str] = Query(default=None, description="Filter by framework"),
) -> list:
    """List assessments for an org."""
    return _get_engine().list_assessments(org_id=org_id, framework=framework)


@router.get("/assessments/{assessment_id}", dependencies=[Depends(api_key_auth)])
def get_assessment_detail(
    assessment_id: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    """Return assessment detail with gaps and remediation plans."""
    result = _get_engine().get_assessment_detail(assessment_id=assessment_id, org_id=org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.post("/assessments/{assessment_id}/gaps", dependencies=[Depends(api_key_auth)], status_code=201)
def add_control_gap(assessment_id: str, req: AddControlGapRequest) -> Dict[str, Any]:
    """Add a control gap to an assessment."""
    try:
        return _get_engine().add_control_gap(
            assessment_id=assessment_id,
            org_id=req.org_id,
            control_id=req.control_id,
            control_name=req.control_name,
            domain=req.domain,
            requirement=req.requirement,
            current_state=req.current_state,
            gap_description=req.gap_description,
            risk_impact=req.risk_impact,
            effort=req.effort,
            priority=req.priority,
            owner=req.owner,
            due_date=req.due_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/gaps/{gap_id}/status", dependencies=[Depends(api_key_auth)])
def update_control_status(gap_id: str, req: UpdateStatusRequest) -> Dict[str, Any]:
    """Update control gap status and recompute assessment coverage."""
    try:
        return _get_engine().update_control_status(
            gap_id=gap_id,
            org_id=req.org_id,
            status=req.status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/gaps/{gap_id}/plans", dependencies=[Depends(api_key_auth)], status_code=201)
def add_remediation_plan(gap_id: str, req: AddRemediationPlanRequest) -> Dict[str, Any]:
    """Add a remediation plan for a control gap."""
    try:
        return _get_engine().add_remediation_plan(
            gap_id=gap_id,
            org_id=req.org_id,
            action=req.action,
            resource_required=req.resource_required,
            estimated_days=req.estimated_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/plans/{plan_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_remediation(plan_id: str, req: CompleteRemediationRequest) -> Dict[str, Any]:
    """Mark a remediation plan as completed."""
    try:
        return _get_engine().complete_remediation(
            plan_id=plan_id,
            org_id=req.org_id,
            actual_days=req.actual_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_gap_summary(
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregated gap summary: counts, by_framework, by_priority, critical_gaps."""
    return _get_engine().get_gap_summary(org_id=org_id)


@router.get("/overdue", dependencies=[Depends(api_key_auth)])
def get_overdue_gaps(
    org_id: str = Query(..., description="Organisation ID"),
) -> list:
    """Return open/in_progress gaps past their due date."""
    return _get_engine().get_overdue_gaps(org_id=org_id)


@router.get("/framework-coverage", dependencies=[Depends(api_key_auth)])
def get_framework_coverage(
    org_id: str = Query(..., description="Organisation ID"),
) -> list:
    """Return per-framework latest coverage_pct, risk_level, and gap_count."""
    return _get_engine().get_framework_coverage(org_id=org_id)
