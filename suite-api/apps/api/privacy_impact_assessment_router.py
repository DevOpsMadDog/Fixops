"""Privacy Impact Assessment Router — ALDECI.

Endpoints for the PrivacyImpactAssessmentEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/privacy-impact
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/privacy-impact/assessments                       create_assessment
  GET   /api/v1/privacy-impact/assessments                       list_assessments
  GET   /api/v1/privacy-impact/assessments/{id}                  get_assessment
  POST  /api/v1/privacy-impact/assessments/{id}/risks            add_risk
  PATCH /api/v1/privacy-impact/risks/{id}/status                 update_risk_status
  POST  /api/v1/privacy-impact/assessments/{id}/consultations    add_consultation
  POST  /api/v1/privacy-impact/consultations/{id}/complete       complete_consultation
  POST  /api/v1/privacy-impact/assessments/{id}/approve          approve_assessment
  GET   /api/v1/privacy-impact/high-risk                         get_high_risk_assessments
  GET   /api/v1/privacy-impact/summary                           get_summary
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/privacy-impact",
    tags=["Privacy Impact Assessment"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.privacy_impact_assessment_engine import PrivacyImpactAssessmentEngine
        _engine = PrivacyImpactAssessmentEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AssessmentCreate(BaseModel):
    project_name: str
    assessment_type: str = "pia"
    data_controller: str = ""
    data_processor: str = ""
    legal_basis: str = ""
    data_categories: List[str] = []
    data_subjects: List[str] = []
    retention_period_days: int = 365
    cross_border_transfer: bool = False


class RiskAdd(BaseModel):
    risk_category: str
    risk_description: str = ""
    likelihood: str = "medium"
    impact: str = "medium"
    mitigation: str = ""
    residual_risk: str = "medium"


class RiskStatusUpdate(BaseModel):
    status: str


class ConsultationAdd(BaseModel):
    consulted_party: str
    consultation_type: str = "internal"
    required: bool = False


class ConsultationComplete(BaseModel):
    outcome: str


class AssessmentApprove(BaseModel):
    dpo: str


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------

@router.get("/")
def list_privacy_impact(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get privacy impact assessment summary for the org."""
    return _get_engine().get_summary(org_id)


@router.post("/assessments", status_code=201)
def create_assessment(body: AssessmentCreate, org_id: str = Query(default="default")):
    """Create a new PIA/DPIA assessment."""
    try:
        return _get_engine().create_assessment(
            org_id=org_id,
            project_name=body.project_name,
            assessment_type=body.assessment_type,
            data_controller=body.data_controller,
            data_processor=body.data_processor,
            legal_basis=body.legal_basis,
            data_categories=body.data_categories,
            data_subjects=body.data_subjects,
            retention_period_days=body.retention_period_days,
            cross_border_transfer=body.cross_border_transfer,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assessments")
def list_assessments(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    assessment_type: Optional[str] = Query(None),
):
    """List assessments with optional status/type filters."""
    return _get_engine().list_assessments(
        org_id, status=status, assessment_type=assessment_type
    )


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str, org_id: str = Query(default="default")):
    """Get a single assessment with its risks and consultations."""
    result = _get_engine().get_assessment(assessment_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.post("/assessments/{assessment_id}/approve")
def approve_assessment(
    assessment_id: str, body: AssessmentApprove, org_id: str = Query(default="default")
):
    """DPO approval — validates all required consultations are completed first."""
    try:
        return _get_engine().approve_assessment(assessment_id, org_id, body.dpo)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Risks
# ---------------------------------------------------------------------------

@router.post("/assessments/{assessment_id}/risks", status_code=201)
def add_risk(assessment_id: str, body: RiskAdd, org_id: str = Query(default="default")):
    """Add a risk to an assessment and recompute its risk_score/risk_level."""
    try:
        return _get_engine().add_risk(
            assessment_id=assessment_id,
            org_id=org_id,
            risk_category=body.risk_category,
            risk_description=body.risk_description,
            likelihood=body.likelihood,
            impact=body.impact,
            mitigation=body.mitigation,
            residual_risk=body.residual_risk,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/risks/{risk_id}/status")
def update_risk_status(risk_id: str, body: RiskStatusUpdate, org_id: str = Query(default="default")):
    """Update risk status (open/mitigated/accepted/transferred)."""
    try:
        result = _get_engine().update_risk_status(risk_id, org_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Risk not found")
    return result


# ---------------------------------------------------------------------------
# Consultations
# ---------------------------------------------------------------------------

@router.post("/assessments/{assessment_id}/consultations", status_code=201)
def add_consultation(
    assessment_id: str, body: ConsultationAdd, org_id: str = Query(default="default")
):
    """Add a consultation requirement to an assessment."""
    return _get_engine().add_consultation(
        assessment_id=assessment_id,
        org_id=org_id,
        consulted_party=body.consulted_party,
        consultation_type=body.consultation_type,
        required=body.required,
    )


@router.post("/consultations/{consultation_id}/complete")
def complete_consultation(
    consultation_id: str, body: ConsultationComplete, org_id: str = Query(default="default")
):
    """Mark a consultation as completed with outcome."""
    result = _get_engine().complete_consultation(consultation_id, org_id, body.outcome)
    if result is None:
        raise HTTPException(status_code=404, detail="Consultation not found")
    return result


# ---------------------------------------------------------------------------
# High-risk and summary
# ---------------------------------------------------------------------------

@router.get("/high-risk")
def get_high_risk_assessments(org_id: str = Query(default="default")):
    """Return assessments with risk_level in (critical, high)."""
    return _get_engine().get_high_risk_assessments(org_id)


@router.get("/summary")
def get_summary(org_id: str = Query(default="default")):
    """Return aggregated PIA summary for an org."""
    return _get_engine().get_summary(org_id)
