"""Security Questionnaire Router — ALDECI.

Endpoints for SecurityQuestionnaireEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/security-questionnaires
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/security-questionnaires/questionnaires                       create_questionnaire
  POST /api/v1/security-questionnaires/questionnaires/{id}/questions         add_question
  POST /api/v1/security-questionnaires/assessments                           send_assessment
  POST /api/v1/security-questionnaires/assessments/{id}/responses            submit_response
  POST /api/v1/security-questionnaires/assessments/{id}/score                score_assessment
  GET  /api/v1/security-questionnaires/assessments/{id}                      get_assessment
  GET  /api/v1/security-questionnaires/assessments                           list_assessments
  GET  /api/v1/security-questionnaires/overdue                               get_overdue_assessments
  GET  /api/v1/security-questionnaires/vendor/{vendor_id}/summary            get_vendor_risk_summary
"""
from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-questionnaires",
    tags=["Security Questionnaires"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_questionnaire_engine import SecurityQuestionnaireEngine
        _engine = SecurityQuestionnaireEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class QuestionnaireCreate(BaseModel):
    questionnaire_name: str
    questionnaire_type: str = "vendor"
    framework: str = "custom"


class QuestionCreate(BaseModel):
    question_text: str
    question_category: str = "governance"
    weight: float = 1.0
    required: bool = True


class AssessmentSend(BaseModel):
    questionnaire_id: str
    vendor_id: str
    vendor_name: str
    due_date: str


class ResponseSubmit(BaseModel):
    question_id: str
    response_text: str = ""
    response_value: int = 0


# ---------------------------------------------------------------------------
# Questionnaires
# ---------------------------------------------------------------------------

@router.post("/questionnaires", dependencies=[Depends(api_key_auth)], status_code=201)
def create_questionnaire(body: QuestionnaireCreate, org_id: str = Query(default="default")):
    """Create a new security questionnaire template."""
    try:
        return _get_engine().create_questionnaire(
            org_id,
            body.questionnaire_name,
            questionnaire_type=body.questionnaire_type,
            framework=body.framework,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/questionnaires/{questionnaire_id}/questions",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_question(questionnaire_id: str, body: QuestionCreate, org_id: str = Query(default="default")):
    """Add a question to an existing questionnaire."""
    try:
        return _get_engine().add_question(
            questionnaire_id,
            org_id,
            body.question_text,
            question_category=body.question_category,
            weight=body.weight,
            required=body.required,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------

@router.post("/assessments", dependencies=[Depends(api_key_auth)], status_code=201)
def send_assessment(body: AssessmentSend, org_id: str = Query(default="default")):
    """Send a questionnaire to a vendor for completion."""
    try:
        return _get_engine().send_assessment(
            org_id,
            body.questionnaire_id,
            body.vendor_id,
            body.vendor_name,
            body.due_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/assessments/{assessment_id}/responses",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def submit_response(assessment_id: str, body: ResponseSubmit, org_id: str = Query(default="default")):
    """Submit a response to a question in an assessment."""
    try:
        return _get_engine().submit_response(
            assessment_id,
            body.question_id,
            org_id,
            body.response_text,
            body.response_value,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/assessments/{assessment_id}/score",
    dependencies=[Depends(api_key_auth)],
)
def score_assessment(assessment_id: str, org_id: str = Query(default="default")):
    """Manually trigger scoring of an assessment."""
    try:
        result = _get_engine().score_assessment(assessment_id, org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.get("/assessments/{assessment_id}", dependencies=[Depends(api_key_auth)])
def get_assessment(assessment_id: str, org_id: str = Query(default="default")):
    """Get an assessment with its responses."""
    result = _get_engine().get_assessment(assessment_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.get("/assessments", dependencies=[Depends(api_key_auth)])
def list_assessments(
     org_id: str = Query(default="default"),
    vendor_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List assessments for an org with optional filters."""
    return _get_engine().list_assessments(org_id, vendor_id=vendor_id, status=status)


@router.get("", dependencies=[Depends(api_key_auth)])
def get_root(org_id: str = Query(default="default")):
    """Root endpoint — returns assessments list for dashboard health-checks."""
    return _get_engine().list_assessments(org_id)


@router.get("/overdue", dependencies=[Depends(api_key_auth)])
def get_overdue_assessments(org_id: str = Query(default="default")):
    """Return assessments that are past their due date."""
    return _get_engine().get_overdue_assessments(org_id)


@router.get("/vendor/{vendor_id}/summary", dependencies=[Depends(api_key_auth)])
def get_vendor_risk_summary(vendor_id: str, org_id: str = Query(default="default")):
    """Return risk summary for a specific vendor."""
    summaries = _get_engine().get_vendor_risk_summary(org_id)
    vendor_summaries = [s for s in summaries if s["vendor_id"] == vendor_id]
    return vendor_summaries
