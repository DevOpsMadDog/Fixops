"""
Compliance Questionnaire Engine API.

8 endpoints for managing vendor security questionnaires with auto-answering.

  POST   /api/v1/questionnaires                        — create questionnaire
  GET    /api/v1/questionnaires                        — list questionnaires
  GET    /api/v1/questionnaires/{id}                   — get questionnaire
  POST   /api/v1/questionnaires/{id}/auto-answer       — auto-fill answers
  PATCH  /api/v1/questionnaires/{id}/questions/{qid}   — update single answer
  POST   /api/v1/questionnaires/{id}/submit            — mark as submitted
  GET    /api/v1/questionnaires/{id}/export            — export JSON or CSV
  GET    /api/v1/questionnaires/answer-bank            — list reusable answers
  GET    /api/v1/questionnaires/templates              — list available templates
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.questionnaire_engine import (
    QuestionCategory,
    QuestionnaireEngine,
    get_questionnaire_engine,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/questionnaires", tags=["questionnaires"])

_engine: Optional[QuestionnaireEngine] = None


def _get_engine() -> QuestionnaireEngine:
    """Return shared QuestionnaireEngine instance."""
    global _engine
    if _engine is None:
        _engine = get_questionnaire_engine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateQuestionnaireRequest(BaseModel):
    name: str = Field(..., description="Questionnaire display name")
    vendor_name: str = Field(..., description="Target vendor / recipient name")
    org_id: str = Field("default", description="Organisation identifier")
    template_type: Optional[str] = Field(
        None, description="One of: soc2, vendor_assessment, sig_lite"
    )
    custom_questions: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Custom questions list: [{text: str, category: str}]",
    )


class UpdateAnswerRequest(BaseModel):
    answer: str = Field(..., description="Answer text")
    evidence_refs: Optional[List[str]] = Field(
        None, description="List of evidence/control references"
    )


class AddAnswerBankRequest(BaseModel):
    question_key: str = Field(..., description="Canonical question text (lowercase)")
    category: QuestionCategory
    answer: str
    evidence_refs: Optional[List[str]] = None
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=Dict[str, Any], status_code=201, dependencies=[Depends(api_key_auth)])
async def create_questionnaire(
    body: CreateQuestionnaireRequest,
    engine: QuestionnaireEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Create a new questionnaire from a template or custom question list."""
    q = engine.create_questionnaire(
        name=body.name,
        vendor_name=body.vendor_name,
        org_id=body.org_id,
        template_type=body.template_type,
        custom_questions=body.custom_questions,
    )
    return q.model_dump()


@router.get("/templates", response_model=List[Dict[str, Any]])
async def list_templates(
    engine: QuestionnaireEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List available questionnaire templates (SOC2, vendor assessment, SIG Lite)."""
    return engine.get_available_templates()


@router.get("/answer-bank", response_model=List[Dict[str, Any]], dependencies=[Depends(api_key_auth)])
async def get_answer_bank(
    org_id: str = Query("default", description="Organisation identifier"),
    engine: QuestionnaireEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """Return all reusable answers from the answer bank."""
    return engine.get_answer_bank(org_id=org_id)


@router.post("/answer-bank", response_model=Dict[str, Any], status_code=201, dependencies=[Depends(api_key_auth)])
async def add_to_answer_bank(
    body: AddAnswerBankRequest,
    engine: QuestionnaireEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Add or update a custom answer in the org's answer bank."""
    return engine.add_to_answer_bank(
        question_key=body.question_key,
        category=body.category,
        answer=body.answer,
        evidence_refs=body.evidence_refs,
        confidence=body.confidence,
        org_id=body.org_id,
    )


@router.get("", response_model=List[Dict[str, Any]], dependencies=[Depends(api_key_auth)])
async def list_questionnaires(
    org_id: str = Query("default", description="Organisation identifier"),
    engine: QuestionnaireEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List all questionnaires for an organisation."""
    questionnaires = engine.list_questionnaires(org_id=org_id)
    return [q.model_dump() for q in questionnaires]


@router.get("/{questionnaire_id}", response_model=Dict[str, Any], dependencies=[Depends(api_key_auth)])
async def get_questionnaire(
    questionnaire_id: str,
    engine: QuestionnaireEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Retrieve a questionnaire with all questions and current answers."""
    q = engine.get_questionnaire(questionnaire_id)
    if q is None:
        raise HTTPException(status_code=404, detail=f"Questionnaire '{questionnaire_id}' not found")
    return q.model_dump()


@router.post("/{questionnaire_id}/auto-answer", response_model=Dict[str, Any], dependencies=[Depends(api_key_auth)])
async def auto_answer(
    questionnaire_id: str,
    engine: QuestionnaireEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Auto-fill unanswered questions using ALDECI capability templates."""
    try:
        q = engine.auto_answer(questionnaire_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return q.model_dump()


@router.patch(
    "/{questionnaire_id}/questions/{question_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(api_key_auth)],
)
async def update_answer(
    questionnaire_id: str,
    question_id: str,
    body: UpdateAnswerRequest,
    engine: QuestionnaireEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Manually override an answer for a specific question."""
    try:
        question = engine.update_answer(
            questionnaire_id=questionnaire_id,
            question_id=question_id,
            answer=body.answer,
            evidence_refs=body.evidence_refs,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return question.model_dump()


@router.post("/{questionnaire_id}/submit", response_model=Dict[str, Any], dependencies=[Depends(api_key_auth)])
async def submit_questionnaire(
    questionnaire_id: str,
    engine: QuestionnaireEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Mark questionnaire as submitted with current timestamp."""
    try:
        q = engine.submit_questionnaire(questionnaire_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return q.model_dump()


@router.get("/{questionnaire_id}/export", dependencies=[Depends(api_key_auth)])
async def export_questionnaire(
    questionnaire_id: str,
    format: str = Query("json", description="Export format: json or csv"),
    engine: QuestionnaireEngine = Depends(_get_engine),
):
    """Export questionnaire as PDF-ready JSON or CSV."""
    try:
        content = engine.export_questionnaire(questionnaire_id, format=format)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    if format == "csv":
        return PlainTextResponse(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="questionnaire-{questionnaire_id}.csv"'},
        )
    return PlainTextResponse(content=content, media_type="application/json")
