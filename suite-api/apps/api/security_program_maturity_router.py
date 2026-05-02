"""Security Program Maturity Router — ALDECI.

CMMI-style security program maturity scoring across governance domains.

Prefix: /api/v1/program-maturity
Auth: api_key_auth on ALL endpoints (router-level dependency)

Routes:
  POST   /api/v1/program-maturity/domains                        register_domain
  GET    /api/v1/program-maturity/domains                        list_domains
  POST   /api/v1/program-maturity/domains/{id}/assess            assess_domain
  POST   /api/v1/program-maturity/assessments                    create_assessment
  POST   /api/v1/program-maturity/assessments/{id}/complete      complete_assessment
  GET    /api/v1/program-maturity/assessments                    list_assessments
  POST   /api/v1/program-maturity/domains/{id}/improvements      add_improvement
  POST   /api/v1/program-maturity/improvements/{id}/complete     complete_improvement
  GET    /api/v1/program-maturity/roadmap                        get_roadmap
  GET    /api/v1/program-maturity/summary                        get_summary
  GET    /api/v1/program-maturity/profile                        get_maturity_profile
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/program-maturity",
    tags=["Security Program Maturity"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_program_maturity_engine import SecurityProgramMaturityEngine
        _engine = SecurityProgramMaturityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterDomainRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    domain_name: str = Field(..., description="Name of the maturity domain")
    domain_type: str = Field(default="governance", description="Domain category")
    target_level: int = Field(default=3, ge=1, le=5, description="Target maturity level (1-5)")


class AssessDomainRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    current_level: int = Field(..., ge=1, le=5, description="Current maturity level (1-5)")
    score: float = Field(..., ge=0.0, le=100.0, description="Assessment score (0-100)")
    evidence: str = Field(default="", description="Supporting evidence")


class CreateAssessmentRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    assessment_name: str = Field(..., description="Name of the formal assessment")
    assessor: str = Field(default="", description="Assessor name or team")


class CompleteAssessmentRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")


class AddImprovementRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    improvement_name: str = Field(..., description="Name of the improvement initiative")
    priority: str = Field(default="medium", description="Priority: critical/high/medium/low")
    target_level: int = Field(default=3, ge=1, le=5, description="Target maturity level")
    effort_days: int = Field(default=0, ge=0, description="Estimated effort in days")
    due_date: str = Field(default="", description="ISO-8601 due date")


class CompleteImprovementRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/domains", summary="Register a new maturity domain")
def register_domain(req: RegisterDomainRequest) -> Dict[str, Any]:
    try:
        return _get_engine().register_domain(
            org_id=req.org_id,
            domain_name=req.domain_name,
            domain_type=req.domain_type,
            target_level=req.target_level,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/domains", summary="List all maturity domains for an org")
def list_domains(org_id: str = Query(..., description="Organisation identifier")) -> List[Dict[str, Any]]:
    return _get_engine().list_domains(org_id=org_id)


@router.post("/domains/{domain_id}/assess", summary="Assess a maturity domain")
def assess_domain(domain_id: str, req: AssessDomainRequest) -> Dict[str, Any]:
    try:
        return _get_engine().assess_domain(
            domain_id=domain_id,
            org_id=req.org_id,
            current_level=req.current_level,
            score=req.score,
            evidence=req.evidence,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/assessments", summary="Create a formal assessment")
def create_assessment(req: CreateAssessmentRequest) -> Dict[str, Any]:
    try:
        return _get_engine().create_assessment(
            org_id=req.org_id,
            assessment_name=req.assessment_name,
            assessor=req.assessor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/assessments/{assessment_id}/complete", summary="Complete a formal assessment")
def complete_assessment(assessment_id: str, req: CompleteAssessmentRequest) -> Dict[str, Any]:
    try:
        return _get_engine().complete_assessment(
            assessment_id=assessment_id,
            org_id=req.org_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/assessments", summary="List assessments for an org")
def list_assessments(org_id: str = Query(..., description="Organisation identifier")) -> List[Dict[str, Any]]:
    return _get_engine().list_assessments(org_id=org_id)


@router.post("/domains/{domain_id}/improvements", summary="Add an improvement plan to a domain")
def add_improvement(domain_id: str, req: AddImprovementRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_improvement(
            domain_id=domain_id,
            org_id=req.org_id,
            improvement_name=req.improvement_name,
            priority=req.priority,
            target_level=req.target_level,
            effort_days=req.effort_days,
            due_date=req.due_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/improvements/{improvement_id}/complete", summary="Mark an improvement as completed")
def complete_improvement(improvement_id: str, req: CompleteImprovementRequest) -> Dict[str, Any]:
    try:
        return _get_engine().complete_improvement(
            improvement_id=improvement_id,
            org_id=req.org_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/roadmap", summary="Get improvement roadmap ordered by priority then effort")
def get_roadmap(org_id: str = Query(..., description="Organisation identifier")) -> List[Dict[str, Any]]:
    return _get_engine().get_roadmap(org_id=org_id)


@router.get("/summary", summary="Get maturity summary for an org")
def get_summary(org_id: str = Query(..., description="Organisation identifier")) -> Dict[str, Any]:
    return _get_engine().get_summary(org_id=org_id)


@router.get("/profile", summary="Get full maturity profile with improvements per domain")
def get_maturity_profile(org_id: str = Query(..., description="Organisation identifier")) -> List[Dict[str, Any]]:
    return _get_engine().get_maturity_profile(org_id=org_id)
