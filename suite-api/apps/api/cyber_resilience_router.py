"""Cyber Resilience Router — ALDECI.

Endpoints for the Cyber Resilience engine.

Prefix: /api/v1/cyber-resilience
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/cyber-resilience/assessments                          create_assessment
  PATCH /api/v1/cyber-resilience/assessments/{id}/maturity            update_maturity
  GET   /api/v1/cyber-resilience/assessments                          list_assessments
  GET   /api/v1/cyber-resilience/score                                get_resilience_score
  POST  /api/v1/cyber-resilience/exercises                            schedule_exercise
  POST  /api/v1/cyber-resilience/exercises/{id}/complete              complete_exercise
  GET   /api/v1/cyber-resilience/exercises                            get_exercise_history
  POST  /api/v1/cyber-resilience/metrics                              record_metric
  GET   /api/v1/cyber-resilience/metrics/summary                      get_metrics_summary
"""
from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cyber-resilience",
    tags=["Cyber Resilience"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cyber_resilience_engine import CyberResilienceEngine
        _engine = CyberResilienceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AssessmentCreate(BaseModel):
    assessment_name: str
    resilience_domain: str
    maturity_level: int
    max_level: int = 5
    evidence: str = ""
    assessor: str = ""
    next_review: str = ""


class MaturityUpdate(BaseModel):
    maturity_level: int
    evidence: str = ""


class ExerciseCreate(BaseModel):
    exercise_name: str
    exercise_type: str
    scenario: str = ""
    scheduled_date: str
    participants: int = 0


class ExerciseComplete(BaseModel):
    findings_count: int = 0
    gaps_identified: List[str] = []
    lessons_learned: List[str] = []


class MetricRecord(BaseModel):
    metric_name: str
    category: str
    value: float
    target: float
    unit: str = ""


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------

@router.post("/assessments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_assessment(body: AssessmentCreate, org_id: str = Query(default="default")):
    """Create a new resilience assessment."""
    try:
        return _get_engine().create_assessment(
            org_id=org_id,
            assessment_name=body.assessment_name,
            resilience_domain=body.resilience_domain,
            maturity_level=body.maturity_level,
            max_level=body.max_level,
            evidence=body.evidence,
            assessor=body.assessor,
            next_review=body.next_review,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/assessments/{assessment_id}/maturity", dependencies=[Depends(api_key_auth)])
def update_maturity(assessment_id: str, body: MaturityUpdate, org_id: str = Query(default="default")):
    """Update maturity level and recompute score."""
    try:
        result = _get_engine().update_maturity(
            assessment_id=assessment_id,
            org_id=org_id,
            maturity_level=body.maturity_level,
            evidence=body.evidence,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.get("/assessments", dependencies=[Depends(api_key_auth)])
def list_assessments(
     org_id: str = Query(default="default"),
    resilience_domain: Optional[str] = Query(None),
):
    """List assessments with optional domain filter."""
    return _get_engine().list_assessments(org_id, resilience_domain=resilience_domain)


@router.get("/score", dependencies=[Depends(api_key_auth)])
def get_resilience_score(org_id: str = Query(default="default")):
    """Return overall resilience score, by-domain breakdown, and maturity distribution."""
    return _get_engine().get_resilience_score(org_id)


# ---------------------------------------------------------------------------
# Exercises
# ---------------------------------------------------------------------------

@router.post("/exercises", dependencies=[Depends(api_key_auth)], status_code=201)
def schedule_exercise(body: ExerciseCreate, org_id: str = Query(default="default")):
    """Schedule a resilience exercise."""
    try:
        return _get_engine().schedule_exercise(
            org_id=org_id,
            exercise_name=body.exercise_name,
            exercise_type=body.exercise_type,
            scenario=body.scenario,
            scheduled_date=body.scheduled_date,
            participants=body.participants,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/exercises/{exercise_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_exercise(exercise_id: str, body: ExerciseComplete, org_id: str = Query(default="default")):
    """Mark exercise as completed and record findings."""
    result = _get_engine().complete_exercise(
        exercise_id=exercise_id,
        org_id=org_id,
        findings_count=body.findings_count,
        gaps_identified=body.gaps_identified,
        lessons_learned=body.lessons_learned,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Exercise not found")
    return result


@router.get("/exercises", dependencies=[Depends(api_key_auth)])
def get_exercise_history(
     org_id: str = Query(default="default"),
    exercise_type: Optional[str] = Query(None),
):
    """List exercises with optional type filter."""
    return _get_engine().get_exercise_history(org_id, exercise_type=exercise_type)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@router.post("/metrics", dependencies=[Depends(api_key_auth)], status_code=201)
def record_metric(body: MetricRecord, org_id: str = Query(default="default")):
    """Record a resilience metric measurement."""
    try:
        return _get_engine().record_metric(
            org_id=org_id,
            metric_name=body.metric_name,
            category=body.category,
            value=body.value,
            target=body.target,
            unit=body.unit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/metrics/summary", dependencies=[Depends(api_key_auth)])
def get_metrics_summary(org_id: str = Query(default="default")):
    """Return per-category metric summary."""
    return _get_engine().get_metrics_summary(org_id)
