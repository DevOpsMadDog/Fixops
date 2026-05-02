"""Security Culture Router — ALDECI.

Endpoints for the Security Culture engine.

Prefix: /api/v1/security-culture
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/security-culture/metrics                          record_metric
  GET    /api/v1/security-culture/metrics/{metric_name}/trend      get_metric_trend
  POST   /api/v1/security-culture/initiatives                      create_initiative
  PATCH  /api/v1/security-culture/initiatives/{id}/progress        update_initiative_progress
  POST   /api/v1/security-culture/assessments                      create_assessment
  GET    /api/v1/security-culture/assessments/latest               get_latest_assessment
  GET    /api/v1/security-culture/departments                      get_department_culture_scores
  GET    /api/v1/security-culture/summary                          get_culture_summary
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-culture",
    tags=["Security Culture"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_culture_engine import SecurityCultureEngine
        _engine = SecurityCultureEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class MetricCreate(BaseModel):
    metric_name: str
    metric_category: str
    value: float
    target_value: float
    department: str = ""
    source: str = ""


class InitiativeCreate(BaseModel):
    initiative_name: str
    initiative_type: str
    target_audience: str = ""
    start_date: str
    end_date: str


class InitiativeProgressUpdate(BaseModel):
    participants: int
    completion_rate: float
    impact_score: float


class AssessmentCreate(BaseModel):
    overall_score: float
    strengths: List[str] = []
    weaknesses: List[str] = []
    recommendations: List[str] = []
    assessed_by: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/metrics", dependencies=[Depends(api_key_auth)], status_code=201)
def record_metric(body: MetricCreate, org_id: str = Query(default="default")):
    """Record a security culture metric data point."""
    try:
        return _get_engine().record_metric(
            org_id=org_id,
            metric_name=body.metric_name,
            metric_category=body.metric_category,
            value=body.value,
            target_value=body.target_value,
            department=body.department,
            source=body.source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/metrics/{metric_name}/trend", dependencies=[Depends(api_key_auth)])
def get_metric_trend(
    metric_name: str,
     org_id: str = Query(default="default"),
    department: Optional[str] = Query(None),
    days: int = Query(90, ge=1),
):
    """Return metric trend data with direction."""
    return _get_engine().get_metric_trend(
        org_id, metric_name, department=department, days=days
    )


@router.post("/initiatives", dependencies=[Depends(api_key_auth)], status_code=201)
def create_initiative(body: InitiativeCreate, org_id: str = Query(default="default")):
    """Create a new security culture initiative."""
    try:
        return _get_engine().create_initiative(
            org_id=org_id,
            initiative_name=body.initiative_name,
            initiative_type=body.initiative_type,
            target_audience=body.target_audience,
            start_date=body.start_date,
            end_date=body.end_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch(
    "/initiatives/{initiative_id}/progress", dependencies=[Depends(api_key_auth)]
)
def update_initiative_progress(
    initiative_id: str, body: InitiativeProgressUpdate, org_id: str = Query(default="default")
):
    """Update progress on an initiative."""
    try:
        return _get_engine().update_initiative_progress(
            initiative_id=initiative_id,
            org_id=org_id,
            participants=body.participants,
            completion_rate=body.completion_rate,
            impact_score=body.impact_score,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/assessments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_assessment(body: AssessmentCreate, org_id: str = Query(default="default")):
    """Create a security culture maturity assessment."""
    return _get_engine().create_assessment(
        org_id=org_id,
        overall_score=body.overall_score,
        strengths=body.strengths,
        weaknesses=body.weaknesses,
        recommendations=body.recommendations,
        assessed_by=body.assessed_by,
    )


@router.get("/assessments/latest", dependencies=[Depends(api_key_auth)])
def get_latest_assessment(org_id: str = Query(default="default")):
    """Return the most recent culture assessment."""
    assessment = _get_engine().get_latest_assessment(org_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="No assessments found")
    return assessment


@router.get("/departments", dependencies=[Depends(api_key_auth)])
def get_department_culture_scores(org_id: str = Query(default="default")):
    """Return per-department culture scores."""
    return _get_engine().get_department_culture_scores(org_id)


@router.get("/", dependencies=[Depends(api_key_auth)])
def get_root(org_id: str = Query(default="default")):
    """Root endpoint — returns culture summary for dashboard health-checks."""
    return _get_engine().get_department_culture_scores(org_id)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_culture_summary(org_id: str = Query(default="default")):
    """Return overall security culture summary."""
    return _get_engine().get_culture_summary(org_id)
