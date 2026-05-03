"""Security Awareness Training Router — ALDECI.

Endpoints:
  GET  /api/v1/security-training/courses                      — list courses
  POST /api/v1/security-training/courses                      — create course
  GET  /api/v1/security-training/enrollments                  — list enrollments
  POST /api/v1/security-training/enrollments                  — enroll user
  POST /api/v1/security-training/enrollments/{id}/complete    — complete enrollment
  GET  /api/v1/security-training/campaigns                    — list campaigns
  POST /api/v1/security-training/campaigns                    — create campaign
  GET  /api/v1/security-training/stats                        — org-level stats
  GET  /api/v1/security-training/users/{user_id}/progress     — user progress
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.security_training_engine import SecurityTrainingEngine
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/security-training", tags=["security-training"])

# Module-level singleton
_engine = None  # lazy-initialised on first request


def _get_engine() -> SecurityTrainingEngine:
    global _engine
    if _engine is None:
        _engine = SecurityTrainingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateCourseRequest(BaseModel):
    title: str
    description: str = ""
    category: str = "compliance"
    duration_minutes: int = 30
    difficulty: str = "beginner"
    format: str = "video"
    passing_score: int = 70


class EnrollUserRequest(BaseModel):
    course_id: str
    user_id: str
    due_date: Optional[str] = None


class CompleteCourseRequest(BaseModel):
    score: int = Field(..., ge=0, le=100)


class CreateCampaignRequest(BaseModel):
    name: str
    target_group: str = ""
    course_ids: List[str] = Field(default_factory=list)
    due_date: Optional[str] = None
    status: str = "draft"
    completion_rate: float = 0.0


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/courses")
def list_courses(
    category: Optional[str] = Query(None, description="Filter by category"),
    org_id: str = Depends(get_org_id),
    engine: SecurityTrainingEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List training courses for the org."""
    return engine.list_courses(org_id, category=category)


@router.post("/courses", status_code=status.HTTP_201_CREATED)
def create_course(
    req: CreateCourseRequest,
    org_id: str = Depends(get_org_id),
    engine: SecurityTrainingEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Create a new training course."""
    return engine.create_course(org_id, req.model_dump())


@router.get("/enrollments")
def list_enrollments(
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    course_id: Optional[str] = Query(None, description="Filter by course ID"),
    org_id: str = Depends(get_org_id),
    engine: SecurityTrainingEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List enrollments for the org."""
    return engine.list_enrollments(org_id, user_id=user_id, course_id=course_id)


@router.post("/enrollments", status_code=status.HTTP_201_CREATED)
def enroll_user(
    req: EnrollUserRequest,
    org_id: str = Depends(get_org_id),
    engine: SecurityTrainingEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Enroll a user in a training course."""
    return engine.enroll_user(
        org_id, req.course_id, req.user_id, due_date=req.due_date
    )


@router.post("/enrollments/{enrollment_id}/complete")
def complete_enrollment(
    enrollment_id: str,
    req: CompleteCourseRequest,
    org_id: str = Depends(get_org_id),
    engine: SecurityTrainingEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Record completion of a course enrollment."""
    try:
        return engine.complete_course(org_id, enrollment_id, req.score)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get("/campaigns")
def list_campaigns(
    org_id: str = Depends(get_org_id),
    engine: SecurityTrainingEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List training campaigns for the org."""
    return engine.list_campaigns(org_id)


@router.post("/campaigns", status_code=status.HTTP_201_CREATED)
def create_campaign(
    req: CreateCampaignRequest,
    org_id: str = Depends(get_org_id),
    engine: SecurityTrainingEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Create a new training campaign."""
    return engine.create_campaign(org_id, req.model_dump())


@router.get("/stats")
def get_stats(
    org_id: str = Depends(get_org_id),
    engine: SecurityTrainingEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Return aggregated training statistics for the org."""
    return engine.get_training_stats(org_id)


@router.get("/users/{user_id}/progress")
def get_user_progress(
    user_id: str,
    org_id: str = Depends(get_org_id),
    engine: SecurityTrainingEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Return training progress summary for a specific user."""
    return engine.get_user_progress(org_id, user_id)


# ---------------------------------------------------------------------------
# Root summary endpoint (5-state envelope)
# ---------------------------------------------------------------------------


@router.get("/")
def get_security_training_root_summary(
    org_id: str = Depends(get_org_id),
    engine: SecurityTrainingEngine = Depends(_get_engine),
):
    """Return a 5-state summary envelope for the Security Training domain.

    States:
      healthy   — courses and enrollments exist, no overdue assignments
      degraded  — overdue enrollments requiring attention
      empty     — no courses configured yet
      error     — engine raised an exception
      unknown   — unexpected summary structure
    """
    try:
        stats = engine.get_training_stats(org_id)
    except Exception as exc:
        logger.error("security_training.summary error: %s", exc)
        return {
            "status": "error",
            "org_id": org_id,
            "error": str(exc),
            "domain": "security-training",
        }

    total_courses = stats.get("total_courses", 0)
    overdue = stats.get("overdue_count", 0)
    total_assignments = stats.get("total_assignments", 0)

    if total_courses == 0:
        status = "empty"
    elif overdue > 0:
        status = "degraded"
    else:
        status = "healthy"

    envelope = {
        "status": status,
        "org_id": org_id,
        "domain": "security-training",
        "summary": stats,
    }
    if status == "empty":
        envelope["hint"] = (
            "Create courses via POST /api/v1/security-training/courses "
            "to begin security training programs."
        )
    elif status == "degraded":
        envelope["hint"] = (
            f"{overdue} overdue enrollment(s) require attention. "
            "Review GET /api/v1/security-training/stats for details."
        )
    return envelope
