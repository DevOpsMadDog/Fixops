"""Incident Lessons Router — ALDECI.

Endpoints for the Incident Lessons Learned engine.

Prefix: /api/v1/incident-lessons
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/incident-lessons/lessons                                   create_lesson
  GET  /api/v1/incident-lessons/lessons                                   list_lessons
  GET  /api/v1/incident-lessons/lessons/{lesson_id}                       get_lesson
  POST /api/v1/incident-lessons/lessons/{lesson_id}/actions               add_action_item
  POST /api/v1/incident-lessons/lessons/{lesson_id}/actions/{action_id}/complete   complete_action
  POST /api/v1/incident-lessons/lessons/{lesson_id}/reviews               review_lesson
  GET  /api/v1/incident-lessons/overdue-actions                           get_overdue_actions
  GET  /api/v1/incident-lessons/implementation-rate                       get_implementation_rate
  GET  /api/v1/incident-lessons/summary                                   get_summary
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/incident-lessons",
    tags=["Incident Lessons"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.incident_lessons_engine import IncidentLessonsEngine
        _engine = IncidentLessonsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class LessonCreate(BaseModel):
    incident_id: str
    title: str
    description: str = ""
    lesson_type: str
    severity: str
    identified_by: str = ""


class ActionItemCreate(BaseModel):
    action: str
    owner: str = ""
    due_date: str
    priority: str = "medium"


class LessonReview(BaseModel):
    reviewer: str
    outcome: str
    notes: str = ""


# ---------------------------------------------------------------------------
# Lessons
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_service_summary(org_id: str = Query(default="default")) -> dict:
    """Return incident-lessons service summary (lessons counts + overdue actions).

    5-state envelope: items/total/org_id/filters_applied/hint.
    """
    summary = _get_engine().get_lessons_summary(org_id)
    overdue = _get_engine().get_overdue_actions(org_id)
    rate = _get_engine().get_implementation_rate(org_id)
    items = [
        {"key": "summary", "value": summary},
        {"key": "implementation_rate", "value": rate},
        {"key": "overdue_actions_count", "value": len(overdue) if isinstance(overdue, list) else 0},
    ]
    envelope: dict = {
        "items": items,
        "total": len(items),
        "org_id": org_id,
        "filters_applied": {},
        "service": "incident-lessons",
    }
    total = summary.get("total", 0) if isinstance(summary, dict) else 0
    if total == 0:
        envelope["hint"] = (
            "No lessons-learned entries yet. Create one via "
            "POST /api/v1/incident-lessons/lessons after closing an incident."
        )
    return envelope


@router.post("/lessons", dependencies=[Depends(api_key_auth)], status_code=201)
def create_lesson(body: LessonCreate, org_id: str = Query(default="default")):
    """Create a new lessons-learned entry."""
    try:
        return _get_engine().create_lesson(
            org_id,
            body.incident_id,
            body.title,
            body.description,
            body.lesson_type,
            body.severity,
            body.identified_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/lessons", dependencies=[Depends(api_key_auth)])
def list_lessons(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    lesson_type: Optional[str] = Query(None),
):
    """List lessons with optional status/lesson_type filters."""
    return _get_engine().list_lessons(org_id, status=status, lesson_type=lesson_type)


@router.get("/lessons/{lesson_id}", dependencies=[Depends(api_key_auth)])
def get_lesson(lesson_id: str, org_id: str = Query(default="default")):
    """Get a lesson with its action_items and reviews."""
    lesson = _get_engine().get_lesson(lesson_id, org_id)
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")
    return lesson


# ---------------------------------------------------------------------------
# Action Items
# ---------------------------------------------------------------------------

@router.post("/lessons/{lesson_id}/actions", dependencies=[Depends(api_key_auth)], status_code=201)
def add_action_item(lesson_id: str, body: ActionItemCreate, org_id: str = Query(default="default")):
    """Add an action item to a lesson."""
    try:
        return _get_engine().add_action_item(
            lesson_id,
            org_id,
            body.action,
            body.owner,
            body.due_date,
            body.priority,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/lessons/{lesson_id}/actions/{action_id}/complete",
    dependencies=[Depends(api_key_auth)],
)
def complete_action(lesson_id: str, action_id: str, org_id: str = Query(default="default")):
    """Mark an action item as completed."""
    try:
        return _get_engine().complete_action(lesson_id, action_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Reviews
# ---------------------------------------------------------------------------

@router.post("/lessons/{lesson_id}/reviews", dependencies=[Depends(api_key_auth)], status_code=201)
def review_lesson(lesson_id: str, body: LessonReview, org_id: str = Query(default="default")):
    """Submit a review for a lesson."""
    try:
        return _get_engine().review_lesson(
            lesson_id, org_id, body.reviewer, body.outcome, body.notes
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

@router.get("/overdue-actions", dependencies=[Depends(api_key_auth)])
def get_overdue_actions(org_id: str = Query(default="default")):
    """Return action items past their due_date and not completed."""
    return _get_engine().get_overdue_actions(org_id)


@router.get("/implementation-rate", dependencies=[Depends(api_key_auth)])
def get_implementation_rate(org_id: str = Query(default="default")):
    """Return implementation rate stats."""
    return _get_engine().get_implementation_rate(org_id)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_summary(org_id: str = Query(default="default")):
    """Return lessons summary counts by status and lesson_type."""
    return _get_engine().get_lessons_summary(org_id)
