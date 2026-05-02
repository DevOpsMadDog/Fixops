"""Security Tabletop Router — ALDECI.

Endpoints for the Security Tabletop engine.

Prefix: /api/v1/tabletop
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/tabletop/exercises                         create_exercise
  GET  /api/v1/tabletop/exercises                         list_exercises
  GET  /api/v1/tabletop/exercises/{exercise_id}           get_exercise
  PUT  /api/v1/tabletop/exercises/{exercise_id}/complete  complete_exercise
  POST /api/v1/tabletop/participants                      add_participant
  GET  /api/v1/tabletop/exercises/{exercise_id}/participants  list_participants
  POST /api/v1/tabletop/findings                          record_finding
  GET  /api/v1/tabletop/findings                          list_findings
  GET  /api/v1/tabletop/stats                             get_tabletop_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tabletop",
    tags=["Security Tabletop"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_tabletop_engine import SecurityTabletopEngine
        _engine = SecurityTabletopEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ExerciseCreate(BaseModel):
    title: str
    scenario_type: str = "ransomware"
    status: str = "planned"
    scheduled_at: Optional[str] = None
    facilitator: str = ""
    participant_count: int = 0


class ExerciseComplete(BaseModel):
    overall_score: float


class ParticipantCreate(BaseModel):
    exercise_id: str
    name: str
    role: str = ""
    department: str = ""
    attended: bool = True
    performance_score: float = 0.0


class FindingCreate(BaseModel):
    exercise_id: str
    finding_type: str = "gap"
    title: str
    description: str = ""
    severity: str = "medium"
    status: str = "open"
    assigned_to: str = ""


# ---------------------------------------------------------------------------
# Exercises
# ---------------------------------------------------------------------------

@router.post("/exercises", dependencies=[Depends(api_key_auth)], status_code=201)
def create_exercise(body: ExerciseCreate, org_id: str = Query(default="default")):
    """Create a new tabletop exercise."""
    try:
        return _get_engine().create_exercise(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/exercises", dependencies=[Depends(api_key_auth)])
def list_exercises(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    scenario_type: Optional[str] = Query(None),
):
    """List exercises with optional filters."""
    return _get_engine().list_exercises(org_id, status=status, scenario_type=scenario_type)


@router.get("/exercises/{exercise_id}", dependencies=[Depends(api_key_auth)])
def get_exercise(exercise_id: str, org_id: str = Query(default="default")):
    """Get a single exercise by ID."""
    ex = _get_engine().get_exercise(org_id, exercise_id)
    if not ex:
        raise HTTPException(status_code=404, detail="Exercise not found")
    return ex


@router.put("/exercises/{exercise_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_exercise(exercise_id: str, body: ExerciseComplete, org_id: str = Query(default="default")):
    """Mark an exercise as completed with a score."""
    try:
        return _get_engine().complete_exercise(org_id, exercise_id, body.overall_score)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Participants
# ---------------------------------------------------------------------------

@router.post("/participants", dependencies=[Depends(api_key_auth)], status_code=201)
def add_participant(body: ParticipantCreate, org_id: str = Query(default="default")):
    """Add a participant to an exercise."""
    try:
        return _get_engine().add_participant(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/exercises/{exercise_id}/participants", dependencies=[Depends(api_key_auth)])
def list_participants(exercise_id: str, org_id: str = Query(default="default")):
    """List participants for a specific exercise."""
    return _get_engine().list_participants(org_id, exercise_id)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@router.post("/findings", dependencies=[Depends(api_key_auth)], status_code=201)
def record_finding(body: FindingCreate, org_id: str = Query(default="default")):
    """Record a finding from a tabletop exercise."""
    try:
        return _get_engine().record_finding(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
     org_id: str = Query(default="default"),
    exercise_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List findings with optional filters."""
    return _get_engine().list_findings(
        org_id, exercise_id=exercise_id, severity=severity, status=status
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_tabletop_stats(org_id: str = Query(default="default")):
    """Return aggregated tabletop statistics."""
    return _get_engine().get_tabletop_stats(org_id)
