"""Security Awareness Program Router — ALDECI.

Endpoints for the Security Awareness Program engine.

Prefix: /api/v1/awareness-program
Auth:   api_key_auth dependency on ALL endpoints

Routes:
  POST /api/v1/awareness-program/programs                    create_program
  POST /api/v1/awareness-program/programs/{id}/enroll        enroll_user
  PUT  /api/v1/awareness-program/enrollments/{id}/complete   record_completion
  POST /api/v1/awareness-program/events                      record_event
  GET  /api/v1/awareness-program/programs/{id}/stats         get_program_stats
  GET  /api/v1/awareness-program/department-compliance       get_department_compliance
  GET  /api/v1/awareness-program/overdue                     get_overdue_enrollments
  GET  /api/v1/awareness-program/summary                     get_program_summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/awareness-program",
    tags=["Security Awareness Program"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_awareness_program_engine import (
            SecurityAwarenessProgramEngine,
        )
        _engine = SecurityAwarenessProgramEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ProgramCreate(BaseModel):
    program_name: str
    program_type: str
    target_audience: str = "all_staff"
    duration_mins: int = 30
    frequency: str = "annual"
    passing_score: int = 70


class EnrollUser(BaseModel):
    user_id: str
    user_name: str = ""
    department: str = ""


class CompletionRecord(BaseModel):
    score: int


class EventRecord(BaseModel):
    event_type: str
    description: str = ""
    affected_users: int = 0
    department: str = ""
    event_date: str
    response_action: str = ""


# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_awareness_programs(org_id: str = Query("default")) -> Dict[str, Any]:
    """List security awareness programs for the org."""
    programs = _get_engine().list_programs(org_id=org_id)
    return {"org_id": org_id, "programs": programs, "total": len(programs)}


@router.post("/programs", dependencies=[Depends(api_key_auth)], status_code=201)
def create_program(body: ProgramCreate, org_id: str = Query(default="default")):
    """Create a new awareness program."""
    try:
        return _get_engine().create_program(
            org_id=org_id,
            program_name=body.program_name,
            program_type=body.program_type,
            target_audience=body.target_audience,
            duration_mins=body.duration_mins,
            frequency=body.frequency,
            passing_score=body.passing_score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/programs/{program_id}/enroll", dependencies=[Depends(api_key_auth)], status_code=201)
def enroll_user(program_id: str, body: EnrollUser, org_id: str = Query(default="default")):
    """Enroll a user in a program (dedup safe)."""
    try:
        return _get_engine().enroll_user(
            program_id=program_id,
            org_id=org_id,
            user_id=body.user_id,
            user_name=body.user_name,
            department=body.department,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Enrollments
# ---------------------------------------------------------------------------

@router.put("/enrollments/{enrollment_id}/complete", dependencies=[Depends(api_key_auth)])
def record_completion(enrollment_id: str, body: CompletionRecord, org_id: str = Query(default="default")):
    """Record completion of an enrollment with a score."""
    try:
        return _get_engine().record_completion(
            enrollment_id=enrollment_id,
            org_id=org_id,
            score=body.score,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@router.post("/events", dependencies=[Depends(api_key_auth)], status_code=201)
def record_event(body: EventRecord, org_id: str = Query(default="default")):
    """Record an awareness event."""
    try:
        return _get_engine().record_event(
            org_id=org_id,
            event_type=body.event_type,
            description=body.description,
            affected_users=body.affected_users,
            department=body.department,
            event_date=body.event_date,
            response_action=body.response_action,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats and queries
# ---------------------------------------------------------------------------

@router.get("/programs/{program_id}/stats", dependencies=[Depends(api_key_auth)])
def get_program_stats(program_id: str, org_id: str = Query(default="default")):
    """Return program stats including completion rate, pass rate, dept breakdown."""
    try:
        return _get_engine().get_program_stats(program_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/department-compliance", dependencies=[Depends(api_key_auth)])
def get_department_compliance(org_id: str = Query(default="default")):
    """Return per-department compliance rates."""
    return _get_engine().get_department_compliance(org_id)


@router.get("/overdue", dependencies=[Depends(api_key_auth)])
def get_overdue_enrollments(org_id: str = Query(default="default")):
    """Return enrollments overdue (not completed within 30 days)."""
    return _get_engine().get_overdue_enrollments(org_id)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_program_summary(org_id: str = Query(default="default")):
    """Return org-level program summary statistics."""
    return _get_engine().get_program_summary(org_id)
