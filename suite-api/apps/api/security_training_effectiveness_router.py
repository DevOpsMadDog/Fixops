"""Security Training Effectiveness Router — ALDECI.

Endpoints for the Security Training Effectiveness engine.

Prefix: /api/v1/training-effectiveness
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/training-effectiveness/programs                     create_program
  GET   /api/v1/training-effectiveness/programs                     list_programs
  GET   /api/v1/training-effectiveness/programs/{id}/effectiveness  get_effectiveness
  POST  /api/v1/training-effectiveness/programs/{id}/enroll         enroll
  POST  /api/v1/training-effectiveness/programs/{id}/complete       record_completion
  POST  /api/v1/training-effectiveness/programs/{id}/retention      record_retention
  GET   /api/v1/training-effectiveness/department-compliance        get_department_compliance
  GET   /api/v1/training-effectiveness/summary                      get_summary
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/training-effectiveness",
    tags=["Security Training Effectiveness"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_training_effectiveness_engine import (
            SecurityTrainingEffectivenessEngine,
        )
        _engine = SecurityTrainingEffectivenessEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ProgramCreate(BaseModel):
    program_name: str
    training_type: str = "awareness"
    target_audience: str = "all"
    delivery_method: str = "online"
    duration_mins: int = 60
    passing_score: float = 70.0


class EnrollRequest(BaseModel):
    employee_id: str
    department: str = ""


class CompletionRequest(BaseModel):
    employee_id: str
    pre_score: float
    post_score: float
    time_spent_mins: int = 0


class RetentionRequest(BaseModel):
    employee_id: str
    retention_score: float
    days_since_training: int = 0


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
def list_training_effectiveness(org_id: str = Query("default")):
    """Get security training effectiveness summary for the org."""
    return _get_engine().get_summary(org_id=org_id)


@router.post("/programs", status_code=201)
def create_program(body: ProgramCreate, org_id: str = Query(default="default")):
    """Create a new training program."""
    try:
        return _get_engine().create_program(
            org_id=org_id,
            program_name=body.program_name,
            training_type=body.training_type,
            target_audience=body.target_audience,
            delivery_method=body.delivery_method,
            duration_mins=body.duration_mins,
            passing_score=body.passing_score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/programs")
def list_programs(
     org_id: str = Query(default="default"),
    training_type: Optional[str] = Query(None),
):
    """List training programs, optionally filtered by training_type."""
    return _get_engine().list_programs(org_id=org_id, training_type=training_type)


@router.get("/programs/{program_id}/effectiveness")
def get_effectiveness(program_id: str, org_id: str = Query(default="default")):
    """Return full effectiveness report for a program."""
    try:
        return _get_engine().get_effectiveness(program_id=program_id, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/programs/{program_id}/enroll", status_code=201)
def enroll(program_id: str, body: EnrollRequest, org_id: str = Query(default="default")):
    """Enroll an employee in a training program."""
    try:
        return _get_engine().enroll(
            program_id=program_id,
            org_id=org_id,
            employee_id=body.employee_id,
            department=body.department,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/programs/{program_id}/complete")
def record_completion(program_id: str, body: CompletionRequest, org_id: str = Query(default="default")):
    """Record a training completion with pre/post scores."""
    try:
        return _get_engine().record_completion(
            program_id=program_id,
            org_id=org_id,
            employee_id=body.employee_id,
            pre_score=body.pre_score,
            post_score=body.post_score,
            time_spent_mins=body.time_spent_mins,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/programs/{program_id}/retention", status_code=201)
def record_retention(program_id: str, body: RetentionRequest, org_id: str = Query(default="default")):
    """Record a knowledge retention assessment."""
    return _get_engine().record_retention(
        program_id=program_id,
        org_id=org_id,
        employee_id=body.employee_id,
        retention_score=body.retention_score,
        days_since_training=body.days_since_training,
    )


@router.get("/department-compliance")
def get_department_compliance(org_id: str = Query(default="default")):
    """Return completion rate and avg score by department."""
    return _get_engine().get_department_compliance(org_id=org_id)


@router.get("/summary")
def get_summary(org_id: str = Query(default="default")):
    """Return aggregate summary across all programs."""
    return _get_engine().get_summary(org_id=org_id)
