"""
ALDECI Purple Team Exercise Router.

REST API for collaborative red + blue team exercises:
  POST   /api/v1/purple-team/exercises                   — create exercise
  GET    /api/v1/purple-team/exercises                   — list exercises
  GET    /api/v1/purple-team/exercises/{id}              — get exercise
  POST   /api/v1/purple-team/exercises/{id}/run          — start/run exercise
  POST   /api/v1/purple-team/exercises/{id}/steps/{idx}  — record step result
  POST   /api/v1/purple-team/exercises/{id}/response     — add blue team action
  POST   /api/v1/purple-team/exercises/{id}/complete     — complete + auto-score
  GET    /api/v1/purple-team/exercises/{id}/report       — after-action report
  GET    /api/v1/purple-team/scenarios                   — scenario library
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from core.purple_team import (
        AfterActionReport,
        BlueTeamAction,
        ContainmentAction,
        DetectionEngine,
        Exercise,
        ExerciseScope,
        ExerciseStatus,
        ExerciseStep,
        StepOutcome,
        get_purple_team_engine,
    )
    _ENGINE_AVAILABLE = True
except ImportError as _e:
    _ENGINE_AVAILABLE = False
    _IMPORT_ERROR = str(_e)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/purple-team",
    tags=["purple-team"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class CreateExerciseRequest(BaseModel):
    name: str = Field(..., description="Exercise name")
    scenario_id: str = Field(..., description="Pre-built scenario ID (e.g. sc-001)")
    description: str = Field("", description="Optional exercise description")
    scope: str = Field("full", description="Exercise scope: full, edr_only, network, cloud, identity")
    red_team_lead: str = Field("red_team", description="Red team lead identifier")
    blue_team_lead: str = Field("blue_team", description="Blue team lead identifier")
    scheduled_at: Optional[str] = Field(None, description="ISO-8601 scheduled start time")
    tags: List[str] = Field(default_factory=list, description="Arbitrary tags")


class RecordStepRequest(BaseModel):
    outcome: str = Field(
        ...,
        description="Step outcome: executed, detected, blocked, missed",
    )
    detected: bool = Field(False, description="Was the step detected by ALDECI?")
    detection_engine: str = Field(
        "none",
        description="Which ALDECI engine detected it: siem, edr, ndr, soar, threat_intel, anomaly, manual, none",
    )
    alert_fired: bool = Field(False, description="Did an alert fire in the platform?")
    time_to_detect_seconds: Optional[float] = Field(
        None, description="Seconds from attack execution to detection"
    )
    detection_notes: str = Field("", description="Free-text detection notes")


class BlueTeamActionRequest(BaseModel):
    step_index: int = Field(..., description="Zero-based index of the step being responded to")
    action: str = Field(
        ...,
        description=(
            "Containment action: isolate_host, block_ip, disable_account, revoke_token, "
            "quarantine_file, firewall_rule, patch_applied, escalate, monitor"
        ),
    )
    actor: str = Field("blue_team", description="Who performed the action")
    description: str = Field("", description="Action details")
    effective: bool = Field(True, description="Was the action effective?")


class ExerciseSummaryResponse(BaseModel):
    exercise_id: str
    name: str
    scenario_name: str
    category: str
    status: str
    scope: str
    step_count: int
    steps_executed: int
    steps_detected: int
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    tags: List[str]


class ScenarioListResponse(BaseModel):
    scenario_id: str
    name: str
    category: str
    description: str
    threat_actor: str
    difficulty: str
    estimated_duration_minutes: int
    step_count: int
    techniques: List[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_engine():
    if not _ENGINE_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail=f"Purple team engine unavailable: {_IMPORT_ERROR}",
        )
    return get_purple_team_engine()


def _exercise_to_summary(ex: Exercise) -> ExerciseSummaryResponse:
    executed = sum(1 for s in ex.steps if s.outcome.value != "not_started")
    detected = sum(1 for s in ex.steps if s.detected)
    return ExerciseSummaryResponse(
        exercise_id=ex.exercise_id,
        name=ex.name,
        scenario_name=ex.scenario_name,
        category=ex.category,
        status=ex.status.value,
        scope=ex.scope.value,
        step_count=len(ex.steps),
        steps_executed=executed,
        steps_detected=detected,
        created_at=ex.created_at,
        started_at=ex.started_at,
        completed_at=ex.completed_at,
        tags=ex.tags,
    )


def _parse_enum(value: str, enum_cls, field_name: str):
    try:
        return enum_cls(value)
    except ValueError:
        valid = [e.value for e in enum_cls]
        raise HTTPException(
            status_code=422,
            detail=f"Invalid {field_name} '{value}'. Valid values: {valid}",
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/exercises",
    response_model=Dict[str, Any],
    summary="Create a purple team exercise",
    status_code=201,
)
def create_exercise(req: CreateExerciseRequest):
    """
    Create a new purple team exercise from a pre-built scenario.
    Returns the full exercise object including all steps.
    """
    engine = _require_engine()
    scope = _parse_enum(req.scope, ExerciseScope, "scope")

    try:
        ex = engine.create_exercise(
            name=req.name,
            scenario_id=req.scenario_id,
            description=req.description,
            scope=scope,
            red_team_lead=req.red_team_lead,
            blue_team_lead=req.blue_team_lead,
            scheduled_at=req.scheduled_at,
            tags=req.tags,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return ex.model_dump()


@router.get(
    "/exercises",
    response_model=List[ExerciseSummaryResponse],
    summary="List all exercises",
)
def list_exercises(
    status: Optional[str] = Query(None, description="Filter by status"),
    category: Optional[str] = Query(None, description="Filter by scenario category"),
):
    engine = _require_engine()
    exercises = engine.list_exercises()

    if status:
        exercises = [e for e in exercises if e.status.value == status]
    if category:
        exercises = [e for e in exercises if e.category == category]

    return [_exercise_to_summary(e) for e in exercises]


@router.get(
    "/exercises/{exercise_id}",
    response_model=Dict[str, Any],
    summary="Get a specific exercise",
)
def get_exercise(exercise_id: str):
    engine = _require_engine()
    ex = engine.get_exercise(exercise_id)
    if ex is None:
        raise HTTPException(status_code=404, detail=f"Exercise not found: {exercise_id}")
    return ex.model_dump()


@router.post(
    "/exercises/{exercise_id}/run",
    response_model=Dict[str, Any],
    summary="Start (run) an exercise",
)
def run_exercise(exercise_id: str):
    """
    Transitions exercise from draft/planned → active.
    Records the start timestamp.
    """
    engine = _require_engine()
    try:
        ex = engine.start_exercise(exercise_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return ex.model_dump()


@router.post(
    "/exercises/{exercise_id}/steps/{step_index}",
    response_model=Dict[str, Any],
    summary="Record detection result for an attack step",
)
def record_step_result(exercise_id: str, step_index: int, req: RecordStepRequest):
    """
    Record whether ALDECI detected a specific attack step.
    Captures: outcome, detection engine, alert fired, time to detect.
    Exercise must be in 'active' status.
    """
    engine = _require_engine()
    outcome = _parse_enum(req.outcome, StepOutcome, "outcome")
    detection_engine = _parse_enum(req.detection_engine, DetectionEngine, "detection_engine")

    try:
        step = engine.record_step_result(
            exercise_id,
            step_index,
            outcome=outcome,
            detected=req.detected,
            detection_engine=detection_engine,
            alert_fired=req.alert_fired,
            time_to_detect_seconds=req.time_to_detect_seconds,
            detection_notes=req.detection_notes,
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    return step.model_dump()


@router.post(
    "/exercises/{exercise_id}/response",
    response_model=Dict[str, Any],
    summary="Add a blue team containment/response action",
)
def add_blue_team_action(exercise_id: str, req: BlueTeamActionRequest):
    """
    Log a blue team response action for a specific attack step.
    Tracks: action type, actor, effectiveness, timestamp.
    """
    engine = _require_engine()
    action = _parse_enum(req.action, ContainmentAction, "action")

    try:
        bta = engine.add_blue_team_action(
            exercise_id,
            req.step_index,
            action=action,
            actor=req.actor,
            description=req.description,
            effective=req.effective,
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return bta.model_dump()


@router.post(
    "/exercises/{exercise_id}/complete",
    response_model=Dict[str, Any],
    summary="Complete exercise and compute scores + gaps",
)
def complete_exercise(exercise_id: str):
    """
    Mark the exercise as complete. Automatically:
    - Computes red/blue team scores (detection rate, MTTD, coverage score)
    - Identifies detection gaps (undetected steps → backlog)
    Returns the completed exercise with scores and gap list.
    """
    engine = _require_engine()
    try:
        ex = engine.complete_exercise(exercise_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return ex.model_dump()


@router.get(
    "/exercises/{exercise_id}/report",
    response_model=Dict[str, Any],
    summary="Generate after-action report",
)
def get_report(exercise_id: str):
    """
    Generate a full after-action report for a completed exercise.
    Includes executive summary, technique-by-technique results,
    tactic coverage breakdown, detection gaps, and recommended improvements.
    """
    engine = _require_engine()
    ex = engine.get_exercise(exercise_id)
    if ex is None:
        raise HTTPException(status_code=404, detail=f"Exercise not found: {exercise_id}")
    if ex.status != ExerciseStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail=f"Exercise must be completed before generating a report. Current status: {ex.status.value}",
        )

    try:
        report = engine.generate_report(exercise_id)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    return report.model_dump()


@router.get(
    "/scenarios",
    response_model=List[ScenarioListResponse],
    summary="List pre-built attack scenarios",
)
def list_scenarios(
    category: Optional[str] = Query(None, description="Filter by category (e.g. ransomware, cloud_breach)"),
):
    """
    Returns the built-in scenario library (30+ scenarios).
    Each scenario has pre-mapped MITRE ATT&CK techniques and estimated duration.
    """
    engine = _require_engine()
    scenarios = engine.list_scenarios(category=category)
    return [ScenarioListResponse(**s) for s in scenarios]
