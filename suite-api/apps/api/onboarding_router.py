"""Onboarding Wizard API Router.

Guided customer setup endpoints:

    POST   /api/v1/onboarding/start                    -- start onboarding for org
    GET    /api/v1/onboarding/progress                 -- get current progress
    POST   /api/v1/onboarding/steps/{step}/complete    -- complete a step with config
    POST   /api/v1/onboarding/steps/{step}/skip        -- skip a step
    GET    /api/v1/onboarding/steps/{step}/config      -- get stored step config
    POST   /api/v1/onboarding/reset                    -- reset onboarding
    GET    /api/v1/onboarding/checklist                -- pre-flight checklist

Security:
    All endpoints require API key authentication (injected by app.py via
    dependencies=[Depends(_verify_api_key)]).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.onboarding import (
    OnboardingManager,
    OnboardingProgress,
    OnboardingStep,
    StepStatus,
)
from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/onboarding", tags=["onboarding"])

# Module-level manager instance (can be replaced in tests)
_manager = None  # lazy-initialised on first request


def _get_manager():
    global _manager
    if _manager is None:
        _manager = OnboardingManager()
    return _manager


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class StartRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=255, description="Organisation identifier")


class CompleteStepRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=255)
    config_data: Dict[str, Any] = Field(default_factory=dict)


class SkipStepRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=255)


class ResetRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=255)


class OnboardingProgressResponse(BaseModel):
    org_id: str
    current_step: str
    steps: Dict[str, str]
    started_at: str
    completed_at: Optional[str] = None
    completion_percentage: float


class StepConfigResponse(BaseModel):
    org_id: str
    step: str
    config: Dict[str, Any]


class ChecklistResponse(BaseModel):
    org_id: str
    onboarding_started: bool
    current_step: Optional[str] = None
    completion_percentage: Optional[float] = None
    items: List[Dict[str, Any]]


class ListOnboardingsResponse(BaseModel):
    onboardings: List[OnboardingProgressResponse]
    total: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _progress_to_response(p: OnboardingProgress) -> OnboardingProgressResponse:
    steps_str: Dict[str, str] = {}
    for k, v in p.steps.items():
        steps_str[k] = v.value if isinstance(v, StepStatus) else str(v)
    return OnboardingProgressResponse(
        org_id=p.org_id,
        current_step=(
            p.current_step.value
            if isinstance(p.current_step, OnboardingStep)
            else str(p.current_step)
        ),
        steps=steps_str,
        started_at=p.started_at.isoformat(),
        completed_at=p.completed_at.isoformat() if p.completed_at else None,
        completion_percentage=p.completion_percentage,
    )


def _parse_step(step_str: str) -> OnboardingStep:
    try:
        return OnboardingStep(step_str.upper())
    except ValueError:
        valid = [s.value for s in OnboardingStep]
        raise HTTPException(
            status_code=422,
            detail=f"Invalid step {step_str!r}. Valid steps: {valid}",
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/start", response_model=OnboardingProgressResponse, status_code=201)
def start_onboarding(body: StartRequest) -> OnboardingProgressResponse:
    """Start or resume onboarding for an organisation."""
    progress = _get_manager().start_onboarding(body.org_id)
    return _progress_to_response(progress)


@router.get("/progress", response_model=OnboardingProgressResponse)
def get_progress(org_id: str = Query(..., min_length=1, max_length=255)) -> OnboardingProgressResponse:
    """Get current onboarding progress for an organisation."""
    try:
        progress = _get_manager().get_progress(org_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"No onboarding found for org_id={org_id!r}")
    return _progress_to_response(progress)


@router.post("/steps/{step}/complete", response_model=OnboardingProgressResponse)
def complete_step(
    step: str = Path(..., description="Onboarding step name (e.g. CONFIGURE_AUTH)"),
    body: CompleteStepRequest = ...,
) -> OnboardingProgressResponse:
    """Mark a step as completed with optional configuration data."""
    step_enum = _parse_step(step)
    try:
        progress = _get_manager().complete_step(body.org_id, step_enum, body.config_data)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _progress_to_response(progress)


@router.post("/steps/{step}/skip", response_model=OnboardingProgressResponse)
def skip_step(
    step: str = Path(..., description="Onboarding step name to skip"),
    body: SkipStepRequest = ...,
) -> OnboardingProgressResponse:
    """Mark a step as skipped."""
    step_enum = _parse_step(step)
    try:
        progress = _get_manager().skip_step(body.org_id, step_enum)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return _progress_to_response(progress)


@router.get("/steps/{step}/config", response_model=StepConfigResponse)
def get_step_config(
    step: str = Path(..., description="Onboarding step name"),
    org_id: str = Query(..., min_length=1, max_length=255),
) -> StepConfigResponse:
    """Retrieve configuration stored when a step was completed."""
    step_enum = _parse_step(step)
    config = _get_manager().get_step_config(org_id, step_enum)
    return StepConfigResponse(org_id=org_id, step=step_enum.value, config=config)


@router.post("/reset", response_model=OnboardingProgressResponse)
def reset_onboarding(body: ResetRequest) -> OnboardingProgressResponse:
    """Reset onboarding for an organisation and start over."""
    progress = _get_manager().reset_onboarding(body.org_id)
    return _progress_to_response(progress)


@router.get("/checklist", response_model=ChecklistResponse)
def get_checklist(org_id: str = Query(..., min_length=1, max_length=255)) -> ChecklistResponse:
    """Pre-flight checklist showing what is configured vs still missing."""
    data = _get_manager().get_checklist(org_id)
    current_step = data.get("current_step")
    if current_step and isinstance(current_step, OnboardingStep):
        current_step = current_step.value
    return ChecklistResponse(
        org_id=data["org_id"],
        onboarding_started=data["onboarding_started"],
        current_step=current_step,
        completion_percentage=data.get("completion_percentage"),
        items=data.get("items", []),
    )


@router.get("/list", response_model=ListOnboardingsResponse)
def list_onboardings(
    status: Optional[str] = Query(
        None,
        description="Filter by status: completed | in_progress | not_started",
    )
) -> ListOnboardingsResponse:
    """Admin endpoint — list all organisation onboardings."""
    onboardings = _get_manager().list_onboardings(status_filter=status)
    return ListOnboardingsResponse(
        onboardings=[_progress_to_response(p) for p in onboardings],
        total=len(onboardings),
    )
