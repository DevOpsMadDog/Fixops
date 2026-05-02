"""
Vulnerability Lifecycle REST API.

Provides endpoints for tracking findings from discovery to resolution
through a validated state machine.

Endpoints:
  POST   /api/v1/vuln-lifecycle/{finding_id}/transition  -- Move to next stage
  GET    /api/v1/vuln-lifecycle/{finding_id}/history     -- Full event history
  GET    /api/v1/vuln-lifecycle/{finding_id}/stage       -- Current stage
  GET    /api/v1/vuln-lifecycle/distribution             -- Stage counts by org
  GET    /api/v1/vuln-lifecycle/bottlenecks              -- Stuck-stage analysis
  GET    /api/v1/vuln-lifecycle/avg-time                 -- Avg hours per stage
  GET    /api/v1/vuln-lifecycle/flow                     -- Throughput & cycle time
  POST   /api/v1/vuln-lifecycle/validate                 -- Check if transition valid

Security: Bearer token / API key required on all endpoints.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.vuln_lifecycle import (
    LifecycleEvent,
    LifecycleStage,
    TransitionError,
    VulnLifecycle,
)
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vuln-lifecycle", tags=["vuln-lifecycle"])

# Module-level singleton (same pattern as analytics_router / findings_routes)
_tracker = VulnLifecycle()


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class TransitionRequest(BaseModel):
    """Request body for a lifecycle transition."""

    to_stage: LifecycleStage = Field(..., description="Target lifecycle stage")
    changed_by: str = Field(
        ..., min_length=1, description="User or system triggering the change"
    )
    reason: str = Field(default="", description="Reason or notes for the transition")


class TransitionResponse(BaseModel):
    """Response after a successful transition."""

    event_id: str
    finding_id: str
    from_stage: Optional[str]
    to_stage: str
    changed_by: str
    reason: str
    timestamp: str
    org_id: str


class CurrentStageResponse(BaseModel):
    """Current stage of a finding."""

    finding_id: str
    stage: Optional[str]


class ValidateRequest(BaseModel):
    """Request body for transition validation."""

    from_stage: Optional[LifecycleStage] = Field(
        None, description="Current stage (None for new findings)"
    )
    to_stage: LifecycleStage = Field(..., description="Proposed next stage")


class ValidateResponse(BaseModel):
    """Result of a transition validation check."""

    valid: bool
    from_stage: Optional[str]
    to_stage: str
    message: str


# ============================================================================
# HELPERS
# ============================================================================


def _event_to_response(event: LifecycleEvent) -> TransitionResponse:
    return TransitionResponse(
        event_id=event.id,
        finding_id=event.finding_id,
        from_stage=event.from_stage.value if event.from_stage else None,
        to_stage=event.to_stage.value,
        changed_by=event.changed_by,
        reason=event.reason,
        timestamp=event.timestamp.isoformat(),
        org_id=event.org_id,
    )


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.get(
    "",
    summary="Vulnerability lifecycle — service summary",
)
def get_service_summary(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return service status and stage distribution for the vuln lifecycle domain."""
    try:
        distribution = _tracker.get_stage_distribution(org_id)
    except Exception as exc:
        logger.warning("get_stage_distribution failed in summary: %s", exc)
        distribution = {}
    try:
        flow = _tracker.get_flow_metrics(org_id)
    except Exception as exc:
        logger.warning("get_flow_metrics failed in summary: %s", exc)
        flow = {}
    return {
        "service": "vuln-lifecycle",
        "status": "ok",
        "org_id": org_id,
        "stage_distribution": distribution,
        "flow": flow,
        "endpoints": [
            "POST /api/v1/vuln-lifecycle/{finding_id}/transition",
            "GET  /api/v1/vuln-lifecycle/{finding_id}/history",
            "GET  /api/v1/vuln-lifecycle/{finding_id}/stage",
            "GET  /api/v1/vuln-lifecycle/distribution",
            "GET  /api/v1/vuln-lifecycle/bottlenecks",
            "GET  /api/v1/vuln-lifecycle/avg-time",
            "GET  /api/v1/vuln-lifecycle/flow",
            "POST /api/v1/vuln-lifecycle/validate",
        ],
    }


@router.post(
    "/{finding_id}/transition",
    response_model=TransitionResponse,
    summary="Record a lifecycle stage transition",
)
def transition_finding(
    finding_id: str,
    body: TransitionRequest,
    org_id: str = Depends(get_org_id),
) -> TransitionResponse:
    """
    Move a finding to a new lifecycle stage.

    Enforces the state machine — invalid transitions return HTTP 422.
    """
    try:
        event = _tracker.transition(
            finding_id=finding_id,
            to_stage=body.to_stage,
            changed_by=body.changed_by,
            reason=body.reason,
            org_id=org_id,
        )
    except TransitionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("lifecycle_transition_error: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error during transition") from exc

    response = _event_to_response(event)
    # TrustGraph async indexing (fire-and-forget, non-blocking)
    try:
        import asyncio

        from core.trustgraph_event_bus import EVENT_FINDING_UPDATED, get_event_bus
        bus = get_event_bus()
        if bus and bus.enabled:
            asyncio.ensure_future(bus.emit(EVENT_FINDING_UPDATED, {
                "finding_id": finding_id,
                "type": "vulnerability",
                "severity": "medium",
                "source": "vuln_lifecycle_router",
                "to_stage": body.to_stage.value,
                "org_id": org_id,
            }))
    except Exception:
        pass  # event bus is best-effort
    return response


@router.get(
    "/{finding_id}/history",
    response_model=List[TransitionResponse],
    summary="Get full lifecycle history of a finding",
)
def get_lifecycle_history(
    finding_id: str,
    org_id: str = Depends(get_org_id),
) -> List[TransitionResponse]:
    """Return all lifecycle events for a finding in chronological order."""
    try:
        events = _tracker.get_lifecycle(finding_id)
    except Exception as exc:
        logger.exception("lifecycle_history_error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to fetch lifecycle history") from exc
    return [_event_to_response(e) for e in events]


@router.get(
    "/{finding_id}/stage",
    response_model=CurrentStageResponse,
    summary="Get the current stage of a finding",
)
def get_current_stage(
    finding_id: str,
    org_id: str = Depends(get_org_id),
) -> CurrentStageResponse:
    """Return the current lifecycle stage of a finding."""
    try:
        stage = _tracker.get_current_stage(finding_id)
    except Exception as exc:
        logger.exception("lifecycle_stage_error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to fetch current stage") from exc
    return CurrentStageResponse(
        finding_id=finding_id,
        stage=stage.value if stage else None,
    )


@router.get(
    "/distribution",
    response_model=Dict[str, int],
    summary="Count of findings at each stage (org-scoped)",
)
def get_stage_distribution(
    org_id: str = Depends(get_org_id),
) -> Dict[str, int]:
    """Return a count of findings currently at each lifecycle stage for the org."""
    try:
        return _tracker.get_stage_distribution(org_id)
    except Exception as exc:
        logger.exception("lifecycle_distribution_error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to compute stage distribution") from exc


@router.get(
    "/bottlenecks",
    response_model=List[Dict[str, Any]],
    summary="Stages where findings get stuck the longest",
)
def get_bottlenecks(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """
    Return stages sorted by average dwell time (descending).

    Stages with the highest average hours represent bottlenecks
    in the remediation pipeline.
    """
    try:
        return _tracker.get_bottlenecks(org_id)
    except Exception as exc:
        logger.exception("lifecycle_bottlenecks_error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to compute bottlenecks") from exc


@router.get(
    "/avg-time",
    response_model=Dict[str, Any],
    summary="Average hours spent at each lifecycle stage",
)
def get_avg_time_per_stage(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return the average number of hours findings spend at each stage."""
    try:
        return _tracker.get_avg_time_per_stage(org_id)
    except Exception as exc:
        logger.exception("lifecycle_avg_time_error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to compute average stage times") from exc


@router.get(
    "/flow",
    response_model=Dict[str, Any],
    summary="Flow metrics: throughput, cycle time, lead time, WIP, reopen rate",
)
def get_flow_metrics(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Return aggregate flow metrics for the org:

    - **throughput**: findings resolved (CLOSED or WONT_FIX)
    - **cycle_time_hours**: avg hours from IN_PROGRESS to FIXED
    - **lead_time_hours**: avg hours from DISCOVERED to CLOSED/WONT_FIX
    - **wip**: findings currently in active (non-terminal) stages
    - **reopen_rate**: fraction of findings reopened at least once
    - **total_findings**: total distinct findings tracked
    """
    try:
        return _tracker.get_flow_metrics(org_id)
    except Exception as exc:
        logger.exception("lifecycle_flow_error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to compute flow metrics") from exc


@router.post(
    "/validate",
    response_model=ValidateResponse,
    summary="Check whether a lifecycle transition is valid",
)
def validate_transition(body: ValidateRequest) -> ValidateResponse:
    """
    Validate a proposed stage transition without recording it.

    Useful for pre-flight checks in UI before submitting a transition.
    """
    valid = _tracker.validate_transition(body.from_stage, body.to_stage)
    from_label = body.from_stage.value if body.from_stage else "none"
    to_label = body.to_stage.value
    message = (
        f"Transition {from_label} → {to_label} is valid."
        if valid
        else f"Transition {from_label} → {to_label} is not allowed by the state machine."
    )
    return ValidateResponse(
        valid=valid,
        from_stage=body.from_stage.value if body.from_stage else None,
        to_stage=body.to_stage.value,
        message=message,
    )
