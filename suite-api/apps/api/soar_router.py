"""
SOAR Router — Security Orchestration, Automation and Response.

8 endpoints:
  POST   /api/v1/soar/playbooks                 create_playbook
  GET    /api/v1/soar/playbooks                 list_playbooks
  GET    /api/v1/soar/playbooks/{id}            get_playbook
  POST   /api/v1/soar/trigger                   evaluate_trigger
  POST   /api/v1/soar/playbooks/{id}/execute    execute_playbook
  GET    /api/v1/soar/executions                get_execution_history
  GET    /api/v1/soar/stats                     get_playbook_stats
  GET    /api/v1/soar/mttr                      get_mean_time_to_respond
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "soar_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.soar_engine import (
    PlaybookStats,
    PlaybookTrigger,
    SOAREngine,
    SOARExecution,
    SOARPlaybook,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/soar",
    tags=["soar"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance (SQLite-backed, shared across requests)
_engine: Optional[SOAREngine] = None


def _get_engine() -> SOAREngine:
    global _engine
    if _engine is None:
        _engine = SOAREngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class CreatePlaybookRequest(BaseModel):
    """Body for creating a new SOAR playbook."""

    name: str = Field(..., description="Human-readable playbook name")
    trigger: PlaybookTrigger = Field(..., description="Event type that fires this playbook")
    actions: List[Dict[str, Any]] = Field(
        ..., description="Ordered list of action definitions"
    )
    conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional key/value conditions that must match the event",
    )
    enabled: bool = Field(True, description="Whether the playbook is active")
    org_id: str = Field("default", description="Organisation ID")


class TriggerEventRequest(BaseModel):
    """Body for evaluating an incoming security event against playbooks."""

    trigger: PlaybookTrigger = Field(..., description="Event trigger type")
    org_id: str = Field("default", description="Organisation ID")
    event_data: Dict[str, Any] = Field(
        default_factory=dict, description="Additional event context"
    )


class ExecutePlaybookRequest(BaseModel):
    """Body for manually executing a playbook."""

    context: Dict[str, Any] = Field(
        default_factory=dict, description="Execution context passed to actions"
    )
    org_id: str = Field("default", description="Organisation ID")


class MTTRResponse(BaseModel):
    org_id: str
    mttr_seconds: float
    mttr_minutes: float


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post(
    "/playbooks",
    response_model=SOARPlaybook,
    status_code=201,
    summary="Create a new SOAR playbook",
)
def create_playbook(body: CreatePlaybookRequest) -> SOARPlaybook:
    """
    Define an automated response playbook.

    The playbook will fire when an event matching `trigger` (and optional
    `conditions`) is submitted to the /trigger endpoint.
    """
    engine = _get_engine()
    try:
        return engine.create_playbook(
            name=body.name,
            trigger=body.trigger,
            actions=body.actions,
            conditions=body.conditions,
            enabled=body.enabled,
            org_id=body.org_id,
        )
    except Exception as exc:
        logger.exception("Failed to create playbook '%s'", body.name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/playbooks",
    response_model=List[SOARPlaybook],
    summary="List all SOAR playbooks",
)
def list_playbooks(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[SOARPlaybook]:
    """Return all playbooks registered for the given org."""
    engine = _get_engine()
    try:
        return engine.list_playbooks(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to list playbooks for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/playbooks/{playbook_id}",
    response_model=SOARPlaybook,
    summary="Get a specific SOAR playbook",
)
def get_playbook(
    playbook_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> SOARPlaybook:
    """Retrieve a playbook by its ID."""
    engine = _get_engine()
    pb = engine.get_playbook(playbook_id, org_id=org_id)
    if pb is None:
        raise HTTPException(
            status_code=404,
            detail=f"Playbook '{playbook_id}' not found for org '{org_id}'",
        )
    return pb


@router.post(
    "/trigger",
    response_model=List[SOARExecution],
    summary="Evaluate an event and fire matching playbooks",
)
def evaluate_trigger(body: TriggerEventRequest) -> List[SOARExecution]:
    """
    Submit a security event for automated response.

    Matches the event against all enabled playbooks with the given trigger type
    and condition set. Returns execution records for every playbook that fired.
    """
    engine = _get_engine()
    try:
        event = {"trigger": body.trigger.value, **body.event_data}
        return engine.evaluate_trigger(event=event, org_id=body.org_id)
    except Exception as exc:
        logger.exception("evaluate_trigger failed for trigger %s", body.trigger)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/playbooks/{playbook_id}/execute",
    response_model=SOARExecution,
    summary="Manually execute a SOAR playbook",
)
def execute_playbook(playbook_id: str, body: ExecutePlaybookRequest) -> SOARExecution:
    """
    Run a playbook immediately, bypassing trigger/condition evaluation.

    Useful for manual incident response or testing playbook actions.
    Returns 404 if the playbook does not exist, 422 if it is disabled.
    """
    engine = _get_engine()
    try:
        return engine.execute_playbook(
            playbook_id=playbook_id,
            context=body.context,
            org_id=body.org_id,
        )
    except ValueError as exc:
        msg = str(exc)
        status = 404 if "not found" in msg else 422
        raise HTTPException(status_code=status, detail=msg) from exc
    except Exception as exc:
        logger.exception("execute_playbook failed for %s", playbook_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/executions",
    response_model=List[SOARExecution],
    summary="Get SOAR execution history",
)
def get_execution_history(
    org_id: str = Query("default", description="Organisation ID"),
    playbook_id: Optional[str] = Query(None, description="Filter by playbook ID"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
) -> List[SOARExecution]:
    """
    Return past SOAR execution records for the org.

    Optionally filter by a specific playbook ID. Results are ordered by
    most recent first.
    """
    engine = _get_engine()
    try:
        return engine.get_execution_history(
            org_id=org_id, limit=limit, playbook_id=playbook_id
        )
    except Exception as exc:
        logger.exception("get_execution_history failed for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/stats",
    response_model=PlaybookStats,
    summary="SOAR playbook aggregate statistics",
)
def get_playbook_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> PlaybookStats:
    """
    Return aggregate SOAR statistics: playbook counts, execution totals,
    completion/failure rates, and breakdown by trigger type.
    """
    engine = _get_engine()
    try:
        return engine.get_playbook_stats(org_id=org_id)
    except Exception as exc:
        logger.exception("get_playbook_stats failed for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/mttr",
    response_model=MTTRResponse,
    summary="Mean Time To Respond (MTTR)",
)
def get_mean_time_to_respond(
    org_id: str = Query("default", description="Organisation ID"),
) -> MTTRResponse:
    """
    Compute MTTR from all completed SOAR executions for the org.

    Returns seconds and minutes. Returns 0.0 if no executions have completed.
    """
    engine = _get_engine()
    try:
        mttr_seconds = engine.get_mean_time_to_respond(org_id=org_id)
        return MTTRResponse(
            org_id=org_id,
            mttr_seconds=mttr_seconds,
            mttr_minutes=round(mttr_seconds / 60.0, 4),
        )
    except Exception as exc:
        logger.exception("get_mean_time_to_respond failed for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/", summary="SOAR index", tags=["soar"])
async def soar_index(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return SOAR playbook summary for the org."""
    playbooks: List[Any] = []
    try:
        engine = _get_engine()
        if hasattr(engine, "list_playbooks"):
            playbooks = engine.list_playbooks(org_id=org_id)
    except Exception:
        pass
    items = [
        p.model_dump(mode="json") if hasattr(p, "model_dump") else dict(p)
        for p in playbooks
    ]
    return {"router": "soar", "org_id": org_id, "items": items, "count": len(items)}
