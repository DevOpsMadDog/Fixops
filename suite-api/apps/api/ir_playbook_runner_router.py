"""
IR Playbook Runner Router — Playbook execution engine endpoints.

5 endpoints:
  POST /api/v1/playbooks/execute                        execute_playbook
  GET  /api/v1/playbooks/executions                     list_executions
  GET  /api/v1/playbooks/execution/{id}                 get_execution
  GET  /api/v1/playbooks/library                        list_library
  POST /api/v1/playbooks/execution/{id}/step/{sid}/override  manual_override
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
        "ir_playbook_runner_router: auth_deps not available"
    )
    _AUTH_DEP = []

from core.ir_playbook_runner import (
    PlaybookDef,
    PlaybookExecution,
    get_playbook_runner,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/playbooks",
    tags=["IR Playbook Runner"],
    dependencies=_AUTH_DEP,
)


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class ExecutePlaybookRequest(BaseModel):
    playbook_id: str = Field(..., description="Playbook ID, e.g. 'phishing_response'")
    incident: Dict[str, Any] = Field(
        ...,
        description=(
            "Incident context. Supported keys: title, description, severity, org_id, "
            "incident_id, affected_assets (list), affected_users (list), "
            "attacker_ip, attacker_ips (list), tags (list)."
        ),
    )
    incident_id: Optional[str] = Field(None, description="Override incident ID")


class StepOverrideRequest(BaseModel):
    result: str = Field(..., description="Override result description (e.g. 'Completed manually')")


class StepResultResponse(BaseModel):
    step_id: str
    step_name: str
    action: str
    status: str
    started_at: str
    completed_at: str
    output: str
    error: Optional[str]


class ExecutionResponse(BaseModel):
    execution_id: str
    playbook_id: str
    incident_id: str
    started_at: str
    completed_at: Optional[str]
    status: str
    steps_total: int
    steps_completed: int
    current_step: Optional[str]
    step_results: List[StepResultResponse]


class PlaybookStepSummary(BaseModel):
    step_id: str
    name: str
    action: str
    description: str
    continue_on_failure: bool


class PlaybookLibraryEntry(BaseModel):
    playbook_id: str
    name: str
    description: str
    trigger_conditions: List[str]
    severity_threshold: str
    step_count: int
    steps: List[PlaybookStepSummary]


class SelectPlaybookResponse(BaseModel):
    playbook_id: Optional[str]
    name: Optional[str]
    message: str


# ============================================================================
# HELPERS
# ============================================================================


def _execution_to_response(ex: PlaybookExecution) -> ExecutionResponse:
    return ExecutionResponse(
        execution_id=ex.execution_id,
        playbook_id=ex.playbook_id,
        incident_id=ex.incident_id,
        started_at=ex.started_at,
        completed_at=ex.completed_at,
        status=ex.status,
        steps_total=ex.steps_total,
        steps_completed=ex.steps_completed,
        current_step=ex.current_step,
        step_results=[
            StepResultResponse(
                step_id=sr.step_id,
                step_name=sr.step_name,
                action=sr.action,
                status=sr.status,
                started_at=sr.started_at,
                completed_at=sr.completed_at,
                output=sr.output,
                error=sr.error,
            )
            for sr in ex.step_results
        ],
    )


def _pb_to_library_entry(pb: PlaybookDef) -> PlaybookLibraryEntry:
    return PlaybookLibraryEntry(
        playbook_id=pb.playbook_id,
        name=pb.name,
        description=pb.description,
        trigger_conditions=pb.trigger_conditions,
        severity_threshold=pb.severity_threshold,
        step_count=len(pb.steps),
        steps=[
            PlaybookStepSummary(
                step_id=s.step_id,
                name=s.name,
                action=s.action,
                description=s.description,
                continue_on_failure=s.continue_on_failure,
            )
            for s in pb.steps
        ],
    )


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post(
    "/execute",
    response_model=ExecutionResponse,
    status_code=201,
    summary="Execute Playbook",
    description=(
        "Trigger an IR playbook for an incident. Executes all steps synchronously "
        "and returns the full execution record with per-step results. "
        "Available playbooks: phishing_response, ransomware_response, "
        "data_exfiltration, unauthorized_access, malware_detected."
    ),
)
def execute_playbook(req: ExecutePlaybookRequest) -> ExecutionResponse:
    runner = get_playbook_runner()
    try:
        execution = runner.execute_playbook(
            playbook_id=req.playbook_id,
            incident=req.incident,
            incident_id=req.incident_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _execution_to_response(execution)


@router.get(
    "/executions",
    response_model=List[ExecutionResponse],
    summary="List Executions",
    description="Return recent playbook executions, optionally filtered by playbook or status.",
)
def list_executions(
    playbook_id: Optional[str] = Query(None, description="Filter by playbook ID"),
    status: Optional[str] = Query(None, description="Filter by status: running|completed|failed|partial"),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
) -> List[ExecutionResponse]:
    runner = get_playbook_runner()
    executions = runner.list_executions(limit=limit, playbook_id=playbook_id, status=status)
    return [_execution_to_response(ex) for ex in executions]


@router.get(
    "/execution/{execution_id}",
    response_model=ExecutionResponse,
    summary="Get Execution Status",
    description="Get the current status and step results for a specific playbook execution.",
)
def get_execution(execution_id: str) -> ExecutionResponse:
    runner = get_playbook_runner()
    execution = runner.get_execution_status(execution_id)
    if execution is None:
        raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found")
    return _execution_to_response(execution)


@router.get(
    "/library",
    response_model=List[PlaybookLibraryEntry],
    summary="List Playbook Library",
    description=(
        "Return all 5 built-in IR playbooks with their trigger conditions, "
        "step definitions, and action types."
    ),
)
def list_library() -> List[PlaybookLibraryEntry]:
    runner = get_playbook_runner()
    return [_pb_to_library_entry(pb) for pb in runner.list_playbooks()]


@router.post(
    "/execution/{execution_id}/step/{step_id}/override",
    response_model=ExecutionResponse,
    summary="Manual Step Override",
    description=(
        "Analyst manually marks a step as overridden (completed or skipped). "
        "Useful when automated action fails but analyst completed it manually."
    ),
)
def manual_step_override(
    execution_id: str,
    step_id: str,
    req: StepOverrideRequest,
) -> ExecutionResponse:
    runner = get_playbook_runner()
    try:
        runner.manual_step_override(execution_id, step_id, req.result)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    execution = runner.get_execution_status(execution_id)
    if execution is None:
        raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found")
    return _execution_to_response(execution)
