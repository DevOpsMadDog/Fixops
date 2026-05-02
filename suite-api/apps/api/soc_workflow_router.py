"""SOC Workflow Router — ALDECI.

Endpoints for the SOC Workflow engine.

Prefix: /api/v1/soc-workflow
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/soc-workflow/workflows                          create_workflow
  GET    /api/v1/soc-workflow/workflows                          list_workflows
  GET    /api/v1/soc-workflow/workflows/{workflow_id}            get_workflow
  POST   /api/v1/soc-workflow/executions                         start_execution
  PUT    /api/v1/soc-workflow/executions/{execution_id}/step     update_execution_step
  PUT    /api/v1/soc-workflow/executions/{execution_id}/complete complete_execution
  GET    /api/v1/soc-workflow/executions                         list_executions
  GET    /api/v1/soc-workflow/stats                              get_soc_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/soc-workflow",
    tags=["SOC Workflow"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.soc_workflow_engine import SOCWorkflowEngine
        _engine = SOCWorkflowEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class WorkflowCreate(BaseModel):
    name: str
    workflow_type: str
    trigger: str = "manual"
    steps: List[Any] = Field(default_factory=list)
    description: str = ""


class ExecutionStart(BaseModel):
    workflow_id: str
    initiated_by: str = ""
    context: Dict[str, Any] = Field(default_factory=dict)


class ExecutionStepUpdate(BaseModel):
    step_name: str
    step_status: str
    step_output: str = ""


class ExecutionComplete(BaseModel):
    outcome: str


# ---------------------------------------------------------------------------
# Workflows
# ---------------------------------------------------------------------------

@router.post("/workflows", dependencies=[Depends(api_key_auth)], status_code=201)
def create_workflow(body: WorkflowCreate, org_id: str = Query(default="default")):
    """Create a new SOC workflow."""
    try:
        return _get_engine().create_workflow(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/workflows", dependencies=[Depends(api_key_auth)])
def list_workflows(
     org_id: str = Query(default="default"),
    workflow_type: Optional[str] = Query(None),
    trigger: Optional[str] = Query(None),
):
    """List workflows with optional filters."""
    return _get_engine().list_workflows(org_id, workflow_type=workflow_type, trigger=trigger)


@router.get("/workflows/{workflow_id}", dependencies=[Depends(api_key_auth)])
def get_workflow(workflow_id: str, org_id: str = Query(default="default")):
    """Get a single workflow by ID."""
    wf = _get_engine().get_workflow(org_id, workflow_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return wf


# ---------------------------------------------------------------------------
# Executions
# ---------------------------------------------------------------------------

@router.post("/executions", dependencies=[Depends(api_key_auth)], status_code=201)
def start_execution(body: ExecutionStart, org_id: str = Query(default="default")):
    """Start a workflow execution."""
    try:
        return _get_engine().start_execution(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/executions/{execution_id}/step", dependencies=[Depends(api_key_auth)])
def update_execution_step(
    execution_id: str,
    body: ExecutionStepUpdate,
     org_id: str = Query(default="default"),
):
    """Record a step result for an execution."""
    result = _get_engine().update_execution(
        org_id,
        execution_id,
        body.step_name,
        body.step_status,
        body.step_output,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Execution not found")
    return result


@router.put("/executions/{execution_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_execution(
    execution_id: str,
    body: ExecutionComplete,
     org_id: str = Query(default="default"),
):
    """Mark an execution as completed."""
    result = _get_engine().complete_execution(org_id, execution_id, body.outcome)
    if not result:
        raise HTTPException(status_code=404, detail="Execution not found")
    return result


@router.get("/executions", dependencies=[Depends(api_key_auth)])
def list_executions(
     org_id: str = Query(default="default"),
    workflow_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List executions with optional filters."""
    return _get_engine().list_executions(org_id, workflow_id=workflow_id, status=status)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_soc_stats(org_id: str = Query(default="default")):
    """Return aggregated SOC workflow stats for the org."""
    return _get_engine().get_soc_stats(org_id)
