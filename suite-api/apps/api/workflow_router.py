"""Workflow Router — ALDECI.

Endpoints for the workflow automation engine.

Prefix: /api/v1/workflows
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/workflows                       list_workflows
  POST   /api/v1/workflows                       create_workflow
  GET    /api/v1/workflows/{workflow_id}          get_workflow
  PATCH  /api/v1/workflows/{workflow_id}          update_workflow
  DELETE /api/v1/workflows/{workflow_id}          delete_workflow
  POST   /api/v1/workflows/{workflow_id}/trigger  trigger_workflow
  GET    /api/v1/workflows/executions             list_executions
  GET    /api/v1/workflows/stats                  get_stats
  GET    /api/v1/workflows/templates              get_templates
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/workflows",
    tags=["Workflow Engine"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.workflow_engine import WorkflowEngine
        _engine = WorkflowEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class WorkflowCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger: str  # TriggerType value e.g. "finding.created"
    conditions: List[Dict[str, Any]] = Field(default_factory=list)
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    enabled: bool = True
    created_by: str = "api"
    org_id: str = "default"


class WorkflowUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger: Optional[str] = None
    conditions: Optional[List[Dict[str, Any]]] = None
    actions: Optional[List[Dict[str, Any]]] = None
    enabled: Optional[bool] = None


class TriggerEventRequest(BaseModel):
    event: Dict[str, Any]


# ---------------------------------------------------------------------------
# Routes — order matters: fixed paths before parameterised ones
# ---------------------------------------------------------------------------

@router.get("/templates", dependencies=[Depends(api_key_auth)])
def get_templates():
    """Return built-in workflow templates."""
    templates = _get_engine().get_templates()
    return [t.model_dump() for t in templates]


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return workflow statistics for an org."""
    return _get_engine().get_workflow_stats(org_id=org_id)


@router.get("/executions", dependencies=[Depends(api_key_auth)])
def list_executions(
    org_id: str = Query(default="default"),
    workflow_id: Optional[str] = Query(None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """Return execution history for the org."""
    execs = _get_engine().get_execution_history(
        org_id=org_id, workflow_id=workflow_id, limit=limit
    )
    return [e.model_dump() for e in execs]


@router.get("", dependencies=[Depends(api_key_auth)])
def list_workflows(
    org_id: str = Query(default="default"),
    trigger_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List workflows, optionally filtered by org_id and trigger type."""
    workflows = _get_engine().list_workflows(org_id=org_id, trigger_filter=trigger_type)
    return [w.model_dump() for w in workflows]


@router.post("", dependencies=[Depends(api_key_auth)], status_code=201)
def create_workflow(body: WorkflowCreate):
    """Create a new workflow."""
    from core.workflow_engine import Workflow
    try:
        wf = Workflow(
            name=body.name,
            description=body.description,
            trigger=body.trigger,
            conditions=body.conditions,
            actions=body.actions,
            enabled=body.enabled,
            created_by=body.created_by,
            org_id=body.org_id,
        )
        result = _get_engine().create_workflow(wf)
        return result.model_dump()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{workflow_id}", dependencies=[Depends(api_key_auth)])
def get_workflow(workflow_id: str):
    """Get a single workflow by ID."""
    wf = _get_engine().get_workflow(workflow_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return wf.model_dump()


@router.patch("/{workflow_id}", dependencies=[Depends(api_key_auth)])
def update_workflow(workflow_id: str, body: WorkflowUpdate):
    """Update fields on an existing workflow."""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        wf = _get_engine().update_workflow(workflow_id, updates)
        return wf.model_dump()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{workflow_id}", dependencies=[Depends(api_key_auth)])
def delete_workflow(workflow_id: str):
    """Delete a workflow by ID."""
    deleted = _get_engine().delete_workflow(workflow_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return {"deleted": True}


@router.post("/{workflow_id}/trigger", dependencies=[Depends(api_key_auth)])
def trigger_workflow(
    workflow_id: str,
    body: TriggerEventRequest,
    org_id: str = Query(default="default"),
):
    """Evaluate an event against all matching workflows and execute them."""
    executions = _get_engine().evaluate_event(body.event, org_id=org_id)
    return [e.model_dump() for e in executions]
