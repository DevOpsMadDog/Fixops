"""Workflow automation engine API router.

Endpoints:
    POST   /api/v1/workflows             — create workflow
    GET    /api/v1/workflows             — list workflows
    GET    /api/v1/workflows/templates   — built-in templates
    GET    /api/v1/workflows/executions  — execution history
    GET    /api/v1/workflows/stats       — workflow stats
    GET    /api/v1/workflows/{id}        — get workflow
    PUT    /api/v1/workflows/{id}        — update workflow
    DELETE /api/v1/workflows/{id}        — delete workflow
    POST   /api/v1/workflows/evaluate    — manually trigger evaluation

Protected by _verify_api_key (injected via app.include_router dependencies).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.workflow_engine import (
    ActionType,
    ConditionOperator,
    TriggerType,
    Workflow,
    WorkflowAction,
    WorkflowCondition,
    WorkflowEngine,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/workflows", tags=["workflow-engine"])

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = WorkflowEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class WorkflowConditionRequest(BaseModel):
    field: str
    operator: ConditionOperator
    value: Any


class WorkflowActionRequest(BaseModel):
    type: ActionType
    config: Dict[str, Any] = Field(default_factory=dict)


class CreateWorkflowRequest(BaseModel):
    name: str
    description: Optional[str] = None
    trigger: TriggerType
    conditions: List[WorkflowConditionRequest] = Field(default_factory=list)
    actions: List[WorkflowActionRequest] = Field(default_factory=list)
    enabled: bool = True
    org_id: str = "default"
    created_by: str = "api"


class UpdateWorkflowRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger: Optional[TriggerType] = None
    conditions: Optional[List[WorkflowConditionRequest]] = None
    actions: Optional[List[WorkflowActionRequest]] = None
    enabled: Optional[bool] = None


class EvaluateEventRequest(BaseModel):
    event: Dict[str, Any]
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Fixed-path routes MUST come before /{workflow_id} to avoid shadowing
# ---------------------------------------------------------------------------


@router.get("/templates")
async def get_templates() -> List[Dict[str, Any]]:
    """Return built-in workflow templates."""
    templates = _get_engine().get_templates()
    return [t.model_dump(mode="json") for t in templates]


@router.get("/executions")
async def get_executions(
    org_id: Optional[str] = Query(None, description="Filter by organization ID"),
    workflow_id: Optional[str] = Query(None, description="Filter by workflow ID"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
) -> List[Dict[str, Any]]:
    """Return workflow execution history."""
    executions = _get_engine().get_execution_history(
        org_id=org_id, workflow_id=workflow_id, limit=limit
    )
    return [e.model_dump(mode="json") for e in executions]


@router.get("/stats")
async def get_stats(
    org_id: Optional[str] = Query(None, description="Filter by organization ID"),
) -> Dict[str, Any]:
    """Return workflow statistics."""
    return _get_engine().get_workflow_stats(org_id=org_id)


@router.post("/evaluate")
async def evaluate_event(req: EvaluateEventRequest) -> List[Dict[str, Any]]:
    """Manually trigger workflow evaluation for an event."""
    executions = _get_engine().evaluate_event(event=req.event, org_id=req.org_id)
    return [e.model_dump(mode="json") for e in executions]


# ---------------------------------------------------------------------------
# Workflow CRUD
# ---------------------------------------------------------------------------


@router.post("", status_code=201)
async def create_workflow(req: CreateWorkflowRequest) -> Dict[str, Any]:
    """Create a new workflow."""
    conditions = [
        WorkflowCondition(
            field=c.field,
            operator=c.operator,
            value=c.value,
        )
        for c in req.conditions
    ]
    actions = [
        WorkflowAction(
            type=a.type,
            config=a.config,
        )
        for a in req.actions
    ]

    workflow = Workflow(
        name=req.name,
        description=req.description,
        trigger=req.trigger,
        conditions=conditions,
        actions=actions,
        enabled=req.enabled,
        org_id=req.org_id,
        created_by=req.created_by,
    )

    created = _get_engine().create_workflow(workflow)
    return created.model_dump(mode="json")


@router.get("")
async def list_workflows(
    org_id: Optional[str] = Query(None, description="Filter by organization ID"),
    trigger: Optional[str] = Query(None, description="Filter by trigger type"),
) -> List[Dict[str, Any]]:
    """List workflows, optionally filtered by org and trigger type."""
    workflows = _get_engine().list_workflows(org_id=org_id, trigger_filter=trigger)
    return [w.model_dump(mode="json") for w in workflows]


@router.get("/{workflow_id}")
async def get_workflow(workflow_id: str) -> Dict[str, Any]:
    """Get a specific workflow by ID."""
    workflow = _get_engine().get_workflow(workflow_id)
    if not workflow:
        raise HTTPException(status_code=404, detail=f"Workflow {workflow_id} not found")
    return workflow.model_dump(mode="json")


@router.put("/{workflow_id}")
async def update_workflow(workflow_id: str, req: UpdateWorkflowRequest) -> Dict[str, Any]:
    """Update an existing workflow."""
    updates: Dict[str, Any] = {}

    if req.name is not None:
        updates["name"] = req.name
    if req.description is not None:
        updates["description"] = req.description
    if req.trigger is not None:
        updates["trigger"] = req.trigger.value if hasattr(req.trigger, "value") else req.trigger
    if req.enabled is not None:
        updates["enabled"] = req.enabled
    if req.conditions is not None:
        updates["conditions"] = [
            c.model_dump() for c in req.conditions
        ]
    if req.actions is not None:
        updates["actions"] = [
            a.model_dump() for a in req.actions
        ]

    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    try:
        updated = _get_engine().update_workflow(workflow_id, updates)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Workflow {workflow_id} not found")

    return updated.model_dump(mode="json")


@router.delete("/{workflow_id}")
async def delete_workflow(workflow_id: str) -> Dict[str, Any]:
    """Delete a workflow by ID."""
    deleted = _get_engine().delete_workflow(workflow_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Workflow {workflow_id} not found")
    return {"id": workflow_id, "status": "deleted"}
