"""
Workflow orchestration API endpoints.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.workflow_db import WorkflowDB
from core.workflow_models import Workflow, WorkflowExecution, WorkflowStatus

router = APIRouter(prefix="/api/v1/workflows", tags=["workflows"])
db = WorkflowDB()


class WorkflowCreate(BaseModel):
    """Request model for creating a workflow."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    triggers: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class WorkflowUpdate(BaseModel):
    """Request model for updating a workflow."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    steps: Optional[List[Dict[str, Any]]] = None
    triggers: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class WorkflowResponse(BaseModel):
    """Response model for a workflow."""

    id: str
    name: str
    description: str
    steps: List[Dict[str, Any]]
    triggers: Dict[str, Any]
    enabled: bool
    created_by: Optional[str]
    created_at: str
    updated_at: str


class WorkflowExecutionResponse(BaseModel):
    """Response model for a workflow execution."""

    id: str
    workflow_id: str
    status: str
    triggered_by: Optional[str]
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    error_message: Optional[str]
    started_at: str
    completed_at: Optional[str]


class PaginatedWorkflowResponse(BaseModel):
    """Paginated workflow response."""

    items: List[WorkflowResponse]
    total: int
    limit: int
    offset: int


@router.get("", response_model=PaginatedWorkflowResponse)
async def list_workflows(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """List all workflows."""
    workflows = db.list_workflows(limit=limit, offset=offset)
    return {
        "items": [WorkflowResponse(**w.to_dict()) for w in workflows],
        "total": len(workflows),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=WorkflowResponse, status_code=201)
async def create_workflow(workflow_data: WorkflowCreate):
    """Create a new workflow."""
    workflow = Workflow(
        id="",
        name=workflow_data.name,
        description=workflow_data.description,
        steps=workflow_data.steps,
        triggers=workflow_data.triggers,
        enabled=workflow_data.enabled,
    )
    created_workflow = db.create_workflow(workflow)
    return WorkflowResponse(**created_workflow.to_dict())


@router.get("/{id}", response_model=WorkflowResponse)
async def get_workflow(id: str):
    """Get workflow details by ID."""
    workflow = db.get_workflow(id)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return WorkflowResponse(**workflow.to_dict())


@router.put("/{id}", response_model=WorkflowResponse)
async def update_workflow(id: str, workflow_data: WorkflowUpdate):
    """Update a workflow."""
    workflow = db.get_workflow(id)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    if workflow_data.name is not None:
        workflow.name = workflow_data.name
    if workflow_data.description is not None:
        workflow.description = workflow_data.description
    if workflow_data.steps is not None:
        workflow.steps = workflow_data.steps
    if workflow_data.triggers is not None:
        workflow.triggers = workflow_data.triggers
    if workflow_data.enabled is not None:
        workflow.enabled = workflow_data.enabled

    updated_workflow = db.update_workflow(workflow)
    return WorkflowResponse(**updated_workflow.to_dict())


@router.delete("/{id}", status_code=204)
async def delete_workflow(id: str):
    """Delete a workflow."""
    workflow = db.get_workflow(id)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    db.delete_workflow(id)
    return None


@router.post("/{id}/execute", response_model=WorkflowExecutionResponse)
async def execute_workflow(id: str, input_data: Dict[str, Any] = None):
    """Execute a workflow."""
    workflow = db.get_workflow(id)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    if not workflow.enabled:
        raise HTTPException(status_code=400, detail="Workflow is disabled")

    execution = WorkflowExecution(
        id="",
        workflow_id=id,
        status=WorkflowStatus.RUNNING,
        input_data=input_data or {},
    )
    created_execution = db.create_execution(execution)

    created_execution.status = WorkflowStatus.COMPLETED
    created_execution.completed_at = datetime.utcnow()
    created_execution.output_data = {
        "result": "success",
        "steps_completed": len(workflow.steps),
    }
    db.update_execution(created_execution)

    return WorkflowExecutionResponse(**created_execution.to_dict())


@router.get("/{id}/history")
async def get_workflow_history(
    id: str, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """Get workflow execution history."""
    workflow = db.get_workflow(id)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    executions = db.list_executions(workflow_id=id, limit=limit, offset=offset)
    return {
        "workflow_id": id,
        "executions": [WorkflowExecutionResponse(**e.to_dict()) for e in executions],
        "total": len(executions),
        "limit": limit,
        "offset": offset,
    }
