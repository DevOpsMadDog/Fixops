"""Compliance Workflow Router — ALDECI.

Endpoints for ComplianceWorkflowEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/compliance-workflows
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/compliance-workflows/workflows                                    create_workflow
  GET   /api/v1/compliance-workflows/workflows                                    list_workflows
  GET   /api/v1/compliance-workflows/workflows/{workflow_id}                      get_workflow
  POST  /api/v1/compliance-workflows/workflows/{workflow_id}/tasks                add_task
  POST  /api/v1/compliance-workflows/workflows/{workflow_id}/tasks/{task_id}/complete  complete_task
  POST  /api/v1/compliance-workflows/workflows/{workflow_id}/approvals            submit_approval
  GET   /api/v1/compliance-workflows/overdue-tasks                                get_overdue_tasks
  GET   /api/v1/compliance-workflows/framework/{framework}/readiness              get_framework_readiness
  GET   /api/v1/compliance-workflows/summary                                      get_workflow_summary
"""
from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/compliance-workflows",
    tags=["Compliance Workflows"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.compliance_workflow_engine import ComplianceWorkflowEngine
            _engine = ComplianceWorkflowEngine()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Engine unavailable: {exc}") from exc
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class WorkflowCreate(BaseModel):
    workflow_name: str
    framework: str
    workflow_type: str
    owner: str = ""
    due_date: str = ""


class TaskCreate(BaseModel):
    task_name: str
    task_type: str = "documentation"
    assignee: str = ""
    priority: str = "medium"
    evidence_required: int = 0
    due_date: str = ""


class TaskComplete(BaseModel):
    evidence_provided: int = 0


class ApprovalSubmit(BaseModel):
    approver: str
    decision: str
    comments: str = ""


# ---------------------------------------------------------------------------
# Workflows
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_compliance_workflows(org_id: str = Query("default")):
    """Get compliance workflow summary for the org."""
    return _get_engine().get_workflow_summary(org_id)


@router.post("/workflows", dependencies=[Depends(api_key_auth)], status_code=201)
def create_workflow(body: WorkflowCreate, org_id: str = Query(default="default")):
    """Create a new compliance workflow."""
    try:
        return _get_engine().create_workflow(
            org_id=org_id,
            workflow_name=body.workflow_name,
            framework=body.framework,
            workflow_type=body.workflow_type,
            owner=body.owner,
            due_date=body.due_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/workflows", dependencies=[Depends(api_key_auth)])
def list_workflows(
     org_id: str = Query(default="default"),
    framework: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List workflows with optional framework and status filters."""
    return _get_engine().list_workflows(org_id, framework=framework, status=status)


@router.get("/workflows/{workflow_id}", dependencies=[Depends(api_key_auth)])
def get_workflow(workflow_id: str, org_id: str = Query(default="default")):
    """Get a workflow with its tasks and approvals."""
    wf = _get_engine().get_workflow(workflow_id, org_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return wf


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

@router.post("/workflows/{workflow_id}/tasks", dependencies=[Depends(api_key_auth)], status_code=201)
def add_task(workflow_id: str, body: TaskCreate, org_id: str = Query(default="default")):
    """Add a task to a workflow."""
    try:
        return _get_engine().add_task(
            workflow_id=workflow_id,
            org_id=org_id,
            task_name=body.task_name,
            task_type=body.task_type,
            assignee=body.assignee,
            priority=body.priority,
            evidence_required=body.evidence_required,
            due_date=body.due_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/workflows/{workflow_id}/tasks/{task_id}/complete",
    dependencies=[Depends(api_key_auth)],
)
def complete_task(workflow_id: str, task_id: str, body: TaskComplete, org_id: str = Query(default="default")):
    """Mark a task as completed and recompute workflow completion_rate."""
    result = _get_engine().complete_task(workflow_id, task_id, org_id, body.evidence_provided)
    if not result:
        raise HTTPException(status_code=404, detail="Task not found")
    return result


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------

@router.post("/workflows/{workflow_id}/approvals", dependencies=[Depends(api_key_auth)], status_code=201)
def submit_approval(workflow_id: str, body: ApprovalSubmit, org_id: str = Query(default="default")):
    """Submit an approval decision for a workflow."""
    return _get_engine().submit_approval(
        workflow_id=workflow_id,
        org_id=org_id,
        approver=body.approver,
        decision=body.decision,
        comments=body.comments,
    )


# ---------------------------------------------------------------------------
# Overdue tasks, framework readiness, summary
# ---------------------------------------------------------------------------

@router.get("/overdue-tasks", dependencies=[Depends(api_key_auth)])
def get_overdue_tasks(org_id: str = Query(default="default")):
    """Return all tasks past their due_date that are not completed."""
    return _get_engine().get_overdue_tasks(org_id)


@router.get("/framework/{framework}/readiness", dependencies=[Depends(api_key_auth)])
def get_framework_readiness(framework: str, org_id: str = Query(default="default")):
    """Return completion rate and workflow counts for a specific framework."""
    return _get_engine().get_framework_readiness(org_id, framework)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_workflow_summary(org_id: str = Query(default="default")):
    """Return workflow counts by status and framework."""
    return _get_engine().get_workflow_summary(org_id)
