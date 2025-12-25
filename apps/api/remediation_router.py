"""Remediation Lifecycle Management API endpoints."""

from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.services.remediation import RemediationService, RemediationStatus

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])

# Initialize service with default path
_DATA_DIR = Path("data/remediation")
_remediation_service: Optional[RemediationService] = None


def get_remediation_service() -> RemediationService:
    """Get or create remediation service instance."""
    global _remediation_service
    if _remediation_service is None:
        _remediation_service = RemediationService(_DATA_DIR / "tasks.db")
    return _remediation_service


class CreateTaskRequest(BaseModel):
    """Request to create a remediation task."""

    cluster_id: str
    org_id: str
    app_id: str
    title: str
    severity: str
    description: Optional[str] = None
    assignee: Optional[str] = None
    assignee_email: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class UpdateStatusRequest(BaseModel):
    """Request to update task status."""

    status: str
    changed_by: Optional[str] = None
    reason: Optional[str] = None


class AssignTaskRequest(BaseModel):
    """Request to assign task."""

    assignee: str
    assignee_email: Optional[str] = None
    changed_by: Optional[str] = None


class SubmitVerificationRequest(BaseModel):
    """Request to submit verification evidence."""

    evidence_type: str
    evidence_data: Dict[str, Any]
    submitted_by: Optional[str] = None


class LinkTicketRequest(BaseModel):
    """Request to link task to external ticket."""

    ticket_id: str
    ticket_url: Optional[str] = None


@router.post("/tasks")
async def create_task(request: CreateTaskRequest) -> Dict[str, Any]:
    """Create a new remediation task."""
    service = get_remediation_service()
    return service.create_task(
        cluster_id=request.cluster_id,
        org_id=request.org_id,
        app_id=request.app_id,
        title=request.title,
        severity=request.severity,
        description=request.description,
        assignee=request.assignee,
        assignee_email=request.assignee_email,
        metadata=request.metadata,
    )


@router.get("/tasks")
async def list_tasks(
    org_id: str,
    app_id: Optional[str] = None,
    status: Optional[str] = None,
    assignee: Optional[str] = None,
    severity: Optional[str] = None,
    overdue_only: bool = False,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List remediation tasks with optional filters."""
    service = get_remediation_service()
    tasks = service.get_tasks(
        org_id=org_id,
        app_id=app_id,
        status=status,
        assignee=assignee,
        severity=severity,
        overdue_only=overdue_only,
        limit=limit,
        offset=offset,
    )
    return {
        "tasks": tasks,
        "count": len(tasks),
        "limit": limit,
        "offset": offset,
    }


@router.get("/tasks/{task_id}")
async def get_task(task_id: str) -> Dict[str, Any]:
    """Get a specific task by ID."""
    service = get_remediation_service()
    task = service.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.put("/tasks/{task_id}/status")
async def update_task_status(
    task_id: str, request: UpdateStatusRequest
) -> Dict[str, Any]:
    """Update task status with state machine validation."""
    service = get_remediation_service()
    try:
        return service.update_status(
            task_id=task_id,
            new_status=request.status,
            changed_by=request.changed_by,
            reason=request.reason,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/tasks/{task_id}/assign")
async def assign_task(task_id: str, request: AssignTaskRequest) -> Dict[str, Any]:
    """Assign task to a user."""
    service = get_remediation_service()
    try:
        return service.assign_task(
            task_id=task_id,
            assignee=request.assignee,
            assignee_email=request.assignee_email,
            changed_by=request.changed_by,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/tasks/{task_id}/verification")
async def submit_verification(
    task_id: str, request: SubmitVerificationRequest
) -> Dict[str, Any]:
    """Submit verification evidence for a task."""
    service = get_remediation_service()
    try:
        return service.submit_verification(
            task_id=task_id,
            evidence_type=request.evidence_type,
            evidence_data=request.evidence_data,
            submitted_by=request.submitted_by,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/tasks/{task_id}/ticket")
async def link_ticket(task_id: str, request: LinkTicketRequest) -> Dict[str, Any]:
    """Link task to external ticket."""
    service = get_remediation_service()
    success = service.link_to_ticket(
        task_id=task_id,
        ticket_id=request.ticket_id,
        ticket_url=request.ticket_url,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Task not found")
    return {
        "status": "linked",
        "task_id": task_id,
        "ticket_id": request.ticket_id,
    }


@router.post("/sla/check")
async def check_sla_breaches(org_id: str) -> Dict[str, Any]:
    """Check for SLA breaches and record them."""
    service = get_remediation_service()
    breaches = service.check_sla_breaches(org_id)
    return {
        "org_id": org_id,
        "breaches_found": len(breaches),
        "breaches": breaches,
    }


@router.get("/metrics/{org_id}")
async def get_metrics(org_id: str, app_id: Optional[str] = None) -> Dict[str, Any]:
    """Get remediation metrics including MTTR."""
    service = get_remediation_service()
    return service.get_metrics(org_id, app_id)


@router.get("/statuses")
async def list_valid_statuses() -> Dict[str, Any]:
    """List all valid remediation statuses."""
    return {
        "statuses": [s.value for s in RemediationStatus],
        "transitions": {
            status.value: [t.value for t in targets]
            for status, targets in __import__(
                "core.services.remediation", fromlist=["VALID_TRANSITIONS"]
            ).VALID_TRANSITIONS.items()
        },
    }
