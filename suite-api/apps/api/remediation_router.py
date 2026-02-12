"""Remediation Lifecycle Management API endpoints."""

from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from apps.api.dependencies import get_org_id
from core.services.remediation import (
    VALID_TRANSITIONS,
    RemediationService,
    RemediationStatus,
)

# Knowledge Brain + Event Bus integration (graceful degradation)
try:
    from core.event_bus import Event, EventType, get_event_bus
    from core.knowledge_brain import get_brain

    _HAS_BRAIN = True
except ImportError:
    _HAS_BRAIN = False

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
    result = service.create_task(
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

    # Emit remediation created event + ingest into Knowledge Brain
    if _HAS_BRAIN:
        bus = get_event_bus()
        brain = get_brain()
        task_id = result.get("task_id", "")
        brain.ingest_remediation(
            task_id,
            org_id=request.org_id,
            title=request.title,
            severity=request.severity,
            assignee=request.assignee,
        )
        await bus.emit(Event(
            event_type=EventType.REMEDIATION_CREATED,
            source="remediation_router",
            data={"task_id": task_id, "org_id": request.org_id,
                  "title": request.title, "severity": request.severity},
            org_id=request.org_id,
        ))

    return result


@router.get("/tasks")
def list_tasks(
    org_id: str = Depends(get_org_id),
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
def get_task(task_id: str) -> Dict[str, Any]:
    """Get a specific task by ID."""
    service = get_remediation_service()
    task = service.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.put("/tasks/{task_id}/status")
async def update_task_status(task_id: str, request: UpdateStatusRequest) -> Dict[str, Any]:
    """Update task status with state machine validation."""
    service = get_remediation_service()
    try:
        result = service.update_status(
            task_id=task_id,
            new_status=request.status,
            changed_by=request.changed_by,
            reason=request.reason,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Emit remediation completed event if status is terminal
    if _HAS_BRAIN:
        bus = get_event_bus()
        completed_statuses = {"verified", "closed", "completed", "resolved"}
        event_type = (
            EventType.REMEDIATION_COMPLETED
            if request.status.lower() in completed_statuses
            else EventType.REMEDIATION_CREATED  # status change
        )
        await bus.emit(Event(
            event_type=event_type,
            source="remediation_router",
            data={"task_id": task_id, "new_status": request.status,
                  "changed_by": request.changed_by},
        ))

    return result


@router.put("/tasks/{task_id}/assign")
def assign_task(task_id: str, request: AssignTaskRequest) -> Dict[str, Any]:
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
def submit_verification(
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
def link_ticket(task_id: str, request: LinkTicketRequest) -> Dict[str, Any]:
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
def check_sla_breaches(org_id: str) -> Dict[str, Any]:
    """Check for SLA breaches and record them."""
    service = get_remediation_service()
    breaches = service.check_sla_breaches(org_id)
    return {
        "org_id": org_id,
        "breaches_found": len(breaches),
        "breaches": breaches,
    }


@router.get("/metrics/{org_id}")
def get_metrics(org_id: str, app_id: Optional[str] = None) -> Dict[str, Any]:
    """Get remediation metrics including MTTR."""
    service = get_remediation_service()
    return service.get_metrics(org_id, app_id)


@router.get("/statuses")
def list_valid_statuses() -> Dict[str, Any]:
    """List all valid remediation statuses."""
    return {
        "statuses": [s.value for s in RemediationStatus],
        "transitions": {
            status.value: [t.value for t in targets]
            for status, targets in VALID_TRANSITIONS.items()
        },
    }


# ---------------------------------------------------------------------------
# AutoFix integration
# ---------------------------------------------------------------------------

# AutoFix engine (graceful degradation)
try:
    from core.autofix_engine import get_autofix_engine
    _HAS_AUTOFIX = True
except ImportError:
    _HAS_AUTOFIX = False


class AutoFixTaskRequest(BaseModel):
    """Request to generate autofix for a remediation task."""
    source_code: Optional[str] = None
    repo_context: Optional[Dict[str, Any]] = None
    repository: Optional[str] = None
    create_pr: bool = True


@router.post("/tasks/{task_id}/autofix")
async def autofix_task(task_id: str, request: AutoFixTaskRequest) -> Dict[str, Any]:
    """Generate an AI-powered autofix for a remediation task.

    Uses the task metadata to generate a code fix, dependency update,
    or configuration change. Optionally creates a pull request.
    """
    if not _HAS_AUTOFIX:
        raise HTTPException(status_code=501, detail="AutoFix engine not available")

    service = get_remediation_service()
    task = service.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Build a finding dict from the task
    finding = {
        "id": task_id,
        "title": task.get("title", ""),
        "description": task.get("description", ""),
        "severity": task.get("severity", "medium"),
        "cve_ids": task.get("metadata", {}).get("cve_ids", []),
        "cwe_id": task.get("metadata", {}).get("cwe_id", ""),
        "file_path": task.get("metadata", {}).get("file_path", ""),
        "category": task.get("metadata", {}).get("category", ""),
    }

    engine = get_autofix_engine()
    suggestion = await engine.generate_fix(
        finding=finding,
        source_code=request.source_code,
        repo_context=request.repo_context,
    )

    result = {
        "task_id": task_id,
        "autofix": engine.to_dict(suggestion),
    }

    # Optionally apply and create PR
    if request.repository and request.create_pr:
        apply_result = await engine.apply_fix(
            fix_id=suggestion.fix_id,
            repository=request.repository,
            create_pr=True,
        )
        result["pr_created"] = apply_result.success
        result["pr_url"] = apply_result.pr_url
        result["pr_number"] = apply_result.pr_number
        if apply_result.error:
            result["pr_error"] = apply_result.error

    return result


@router.get("/tasks/{task_id}/autofix/suggestions")
async def get_task_autofix_suggestions(task_id: str) -> Dict[str, Any]:
    """Get existing autofix suggestions for a remediation task."""
    if not _HAS_AUTOFIX:
        raise HTTPException(status_code=501, detail="AutoFix engine not available")

    engine = get_autofix_engine()
    fixes = engine.list_fixes(finding_id=task_id)
    return {
        "task_id": task_id,
        "suggestions": [engine.to_dict(f) for f in fixes],
        "count": len(fixes),
    }


# CLI-compatible alias endpoints


@router.put("/tasks/{task_id}/transition")
def transition_task_status(
    task_id: str, request: UpdateStatusRequest
) -> Dict[str, Any]:
    """Transition task status (CLI-compatible alias for /tasks/{task_id}/status)."""
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


@router.post("/tasks/{task_id}/verify")
def verify_task(task_id: str, request: SubmitVerificationRequest) -> Dict[str, Any]:
    """Verify task (CLI-compatible alias for /tasks/{task_id}/verification)."""
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


@router.get("/metrics")
def get_global_metrics() -> Dict[str, Any]:
    """Get global remediation metrics (CLI-compatible endpoint)."""
    service = get_remediation_service()
    return service.get_metrics("default", None)
