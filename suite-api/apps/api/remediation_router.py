"""Remediation Lifecycle Management API endpoints."""

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from apps.api.dependencies import get_org_id
from core.services.remediation import (
    VALID_TRANSITIONS,
    RemediationService,
    RemediationStatus,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

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
        await bus.emit(
            Event(
                event_type=EventType.REMEDIATION_CREATED,
                source="remediation_router",
                data={
                    "task_id": task_id,
                    "org_id": request.org_id,
                    "title": request.title,
                    "severity": request.severity,
                },
                org_id=request.org_id,
            )
        )

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
async def update_task_status(
    task_id: str, request: UpdateStatusRequest
) -> Dict[str, Any]:
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
        _logger.warning("remediation.update_status.invalid: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail="Invalid status transition")

    # Emit remediation completed event if status is terminal
    if _HAS_BRAIN:
        bus = get_event_bus()
        completed_statuses = {"verified", "closed", "completed", "resolved"}
        event_type = (
            EventType.REMEDIATION_COMPLETED
            if request.status.lower() in completed_statuses
            else EventType.REMEDIATION_CREATED  # status change
        )
        await bus.emit(
            Event(
                event_type=event_type,
                source="remediation_router",
                data={
                    "task_id": task_id,
                    "new_status": request.status,
                    "changed_by": request.changed_by,
                },
            )
        )

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
        _logger.warning("remediation.assign_task.invalid: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail="Invalid assignment request")


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
        _logger.warning("remediation.submit_verification.invalid: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail="Invalid verification submission")


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
        _logger.warning("remediation.transition.invalid: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail="Invalid status transition")


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
        _logger.warning("remediation.verify.invalid: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail="Invalid verification submission")


@router.get("/metrics")
def get_global_metrics() -> Dict[str, Any]:
    """Get global remediation metrics (CLI-compatible endpoint)."""
    service = get_remediation_service()
    return service.get_metrics("default", None)


# ---------------------------------------------------------------------------
# Sprint-aware security backlog
# ---------------------------------------------------------------------------

# Estimated effort hours by severity (aligned with SLA urgency)
_EFFORT_HOURS: Dict[str, int] = {
    "critical": 4,
    "high": 8,
    "medium": 16,
    "low": 24,
}

# Active (non-terminal) statuses eligible for sprint planning
_BACKLOG_STATUSES = {"open", "assigned", "in_progress", "verification"}


def _compute_sla_status(task: Dict[str, Any]) -> str:
    """Derive SLA status for a backlog item.

    Returns one of: 'overdue', 'at_risk' (< 20% SLA time remaining), 'on_track'.
    """
    from datetime import datetime, timezone

    if task.get("is_overdue"):
        return "overdue"

    due_at_raw = task.get("due_at")
    sla_hours = task.get("sla_hours") or 168
    if not due_at_raw:
        return "on_track"

    due_at = datetime.fromisoformat(due_at_raw)
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    remaining_hours = (due_at - now).total_seconds() / 3600
    threshold_hours = sla_hours * 0.20  # at-risk when < 20% SLA time remains

    if remaining_hours <= threshold_hours:
        return "at_risk"
    return "on_track"


def _to_backlog_item(task: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw task row into a sprint-backlog item."""
    severity = (task.get("severity") or "medium").lower()
    status = (task.get("status") or "open").lower()
    sla_status = _compute_sla_status(task)

    # sprint_eligible: active, not overdue, and ready for assignment
    sprint_eligible = (
        status in {"open", "assigned", "in_progress"}
        and sla_status != "overdue"
    )

    # Normalise the SLA deadline field name for the API response
    sla_deadline = task.get("due_at")

    # Extract finding_id from metadata if present
    metadata = task.get("metadata")
    if isinstance(metadata, str):
        import json as _json
        try:
            metadata = _json.loads(metadata)
        except Exception:
            metadata = {}
    finding_id = (metadata or {}).get("finding_id") or task.get("task_id")

    return {
        "task_id": task.get("task_id"),
        "title": task.get("title"),
        "severity": severity,
        "status": status,
        "sprint_eligible": sprint_eligible,
        "estimated_effort_hours": _EFFORT_HOURS.get(severity, 16),
        "assignee": task.get("assignee"),
        "finding_id": finding_id,
        "sla_deadline": sla_deadline,
        "sla_status": sla_status,
        "created_at": task.get("created_at"),
    }


@router.get("/backlog")
def get_remediation_backlog(
    org_id: str = Depends(get_org_id),
    severity: Optional[str] = Query(default=None, description="Filter by severity: critical|high|medium|low"),
    sprint: Optional[str] = Query(default=None, description="'current' returns only sprint-eligible tasks"),
    assignee: Optional[str] = Query(default=None, description="Filter by assignee; 'unassigned' returns tasks with no assignee"),
    limit: int = Query(default=50, le=500),
) -> Dict[str, Any]:
    """Return the sprint-aware security remediation backlog.

    Query parameters:
    - **severity**: Filter by severity level (critical, high, medium, low)
    - **sprint**: Pass ``current`` to return only sprint-eligible (open/active, non-overdue) tasks
    - **assignee**: Filter by assignee username; use ``unassigned`` to return tasks with no assignee
    - **limit**: Maximum number of items to return (default 50, max 500)
    """
    service = get_remediation_service()

    # Resolve assignee filter
    assignee_filter: Optional[str] = None
    unassigned_only = False
    if assignee is not None:
        if assignee.lower() == "unassigned":
            unassigned_only = True
        else:
            assignee_filter = assignee

    # Fetch all active (non-terminal) tasks for this org, honouring severity
    # and assignee filters where the service supports them natively.
    raw_tasks = service.get_tasks(
        org_id=org_id,
        severity=severity,
        assignee=assignee_filter,
        limit=limit * 4,  # over-fetch to allow for post-filter trimming
        offset=0,
    )

    # Build backlog items
    backlog = []
    for task in raw_tasks:
        status = (task.get("status") or "").lower()
        # Exclude terminal statuses from the backlog
        if status not in _BACKLOG_STATUSES:
            continue

        item = _to_backlog_item(task)

        # Apply unassigned filter post-fetch
        if unassigned_only and item["assignee"] is not None:
            continue

        # Apply sprint=current filter: keep only sprint-eligible items
        if sprint and sprint.lower() == "current" and not item["sprint_eligible"]:
            continue

        backlog.append(item)

        if len(backlog) >= limit:
            break

    # Aggregate statistics
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_status: Dict[str, int] = {"open": 0, "in_progress": 0, "resolved": 0}
    sprint_ready = 0
    overdue = 0

    for item in backlog:
        sev = item["severity"]
        if sev in by_severity:
            by_severity[sev] += 1

        st = item["status"]
        if st == "open" or st == "assigned":
            by_status["open"] += 1
        elif st == "in_progress" or st == "verification":
            by_status["in_progress"] += 1
        elif st == "resolved":
            by_status["resolved"] += 1

        if item["sprint_eligible"]:
            sprint_ready += 1
        if item["sla_status"] == "overdue":
            overdue += 1

    return {
        "backlog": backlog,
        "total": len(backlog),
        "by_severity": by_severity,
        "by_status": by_status,
        "sprint_ready": sprint_ready,
        "overdue": overdue,
    }


@router.get("/stats")
async def remediation_stats(request: Request):
    """Remediation statistics — task counts by severity/status/assignee."""
    svc = get_remediation_service()
    tasks = []
    try:
        raw = svc.get_tasks(limit=1000) if hasattr(svc, "get_tasks") else []
        tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except Exception:
        pass

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_status = {"open": 0, "in_progress": 0, "resolved": 0, "closed": 0}
    by_assignee: dict = {}

    for t in tasks:
        t_dict = t if isinstance(t, dict) else (t.__dict__ if hasattr(t, "__dict__") else {})
        sev = (t_dict.get("severity") or "medium").lower()
        if sev in by_severity:
            by_severity[sev] += 1
        st = (t_dict.get("status") or "open")
        st_val = st.value if hasattr(st, "value") else str(st)
        if st_val.lower() in by_status:
            by_status[st_val.lower()] += 1
        assignee = t_dict.get("assignee") or "unassigned"
        by_assignee[assignee] = by_assignee.get(assignee, 0) + 1

    return {
        "status": "ok",
        "total": len(tasks),
        "by_severity": by_severity,
        "by_status": by_status,
        "by_assignee": dict(sorted(by_assignee.items(), key=lambda x: -x[1])[:20]),
    }


@router.get("/queue")
async def remediation_queue(request: Request):
    """Remediation queue — pending tasks ordered by priority."""
    svc = get_remediation_service()
    tasks = []
    try:
        raw = svc.get_tasks(limit=200) if hasattr(svc, "get_tasks") else []
        tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except Exception:
        pass

    # Filter to open/in_progress tasks
    queue = []
    for t in tasks:
        t_dict = t if isinstance(t, dict) else (t.__dict__ if hasattr(t, "__dict__") else {})
        st = t_dict.get("status") or ""
        st_val = st.value if hasattr(st, "value") else str(st)
        if st_val.lower() in ("open", "assigned", "in_progress", "pending"):
            queue.append(t_dict)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    queue.sort(key=lambda t: severity_order.get((t.get("severity") or "low").lower(), 3))

    return {
        "status": "ok",
        "queue": queue[:100],
        "total": len(queue),
    }


@router.get("/summary")
async def remediation_summary(request: Request):
    """Remediation summary — high-level overview."""
    svc = get_remediation_service()
    tasks = []
    try:
        raw = svc.get_tasks(limit=1000) if hasattr(svc, "get_tasks") else []
        tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except Exception:
        pass

    total = len(tasks)
    resolved = 0
    in_progress = 0
    for t in tasks:
        t_dict = t if isinstance(t, dict) else (t.__dict__ if hasattr(t, "__dict__") else {})
        st = t_dict.get("status") or ""
        st_val = st.value if hasattr(st, "value") else str(st)
        if st_val.lower() in ("resolved", "closed", "completed"):
            resolved += 1
        elif st_val.lower() == "in_progress":
            in_progress += 1

    open_count = total - resolved - in_progress

    return {
        "status": "ok",
        "total": total,
        "resolved": resolved,
        "in_progress": in_progress,
        "open": open_count,
        "resolution_rate": round(resolved / max(total, 1) * 100, 1),
    }
