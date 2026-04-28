"""Remediation Lifecycle Management API endpoints."""

import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

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
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
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
        org_id = request.query_params.get("org_id", "default")
        raw = svc.get_tasks(org_id=org_id, limit=1000) if hasattr(svc, "get_tasks") else []
        tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except (OSError, ValueError, RuntimeError, sqlite3.OperationalError, sqlite3.ProgrammingError):
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
        org_id = request.query_params.get("org_id", "default")
        raw = svc.get_tasks(org_id=org_id, limit=200) if hasattr(svc, "get_tasks") else []
        tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except (OSError, ValueError, RuntimeError, sqlite3.OperationalError, sqlite3.ProgrammingError):
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
        raw = svc.get_tasks(org_id="default", limit=1000) if hasattr(svc, "get_tasks") else []
        tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except (OSError, ValueError, RuntimeError, sqlite3.OperationalError, sqlite3.ProgrammingError):
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


@router.get("/tasks/{task_id}/timeline")
def get_task_timeline(task_id: str) -> Dict[str, Any]:
    """Full remediation lifecycle timeline for a task.

    Returns every phase of the finding lifecycle:
    discovery → triage → ticket → fix → verification → evidence,
    assembled from task_history, task metadata, and linked evidence.
    """
    service = get_remediation_service()
    task = service.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    task_dict = dict(task) if not isinstance(task, dict) else task

    # Build timeline events from task_history
    events: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(service.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM task_history WHERE task_id = ? ORDER BY timestamp ASC",
            (task_id,),
        ).fetchall()
        conn.close()
        for row in rows:
            r = dict(row)
            events.append(
                {
                    "phase": _status_to_phase(r.get("new_status", "")),
                    "status": r.get("new_status", ""),
                    "previous_status": r.get("old_status"),
                    "changed_by": r.get("changed_by"),
                    "reason": r.get("reason"),
                    "timestamp": r.get("timestamp"),
                }
            )
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass

    # Derive lifecycle phases with timestamps
    phases: Dict[str, Any] = {
        "discovery": {
            "status": "completed",
            "timestamp": task_dict.get("created_at"),
        },
        "triage": {"status": "pending", "timestamp": None},
        "ticket": {"status": "pending", "timestamp": None},
        "fix": {"status": "pending", "timestamp": None},
        "verification": {"status": "pending", "timestamp": None},
        "evidence": {"status": "pending", "timestamp": None},
    }

    # Mark phases based on history events
    for ev in events:
        phase = ev.get("phase", "")
        ts = ev.get("timestamp")
        if phase in phases and ts:
            phases[phase] = {"status": "completed", "timestamp": ts}

    # Ticket linking
    if task_dict.get("ticket_id"):
        phases["ticket"] = {
            "status": "completed",
            "timestamp": task_dict.get("updated_at"),
            "ticket_id": task_dict.get("ticket_id"),
            "ticket_url": task_dict.get("ticket_url"),
        }

    # Verification evidence
    if task_dict.get("verification_evidence"):
        phases["evidence"] = {
            "status": "completed",
            "timestamp": task_dict.get("resolved_at") or task_dict.get("updated_at"),
        }

    # Compute MTTR if resolved
    mttr_hours = None
    if task_dict.get("resolved_at") and task_dict.get("created_at"):
        try:
            created = datetime.fromisoformat(task_dict["created_at"])
            resolved = datetime.fromisoformat(task_dict["resolved_at"])
            mttr_hours = round((resolved - created).total_seconds() / 3600, 2)
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
            pass

    # Current phase
    current_phase = "discovery"
    for p in ("evidence", "verification", "fix", "ticket", "triage", "discovery"):
        if phases[p]["status"] == "completed":
            idx = list(phases.keys()).index(p)
            next_phases = list(phases.keys())
            if idx + 1 < len(next_phases):
                current_phase = next_phases[idx + 1]
            else:
                current_phase = p  # all done
            break

    sla_breached = bool(task_dict.get("sla_breached"))

    return {
        "task_id": task_id,
        "title": task_dict.get("title", ""),
        "severity": task_dict.get("severity", ""),
        "current_status": task_dict.get("status", ""),
        "current_phase": current_phase,
        "phases": phases,
        "events": events,
        "mttr_hours": mttr_hours,
        "sla_breached": sla_breached,
        "sla_hours": task_dict.get("sla_hours"),
        "assignee": task_dict.get("assignee"),
        "app_id": task_dict.get("app_id"),
    }


def _status_to_phase(status: str) -> str:
    """Map a remediation status to a lifecycle phase."""
    mapping = {
        "open": "discovery",
        "triaged": "triage",
        "in_progress": "fix",
        "review": "fix",
        "verification": "verification",
        "verified": "verification",
        "resolved": "evidence",
        "closed": "evidence",
        "wont_fix": "triage",
        "deferred": "triage",
    }
    return mapping.get(status, "discovery")


# ---------------------------------------------------------------------------
# CWE-based Remediation Plan endpoints
# ---------------------------------------------------------------------------

try:
    from core.remediation_engine import (
        CodeFix,
        EffortLevel,
        PlanState,
        RemediationPlan,
        RemediationPlanEngine,
    )

    _HAS_PLAN_ENGINE = True
except ImportError:
    _HAS_PLAN_ENGINE = False

_plan_engine: Optional["RemediationPlanEngine"] = None


def _get_plan_engine() -> "RemediationPlanEngine":
    global _plan_engine
    if _plan_engine is None:
        _plan_engine = RemediationPlanEngine(_DATA_DIR / "plans.db")
    return _plan_engine


class CreatePlanRequest(BaseModel):
    """Request to create a CWE-based remediation plan."""

    id: str
    cwe_id: str
    severity: str = "MEDIUM"
    title: Optional[str] = None


class UpdatePlanStateRequest(BaseModel):
    """Request to advance a plan's state."""

    state: str


class SuggestFixRequest(BaseModel):
    """Request to get a code fix suggestion."""

    id: str
    cwe_id: str
    code_snippet: str = ""


class VerifyFixRequest(BaseModel):
    """Request to verify a fix via re-scan results."""

    finding_id: str
    new_scan_results: List[Dict[str, Any]]


@router.post("/plan", summary="Create CWE-based remediation plan")
def create_plan(req: CreatePlanRequest) -> Dict[str, Any]:
    """Generate a step-by-step remediation plan for a finding based on its CWE ID."""
    if not _HAS_PLAN_ENGINE:
        raise HTTPException(status_code=501, detail="Remediation plan engine not available")
    engine = _get_plan_engine()
    plan = engine.create_remediation_plan(req.model_dump())
    return plan.model_dump(mode="json")


@router.get("/plans", summary="List all remediation plans")
def list_plans(
    finding_id: Optional[str] = None,
    state: Optional[str] = None,
) -> Dict[str, Any]:
    """List remediation plans with optional filters."""
    if not _HAS_PLAN_ENGINE:
        raise HTTPException(status_code=501, detail="Remediation plan engine not available")
    engine = _get_plan_engine()
    state_filter = None
    if state:
        try:
            state_filter = PlanState(state.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid state: {state}")
    plans = engine.list_plans(finding_id=finding_id, state_filter=state_filter)
    return {"plans": [p.model_dump(mode="json") for p in plans], "count": len(plans)}


@router.put("/{plan_id}/status", summary="Update plan state")
def update_plan_state(plan_id: str, req: UpdatePlanStateRequest) -> Dict[str, Any]:
    """Advance a remediation plan through its state machine."""
    if not _HAS_PLAN_ENGINE:
        raise HTTPException(status_code=501, detail="Remediation plan engine not available")
    engine = _get_plan_engine()
    try:
        new_state = PlanState(req.state.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid state: {req.state}")
    try:
        plan = engine.update_state(plan_id, new_state)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return plan.model_dump(mode="json")


@router.post("/suggest-fix", summary="Get code fix suggestion for a finding")
def suggest_fix(req: SuggestFixRequest) -> Dict[str, Any]:
    """Return a safe code fix suggestion based on the finding's CWE ID."""
    if not _HAS_PLAN_ENGINE:
        raise HTTPException(status_code=501, detail="Remediation plan engine not available")
    engine = _get_plan_engine()
    fix = engine.suggest_code_fix(req.model_dump(), req.code_snippet)
    return fix.model_dump(mode="json")


@router.post("/verify", summary="Verify fix via re-scan results")
def verify_fix(req: VerifyFixRequest) -> Dict[str, Any]:
    """Check whether a finding still appears in new scan results."""
    if not _HAS_PLAN_ENGINE:
        raise HTTPException(status_code=501, detail="Remediation plan engine not available")
    engine = _get_plan_engine()
    fixed = engine.verify_fix(req.finding_id, req.new_scan_results)
    return {
        "finding_id": req.finding_id,
        "verified": fixed,
        "message": "Finding no longer detected — fix verified." if fixed else "Finding still present — fix incomplete.",
    }


@router.get("/cwe-templates", summary="List CWE remediation templates")
def list_cwe_templates() -> Dict[str, Any]:
    """Return all built-in CWE remediation templates with effort and step counts."""
    if not _HAS_PLAN_ENGINE:
        raise HTTPException(status_code=501, detail="Remediation plan engine not available")
    engine = _get_plan_engine()
    templates = engine.list_cwe_templates()
    return {"templates": templates, "count": len(templates)}


@router.get("/sla", summary="Get SLA deadline for a severity")
def get_sla(severity: str = "MEDIUM") -> Dict[str, Any]:
    """Return the SLA timedelta and hours for a given severity level."""
    if not _HAS_PLAN_ENGINE:
        raise HTTPException(status_code=501, detail="Remediation plan engine not available")
    engine = _get_plan_engine()
    sla = engine.calculate_remediation_sla(severity)
    return {
        "severity": severity.upper(),
        "sla_hours": int(sla.total_seconds() / 3600),
        "sla_days": round(sla.total_seconds() / 86400, 1),
    }
