"""SLA Management Router for ALDECI.

Provides per-severity SLA policy management, compliance tracking, breach
detection, and auto-escalation.

Endpoints:
  POST /api/v1/sla/policies            — create/update SLA policy
  GET  /api/v1/sla/policies            — get policy for org
  GET  /api/v1/sla/status/{finding_id} — SLA status for a finding
  GET  /api/v1/sla/breached            — all breached findings
  GET  /api/v1/sla/at-risk             — approaching deadline
  GET  /api/v1/sla/compliance          — compliance rate
  GET  /api/v1/sla/dashboard           — all SLA metrics
  POST /api/v1/sla/escalate            — run escalation check

  Legacy endpoints (V3 analytics — retained for backward compat):
  GET  /api/v1/sla/dashboard-legacy    — old remediation-task view
  GET  /api/v1/sla/metrics             — MTTR + team breakdown
  GET  /api/v1/sla/breaches            — task-level breach list
  GET  /api/v1/sla/health              — health check
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.sla_manager import SLAManager, SLAPolicy, SLARecord
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sla", tags=["SLA"])

# Module-level singleton
_manager = None  # lazy-initialised on first request


def _get_manager() -> SLAManager:
    global _manager
    if _manager is None:
        _manager = SLAManager()
    return _manager


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class SLAPolicyRequest(BaseModel):
    """Payload for creating or updating an SLA policy."""

    name: str
    severity_deadlines: Dict[str, int] = Field(
        default_factory=lambda: {"critical": 24, "high": 72, "medium": 336, "low": 720}
    )
    escalation_chain: List[str] = Field(default_factory=list)
    grace_period_hours: int = 0
    enabled: bool = True


class TrackFindingRequest(BaseModel):
    finding_id: str
    severity: str
    discovered_at: Optional[datetime] = None


class BulkTrackRequest(BaseModel):
    findings: List[Dict[str, Any]]


class EscalateResponse(BaseModel):
    escalated_count: int
    org_id: str


# ---------------------------------------------------------------------------
# Policy endpoints
# ---------------------------------------------------------------------------


@router.get("/")
async def list_sla(org_id: str = Depends(get_org_id), manager: SLAManager = Depends(_get_manager)):
    """List SLA records for the org."""
    breached = manager.get_breached(org_id)
    at_risk = manager.get_at_risk(org_id)
    return {"org_id": org_id, "breached": [r.model_dump() for r in breached], "at_risk": [r.model_dump() for r in at_risk], "total": len(breached) + len(at_risk)}


@router.post("/policies", response_model=SLAPolicy, status_code=status.HTTP_201_CREATED)
async def create_or_update_policy(
    payload: SLAPolicyRequest,
    org_id: str = Depends(get_org_id),
    manager: SLAManager = Depends(_get_manager),
) -> SLAPolicy:
    """Create or update the SLA policy for the current org."""
    existing = manager.get_policy(org_id)
    if existing:
        policy = manager.update_policy(
            org_id,
            {
                "name": payload.name,
                "severity_deadlines": payload.severity_deadlines,
                "escalation_chain": payload.escalation_chain,
                "grace_period_hours": payload.grace_period_hours,
                "enabled": payload.enabled,
            },
        )
    else:
        policy = SLAPolicy(
            org_id=org_id,
            name=payload.name,
            severity_deadlines=payload.severity_deadlines,
            escalation_chain=payload.escalation_chain,
            grace_period_hours=payload.grace_period_hours,
            enabled=payload.enabled,
        )
        policy = manager.create_policy(policy)
    return policy


@router.get("/policies", response_model=Optional[SLAPolicy])
async def get_policy(
    org_id: str = Depends(get_org_id),
    manager: SLAManager = Depends(_get_manager),
) -> Optional[SLAPolicy]:
    """Get the SLA policy for the current org."""
    return manager.get_policy(org_id)


# ---------------------------------------------------------------------------
# Finding tracking endpoints
# ---------------------------------------------------------------------------


@router.post("/track", response_model=SLARecord, status_code=status.HTTP_201_CREATED)
async def track_finding(
    payload: TrackFindingRequest,
    org_id: str = Depends(get_org_id),
    manager: SLAManager = Depends(_get_manager),
) -> SLARecord:
    """Start SLA tracking for a finding."""
    disc = payload.discovered_at or datetime.now(timezone.utc)
    return manager.track_finding(payload.finding_id, payload.severity, disc, org_id)


@router.post("/track/bulk", response_model=Dict[str, Any])
async def bulk_track(
    payload: BulkTrackRequest,
    org_id: str = Depends(get_org_id),
    manager: SLAManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Track multiple findings at once."""
    count = manager.bulk_track(payload.findings, org_id)
    return {"tracked": count, "org_id": org_id}


# ---------------------------------------------------------------------------
# Status / query endpoints
# ---------------------------------------------------------------------------


@router.get("/status/{finding_id}", response_model=Dict[str, Any])
async def get_sla_status(
    finding_id: str,
    org_id: str = Depends(get_org_id),
    manager: SLAManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Get the current SLA status for a specific finding."""
    record = manager.get_record(finding_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"No SLA record for finding '{finding_id}'")
    computed_status = manager.check_sla_status(finding_id)
    return {
        "finding_id": finding_id,
        "status": computed_status,
        "severity": record.severity,
        "deadline": record.deadline.isoformat(),
        "discovered_at": record.discovered_at.isoformat(),
        "escalated": record.escalated,
        "exempt_reason": record.exempt_reason,
    }


@router.get("/breached", response_model=List[SLARecord])
async def get_breached(
    org_id: str = Depends(get_org_id),
    manager: SLAManager = Depends(_get_manager),
) -> List[SLARecord]:
    """Return all breached SLA findings for the current org."""
    return manager.get_breached(org_id)


@router.get("/at-risk", response_model=List[SLARecord])
async def get_at_risk(
    hours_threshold: float = Query(24.0, ge=1.0, le=720.0),
    org_id: str = Depends(get_org_id),
    manager: SLAManager = Depends(_get_manager),
) -> List[SLARecord]:
    """Return findings approaching their SLA deadline."""
    return manager.get_at_risk(org_id, hours_threshold=hours_threshold)


@router.get("/compliance", response_model=Dict[str, Any])
async def get_compliance(
    period_days: int = Query(30, ge=1, le=365),
    org_id: str = Depends(get_org_id),
    manager: SLAManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Return the SLA compliance rate for the current org."""
    rate = manager.get_sla_compliance_rate(org_id, period_days=period_days)
    mttr = manager.get_mttr_by_severity(org_id)
    return {
        "org_id": org_id,
        "period_days": period_days,
        "compliance_rate": rate,
        "mttr_by_severity": mttr,
    }


@router.get("/dashboard", response_model=Dict[str, Any])
async def get_dashboard(
    org_id: str = Depends(get_org_id),
    manager: SLAManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Return all SLA metrics for dashboard display."""
    return manager.get_sla_dashboard(org_id)


@router.post("/escalate", response_model=EscalateResponse)
async def run_escalation(
    org_id: str = Depends(get_org_id),
    manager: SLAManager = Depends(_get_manager),
) -> EscalateResponse:
    """Run escalation check — alerts on all breached, un-escalated findings."""
    count = manager.run_escalation_check(org_id)
    return EscalateResponse(escalated_count=count, org_id=org_id)


# ---------------------------------------------------------------------------
# Legacy V3 endpoints — retained for backward compatibility
# ---------------------------------------------------------------------------


def _get_remediation_db():
    """Get remediation tasks from the analytics DB."""
    try:
        from apps.api.remediation_router import _get_db
        return _get_db()
    except ImportError:
        return None


def _compute_sla_targets() -> Dict[str, int]:
    """Default SLA targets in hours by severity."""
    return {
        "critical": 24,
        "high": 72,
        "medium": 168,
        "low": 720,
    }


def _task_age_hours(task: Dict[str, Any], now: datetime) -> float:
    """Calculate task age in hours."""
    created = task.get("created_at")
    if not created:
        return 0
    try:
        dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (now - dt).total_seconds() / 3600
    except (ValueError, TypeError):
        return 0


@router.get("/dashboard-legacy")
async def sla_dashboard_legacy() -> Dict[str, Any]:
    """Legacy SLA compliance dashboard — breach counts from remediation tasks."""
    now = datetime.now(timezone.utc)
    targets = _compute_sla_targets()
    tasks: List[Dict[str, Any]] = []
    try:
        db = _get_remediation_db()
        if db:
            raw = db.list_tasks(limit=500) if hasattr(db, "list_tasks") else []
            tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except (OSError, ValueError, RuntimeError):
        pass

    total = len(tasks)
    breached = 0
    at_risk = 0
    compliant = 0
    by_severity: Dict[str, Dict[str, int]] = {
        sev: {"total": 0, "breached": 0, "compliant": 0} for sev in targets
    }

    for task in tasks:
        sev = (task.get("severity") or "medium").lower()
        st = (task.get("status") or "").lower()
        created = task.get("created_at")
        if sev not in by_severity:
            sev = "medium"
        by_severity[sev]["total"] += 1
        if st in ("resolved", "closed", "completed"):
            by_severity[sev]["compliant"] += 1
            compliant += 1
            continue
        if created:
            try:
                created_dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                hours_elapsed = (now - created_dt).total_seconds() / 3600
                sla_hours = targets.get(sev, 168)
                if hours_elapsed > sla_hours:
                    breached += 1
                    by_severity[sev]["breached"] += 1
                elif hours_elapsed > sla_hours * 0.8:
                    at_risk += 1
                else:
                    compliant += 1
                    by_severity[sev]["compliant"] += 1
            except (ValueError, TypeError):
                compliant += 1
                by_severity[sev]["compliant"] += 1
        else:
            compliant += 1
            by_severity[sev]["compliant"] += 1

    compliance_rate = round(compliant / max(total, 1) * 100, 1)
    return {
        "status": "ok",
        "compliance_rate": compliance_rate,
        "total_tasks": total,
        "breached": breached,
        "at_risk": at_risk,
        "compliant": compliant,
        "sla_targets": {sev: f"{hours}h" for sev, hours in targets.items()},
        "by_severity": by_severity,
        "aging_buckets": {
            "0-24h": sum(1 for t in tasks if _task_age_hours(t, now) <= 24),
            "1-3d": sum(1 for t in tasks if 24 < _task_age_hours(t, now) <= 72),
            "3-7d": sum(1 for t in tasks if 72 < _task_age_hours(t, now) <= 168),
            "7-30d": sum(1 for t in tasks if 168 < _task_age_hours(t, now) <= 720),
            "30d+": sum(1 for t in tasks if _task_age_hours(t, now) > 720),
        },
        "trend": {"direction": "improving" if compliance_rate > 80 else "needs_attention", "change_7d": 0},
    }


@router.get("/metrics")
async def sla_metrics() -> Dict[str, Any]:
    """Detailed SLA metrics — MTTR, team breakdown, escalations."""
    targets = _compute_sla_targets()
    tasks: List[Dict[str, Any]] = []
    try:
        db = _get_remediation_db()
        if db:
            raw = db.list_tasks(limit=500) if hasattr(db, "list_tasks") else []
            tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except (OSError, ValueError, RuntimeError):
        pass

    resolved_times: List[float] = []
    for task in tasks:
        st = (task.get("status") or "").lower()
        if st in ("resolved", "closed", "completed"):
            created = task.get("created_at")
            resolved = task.get("resolved_at") or task.get("updated_at")
            if created and resolved:
                try:
                    c = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
                    r = datetime.fromisoformat(str(resolved).replace("Z", "+00:00"))
                    if c.tzinfo is None:
                        c = c.replace(tzinfo=timezone.utc)
                    if r.tzinfo is None:
                        r = r.replace(tzinfo=timezone.utc)
                    hours = (r - c).total_seconds() / 3600
                    if hours > 0:
                        resolved_times.append(hours)
                except (ValueError, TypeError):
                    pass

    avg_mttr = round(sum(resolved_times) / max(len(resolved_times), 1), 1) if resolved_times else 0
    p50_mttr = round(sorted(resolved_times)[len(resolved_times) // 2], 1) if resolved_times else 0
    p90_mttr = round(sorted(resolved_times)[int(len(resolved_times) * 0.9)], 1) if resolved_times else 0

    by_team: Dict[str, int] = {}
    for task in tasks:
        team = task.get("team") or task.get("assigned_team") or "unassigned"
        by_team[team] = by_team.get(team, 0) + 1

    return {
        "status": "ok",
        "mttr": {
            "average_hours": avg_mttr,
            "p50_hours": p50_mttr,
            "p90_hours": p90_mttr,
            "total_resolved": len(resolved_times),
        },
        "sla_targets": targets,
        "by_team": [{"team": t, "count": c} for t, c in sorted(by_team.items(), key=lambda x: -x[1])[:20]],
        "total_tasks": len(tasks),
        "escalation_count": sum(1 for t in tasks if t.get("escalated", False)),
    }


@router.get("/breaches")
async def sla_breaches() -> Dict[str, Any]:
    """List current SLA breaches (task-level, legacy view)."""
    now = datetime.now(timezone.utc)
    targets = _compute_sla_targets()
    tasks: List[Dict[str, Any]] = []
    try:
        db = _get_remediation_db()
        if db:
            raw = db.list_tasks(limit=500) if hasattr(db, "list_tasks") else []
            tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except (OSError, ValueError, RuntimeError):
        pass

    breaches = []
    for task in tasks:
        st = (task.get("status") or "").lower()
        if st in ("resolved", "closed", "completed"):
            continue
        sev = (task.get("severity") or "medium").lower()
        created = task.get("created_at")
        if not created:
            continue
        try:
            created_dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            hours_elapsed = (now - created_dt).total_seconds() / 3600
            sla_hours = targets.get(sev, 168)
            if hours_elapsed > sla_hours:
                breaches.append({
                    "task_id": task.get("id") or task.get("task_id", ""),
                    "title": task.get("title", "Untitled"),
                    "severity": sev,
                    "hours_elapsed": round(hours_elapsed, 1),
                    "sla_target_hours": sla_hours,
                    "overdue_hours": round(hours_elapsed - sla_hours, 1),
                    "assignee": task.get("assignee"),
                })
        except (ValueError, TypeError):
            continue

    breaches.sort(key=lambda x: x["overdue_hours"], reverse=True)
    return {
        "status": "ok",
        "breaches": breaches[:50],
        "total_breaches": len(breaches),
    }


@router.get("/health")
async def sla_health(org_id: str = Depends(get_org_id)):
    """SLA service health check."""
    return {"status": "healthy", "engine": "sla_manager", "version": "2.0.0"}


__all__ = ["router"]
