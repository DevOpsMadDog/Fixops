"""SLA Dashboard & Metrics Router (V3 — Decision Intelligence).

Provides SLA tracking, breach detection, team performance metrics,
and aging analysis for remediation tasks.

Endpoints:
  GET /dashboard  — SLA compliance dashboard overview
  GET /metrics    — Detailed SLA metrics by team/severity/app
  GET /breaches   — Current SLA breaches list
  GET /health     — Health check
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Request
from apps.api.dependencies import get_org_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sla", tags=["SLA"])


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
        "medium": 168,   # 7 days
        "low": 720,      # 30 days
    }


@router.get("/dashboard")
async def sla_dashboard() -> Dict[str, Any]:
    """SLA compliance dashboard — breach counts, compliance rates, aging analysis."""
    now = datetime.now(timezone.utc)
    targets = _compute_sla_targets()

    # Attempt to get real remediation data
    tasks: List[Dict[str, Any]] = []
    try:
        db = _get_remediation_db()
        if db:
            raw = db.list_tasks(limit=500) if hasattr(db, "list_tasks") else []
            tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass

    # Compute SLA stats from tasks
    total = len(tasks)
    breached = 0
    at_risk = 0
    compliant = 0
    by_severity: Dict[str, Dict[str, int]] = {
        sev: {"total": 0, "breached": 0, "compliant": 0}
        for sev in targets
    }

    for task in tasks:
        sev = (task.get("severity") or "medium").lower()
        status = (task.get("status") or "").lower()
        created = task.get("created_at")

        if sev not in by_severity:
            sev = "medium"
        by_severity[sev]["total"] += 1

        if status in ("resolved", "closed", "completed"):
            by_severity[sev]["compliant"] += 1
            compliant += 1
            continue

        # Check if breached based on creation time vs SLA target
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

    # Get real data if available
    tasks: List[Dict[str, Any]] = []
    try:
        db = _get_remediation_db()
        if db:
            raw = db.list_tasks(limit=500) if hasattr(db, "list_tasks") else []
            tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass

    # Calculate MTTR from resolved tasks
    resolved_times: List[float] = []
    for task in tasks:
        status = (task.get("status") or "").lower()
        if status in ("resolved", "closed", "completed"):
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

    # Team breakdown
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
    """List current SLA breaches."""
    now = datetime.now(timezone.utc)
    targets = _compute_sla_targets()
    tasks: List[Dict[str, Any]] = []
    try:
        db = _get_remediation_db()
        if db:
            raw = db.list_tasks(limit=500) if hasattr(db, "list_tasks") else []
            tasks = raw if isinstance(raw, list) else (raw.get("tasks", []) if isinstance(raw, dict) else [])
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass

    breaches = []
    for task in tasks:
        status = (task.get("status") or "").lower()
        if status in ("resolved", "closed", "completed"):
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
    return {"status": "healthy", "engine": "sla", "version": "1.0.0"}


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


__all__ = ["router"]
