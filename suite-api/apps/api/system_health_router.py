"""System Health Dashboard API Router.

Endpoints:
    GET /api/v1/system/health          -- Full health report
    GET /api/v1/system/health/{name}   -- Specific subsystem health
    GET /api/v1/system/resources       -- Resource usage
    GET /api/v1/system/health/history  -- Health trend (last N hours)
    GET /api/v1/system/health/degraded -- Degraded subsystems
    GET /api/v1/system/warnings        -- Active warnings

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/system", tags=["system-health"])

# ---------------------------------------------------------------------------
# Lazy monitor singleton
# ---------------------------------------------------------------------------

_monitor: Optional[Any] = None


def _get_monitor() -> Any:
    """Return a module-level SystemHealthMonitor singleton."""
    global _monitor
    if _monitor is None:
        from core.system_health import SystemHealthMonitor
        _monitor = SystemHealthMonitor()
    return _monitor


# ---------------------------------------------------------------------------
# Endpoints — order matters: specific paths before parameterised ones
# ---------------------------------------------------------------------------


@router.get("/health/history", summary="Health history trend")
async def get_health_history(
    hours: int = Query(24, ge=1, le=168, description="Hours of history to return"),
) -> List[Dict[str, Any]]:
    """Return health reports from the last N hours."""
    monitor = _get_monitor()
    reports = monitor.get_health_history(hours=hours)
    return [r.model_dump() for r in reports]


@router.get("/health/degraded", summary="Degraded subsystems")
async def get_degraded_subsystems() -> List[Dict[str, Any]]:
    """Return subsystems that are not HEALTHY from the latest check."""
    monitor = _get_monitor()
    subsystems = monitor.get_degraded_subsystems()
    return [s.model_dump() for s in subsystems]


@router.get("/health/{subsystem}", summary="Specific subsystem health")
async def get_subsystem_health(subsystem: str) -> Dict[str, Any]:
    """Check health of a specific subsystem by name."""
    valid_subsystems = {"pipeline", "database", "connectors", "feeds", "queue", "cache"}
    if subsystem.lower() not in valid_subsystems:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown subsystem '{subsystem}'. Valid: {sorted(valid_subsystems)}",
        )
    monitor = _get_monitor()
    result = monitor.check_subsystem(subsystem)
    return result.model_dump()


@router.get("/health", summary="Full system health report")
async def get_system_health() -> Dict[str, Any]:
    """Return a full system health report aggregating all subsystems."""
    monitor = _get_monitor()
    report = monitor.check_all()
    return report.model_dump()


@router.get("/resources", summary="Resource usage")
async def get_resource_usage() -> Dict[str, Any]:
    """Return current disk, memory, CPU, and database size metrics."""
    monitor = _get_monitor()
    resources = monitor.get_resource_usage()
    return resources.model_dump()


@router.get("/warnings", summary="Active system warnings")
async def get_warnings() -> Dict[str, Any]:
    """Return active warnings (disk >80%, memory >80%, subsystems down, etc.)."""
    monitor = _get_monitor()
    # Run a fresh check to generate current warnings
    report = monitor.check_all()
    return {
        "warnings": report.warnings,
        "count": len(report.warnings),
        "overall_status": report.overall_status,
        "checked_at": report.checked_at,
    }


@router.get("/health/{subsystem}/trend", summary="Subsystem health trend")
async def get_subsystem_trend(
    subsystem: str,
    hours: int = Query(24, ge=1, le=168, description="Hours of history"),
) -> List[Dict[str, Any]]:
    """Return status history for a specific subsystem over time."""
    monitor = _get_monitor()
    trend = monitor.get_health_trend(subsystem=subsystem, hours=hours)
    return trend
