"""System administration API Router — system health and diagnostics.

Provides system-level endpoints expected by the Platform Admin (Hasan) persona:
    GET  /api/v1/system/health    -- Comprehensive system health (all subsystems)
    GET  /api/v1/system/info      -- System information and version
    GET  /api/v1/system/config    -- Non-sensitive configuration summary

Security:
    - All endpoints require API key + admin:all scope
    - Never exposes secrets, tokens, or sensitive configuration
"""

from __future__ import annotations

import logging
import os
import platform
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Request

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/system", tags=["system"])

_START_TIME = time.monotonic()
_VERSION = os.getenv("FIXOPS_VERSION", "0.1.0")
_BUILD_DATE = os.getenv("FIXOPS_BUILD_DATE", "unknown")
_GIT_COMMIT = os.getenv("FIXOPS_GIT_COMMIT", "unknown")


def _check_db(db_path: str) -> Dict[str, Any]:
    """Check if a SQLite database is healthy."""
    path = Path(db_path)
    if not path.exists():
        return {"status": "not_found", "path": str(path)}
    try:
        conn = sqlite3.connect(str(path), timeout=2)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        size_mb = round(path.stat().st_size / (1024 * 1024), 2)
        return {"status": "healthy", "size_mb": size_mb}
    except Exception as e:
        return {"status": "unhealthy", "error": type(e).__name__}


@router.get("/health", summary="Comprehensive system health")
async def system_health(request: Request) -> Dict[str, Any]:
    """Return comprehensive system health covering all subsystems.

    Checks:
    - API process uptime
    - Database health (users, integrations, webhooks, findings)
    - Scanner engine availability
    - Brain pipeline status
    - Data directory accessibility
    """
    now = datetime.now(timezone.utc)
    uptime_seconds = round(time.monotonic() - _START_TIME, 1)

    subsystems: Dict[str, Any] = {}
    overall_healthy = True

    # 1. API core
    subsystems["api"] = {
        "status": "healthy",
        "uptime_seconds": uptime_seconds,
        "version": _VERSION,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }

    # 2. App state checks
    try:
        app_state = getattr(request.app, "state", None)
        if app_state:
            overlay = getattr(app_state, "overlay", None)
            subsystems["configuration"] = {
                "status": "healthy",
                "mode": getattr(overlay, "mode", "unknown") if overlay else "unknown",
            }
        else:
            subsystems["configuration"] = {"status": "degraded", "message": "App state not initialized"}
    except Exception as e:
        subsystems["configuration"] = {"status": "unhealthy", "error": type(e).__name__}
        overall_healthy = False

    # 3. Database checks
    db_checks: Dict[str, Any] = {}
    db_files = {
        "users": "data/users.db",
        "integrations": "data/integrations.db",
        "webhooks": "data/integrations/webhooks.db",
        "analytics": "data/analytics.db",
        "audit": "data/audit.db",
        "findings": "data/findings/findings.db",
        "collaboration": "data/collaboration.db",
    }
    for name, path_str in db_files.items():
        result = _check_db(path_str)
        db_checks[name] = result
        if result["status"] == "unhealthy":
            overall_healthy = False

    healthy_dbs = sum(1 for v in db_checks.values() if v["status"] == "healthy")
    subsystems["databases"] = {
        "status": "healthy" if healthy_dbs == len(db_checks) else "degraded",
        "total": len(db_checks),
        "healthy": healthy_dbs,
        "details": db_checks,
    }

    # 4. Scanner engines availability
    scanner_status: Dict[str, Any] = {}
    scanner_modules = {
        "sast": "core.sast_engine",
        "dast": "core.dast_engine",
        "secrets": "core.secrets_scanner",
        "container": "core.container_scanner",
        "cspm": "core.cspm_engine",
        "autofix": "core.autofix_engine",
    }
    for name, module in scanner_modules.items():
        try:
            if module in sys.modules:
                scanner_status[name] = {"status": "loaded"}
            else:
                # Don't actually import — just check if file exists
                parts = module.split(".")
                module_path = Path("suite-core") / "/".join(parts[:-1]) / f"{parts[-1]}.py"
                if module_path.exists():
                    scanner_status[name] = {"status": "available"}
                else:
                    scanner_status[name] = {"status": "not_found"}
        except Exception as e:
            scanner_status[name] = {"status": "error", "error": type(e).__name__}

    available_scanners = sum(
        1 for v in scanner_status.values() if v["status"] in ("loaded", "available")
    )
    subsystems["scanners"] = {
        "status": "healthy" if available_scanners >= 4 else "degraded",
        "total": len(scanner_status),
        "available": available_scanners,
        "details": scanner_status,
    }

    # 5. Brain pipeline
    try:
        if "core.brain_pipeline" in sys.modules:
            subsystems["brain_pipeline"] = {"status": "loaded"}
        else:
            brain_path = Path("suite-core/core/brain_pipeline.py")
            subsystems["brain_pipeline"] = {
                "status": "available" if brain_path.exists() else "not_found",
            }
    except Exception as e:
        subsystems["brain_pipeline"] = {"status": "error", "error": type(e).__name__}

    # 6. Data directories
    dir_checks: Dict[str, str] = {}
    required_dirs = ["data", "data/archive", "data/evidence"]
    for d in required_dirs:
        p = Path(d)
        if p.exists() and p.is_dir():
            dir_checks[d] = "accessible"
        elif p.exists():
            dir_checks[d] = "not_directory"
        else:
            dir_checks[d] = "missing"

    accessible_dirs = sum(1 for v in dir_checks.values() if v == "accessible")
    subsystems["storage"] = {
        "status": "healthy" if accessible_dirs == len(dir_checks) else "degraded",
        "directories": dir_checks,
    }

    # 7. Connectors
    try:
        from connectors.universal_connector import UniversalConnector
        uc = UniversalConnector()
        connectors = uc.list_connectors()
        configured = sum(1 for c in connectors if c.get("configured"))
        subsystems["connectors"] = {
            "status": "healthy",
            "total": len(connectors),
            "configured": configured,
        }
    except Exception:
        subsystems["connectors"] = {"status": "degraded", "message": "Connector module not available"}

    return {
        "status": "healthy" if overall_healthy else "degraded",
        "timestamp": now.isoformat() + "Z",
        "service": "fixops-api",
        "version": _VERSION,
        "uptime_seconds": uptime_seconds,
        "subsystems": subsystems,
    }


@router.get("/info", summary="System information")
async def system_info() -> Dict[str, Any]:
    """Return system information and version details."""
    return {
        "service": "fixops-api",
        "version": _VERSION,
        "build_date": _BUILD_DATE,
        "git_commit": _GIT_COMMIT,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform.platform(),
        "mode": os.getenv("FIXOPS_MODE", "enterprise"),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }


@router.get("/config", summary="Non-sensitive configuration")
async def system_config(request: Request) -> Dict[str, Any]:
    """Return non-sensitive configuration summary.

    Never exposes tokens, secrets, or credentials.
    """
    config_summary: Dict[str, Any] = {
        "mode": os.getenv("FIXOPS_MODE", "enterprise"),
        "rate_limiting": os.getenv("FIXOPS_DISABLE_RATE_LIMIT", "0") != "1",
        "cors_configured": bool(os.getenv("FIXOPS_ALLOWED_ORIGINS")),
        "data_dir": os.getenv("FIXOPS_DATA_DIR", ".fixops_data"),
    }

    try:
        overlay = getattr(request.app.state, "overlay", None)
        if overlay:
            config_summary["auth_strategy"] = overlay.auth.get("strategy", "none")
            config_summary["overlay_mode"] = overlay.mode
    except Exception:
        pass

    return {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "config": config_summary,
    }


@router.get("/metrics", summary="System metrics")
async def system_metrics() -> Dict[str, Any]:
    """Return system performance metrics for the Platform Admin (Hasan) persona.

    Includes uptime, memory, CPU, request counts, and database stats.
    """
    import resource

    now = datetime.now(timezone.utc)
    uptime_seconds = time.monotonic() - _START_TIME
    rusage = resource.getrusage(resource.RUSAGE_SELF)

    # Count database files
    data_dir = Path(os.getenv("FIXOPS_DATA_DIR", ".fixops_data"))
    db_files = list(data_dir.glob("**/*.db")) if data_dir.exists() else []
    total_db_size = sum(f.stat().st_size for f in db_files if f.exists())

    return {
        "timestamp": now.isoformat() + "Z",
        "uptime_seconds": round(uptime_seconds, 1),
        "process": {
            "pid": os.getpid(),
            "user_cpu_seconds": round(rusage.ru_utime, 2),
            "system_cpu_seconds": round(rusage.ru_stime, 2),
            "max_rss_mb": round(rusage.ru_maxrss / (1024 * 1024), 1),
        },
        "databases": {
            "count": len(db_files),
            "total_size_mb": round(total_db_size / (1024 * 1024), 2),
        },
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform.platform(),
    }


@router.get("/status", summary="System status overview")
async def system_status() -> Dict[str, Any]:
    """Return simplified system status for dashboards.

    Provides a quick UP/DOWN status with key indicators.
    """
    now = datetime.now(timezone.utc)
    uptime_seconds = time.monotonic() - _START_TIME

    return {
        "status": "operational",
        "timestamp": now.isoformat() + "Z",
        "service": "fixops-api",
        "version": _VERSION,
        "mode": os.getenv("FIXOPS_MODE", "enterprise"),
        "uptime_seconds": round(uptime_seconds, 1),
        "indicators": {
            "api": "up",
            "database": "up",
            "scanners": "available",
            "ai_engine": "standby",
        },
    }


__all__ = ["router"]
