"""Health check and readiness endpoints for Kubernetes and monitoring."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Request, Response, status

router = APIRouter(prefix="/api/v1", tags=["health"])

VERSION = os.getenv("FIXOPS_VERSION", "0.1.0")
BUILD_DATE = os.getenv("FIXOPS_BUILD_DATE", "unknown")
GIT_COMMIT = os.getenv("FIXOPS_GIT_COMMIT", "unknown")


@router.get("/health", status_code=status.HTTP_200_OK)
def health_check() -> Dict[str, Any]:
    """
    Liveness probe endpoint for Kubernetes.

    Returns 200 OK if the service is alive and can handle requests.
    This endpoint should be lightweight and always return quickly.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "service": "fixops-api",
        "version": VERSION,
    }


@router.get("/ready", status_code=status.HTTP_200_OK)
def readiness_check(request: Request, response: Response) -> Dict[str, Any]:
    """
    Readiness probe endpoint for Kubernetes.

    Returns 200 OK if the service is ready to accept traffic.
    Checks critical dependencies and returns 503 if any are unavailable.
    """
    checks: Dict[str, Dict[str, Any]] = {}
    overall_ready = True

    try:
        app_state = getattr(request.app, "state", None)
        if app_state is None:
            checks["app_state"] = {
                "status": "unhealthy",
                "message": "App state not initialized",
            }
            overall_ready = False
        else:
            checks["app_state"] = {"status": "healthy"}
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        checks["app_state"] = {"status": "unhealthy", "error": type(exc).__name__}
        overall_ready = False

    try:
        overlay = getattr(request.app.state, "overlay", None)
        if overlay is None:
            checks["overlay"] = {"status": "unhealthy", "message": "Overlay not loaded"}
            overall_ready = False
        else:
            checks["overlay"] = {
                "status": "healthy",
                "mode": overlay.mode,
            }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        checks["overlay"] = {"status": "unhealthy", "error": type(exc).__name__}
        overall_ready = False

    try:
        engine = getattr(request.app.state, "enhanced_engine", None)
        if engine is None:
            checks["enhanced_engine"] = {
                "status": "degraded",
                "message": "Engine not initialized",
            }
        else:
            checks["enhanced_engine"] = {"status": "healthy"}
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        checks["enhanced_engine"] = {"status": "degraded", "error": type(exc).__name__}

    try:
        archive = getattr(request.app.state, "archive", None)
        if archive is None:
            checks["storage"] = {
                "status": "unhealthy",
                "message": "Archive not initialized",
            }
            overall_ready = False
        else:
            checks["storage"] = {
                "status": "healthy",
                "base_directory": str(archive.base_directory),
            }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        checks["storage"] = {"status": "unhealthy", "error": type(exc).__name__}
        overall_ready = False

    if not overall_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if overall_ready else "not_ready",
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "service": "fixops-api",
        "version": VERSION,
        "checks": checks,
    }


@router.get("/version", status_code=status.HTTP_200_OK)
def version_info() -> Dict[str, Any]:
    """
    Return version and build information.

    Useful for debugging and deployment verification.
    """
    return {
        "service": "fixops-api",
        "version": VERSION,
        "build_date": BUILD_DATE,
        "git_commit": GIT_COMMIT,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "environment": os.getenv("FIXOPS_MODE", "unknown"),
    }


@router.get("/metrics", status_code=status.HTTP_200_OK)
def metrics_endpoint(request: Request) -> Dict[str, Any]:
    """
    Return basic metrics in JSON format.

    For Prometheus metrics, use the /metrics endpoint exposed by OpenTelemetry.
    This endpoint provides application-level metrics in JSON format.
    """
    metrics: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "service": "fixops-api",
        "version": VERSION,
    }

    try:
        artifacts = getattr(request.app.state, "artifacts", {})
        metrics["artifacts_count"] = len(artifacts)
        metrics["artifact_stages"] = list(artifacts.keys())
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass

    try:
        archive_records = getattr(request.app.state, "archive_records", {})
        metrics["archive_records_count"] = len(archive_records)
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass

    return metrics


@router.get("/health/deep", status_code=status.HTTP_200_OK)
def deep_health_check(response: Response) -> Dict[str, Any]:
    """
    Deep health check — verifies each subsystem individually.

    Checks:
      - database:        SQLite SELECT 1 on the primary audit DB
      - scanners:        importability of all 8 scanner engine modules
      - brain_pipeline:  importability of core.brain_pipeline.BrainPipeline
      - disk_space:      evidence storage directory free space (warn <1 GB)
      - memory:          process RSS via /proc/self/status or psutil

    Returns HTTP 200 when all critical checks pass, 503 when any critical
    check fails.  Scanner/memory checks are non-critical (degraded).

    No auth required — same as the liveness probe.  Do NOT put secrets in
    this response.
    """
    checks: Dict[str, Dict[str, Any]] = {}
    overall_healthy = True

    # ------------------------------------------------------------------
    # 1. Database — SQLite SELECT 1
    # ------------------------------------------------------------------
    _db_path = os.path.join(
        os.getenv("FIXOPS_DATA_DIR", ".fixops_data"), "audit.db"
    )
    try:
        conn = sqlite3.connect(_db_path, timeout=3)
        conn.execute("SELECT 1")
        conn.close()
        checks["database"] = {
            "status": "healthy",
            "backend": "sqlite",
            "path": _db_path,
        }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        # If the file doesn't exist yet that's OK — write a temp DB to verify
        # SQLite itself is functional on this host.
        try:
            with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as tmp:
                tmp_conn = sqlite3.connect(tmp.name, timeout=3)
                tmp_conn.execute("SELECT 1")
                tmp_conn.close()
            checks["database"] = {
                "status": "healthy",
                "backend": "sqlite",
                "note": "primary db not yet created — sqlite operational",
            }
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as inner:
            checks["database"] = {
                "status": "unhealthy",
                "error": type(inner).__name__,
                "message": str(inner)[:200],
            }
            overall_healthy = False

    # ------------------------------------------------------------------
    # 2. Scanner engine availability — import checks (non-critical)
    # ------------------------------------------------------------------
    _SCANNER_MODULES = {
        "sast": "core.sast_engine",
        "dast": "core.dast_engine",
        "secrets": "core.secrets_engine",
        "container": "core.container_engine",
        "cspm": "core.cspm_engine",
        "iac": "core.iac_engine",
        "malware": "core.malware_engine",
        "api_fuzzer": "core.api_fuzzer_engine",
    }
    scanner_results: Dict[str, str] = {}
    for scanner_name, module_path in _SCANNER_MODULES.items():
        spec = importlib.util.find_spec(module_path)
        scanner_results[scanner_name] = "available" if spec is not None else "not_found"

    available_count = sum(1 for v in scanner_results.values() if v == "available")
    checks["scanners"] = {
        "status": "healthy" if available_count == 8 else "degraded",
        "available": available_count,
        "total": 8,
        "engines": scanner_results,
        "note": "degraded scanners reduce coverage but do not block API startup",
    }

    # ------------------------------------------------------------------
    # 3. Brain Pipeline importability (non-critical — degrades gracefully)
    # ------------------------------------------------------------------
    try:
        spec = importlib.util.find_spec("core.brain_pipeline")
        if spec is not None:
            checks["brain_pipeline"] = {"status": "available"}
        else:
            checks["brain_pipeline"] = {
                "status": "degraded",
                "message": "core.brain_pipeline module not found on sys.path",
            }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        checks["brain_pipeline"] = {
            "status": "degraded",
            "error": type(exc).__name__,
        }

    # ------------------------------------------------------------------
    # 4. Disk space — evidence storage directory
    # ------------------------------------------------------------------
    _evidence_dir = os.path.join(
        os.getenv("FIXOPS_DATA_DIR", ".fixops_data"), "evidence"
    )
    _check_dir = _evidence_dir if os.path.isdir(_evidence_dir) else os.getcwd()
    try:
        st = os.statvfs(_check_dir)
        free_bytes = st.f_frsize * st.f_bavail
        total_bytes = st.f_frsize * st.f_blocks
        free_gb = free_bytes / (1024 ** 3)
        total_gb = total_bytes / (1024 ** 3)
        disk_status = "healthy"
        disk_note = None
        if free_gb < 1.0:
            disk_status = "degraded"
            disk_note = f"Low disk space: {free_gb:.2f} GB free (warn threshold 1 GB)"
        checks["disk_space"] = {
            "status": disk_status,
            "free_gb": round(free_gb, 2),
            "total_gb": round(total_gb, 2),
            "path": _check_dir,
        }
        if disk_note:
            checks["disk_space"]["note"] = disk_note
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        checks["disk_space"] = {
            "status": "unknown",
            "error": type(exc).__name__,
            "message": str(exc)[:200],
        }

    # ------------------------------------------------------------------
    # 5. Memory usage — prefer psutil, fall back to /proc/self/status
    # ------------------------------------------------------------------
    rss_mb: float = 0.0
    mem_source = "unavailable"
    try:
        import psutil  # type: ignore[import]
        proc = psutil.Process()
        rss_mb = proc.memory_info().rss / (1024 * 1024)
        mem_source = "psutil"
    except ImportError:
        # Fall back to /proc/self/status (Linux only)
        proc_status = Path("/proc/self/status")
        if proc_status.exists():
            try:
                for line in proc_status.read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        rss_kb = int(line.split()[1])
                        rss_mb = rss_kb / 1024
                        mem_source = "/proc/self/status"
                        break
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                pass
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass

    if rss_mb > 0:
        checks["memory"] = {
            "status": "healthy",
            "rss_mb": round(rss_mb, 1),
            "source": mem_source,
        }
    else:
        checks["memory"] = {
            "status": "unknown",
            "message": "Could not determine memory usage (psutil not installed, /proc not available)",
            "source": mem_source,
        }

    # ------------------------------------------------------------------
    # Response
    # ------------------------------------------------------------------
    if not overall_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if overall_healthy else "unhealthy",
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "service": "fixops-api",
        "version": VERSION,
        "checks": checks,
        "duration_ms": None,  # populated at call site if needed
    }


@router.get("/health/database", status_code=status.HTTP_200_OK)
async def database_health_check(response: Response) -> Dict[str, Any]:
    """
    Enterprise database health check.

    Reports connectivity and pool/file stats for the configured backend:
      - PostgreSQL (production): SELECT 1 + pool stats (size, checked_in/out)
      - SQLite (local dev / air-gap): SELECT 1 + file size + journal_mode

    Returns HTTP 200 when healthy, HTTP 503 when the database is unreachable.
    Non-critical: a degraded database does NOT fail the liveness probe.

    No auth required (same as other health probes).
    """
    try:
        from core.brain_pipeline_db import check_database_health  # noqa: PLC0415
        result = await check_database_health()
    except ImportError as exc:
        result = {
            "status": "unhealthy",
            "error": f"{type(exc).__name__}: database health check failed",
        }

    if result.get("status") != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "service": "fixops-api",
        "version": VERSION,
        "database": result,
    }


__all__ = ["router"]
