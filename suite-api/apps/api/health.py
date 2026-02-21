"""Health check and readiness endpoints for Kubernetes and monitoring."""

from __future__ import annotations

import os
import sys
from datetime import datetime
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
        "timestamp": datetime.utcnow().isoformat() + "Z",
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
    except Exception as exc:
        checks["app_state"] = {"status": "unhealthy", "error": str(exc)}
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
    except Exception as exc:
        checks["overlay"] = {"status": "unhealthy", "error": str(exc)}
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
    except Exception as exc:
        checks["enhanced_engine"] = {"status": "degraded", "error": str(exc)}

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
    except Exception as exc:
        checks["storage"] = {"status": "unhealthy", "error": str(exc)}
        overall_ready = False

    if not overall_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if overall_ready else "not_ready",
        "timestamp": datetime.utcnow().isoformat() + "Z",
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
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "fixops-api",
        "version": VERSION,
    }

    try:
        artifacts = getattr(request.app.state, "artifacts", {})
        metrics["artifacts_count"] = len(artifacts)
        metrics["artifact_stages"] = list(artifacts.keys())
    except Exception:
        pass

    try:
        archive_records = getattr(request.app.state, "archive_records", {})
        metrics["archive_records_count"] = len(archive_records)
    except Exception:
        pass

    return metrics


__all__ = ["router"]
