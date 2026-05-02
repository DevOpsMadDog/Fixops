"""GET /api/v1/version — returns API version info, build date, and git commit."""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict

from apps.api.api_versioning_middleware import API_VERSION, DEPRECATED_ENDPOINTS
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["version"])


def _git_commit() -> str:
    """Return the current git commit SHA (short), or 'unknown' if unavailable."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return os.getenv("GIT_COMMIT", "unknown")


def _build_date() -> str:
    """Return build date from env var BUILD_DATE, or today's UTC date."""
    return os.getenv("BUILD_DATE", datetime.now(timezone.utc).strftime("%Y-%m-%d"))


@router.get("/version", summary="API version information")
async def get_version() -> Dict[str, Any]:
    """Return API version metadata.

    Response fields:
    - **version**: Semantic version of the ALDECI API (e.g. ``1.0.0``)
    - **build_date**: Date the current build was produced (``YYYY-MM-DD``)
    - **git_commit**: Short git SHA of the deployed revision
    - **deprecated_endpoints**: Count of currently deprecated API paths
    - **timestamp**: UTC timestamp of this response
    """
    return {
        "version": API_VERSION,
        "build_date": _build_date(),
        "git_commit": _git_commit(),
        "deprecated_endpoints": len(DEPRECATED_ENDPOINTS),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }
