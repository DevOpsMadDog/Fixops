"""
ALdeci Trivy Scanner API Router.

Exposes real Trivy scanning (Docker images, filesystems, git repos) via REST.
Falls back to mock data when the trivy binary is not installed.

Endpoints:
  POST /api/v1/scan/trivy/image       — scan a Docker image
  POST /api/v1/scan/trivy/filesystem  — scan a filesystem path
  POST /api/v1/scan/trivy/repo        — scan a git repository
  GET  /api/v1/scan/trivy/status      — check trivy availability
  GET  /api/v1/scan/trivy/history     — list scan history for an org

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/scan/trivy",
    tags=["trivy-scanner"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton scanner
# ---------------------------------------------------------------------------

_scanner = None


def _get_scanner():
    global _scanner
    if _scanner is None:
        from core.trivy_integration import TrivyScanner
        _scanner = TrivyScanner()
    return _scanner


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScanImageRequest(BaseModel):
    """Request body for scanning a Docker image."""

    image: str = Field(..., description="Docker image reference, e.g. nginx:latest")
    org_id: str = Field("default", description="Organisation identifier")


class ScanFilesystemRequest(BaseModel):
    """Request body for scanning a filesystem path."""

    path: str = Field(..., description="Absolute or relative path to scan")
    org_id: str = Field("default", description="Organisation identifier")


class ScanRepoRequest(BaseModel):
    """Request body for scanning a git repository."""

    repo_url: str = Field(..., description="Git repository URL")
    org_id: str = Field("default", description="Organisation identifier")


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResponse(BaseModel):
    scan_id: str
    org_id: str
    target: str
    scan_type: str
    started_at: str
    completed_at: str
    status: str
    is_mock: bool
    findings_count: int
    severity_breakdown: Dict[str, int]
    findings: List[Dict[str, Any]]
    error: Optional[str] = None


class ScanSummaryResponse(BaseModel):
    """Scan history entry (findings omitted for brevity)."""

    scan_id: str
    org_id: str
    target: str
    scan_type: str
    started_at: str
    completed_at: str
    status: str
    is_mock: bool
    findings_count: int
    severity_breakdown: Dict[str, int]
    error: Optional[str] = None


class TrivyStatusResponse(BaseModel):
    available: bool
    message: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/image", response_model=ScanResponse, summary="Scan a Docker image")
def scan_image(body: ScanImageRequest):
    """
    Scan a Docker image for OS and library vulnerabilities using Trivy.

    Returns normalized findings ingested into the Brain Pipeline.
    Falls back to mock data when trivy is not installed.
    """
    scanner = _get_scanner()
    try:
        result = scanner.scan_and_ingest(
            image_name=body.image,
            org_id=body.org_id,
            scan_type="image",
        )
    except Exception as exc:
        logger.error("scan_image failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    return result


@router.post(
    "/filesystem", response_model=ScanResponse, summary="Scan a filesystem path"
)
def scan_filesystem(body: ScanFilesystemRequest):
    """
    Scan a local filesystem path for vulnerabilities using Trivy.

    Falls back to mock data when trivy is not installed.
    """
    scanner = _get_scanner()
    try:
        result = scanner.scan_and_ingest(
            image_name=body.path,
            org_id=body.org_id,
            scan_type="filesystem",
        )
    except Exception as exc:
        logger.error("scan_filesystem failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    return result


@router.post("/repo", response_model=ScanResponse, summary="Scan a git repository")
def scan_repo(body: ScanRepoRequest):
    """
    Scan a remote git repository for vulnerabilities using Trivy.

    Falls back to mock data when trivy is not installed.
    """
    scanner = _get_scanner()
    try:
        result = scanner.scan_and_ingest(
            image_name=body.repo_url,
            org_id=body.org_id,
            scan_type="repo",
        )
    except Exception as exc:
        logger.error("scan_repo failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    return result


@router.get(
    "/status", response_model=TrivyStatusResponse, summary="Check trivy availability"
)
def trivy_status():
    """
    Return whether the trivy binary is available on this host.

    When trivy is not installed all scan endpoints return mock data.
    """
    scanner = _get_scanner()
    available = scanner.is_trivy_available()
    return {
        "available": available,
        "message": (
            "trivy binary found — real scans active"
            if available
            else "trivy binary not found — mock data mode. "
            "Install: https://aquasecurity.github.io/trivy/"
        ),
    }


@router.get(
    "/history",
    response_model=List[ScanSummaryResponse],
    summary="List scan history",
)
def scan_history(
    org_id: str = Query("default", description="Organisation identifier"),
):
    """
    Return the scan history for the given organisation, most recent first.

    Findings are omitted from the summary; re-run a scan to get full results.
    """
    scanner = _get_scanner()
    try:
        history = scanner.get_scan_history(org_id=org_id)
    except Exception as exc:
        logger.error("scan_history failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    return history
