"""
ALdeci Snyk Scanner API Router.

Exposes Snyk REST API integration via ALdeci REST endpoints.
Falls back to mock data when SNYK_API_TOKEN is not configured.

Endpoints:
  GET  /api/v1/scan/snyk/status            — check Snyk configuration
  GET  /api/v1/scan/snyk/projects          — list all Snyk projects
  GET  /api/v1/scan/snyk/issues            — get issues for a project
  POST /api/v1/scan/snyk/test-package      — test a single package
  POST /api/v1/scan/snyk/import            — import all org issues
  GET  /api/v1/scan/snyk/history           — list import history for an org

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/scan/snyk",
    tags=["snyk-scanner"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton client
# ---------------------------------------------------------------------------

_client = None


def _get_client():
    global _client
    if _client is None:
        from core.snyk_integration import SnykClient
        _client = SnykClient()
    return _client


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class TestPackageRequest(BaseModel):
    """Request body for testing a single package."""

    ecosystem: str = Field(..., description="Package ecosystem (npm, pip, maven, etc.)")
    package: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    org_id: str = Field("default", description="Organisation identifier")


class ImportRequest(BaseModel):
    """Request body for importing all Snyk issues for an org."""

    org_id: str = Field("default", description="Organisation identifier")


class SnykStatusResponse(BaseModel):
    configured: bool
    message: str
    org_id: Optional[str] = None


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ImportResponse(BaseModel):
    import_id: str
    org_id: str
    started_at: str
    completed_at: str
    status: str
    is_mock: bool
    findings_count: int
    severity_breakdown: Dict[str, int]
    findings: List[Dict[str, Any]]
    error: Optional[str] = None


class ImportSummaryResponse(BaseModel):
    """Import history entry (findings omitted for brevity)."""

    import_id: str
    org_id: str
    started_at: str
    completed_at: str
    status: str
    is_mock: bool
    findings_count: int
    severity_breakdown: Dict[str, int]
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=SnykStatusResponse,
    summary="Check Snyk API configuration",
)
def snyk_status():
    """
    Return whether the Snyk API token is configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real credentials.
    """
    client = _get_client()
    configured = client.is_configured()
    import os
    org_id = os.environ.get("SNYK_ORG_ID", "") or client._org_id or None
    return {
        "configured": configured,
        "org_id": org_id if configured else None,
        "message": (
            "Snyk API token configured — real data active"
            if configured
            else "SNYK_API_TOKEN not set — mock data mode. "
            "Set SNYK_API_TOKEN and SNYK_ORG_ID environment variables."
        ),
    }


@router.get(
    "/projects",
    response_model=List[Dict[str, Any]],
    summary="List Snyk projects",
)
def list_projects():
    """
    List all projects monitored by Snyk for the configured org.

    Returns mock project data when SNYK_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        return client.list_projects()
    except Exception as exc:
        logger.error("list_projects failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/issues",
    response_model=List[Dict[str, Any]],
    summary="Get issues for a Snyk project",
)
def get_project_issues(
    project_id: str = Query(..., description="Snyk project UUID"),
):
    """
    Get all open issues for a specific Snyk project.

    Returns mock issue data when SNYK_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        return client.get_project_issues(project_id=project_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("get_project_issues failed for %s: %s", project_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/test-package",
    response_model=Dict[str, Any],
    summary="Test a single package for vulnerabilities",
)
def test_package(body: TestPackageRequest):
    """
    Test a single package version against Snyk's vulnerability database.

    Returns mock data when SNYK_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        return client.test_package(
            ecosystem=body.ecosystem,
            package=body.package,
            version=body.version,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error(
            "test_package failed for %s/%s@%s: %s",
            body.ecosystem, body.package, body.version, exc,
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/import",
    response_model=ImportResponse,
    summary="Import all Snyk issues for an org",
)
def import_results(body: ImportRequest):
    """
    Pull all issues from Snyk for the given org, normalize them via
    SnykNormalizer, and ingest into the Brain Pipeline.

    Returns mock data when SNYK_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        from core.snyk_integration import _import_history
        findings = client.import_results(org_id=body.org_id)
        # Retrieve the stored entry (most recent for this org)
        from core.snyk_integration import _get_lock
        with _get_lock():
            entries = list(_import_history.get(body.org_id or client._org_id or "default", []))
        if entries:
            return entries[-1]
        # Fallback if history lookup fails
        return {
            "import_id": "unknown",
            "org_id": body.org_id,
            "started_at": "",
            "completed_at": "",
            "status": "completed",
            "is_mock": not client.is_configured(),
            "findings_count": len(findings),
            "severity_breakdown": {},
            "findings": findings,
        }
    except Exception as exc:
        logger.error("import_results failed for org=%s: %s", body.org_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/history",
    response_model=List[ImportSummaryResponse],
    summary="List Snyk import history",
)
def import_history(
    org_id: str = Query("default", description="Organisation identifier"),
):
    """
    Return the import history for the given organisation, most recent first.

    Findings are omitted from the summary; re-run an import to get full results.
    """
    client = _get_client()
    try:
        return client.get_import_history(org_id=org_id)
    except Exception as exc:
        logger.error("import_history failed for org=%s: %s", org_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
