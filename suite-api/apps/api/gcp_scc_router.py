"""
ALdeci GCP Security Command Center API Router.

Exposes GCP SCC integration via ALdeci REST endpoints.
Falls back to mock data when GCP credentials are not configured.

Endpoints:
  GET  /api/v1/scan/gcp-scc/status          — check GCP configuration
  GET  /api/v1/scan/gcp-scc/findings        — pull raw SCC findings
  GET  /api/v1/scan/gcp-scc/sources         — get SCC sources
  GET  /api/v1/scan/gcp-scc/assets          — get SCC assets
  POST /api/v1/scan/gcp-scc/import          — pull → normalize → store findings
  GET  /api/v1/scan/gcp-scc/history         — list import history for an org

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
    prefix="/api/v1/scan/gcp-scc",
    tags=["gcp-scc"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton client
# ---------------------------------------------------------------------------

_client = None


def _get_client():
    global _client
    if _client is None:
        from core.gcp_scc import GCPSecurityClient
        _client = GCPSecurityClient()
    return _client


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ImportRequest(BaseModel):
    """Request body for importing SCC findings for an org."""

    org_id: str = Field("default", description="Organisation identifier")


class GCPStatusResponse(BaseModel):
    configured: bool
    project_id: str
    organization_id: str
    message: str


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ImportResponse(BaseModel):
    import_id: str
    org_id: str = Query(default="default")
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
    org_id: str = Query(default="default")
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
    response_model=GCPStatusResponse,
    summary="Check GCP Security Command Center configuration",
)
def gcp_scc_status():
    """
    Return whether GCP credentials are configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real GCP credentials.
    """
    client = _get_client()
    configured = client.is_configured()
    return {
        "configured": configured,
        "project_id": client._project_id,
        "organization_id": client._organization_id,
        "message": (
            f"GCP credentials configured — real SCC data active "
            f"(project: {client._project_id}, org: {client._organization_id})"
            if configured
            else "GCP credentials not set — mock data mode. "
            "Set GCP_PROJECT_ID and GOOGLE_APPLICATION_CREDENTIALS environment variables."
        ),
    }


@router.get(
    "/findings",
    response_model=List[Dict[str, Any]],
    summary="Pull raw findings from GCP Security Command Center",
)
def get_findings(
    severity: Optional[str] = Query(
        None,
        description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL",
    ),
    state: Optional[str] = Query(
        None,
        description="Filter by state: ACTIVE, INACTIVE",
    ),
    source_id: str = Query(
        "-",
        description="SCC source ID to list findings from. Defaults to '-' (all sources).",
    ),
):
    """
    Pull raw GCP SCC findings.

    Supports optional filtering by severity and state.
    Returns mock data when GCP credentials are not configured.
    """
    client = _get_client()
    filter_parts: List[str] = []
    if severity:
        filter_parts.append(f'severity="{severity.upper()}"')
    if state:
        filter_parts.append(f'state="{state.upper()}"')
    scc_filter = " AND ".join(filter_parts) if filter_parts else None

    try:
        return client.get_findings(filters=scc_filter, source_id=source_id)
    except Exception as exc:
        logger.error("get_findings failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/sources",
    response_model=List[Dict[str, Any]],
    summary="Get GCP SCC sources",
)
def get_sources():
    """
    Retrieve GCP Security Command Center sources (Security Health Analytics,
    Event Threat Detection, Container Threat Detection, etc.).

    Returns mock data when GCP credentials are not configured.
    """
    client = _get_client()
    try:
        return client.get_sources()
    except Exception as exc:
        logger.error("get_sources failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/assets",
    response_model=List[Dict[str, Any]],
    summary="Get GCP SCC assets",
)
def get_assets():
    """
    Retrieve assets tracked by GCP Security Command Center.

    Returns mock data when GCP credentials are not configured.
    """
    client = _get_client()
    try:
        return client.get_assets()
    except Exception as exc:
        logger.error("get_assets failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/import",
    response_model=ImportResponse,
    summary="Import GCP SCC findings into ALDECI",
)
def import_findings(body: ImportRequest):
    """
    Pull findings from GCP Security Command Center, normalize to UnifiedFinding
    format, store in history, and ingest into the Brain Pipeline.

    Returns mock data when GCP credentials are not configured.
    """
    client = _get_client()
    try:
        return client.import_findings(org_id=body.org_id)
    except Exception as exc:
        logger.error(
            "import_findings failed for org=%s: %s", body.org_id, exc, exc_info=True
        )
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/history",
    response_model=List[ImportSummaryResponse],
    summary="List GCP SCC import history",
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
