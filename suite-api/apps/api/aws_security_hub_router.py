"""
ALdeci AWS Security Hub API Router.

Exposes AWS Security Hub integration via ALdeci REST endpoints.
Falls back to mock data when AWS credentials are not configured.

Endpoints:
  GET  /api/v1/scan/aws-security-hub/status          — check AWS configuration
  GET  /api/v1/scan/aws-security-hub/findings        — pull raw ASFF findings
  GET  /api/v1/scan/aws-security-hub/insights        — get Security Hub insights
  GET  /api/v1/scan/aws-security-hub/standards       — get compliance standards status
  POST /api/v1/scan/aws-security-hub/import          — pull → normalize → store findings
  GET  /api/v1/scan/aws-security-hub/history         — list import history for an org

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
    prefix="/api/v1/scan/aws-security-hub",
    tags=["aws-security-hub"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton client
# ---------------------------------------------------------------------------

_client = None


def _get_client():
    global _client
    if _client is None:
        from core.aws_security_hub import AWSSecurityHubClient
        _client = AWSSecurityHubClient()
    return _client


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ImportRequest(BaseModel):
    """Request body for importing Security Hub findings for an org."""

    org_id: str = Field("default", description="Organisation identifier")


class AWSStatusResponse(BaseModel):
    configured: bool
    region: str
    message: str


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
    response_model=AWSStatusResponse,
    summary="Check AWS Security Hub configuration",
)
def aws_security_hub_status():
    """
    Return whether AWS credentials are configured.

    When unconfigured all endpoints return EMPTY data (never mock).
    Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or use the boto3 default
    credential chain (profile, IAM role) for real Security Hub data.
    """
    client = _get_client()
    configured = client.is_configured()
    return {
        "configured": configured,
        "region": client._region,
        "message": (
            f"AWS credentials configured — real Security Hub data active (region: {client._region})"
            if configured
            else "AWS credentials not set — endpoints return empty results. "
            "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
        ),
    }


@router.get(
    "/findings",
    response_model=List[Dict[str, Any]],
    summary="Pull raw ASFF findings from Security Hub",
)
def get_findings(
    severity: Optional[str] = Query(
        None,
        description="Filter by severity label: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL",
    ),
    workflow_status: Optional[str] = Query(
        None,
        description="Filter by workflow status: NEW, NOTIFIED, RESOLVED, SUPPRESSED",
    ),
):
    """
    Pull raw AWS Security Finding Format (ASFF) findings from Security Hub.

    Supports optional filtering by severity and workflow status.
    Returns mock data when AWS credentials are not configured.
    """
    client = _get_client()
    filters: Dict[str, Any] = {}
    if severity:
        filters["SeverityLabel"] = [{"Value": severity.upper(), "Comparison": "EQUALS"}]
    if workflow_status:
        filters["WorkflowStatus"] = [{"Value": workflow_status.upper(), "Comparison": "EQUALS"}]
    try:
        return client.get_findings(filters=filters or None)
    except Exception as exc:
        logger.error("get_findings failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/insights",
    response_model=List[Dict[str, Any]],
    summary="Get Security Hub insights",
)
def get_insights():
    """
    Retrieve Security Hub insights.

    Returns mock data when AWS credentials are not configured.
    """
    client = _get_client()
    try:
        return client.get_insights()
    except Exception as exc:
        logger.error("get_insights failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/standards",
    response_model=Dict[str, Any],
    summary="Get enabled compliance standards status",
)
def get_standards_status():
    """
    Retrieve enabled compliance standards (CIS, PCI DSS, AWS FSBP) and their
    pass/fail control counts.

    Returns mock data when AWS credentials are not configured.
    """
    client = _get_client()
    try:
        return client.get_standards_status()
    except Exception as exc:
        logger.error("get_standards_status failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/import",
    response_model=ImportResponse,
    summary="Import Security Hub findings into ALDECI",
)
def import_findings(body: ImportRequest):
    """
    Pull findings from AWS Security Hub, normalize from ASFF to UnifiedFinding
    format, store in history, and ingest into the Brain Pipeline.

    Returns mock data when AWS credentials are not configured.
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
    summary="List Security Hub import history",
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
