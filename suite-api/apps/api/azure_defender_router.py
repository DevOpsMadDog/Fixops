"""
ALdeci Azure Defender / Microsoft Defender for Cloud API Router.

Exposes Azure Defender integration via ALdeci REST endpoints.
Falls back to mock data when Azure credentials are not configured.

Endpoints:
  GET  /api/v1/scan/azure-defender/status          — check Azure configuration
  GET  /api/v1/scan/azure-defender/alerts          — pull security alerts
  GET  /api/v1/scan/azure-defender/secure-score    — get Azure Secure Score
  GET  /api/v1/scan/azure-defender/recommendations — get security recommendations
  POST /api/v1/scan/azure-defender/import          — pull → normalize → store findings
  GET  /api/v1/scan/azure-defender/history         — list import history for an org

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
    prefix="/api/v1/scan/azure-defender",
    tags=["azure-defender"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton client
# ---------------------------------------------------------------------------

_client = None


def _get_client():
    global _client
    if _client is None:
        from core.azure_defender import AzureDefenderClient
        _client = AzureDefenderClient()
    return _client


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ImportRequest(BaseModel):
    """Request body for importing Azure Defender findings for an org."""

    org_id: str = Field("default", description="Organisation identifier")


class AzureStatusResponse(BaseModel):
    configured: bool
    subscription_id: str
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
    response_model=AzureStatusResponse,
    summary="Check Azure Defender configuration",
)
def azure_defender_status():
    """
    Return whether Azure credentials are configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real Azure credentials.
    """
    client = _get_client()
    configured = client.is_configured()
    sub_id = client._subscription_id or "not-set"
    return {
        "configured": configured,
        "subscription_id": sub_id,
        "message": (
            f"Azure credentials configured — real Defender data active "
            f"(subscription: {sub_id})"
            if configured
            else "Azure credentials not set — mock data mode. "
            "Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, "
            "AZURE_CLIENT_SECRET environment variables."
        ),
    }


@router.get(
    "/alerts",
    response_model=List[Dict[str, Any]],
    summary="Pull security alerts from Microsoft Defender for Cloud",
)
def get_alerts(
    severity: Optional[str] = Query(
        None,
        description="Filter by severity: Critical, High, Medium, Low",
    ),
):
    """
    Pull security alerts from Microsoft Defender for Cloud.

    Supports optional filtering by severity.
    Returns mock data when Azure credentials are not configured.
    """
    client = _get_client()
    try:
        return client.get_alerts(severity_filter=severity)
    except Exception as exc:
        logger.error("get_alerts failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/secure-score",
    response_model=Dict[str, Any],
    summary="Get Azure Secure Score",
)
def get_secure_score():
    """
    Retrieve the Azure Secure Score for the configured subscription.

    Returns mock data when Azure credentials are not configured.
    """
    client = _get_client()
    try:
        return client.get_secure_score()
    except Exception as exc:
        logger.error("get_secure_score failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/recommendations",
    response_model=List[Dict[str, Any]],
    summary="Get security recommendations from Microsoft Defender for Cloud",
)
def get_recommendations(
    category: Optional[str] = Query(
        None,
        description="Filter by category: IdentityAndAccess, Compute, Data, Networking",
    ),
):
    """
    Retrieve security recommendations from Microsoft Defender for Cloud.

    Supports optional filtering by category.
    Returns mock data when Azure credentials are not configured.
    """
    client = _get_client()
    try:
        return client.get_recommendations(category=category)
    except Exception as exc:
        logger.error("get_recommendations failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/import",
    response_model=ImportResponse,
    summary="Import Azure Defender findings into ALDECI",
)
def import_findings(body: ImportRequest):
    """
    Pull alerts from Microsoft Defender for Cloud, normalize to UnifiedFinding
    format, store in history, and ingest into the Brain Pipeline.

    Returns mock data when Azure credentials are not configured.
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
    summary="List Azure Defender import history",
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
