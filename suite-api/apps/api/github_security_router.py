"""
ALdeci GitHub Advanced Security API Router.

Exposes GitHub code scanning, Dependabot, and secret scanning alerts via REST.
Falls back to mock data when no GitHub token is configured.

Endpoints:
  GET  /api/v1/security/github/status                     — check configuration
  GET  /api/v1/security/github/alerts/code-scanning       — list code scanning alerts
  GET  /api/v1/security/github/alerts/dependabot          — list Dependabot alerts
  GET  /api/v1/security/github/alerts/secret-scanning     — list secret scanning alerts
  POST /api/v1/security/github/import                     — import all alerts
  GET  /api/v1/security/github/history                    — list import history
  POST /api/v1/security/github/alerts/{alert_type}/{alert_number}/dismiss — dismiss alert
  GET  /api/v1/security/github/alerts/all                 — all normalized findings

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security/github",
    tags=["github-security"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton client
# ---------------------------------------------------------------------------

_client = None


def _get_client():
    global _client
    if _client is None:
        from core.github_security import GitHubSecurityClient
        _client = GitHubSecurityClient()
    return _client


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ImportRequest(BaseModel):
    """Request body for importing all GitHub Advanced Security alerts."""

    org_id: str = Field("default", description="Organisation identifier for multi-tenancy")


class DismissRequest(BaseModel):
    """Request body for dismissing a GitHub alert."""

    reason: str = Field(
        ...,
        description="Dismissal reason, e.g. 'false_positive', 'used_in_tests', 'tolerable_risk'",
    )
    comment: Optional[str] = Field(None, description="Optional human-readable comment")


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ImportResponse(BaseModel):
    import_id: str
    org_id: str
    owner: str
    repo: str
    started_at: str
    completed_at: str
    status: str
    is_mock: bool
    total_findings: int
    counts_by_type: Dict[str, int]
    severity_breakdown: Dict[str, int]
    errors: Dict[str, str]
    findings: List[Dict[str, Any]]


class ImportSummaryResponse(BaseModel):
    """Import history entry — findings omitted."""

    import_id: str
    org_id: str
    owner: str
    repo: str
    started_at: str
    completed_at: str
    status: str
    is_mock: bool
    total_findings: int
    counts_by_type: Dict[str, int]
    severity_breakdown: Dict[str, int]
    errors: Dict[str, str]


class StatusResponse(BaseModel):
    configured: bool
    is_mock: bool
    owner: Optional[str]
    repo: Optional[str]
    message: str


class DismissResponse(BaseModel):
    status: str
    alert_type: str
    alert_number: int
    details: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=StatusResponse,
    summary="Check GitHub Security configuration",
)
def github_status():
    """
    Return whether the GitHub Security client is fully configured.

    When not configured, all alert endpoints return mock sample data.
    """
    client = _get_client()
    configured = client.is_configured()
    return {
        "configured": configured,
        "is_mock": not configured,
        "owner": client.owner,
        "repo": client.repo,
        "message": (
            f"GitHub Security active for {client.owner}/{client.repo}"
            if configured
            else "Not configured — set GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO env vars. "
            "Mock data mode active."
        ),
    }


@router.get(
    "/alerts/code-scanning",
    response_model=List[Dict[str, Any]],
    summary="List code scanning alerts",
)
def list_code_scanning_alerts(
    normalize: bool = Query(True, description="Return normalized ALDECI findings"),
):
    """
    Fetch open code scanning alerts (CodeQL, Semgrep, etc.) for the configured repository.

    Returns mock data when no GitHub token is configured.
    """
    client = _get_client()
    try:
        raw = client.get_code_scanning_alerts()
        if normalize:
            return client.normalize_results(raw, "code_scanning")
        return raw
    except Exception as exc:
        logger.error("list_code_scanning_alerts failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/alerts/dependabot",
    response_model=List[Dict[str, Any]],
    summary="List Dependabot alerts",
)
def list_dependabot_alerts(
    normalize: bool = Query(True, description="Return normalized ALDECI findings"),
):
    """
    Fetch open Dependabot vulnerability alerts for the configured repository.

    Returns mock data when no GitHub token is configured.
    """
    client = _get_client()
    try:
        raw = client.get_dependabot_alerts()
        if normalize:
            return client.normalize_results(raw, "dependabot")
        return raw
    except Exception as exc:
        logger.error("list_dependabot_alerts failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/alerts/secret-scanning",
    response_model=List[Dict[str, Any]],
    summary="List secret scanning alerts",
)
def list_secret_scanning_alerts(
    normalize: bool = Query(True, description="Return normalized ALDECI findings"),
):
    """
    Fetch open secret scanning alerts for the configured repository.

    Returns mock data when no GitHub token is configured.
    """
    client = _get_client()
    try:
        raw = client.get_secret_scanning_alerts()
        if normalize:
            return client.normalize_results(raw, "secret_scanning")
        return raw
    except Exception as exc:
        logger.error("list_secret_scanning_alerts failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/alerts/all",
    response_model=List[Dict[str, Any]],
    summary="List all normalized findings (all alert types combined)",
)
def list_all_alerts():
    """
    Fetch and normalize all alert types (code scanning + Dependabot + secret scanning).

    Returns combined list of normalized ALDECI findings.
    """
    client = _get_client()
    try:
        all_findings: List[Dict[str, Any]] = []
        for alert_type, fetcher in [
            ("code_scanning", client.get_code_scanning_alerts),
            ("dependabot", client.get_dependabot_alerts),
            ("secret_scanning", client.get_secret_scanning_alerts),
        ]:
            raw = fetcher()
            all_findings.extend(client.normalize_results(raw, alert_type))
        return all_findings
    except Exception as exc:
        logger.error("list_all_alerts failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/import",
    response_model=ImportResponse,
    summary="Import all GitHub Advanced Security alerts",
)
def import_all_alerts(body: ImportRequest):
    """
    Pull all alert types from GitHub, normalize, and ingest into the Brain Pipeline.

    Falls back to mock data when not configured.
    """
    client = _get_client()
    try:
        result = client.import_all(org_id=body.org_id)
    except Exception as exc:
        logger.error("import_all_alerts failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    return result


@router.get(
    "/history",
    response_model=List[ImportSummaryResponse],
    summary="List import history",
)
def import_history(
    org_id: str = Query("default", description="Organisation identifier"),
):
    """
    Return import history for the given organisation, most recent first.

    Findings are omitted from summaries; use /import to get full results.
    """
    client = _get_client()
    try:
        history = client.get_import_history(org_id=org_id)
    except Exception as exc:
        logger.error("import_history failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    return history


@router.post(
    "/alerts/{alert_type}/{alert_number}/dismiss",
    response_model=DismissResponse,
    summary="Dismiss a GitHub Advanced Security alert",
)
def dismiss_alert(
    alert_type: str,
    alert_number: int,
    body: DismissRequest,
):
    """
    Dismiss a code scanning, Dependabot, or secret scanning alert.

    ``alert_type`` must be one of: ``code_scanning``, ``dependabot``, ``secret_scanning``.
    """
    valid_types = {"code_scanning", "dependabot", "secret_scanning"}
    if alert_type not in valid_types:
        raise HTTPException(
            status_code=422,
            detail=f"alert_type must be one of {sorted(valid_types)}",
        )
    client = _get_client()
    try:
        result = client.dismiss_alert(
            alert_type=alert_type,
            alert_number=alert_number,
            reason=body.reason,
            comment=body.comment,
        )
    except Exception as exc:
        logger.error("dismiss_alert failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

    if result.get("status") == "failed":
        raise HTTPException(status_code=502, detail=result.get("details", result))

    return {
        "status": result.get("status", "unknown"),
        "alert_type": alert_type,
        "alert_number": alert_number,
        "details": result.get("details"),
        "reason": result.get("reason"),
    }
