"""
ALdeci Semgrep Scanner API Router.

Exposes Semgrep SAST scanning via REST.
Falls back to mock data when the semgrep binary is not installed.

Endpoints:
  POST /api/v1/scan/semgrep/directory    — scan a filesystem directory
  POST /api/v1/scan/semgrep/file         — scan a single file
  POST /api/v1/scan/semgrep/config       — scan with custom config
  GET  /api/v1/scan/semgrep/status       — check semgrep availability
  GET  /api/v1/scan/semgrep/rulesets     — list available rulesets
  GET  /api/v1/scan/semgrep/history      — list scan history for an org

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
    prefix="/api/v1/scan/semgrep",
    tags=["semgrep-scanner"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton scanner
# ---------------------------------------------------------------------------

_scanner = None


def _get_scanner():
    global _scanner
    if _scanner is None:
        from core.semgrep_integration import SemgrepScanner
        _scanner = SemgrepScanner()
    return _scanner


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScanDirectoryRequest(BaseModel):
    """Request body for scanning a directory."""

    path: str = Field(..., description="Absolute or relative filesystem path to scan")
    rules: Optional[str] = Field(
        None,
        description="Semgrep ruleset or config, e.g. p/security-audit. Defaults to p/default.",
    )
    org_id: str = Field("default", description="Organisation identifier")


class ScanFileRequest(BaseModel):
    """Request body for scanning a single file."""

    file_path: str = Field(..., description="Absolute or relative path to the file")
    rules: Optional[str] = Field(None, description="Semgrep ruleset or config")
    org_id: str = Field("default", description="Organisation identifier")


class ScanWithConfigRequest(BaseModel):
    """Request body for scanning with a custom semgrep config."""

    path: str = Field(..., description="Filesystem path to scan")
    config: str = Field(
        ...,
        description="Semgrep config — registry ID, local YAML file, or URL",
    )
    org_id: str = Field("default", description="Organisation identifier")


class ScanResponse(BaseModel):
    scan_id: str
    org_id: str
    target: str
    rules: str
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
    rules: str
    started_at: str
    completed_at: str
    status: str
    is_mock: bool
    findings_count: int
    severity_breakdown: Dict[str, int]
    error: Optional[str] = None


class SemgrepStatusResponse(BaseModel):
    available: bool
    message: str


class RulesetsResponse(BaseModel):
    rulesets: List[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/directory",
    response_model=ScanResponse,
    summary="Scan a filesystem directory",
)
def scan_directory(body: ScanDirectoryRequest):
    """
    Scan a local directory for SAST findings using Semgrep.

    Returns normalized findings ingested into the Brain Pipeline.
    Falls back to mock data when semgrep is not installed.
    """
    scanner = _get_scanner()
    try:
        result = scanner.scan_and_ingest(
            path=body.path,
            org_id=body.org_id,
            rules=body.rules,
        )
    except Exception as exc:
        logger.error("scan_directory failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    return result


@router.post(
    "/file",
    response_model=ScanResponse,
    summary="Scan a single file",
)
def scan_file(body: ScanFileRequest):
    """
    Scan a single file for SAST findings using Semgrep.

    Falls back to mock data when semgrep is not installed.
    """
    scanner = _get_scanner()
    try:
        raw = scanner.scan_file(file_path=body.file_path, rules=body.rules)
        findings = scanner.normalize_results(raw)

        sev_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        import uuid
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        result = {
            "scan_id": str(uuid.uuid4()),
            "org_id": body.org_id,
            "target": body.file_path,
            "rules": body.rules or "p/default",
            "started_at": now,
            "completed_at": now,
            "status": "completed",
            "is_mock": not scanner.is_semgrep_available(),
            "findings_count": len(findings),
            "severity_breakdown": sev_counts,
            "findings": findings,
        }
    except Exception as exc:
        logger.error("scan_file failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    return result


@router.post(
    "/config",
    response_model=ScanResponse,
    summary="Scan with a custom semgrep config",
)
def scan_with_config(body: ScanWithConfigRequest):
    """
    Scan a path using a custom semgrep config (registry ID, YAML file, or URL).

    Falls back to mock data when semgrep is not installed.
    """
    scanner = _get_scanner()
    try:
        raw = scanner.scan_with_config(path=body.path, config=body.config)
        findings = scanner.normalize_results(raw)

        sev_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        import uuid
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        result = {
            "scan_id": str(uuid.uuid4()),
            "org_id": body.org_id,
            "target": body.path,
            "rules": body.config,
            "started_at": now,
            "completed_at": now,
            "status": "completed",
            "is_mock": not scanner.is_semgrep_available(),
            "findings_count": len(findings),
            "severity_breakdown": sev_counts,
            "findings": findings,
        }
    except Exception as exc:
        logger.error("scan_with_config failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    return result


@router.get(
    "/status",
    response_model=SemgrepStatusResponse,
    summary="Check semgrep availability",
)
def semgrep_status():
    """
    Return whether the semgrep binary is available on this host.

    When semgrep is not installed all scan endpoints return mock data.
    """
    scanner = _get_scanner()
    available = scanner.is_semgrep_available()
    return {
        "available": available,
        "message": (
            "semgrep binary found — real scans active"
            if available
            else "semgrep binary not found — mock data mode. "
            "Install: https://semgrep.dev/docs/getting-started/"
        ),
    }


@router.get(
    "/rulesets",
    response_model=RulesetsResponse,
    summary="List available Semgrep rulesets",
)
def list_rulesets():
    """
    Return the list of well-known public Semgrep rulesets from the registry.
    """
    scanner = _get_scanner()
    return {"rulesets": scanner.get_available_rulesets()}


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
