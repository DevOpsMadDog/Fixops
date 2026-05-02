"""Application Security (AppSec) API Router — ALDECI.

Endpoints:
  GET  /api/v1/app-security/apps                    — list applications
  POST /api/v1/app-security/apps                    — register application
  GET  /api/v1/app-security/apps/{app_id}/scans     — scans for one app
  GET  /api/v1/app-security/scans                   — list all scans
  POST /api/v1/app-security/scans                   — create scan (SAST or DAST)
  GET  /api/v1/app-security/findings                — list findings
  POST /api/v1/app-security/findings                — create finding
  PATCH /api/v1/app-security/findings/{finding_id}/status — update finding status
  GET  /api/v1/app-security/stats                   — org-level stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/app-security",
    tags=["app-security"],
    dependencies=[Depends(api_key_auth)],
)

# Module-level singleton — imported lazily to avoid circular imports at module load.
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.app_security_engine import get_app_security_engine
        _engine = get_app_security_engine()
    return _engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AppRegisterRequest(BaseModel):
    name: str
    app_type: str = "web"
    repo_url: str = ""
    tech_stack: List[str] = Field(default_factory=list)
    risk_rating: str = "medium"
    last_scan: Optional[str] = None
    compliance_score: float = 0.0


class ScanCreateRequest(BaseModel):
    app_id: str
    scan_type: str = "sast"  # "sast" or "dast"
    tool: str
    status: str = "pending"
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class FindingCreateRequest(BaseModel):
    app_id: str
    scan_id: Optional[str] = None
    vuln_type: str = "misconfig"
    severity: str = "medium"
    cwe_id: str = ""
    description: str = ""
    file_path: str = ""
    line_number: int = 0
    status: str = "open"
    owasp_category: Optional[str] = None


class FindingStatusUpdate(BaseModel):
    status: str


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------

@router.get("/apps", summary="List applications")
def list_apps(org_id: str = Depends(get_org_id)) -> List[Dict[str, Any]]:
    """Return all registered applications for the org."""
    return _get_engine().list_apps(org_id)


@router.post("/apps", status_code=status.HTTP_201_CREATED, summary="Register application")
def register_app(
    body: AppRegisterRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Register a new application in the inventory."""
    return _get_engine().register_app(org_id, body.model_dump())


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@router.get("/apps/{app_id}/scans", summary="List scans for an application")
def list_scans_for_app(
    app_id: str,
    scan_type: Optional[str] = Query(None, description="Filter: sast or dast"),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return scans for a specific application."""
    return _get_engine().list_scans(org_id, app_id=app_id, scan_type=scan_type)


@router.get("/scans", summary="List all scans")
def list_scans(
    app_id: Optional[str] = Query(None),
    scan_type: Optional[str] = Query(None, description="Filter: sast or dast"),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return all scans for the org, optionally filtered."""
    return _get_engine().list_scans(org_id, app_id=app_id, scan_type=scan_type)


@router.post("/scans", status_code=status.HTTP_201_CREATED, summary="Create scan")
def create_scan(
    body: ScanCreateRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a SAST or DAST scan record."""
    engine = _get_engine()
    data = body.model_dump()
    scan_type = data.pop("scan_type", "sast")
    app_id = data.pop("app_id")

    if scan_type == "dast":
        return engine.create_dast_scan(org_id, app_id, data)
    return engine.create_sast_scan(org_id, app_id, data)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@router.get("/findings", summary="List findings")
def list_findings(
    app_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return findings for the org, optionally filtered."""
    return _get_engine().list_findings(
        org_id, app_id=app_id, severity=severity, status=status
    )


@router.post("/findings", status_code=status.HTTP_201_CREATED, summary="Create finding")
def create_finding(
    body: FindingCreateRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a new application security finding."""
    return _get_engine().create_finding(org_id, body.model_dump())


@router.patch(
    "/findings/{finding_id}/status",
    summary="Update finding status",
)
def update_finding_status(
    finding_id: str,
    body: FindingStatusUpdate,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Update the status of a finding (open / false_positive / accepted / fixed)."""
    updated = _get_engine().update_finding_status(org_id, finding_id, body.status)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found or invalid status '{body.status}'",
        )
    return {"finding_id": finding_id, "status": body.status, "updated": True}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", summary="AppSec statistics")
def get_stats(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return application security statistics for the org."""
    return _get_engine().get_appsec_stats(org_id)
