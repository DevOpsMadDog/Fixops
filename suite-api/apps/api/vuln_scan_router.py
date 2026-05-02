"""Vulnerability Scan Router — ALDECI.

Manages vulnerability scan lifecycle and findings across Nessus, Qualys,
Rapid7, OpenVAS, Nuclei, Trivy, Grype, and custom scanners.

Prefix: /api/v1/vuln-scans
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/vuln-scans/scans                        create_scan
  GET    /api/v1/vuln-scans/scans                        list_scans
  GET    /api/v1/vuln-scans/scans/{id}                   get_scan
  PATCH  /api/v1/vuln-scans/scans/{id}/status            update_scan_status
  POST   /api/v1/vuln-scans/scans/{id}/findings          add_finding
  GET    /api/v1/vuln-scans/findings                     list_findings
  PATCH  /api/v1/vuln-scans/findings/{id}/status         update_finding_status
  GET    /api/v1/vuln-scans/stats                        get_scan_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vuln-scans",
    tags=["Vulnerability Scans"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.vuln_scan_engine import VulnScanEngine
        _engine = VulnScanEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateScanRequest(BaseModel):
    scan_name: str = Field(..., description="Descriptive scan name")
    scanner_type: str = Field(
        default="custom",
        description=(
            "nessus | qualys | rapid7 | openvas | nuclei | trivy | grype | custom"
        ),
    )
    target: str = Field(..., description="Scan target (IP, CIDR, hostname, URL)")
    scan_status: str = Field(
        default="pending",
        description="pending | running | completed | failed | cancelled",
    )
    started_at: Optional[str] = Field(default=None)
    scanner_version: Optional[str] = Field(default=None)


class UpdateScanStatusRequest(BaseModel):
    new_status: str = Field(
        ...,
        description="pending | running | completed | failed | cancelled",
    )
    completed_at: Optional[str] = Field(default=None)


class AddFindingRequest(BaseModel):
    title: str = Field(..., description="Short finding title")
    severity: str = Field(
        ...,
        description="critical | high | medium | low | info",
    )
    cve_id: Optional[str] = Field(default=None)
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    finding_status: str = Field(
        default="open",
        description="open | in_progress | resolved | accepted_risk | false_positive",
    )
    affected_asset: Optional[str] = Field(default=None)
    plugin_id: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None)
    remediation: Optional[str] = Field(default=None)
    detected_at: Optional[str] = Field(default=None)


class UpdateFindingStatusRequest(BaseModel):
    new_status: str = Field(
        ...,
        description="open | in_progress | resolved | accepted_risk | false_positive",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scans", dependencies=[Depends(api_key_auth)])
def create_scan(
    req: CreateScanRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a new vulnerability scan."""
    try:
        return _get_engine().create_scan(
            org_id,
            {
                "scan_name": req.scan_name,
                "scanner_type": req.scanner_type,
                "target": req.target,
                "scan_status": req.scan_status,
                "started_at": req.started_at,
                "scanner_version": req.scanner_version or "",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/scans", dependencies=[Depends(api_key_auth)])
def list_scans(
    org_id: str = Query(..., description="Organization ID"),
    scanner_type: Optional[str] = Query(default=None),
    scan_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List scans with optional filters."""
    return _get_engine().list_scans(
        org_id, scanner_type=scanner_type, scan_status=scan_status
    )


@router.get("/scans/{scan_id}", dependencies=[Depends(api_key_auth)])
def get_scan(
    scan_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single scan by ID."""
    scan = _get_engine().get_scan(org_id, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return scan


@router.patch("/scans/{scan_id}/status", dependencies=[Depends(api_key_auth)])
def update_scan_status(
    scan_id: str,
    req: UpdateScanStatusRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update scan status."""
    try:
        return _get_engine().update_scan_status(
            org_id, scan_id, req.new_status, completed_at=req.completed_at
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/scans/{scan_id}/findings", dependencies=[Depends(api_key_auth)])
def add_finding(
    scan_id: str,
    req: AddFindingRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Add a finding to a scan."""
    try:
        return _get_engine().add_finding(
            org_id,
            scan_id,
            {
                "title": req.title,
                "severity": req.severity,
                "cve_id": req.cve_id or "",
                "cvss_score": req.cvss_score if req.cvss_score is not None else 0.0,
                "finding_status": req.finding_status,
                "affected_asset": req.affected_asset or "",
                "plugin_id": req.plugin_id or "",
                "description": req.description or "",
                "remediation": req.remediation or "",
                "detected_at": req.detected_at,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
    org_id: str = Query(..., description="Organization ID"),
    scan_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    finding_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List findings with optional filters."""
    return _get_engine().list_findings(
        org_id,
        scan_id=scan_id,
        severity=severity,
        finding_status=finding_status,
    )


@router.patch("/findings/{finding_id}/status", dependencies=[Depends(api_key_auth)])
def update_finding_status(
    finding_id: str,
    req: UpdateFindingStatusRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update a finding's status."""
    try:
        return _get_engine().update_finding_status(org_id, finding_id, req.new_status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_scan_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregate scan and finding statistics."""
    return _get_engine().get_scan_stats(org_id)
