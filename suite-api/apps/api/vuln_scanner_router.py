"""Vulnerability Scanner Management Router — ALDECI.

Endpoints:
  GET  /api/v1/vuln-scanner/scanners          — list scanners
  POST /api/v1/vuln-scanner/scanners          — add scanner
  GET  /api/v1/vuln-scanner/schedules         — list schedules
  POST /api/v1/vuln-scanner/schedules         — create schedule
  GET  /api/v1/vuln-scanner/results           — list scan results
  POST /api/v1/vuln-scanner/results           — create scan result
  GET  /api/v1/vuln-scanner/findings          — list findings
  POST /api/v1/vuln-scanner/findings          — create finding
  PATCH /api/v1/vuln-scanner/findings/{id}/status — update finding status
  GET  /api/v1/vuln-scanner/stats             — scanner statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.vuln_scanner_engine import VulnScannerEngine
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vuln-scanner", tags=["vuln-scanner"])

# Module-level singleton
_engine = None  # lazy-initialised on first request


def _get_engine() -> VulnScannerEngine:
    global _engine
    if _engine is None:
        _engine = VulnScannerEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AddScannerRequest(BaseModel):
    name: str
    scanner_type: str = "nessus"
    version: str = ""
    license_type: str = "oss"
    status: str = "active"
    last_sync: Optional[str] = None
    scan_count: int = 0


class CreateScheduleRequest(BaseModel):
    scanner_id: str
    name: str
    target_type: str = "hostname"
    targets: List[str] = Field(default_factory=list)
    frequency: str = "on_demand"
    cron_expression: str = ""
    enabled: bool = True
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    status: str = "active"


class CreateScanResultRequest(BaseModel):
    schedule_id: Optional[str] = None
    scanner_id: str
    scan_start: Optional[str] = None
    scan_end: Optional[str] = None
    assets_scanned: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    status: str = "running"


class CreateFindingRequest(BaseModel):
    result_id: str
    asset_ip: str = ""
    asset_hostname: str = ""
    vuln_name: str
    cve_id: str = ""
    cvss_score: float = 0.0
    severity: str = "medium"
    plugin_id: str = ""
    description: str = ""
    solution: str = ""
    status: str = "open"


class UpdateFindingStatusRequest(BaseModel):
    status: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/scanners")
def list_scanners(
    org_id: str = Depends(get_org_id),
    engine: VulnScannerEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List all registered scanners for the org."""
    return engine.list_scanners(org_id)


@router.post("/scanners", status_code=status.HTTP_201_CREATED)
def add_scanner(
    req: AddScannerRequest,
    org_id: str = Depends(get_org_id),
    engine: VulnScannerEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Register a new vulnerability scanner."""
    return engine.add_scanner(org_id, req.model_dump())


@router.get("/schedules")
def list_schedules(
    enabled: Optional[bool] = Query(None, description="Filter by enabled flag"),
    org_id: str = Depends(get_org_id),
    engine: VulnScannerEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List scan schedules for the org."""
    return engine.list_schedules(org_id, enabled=enabled)


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
def create_schedule(
    req: CreateScheduleRequest,
    org_id: str = Depends(get_org_id),
    engine: VulnScannerEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Create a new scan schedule."""
    return engine.create_schedule(org_id, req.model_dump())


@router.get("/results")
def list_results(
    schedule_id: Optional[str] = Query(None, description="Filter by schedule ID"),
    org_id: str = Depends(get_org_id),
    engine: VulnScannerEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List scan results for the org."""
    return engine.list_scan_results(org_id, schedule_id=schedule_id)


@router.post("/results", status_code=status.HTTP_201_CREATED)
def create_result(
    req: CreateScanResultRequest,
    org_id: str = Depends(get_org_id),
    engine: VulnScannerEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Record a scan result."""
    return engine.create_scan_result(org_id, req.model_dump())


@router.get("/findings")
def list_findings(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    org_id: str = Depends(get_org_id),
    engine: VulnScannerEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List vulnerability findings for the org."""
    return engine.list_findings(org_id, severity=severity, status=status)


@router.post("/findings", status_code=status.HTTP_201_CREATED)
def create_finding(
    req: CreateFindingRequest,
    org_id: str = Depends(get_org_id),
    engine: VulnScannerEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Record a new vulnerability finding."""
    data = req.model_dump()
    result_id = data.pop("result_id")
    return engine.create_finding(org_id, result_id, data)


@router.patch("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: str,
    req: UpdateFindingStatusRequest,
    org_id: str = Depends(get_org_id),
    engine: VulnScannerEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Update the remediation status of a vulnerability finding."""
    updated = engine.update_finding_status(org_id, finding_id, req.status)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found or invalid status '{req.status}'",
        )
    return {"finding_id": finding_id, "status": req.status, "updated": True}


@router.get("/stats")
def get_stats(
    org_id: str = Depends(get_org_id),
    engine: VulnScannerEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Return aggregated scanner statistics for the org."""
    return engine.get_scanner_stats(org_id)
