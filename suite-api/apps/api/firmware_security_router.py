"""Firmware Security Router — ALDECI.

Endpoints for the Firmware Security engine.

Prefix: /api/v1/firmware-security
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/firmware-security/devices                       register_device
  GET    /api/v1/firmware-security/devices                       list_devices
  GET    /api/v1/firmware-security/devices/{device_id}           get_device
  POST   /api/v1/firmware-security/vulnerabilities               record_vulnerability
  GET    /api/v1/firmware-security/vulnerabilities               list_vulnerabilities
  POST   /api/v1/firmware-security/scans                         create_scan
  PUT    /api/v1/firmware-security/scans/{scan_id}/complete      complete_scan
  GET    /api/v1/firmware-security/scans                         list_scans
  GET    /api/v1/firmware-security/stats                         get_firmware_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/firmware-security",
    tags=["Firmware Security"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.firmware_security_engine import FirmwareSecurityEngine
        _engine = FirmwareSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DeviceCreate(BaseModel):
    device_name: str = ""
    device_type: str = "embedded"
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    last_scanned: Optional[str] = None
    risk_score: float = 50.0
    risk_level: str = "medium"
    status: str = "active"


class VulnerabilityCreate(BaseModel):
    device_id: str
    cve_id: str
    title: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    affected_component: str = ""
    patch_available: bool = False
    patch_version: str = ""
    status: str = "open"
    discovered_at: Optional[str] = None


class ScanCreate(BaseModel):
    device_id: str = ""
    scan_type: str = "static"
    started_at: Optional[str] = None


class ScanComplete(BaseModel):
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0


# ---------------------------------------------------------------------------
# Device routes
# ---------------------------------------------------------------------------

@router.post("/devices", dependencies=[Depends(api_key_auth)], status_code=201)
def register_device(body: DeviceCreate, org_id: str = Query(default="default")):
    """Register a new firmware device."""
    try:
        return _get_engine().register_device(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/devices", dependencies=[Depends(api_key_auth)])
def list_devices(
     org_id: str = Query(default="default"),
    device_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List firmware devices, optionally filtered by device_type and/or risk_level."""
    return _get_engine().list_devices(org_id, device_type=device_type, risk_level=risk_level)


@router.get("/devices/{device_id}", dependencies=[Depends(api_key_auth)])
def get_device(device_id: str, org_id: str = Query(default="default")):
    """Get a single firmware device by ID."""
    device = _get_engine().get_device(org_id, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


# ---------------------------------------------------------------------------
# Vulnerability routes
# ---------------------------------------------------------------------------

@router.post("/vulnerabilities", dependencies=[Depends(api_key_auth)], status_code=201)
def record_vulnerability(body: VulnerabilityCreate, org_id: str = Query(default="default")):
    """Record a firmware vulnerability."""
    try:
        return _get_engine().record_vulnerability(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/vulnerabilities", dependencies=[Depends(api_key_auth)])
def list_vulnerabilities(
     org_id: str = Query(default="default"),
    device_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List firmware vulnerabilities, optionally filtered."""
    return _get_engine().list_vulnerabilities(
        org_id, device_id=device_id, severity=severity, status=status
    )


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@router.post("/scans", dependencies=[Depends(api_key_auth)], status_code=201)
def create_scan(body: ScanCreate, org_id: str = Query(default="default")):
    """Create a new firmware scan job."""
    try:
        return _get_engine().create_scan(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/scans/{scan_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_scan(scan_id: str, body: ScanComplete, org_id: str = Query(default="default")):
    """Mark a firmware scan as completed with findings."""
    result = _get_engine().complete_scan(
        org_id, scan_id, body.findings_count, body.critical_count, body.high_count
    )
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.get("/scans", dependencies=[Depends(api_key_auth)])
def list_scans(
     org_id: str = Query(default="default"),
    device_id: Optional[str] = Query(None),
    scan_status: Optional[str] = Query(None),
):
    """List firmware scans, optionally filtered by device_id and/or scan_status."""
    return _get_engine().list_scans(org_id, device_id=device_id, scan_status=scan_status)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_firmware_stats(org_id: str = Query(default="default")):
    """Return aggregated firmware security statistics for the org."""
    return _get_engine().get_firmware_stats(org_id)
