"""Attack Surface Engine Router — ALDECI.

Alias router for AttackSurfaceEngine at /api/v1/attack-surface-mgmt.
Mirrors the full attack surface management API under a canonical path.

Prefix: /api/v1/attack-surface-mgmt
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/attack-surface-mgmt/assets                        add_asset
  GET    /api/v1/attack-surface-mgmt/assets                        list_assets
  GET    /api/v1/attack-surface-mgmt/assets/{asset_id}             get_asset
  POST   /api/v1/attack-surface-mgmt/assets/{asset_id}/exposures   add_exposure
  GET    /api/v1/attack-surface-mgmt/exposures                     list_exposures
  POST   /api/v1/attack-surface-mgmt/exposures/{exposure_id}/fix   fix_exposure
  POST   /api/v1/attack-surface-mgmt/scans                         create_scan
  POST   /api/v1/attack-surface-mgmt/scans/{scan_id}/complete      complete_scan
  GET    /api/v1/attack-surface-mgmt/scans                         list_scans
  GET    /api/v1/attack-surface-mgmt/changes                       list_changes
  GET    /api/v1/attack-surface-mgmt/stats                         get_surface_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/attack-surface-mgmt",
    tags=["Attack Surface Management"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.attack_surface_engine import AttackSurfaceEngine
        _engine = AttackSurfaceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    asset_type: str = "domain"
    value: str
    parent_asset_id: Optional[str] = None
    status: str = "active"
    risk_score: float = Field(default=0.0, ge=0.0)
    first_discovered: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = []
    notes: str = ""


class ExposureCreate(BaseModel):
    exposure_type: str = "open_port"
    severity: str = "medium"
    title: str
    description: str = ""
    evidence: str = ""
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    remediation: str = ""
    first_detected: Optional[str] = None
    last_seen: Optional[str] = None


class ScanCreate(BaseModel):
    scan_type: str = "full"
    target_scope: List[str] = []


class ScanComplete(BaseModel):
    assets_discovered: int = 0
    new_assets: int = 0
    new_exposures: int = 0
    critical_exposures: int = 0


# ---------------------------------------------------------------------------
# Asset endpoints
# ---------------------------------------------------------------------------

@router.post("/assets", dependencies=[Depends(api_key_auth)], status_code=201)
def add_asset(body: AssetCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Register a surface asset."""
    try:
        return _get_engine().add_asset(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_assets(
    org_id: str = Query("default"),
    asset_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    min_risk: Optional[float] = Query(None),
) -> List[Dict[str, Any]]:
    """List surface assets with optional filters."""
    return _get_engine().list_assets(
        org_id,
        asset_type=asset_type,
        status=status,
        min_risk=min_risk,
    )


@router.get("/assets/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_asset(asset_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Get a single asset with its exposures."""
    result = _get_engine().get_asset(org_id, asset_id)
    if not result:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return result


# ---------------------------------------------------------------------------
# Exposure endpoints
# ---------------------------------------------------------------------------

@router.post("/assets/{asset_id}/exposures", dependencies=[Depends(api_key_auth)], status_code=201)
def add_exposure(
    asset_id: str,
    body: ExposureCreate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Add an exposure finding for an asset."""
    try:
        return _get_engine().add_exposure(org_id, asset_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/exposures", dependencies=[Depends(api_key_auth)])
def list_exposures(
    org_id: str = Query("default"),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    exposure_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List exposures with optional filters."""
    return _get_engine().list_exposures(
        org_id,
        severity=severity,
        status=status,
        exposure_type=exposure_type,
        limit=limit,
    )


@router.post("/exposures/{exposure_id}/fix", dependencies=[Depends(api_key_auth)])
def fix_exposure(exposure_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Mark an exposure as fixed."""
    fixed = _get_engine().fix_exposure(org_id, exposure_id)
    if not fixed:
        raise HTTPException(status_code=404, detail="Exposure not found.")
    return {"fixed": True, "exposure_id": exposure_id}


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------

@router.post("/scans", dependencies=[Depends(api_key_auth)], status_code=201)
def create_scan(body: ScanCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Create a scan job."""
    try:
        return _get_engine().create_scan(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/scans/{scan_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_scan(
    scan_id: str,
    body: ScanComplete,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Mark scan complete with discovery metrics."""
    completed = _get_engine().complete_scan(org_id, scan_id, body.model_dump())
    if not completed:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {"completed": True, "scan_id": scan_id}


@router.get("/scans", dependencies=[Depends(api_key_auth)])
def list_scans(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List scans with optional status filter."""
    return _get_engine().list_scans(org_id, status=status)


# ---------------------------------------------------------------------------
# Changes
# ---------------------------------------------------------------------------

@router.get("/changes", dependencies=[Depends(api_key_auth)])
def list_changes(
    org_id: str = Query("default"),
    days: int = Query(7, ge=1, le=90),
    severity: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List recent surface change events."""
    return _get_engine().list_changes(org_id, days=days, severity=severity)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_surface_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregated attack surface stats for the org."""
    return _get_engine().get_surface_stats(org_id)
