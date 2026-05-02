"""Asset Lifecycle Router — ALDECI.

Prefix: /api/v1/asset-lifecycle
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/asset-lifecycle/assets                            register_asset
  GET    /api/v1/asset-lifecycle/assets                            list_assets
  GET    /api/v1/asset-lifecycle/assets/{asset_id}                 get_asset
  PUT    /api/v1/asset-lifecycle/assets/{asset_id}/lifecycle-phase update_lifecycle_phase
  POST   /api/v1/asset-lifecycle/assets/{asset_id}/maintenance     record_maintenance
  POST   /api/v1/asset-lifecycle/assets/{asset_id}/decommission    decommission_asset
  GET    /api/v1/asset-lifecycle/stats                             get_lifecycle_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/asset-lifecycle",
    tags=["Asset Lifecycle"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.asset_lifecycle_engine import AssetLifecycleEngine
        _engine = AssetLifecycleEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    name: str
    asset_type: str
    lifecycle_phase: str = "deployment"
    criticality: str = "medium"
    vendor: str = ""
    model: str = ""
    serial_number: str = ""
    location: str = ""
    acquisition_date: Optional[str] = None


class LifecyclePhaseUpdate(BaseModel):
    new_phase: str
    notes: str = ""


class MaintenanceRecord(BaseModel):
    maintenance_type: str
    performed_by: str
    cost: float = 0.0
    notes: str = ""
    next_maintenance_date: Optional[str] = None


class DecommissionRequest(BaseModel):
    reason: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/assets", dependencies=[Depends(api_key_auth)], status_code=201)
def register_asset(body: AssetCreate, org_id: str = Query(default="default")):
    """Register a new asset."""
    try:
        return _get_engine().register_asset(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_assets(
     org_id: str = Query(default="default"),
    asset_type: Optional[str] = Query(None),
    lifecycle_phase: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
):
    """List assets for the org with optional filters."""
    return _get_engine().list_assets(
        org_id,
        asset_type=asset_type,
        lifecycle_phase=lifecycle_phase,
        criticality=criticality,
    )


@router.get("/assets/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_asset(asset_id: str, org_id: str = Query(default="default")):
    """Retrieve a single asset by ID."""
    result = _get_engine().get_asset(org_id, asset_id)
    if not result:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


@router.put("/assets/{asset_id}/lifecycle-phase", dependencies=[Depends(api_key_auth)])
def update_lifecycle_phase(
    asset_id: str, body: LifecyclePhaseUpdate, org_id: str = Query(default="default")
):
    """Transition an asset to a new lifecycle phase."""
    try:
        return _get_engine().update_lifecycle_phase(
            org_id, asset_id, body.new_phase, notes=body.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/assets/{asset_id}/maintenance", dependencies=[Depends(api_key_auth)], status_code=201)
def record_maintenance(
    asset_id: str, body: MaintenanceRecord, org_id: str = Query(default="default")
):
    """Record a maintenance event for an asset."""
    try:
        return _get_engine().record_maintenance(org_id, asset_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/assets/{asset_id}/decommission", dependencies=[Depends(api_key_auth)])
def decommission_asset(
    asset_id: str, body: DecommissionRequest, org_id: str = Query(default="default")
):
    """Decommission an asset."""
    try:
        return _get_engine().decommission_asset(org_id, asset_id, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_lifecycle_stats(org_id: str = Query(default="default")):
    """Return aggregated lifecycle statistics for the org."""
    return _get_engine().get_lifecycle_stats(org_id)
