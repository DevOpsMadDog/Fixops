"""Operational Technology Security Router — ALDECI.

Endpoints for the Operational Technology Security engine.

Prefix: /api/v1/ot-sec
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/ot-sec/assets                          register_asset
  GET  /api/v1/ot-sec/assets                          list_assets
  GET  /api/v1/ot-sec/assets/{asset_id}               get_asset
  PUT  /api/v1/ot-sec/assets/{asset_id}/status        update_asset_status
  POST /api/v1/ot-sec/incidents                       record_incident
  GET  /api/v1/ot-sec/incidents                       list_incidents
  PUT  /api/v1/ot-sec/incidents/{incident_id}/status  update_incident_status
  POST /api/v1/ot-sec/zones                           create_zone
  GET  /api/v1/ot-sec/zones                           list_zones
  GET  /api/v1/ot-sec/stats                           get_ot_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ot-sec",
    tags=["Operational Technology Security"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.operational_technology_security_engine import (
            OperationalTechnologySecurityEngine,
        )
        _engine = OperationalTechnologySecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    asset_name: str = ""
    asset_type: str
    vendor: str = ""
    model: str = ""
    firmware_version: str = ""
    zone: str
    protocol: str = "other"
    risk_score: float = 50.0
    status: str = "operational"
    last_patched: Optional[str] = None


class AssetStatusUpdate(BaseModel):
    status: str


class IncidentCreate(BaseModel):
    asset_id: str = ""
    incident_type: str
    severity: str = "medium"
    impact_level: str = "none"
    detected_at: Optional[str] = None


class IncidentStatusUpdate(BaseModel):
    status: str


class ZoneCreate(BaseModel):
    zone_name: str = ""
    zone_type: str
    asset_count: int = 0
    security_level: str = "sl1"
    purdue_level: int = 0
    conduit_count: int = 0


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

@router.post("/assets", dependencies=[Depends(api_key_auth)], status_code=201)
def register_asset(body: AssetCreate, org_id: str = Query(default="default")):
    """Register a new OT asset."""
    try:
        return _get_engine().register_asset(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_assets(
     org_id: str = Query(default="default"),
    asset_type: Optional[str] = Query(None),
    zone: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List OT assets with optional filters."""
    return _get_engine().list_assets(
        org_id,
        asset_type=asset_type,
        zone=zone,
        status=status,
    )


@router.get("/assets/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_asset(asset_id: str, org_id: str = Query(default="default")):
    """Get a single OT asset by ID."""
    result = _get_engine().get_asset(org_id, asset_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


@router.put("/assets/{asset_id}/status", dependencies=[Depends(api_key_auth)])
def update_asset_status(asset_id: str, body: AssetStatusUpdate, org_id: str = Query(default="default")):
    """Update asset operational status."""
    try:
        return _get_engine().update_asset_status(org_id, asset_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.post("/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def record_incident(body: IncidentCreate, org_id: str = Query(default="default")):
    """Record an OT security incident."""
    try:
        return _get_engine().record_incident(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/incidents", dependencies=[Depends(api_key_auth)])
def list_incidents(
     org_id: str = Query(default="default"),
    asset_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List incidents with optional filters."""
    return _get_engine().list_incidents(
        org_id,
        asset_id=asset_id,
        severity=severity,
        status=status,
    )


@router.put("/incidents/{incident_id}/status", dependencies=[Depends(api_key_auth)])
def update_incident_status(
    incident_id: str, body: IncidentStatusUpdate, org_id: str = Query(default="default")
):
    """Update incident status."""
    try:
        return _get_engine().update_incident_status(org_id, incident_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Zones
# ---------------------------------------------------------------------------

@router.post("/zones", dependencies=[Depends(api_key_auth)], status_code=201)
def create_zone(body: ZoneCreate, org_id: str = Query(default="default")):
    """Create an OT network zone."""
    try:
        return _get_engine().create_zone(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/zones", dependencies=[Depends(api_key_auth)])
def list_zones(
     org_id: str = Query(default="default"),
    zone_type: Optional[str] = Query(None),
):
    """List zones with optional zone_type filter."""
    return _get_engine().list_zones(org_id, zone_type=zone_type)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_ot_stats(org_id: str = Query(default="default")):
    """Return aggregated OT security statistics."""
    return _get_engine().get_ot_stats(org_id)
