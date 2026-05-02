"""Operational Technology (OT) Security API endpoints — ALDECI.

7 endpoints covering OT asset registration, anomaly lifecycle management,
and environment statistics for ICS/SCADA environments.

Protected via api_key_auth dependency.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.ot_security_engine import OTSecurityEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/api/v1/ot-security",
    tags=["ot-security"],
    dependencies=[Depends(api_key_auth)],
)

_engine: Optional[OTSecurityEngine] = None


def _get_engine() -> OTSecurityEngine:
    global _engine
    if _engine is None:
        _engine = OTSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterAssetRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    name: str = Field(..., min_length=1, description="Asset name")
    asset_type: str = Field(..., description="Asset type: plc/hmi/scada/rtu/sensor/historian")
    criticality: str = Field("medium", description="Criticality: low/medium/high/critical")
    vendor: str = Field("", description="Vendor/manufacturer")
    firmware_version: str = Field("", description="Firmware version")
    ip_address: str = Field("", description="IP address")
    zone: str = Field("", description="Network zone or purdue level")


class RecordAnomalyRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    asset_id: str = Field(..., description="Target asset ID")
    anomaly_type: str = Field(..., min_length=1, description="Type of anomaly")
    severity: str = Field(..., description="Severity: low/medium/high/critical")
    description: str = Field("", description="Anomaly description")


class ResolveAnomalyRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    resolution: str = Field(..., min_length=1, description="Resolution notes")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/assets", status_code=201)
async def register_asset(body: RegisterAssetRequest) -> Dict[str, Any]:
    """Register a new OT asset (PLC, HMI, SCADA, RTU, sensor, or historian)."""
    try:
        return _get_engine().register_asset(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/assets")
async def list_assets(
    org_id: str = Query("default", description="Organisation identifier"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    criticality: Optional[str] = Query(None, description="Filter by criticality"),
) -> List[Dict[str, Any]]:
    """List OT assets with optional filters."""
    return _get_engine().list_assets(org_id, asset_type=asset_type, criticality=criticality)


@router.get("/assets/{asset_id}")
async def get_asset(
    asset_id: str,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Get a single OT asset by ID."""
    try:
        return _get_engine().get_asset(org_id, asset_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/anomalies", status_code=201)
async def record_anomaly(body: RecordAnomalyRequest) -> Dict[str, Any]:
    """Record a new anomaly against an OT asset."""
    try:
        return _get_engine().record_anomaly(
            body.org_id,
            body.asset_id,
            body.anomaly_type,
            body.severity,
            body.description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/anomalies")
async def list_anomalies(
    org_id: str = Query("default", description="Organisation identifier"),
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
) -> List[Dict[str, Any]]:
    """List OT anomalies with optional status and severity filters."""
    return _get_engine().list_anomalies(org_id, status=status, severity=severity)


@router.put("/anomalies/{anomaly_id}/resolve")
async def resolve_anomaly(
    anomaly_id: str,
    body: ResolveAnomalyRequest,
) -> Dict[str, Any]:
    """Resolve an open anomaly with a resolution note."""
    try:
        return _get_engine().resolve_anomaly(body.org_id, anomaly_id, body.resolution)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/stats")
async def get_ot_stats(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Get OT environment statistics: asset counts by type/criticality, open anomalies."""
    return _get_engine().get_ot_stats(org_id)


# ---------------------------------------------------------------------------
# Root — capability summary (fixes BUG-1: missing GET /)
# ---------------------------------------------------------------------------

@router.get("/")
async def get_ot_root(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return OT Security service capabilities and live stats summary."""
    stats = _get_engine().get_ot_stats(org_id)
    return {
        "service": "ot-security",
        "version": "1.0",
        "status": "operational",
        "capabilities": [
            "asset_registry",
            "anomaly_detection",
            "ics_scada_monitoring",
            "criticality_scoring",
        ],
        "stats": stats,
    }
