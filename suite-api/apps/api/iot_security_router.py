"""IoT Security Router — ALDECI.

Endpoints for the IoT Security engine.

Prefix: /api/v1/iot-security
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/iot-security/devices                         register_device
  GET    /api/v1/iot-security/devices                         list_devices
  GET    /api/v1/iot-security/devices/{device_id}             get_device
  PUT    /api/v1/iot-security/devices/{device_id}/status      update_device_status
  POST   /api/v1/iot-security/anomalies                       record_anomaly
  GET    /api/v1/iot-security/anomalies                       list_anomalies
  PUT    /api/v1/iot-security/anomalies/{anomaly_id}/resolve  resolve_anomaly
  POST   /api/v1/iot-security/policies                        create_policy
  GET    /api/v1/iot-security/policies                        list_policies
  GET    /api/v1/iot-security/stats                           get_iot_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/iot-security",
    tags=["IoT Security"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.iot_security_engine import IoTSecurityEngine
        _engine = IoTSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DeviceCreate(BaseModel):
    device_name: str = ""
    device_category: str = "other"
    protocol: str = "mqtt"
    ip_address: str = ""
    mac_address: str = ""
    firmware_version: str = ""
    last_seen: Optional[str] = None
    risk_score: float = 50.0
    status: str = "online"


class DeviceStatusUpdate(BaseModel):
    status: str


class AnomalyCreate(BaseModel):
    device_id: str = ""
    anomaly_type: str = "unusual_traffic"
    severity: str = "medium"
    description: str = ""
    detected_at: Optional[str] = None


class AnomalyResolve(BaseModel):
    resolution_status: str


class PolicyCreate(BaseModel):
    policy_name: str = ""
    policy_type: str = "monitoring"
    applies_to_category: str = "all"
    enforcement: str = "recommended"
    enabled: bool = True


# ---------------------------------------------------------------------------
# Device routes
# ---------------------------------------------------------------------------

@router.post("/devices", dependencies=[Depends(api_key_auth)], status_code=201)
def register_device(body: DeviceCreate, org_id: str = Query(default="default")):
    """Register a new IoT device."""
    try:
        return _get_engine().register_device(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/devices", dependencies=[Depends(api_key_auth)])
def list_devices(
     org_id: str = Query(default="default"),
    device_category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List IoT devices, optionally filtered by device_category and/or status."""
    return _get_engine().list_devices(org_id, device_category=device_category, status=status)


@router.get("/devices/{device_id}", dependencies=[Depends(api_key_auth)])
def get_device(device_id: str, org_id: str = Query(default="default")):
    """Get a single IoT device by ID."""
    device = _get_engine().get_device(org_id, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.put("/devices/{device_id}/status", dependencies=[Depends(api_key_auth)])
def update_device_status(device_id: str, body: DeviceStatusUpdate, org_id: str = Query(default="default")):
    """Update the status of an IoT device."""
    try:
        result = _get_engine().update_device_status(org_id, device_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Device not found")
    return result


# ---------------------------------------------------------------------------
# Anomaly routes
# ---------------------------------------------------------------------------

@router.post("/anomalies", dependencies=[Depends(api_key_auth)], status_code=201)
def record_anomaly(body: AnomalyCreate, org_id: str = Query(default="default")):
    """Record an IoT anomaly."""
    try:
        return _get_engine().record_anomaly(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/anomalies", dependencies=[Depends(api_key_auth)])
def list_anomalies(
     org_id: str = Query(default="default"),
    device_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List IoT anomalies, optionally filtered."""
    return _get_engine().list_anomalies(
        org_id, device_id=device_id, severity=severity, status=status
    )


@router.put("/anomalies/{anomaly_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_anomaly(anomaly_id: str, body: AnomalyResolve, org_id: str = Query(default="default")):
    """Resolve an IoT anomaly."""
    try:
        result = _get_engine().resolve_anomaly(org_id, anomaly_id, body.resolution_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return result


# ---------------------------------------------------------------------------
# Policy routes
# ---------------------------------------------------------------------------

@router.post("/policies", dependencies=[Depends(api_key_auth)], status_code=201)
def create_policy(body: PolicyCreate, org_id: str = Query(default="default")):
    """Create an IoT security policy."""
    try:
        return _get_engine().create_policy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/policies", dependencies=[Depends(api_key_auth)])
def list_policies(
     org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(None),
):
    """List IoT security policies, optionally filtered by enabled flag."""
    return _get_engine().list_policies(org_id, enabled=enabled)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_iot_stats(org_id: str = Query(default="default")):
    """Return aggregated IoT security statistics for the org."""
    return _get_engine().get_iot_stats(org_id)


# ---------------------------------------------------------------------------
# Root — capability summary (fixes BUG-1: missing GET /)
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_iot_root(org_id: str = Query(default="default")):
    """Return IoT Security service capabilities and live stats summary."""
    stats = _get_engine().get_iot_stats(org_id)
    return {
        "service": "iot-security",
        "version": "1.0",
        "status": "operational",
        "capabilities": [
            "device_registration",
            "anomaly_detection",
            "policy_enforcement",
            "risk_scoring",
        ],
        "stats": stats,
    }
