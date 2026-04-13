"""IoT/OT Security Scanner API Router — ALDECI.

8 endpoints under /api/v1/iot:
  POST   /api/v1/iot/devices              register_device
  GET    /api/v1/iot/devices              list_devices
  GET    /api/v1/iot/devices/{id}         get_device
  POST   /api/v1/iot/devices/{id}/scan    scan_device
  POST   /api/v1/iot/devices/{id}/comms   record_communication
  GET    /api/v1/iot/devices/{id}/comms   get_communication_anomalies
  GET    /api/v1/iot/devices/{id}/compliance  get_compliance
  GET    /api/v1/iot/summary              get_summary

Auth applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.iot_security import (
    CommunicationAnomaly,
    CommunicationPattern,
    ComplianceFramework,
    ComplianceResult,
    CredentialFinding,
    DeviceScanResult,
    DeviceProtocol,
    DeviceType,
    FirmwareFinding,
    IoTDevice,
    IoTSecurityEngine,
    IoTSummary,
    NetworkSegment,
    ProtocolFinding,
    RiskLevel,
    SegmentationFinding,
    get_iot_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/iot", tags=["iot-security"])

_engine: Optional[IoTSecurityEngine] = None


def _get_engine() -> IoTSecurityEngine:
    global _engine
    if _engine is None:
        _engine = get_iot_engine()
    return _engine


# ============================================================================
# REQUEST MODELS
# ============================================================================


class RegisterDeviceRequest(BaseModel):
    name: str = Field(..., description="Human-readable device name")
    device_type: DeviceType = Field(..., description="Type of IoT/OT device")
    manufacturer: str = Field(..., description="Device manufacturer")
    model: Optional[str] = Field(None, description="Device model identifier")
    firmware_version: Optional[str] = Field(None, description="Current firmware version")
    ip_address: str = Field(..., description="Device IP address")
    mac_address: Optional[str] = Field(None, description="MAC address for unique identification")
    network_segment: NetworkSegment = Field(NetworkSegment.UNKNOWN, description="Network segment or VLAN")
    vlan_id: Optional[int] = Field(None, description="VLAN identifier")
    protocols: List[DeviceProtocol] = Field(default_factory=list, description="Active protocols")
    open_ports: List[int] = Field(default_factory=list, description="Open TCP/UDP ports")
    location: Optional[str] = Field(None, description="Physical location")
    org_id: str = Field("default", description="Organisation ID")
    tags: List[str] = Field(default_factory=list, description="Free-form tags")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ScanDeviceRequest(BaseModel):
    frameworks: Optional[List[ComplianceFramework]] = Field(
        None,
        description="Compliance frameworks to assess (auto-detected if omitted)",
    )


class RecordCommunicationRequest(BaseModel):
    remote_ip: str = Field(..., description="Remote IP address")
    remote_port: int = Field(..., description="Remote port")
    protocol: str = Field(..., description="Transport protocol (tcp/udp/etc.)")
    bytes_sent: int = Field(0, description="Bytes sent to remote")
    bytes_received: int = Field(0, description="Bytes received from remote")
    org_id: str = Field("default", description="Organisation ID")


class CheckCredentialsRequest(BaseModel):
    credentials: List[Dict[str, str]] = Field(
        ...,
        description='List of {"username": "x", "password": "y"} pairs to test',
    )


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/devices", response_model=IoTDevice, status_code=201)
def register_device(req: RegisterDeviceRequest) -> IoTDevice:
    """Register a new IoT/OT device in the inventory."""
    engine = _get_engine()
    device = IoTDevice(
        name=req.name,
        device_type=req.device_type,
        manufacturer=req.manufacturer,
        model=req.model,
        firmware_version=req.firmware_version,
        ip_address=req.ip_address,
        mac_address=req.mac_address,
        network_segment=req.network_segment,
        vlan_id=req.vlan_id,
        protocols=req.protocols,
        open_ports=req.open_ports,
        location=req.location,
        org_id=req.org_id,
        tags=req.tags,
        metadata=req.metadata,
    )
    registered = engine.register_device(device)
    logger.info("Registered IoT device %s (%s)", registered.id, registered.name)
    return registered


@router.get("/devices", response_model=List[IoTDevice])
def list_devices(
    org_id: str = Query("default", description="Organisation ID"),
    device_type: Optional[DeviceType] = Query(None, description="Filter by device type"),
    network_segment: Optional[NetworkSegment] = Query(None, description="Filter by network segment"),
) -> List[IoTDevice]:
    """List all IoT/OT devices for an organisation."""
    engine = _get_engine()
    return engine.list_devices(org_id=org_id, device_type=device_type, network_segment=network_segment)


@router.get("/devices/{device_id}", response_model=IoTDevice)
def get_device(device_id: str) -> IoTDevice:
    """Get a specific IoT/OT device by ID."""
    engine = _get_engine()
    device = engine.get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return device


@router.post("/devices/{device_id}/scan", response_model=DeviceScanResult)
def scan_device(device_id: str, req: ScanDeviceRequest) -> DeviceScanResult:
    """Run a comprehensive IoT/OT security scan on a device.

    Covers firmware CVEs, protocol security, segmentation, credentials,
    communication anomalies, and compliance mapping.
    """
    engine = _get_engine()
    try:
        result = engine.scan_device(device_id, frameworks=req.frameworks)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception("scan_device failed for %s", device_id)
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}")
    return result


@router.post("/devices/{device_id}/comms", response_model=CommunicationPattern, status_code=201)
def record_communication(device_id: str, req: RecordCommunicationRequest) -> CommunicationPattern:
    """Record a communication pattern observed from a device.

    Used to build the baseline and detect anomalies (C2 beaconing, data exfiltration).
    """
    engine = _get_engine()
    device = engine.get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    from datetime import datetime, timezone

    pattern = CommunicationPattern(
        device_id=device_id,
        remote_ip=req.remote_ip,
        remote_port=req.remote_port,
        protocol=req.protocol,
        bytes_sent=req.bytes_sent,
        bytes_received=req.bytes_received,
        org_id=req.org_id,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    recorded = engine.record_communication(pattern)
    return recorded


@router.get("/devices/{device_id}/comms", response_model=List[CommunicationAnomaly])
def get_communication_anomalies(device_id: str) -> List[CommunicationAnomaly]:
    """Get detected communication anomalies for a device (C2, data exfiltration)."""
    engine = _get_engine()
    device = engine.get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return engine.get_communication_anomalies(device_id)


@router.get("/devices/{device_id}/compliance", response_model=List[ComplianceResult])
def get_compliance(
    device_id: str,
    framework: Optional[ComplianceFramework] = Query(None, description="Filter by framework"),
) -> List[ComplianceResult]:
    """Get compliance assessment results for a device.

    Covers NIST IoT guidelines, IEC 62443 (OT), and FDA (medical devices).
    """
    engine = _get_engine()
    device = engine.get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return engine.get_compliance_results(device_id, framework=framework)


@router.get("/summary", response_model=IoTSummary)
def get_summary(org_id: str = Query("default", description="Organisation ID")) -> IoTSummary:
    """Get IoT/OT security posture summary for an organisation.

    Returns device counts by type/segment/risk, finding totals, and key metrics
    for CISO dashboard and compliance reporting.
    """
    engine = _get_engine()
    return engine.get_summary(org_id=org_id)
