"""Network Detection & Response (NDR) API router — ALDECI.

Endpoints at /api/v1/ndr/* for network flow ingestion, alert management,
baseline learning, segment management, and anomaly detection.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.ndr_engine import NDREngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/ndr", tags=["ndr"])
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = NDREngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class IngestFlowRequest(BaseModel):
    src_ip: str = Field(default="", description="Source IP address")
    dst_ip: str = Field(default="", description="Destination IP address")
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    protocol: str = Field(default="TCP", description="Protocol (TCP/UDP/ICMP/DNS/HTTP/HTTPS/SSH/RDP)")
    bytes_sent: int = Field(default=0, ge=0)
    bytes_recv: int = Field(default=0, ge=0)
    duration_ms: int = Field(default=0, ge=0)
    flow_type: str = Field(default="internal", description="internal/external/lateral/exfiltration_suspect/c2_suspect")
    mitre_technique: str = Field(default="")
    observed_at: Optional[str] = None


class UpdateAlertStatusRequest(BaseModel):
    status: str = Field(..., description="open/investigating/resolved/false_positive")


class SetBaselineRequest(BaseModel):
    typical_protocols: List[str] = Field(default_factory=list)
    typical_ports: List[int] = Field(default_factory=list)
    typical_daily_bytes: int = Field(default=0, ge=0)
    typical_connections_per_hr: int = Field(default=0, ge=0)


class AddSegmentRequest(BaseModel):
    name: str = Field(..., min_length=1)
    cidr: str = Field(default="")
    segment_type: str = Field(default="internal", description="dmz/internal/cloud/ot/guest")
    sensitivity: str = Field(default="medium", description="critical/high/medium/low")


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------


@router.post("/flows", summary="Ingest a network flow")
def ingest_flow(
    body: IngestFlowRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Ingest a network flow, score its risk, and auto-alert if risk > 0.7."""
    return _get_engine().ingest_flow(org_id, body.model_dump())


@router.get("/flows", summary="List network flows")
def list_flows(
    flow_type: Optional[str] = Query(None, description="Filter by flow type"),
    min_risk: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum risk score"),
    limit: int = Query(100, ge=1, le=1000),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List network flows with optional flow_type and min_risk filters."""
    return _get_engine().list_flows(org_id, flow_type=flow_type, min_risk=min_risk, limit=limit)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@router.get("/alerts", summary="List network alerts")
def list_alerts(
    alert_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List network alerts with optional filters."""
    return _get_engine().list_alerts(org_id, alert_type=alert_type, status=status, severity=severity)


@router.patch("/alerts/{alert_id}/status", summary="Update alert status")
def update_alert_status(
    alert_id: str,
    body: UpdateAlertStatusRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Update the status of a network alert."""
    try:
        updated = _get_engine().update_alert_status(org_id, alert_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
    return {"alert_id": alert_id, "status": body.status}


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


@router.put("/baselines/{asset_ip}", summary="Set or update a baseline for an asset IP")
def set_baseline(
    asset_ip: str,
    body: SetBaselineRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Upsert a network behaviour baseline for an asset IP."""
    return _get_engine().set_baseline(org_id, asset_ip, body.model_dump())


@router.get("/baselines/{asset_ip}", summary="Get baseline for an asset IP")
def get_baseline(
    asset_ip: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Retrieve the stored baseline for an asset IP."""
    bl = _get_engine().get_baseline(org_id, asset_ip)
    if bl is None:
        raise HTTPException(status_code=404, detail=f"No baseline for IP {asset_ip!r}")
    return bl


# ---------------------------------------------------------------------------
# Segments
# ---------------------------------------------------------------------------


@router.post("/segments", summary="Add a network segment")
def add_segment(
    body: AddSegmentRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Add a network segment (DMZ, internal, cloud, OT, guest)."""
    return _get_engine().add_segment(org_id, body.model_dump())


@router.get("/segments", summary="List network segments")
def list_segments(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List all network segments for the org."""
    return _get_engine().list_segments(org_id)


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------


@router.post("/anomalies/detect", summary="Detect anomalies against baselines")
def detect_anomalies(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Compare recent 24h flows against stored baselines and return anomalies."""
    return _get_engine().detect_anomalies(org_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", summary="NDR statistics")
def get_ndr_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return aggregate NDR statistics for the org."""
    return _get_engine().get_ndr_stats(org_id)
