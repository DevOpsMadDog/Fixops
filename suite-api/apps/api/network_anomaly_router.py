"""Network Anomaly API router — ALDECI.

Endpoints at /api/v1/network-anomaly/* for recording traffic samples,
updating baselines, detecting anomalies, resolving alerts, and trend views.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "network_anomaly_router: auth_deps not available"
    )
    _AUTH_DEP = []

from core.network_anomaly_engine import NetworkAnomalyEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/network-anomaly",
    tags=["network-anomaly"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[NetworkAnomalyEngine] = None


def _get_engine() -> NetworkAnomalyEngine:
    global _engine
    if _engine is None:
        _engine = NetworkAnomalyEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class TrafficSampleRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    segment: str = Field(..., min_length=1, description="Network segment name")
    protocol: str = Field("TCP", description="TCP/UDP/ICMP/HTTP/HTTPS/DNS/SMTP/FTP/SSH/other")
    direction: str = Field("inbound", description="inbound/outbound/lateral")
    bytes_per_min: float = Field(0.0, ge=0.0, description="Bytes per minute")
    packets_per_min: float = Field(0.0, ge=0.0, description="Packets per minute")


class BaselineUpdateRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    segment: str = Field(..., min_length=1, description="Network segment name")
    protocol: str = Field("TCP", description="Protocol")
    direction: str = Field("inbound", description="Traffic direction")


class DetectAnomalyRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    segment: str = Field(..., min_length=1, description="Network segment name")
    protocol: str = Field("TCP", description="Protocol")
    direction: str = Field("inbound", description="Traffic direction")
    bytes_per_min: float = Field(0.0, ge=0.0, description="Observed bytes per minute")
    packets_per_min: float = Field(0.0, ge=0.0, description="Observed packets per minute")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/samples", summary="Record a traffic sample")
def record_sample(req: TrafficSampleRequest) -> Dict[str, Any]:
    try:
        return _get_engine().record_sample(
            org_id=req.org_id,
            segment=req.segment,
            protocol=req.protocol,
            direction=req.direction,
            bytes_per_min=req.bytes_per_min,
            packets_per_min=req.packets_per_min,
        )
    except Exception as exc:
        logger.exception("record_sample failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/baselines/update", summary="Update baseline from recent samples")
def update_baseline(req: BaselineUpdateRequest) -> Dict[str, Any]:
    try:
        return _get_engine().update_baseline(
            org_id=req.org_id,
            segment=req.segment,
            protocol=req.protocol,
            direction=req.direction,
        )
    except Exception as exc:
        logger.exception("update_baseline failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/detect", summary="Detect anomalies against current baseline")
def detect_anomalies(req: DetectAnomalyRequest) -> List[Dict[str, Any]]:
    try:
        return _get_engine().detect_anomalies(
            org_id=req.org_id,
            segment=req.segment,
            protocol=req.protocol,
            direction=req.direction,
            bytes_per_min=req.bytes_per_min,
            packets_per_min=req.packets_per_min,
        )
    except Exception as exc:
        logger.exception("detect_anomalies failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/anomalies/{anomaly_id}/resolve", summary="Resolve a network anomaly")
def resolve_anomaly(
    anomaly_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().resolve_anomaly(anomaly_id=anomaly_id, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception("resolve_anomaly failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/summary", summary="Get anomaly summary for org")
def get_anomaly_summary(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_anomaly_summary(org_id=org_id)
    except Exception as exc:
        logger.exception("get_anomaly_summary failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/baselines", summary="Get baseline health for org")
def get_baseline_health(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().get_baseline_health(org_id=org_id)
    except Exception as exc:
        logger.exception("get_baseline_health failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/traffic-trend", summary="Get traffic trend for segment/protocol")
def get_traffic_trend(
    org_id: str = Query("default", description="Organisation ID"),
    segment: str = Query(..., description="Network segment"),
    protocol: str = Query("TCP", description="Protocol"),
    hours: int = Query(24, ge=1, le=720, description="Hours of history to return"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().get_traffic_trend(
            org_id=org_id, segment=segment, protocol=protocol, hours=hours
        )
    except Exception as exc:
        logger.exception("get_traffic_trend failed")
        raise HTTPException(status_code=500, detail=str(exc))
