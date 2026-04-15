"""Bandwidth Analysis API router — ALDECI.

Endpoints at /api/v1/bandwidth-analysis/* for link registration,
utilization tracking, anomaly detection, QoS policy management, and stats.
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
        "bandwidth_analysis_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.bandwidth_analysis_engine import BandwidthAnalysisEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/bandwidth-analysis",
    tags=["bandwidth-analysis"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[BandwidthAnalysisEngine] = None


def _get_engine() -> BandwidthAnalysisEngine:
    global _engine
    if _engine is None:
        _engine = BandwidthAnalysisEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RegisterLinkRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    name: str = Field(..., min_length=1, description="Link name, e.g. WAN-Primary")
    capacity_mbps: float = Field(0.0, ge=0, description="Link capacity in Mbps")
    link_type: str = Field("internet", description="Link type: fiber/vpn/internet/mpls")


class RecordUtilizationRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    utilization_pct: float = Field(0.0, ge=0.0, le=100.0, description="Utilization percentage 0-100")
    direction: str = Field("both", description="Traffic direction: inbound/outbound/both")
    recorded_at: Optional[str] = Field(None, description="ISO-8601 timestamp")


class QoSPolicyRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    name: str = Field(..., min_length=1, description="Policy name")
    priority: int = Field(4, ge=1, le=8, description="QoS priority 1 (highest) to 8 (lowest)")
    traffic_class: str = Field("", description="Traffic class, e.g. 'voice', 'bulk', 'critical'")
    bandwidth_limit_pct: float = Field(100.0, ge=0.0, le=100.0, description="Bandwidth cap 0-100%")


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------


@router.post("/links", summary="Register a network link")
def register_link(body: RegisterLinkRequest) -> Dict[str, Any]:
    """Register a network link (fiber/VPN/internet/MPLS) for bandwidth analysis."""
    engine = _get_engine()
    try:
        return engine.register_link(body.org_id, body.model_dump())
    except Exception as exc:
        logger.exception("Failed to register link")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/links", summary="List network links")
def list_links(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Dict[str, Any]]:
    """List all registered links for an org."""
    engine = _get_engine()
    try:
        return engine.list_links(org_id)
    except Exception as exc:
        logger.exception("Failed to list links")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Utilization
# ---------------------------------------------------------------------------


@router.post("/links/{link_id}/utilization", summary="Record utilization sample")
def record_utilization(
    link_id: str,
    body: RecordUtilizationRequest,
) -> Dict[str, Any]:
    """Record a utilization sample (0-100%) for a specific link."""
    engine = _get_engine()
    try:
        return engine.record_utilization(body.org_id, link_id, body.model_dump())
    except Exception as exc:
        logger.exception("Failed to record utilization for link %s", link_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/links/{link_id}/trend", summary="Get utilization trend")
def get_utilization_trend(
    link_id: str,
    org_id: str = Query("default", description="Organisation ID"),
    hours: int = Query(24, ge=1, le=720, description="Lookback window in hours"),
) -> Dict[str, Any]:
    """Return avg_pct, peak_pct, and per-sample data for a link over N hours."""
    engine = _get_engine()
    try:
        return engine.get_utilization_trend(org_id, link_id, hours=hours)
    except Exception as exc:
        logger.exception("Failed to get utilization trend for link %s", link_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/links/{link_id}/anomaly", summary="Detect bandwidth anomaly")
def detect_anomaly(
    link_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Detect utilization anomaly for a link using z-score against historical baseline."""
    engine = _get_engine()
    try:
        return engine.detect_anomaly(org_id, link_id)
    except Exception as exc:
        logger.exception("Failed to detect anomaly for link %s", link_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# QoS policies
# ---------------------------------------------------------------------------


@router.post("/qos-policies", summary="Create a QoS policy")
def create_qos_policy(body: QoSPolicyRequest) -> Dict[str, Any]:
    """Create a QoS policy for traffic prioritisation and bandwidth capping."""
    engine = _get_engine()
    try:
        return engine.create_qos_policy(body.org_id, body.model_dump())
    except Exception as exc:
        logger.exception("Failed to create QoS policy")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/qos-policies", summary="List QoS policies")
def list_qos_policies(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Dict[str, Any]]:
    """List QoS policies for an org ordered by priority."""
    engine = _get_engine()
    try:
        return engine.list_qos_policies(org_id)
    except Exception as exc:
        logger.exception("Failed to list QoS policies")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", summary="Get bandwidth stats")
def get_bandwidth_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregate bandwidth stats: total links, avg utilization, high-util links."""
    engine = _get_engine()
    try:
        return engine.get_bandwidth_stats(org_id)
    except Exception as exc:
        logger.exception("Failed to get bandwidth stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
