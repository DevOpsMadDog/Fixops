"""Network Monitoring API router — ALDECI.

Endpoints at /api/v1/network-monitoring/* for interface registration,
traffic sampling, alert rule management, and monitoring stats.
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
        "network_monitoring_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.network_monitoring_engine import NetworkMonitoringEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/network-monitoring",
    tags=["network-monitoring"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[NetworkMonitoringEngine] = None


def _get_engine() -> NetworkMonitoringEngine:
    global _engine
    if _engine is None:
        _engine = NetworkMonitoringEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RegisterInterfaceRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    name: str = Field(..., min_length=1, description="Interface name, e.g. eth0")
    ip: str = Field("", description="Interface IP address")
    if_type: str = Field("lan", description="Interface type: wan/lan/dmz")
    description: str = Field("", description="Optional description")


class TrafficSampleRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    bytes_in: int = Field(0, ge=0, description="Bytes received")
    bytes_out: int = Field(0, ge=0, description="Bytes transmitted")
    packets_in: int = Field(0, ge=0, description="Packets received")
    packets_out: int = Field(0, ge=0, description="Packets transmitted")
    timestamp: Optional[str] = Field(None, description="ISO-8601 sample timestamp")


class AlertRuleRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    interface_id: str = Field(..., description="Target interface ID")
    metric: str = Field("bytes_in", description="Metric to monitor")
    threshold: float = Field(0.0, ge=0, description="Alert threshold value")
    severity: str = Field("medium", description="Severity: critical/high/medium/low")


class TriggerAlertRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    value: float = Field(..., description="Observed metric value that triggered the rule")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Network monitoring summary (5-state envelope)")
def get_network_monitoring_summary(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """5-state envelope summarising network monitoring posture for the org.

    States: ok | warning | critical | empty | error
    Calls the real engine — no mocks.
    """
    engine = _get_engine()
    try:
        stats = engine.get_monitoring_stats(org_id)
        interfaces = stats.get("total_interfaces", 0)
        active_alerts = stats.get("active_alerts", stats.get("alerts_triggered", 0))
        critical_alerts = stats.get("critical_alerts", 0)

        if interfaces == 0:
            state = "empty"
            message = "No interfaces registered. Add interfaces via POST /interfaces."
        elif critical_alerts > 0:
            state = "critical"
            message = f"{critical_alerts} critical alert(s) across {interfaces} interface(s)."
        elif active_alerts > 0:
            state = "warning"
            message = f"{active_alerts} active alert(s) across {interfaces} interface(s)."
        else:
            state = "ok"
            message = f"{interfaces} interface(s) monitored, no active alerts."

        return {
            "state": state,
            "message": message,
            "org_id": org_id,
            "stats": stats,
            "links": {
                "interfaces": "/api/v1/network-monitoring/interfaces",
                "alert_rules": "/api/v1/network-monitoring/alert-rules",
                "alerts": "/api/v1/network-monitoring/alerts",
                "stats": "/api/v1/network-monitoring/stats",
            },
        }
    except Exception as exc:
        logger.exception("network_monitoring_summary_failed")
        return {
            "state": "error",
            "message": str(exc),
            "org_id": org_id,
            "stats": {},
            "links": {},
        }


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


@router.post("/interfaces", summary="Register a network interface")
def register_interface(body: RegisterInterfaceRequest) -> Dict[str, Any]:
    """Register a network interface (WAN/LAN/DMZ) for monitoring."""
    engine = _get_engine()
    try:
        return engine.register_interface(body.org_id, body.model_dump())
    except Exception as exc:
        logger.exception("Failed to register interface")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/interfaces", summary="List network interfaces")
def list_interfaces(
    org_id: str = Query("default", description="Organisation ID"),
    if_type: Optional[str] = Query(None, description="Filter by type: wan/lan/dmz"),
) -> List[Dict[str, Any]]:
    """List registered interfaces for an org with optional type filter."""
    engine = _get_engine()
    try:
        return engine.list_interfaces(org_id, if_type=if_type)
    except Exception as exc:
        logger.exception("Failed to list interfaces")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Traffic samples
# ---------------------------------------------------------------------------


@router.post("/interfaces/{interface_id}/samples", summary="Record a traffic sample")
def record_traffic_sample(
    interface_id: str,
    body: TrafficSampleRequest,
) -> Dict[str, Any]:
    """Record a traffic sample (bytes/packets) for a specific interface."""
    engine = _get_engine()
    try:
        return engine.record_traffic_sample(body.org_id, interface_id, body.model_dump())
    except Exception as exc:
        logger.exception("Failed to record traffic sample for interface %s", interface_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/interfaces/{interface_id}/stats", summary="Get traffic statistics")
def get_traffic_stats(
    interface_id: str,
    org_id: str = Query("default", description="Organisation ID"),
    hours: int = Query(24, ge=1, le=720, description="Lookback window in hours"),
) -> Dict[str, Any]:
    """Return avg_bps, peak_bps, and total_bytes for an interface over N hours."""
    engine = _get_engine()
    try:
        return engine.get_traffic_stats(org_id, interface_id, hours=hours)
    except Exception as exc:
        logger.exception("Failed to get traffic stats for interface %s", interface_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Alert rules
# ---------------------------------------------------------------------------


@router.post("/alert-rules", summary="Create an alert rule")
def create_alert_rule(body: AlertRuleRequest) -> Dict[str, Any]:
    """Create an alert rule that triggers when a metric exceeds a threshold."""
    engine = _get_engine()
    try:
        return engine.create_alert_rule(body.org_id, body.model_dump())
    except Exception as exc:
        logger.exception("Failed to create alert rule")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/alert-rules", summary="List alert rules")
def list_alert_rules(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Dict[str, Any]]:
    """List all alert rules for an org."""
    engine = _get_engine()
    try:
        return engine.list_alert_rules(org_id)
    except Exception as exc:
        logger.exception("Failed to list alert rules")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@router.post("/alert-rules/{rule_id}/trigger", summary="Trigger an alert for a rule")
def trigger_alert(rule_id: str, body: TriggerAlertRequest) -> Dict[str, Any]:
    """Manually trigger an alert for a rule with an observed metric value."""
    engine = _get_engine()
    try:
        return engine.trigger_alert(body.org_id, rule_id, body.value)
    except Exception as exc:
        logger.exception("Failed to trigger alert for rule %s", rule_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/alerts", summary="List triggered alerts")
def list_alerts(
    org_id: str = Query("default", description="Organisation ID"),
    severity: Optional[str] = Query(None, description="Filter by severity: critical/high/medium/low"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> List[Dict[str, Any]]:
    """List triggered alerts for an org with optional severity filter."""
    engine = _get_engine()
    try:
        return engine.list_alerts(org_id, severity=severity, limit=limit)
    except Exception as exc:
        logger.exception("Failed to list alerts")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", summary="Get monitoring stats")
def get_monitoring_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregate monitoring stats: interface count, sample count, alert count."""
    engine = _get_engine()
    try:
        return engine.get_monitoring_stats(org_id)
    except Exception as exc:
        logger.exception("Failed to get monitoring stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
