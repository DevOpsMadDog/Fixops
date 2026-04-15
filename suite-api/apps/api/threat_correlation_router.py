"""Threat Correlation Router — ALDECI.

Exposes the ThreatCorrelationEngine via REST API.

Compliance: NIST CSF DE.AE-2, SOC2 CC7.1, MITRE ATT&CK correlation layer
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from apps.api.auth_deps import api_key_auth
from core.threat_correlation_engine import ThreatCorrelationEngine

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threat-correlation", tags=["threat-correlation"])

# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[ThreatCorrelationEngine] = None


def get_threat_correlation_engine() -> ThreatCorrelationEngine:
    global _engine
    if _engine is None:
        _engine = ThreatCorrelationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RuleBody(BaseModel):
    name: str = "Unnamed Rule"
    description: str = ""
    event_types: list = []
    time_window_minutes: int = 60
    threshold: int = 3
    severity: str = "medium"
    correlation_logic: Dict[str, Any] = {}
    enabled: bool = True


class EventBody(BaseModel):
    event_type: str
    source_ip: str = ""
    user_id: str = ""
    asset_id: str = ""
    timestamp: Optional[str] = None
    raw_data: Dict[str, Any] = {}


class CloseAlertBody(BaseModel):
    resolution: str


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@router.get("/rules")
def list_rules(
    org_id: str = Query(..., description="Organisation identifier"),
    engine: ThreatCorrelationEngine = Depends(get_threat_correlation_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List all correlation rules for an org."""
    rules = engine.list_rules(org_id)
    return {"org_id": org_id, "count": len(rules), "rules": rules}


@router.post("/rules", status_code=201)
def create_rule(
    body: RuleBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: ThreatCorrelationEngine = Depends(get_threat_correlation_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Create a new correlation rule."""
    rule = engine.create_rule(org_id, body.model_dump())
    return rule


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


@router.get("/events")
def list_events(
    org_id: str = Query(..., description="Organisation identifier"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    hours_back: int = Query(24, ge=1, le=8760, description="Look-back window in hours"),
    engine: ThreatCorrelationEngine = Depends(get_threat_correlation_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List recent security events for an org."""
    events = engine.list_events(org_id, event_type=event_type, hours_back=hours_back)
    return {"org_id": org_id, "hours_back": hours_back, "count": len(events), "events": events}


@router.post("/events", status_code=201)
def ingest_event(
    body: EventBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: ThreatCorrelationEngine = Depends(get_threat_correlation_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Ingest a security event."""
    event = engine.ingest_event(org_id, body.model_dump())
    return event


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


@router.post("/correlate")
def correlate(
    org_id: str = Query(..., description="Organisation identifier"),
    engine: ThreatCorrelationEngine = Depends(get_threat_correlation_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Run all enabled correlation rules against recent events. Returns new alerts."""
    new_alerts = engine.correlate(org_id)
    return {"org_id": org_id, "new_alerts_created": len(new_alerts), "alerts": new_alerts}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@router.get("/alerts")
def list_alerts(
    org_id: str = Query(..., description="Organisation identifier"),
    status: Optional[str] = Query(None, description="Filter by status (open/investigating/closed)"),
    engine: ThreatCorrelationEngine = Depends(get_threat_correlation_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List correlation alerts for an org."""
    alerts = engine.list_alerts(org_id, status=status)
    return {"org_id": org_id, "count": len(alerts), "alerts": alerts}


@router.post("/alerts/{alert_id}/close")
def close_alert(
    alert_id: str,
    body: CloseAlertBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: ThreatCorrelationEngine = Depends(get_threat_correlation_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Close a correlation alert with a resolution note."""
    updated = engine.close_alert(org_id, alert_id, body.resolution)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found or already closed")
    return {"alert_id": alert_id, "status": "closed", "resolution": body.resolution}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(
    org_id: str = Query(..., description="Organisation identifier"),
    engine: ThreatCorrelationEngine = Depends(get_threat_correlation_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return correlation statistics for an org."""
    return engine.get_correlation_stats(org_id)
