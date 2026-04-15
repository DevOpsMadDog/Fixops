"""SIEM Integration API Router — ALDECI.

Endpoints (all under /api/v1/siem):

  Integrations:
    GET  /integrations              — list registered SIEMs
    POST /integrations              — register a new SIEM
    GET  /integrations/{siem_id}    — get a single SIEM
    PUT  /integrations/{siem_id}/status — enable/disable a SIEM

  Events:
    GET  /events                    — list events (filters: siem_id, event_type, severity, hours)
    POST /events                    — ingest a new event

  Correlation:
    POST /correlate                 — apply a correlation rule

  Alerts:
    GET  /alerts                    — list alerts (filters: status, severity)
    POST /alerts                    — create an alert
    POST /alerts/{alert_id}/resolve — resolve an alert

  Stats:
    GET  /stats                     — aggregate SIEM statistics

Auth: _verify_api_key injected at app.include_router() level.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.siem_integration_engine import SIEMIntegrationEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/siem", tags=["siem-integration"])

_engine = SIEMIntegrationEngine()

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class SIEMRegisterIn(BaseModel):
    siem_name: str = ""
    siem_type: str = "generic"
    host: str = ""
    port: int = 0
    api_token: str = ""
    enabled: bool = True
    index_name: str = ""
    org_id: str = "default"


class SIEMStatusIn(BaseModel):
    enabled: bool
    org_id: str = "default"


class EventIngestIn(BaseModel):
    siem_id: str = ""
    raw_event: Dict[str, Any] = Field(default_factory=dict)
    event_type: str = "application"
    severity: str = "info"
    source_ip: str = ""
    destination_ip: str = ""
    user: str = ""
    timestamp: str = ""
    org_id: str = "default"


class CorrelationRuleIn(BaseModel):
    event_type: Optional[str] = None
    severity: Optional[str] = None
    field: str = "user"
    threshold: int = 5
    window_hours: int = 1
    action: str = "repeated_event"
    org_id: str = "default"


class AlertCreateIn(BaseModel):
    title: str = ""
    description: str = ""
    severity: str = "medium"
    source_event_ids: List[str] = Field(default_factory=list)
    assignee: str = ""
    org_id: str = "default"


class AlertResolveIn(BaseModel):
    resolved_by: str
    resolution_notes: str = ""
    org_id: str = "default"


# ---------------------------------------------------------------------------
# SIEM Integration endpoints
# ---------------------------------------------------------------------------


@router.get("/integrations")
def list_integrations(org_id: str = Query("default")) -> Dict[str, Any]:
    """List all registered SIEM integrations."""
    siems = _engine.list_siems(org_id)
    return {"org_id": org_id, "siems": siems, "total": len(siems)}


@router.post("/integrations")
def register_integration(body: SIEMRegisterIn) -> Dict[str, Any]:
    """Register a new SIEM integration."""
    try:
        result = _engine.register_siem(body.org_id, body.model_dump())
        return {"status": "registered", "siem": result}
    except Exception as exc:
        logger.exception("Failed to register SIEM")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/integrations/{siem_id}")
def get_integration(siem_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Get a single SIEM integration."""
    siem = _engine.get_siem(org_id, siem_id)
    if not siem:
        raise HTTPException(status_code=404, detail="SIEM integration not found")
    return siem


@router.put("/integrations/{siem_id}/status")
def update_integration_status(siem_id: str, body: SIEMStatusIn) -> Dict[str, Any]:
    """Enable or disable a SIEM integration."""
    ok = _engine.update_siem_status(body.org_id, siem_id, body.enabled)
    if not ok:
        raise HTTPException(status_code=404, detail="SIEM integration not found")
    return {"status": "updated", "siem_id": siem_id, "enabled": body.enabled}


# ---------------------------------------------------------------------------
# Event endpoints
# ---------------------------------------------------------------------------


@router.get("/events")
def list_events(
    org_id: str = Query("default"),
    siem_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    hours: int = Query(24, ge=1, le=168),
) -> Dict[str, Any]:
    """List SIEM events with optional filters."""
    events = _engine.list_events(
        org_id,
        siem_id=siem_id,
        event_type=event_type,
        severity=severity,
        limit=limit,
        hours=hours,
    )
    return {"org_id": org_id, "events": events, "total": len(events)}


@router.post("/events")
def ingest_event(body: EventIngestIn) -> Dict[str, Any]:
    """Ingest and normalize a SIEM event."""
    try:
        result = _engine.ingest_event(body.org_id, body.model_dump())
        return {"status": "ingested", "event": result}
    except Exception as exc:
        logger.exception("Failed to ingest event")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Correlation endpoint
# ---------------------------------------------------------------------------


@router.post("/correlate")
def correlate_events(body: CorrelationRuleIn) -> Dict[str, Any]:
    """Apply a correlation rule and return matched event groups."""
    rule = body.model_dump()
    org_id = rule.pop("org_id", "default")
    matched = _engine.correlate_events(org_id, rule)
    return {"org_id": org_id, "matched_groups": matched, "total": len(matched)}


# ---------------------------------------------------------------------------
# Alert endpoints
# ---------------------------------------------------------------------------


@router.get("/alerts")
def list_alerts(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """List SIEM alerts."""
    alerts = _engine.list_alerts(org_id, status=status, severity=severity, limit=limit)
    return {"org_id": org_id, "alerts": alerts, "total": len(alerts)}


@router.post("/alerts")
def create_alert(body: AlertCreateIn) -> Dict[str, Any]:
    """Create a new SIEM alert."""
    try:
        result = _engine.create_alert(body.org_id, body.model_dump())
        return {"status": "created", "alert": result}
    except Exception as exc:
        logger.exception("Failed to create alert")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: str, body: AlertResolveIn) -> Dict[str, Any]:
    """Resolve a SIEM alert."""
    ok = _engine.resolve_alert(
        body.org_id, alert_id, body.resolved_by, body.resolution_notes
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "resolved", "alert_id": alert_id}


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get aggregate SIEM statistics for an org."""
    return _engine.get_siem_stats(org_id)
