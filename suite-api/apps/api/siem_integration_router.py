"""SIEM Integration API Router — ALDECI.

Endpoints (all under /api/v1/siem):

  Legacy integration endpoints (backward compat):
    GET  /integrations              — list registered SIEMs
    POST /integrations              — register a new SIEM
    GET  /integrations/{siem_id}    — get a single SIEM
    PUT  /integrations/{siem_id}/status — enable/disable a SIEM
    POST /correlate                 — apply a correlation rule
    POST /alerts/resolve/{alert_id} — resolve a legacy alert

  Source-based endpoints (new schema):
    POST /sources                   — register a SIEM source
    GET  /sources                   — list sources (filters: source_type, status)
    GET  /sources/{source_id}       — get a single source
    POST /events                    — ingest a SIEM event
    GET  /events                    — list events (filters: source_id, severity, event_type)
    POST /alerts                    — create correlation alert
    GET  /alerts                    — list alerts (filters: status, severity)
    PUT  /alerts/{alert_id}/acknowledge — acknowledge a correlation alert
    GET  /stats                     — aggregate stats

Auth: api_key_auth injected via Depends.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.siem_integration_engine import SIEMIntegrationEngine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/siem", tags=["siem-integration"])

# Lazy singleton
_engine: Optional[SIEMIntegrationEngine] = None


def _get_engine() -> SIEMIntegrationEngine:
    global _engine
    if _engine is None:
        _engine = SIEMIntegrationEngine()
    return _engine


def _api_key_auth() -> None:  # noqa: D401
    """Placeholder — replaced by app-level dependency injection."""


# ---------------------------------------------------------------------------
# Pydantic models — source-based (new schema)
# ---------------------------------------------------------------------------


class SIEMSourceCreate(BaseModel):
    org_id: str = "default"
    name: str
    source_type: str
    host: Optional[str] = None
    port: Optional[int] = None


class SIEMEventIngest(BaseModel):
    org_id: str = "default"
    source_id: str
    event_type: str
    severity: str = "info"
    raw_data: Any = Field(default_factory=dict)
    parsed_fields: Optional[Dict[str, Any]] = None


class CorrelationAlertCreate(BaseModel):
    org_id: str = "default"
    title: str
    rule_name: str
    severity: str = "medium"
    matched_events: List[str] = Field(default_factory=list)


class AlertAcknowledge(BaseModel):
    org_id: str = "default"
    acknowledged_by: str


# ---------------------------------------------------------------------------
# Pydantic models — legacy (kept for backward compat)
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
# Source-based endpoints (new schema)
# ---------------------------------------------------------------------------


@router.post("/sources")
def create_source(body: SIEMSourceCreate) -> Dict[str, Any]:
    """Register a new SIEM source."""
    try:
        result = _get_engine().register_siem_source(body.org_id, body.model_dump())
        return {"status": "created", "source": result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to register SIEM source")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/sources")
def list_sources(
    org_id: str = Query("default"),
    source_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List SIEM sources for an org."""
    sources = _get_engine().list_siem_sources(org_id, source_type=source_type, status=status)
    return {"org_id": org_id, "sources": sources, "total": len(sources)}


@router.get("/sources/{source_id}")
def get_source(source_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Get a single SIEM source."""
    try:
        return _get_engine().get_siem_source(org_id, source_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/events")
def ingest_event(body: SIEMEventIngest) -> Dict[str, Any]:
    """Ingest a SIEM event for a source."""
    try:
        result = _get_engine().ingest_siem_event(body.org_id, body.model_dump())
        return {"status": "ingested", "event": result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to ingest SIEM event")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/events")
def list_events(
    org_id: str = Query("default"),
    source_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List SIEM events with optional filters."""
    events = _get_engine().list_siem_events(
        org_id, source_id=source_id, severity=severity, event_type=event_type
    )
    return {"org_id": org_id, "events": events, "total": len(events)}


@router.get("/events/search")
def search_events(
    q: str = Query(..., description="Keyword or phrase to search across event raw_data and parsed_fields"),
    org_id: str = Query("default"),
    source_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """Full-text keyword search across SIEM event raw_data and parsed_fields.

    Performs a case-insensitive substring match of ``q`` against the
    ``raw_data`` and ``parsed_fields`` columns of ``siem_source_events``.
    Results are ordered newest-first.

    Optional column-level filters (source_id, severity, event_type) are
    ANDed with the keyword filter.
    """
    events = _get_engine().search_events(
        org_id,
        q=q,
        source_id=source_id,
        severity=severity,
        event_type=event_type,
        limit=limit,
    )
    return {
        "org_id": org_id,
        "q": q,
        "events": events,
        "total": len(events),
    }


@router.post("/alerts")
def create_alert(body: CorrelationAlertCreate) -> Dict[str, Any]:
    """Create a correlation alert."""
    try:
        result = _get_engine().create_correlation_alert(body.org_id, body.model_dump())
        return {"status": "created", "alert": result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create correlation alert")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/alerts")
def list_alerts(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List correlation alerts for an org."""
    alerts = _get_engine().list_correlation_alerts(org_id, status=status, severity=severity)
    return {"org_id": org_id, "alerts": alerts, "total": len(alerts)}


@router.put("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str, body: AlertAcknowledge) -> Dict[str, Any]:
    """Acknowledge a correlation alert."""
    try:
        result = _get_engine().acknowledge_alert(body.org_id, alert_id, body.acknowledged_by)
        return {"status": "acknowledged", "alert": result}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/stats")
def get_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get aggregate SIEM statistics for an org."""
    return _get_engine().get_siem_stats(org_id)


# ---------------------------------------------------------------------------
# Raw syslog / CEF ingestion endpoint
# ---------------------------------------------------------------------------


class RawIngestIn(BaseModel):
    org_id: str = "default"
    raw: str = Field(..., description="Raw syslog (RFC 3164/5424) or CEF log line")
    format: str = Field(
        default="auto",
        description="'syslog' | 'cef' | 'auto' (default — auto-detected from content)",
    )


@router.post("/ingest")
def ingest_raw(body: RawIngestIn) -> Dict[str, Any]:
    """Parse and ingest a raw syslog or CEF log line as a SIEM event.

    Accepts:
    - Syslog RFC 3164: ``<PRI>Mmm DD HH:MM:SS hostname tag: message``
    - Syslog RFC 5424: ``<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...``
    - CEF: ``CEF:0|Vendor|Product|Version|SigID|Name|Severity|extensions``
    - format="auto" (default) detects CEF by presence of "CEF:" prefix.

    Returns the normalised, stored event record including parsed fields.
    """
    try:
        event = _get_engine().ingest_raw(body.org_id, body.raw, body.format)
        return {"status": "ingested", "format": body.format, "event": event}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to ingest raw log line")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Correlation rules endpoints
# ---------------------------------------------------------------------------


class CorrelationRuleCreate(BaseModel):
    org_id: str = "default"
    name: str
    description: str = ""
    event_type: Optional[str] = None
    severity: Optional[str] = None
    field: str = "user"
    threshold: int = 5
    window_hours: int = 1
    action: str = "repeated_event"
    enabled: bool = True


@router.post("/correlation-rules")
def create_correlation_rule(body: CorrelationRuleCreate) -> Dict[str, Any]:
    """Create a named correlation rule."""
    try:
        result = _get_engine().create_correlation_rule(body.org_id, body.model_dump())
        return {"status": "created", "rule": result}
    except Exception as exc:
        logger.exception("Failed to create correlation rule")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/correlation-rules")
def list_correlation_rules(
    org_id: str = Query("default"),
    enabled_only: bool = Query(False),
) -> Dict[str, Any]:
    """List correlation rules for an org."""
    rules = _get_engine().list_correlation_rules(org_id, enabled_only=enabled_only)
    return {"org_id": org_id, "rules": rules, "total": len(rules)}


@router.get("/correlation-rules/{rule_id}")
def get_correlation_rule(rule_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Get a single correlation rule by ID."""
    rule = _get_engine().get_correlation_rule(org_id, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    return rule


@router.delete("/correlation-rules/{rule_id}")
def delete_correlation_rule(rule_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Delete a correlation rule."""
    deleted = _get_engine().delete_correlation_rule(org_id, rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    return {"status": "deleted", "rule_id": rule_id}


@router.post("/correlation-rules/{rule_id}/run")
def run_correlation_rule(rule_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Execute a stored correlation rule against recent events."""
    try:
        result = _get_engine().run_correlation_rule(org_id, rule_id)
        return {"status": "ok", **result}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to run correlation rule")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Legacy endpoints (backward compat)
# ---------------------------------------------------------------------------


@router.get("/integrations")
def list_integrations(org_id: str = Query("default")) -> Dict[str, Any]:
    """List all registered SIEM integrations (legacy)."""
    siems = _get_engine().list_siems(org_id)
    return {"org_id": org_id, "siems": siems, "total": len(siems)}


@router.post("/integrations")
def register_integration(body: SIEMRegisterIn) -> Dict[str, Any]:
    """Register a new SIEM integration (legacy)."""
    try:
        result = _get_engine().register_siem(body.org_id, body.model_dump())
        return {"status": "registered", "siem": result}
    except Exception as exc:
        logger.exception("Failed to register SIEM")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/integrations/{siem_id}")
def get_integration(siem_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Get a single SIEM integration (legacy)."""
    siem = _get_engine().get_siem(org_id, siem_id)
    if not siem:
        raise HTTPException(status_code=404, detail="SIEM integration not found")
    return siem


@router.put("/integrations/{siem_id}/status")
def update_integration_status(siem_id: str, body: SIEMStatusIn) -> Dict[str, Any]:
    """Enable or disable a SIEM integration (legacy)."""
    ok = _get_engine().update_siem_status(body.org_id, siem_id, body.enabled)
    if not ok:
        raise HTTPException(status_code=404, detail="SIEM integration not found")
    return {"status": "updated", "siem_id": siem_id, "enabled": body.enabled}


@router.post("/alerts/{alert_id}/resolve")
def resolve_legacy_alert(alert_id: str, body: AlertResolveIn) -> Dict[str, Any]:
    """Resolve a legacy SIEM alert."""
    ok = _get_engine().resolve_alert(
        body.org_id, alert_id, body.resolved_by, body.resolution_notes
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "resolved", "alert_id": alert_id}
