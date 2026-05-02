"""Security Event Timeline Router — ALDECI.

Endpoints for the Security Event Timeline engine.

Prefix: /api/v1/event-timeline
Auth:   api_key_auth dependency on ALL endpoints

Routes:
  POST /api/v1/event-timeline/timelines                       create_timeline
  POST /api/v1/event-timeline/events                          add_event
  POST /api/v1/event-timeline/correlations                    correlate_events
  PUT  /api/v1/event-timeline/timelines/{id}/close            close_timeline
  GET  /api/v1/event-timeline/timelines/{incident_id}         get_timeline
  GET  /api/v1/event-timeline/events/{incident_id}            get_event_sequence
  GET  /api/v1/event-timeline/actor/{incident_id}/{actor}     get_actor_activity
  GET  /api/v1/event-timeline/summary                         get_timeline_summary
  GET  /api/v1/event-timeline/search                          search_events
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/event-timeline",
    tags=["Security Event Timeline"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_event_timeline_engine import SecurityEventTimelineEngine
        _engine = SecurityEventTimelineEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TimelineCreate(BaseModel):
    incident_id: str
    title: str


class EventCreate(BaseModel):
    incident_id: str
    event_time: str
    event_type: str
    source_system: str
    actor: str = ""
    target: str = ""
    action: str
    outcome: str = "unknown"
    severity: str = "medium"
    raw_data: str = ""
    tags: List[str] = Field(default_factory=list)


class CorrelationCreate(BaseModel):
    incident_id: str
    primary_event_id: str
    correlated_event_id: str
    correlation_type: str
    confidence: float = 0.5


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/timelines", status_code=201)
def create_timeline(body: TimelineCreate, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Create a new incident timeline."""
    try:
        return _get_engine().create_timeline(org_id, body.incident_id, body.title)
    except Exception as exc:
        _logger.exception("create_timeline failed")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/events", status_code=201)
def add_event(body: EventCreate, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Add a security event to an incident timeline."""
    try:
        return _get_engine().add_event(
            org_id=org_id,
            incident_id=body.incident_id,
            event_time=body.event_time,
            event_type=body.event_type,
            source_system=body.source_system,
            actor=body.actor,
            target=body.target,
            action=body.action,
            outcome=body.outcome,
            severity=body.severity,
            raw_data=body.raw_data,
            tags=body.tags,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("add_event failed")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/correlations", status_code=201)
def correlate_events(body: CorrelationCreate, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Create a correlation between two timeline events."""
    try:
        return _get_engine().correlate_events(
            org_id=org_id,
            incident_id=body.incident_id,
            primary_event_id=body.primary_event_id,
            correlated_event_id=body.correlated_event_id,
            correlation_type=body.correlation_type,
            confidence=body.confidence,
        )
    except Exception as exc:
        _logger.exception("correlate_events failed")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/timelines/{timeline_id}/close")
def close_timeline(timeline_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Close an incident timeline."""
    try:
        return _get_engine().close_timeline(timeline_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("close_timeline failed")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/timelines/{incident_id}")
def get_timeline(incident_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get timeline header + events + correlations for an incident."""
    result = _get_engine().get_timeline(org_id, incident_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Timeline for incident {incident_id!r} not found.")
    return result


@router.get("/events/{incident_id}")
def get_event_sequence(
    incident_id: str,
     org_id: str = Query(default="default"),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """Get ordered event sequence for an incident, with optional time range filter."""
    return _get_engine().get_event_sequence(org_id, incident_id, start_time, end_time)


@router.get("/actor/{incident_id}/{actor}")
def get_actor_activity(
    incident_id: str,
    actor: str,
     org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    """Get all events for a specific actor in an incident."""
    return _get_engine().get_actor_activity(org_id, incident_id, actor)


@router.get("/summary")
def get_timeline_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get org-level summary of all timelines."""
    return _get_engine().get_timeline_summary(org_id)


@router.get("/search")
def search_events(
     org_id: str = Query(default="default"),
    q: str = Query(..., description="Search query (LIKE match on actor/target/action/raw_data)"),
) -> List[Dict[str, Any]]:
    """Search events by actor, target, action, or raw_data."""
    return _get_engine().search_events(org_id, q)
