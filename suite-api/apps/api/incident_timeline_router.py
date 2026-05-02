"""Incident Timeline Router — ALDECI.

Exposes CRUD for incident timelines, events, affected systems, and metrics.
Prefix: /api/v1/incident-timeline
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/incident-timeline",
    tags=["Incident Timeline Builder"],
)

# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.incident_timeline_engine import IncidentTimelineEngine
        _engine = IncidentTimelineEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TimelineCreate(BaseModel):
    title: str
    incident_type: str = "unknown"
    severity: str = "medium"
    summary: str = ""
    started_at: Optional[str] = None


class TimelineStatusUpdate(BaseModel):
    status: str
    timestamp_field: Optional[str] = None


class EventCreate(BaseModel):
    event_time: Optional[str] = None
    event_type: str = "action"
    title: str
    description: str = ""
    actor: str = ""
    source_system: str = ""
    evidence_refs: List[Any] = Field(default_factory=list)
    severity: str = "info"


class AffectedSystemCreate(BaseModel):
    hostname: str = ""
    ip_address: str = ""
    system_type: str = ""
    affected_at: Optional[str] = None
    restored_at: Optional[str] = None
    impact_description: str = ""


# ---------------------------------------------------------------------------
# Timeline endpoints
# ---------------------------------------------------------------------------

@router.post("", dependencies=[Depends(api_key_auth)], status_code=201)
def create_timeline(body: TimelineCreate, org_id: str = Query(default="default")):
    """Create a new incident timeline."""
    try:
        return _get_engine().create_timeline(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("", dependencies=[Depends(api_key_auth)])
def list_timelines(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    incident_type: Optional[str] = Query(None),
):
    """List incident timelines with optional status/type filters."""
    return _get_engine().list_timelines(org_id, status=status, incident_type=incident_type)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")):
    """Return aggregate timeline statistics for an org."""
    return _get_engine().get_timeline_stats(org_id)


@router.get("/{timeline_id}", dependencies=[Depends(api_key_auth)])
def get_timeline(timeline_id: str, org_id: str = Query(default="default")):
    """Get a single incident timeline by ID."""
    tl = _get_engine().get_timeline(org_id, timeline_id)
    if not tl:
        raise HTTPException(status_code=404, detail="Timeline not found")
    return tl


@router.patch("/{timeline_id}/status", dependencies=[Depends(api_key_auth)])
def update_status(
    timeline_id: str,
    body: TimelineStatusUpdate,
     org_id: str = Query(default="default"),
):
    """Update the status of an incident timeline."""
    try:
        updated = _get_engine().update_timeline_status(
            org_id, timeline_id, body.status, body.timestamp_field
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Timeline not found")
    return {"updated": True, "timeline_id": timeline_id, "status": body.status}


# ---------------------------------------------------------------------------
# Event endpoints
# ---------------------------------------------------------------------------

@router.post("/{timeline_id}/events", dependencies=[Depends(api_key_auth)], status_code=201)
def add_event(
    timeline_id: str,
    body: EventCreate,
     org_id: str = Query(default="default"),
):
    """Add an event to an incident timeline."""
    try:
        return _get_engine().add_event(org_id, timeline_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{timeline_id}/events", dependencies=[Depends(api_key_auth)])
def list_events(
    timeline_id: str,
     org_id: str = Query(default="default"),
    event_type: Optional[str] = Query(None),
):
    """List events for a timeline ordered by event_time ascending."""
    return _get_engine().list_events(org_id, timeline_id, event_type=event_type)


# ---------------------------------------------------------------------------
# Affected systems endpoints
# ---------------------------------------------------------------------------

@router.post("/{timeline_id}/systems", dependencies=[Depends(api_key_auth)], status_code=201)
def add_affected_system(
    timeline_id: str,
    body: AffectedSystemCreate,
     org_id: str = Query(default="default"),
):
    """Add an affected system to an incident timeline."""
    return _get_engine().add_affected_system(org_id, timeline_id, body.model_dump())


@router.get("/{timeline_id}/systems", dependencies=[Depends(api_key_auth)])
def list_affected_systems(
    timeline_id: str,
     org_id: str = Query(default="default"),
):
    """List affected systems for an incident timeline."""
    return _get_engine().list_affected_systems(org_id, timeline_id)


# ---------------------------------------------------------------------------
# Metrics endpoint
# ---------------------------------------------------------------------------

@router.post("/{timeline_id}/metrics", dependencies=[Depends(api_key_auth)], status_code=201)
def calculate_metrics(
    timeline_id: str,
     org_id: str = Query(default="default"),
):
    """Calculate and persist MTTD/MTTR/MTTC metrics for a timeline."""
    try:
        return _get_engine().calculate_metrics(org_id, timeline_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
