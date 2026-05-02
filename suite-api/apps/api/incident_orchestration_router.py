"""Incident Orchestration Router — ALDECI.

Endpoints for the Incident Orchestration engine.

Prefix: /api/v1/incident-orchestration
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/incident-orchestration/incidents                     create_incident
  GET    /api/v1/incident-orchestration/incidents                     list_incidents
  GET    /api/v1/incident-orchestration/incidents/{incident_id}       get_incident
  PATCH  /api/v1/incident-orchestration/incidents/{incident_id}/status  update_status
  PATCH  /api/v1/incident-orchestration/incidents/{incident_id}/assign  assign_incident
  POST   /api/v1/incident-orchestration/incidents/{incident_id}/timeline  add_timeline_event
  GET    /api/v1/incident-orchestration/incidents/{incident_id}/timeline  get_timeline
  GET    /api/v1/incident-orchestration/metrics                       get_metrics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth, require_role
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

_ANALYST_ROLES = ("admin", "super_admin", "org_admin", "security_engineer", "analyst")

router = APIRouter(
    prefix="/api/v1/incident-orchestration",
    tags=["Incident Orchestration"],
    dependencies=[require_role(*_ANALYST_ROLES)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.incident_orchestration_engine import IncidentOrchestrationEngine
        _engine = IncidentOrchestrationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IncidentCreate(BaseModel):
    title: str
    severity: str = "medium"
    type: str = "other"
    source: str = ""


class StatusUpdate(BaseModel):
    status: str
    notes: str = ""


class AssignRequest(BaseModel):
    assignee: str


class TimelineEventCreate(BaseModel):
    event_type: str = "note"
    description: str = ""
    actor: str = ""


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.post("/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def create_incident(body: IncidentCreate, org_id: str = Query(default="default")):
    """Create a new security incident."""
    try:
        return _get_engine().create_incident(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/incidents", dependencies=[Depends(api_key_auth)])
def list_incidents(
     org_id: str = Query(default="default"),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """List incidents with optional filters."""
    return _get_engine().list_incidents(org_id, severity=severity, status=status, limit=limit)


@router.get("/incidents/{incident_id}", dependencies=[Depends(api_key_auth)])
def get_incident(incident_id: str, org_id: str = Query(default="default")):
    """Get a single incident by ID."""
    incident = _get_engine().get_incident(org_id, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/incidents/{incident_id}/status", dependencies=[Depends(api_key_auth)])
def update_incident_status(
    incident_id: str,
    body: StatusUpdate,
     org_id: str = Query(default="default"),
):
    """Update the status of an incident."""
    try:
        result = _get_engine().update_incident_status(
            org_id, incident_id, body.status, notes=body.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@router.patch("/incidents/{incident_id}/assign", dependencies=[Depends(api_key_auth)])
def assign_incident(
    incident_id: str,
    body: AssignRequest,
     org_id: str = Query(default="default"),
):
    """Assign an incident to a user or team."""
    result = _get_engine().assign_incident(org_id, incident_id, body.assignee)
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

@router.post(
    "/incidents/{incident_id}/timeline",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_timeline_event(
    incident_id: str,
    body: TimelineEventCreate,
     org_id: str = Query(default="default"),
):
    """Add a timeline event to an incident."""
    try:
        result = _get_engine().add_timeline_event(org_id, incident_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@router.get("/incidents/{incident_id}/timeline", dependencies=[Depends(api_key_auth)])
def get_timeline(incident_id: str, org_id: str = Query(default="default")):
    """Get the full ordered timeline for an incident."""
    return _get_engine().get_timeline(org_id, incident_id)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@router.get("/metrics", dependencies=[Depends(api_key_auth)])
def get_incident_metrics(org_id: str = Query(default="default")):
    """Return aggregated incident metrics for the org."""
    return _get_engine().get_incident_metrics(org_id)


@router.get("/incidents/{incident_id}/context", dependencies=[Depends(api_key_auth)])
def get_incident_context(
    incident_id: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return TrustGraph cross-domain context for an incident (related alerts, assets, similar incidents)."""
    return _get_engine().get_incident_context(org_id, incident_id)
