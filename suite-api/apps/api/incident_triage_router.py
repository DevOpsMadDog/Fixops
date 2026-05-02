"""Incident Triage Router — ALDECI.

Endpoints for the Incident Triage engine.

Prefix: /api/v1/incident-triage
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/incident-triage/incidents                              submit_for_triage
  GET    /api/v1/incident-triage/incidents                              list_incidents
  GET    /api/v1/incident-triage/incidents/{incident_id}                get_incident
  POST   /api/v1/incident-triage/incidents/{incident_id}/triage         triage_incident
  POST   /api/v1/incident-triage/incidents/{incident_id}/escalate       escalate_incident
  POST   /api/v1/incident-triage/incidents/{incident_id}/resolve        resolve_triage
  GET    /api/v1/incident-triage/stats                                  get_triage_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/incident-triage",
    tags=["Incident Triage"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.incident_triage_engine import IncidentTriageEngine
        _engine = IncidentTriageEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IncidentSubmit(BaseModel):
    title: str
    source: str
    severity: str = "medium"
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class TriageData(BaseModel):
    confirmed: bool = False
    severity_override: Optional[str] = None
    assignee: Optional[str] = None
    classification: str
    notes: Optional[str] = None


class EscalateRequest(BaseModel):
    escalated_to: str
    reason: str


class ResolveRequest(BaseModel):
    resolution: str


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.post("/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def submit_for_triage(body: IncidentSubmit, org_id: str = Query(default="default")):
    """Submit a new incident for triage."""
    try:
        return _get_engine().submit_for_triage(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/incidents", dependencies=[Depends(api_key_auth)])
def list_incidents(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    classification: Optional[str] = Query(None),
):
    """List incidents with optional filters."""
    return _get_engine().list_incidents(
        org_id, status=status, severity=severity, classification=classification
    )


@router.get("/incidents/{incident_id}", dependencies=[Depends(api_key_auth)])
def get_incident(incident_id: str, org_id: str = Query(default="default")):
    """Get a single incident by ID."""
    incident = _get_engine().get_incident(org_id, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/incidents/{incident_id}/triage", dependencies=[Depends(api_key_auth)])
def triage_incident(
    incident_id: str,
    body: TriageData,
     org_id: str = Query(default="default"),
):
    """Triage an incident: score, classify, assign."""
    try:
        result = _get_engine().triage_incident(org_id, incident_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@router.post("/incidents/{incident_id}/escalate", dependencies=[Depends(api_key_auth)])
def escalate_incident(
    incident_id: str,
    body: EscalateRequest,
     org_id: str = Query(default="default"),
):
    """Escalate an incident."""
    result = _get_engine().escalate_incident(
        org_id, incident_id, body.escalated_to, body.reason
    )
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@router.post("/incidents/{incident_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_triage(
    incident_id: str,
    body: ResolveRequest,
     org_id: str = Query(default="default"),
):
    """Resolve a triaged incident."""
    result = _get_engine().resolve_triage(org_id, incident_id, body.resolution)
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_triage_stats(org_id: str = Query(default="default")):
    """Return aggregated triage stats for the org."""
    return _get_engine().get_triage_stats(org_id)
