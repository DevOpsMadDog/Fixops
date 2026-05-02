"""Threat Response Router — ALDECI.

Endpoints for the Threat Response engine.

Prefix: /api/v1/threat-response
Auth:   api_key_auth dependency on ALL endpoints

Routes:
  POST /api/v1/threat-response/playbooks                         create_playbook
  POST /api/v1/threat-response/playbooks/{id}/actions            add_action
  POST /api/v1/threat-response/incidents                         trigger_incident
  POST /api/v1/threat-response/incidents/{id}/log-action         log_action
  PUT  /api/v1/threat-response/action-logs/{id}/complete         complete_action
  PUT  /api/v1/threat-response/incidents/{id}/resolve            resolve_incident
  GET  /api/v1/threat-response/incidents/active                  get_active_incidents
  GET  /api/v1/threat-response/playbooks/performance             get_playbook_performance
  GET  /api/v1/threat-response/incidents/{id}/timeline           get_incident_timeline
  GET  /api/v1/threat-response/summary                           get_response_summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-response",
    tags=["Threat Response"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_response_engine import ThreatResponseEngine
        _engine = ThreatResponseEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class PlaybookCreate(BaseModel):
    playbook_name: str
    threat_type: str
    severity_scope: str = "all"
    description: str = ""
    created_by: str = ""


class ActionCreate(BaseModel):
    action_name: str
    action_type: str
    description: str = ""
    automated: bool = False
    timeout_mins: int = 30


class IncidentTrigger(BaseModel):
    playbook_id: str
    incident_name: str
    threat_type: str
    severity: str = "high"
    triggered_by: str = ""


class ActionLogCreate(BaseModel):
    action_id: str = ""
    action_name: str
    executed_by: str = ""


class ActionComplete(BaseModel):
    status: str
    notes: str = ""


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_threat_response(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get threat response summary for the org."""
    return _get_engine().get_response_summary(org_id=org_id)


@router.post("/playbooks", dependencies=[Depends(api_key_auth)], status_code=201)
def create_playbook(body: PlaybookCreate, org_id: str = Query(default="default")):
    """Create a new response playbook."""
    try:
        return _get_engine().create_playbook(
            org_id=org_id,
            playbook_name=body.playbook_name,
            threat_type=body.threat_type,
            severity_scope=body.severity_scope,
            description=body.description,
            created_by=body.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/playbooks/{playbook_id}/actions", dependencies=[Depends(api_key_auth)], status_code=201)
def add_action(playbook_id: str, body: ActionCreate, org_id: str = Query(default="default")):
    """Add an action step to a playbook."""
    try:
        return _get_engine().add_action(
            playbook_id=playbook_id,
            org_id=org_id,
            action_name=body.action_name,
            action_type=body.action_type,
            description=body.description,
            automated=body.automated,
            timeout_mins=body.timeout_mins,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/playbooks/performance", dependencies=[Depends(api_key_auth)])
def get_playbook_performance(org_id: str = Query(default="default")):
    """Return playbook performance metrics."""
    return _get_engine().get_playbook_performance(org_id)


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.post("/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def trigger_incident(body: IncidentTrigger, org_id: str = Query(default="default")):
    """Trigger a new incident linked to a playbook."""
    try:
        return _get_engine().trigger_incident(
            org_id=org_id,
            playbook_id=body.playbook_id,
            incident_name=body.incident_name,
            threat_type=body.threat_type,
            severity=body.severity,
            triggered_by=body.triggered_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/incidents/{incident_id}/log-action", dependencies=[Depends(api_key_auth)], status_code=201)
def log_action(incident_id: str, body: ActionLogCreate, org_id: str = Query(default="default")):
    """Log an action being executed on an incident."""
    try:
        return _get_engine().log_action(
            incident_id=incident_id,
            org_id=org_id,
            action_id=body.action_id,
            action_name=body.action_name,
            executed_by=body.executed_by,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/incidents/{incident_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_incident(incident_id: str, org_id: str = Query(default="default")):
    """Resolve an incident and update playbook stats."""
    try:
        return _get_engine().resolve_incident(incident_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/incidents/active", dependencies=[Depends(api_key_auth)])
def get_active_incidents(org_id: str = Query(default="default")):
    """Return all active incidents with their action logs."""
    return _get_engine().get_active_incidents(org_id)


@router.get("/incidents/{incident_id}/timeline", dependencies=[Depends(api_key_auth)])
def get_incident_timeline(incident_id: str, org_id: str = Query(default="default")):
    """Return incident timeline with ordered action log."""
    try:
        return _get_engine().get_incident_timeline(incident_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Action Logs
# ---------------------------------------------------------------------------

@router.put("/action-logs/{log_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_action(log_id: str, body: ActionComplete, org_id: str = Query(default="default")):
    """Mark an action log entry as completed or failed."""
    try:
        return _get_engine().complete_action(
            log_id=log_id,
            org_id=org_id,
            status=body.status,
            notes=body.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_response_summary(org_id: str = Query(default="default")):
    """Return org-level threat response summary."""
    return _get_engine().get_response_summary(org_id)
