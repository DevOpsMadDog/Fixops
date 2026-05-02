"""Incident Metrics Router — ALDECI.

Endpoints for the Incident Metrics engine.

Prefix: /api/v1/incident-metrics
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/incident-metrics/incidents                          record_incident
  GET  /api/v1/incident-metrics/incidents                          list_incidents
  GET  /api/v1/incident-metrics/incidents/{incident_id}            get_incident
  PUT  /api/v1/incident-metrics/incidents/{incident_id}/timeline   update_timeline
  PUT  /api/v1/incident-metrics/incidents/{incident_id}/escalate   escalate_incident
  POST /api/v1/incident-metrics/compute-metrics                    compute_metrics
  POST /api/v1/incident-metrics/sla-config                         set_sla_config
  GET  /api/v1/incident-metrics/sla-config/{severity}              get_sla_config
  GET  /api/v1/incident-metrics/stats                              get_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/incident-metrics",
    tags=["Incident Metrics"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.incident_metrics_engine import IncidentMetricsEngine
        _engine = IncidentMetricsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IncidentCreate(BaseModel):
    incident_id: str
    title: str
    severity: str
    category: str
    team: str = ""


class TimelineUpdate(BaseModel):
    event_type: str
    timestamp: Optional[str] = None


class SLAConfigCreate(BaseModel):
    severity: str
    response_sla_minutes: int = 60
    containment_sla_minutes: int = 240
    resolution_sla_minutes: int = 1440


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.post("/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def record_incident(body: IncidentCreate, org_id: str = Query(default="default")):
    """Record a new security incident."""
    try:
        return _get_engine().record_incident(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/incidents", dependencies=[Depends(api_key_auth)])
def list_incidents(
     org_id: str = Query(default="default"),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """List incidents with optional filters."""
    return _get_engine().list_incidents(
        org_id,
        severity=severity,
        status=status,
        category=category,
        limit=limit,
    )


@router.get("/incidents/{incident_id}", dependencies=[Depends(api_key_auth)])
def get_incident(incident_id: str, org_id: str = Query(default="default")):
    """Get a single incident by its external incident_id."""
    inc = _get_engine().get_incident(org_id, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@router.put("/incidents/{incident_id}/timeline", dependencies=[Depends(api_key_auth)])
def update_timeline(
    incident_id: str, body: TimelineUpdate, org_id: str = Query(default="default")
):
    """Update a timeline event for an incident."""
    try:
        return _get_engine().update_incident_timeline(
            org_id, incident_id, body.event_type, timestamp=body.timestamp
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/incidents/{incident_id}/escalate", dependencies=[Depends(api_key_auth)])
def escalate_incident(incident_id: str, org_id: str = Query(default="default")):
    """Escalate an incident."""
    try:
        return _get_engine().escalate_incident(org_id, incident_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@router.post("/compute-metrics", dependencies=[Depends(api_key_auth)])
def compute_metrics(org_id: str = Query(default="default")):
    """Trigger metric computation and save a daily snapshot."""
    return _get_engine().compute_metrics(org_id)


# ---------------------------------------------------------------------------
# SLA Config
# ---------------------------------------------------------------------------

@router.post("/sla-config", dependencies=[Depends(api_key_auth)], status_code=201)
def set_sla_config(body: SLAConfigCreate, org_id: str = Query(default="default")):
    """Upsert SLA configuration for a severity level."""
    try:
        return _get_engine().set_sla_config(
            org_id,
            body.severity,
            body.response_sla_minutes,
            body.containment_sla_minutes,
            body.resolution_sla_minutes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/sla-config/{severity}", dependencies=[Depends(api_key_auth)])
def get_sla_config(severity: str, org_id: str = Query(default="default")):
    """Get SLA config for a severity level."""
    cfg = _get_engine().get_sla_config(org_id, severity)
    if not cfg:
        raise HTTPException(status_code=404, detail="SLA config not found")
    return cfg


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")):
    """Return aggregated incident metrics statistics."""
    return _get_engine().get_metrics_stats(org_id)
