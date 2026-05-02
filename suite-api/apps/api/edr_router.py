"""EDR Router — ALDECI.

Endpoints for the Endpoint Detection & Response engine.

Prefix: /api/v1/edr
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/edr/endpoints                              register_endpoint
  GET    /api/v1/edr/endpoints                              list_endpoints
  GET    /api/v1/edr/endpoints/{endpoint_id}                get_endpoint
  POST   /api/v1/edr/endpoints/{endpoint_id}/process-events ingest_process_event
  GET    /api/v1/edr/process-events                         list_process_events
  GET    /api/v1/edr/detections                             list_detections
  PATCH  /api/v1/edr/detections/{detection_id}/status       update_detection_status
  POST   /api/v1/edr/endpoints/{endpoint_id}/isolate        isolate_endpoint
  POST   /api/v1/edr/endpoints/{endpoint_id}/release        release_endpoint
  GET    /api/v1/edr/stats                                  get_edr_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/edr",
    tags=["EDR Engine"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.edr_engine import EDREngine
        _engine = EDREngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EndpointCreate(BaseModel):
    hostname: str
    ip_address: str = ""
    os_type: str = "linux"
    os_version: str = ""
    agent_version: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class ProcessEventCreate(BaseModel):
    process_name: str = ""
    process_hash: str = ""
    parent_process: str = ""
    cmdline: str = ""
    user: str = ""
    pid: int = 0
    event_type: str = "create"
    severity: Optional[str] = None
    mitre_technique: str = ""


class DetectionStatusUpdate(BaseModel):
    status: str


class IsolateRequest(BaseModel):
    reason: str
    isolated_by: str = "analyst"


# ---------------------------------------------------------------------------
# Endpoint routes
# ---------------------------------------------------------------------------

@router.post("/endpoints", dependencies=[Depends(api_key_auth)], status_code=201)
def register_endpoint(body: EndpointCreate, org_id: str = Query(default="default")):
    """Register a new managed endpoint."""
    try:
        return _get_engine().register_endpoint(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/endpoints", dependencies=[Depends(api_key_auth)])
def list_endpoints(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    os_type: Optional[str] = Query(None),
):
    """List endpoints, optionally filtered by status and/or os_type."""
    return _get_engine().list_endpoints(org_id, status=status, os_type=os_type)


@router.get("/endpoints/{endpoint_id}", dependencies=[Depends(api_key_auth)])
def get_endpoint(endpoint_id: str, org_id: str = Query(default="default")):
    """Get a single endpoint by ID."""
    ep = _get_engine().get_endpoint(org_id, endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return ep


# ---------------------------------------------------------------------------
# Process event routes
# ---------------------------------------------------------------------------

@router.post(
    "/endpoints/{endpoint_id}/process-events",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def ingest_process_event(
    endpoint_id: str,
    body: ProcessEventCreate,
     org_id: str = Query(default="default"),
):
    """Ingest a process event. Auto-detects suspicious patterns and creates detections."""
    try:
        return _get_engine().ingest_process_event(org_id, endpoint_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/process-events", dependencies=[Depends(api_key_auth)])
def list_process_events(
     org_id: str = Query(default="default"),
    endpoint_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """List process events with optional filters."""
    return _get_engine().list_process_events(
        org_id, endpoint_id=endpoint_id, severity=severity, limit=limit
    )


# ---------------------------------------------------------------------------
# Detection routes
# ---------------------------------------------------------------------------

@router.get("/detections", dependencies=[Depends(api_key_auth)])
def list_detections(
     org_id: str = Query(default="default"),
    detection_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List EDR detections with optional filters."""
    return _get_engine().list_detections(
        org_id,
        detection_type=detection_type,
        status=status,
        severity=severity,
    )


@router.patch("/detections/{detection_id}/status", dependencies=[Depends(api_key_auth)])
def update_detection_status(
    detection_id: str,
    body: DetectionStatusUpdate,
     org_id: str = Query(default="default"),
):
    """Update the status of a detection."""
    try:
        updated = _get_engine().update_detection_status(org_id, detection_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Detection not found")
    return {"updated": True, "detection_id": detection_id, "status": body.status}


# ---------------------------------------------------------------------------
# Isolation routes
# ---------------------------------------------------------------------------

@router.post(
    "/endpoints/{endpoint_id}/isolate",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def isolate_endpoint(
    endpoint_id: str,
    body: IsolateRequest,
     org_id: str = Query(default="default"),
):
    """Isolate an endpoint (network quarantine). Creates an isolation record."""
    return _get_engine().isolate_endpoint(
        org_id, endpoint_id, body.reason, body.isolated_by
    )


@router.post("/endpoints/{endpoint_id}/release", dependencies=[Depends(api_key_auth)])
def release_endpoint(endpoint_id: str, org_id: str = Query(default="default")):
    """Release an isolated endpoint back to online status."""
    released = _get_engine().release_endpoint(org_id, endpoint_id)
    if not released:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"released": True, "endpoint_id": endpoint_id}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_edr_stats(org_id: str = Query(default="default")):
    """Return aggregated EDR statistics for the org."""
    return _get_engine().get_edr_stats(org_id)


# ---------------------------------------------------------------------------
# Root — capability summary (fixes BUG-1: missing GET /)
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_edr_root(org_id: str = Query(default="default")):
    """Return EDR service capabilities and live stats summary."""
    stats = _get_engine().get_edr_stats(org_id)
    return {
        "service": "edr",
        "version": "1.0",
        "status": "operational",
        "capabilities": [
            "endpoint_registration",
            "process_event_ingestion",
            "threat_detection",
            "endpoint_isolation",
        ],
        "stats": stats,
    }
