"""Security Health Check Router — ALDECI.

Exposes CRUD for health checks, snapshots, incidents, and stats.
Prefix: /api/v1/security-health
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-health",
    tags=["Security Health Engine"],
)

# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_health_engine import SecurityHealthEngine
        _engine = SecurityHealthEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class HealthCheckCreate(BaseModel):
    check_name: str
    category: str = "network"
    status: str = "unknown"
    score: int = Field(default=0, ge=0, le=100)
    details: str = ""
    check_interval_hours: int = 24


class CheckStatusUpdate(BaseModel):
    status: str
    score: int = Field(ge=0, le=100)
    details: str = ""


class IncidentCreate(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"


# ---------------------------------------------------------------------------
# Health check endpoints
# ---------------------------------------------------------------------------

@router.post("/checks", dependencies=[Depends(api_key_auth)], status_code=201)
def register_check(body: HealthCheckCreate, org_id: str = Query(default="default")):
    """Register a new security health check."""
    try:
        return _get_engine().register_check(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/checks", dependencies=[Depends(api_key_auth)])
def list_checks(
     org_id: str = Query(default="default"),
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List health checks with optional category/status filters."""
    return _get_engine().list_checks(org_id, category=category, status=status)


@router.patch("/checks/{check_id}/status", dependencies=[Depends(api_key_auth)])
def update_check_status(
    check_id: str,
    body: CheckStatusUpdate,
     org_id: str = Query(default="default"),
):
    """Update the status and score of a health check."""
    try:
        updated = _get_engine().update_check_status(
            org_id, check_id, body.status, body.score, body.details
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Health check not found")
    return {"updated": True, "check_id": check_id}


# ---------------------------------------------------------------------------
# Snapshot endpoints
# ---------------------------------------------------------------------------

@router.post("/snapshots", dependencies=[Depends(api_key_auth)], status_code=201)
def run_snapshot(org_id: str = Query(default="default")):
    """Run a health snapshot and persist it. Returns the snapshot."""
    return _get_engine().run_health_snapshot(org_id)


@router.get("/snapshots/latest", dependencies=[Depends(api_key_auth)])
def get_latest_snapshot(org_id: str = Query(default="default")):
    """Return the most recent health snapshot."""
    snapshot = _get_engine().get_latest_snapshot(org_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="No snapshots found")
    return snapshot


@router.get("/snapshots", dependencies=[Depends(api_key_auth)])
def list_snapshots(org_id: str = Query(default="default"), limit: int = Query(default=30, ge=1, le=100)):
    """Return recent health snapshots (default last 30)."""
    return _get_engine().list_snapshots(org_id, limit=limit)


# ---------------------------------------------------------------------------
# Incident endpoints
# ---------------------------------------------------------------------------

@router.post("/checks/{check_id}/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def log_incident(
    check_id: str,
    body: IncidentCreate,
     org_id: str = Query(default="default"),
):
    """Log a security health incident linked to a check."""
    try:
        return _get_engine().log_incident(org_id, check_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/incidents/{incident_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_incident(incident_id: str, org_id: str = Query(default="default")):
    """Mark a health incident as resolved."""
    resolved = _get_engine().resolve_incident(org_id, incident_id)
    if not resolved:
        raise HTTPException(status_code=404, detail="Incident not found or already resolved")
    return {"resolved": True, "incident_id": incident_id}


@router.get("/incidents", dependencies=[Depends(api_key_auth)])
def list_incidents(
     org_id: str = Query(default="default"),
    resolved: bool = Query(default=False, description="Set true to list resolved incidents"),
):
    """List open or resolved health incidents."""
    return _get_engine().list_incidents(org_id, resolved=resolved)


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_health_stats(org_id: str = Query(default="default")):
    """Return aggregate health statistics for an org."""
    return _get_engine().get_health_stats(org_id)
