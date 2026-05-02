"""ITDR Router — ALDECI (Identity Threat Detection and Response).

Endpoints for the ITDR engine.

Prefix: /api/v1/itdr
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/itdr/threats                           detect_threat
  GET   /api/v1/itdr/threats                           list_threats
  GET   /api/v1/itdr/threats/{id}                      get_threat
  PUT   /api/v1/itdr/threats/{id}/status               update_threat_status
  POST  /api/v1/itdr/behaviors                         record_behavior
  GET   /api/v1/itdr/behaviors                         list_behaviors
  POST  /api/v1/itdr/response-actions                  create_response_action
  PUT   /api/v1/itdr/response-actions/{id}/execute     execute_response_action
  GET   /api/v1/itdr/response-actions                  list_response_actions
  GET   /api/v1/itdr/stats                             get_itdr_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/itdr",
    tags=["ITDR"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.itdr_engine import ITDREngine
        _engine = ITDREngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ThreatCreate(BaseModel):
    threat_type: str
    user_id: str
    source_ip: str = ""
    severity: str = "medium"
    confidence: float = 50.0
    indicators: List[str] = []


class ThreatStatusUpdate(BaseModel):
    new_status: str


class BehaviorCreate(BaseModel):
    user_id: str
    behavior_type: str
    risk_score: int = 50
    details: Dict[str, Any] = {}


class ResponseActionCreate(BaseModel):
    threat_id: str
    action_type: str
    notes: str = ""


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------

@router.post("/threats", dependencies=[Depends(api_key_auth)], status_code=201)
def detect_threat(body: ThreatCreate, org_id: str = Query(default="default")):
    """Record a new identity threat detection."""
    try:
        return _get_engine().detect_threat(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/threats", dependencies=[Depends(api_key_auth)])
def list_threats(
     org_id: str = Query(default="default"),
    threat_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List identity threats with optional filters."""
    return _get_engine().list_threats(
        org_id,
        threat_type=threat_type,
        status=status,
        severity=severity,
    )


@router.get("/threats/{threat_id}", dependencies=[Depends(api_key_auth)])
def get_threat(threat_id: str, org_id: str = Query(default="default")):
    """Get a single identity threat by ID."""
    threat = _get_engine().get_threat(org_id, threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat


@router.put("/threats/{threat_id}/status", dependencies=[Depends(api_key_auth)])
def update_threat_status(
    threat_id: str,
    body: ThreatStatusUpdate,
     org_id: str = Query(default="default"),
):
    """Update the status of an identity threat."""
    try:
        return _get_engine().update_threat_status(org_id, threat_id, body.new_status)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Behaviors
# ---------------------------------------------------------------------------

@router.post("/behaviors", dependencies=[Depends(api_key_auth)], status_code=201)
def record_behavior(body: BehaviorCreate, org_id: str = Query(default="default")):
    """Record an identity behavior event."""
    try:
        return _get_engine().record_behavior(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/behaviors", dependencies=[Depends(api_key_auth)])
def list_behaviors(
     org_id: str = Query(default="default"),
    user_id: Optional[str] = Query(None),
    behavior_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """List identity behaviors with optional filters."""
    return _get_engine().list_behaviors(
        org_id,
        user_id=user_id,
        behavior_type=behavior_type,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# Response Actions
# ---------------------------------------------------------------------------

@router.post("/response-actions", dependencies=[Depends(api_key_auth)], status_code=201)
def create_response_action(body: ResponseActionCreate, org_id: str = Query(default="default")):
    """Create a response action for a threat."""
    try:
        return _get_engine().create_response_action(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put(
    "/response-actions/{action_id}/execute",
    dependencies=[Depends(api_key_auth)],
)
def execute_response_action(action_id: str, org_id: str = Query(default="default")):
    """Execute a response action."""
    try:
        return _get_engine().execute_response_action(org_id, action_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/response-actions", dependencies=[Depends(api_key_auth)])
def list_response_actions(
     org_id: str = Query(default="default"),
    threat_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List response actions with optional filters."""
    return _get_engine().list_response_actions(
        org_id,
        threat_id=threat_id,
        status=status,
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_itdr_stats(org_id: str = Query(default="default")):
    """Return aggregated ITDR statistics."""
    return _get_engine().get_itdr_stats(org_id)
