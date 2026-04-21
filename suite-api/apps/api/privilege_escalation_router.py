"""
Privilege Escalation Detector API — ALDECI.

Endpoints:
  POST   /api/v1/privilege-escalation/events                   record_privilege_event
  GET    /api/v1/privilege-escalation/events                   list_privilege_events
  GET    /api/v1/privilege-escalation/events/{id}/detect       detect_anomalous_escalation
  POST   /api/v1/privilege-escalation/rules                    create_detection_rule
  GET    /api/v1/privilege-escalation/rules                    list_detection_rules
  GET    /api/v1/privilege-escalation/heatmap                  get_escalation_heatmap
  GET    /api/v1/privilege-escalation/stats                    get_detection_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "privilege_escalation_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.privilege_escalation_detector_engine import (
    PrivilegeEscalationDetectorEngine,
    get_privilege_escalation_detector,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/privilege-escalation",
    tags=["privilege-escalation"],
    dependencies=_AUTH_DEP,
)

_engine_singleton: Optional[PrivilegeEscalationDetectorEngine] = None


def _engine() -> PrivilegeEscalationDetectorEngine:
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = get_privilege_escalation_detector()
    return _engine_singleton


# ============================================================================
# Request / Response models
# ============================================================================


class RecordEventRequest(BaseModel):
    org_id: str = Field(..., description="Organization identifier")
    user_id: str = Field(..., description="User or service account identifier")
    from_role: str = Field(..., description="Role/permission level before escalation")
    to_role: str = Field(..., description="Role/permission level after escalation")
    method: str = Field("other", description="Escalation method: sudo/setuid/token/exploit/impersonation/suid/other")
    source_ip: str = Field("", description="Source IP address of the escalation event")


class CreateRuleRequest(BaseModel):
    org_id: str = Field(..., description="Organization identifier")
    name: str = Field(..., description="Rule name")
    pattern: str = Field(..., description="Regex pattern to match against event strings")
    severity: str = Field("medium", description="critical/high/medium/low")
    action: str = Field("alert", description="alert/block/log")


# ============================================================================
# Endpoints
# ============================================================================


@router.post("/events", summary="Record a privilege escalation event")
def record_event(req: RecordEventRequest) -> Dict[str, Any]:
    """Record a privilege escalation event and compute its anomaly score."""
    try:
        return _engine().record_privilege_event(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("record_event failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/events", summary="List privilege escalation events")
def list_events(
    org_id: str = Query(..., description="Organization identifier"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
) -> List[Dict[str, Any]]:
    """List privilege escalation events, optionally filtered by user."""
    try:
        return _engine().list_privilege_events(org_id, user_id=user_id, limit=limit)
    except Exception as exc:
        logger.exception("list_events failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/events/{event_id}/detect", summary="Detect anomaly for a specific escalation event")
def detect_anomaly(
    event_id: str,
    org_id: str = Query(..., description="Organization identifier"),
) -> Dict[str, Any]:
    """Analyze a specific escalation event and return its anomaly assessment."""
    try:
        return _engine().detect_anomalous_escalation(org_id, event_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("detect_anomaly failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/rules", summary="Create a privilege escalation detection rule")
def create_rule(req: CreateRuleRequest) -> Dict[str, Any]:
    """Create a regex-based detection rule for privilege escalation patterns."""
    try:
        return _engine().create_detection_rule(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("create_rule failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/rules", summary="List detection rules for an org")
def list_rules(
    org_id: str = Query(..., description="Organization identifier"),
) -> List[Dict[str, Any]]:
    """List all privilege escalation detection rules."""
    try:
        return _engine().list_detection_rules(org_id)
    except Exception as exc:
        logger.exception("list_rules failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/heatmap", summary="Get escalation activity heatmap")
def get_heatmap(
    org_id: str = Query(..., description="Organization identifier"),
    hours: int = Query(24, ge=1, le=168, description="Time window in hours (max 7 days)"),
) -> Dict[str, Any]:
    """Return escalation heatmap: top users, top methods, events by hour."""
    try:
        return _engine().get_escalation_heatmap(org_id, hours=hours)
    except Exception as exc:
        logger.exception("get_heatmap failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", summary="Get privilege escalation detection statistics")
def get_stats(
    org_id: str = Query(..., description="Organization identifier"),
) -> Dict[str, Any]:
    """Return aggregate stats: total events, anomalies detected, blocked attempts."""
    try:
        return _engine().get_detection_stats(org_id)
    except Exception as exc:
        logger.exception("get_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
