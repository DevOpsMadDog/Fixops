"""Breach Detection Router — ALDECI.

Detection rules and event lifecycle management.

Prefix: /api/v1/breach-detection
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/breach-detection/rules                  create_detection_rule
  GET    /api/v1/breach-detection/rules                  list_detection_rules
  POST   /api/v1/breach-detection/events                 record_detection_event
  GET    /api/v1/breach-detection/events                 list_detection_events
  POST   /api/v1/breach-detection/events/{id}/investigate  investigate_event
  POST   /api/v1/breach-detection/events/{id}/close        close_event
  GET    /api/v1/breach-detection/stats                  get_detection_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/breach-detection",
    tags=["Breach Detection"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.breach_detection_engine import BreachDetectionEngine
        _engine = BreachDetectionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateRuleRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    name: str = Field(..., description="Rule name")
    rule_type: str = Field(..., description="behavioral/signature/anomaly/heuristic/ml_based")
    data_source: str = Field(default="endpoint", description="endpoint/network/cloud/email/identity/application")
    threshold: int = Field(default=5, description="Alert threshold count")
    status: str = Field(default="active", description="Rule status")


class RecordEventRequest(BaseModel):
    org_id: str = Field(default="default")
    rule_id: str = Field(..., description="ID of the triggering rule")
    severity: str = Field(..., description="low/medium/high/critical")
    entity: str = Field(..., description="Host, user, or IP that triggered the event")
    indicators: List[str] = Field(default_factory=list, description="List of indicators")
    matched_count: int = Field(default=1, description="Number of matched occurrences")
    status: str = Field(default="open")


class InvestigateEventRequest(BaseModel):
    org_id: str = Field(default="default")
    investigator: str = Field(..., description="Name/ID of the investigator")
    notes: str = Field(default="", description="Investigation notes")


class CloseEventRequest(BaseModel):
    org_id: str = Field(default="default")
    verdict: str = Field(..., description="true_positive/false_positive/benign")
    resolution: str = Field(default="", description="Resolution description")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/rules", dependencies=[Depends(api_key_auth)])
def create_detection_rule(req: CreateRuleRequest) -> Dict[str, Any]:
    """Create a new detection rule."""
    try:
        data = req.model_dump(exclude={"org_id"})
        return _get_engine().create_detection_rule(req.org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_detection_rule failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/rules", dependencies=[Depends(api_key_auth)])
def list_detection_rules(
    org_id: str = Query(default="default"),
    rule_type: Optional[str] = Query(default=None),
    data_source: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List detection rules for the org."""
    try:
        return _get_engine().list_detection_rules(org_id, rule_type=rule_type, data_source=data_source)
    except Exception as exc:
        _logger.exception("list_detection_rules failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/events", dependencies=[Depends(api_key_auth)])
def record_detection_event(req: RecordEventRequest) -> Dict[str, Any]:
    """Record a new detection event."""
    try:
        data = req.model_dump(exclude={"org_id"})
        return _get_engine().record_detection_event(req.org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("record_detection_event failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/events", dependencies=[Depends(api_key_auth)])
def list_detection_events(
    org_id: str = Query(default="default"),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List detection events for the org."""
    try:
        return _get_engine().list_detection_events(
            org_id, severity=severity, status=status, rule_id=rule_id
        )
    except Exception as exc:
        _logger.exception("list_detection_events failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/events/{event_id}/investigate", dependencies=[Depends(api_key_auth)])
def investigate_event(event_id: str, req: InvestigateEventRequest) -> Dict[str, Any]:
    """Mark a detection event as under investigation."""
    try:
        return _get_engine().investigate_event(
            req.org_id, event_id, req.investigator, req.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("investigate_event failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/events/{event_id}/close", dependencies=[Depends(api_key_auth)])
def close_event(event_id: str, req: CloseEventRequest) -> Dict[str, Any]:
    """Close a detection event with a verdict."""
    try:
        return _get_engine().close_event(
            req.org_id, event_id, req.verdict, req.resolution
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("close_event failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_detection_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate detection statistics for the org."""
    try:
        return _get_engine().get_detection_stats(org_id)
    except Exception as exc:
        _logger.exception("get_detection_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
