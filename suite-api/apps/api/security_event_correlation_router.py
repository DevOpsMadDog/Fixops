"""Security Event Correlation API Router — ALDECI.

Endpoints (all under /api/v1/event-correlation):

  Events:
    POST   /events                  — ingest a security event
    GET    /events                  — list events (filter: source_system, event_type, severity)

  Rules:
    POST   /rules                   — create correlation rule
    GET    /rules                   — list correlation rules

  Correlation:
    POST   /run                     — run correlation engine, return matches

  Incidents:
    POST   /incidents               — create correlated incident
    GET    /incidents               — list correlated incidents (filter: status)

  Stats:
    GET    /stats                   — correlation statistics

Auth: api_key_auth from apps.api.auth_deps
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/event-correlation", tags=["event-correlation"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_event_correlation_engine import (
            SecurityEventCorrelationEngine,
        )
        _engine = SecurityEventCorrelationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class IngestEventRequest(BaseModel):
    source_system: str = Field(default="")
    event_type: str = Field(default="")
    severity: str = Field(default="medium")
    entity_id: str = Field(default="")
    entity_type: str = Field(default="")
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[str] = None


class CreateRuleRequest(BaseModel):
    name: str = Field(..., min_length=1)
    pattern: List[str] = Field(default_factory=list)
    time_window_seconds: int = Field(default=300, ge=1)
    min_count: int = Field(default=2, ge=1)
    output_severity: str = Field(default="high")


class CreateIncidentRequest(BaseModel):
    rule_id: str = Field(default="")
    matched_event_ids: List[str] = Field(default_factory=list)
    title: str = Field(default="Correlated Security Incident")
    severity: str = Field(default="high")


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


@router.post("/events", summary="Ingest a security event")
def ingest_event(req: IngestEventRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().ingest_event(org_id, req.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/events", summary="List security events")
def list_events(
    source_system: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_events(
        org_id,
        source_system=source_system,
        event_type=event_type,
        severity=severity,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@router.post("/rules", summary="Create a correlation rule")
def create_rule(req: CreateRuleRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().create_correlation_rule(org_id, req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/rules", summary="List correlation rules")
def list_rules(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    return _get_engine().list_correlation_rules(org_id)


# ---------------------------------------------------------------------------
# Correlation Run
# ---------------------------------------------------------------------------


@router.post("/run", summary="Run correlation engine against recent events")
def run_correlation(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    return _get_engine().run_correlation(org_id)


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


@router.post("/incidents", summary="Create a correlated incident")
def create_incident(req: CreateIncidentRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().create_correlated_incident(org_id, req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/incidents", summary="List correlated incidents")
def list_incidents(
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_correlated_incidents(org_id, status=status, limit=limit)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", summary="Get correlation statistics")
def get_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_correlation_stats(org_id)
