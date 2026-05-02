"""Threat Landscape Router — ALDECI.

Endpoints for ThreatLandscapeEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/threat-landscape
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/threat-landscape/actors                     add_threat_actor
  PATCH /api/v1/threat-landscape/actors/{actor_id}/activity update_actor_activity
  GET   /api/v1/threat-landscape/actors                     get_active_actors
  POST  /api/v1/threat-landscape/threats                    add_emerging_threat
  POST  /api/v1/threat-landscape/threats/{threat_id}/resolve resolve_threat
  GET   /api/v1/threat-landscape/threats                    get_active_threats
  POST  /api/v1/threat-landscape/assessments                create_assessment
  GET   /api/v1/threat-landscape/assessments                list_assessments
  GET   /api/v1/threat-landscape/assessments/{id}           get_assessment
  GET   /api/v1/threat-landscape/summary                    get_landscape_summary
"""
from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-landscape",
    tags=["Threat Landscape"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.threat_landscape_engine import ThreatLandscapeEngine
            _engine = ThreatLandscapeEngine()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Engine unavailable: {exc}") from exc
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ThreatActorCreate(BaseModel):
    actor_name: str
    actor_type: str = "unknown"
    motivation: str = "unknown"
    sophistication: str = "unknown"
    ttps: List[str] = []
    target_sectors: List[str] = []
    confidence: float = 0.5


class ActorActivityUpdate(BaseModel):
    active: int
    last_seen: str


class EmergingThreatCreate(BaseModel):
    threat_name: str
    threat_category: str = "malware"
    severity: str = "medium"
    description: str = ""
    affected_sectors: List[str] = []
    indicators: List[str] = []
    mitigations: List[str] = []


class AssessmentCreate(BaseModel):
    sector: str = ""
    key_findings: List[str] = []
    recommendations: List[str] = []


# ---------------------------------------------------------------------------
# Threat Actors
# ---------------------------------------------------------------------------

@router.post("/actors", dependencies=[Depends(api_key_auth)], status_code=201)
def add_threat_actor(body: ThreatActorCreate, org_id: str = Query(default="default")):
    """Add a new threat actor; confidence clamped to [0, 1]."""
    try:
        return _get_engine().add_threat_actor(
            org_id=org_id,
            actor_name=body.actor_name,
            actor_type=body.actor_type,
            motivation=body.motivation,
            sophistication=body.sophistication,
            ttps=body.ttps,
            target_sectors=body.target_sectors,
            confidence=body.confidence,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/actors/{actor_id}/activity", dependencies=[Depends(api_key_auth)])
def update_actor_activity(actor_id: str, body: ActorActivityUpdate, org_id: str = Query(default="default")):
    """Update actor active status and last_seen timestamp."""
    result = _get_engine().update_actor_activity(actor_id, org_id, body.active, body.last_seen)
    if not result:
        raise HTTPException(status_code=404, detail="Actor not found")
    return result


@router.get("/actors", dependencies=[Depends(api_key_auth)])
def get_active_actors(
     org_id: str = Query(default="default"),
    actor_type: Optional[str] = Query(None),
):
    """List active threat actors, optionally filtered by type."""
    return _get_engine().get_active_actors(org_id, actor_type=actor_type)


# ---------------------------------------------------------------------------
# Emerging Threats
# ---------------------------------------------------------------------------

@router.post("/threats", dependencies=[Depends(api_key_auth)], status_code=201)
def add_emerging_threat(body: EmergingThreatCreate, org_id: str = Query(default="default")):
    """Add a new emerging threat with status=active."""
    try:
        return _get_engine().add_emerging_threat(
            org_id=org_id,
            threat_name=body.threat_name,
            threat_category=body.threat_category,
            severity=body.severity,
            description=body.description,
            affected_sectors=body.affected_sectors,
            indicators=body.indicators,
            mitigations=body.mitigations,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/threats/{threat_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_threat(threat_id: str, org_id: str = Query(default="default")):
    """Mark a threat as resolved."""
    result = _get_engine().resolve_threat(threat_id, org_id)
    if not result:
        raise HTTPException(status_code=404, detail="Threat not found")
    return result


@router.get("/threats", dependencies=[Depends(api_key_auth)])
def get_active_threats(
     org_id: str = Query(default="default"),
    severity: Optional[str] = Query(None),
):
    """List active threats, optionally filtered by severity."""
    return _get_engine().get_active_threats(org_id, severity=severity)


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------

@router.post("/assessments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_assessment(body: AssessmentCreate, org_id: str = Query(default="default")):
    """Create a landscape assessment with auto-computed overall_risk and counts."""
    return _get_engine().create_assessment(
        org_id=org_id,
        sector=body.sector,
        key_findings=body.key_findings,
        recommendations=body.recommendations,
    )


@router.get("/assessments", dependencies=[Depends(api_key_auth)])
def list_assessments(
     org_id: str = Query(default="default"),
    sector: Optional[str] = Query(None),
):
    """List assessments with optional sector filter."""
    return _get_engine().list_assessments(org_id, sector=sector)


@router.get("/assessments/{assessment_id}", dependencies=[Depends(api_key_auth)])
def get_assessment(assessment_id: str, org_id: str = Query(default="default")):
    """Get a single assessment by ID."""
    result = _get_engine().get_assessment(assessment_id, org_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_landscape_summary(org_id: str = Query(default="default")):
    """Return summary stats across actors and threats."""
    return _get_engine().get_landscape_summary(org_id)


@router.get("", dependencies=[Depends(api_key_auth)])
def get_root(org_id: str = Query(default="default")):
    """Root endpoint — returns landscape summary for dashboard health-checks."""
    return _get_engine().get_landscape_summary(org_id)
