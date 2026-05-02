"""Threat Attribution Router — ALDECI.

Manages threat actor profiles, incident-to-actor attributions,
and supporting indicators.

Prefix: /api/v1/threat-attribution
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/threat-attribution/actors                    create_actor
  GET    /api/v1/threat-attribution/actors                    list_actors
  GET    /api/v1/threat-attribution/actors/{id}               get_actor
  POST   /api/v1/threat-attribution/attributions              create_attribution
  PATCH  /api/v1/threat-attribution/attributions/{id}/status  update_status
  POST   /api/v1/threat-attribution/attributions/{id}/indicators  add_indicator
  GET    /api/v1/threat-attribution/attributions              list_attributions
  GET    /api/v1/threat-attribution/stats                     get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-attribution",
    tags=["Threat Attribution"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_attribution_engine import ThreatAttributionEngine
        _engine = ThreatAttributionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateActorRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    name: str = Field(..., description="Threat actor name (required)")
    actor_type: str = Field(
        default="unknown",
        description="Type: nation_state, criminal_group, hacktivist, insider, competitor, unknown",
    )
    aliases: List[str] = Field(default_factory=list, description="Known aliases / alternate names")
    origin_country: str = Field(default="", description="Country of origin (ISO-3166 code)")
    motivation: str = Field(default="", description="Primary motivation (e.g. espionage, financial)")
    sophistication: str = Field(
        default="basic",
        description="Sophistication level: advanced, moderate, basic",
    )
    active: bool = Field(default=True, description="Whether the actor is currently active")


class CreateAttributionRequest(BaseModel):
    org_id: str = Field(default="default")
    incident_id: str = Field(..., description="Incident identifier (required)")
    actor_id: str = Field(default="", description="Threat actor id (optional)")
    confidence: str = Field(
        default="possible",
        description="Confidence: confirmed, likely, possible, unlikely",
    )
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting evidence map")
    analyst: str = Field(default="", description="Analyst who created the attribution")
    attribution_date: Optional[str] = Field(default=None, description="ISO datetime of attribution")
    notes: str = Field(default="", description="Analyst notes")


class UpdateAttributionStatusRequest(BaseModel):
    status: str = Field(
        ...,
        description="New status: investigating, attributed, disputed, closed",
    )
    notes: str = Field(default="", description="Optional notes for status change")


class AddIndicatorRequest(BaseModel):
    org_id: str = Field(default="default")
    indicator_type: str = Field(
        default="iocs",
        description="Type: ttps, iocs, infrastructure, malware, victimology",
    )
    value: str = Field(default="", description="Indicator value (IP, hash, domain, etc.)")
    description: str = Field(default="", description="Description of the indicator")
    first_seen: Optional[str] = Field(default=None, description="ISO datetime first observed")
    last_seen: Optional[str] = Field(default=None, description="ISO datetime last observed")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/actors", dependencies=[Depends(api_key_auth)])
def create_actor(req: CreateActorRequest) -> Dict[str, Any]:
    """Create a new threat actor profile."""
    try:
        return _get_engine().create_threat_actor(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_actor failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/actors", dependencies=[Depends(api_key_auth)])
def list_actors(
    org_id: str = Query(default="default"),
    actor_type: Optional[str] = Query(default=None),
    active: Optional[bool] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List threat actors with optional filters."""
    try:
        return _get_engine().list_threat_actors(org_id, actor_type=actor_type, active=active)
    except Exception as exc:
        _logger.exception("list_actors failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate threat attribution statistics."""
    try:
        return _get_engine().get_attribution_stats(org_id)
    except Exception as exc:
        _logger.exception("get_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/attributions", dependencies=[Depends(api_key_auth)])
def list_attributions(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    confidence: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List attributions with optional filters."""
    try:
        return _get_engine().list_attributions(org_id, status=status, confidence=confidence)
    except Exception as exc:
        _logger.exception("list_attributions failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/attributions", dependencies=[Depends(api_key_auth)])
def create_attribution(req: CreateAttributionRequest) -> Dict[str, Any]:
    """Create a new incident attribution."""
    try:
        return _get_engine().create_attribution(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_attribution failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/actors/{actor_id}", dependencies=[Depends(api_key_auth)])
def get_actor(actor_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get a single threat actor by id."""
    try:
        actor = _get_engine().get_threat_actor(org_id, actor_id)
        if not actor:
            raise HTTPException(status_code=404, detail=f"Actor {actor_id!r} not found")
        return actor
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("get_actor failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.patch("/attributions/{attribution_id}/status", dependencies=[Depends(api_key_auth)])
def update_attribution_status(
    attribution_id: str,
    req: UpdateAttributionStatusRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Update the status of an attribution."""
    try:
        return _get_engine().update_attribution_status(
            org_id, attribution_id, req.status, req.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("update_attribution_status failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/attributions/{attribution_id}/indicators", dependencies=[Depends(api_key_auth)])
def add_indicator(
    attribution_id: str,
    req: AddIndicatorRequest,
) -> Dict[str, Any]:
    """Add an indicator to an attribution."""
    try:
        return _get_engine().add_indicator(
            req.org_id, attribution_id, req.model_dump(exclude={"org_id"})
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("add_indicator failed")
        raise HTTPException(status_code=500, detail=str(exc))
