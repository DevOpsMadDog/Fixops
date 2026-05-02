"""Threat Actor Router — ALDECI.

Endpoints for the Threat Actor engine (APT/nation-state/criminal group tracking,
campaigns, IOCs, watchlist).

Prefix: /api/v1/threat-actors
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/threat-actors/actors                              add_actor
  GET    /api/v1/threat-actors/actors                              list_actors
  GET    /api/v1/threat-actors/actors/{actor_id}                   get_actor
  POST   /api/v1/threat-actors/actors/{actor_id}/campaigns         add_campaign
  GET    /api/v1/threat-actors/campaigns                           list_campaigns
  POST   /api/v1/threat-actors/actors/{actor_id}/iocs              add_ioc
  GET    /api/v1/threat-actors/iocs                                list_iocs
  POST   /api/v1/threat-actors/actors/{actor_id}/watchlist         add_to_watchlist
  GET    /api/v1/threat-actors/watchlist                           get_watchlist
  GET    /api/v1/threat-actors/stats                               get_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-actors",
    tags=["Threat Actor Engine"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_actor_engine import ThreatActorEngine
        _engine = ThreatActorEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ActorCreate(BaseModel):
    name: str
    aliases: List[str] = Field(default_factory=list)
    actor_type: str = "apt"
    origin_country: str = ""
    motivation: str = "espionage"
    sophistication: str = "high"
    first_observed: str = ""
    last_observed: str = ""
    active: bool = True
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    mitre_group_id: str = ""


class CampaignCreate(BaseModel):
    campaign_name: str
    start_date: str = ""
    end_date: str = ""
    target_sectors: List[str] = Field(default_factory=list)
    target_regions: List[str] = Field(default_factory=list)
    ttps_used: List[str] = Field(default_factory=list)
    malware_families: List[str] = Field(default_factory=list)
    status: str = "active"
    impact_level: str = "medium"


class IOCCreate(BaseModel):
    ioc_type: str = "ip"
    value: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    first_seen: str = ""
    last_seen: str = ""
    active: bool = True
    source: str = ""


class WatchlistAdd(BaseModel):
    added_by: str = ""
    reason: str = ""
    priority: str = "high"
    alert_on_ioc_match: bool = True


# ---------------------------------------------------------------------------
# Actor routes
# ---------------------------------------------------------------------------

@router.post("/actors", dependencies=[Depends(api_key_auth)], status_code=201)
def add_actor(body: ActorCreate, org_id: str = Query(default="default")):
    """Register a new threat actor (APT, nation-state, cybercriminal group, etc.)."""
    try:
        return _get_engine().add_actor(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/actors", dependencies=[Depends(api_key_auth)])
def list_actors(
     org_id: str = Query(default="default"),
    actor_type: Optional[str] = Query(None),
    active: Optional[bool] = Query(None),
):
    """List threat actors, optionally filtered by type and/or active status."""
    return _get_engine().list_actors(org_id, actor_type=actor_type, active=active)


@router.get("/actors/{actor_id}", dependencies=[Depends(api_key_auth)])
def get_actor(actor_id: str, org_id: str = Query(default="default")):
    """Get a single threat actor with campaign list and IOC count."""
    actor = _get_engine().get_actor(org_id, actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    return actor


# ---------------------------------------------------------------------------
# Campaign routes
# ---------------------------------------------------------------------------

@router.post(
    "/actors/{actor_id}/campaigns",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_campaign(actor_id: str, body: CampaignCreate, org_id: str = Query(default="default")):
    """Add a campaign attributed to a threat actor."""
    try:
        return _get_engine().add_campaign(org_id, actor_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/campaigns", dependencies=[Depends(api_key_auth)])
def list_campaigns(
     org_id: str = Query(default="default"),
    actor_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List campaigns with optional actor_id and/or status filters."""
    return _get_engine().list_campaigns(org_id, actor_id=actor_id, status=status)


# ---------------------------------------------------------------------------
# IOC routes
# ---------------------------------------------------------------------------

@router.post(
    "/actors/{actor_id}/iocs",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_ioc(actor_id: str, body: IOCCreate, org_id: str = Query(default="default")):
    """Add an IOC attributed to a threat actor."""
    try:
        return _get_engine().add_ioc(org_id, actor_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/iocs", dependencies=[Depends(api_key_auth)])
def list_iocs(
     org_id: str = Query(default="default"),
    actor_id: Optional[str] = Query(None),
    ioc_type: Optional[str] = Query(None),
    active: Optional[bool] = Query(None),
):
    """List IOCs with optional filters."""
    return _get_engine().list_iocs(
        org_id, actor_id=actor_id, ioc_type=ioc_type, active=active
    )


# ---------------------------------------------------------------------------
# Watchlist routes
# ---------------------------------------------------------------------------

@router.post(
    "/actors/{actor_id}/watchlist",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_to_watchlist(actor_id: str, body: WatchlistAdd, org_id: str = Query(default="default")):
    """Add a threat actor to the org watchlist for active monitoring."""
    try:
        return _get_engine().add_to_watchlist(org_id, actor_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/watchlist", dependencies=[Depends(api_key_auth)])
def get_watchlist(org_id: str = Query(default="default")):
    """Return all watchlist entries for the org, ordered by priority."""
    return _get_engine().get_watchlist(org_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")):
    """Return aggregated threat actor statistics for the org."""
    return _get_engine().get_stats(org_id)
