"""
Threat Intelligence Correlation API endpoints — ALDECI.

Exposes threat actor profiles, campaign data, and finding correlation
via the ThreatIntelCorrelator engine.

Protected with API key authentication via ``_verify_api_key`` (injected
via ``app.include_router`` dependencies — see app.py).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.threat_intel_correlator import (
    Campaign,
    ThreatActor,
    ThreatCorrelation,
    ThreatIntelCorrelator,
)

router = APIRouter(
    prefix="/api/v1/threat-intel",
    tags=["threat-intel"],
)

_correlator = ThreatIntelCorrelator()


# ---------------------------------------------------------------------------
# Request / Response shapes
# ---------------------------------------------------------------------------


class CorrelateRequest(BaseModel):
    """Request body for finding correlation."""

    finding: Dict[str, Any]


class BatchCorrelateRequest(BaseModel):
    """Request body for batch correlation."""

    findings: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/correlate", response_model=ThreatCorrelation)
async def correlate_finding(body: CorrelateRequest) -> ThreatCorrelation:
    """
    Correlate a single security finding against all known threat actors
    and campaigns. Returns the best-matching ThreatCorrelation.
    """
    if not body.finding:
        raise HTTPException(status_code=422, detail="finding must not be empty")
    return _correlator.correlate_finding(body.finding)


@router.post("/correlate/batch", response_model=List[ThreatCorrelation])
async def correlate_batch(body: BatchCorrelateRequest) -> List[ThreatCorrelation]:
    """
    Correlate a batch of security findings. Returns a correlation result
    for each finding in the same order as the input list.
    """
    if not body.findings:
        raise HTTPException(status_code=422, detail="findings list must not be empty")
    return _correlator.correlate_batch(body.findings)


@router.get("/actors", response_model=List[ThreatActor])
async def list_threat_actors(
    active_only: bool = Query(False, description="Return only active actors"),
) -> List[ThreatActor]:
    """
    List all registered threat actor profiles. Optionally filter to
    active actors only.
    """
    actors = _correlator._load_all_actors()
    if active_only:
        actors = [a for a in actors if a.active]
    return actors


@router.post("/actors", response_model=ThreatActor)
async def add_threat_actor(actor: ThreatActor) -> ThreatActor:
    """
    Register a new threat actor profile. If an actor with the same ID
    already exists it will be replaced (upsert).
    """
    _correlator.add_threat_actor(actor)
    return actor


@router.get("/actors/{actor_id}", response_model=Dict[str, Any])
async def get_actor_profile(actor_id: str) -> Dict[str, Any]:
    """
    Return full actor dossier: profile, associated campaigns, and
    recent finding correlations.
    """
    profile = _correlator.get_actor_profile(actor_id)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"Threat actor '{actor_id}' not found")
    return profile


@router.post("/campaigns", response_model=Campaign)
async def add_campaign(campaign: Campaign) -> Campaign:
    """
    Register a new threat campaign. Upserts on duplicate ID.
    """
    _correlator.add_campaign(campaign)
    return campaign


@router.get("/campaigns/{campaign_id}/timeline", response_model=Dict[str, Any])
async def get_campaign_timeline(campaign_id: str) -> Dict[str, Any]:
    """
    Return campaign details and all correlated finding events as a
    chronological timeline.
    """
    timeline = _correlator.get_campaign_timeline(campaign_id)
    if timeline is None:
        raise HTTPException(
            status_code=404, detail=f"Campaign '{campaign_id}' not found"
        )
    return timeline


@router.get("/landscape", response_model=Dict[str, Any])
async def get_threat_landscape(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Return a high-level threat landscape overview for the organisation:
    active actor count, active campaigns, and top correlated threat actors.
    """
    return _correlator.get_threat_landscape(org_id)


@router.get("/active-threats", response_model=List[ThreatActor])
async def get_active_threats(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[ThreatActor]:
    """
    Return all currently active threat actors relevant to the organisation.
    """
    return _correlator.get_active_threats(org_id)
