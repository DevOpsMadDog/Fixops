"""ThreatActorTracking Router — ALDECI.

Exposes endpoints for tracking threat actors, recording activities,
adding intelligence, and retrieving summaries.

Prefix: /api/v1/actor-tracking
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/actor-tracking",
    tags=["Threat Actor Tracking"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_actor_tracking_engine import ThreatActorTrackingEngine
        _engine = ThreatActorTrackingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TrackActorModel(BaseModel):
    actor_name: str
    actor_alias: str = ""
    nation_state: str = ""
    actor_type: str = "unknown"
    threat_level: str = "medium"
    targeting_our_sector: bool = False
    mitre_groups: List[str] = []
    org_id: str = "default"


class RecordActivityModel(BaseModel):
    activity_type: str
    description: str = ""
    affected_sectors: str = ""
    ttps_used: List[str] = []
    indicators: List[str] = []
    source: str = ""
    verified: bool = False
    org_id: str = "default"


class AddIntelligenceModel(BaseModel):
    intel_type: str
    content: str
    confidence: float = 0.5
    source: str = ""
    valid_until: Optional[str] = None
    org_id: str = "default"


class UpdateActivityModel(BaseModel):
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_threat_actors(org_id: str = Query("default")):
    """Get threat actor tracking summary for the org."""
    return _get_engine().get_tracking_summary(org_id=org_id)


@router.post("/actors", dependencies=[Depends(api_key_auth)], status_code=201)
def track_actor(body: TrackActorModel):
    """Register a threat actor for tracking."""
    try:
        return _get_engine().track_actor(
            org_id=body.org_id,
            actor_name=body.actor_name,
            actor_alias=body.actor_alias,
            nation_state=body.nation_state,
            actor_type=body.actor_type,
            threat_level=body.threat_level,
            targeting_our_sector=body.targeting_our_sector,
            mitre_groups=body.mitre_groups,
        )
    except Exception as exc:
        logger.error("track_actor failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.patch("/actors/{actor_id}/activity", dependencies=[Depends(api_key_auth)])
def update_actor_activity(actor_id: str, body: UpdateActivityModel):
    """Update last_activity timestamp for an actor."""
    try:
        result = _get_engine().update_actor_activity(actor_id=actor_id, org_id=body.org_id)
        if not result:
            raise HTTPException(status_code=404, detail="Actor not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("update_actor_activity failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/actors/{actor_id}/activities", dependencies=[Depends(api_key_auth)], status_code=201)
def record_activity(actor_id: str, body: RecordActivityModel):
    """Record an observed activity for a threat actor."""
    try:
        return _get_engine().record_activity(
            actor_id=actor_id,
            org_id=body.org_id,
            activity_type=body.activity_type,
            description=body.description,
            affected_sectors=body.affected_sectors,
            ttps_used=body.ttps_used,
            indicators=body.indicators,
            source=body.source,
            verified=body.verified,
        )
    except Exception as exc:
        logger.error("record_activity failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/actors/{actor_id}/intelligence", dependencies=[Depends(api_key_auth)], status_code=201)
def add_intelligence(actor_id: str, body: AddIntelligenceModel):
    """Add intelligence entry for a threat actor."""
    try:
        return _get_engine().add_intelligence(
            actor_id=actor_id,
            org_id=body.org_id,
            intel_type=body.intel_type,
            content=body.content,
            confidence=body.confidence,
            source=body.source,
            valid_until=body.valid_until,
        )
    except Exception as exc:
        logger.error("add_intelligence failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/actors/{actor_id}", dependencies=[Depends(api_key_auth)])
def get_actor(actor_id: str, org_id: str = Query("default")):
    """Get a threat actor with recent activities and intelligence."""
    result = _get_engine().get_actor(actor_id=actor_id, org_id=org_id)
    if not result:
        raise HTTPException(status_code=404, detail="Actor not found")
    return result


@router.get("/actors", dependencies=[Depends(api_key_auth)])
def list_actors(
    org_id: str = Query("default"),
    actor_type: Optional[str] = Query(None),
    threat_level: Optional[str] = Query(None),
    targeting_our_sector: Optional[bool] = Query(None),
):
    """List tracked actors with optional filters."""
    return _get_engine().list_actors(
        org_id=org_id,
        actor_type=actor_type,
        threat_level=threat_level,
        targeting_our_sector=targeting_our_sector,
    )


@router.get("/active", dependencies=[Depends(api_key_auth)])
def get_active_threats(org_id: str = Query("default")):
    """Get actors with activity in the past 90 days."""
    return _get_engine().get_active_threats(org_id=org_id)


@router.get("/ttp-summary", dependencies=[Depends(api_key_auth)])
def get_ttp_summary(org_id: str = Query("default")):
    """Get aggregated TTP frequency across all tracked actors."""
    return _get_engine().get_actor_ttp_summary(org_id=org_id)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_summary(org_id: str = Query("default")):
    """Get threat actor tracking summary for the org."""
    return _get_engine().get_tracking_summary(org_id=org_id)


# ---------------------------------------------------------------------------
# MITRE ATT&CK Importer (real public-source data, no fakes)
# ---------------------------------------------------------------------------

class ImportMitreModel(BaseModel):
    org_id: str = "default"
    limit: Optional[int] = Field(
        default=None,
        description="Cap number of actors imported (None = all ~150 MITRE groups)",
    )
    cached_path: Optional[str] = Field(
        default=None,
        description="Optional local path to cached enterprise-attack.json (skips network fetch)",
    )


@router.post(
    "/actors/import-mitre",
    dependencies=[Depends(api_key_auth)],
    summary="Import threat actors from public MITRE ATT&CK enterprise dataset",
)
def import_mitre_actors_endpoint(body: ImportMitreModel):
    """Pull intrusion-set objects from MITRE ATT&CK STIX bundle and register
    each as a tracked actor for this org. Idempotent: dedupes on actor_name.
    Returns import summary + sample records.

    Source: https://github.com/mitre/cti (Apache-2.0 licensed public data).
    """
    try:
        from core.mitre_actor_importer import import_mitre_actors

        engine = _get_engine()
        result = import_mitre_actors(
            engine=engine,
            org_id=body.org_id,
            limit=body.limit,
            cached_path=body.cached_path,
        )
        return result
    except Exception as exc:
        logger.error("MITRE actor import failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=502, detail=f"MITRE import failed: {exc}")
