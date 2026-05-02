"""Threat Deception Management Router — ALDECI.

Decoy lifecycle, attacker interaction recording, campaign orchestration.

Prefix: /api/v1/threat-deception
Auth: api_key_auth dependency

Routes:
  POST  /api/v1/threat-deception/decoys                       create_decoy
  GET   /api/v1/threat-deception/decoys                       list_decoys
  GET   /api/v1/threat-deception/decoys/{id}                  get_decoy
  POST  /api/v1/threat-deception/decoys/{id}/interactions     record_interaction
  GET   /api/v1/threat-deception/interactions                 list_interactions
  POST  /api/v1/threat-deception/campaigns                    create_campaign
  GET   /api/v1/threat-deception/campaigns                    list_campaigns
  GET   /api/v1/threat-deception/stats                        get_deception_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-deception",
    tags=["Threat Deception Management"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_deception_management_engine import (
            ThreatDeceptionManagementEngine,
        )
        _engine = ThreatDeceptionManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateDecoyRequest(BaseModel):
    name: str = Field(..., description="Human-readable decoy name")
    decoy_type: str = Field(
        default="honeypot",
        description="honeypot | honeytoken | honeydoc | fake_service | canary_endpoint",
    )
    ip_address: str = Field(default="", description="Decoy IP address")
    port: int = Field(default=0, ge=0, description="Decoy port number")
    description: str = Field(default="")
    active: bool = Field(default=True)


class RecordInteractionRequest(BaseModel):
    interaction_type: str = Field(
        default="scan",
        description="scan | login_attempt | file_access | network_probe | data_exfil",
    )
    source_ip: str = Field(default="", description="Attacker source IP")
    user_agent: str = Field(default="")
    payload_preview: str = Field(default="")
    attacker_fingerprint: str = Field(default="")
    occurred_at: Optional[str] = Field(default=None)


class CreateCampaignRequest(BaseModel):
    name: str = Field(..., description="Campaign name")
    description: str = Field(default="")
    decoy_ids_json: str = Field(default="[]", description="JSON array of decoy IDs")
    objective: str = Field(default="", description="Campaign objective")
    status: str = Field(default="active", description="active | paused | completed")
    started_at: Optional[str] = Field(default=None)
    ended_at: Optional[str] = Field(default=None)


# ---------------------------------------------------------------------------
# Routes — Decoys
# ---------------------------------------------------------------------------

@router.post("/decoys", dependencies=[Depends(api_key_auth)], status_code=201)
def create_decoy(
    body: CreateDecoyRequest,
    org_id: str = Query(default="default"),
):
    """Create a new deception decoy (honeypot, canary, honeydoc, etc.)."""
    try:
        return _get_engine().create_decoy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating decoy")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/decoys", dependencies=[Depends(api_key_auth)])
def list_decoys(
    org_id: str = Query(default="default"),
    decoy_type: Optional[str] = Query(default=None),
    active: Optional[bool] = Query(default=None),
):
    """List decoys with optional type/active filters."""
    return _get_engine().list_decoys(org_id, decoy_type=decoy_type, active=active)


@router.get("/decoys/{decoy_id}", dependencies=[Depends(api_key_auth)])
def get_decoy(
    decoy_id: str,
    org_id: str = Query(default="default"),
):
    """Retrieve a single decoy by ID."""
    decoy = _get_engine().get_decoy(org_id, decoy_id)
    if decoy is None:
        raise HTTPException(status_code=404, detail=f"Decoy {decoy_id} not found")
    return decoy


# ---------------------------------------------------------------------------
# Routes — Interactions
# ---------------------------------------------------------------------------

@router.post("/decoys/{decoy_id}/interactions", dependencies=[Depends(api_key_auth)], status_code=201)
def record_interaction(
    decoy_id: str,
    body: RecordInteractionRequest,
    org_id: str = Query(default="default"),
):
    """Record an attacker interaction with a specific decoy."""
    try:
        return _get_engine().record_interaction(org_id, decoy_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error recording interaction")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/interactions", dependencies=[Depends(api_key_auth)])
def list_interactions(
    org_id: str = Query(default="default"),
    decoy_id: Optional[str] = Query(default=None),
    interaction_type: Optional[str] = Query(default=None),
):
    """List interactions with optional decoy/type filters."""
    return _get_engine().list_interactions(
        org_id, decoy_id=decoy_id, interaction_type=interaction_type
    )


# ---------------------------------------------------------------------------
# Routes — Campaigns
# ---------------------------------------------------------------------------

@router.post("/campaigns", dependencies=[Depends(api_key_auth)], status_code=201)
def create_campaign(
    body: CreateCampaignRequest,
    org_id: str = Query(default="default"),
):
    """Create a new deception campaign."""
    try:
        return _get_engine().create_campaign(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating campaign")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/campaigns", dependencies=[Depends(api_key_auth)])
def list_campaigns(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
):
    """List campaigns with optional status filter."""
    return _get_engine().list_campaigns(org_id, status=status)


# ---------------------------------------------------------------------------
# Routes — Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_deception_stats(org_id: str = Query(default="default")):
    """Return aggregated deception stats: decoys, interactions, unique attackers, hottest decoy."""
    return _get_engine().get_deception_stats(org_id)
