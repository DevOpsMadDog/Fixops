"""Deception Analytics Router — ALDECI.

Deception asset management, interaction recording, campaign orchestration,
and analytics.

Prefix: /api/v1/deception-analytics
Auth: api_key_auth dependency

Routes:
  POST  /api/v1/deception-analytics/assets                    register_asset
  GET   /api/v1/deception-analytics/assets                    list_assets
  GET   /api/v1/deception-analytics/assets/{id}               get_asset
  PUT   /api/v1/deception-analytics/assets/{id}/deactivate    deactivate_asset
  POST  /api/v1/deception-analytics/interactions              record_interaction
  GET   /api/v1/deception-analytics/interactions              list_interactions
  POST  /api/v1/deception-analytics/campaigns                 create_campaign
  GET   /api/v1/deception-analytics/campaigns                 list_campaigns
  PUT   /api/v1/deception-analytics/campaigns/{id}/stats      update_campaign_stats
  GET   /api/v1/deception-analytics/stats                     get_deception_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/deception-analytics",
    tags=["Deception Analytics"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.deception_analytics_engine import DeceptionAnalyticsEngine
        _engine = DeceptionAnalyticsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterAssetRequest(BaseModel):
    asset_name: str = Field(..., description="Human-readable asset name")
    asset_type: str = Field(
        default="honeypot",
        description=(
            "honeypot | honeytoken | canary_file | canary_cred | "
            "fake_service | honey_user | lure_document | breadcrumb"
        ),
    )
    location: str = Field(default="", description="Asset location (IP, path, URL)")
    decoy_category: str = Field(
        default="network",
        description="network | endpoint | cloud | identity | data | application",
    )
    active: bool = Field(default=True)


class RecordInteractionRequest(BaseModel):
    asset_id: str = Field(..., description="ID of the triggered deception asset")
    source_ip: str = Field(..., description="Attacker source IP address")
    attacker_technique: str = Field(
        default="recon",
        description=(
            "recon | lateral_movement | credential_access | execution | "
            "persistence | exfiltration | discovery | collection | impact"
        ),
    )
    confidence_score: float = Field(default=0.0, ge=0.0, le=100.0)
    threat_actor_signature: str = Field(default="")
    severity: str = Field(default="medium", description="critical | high | medium | low")
    details: str = Field(default="")
    detected_at: Optional[str] = Field(default=None)


class CreateCampaignRequest(BaseModel):
    campaign_name: str = Field(..., description="Campaign name")
    objective: str = Field(
        default="early_detection",
        description=(
            "early_detection | attacker_profiling | threat_intelligence | "
            "honeypot_network | insider_threat"
        ),
    )
    started_at: Optional[str] = Field(default=None)
    ended_at: Optional[str] = Field(default=None)


class UpdateCampaignStatsRequest(BaseModel):
    asset_count: Optional[int] = Field(default=None, ge=0)
    interaction_count: Optional[int] = Field(default=None, ge=0)
    unique_attacker_ips: Optional[int] = Field(default=None, ge=0)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/assets", dependencies=[Depends(api_key_auth)], status_code=201)
def register_asset(
    body: RegisterAssetRequest,
    org_id: str = Query(default="default"),
):
    """Register a new deception asset (honeypot, canary, lure, etc.)."""
    try:
        return _get_engine().register_asset(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error registering deception asset")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_assets(
    org_id: str = Query(default="default"),
    asset_type: Optional[str] = Query(default=None),
    active: Optional[bool] = Query(default=None),
):
    """List deception assets with optional type/active filters."""
    return _get_engine().list_assets(org_id, asset_type=asset_type, active=active)


@router.get("/assets/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_asset(
    asset_id: str,
    org_id: str = Query(default="default"),
):
    """Retrieve a single deception asset by ID."""
    asset = _get_engine().get_asset(org_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return asset


@router.put("/assets/{asset_id}/deactivate", dependencies=[Depends(api_key_auth)])
def deactivate_asset(
    asset_id: str,
    org_id: str = Query(default="default"),
):
    """Deactivate a deception asset."""
    try:
        return _get_engine().deactivate_asset(org_id, asset_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error deactivating asset")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/interactions", dependencies=[Depends(api_key_auth)], status_code=201)
def record_interaction(
    body: RecordInteractionRequest,
    org_id: str = Query(default="default"),
):
    """Record an attacker interaction with a deception asset."""
    try:
        return _get_engine().record_interaction(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error recording interaction")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/interactions", dependencies=[Depends(api_key_auth)])
def list_interactions(
    org_id: str = Query(default="default"),
    asset_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    attacker_technique: Optional[str] = Query(default=None),
):
    """List interactions with optional asset/severity/technique filters."""
    return _get_engine().list_interactions(
        org_id,
        asset_id=asset_id,
        severity=severity,
        attacker_technique=attacker_technique,
    )


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
    """List deception campaigns with optional status filter."""
    return _get_engine().list_campaigns(org_id, status=status)


@router.put("/campaigns/{campaign_id}/stats", dependencies=[Depends(api_key_auth)])
def update_campaign_stats(
    campaign_id: str,
    body: UpdateCampaignStatsRequest,
    org_id: str = Query(default="default"),
):
    """Update campaign statistics (asset_count, interaction_count, unique_attacker_ips)."""
    try:
        return _get_engine().update_campaign_stats(
            org_id,
            campaign_id,
            asset_count=body.asset_count,
            interaction_count=body.interaction_count,
            unique_attacker_ips=body.unique_attacker_ips,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error updating campaign stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_deception_stats(org_id: str = Query(default="default")):
    """Return aggregated deception statistics: assets, interactions, campaigns, breakdowns."""
    return _get_engine().get_deception_stats(org_id)
