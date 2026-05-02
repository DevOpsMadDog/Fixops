"""Subsidiary Attribution Router — ALDECI (GAP-030 + GAP-045).

Unified REST surface for subsidiary-aware attack-surface intelligence:
  - Attribute discovered assets to named subsidiaries (GAP-030)
  - Tag assets with network-zone exposure layers (GAP-045)
  - Discover candidate subsidiary domains from passive DNS (GAP-030)
  - Register dark-web monitors scoped to subsidiary names (GAP-030)

Prefix: /api/v1/subsidiary
Auth:   api_key_auth dependency on every endpoint
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/subsidiary",
    tags=["Subsidiary Attribution"],
)


# ---------------------------------------------------------------------------
# Lazy engine singletons (avoid import cost at app boot)
# ---------------------------------------------------------------------------

_as_engine = None
_pdns_engine = None
_dwm_engine = None


def _get_attack_surface_engine():
    global _as_engine
    if _as_engine is None:
        from core.attack_surface_engine import AttackSurfaceEngine
        _as_engine = AttackSurfaceEngine()
    return _as_engine


def _get_passive_dns_engine():
    global _pdns_engine
    if _pdns_engine is None:
        from core.passive_dns_engine import PassiveDNSEngine
        _pdns_engine = PassiveDNSEngine()
    return _pdns_engine


def _get_dark_web_engine():
    global _dwm_engine
    if _dwm_engine is None:
        from core.dark_web_monitoring_engine import DarkWebMonitoringEngine
        _dwm_engine = DarkWebMonitoringEngine()
    return _dwm_engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AttributeAssetRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    asset_ref: str = Field(..., description="Opaque reference to the asset (e.g. domain, ID)")
    subsidiary_name: str = Field(..., description="Subsidiary / business-unit name")
    attribution_source: str = Field(..., description="Source of attribution: manual / whois / registration / heuristic")
    confidence: float = Field(0.5, ge=0.0, le=1.0, description="Attribution confidence (0-1)")


class ExposureLayerRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    asset_ref: str = Field(..., description="Opaque reference to the asset")
    exposure_layer: str = Field(
        ...,
        description=(
            "Network-zone tag: external-internet / dmz / internal / restricted / isolated"
        ),
    )


class DarkWebMonitorRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    subsidiary_name: str = Field(..., description="Subsidiary to monitor on dark-web sources")
    keywords: List[str] = Field(
        default_factory=list,
        description="Keywords (brands, email domains, product names) to watch for",
    )


class FindDomainsRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    parent_domain: str = Field(..., description="Parent-org apex domain, e.g. acmecorp.com")
    seed_patterns: List[str] = Field(
        default_factory=list,
        description="Optional seed substrings to boost confidence (e.g. subsidiary names)",
    )


# ---------------------------------------------------------------------------
# Endpoints — Subsidiary Attribution (GAP-030)
# ---------------------------------------------------------------------------

@router.post(
    "/attribute",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def attribute_asset(req: AttributeAssetRequest) -> Dict[str, Any]:
    """Attribute an asset to a subsidiary (GAP-030)."""
    try:
        return _get_attack_surface_engine().attribute_asset_to_subsidiary(
            org_id=req.org_id,
            asset_ref=req.asset_ref,
            subsidiary_name=req.subsidiary_name,
            attribution_source=req.attribution_source,
            confidence=req.confidence,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_subsidiary_assets(
    org_id: str = Query("default"),
    subsidiary_name: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List subsidiary-attributed assets, optionally filtered by subsidiary name."""
    return _get_attack_surface_engine().list_subsidiary_assets(
        org_id=org_id,
        subsidiary_name=subsidiary_name,
    )


# ---------------------------------------------------------------------------
# Endpoints — Exposure Layer Tagging (GAP-045)
# ---------------------------------------------------------------------------

@router.post(
    "/exposure-layer",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def tag_exposure_layer(req: ExposureLayerRequest) -> Dict[str, Any]:
    """Tag an asset with a network-zone exposure layer (GAP-045)."""
    try:
        return _get_attack_surface_engine().tag_exposure_layer(
            org_id=req.org_id,
            asset_ref=req.asset_ref,
            exposure_layer=req.exposure_layer,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/exposure", dependencies=[Depends(api_key_auth)])
def list_assets_by_exposure(
    org_id: str = Query("default"),
    exposure_layer: str = Query(..., description="One of external-internet/dmz/internal/restricted/isolated"),
) -> List[Dict[str, Any]]:
    """List assets tagged with a given exposure layer (GAP-045)."""
    try:
        return _get_attack_surface_engine().list_assets_by_exposure(
            org_id=org_id,
            exposure_layer=exposure_layer,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints — Dark-Web Subsidiary Monitors (GAP-030)
# ---------------------------------------------------------------------------

@router.post(
    "/dark-web-monitor",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def register_dark_web_monitor(req: DarkWebMonitorRequest) -> Dict[str, Any]:
    """Register (or update) a dark-web monitor for a subsidiary."""
    try:
        return _get_dark_web_engine().monitor_subsidiary_mentions(
            org_id=req.org_id,
            subsidiary_name=req.subsidiary_name,
            keywords=req.keywords,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints — Subsidiary Domain Discovery (GAP-030)
# ---------------------------------------------------------------------------

@router.post(
    "/find-domains",
    dependencies=[Depends(api_key_auth)],
    status_code=200,
)
def find_subsidiary_domains(req: FindDomainsRequest) -> List[Dict[str, Any]]:
    """Heuristic discovery of candidate subsidiary domains from passive DNS."""
    try:
        return _get_passive_dns_engine().find_subsidiary_domains(
            org_id=req.org_id,
            parent_domain=req.parent_domain,
            seed_patterns=req.seed_patterns,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
