"""Attack Surface Mapping API Router.

Endpoints for registering assets, querying exposure paths, scoring risk,
and computing full attack surface summaries per org.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.attack_surface import (
    Asset,
    AssetType,
    AttackSurface,
    AttackSurfaceMapper,
    ExposureLevel,
    ExposurePath,
    get_attack_surface_mapper,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/attack-surface", tags=["attack-surface"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterAssetRequest(BaseModel):
    name: str = Field(..., description="Asset name or identifier")
    type: AssetType = Field(..., description="Asset type")
    exposure_level: ExposureLevel = Field(ExposureLevel.INTERNAL, description="Exposure level")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Asset attributes (port, protocol, etc.)")
    tags: List[str] = Field(default_factory=list, description="Free-form tags")
    org_id: str = Field("default", description="Organisation ID")


class DiscoverFromFindingsRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="Pipeline findings to extract assets from")
    org_id: str = Field("default", description="Organisation ID")


class MapPathRequest(BaseModel):
    source_asset_id: str = Field(..., description="Source asset ID")
    target_asset_id: str = Field(..., description="Target asset ID")
    hops: List[str] = Field(default_factory=list, description="Intermediate hop asset IDs")
    protocol: str = Field("unknown", description="Network protocol")
    org_id: str = Field("default", description="Organisation ID")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _get_mapper() -> AttackSurfaceMapper:
    return get_attack_surface_mapper()


@router.post("/assets", response_model=Asset, summary="Register an asset")
def register_asset(req: RegisterAssetRequest) -> Asset:
    """Add or update an asset in the attack surface inventory."""
    mapper = _get_mapper()
    asset = Asset(
        name=req.name,
        type=req.type,
        exposure_level=req.exposure_level,
        attributes=req.attributes,
        tags=req.tags,
        org_id=req.org_id,
    )
    try:
        return mapper.register_asset(asset)
    except Exception as exc:
        logger.exception("Failed to register asset: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to register asset: {exc}") from exc


@router.get("/assets", response_model=List[Asset], summary="List assets")
def list_assets(
    org_id: str = Query("default", description="Organisation ID"),
    type_filter: Optional[AssetType] = Query(None, description="Filter by asset type"),
    exposure_filter: Optional[ExposureLevel] = Query(None, description="Filter by exposure level"),
) -> List[Asset]:
    """List all assets for an org with optional filters."""
    mapper = _get_mapper()
    return mapper.list_assets(org_id, type_filter=type_filter, exposure_filter=exposure_filter)


@router.get("/assets/{asset_id}", response_model=Asset, summary="Get asset")
def get_asset(asset_id: str) -> Asset:
    """Retrieve a single asset by ID."""
    mapper = _get_mapper()
    asset = mapper.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return asset


@router.delete("/assets/{asset_id}", summary="Delete asset")
def delete_asset(asset_id: str) -> Dict[str, Any]:
    """Remove an asset from the inventory."""
    mapper = _get_mapper()
    deleted = mapper.delete_asset(asset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return {"deleted": True, "asset_id": asset_id}


@router.get("/summary", response_model=AttackSurface, summary="Attack surface summary")
def get_surface_summary(
    org_id: str = Query("default", description="Organisation ID"),
) -> AttackSurface:
    """Return the full attack surface summary for an org."""
    mapper = _get_mapper()
    return mapper.get_attack_surface(org_id)


@router.get("/external", response_model=List[Asset], summary="External-facing assets")
def get_external_assets(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Asset]:
    """Return only internet-facing (EXTERNAL exposure) assets."""
    mapper = _get_mapper()
    return mapper.get_external_assets(org_id)


@router.get("/paths", response_model=List[ExposurePath], summary="Exposure paths")
def get_exposure_paths(
    org_id: str = Query("default", description="Organisation ID"),
    min_score: float = Query(0.0, ge=0.0, le=1.0, description="Minimum risk score"),
) -> List[ExposurePath]:
    """Return exposure paths, optionally filtered by minimum risk score."""
    mapper = _get_mapper()
    return mapper.get_high_risk_paths(org_id, min_score=min_score)


@router.get("/changes", summary="Recent surface changes")
def get_surface_changes(
    org_id: str = Query("default", description="Organisation ID"),
    since_days: int = Query(7, ge=1, le=365, description="Look-back window in days"),
) -> Dict[str, Any]:
    """Return new and potentially removed assets since N days ago."""
    mapper = _get_mapper()
    return mapper.get_surface_changes(org_id, since_days=since_days)


@router.post("/discover", response_model=List[Asset], summary="Discover assets from findings")
def discover_from_findings(req: DiscoverFromFindingsRequest) -> List[Asset]:
    """Extract and register assets from pipeline findings."""
    # Inject org_id into each finding if not present
    for f in req.findings:
        f.setdefault("org_id", req.org_id)
    mapper = _get_mapper()
    try:
        assets = mapper.discover_from_findings(req.findings)
        # TrustGraph explicit indexing (fire-and-forget)
        try:
            from core.trustgraph_event_bus import EVENT_FINDING_CREATED
            from core.trustgraph_event_bus import get_event_bus as _get_eb
            _bus = _get_eb()
            if _bus and _bus.enabled and assets:
                import asyncio as _asyncio
                _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                    "finding_id": f"attack-surface-{req.org_id}-{len(assets)}",
                    "type": "attack_surface_finding", "severity": "high",
                    "source": "attack_surface_router",
                    "data": {"org_id": req.org_id, "assets_discovered": len(assets)},
                }))
        except Exception:
            pass
        return assets
    except Exception as exc:
        logger.exception("Discovery failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Discovery failed: {exc}") from exc


@router.get("/score", summary="Attack surface risk score")
def get_surface_score(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return a numeric risk score (0-100) derived from the attack surface summary."""
    mapper = _get_mapper()
    surface = mapper.get_attack_surface(org_id)
    return {
        "org_id": org_id,
        "risk_score": round(surface.risk_score, 2),
        "total_assets": surface.total_assets,
        "external_assets": surface.external_assets,
        "high_risk_paths": surface.high_risk_paths,
    }


@router.get("/exposed", summary="Exposed assets")
def get_exposed_assets(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Asset]:
    """Return internet-facing (externally exposed) assets — alias for /external."""
    mapper = _get_mapper()
    return mapper.get_external_assets(org_id)


@router.get("/shadow-it", summary="Shadow IT assets")
def get_shadow_it(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return a list of unmanaged / shadow-IT assets (those with 'shadow' or 'unmanaged' tags)."""
    mapper = _get_mapper()
    all_assets = mapper.list_assets(org_id)
    shadow = [a for a in all_assets if any(t in ("shadow", "unmanaged", "shadow-it") for t in (getattr(a, "tags", []) or []))]
    return {"org_id": org_id, "shadow_it_count": len(shadow), "assets": shadow}


@router.post("/paths", response_model=ExposurePath, summary="Map an exposure path")
def map_exposure_path(req: MapPathRequest) -> ExposurePath:
    """Explicitly map an exposure path between two assets."""
    mapper = _get_mapper()
    try:
        return mapper.map_exposure_path(
            source_id=req.source_asset_id,
            target_id=req.target_asset_id,
            hops=req.hops,
            protocol=req.protocol,
            org_id=req.org_id,
        )
    except Exception as exc:
        logger.exception("Path mapping failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Path mapping failed: {exc}") from exc
