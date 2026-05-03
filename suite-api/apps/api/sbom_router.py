"""SBOM Router — ALDECI.

Endpoints for the Software Bill of Materials generation engine.

Prefix: /api/v1/sbom
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/sbom/assets                              register_asset
  GET    /api/v1/sbom/assets                              list_assets
  GET    /api/v1/sbom/assets/{asset_id}                   get_asset
  POST   /api/v1/sbom/assets/{asset_id}/components        add_component
  GET    /api/v1/sbom/assets/{asset_id}/components        list_components
  GET    /api/v1/sbom/assets/{asset_id}/export/cyclonedx  generate_cyclonedx
  GET    /api/v1/sbom/assets/{asset_id}/export/spdx       generate_spdx
  GET    /api/v1/sbom/license-summary                     get_license_summary
  GET    /api/v1/sbom/vuln-exposure                       get_vuln_exposure
  GET    /api/v1/sbom/stats                               get_sbom_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sbom",
    tags=["sbom"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.sbom_engine import SBOMEngine
        _engine = SBOMEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    asset_name: str
    asset_type: str = "application"
    asset_version: str = ""
    description: str = ""
    team_owner: str = ""
    sbom_format: str = "cyclonedx"


class ComponentCreate(BaseModel):
    component_name: str
    component_version: str = ""
    component_type: str = "library"
    purl: str = ""
    cpe: str = ""
    license: str = ""
    supplier: str = ""
    ecosystem: str = ""
    known_vulns: List[str] = Field(default_factory=list)
    risk_score: Optional[float] = None


# ---------------------------------------------------------------------------
# Asset routes
# ---------------------------------------------------------------------------

@router.post("/assets", dependencies=[Depends(api_key_auth)], status_code=201)
def register_asset(body: AssetCreate, org_id: str = Query(default="default")):
    """Register a new asset for SBOM tracking."""
    try:
        return _get_engine().register_asset(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_assets(org_id: str = Query(default="default")):
    """List all assets for the org."""
    return _get_engine().list_assets(org_id)


@router.get("/assets/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_asset(asset_id: str, org_id: str = Query(default="default")):
    """Get an asset with component summary."""
    asset = _get_engine().get_asset(org_id, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


# ---------------------------------------------------------------------------
# Component routes
# ---------------------------------------------------------------------------

@router.post(
    "/assets/{asset_id}/components",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_component(asset_id: str, body: ComponentCreate, org_id: str = Query(default="default")):
    """Add a component to an asset's SBOM."""
    data = body.model_dump()
    if data.get("risk_score") is None:
        data.pop("risk_score", None)
    try:
        return _get_engine().add_component(org_id, asset_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assets/{asset_id}/components", dependencies=[Depends(api_key_auth)])
def list_components(
    asset_id: str,
     org_id: str = Query(default="default"),
    has_vulns: Optional[bool] = Query(None),
):
    """List components for an asset, optionally filtered by vulnerability presence."""
    return _get_engine().list_components(org_id, asset_id=asset_id, has_vulns=has_vulns)


# ---------------------------------------------------------------------------
# Export routes
# ---------------------------------------------------------------------------

@router.get("/assets/{asset_id}/export/cyclonedx", dependencies=[Depends(api_key_auth)])
def export_cyclonedx(asset_id: str, org_id: str = Query(default="default"), save: bool = Query(False)):
    """Generate and return a CycloneDX 1.4 SBOM for the asset."""
    try:
        sbom = _get_engine().generate_cyclonedx(org_id, asset_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if save:
        _get_engine().save_export(org_id, asset_id, "cyclonedx", sbom)
    return sbom


@router.get("/assets/{asset_id}/export/spdx", dependencies=[Depends(api_key_auth)])
def export_spdx(asset_id: str, org_id: str = Query(default="default"), save: bool = Query(False)):
    """Generate and return an SPDX 2.3 SBOM for the asset."""
    try:
        sbom = _get_engine().generate_spdx(org_id, asset_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if save:
        _get_engine().save_export(org_id, asset_id, "spdx", sbom)
    return sbom


# ---------------------------------------------------------------------------
# Analytics routes
# ---------------------------------------------------------------------------

@router.get("/license-summary", dependencies=[Depends(api_key_auth)])
def license_summary(org_id: str = Query(default="default")):
    """Return license risk breakdown for the org."""
    return _get_engine().get_license_summary(org_id)


@router.get("/vuln-exposure", dependencies=[Depends(api_key_auth)])
def vuln_exposure(org_id: str = Query(default="default")):
    """Return vulnerability exposure statistics for the org."""
    return _get_engine().get_vuln_exposure(org_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def sbom_stats(org_id: str = Query(default="default")):
    """Return aggregated SBOM statistics for the org."""
    return _get_engine().get_sbom_stats(org_id)


@router.get("/assets/{asset_id}/diff/{other_asset_id}", dependencies=[Depends(api_key_auth)])
def diff_sboms(
    asset_id: str,
    other_asset_id: str,
    org_id: str = Query(default="default"),
):
    """Return a component-level diff (added/removed/changed) between two assets.

    Keyed by purl. Useful for tracking what changed between two SBOM snapshots
    or two versions of an application.
    """
    engine = _get_engine()
    base = engine.get_asset(org_id, asset_id)
    if not base:
        raise HTTPException(status_code=404, detail=f"Base asset not found: {asset_id}")
    head = engine.get_asset(org_id, other_asset_id)
    if not head:
        raise HTTPException(status_code=404, detail=f"Head asset not found: {other_asset_id}")
    return engine.diff_sboms(org_id, asset_id, other_asset_id)


@router.get("/", dependencies=[Depends(api_key_auth)])
def sbom_overview(org_id: str = Query(default="default")):
    """Top-level SBOM overview: asset/component counts, vuln exposure, license summary."""
    engine = _get_engine()
    return {
        "status": "ok",
        "org_id": org_id,
        "stats": engine.get_sbom_stats(org_id),
        "vuln_exposure": engine.get_vuln_exposure(org_id),
        "license_summary": engine.get_license_summary(org_id),
    }
