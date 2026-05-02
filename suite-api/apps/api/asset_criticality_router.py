"""Asset Criticality Router — ALDECI.

Endpoints for the Asset Criticality engine.

Prefix: /api/v1/asset-criticality
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/asset-criticality/assets                     register_asset
  POST /api/v1/asset-criticality/assets/{id}/score          score_asset
  POST /api/v1/asset-criticality/assets/{id}/dependencies   add_dependency
  GET  /api/v1/asset-criticality/assets/{id}                get_asset
  GET  /api/v1/asset-criticality/assets                     list_assets
  GET  /api/v1/asset-criticality/assets/{id}/critical-path  get_critical_path
  GET  /api/v1/asset-criticality/summary                    get_criticality_summary
"""
from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/asset-criticality",
    tags=["Asset Criticality"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.asset_criticality_engine import AssetCriticalityEngine
        _engine = AssetCriticalityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    asset_name: str
    asset_type: str
    owner: str = ""
    business_function: str = ""
    data_classification: str = "internal"
    availability_requirement: str = "medium"
    integrity_requirement: str = "medium"
    confidentiality_requirement: str = "medium"


class CriticalityFactor(BaseModel):
    factor_name: str
    factor_category: str = ""
    weight: float = 1.0
    value: float = 0.0


class AssetScore(BaseModel):
    factors: List[CriticalityFactor]


class DependencyCreate(BaseModel):
    depends_on_asset_id: str
    dependency_type: str = "technical"
    criticality_impact: str = "medium"


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

@router.post("/assets", dependencies=[Depends(api_key_auth)], status_code=201)
def register_asset(body: AssetCreate, org_id: str = Query(default="default")):
    """Register a new asset."""
    try:
        return _get_engine().register_asset(
            org_id=org_id,
            asset_name=body.asset_name,
            asset_type=body.asset_type,
            owner=body.owner,
            business_function=body.business_function,
            data_classification=body.data_classification,
            availability_requirement=body.availability_requirement,
            integrity_requirement=body.integrity_requirement,
            confidentiality_requirement=body.confidentiality_requirement,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/assets/{asset_id}/score", dependencies=[Depends(api_key_auth)])
def score_asset(asset_id: str, body: AssetScore, org_id: str = Query(default="default")):
    """Score an asset using weighted factors."""
    try:
        result = _get_engine().score_asset(
            asset_id=asset_id,
            org_id=org_id,
            factors=[f.model_dump() for f in body.factors],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


@router.post("/assets/{asset_id}/dependencies", dependencies=[Depends(api_key_auth)], status_code=201)
def add_dependency(asset_id: str, body: DependencyCreate, org_id: str = Query(default="default")):
    """Add a dependency between assets."""
    try:
        return _get_engine().add_dependency(
            asset_id=asset_id,
            org_id=org_id,
            depends_on_asset_id=body.depends_on_asset_id,
            dependency_type=body.dependency_type,
            criticality_impact=body.criticality_impact,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assets/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_asset(asset_id: str, org_id: str = Query(default="default")):
    """Get asset with factors and dependencies."""
    result = _get_engine().get_asset(asset_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_assets(
     org_id: str = Query(default="default"),
    criticality_tier: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
):
    """List assets with optional filters.

    Type-a #3 wiring: when the org has no registered assets, the engine falls
    back to SecurityFindingsEngine inventory — projects distinct asset_ids
    written by the cloud-credential-backed connectors (CSPM/SSPM/PAM/EDR) into
    asset records with derived criticality_score from severity weights.
    Returns a 5-state envelope (org_registered / security_findings /
    needs_credentials / needs_data / connector_error). NEVER mocks.
    """
    return _get_engine().list_assets_with_findings_fallback(
        org_id,
        criticality_tier=criticality_tier,
        asset_type=asset_type,
    )


@router.get("/assets/{asset_id}/critical-path", dependencies=[Depends(api_key_auth)])
def get_critical_path(asset_id: str, org_id: str = Query(default="default")):
    """Return transitive dependency path (BFS, max 3 hops)."""
    return _get_engine().get_critical_path(org_id, asset_id)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_criticality_summary(org_id: str = Query(default="default")):
    """Return criticality summary: count by tier, avg score, top 5 critical assets."""
    return _get_engine().get_criticality_summary(org_id)
