"""
Asset Criticality Router — ALDECI.

Endpoints:
  POST /api/v1/asset-criticality/assets
  GET  /api/v1/asset-criticality/assets
  GET  /api/v1/asset-criticality/assets/{asset_id}
  GET  /api/v1/asset-criticality/assets/{asset_id}/score
  PUT  /api/v1/asset-criticality/assets/{asset_id}
  GET  /api/v1/asset-criticality/stats
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "asset_criticality_router: auth_deps not available"
    )
    _AUTH_DEP = []

from core.asset_criticality_scorer import AssetCriticalityScorer

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/asset-criticality",
    tags=["asset-criticality"],
    dependencies=_AUTH_DEP,
)

# Lazy singleton (shared, single DB file)
_scorer: Optional[AssetCriticalityScorer] = None


def _get_scorer() -> AssetCriticalityScorer:
    global _scorer
    if _scorer is None:
        _scorer = AssetCriticalityScorer()
    return _scorer


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AssetCreate(BaseModel):
    asset_name: str
    asset_type: str = "server"
    business_owner: str = ""
    data_classification: str = "internal"
    internet_facing: bool = False
    regulatory_scope: List[str] = Field(default_factory=list)
    dependencies_count: int = Field(default=0, ge=0)


class AssetUpdate(BaseModel):
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None
    business_owner: Optional[str] = None
    data_classification: Optional[str] = None
    internet_facing: Optional[bool] = None
    regulatory_scope: Optional[List[str]] = None
    dependencies_count: Optional[int] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/assets", status_code=201)
async def register_asset(
    payload: AssetCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Register a new asset and compute its criticality score."""
    scorer = _get_scorer()
    try:
        return scorer.register_asset(org_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/assets")
async def list_assets(
    org_id: str = Query(default="default"),
    criticality_tier: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List assets for an org, optionally filtered by criticality tier."""
    scorer = _get_scorer()
    return scorer.list_assets(org_id, criticality_tier=criticality_tier)


@router.get("/assets/{asset_id}")
async def get_asset(
    asset_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a single asset by ID."""
    scorer = _get_scorer()
    result = scorer.get_asset(org_id, asset_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return result


@router.get("/assets/{asset_id}/score")
async def score_asset(
    asset_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Recompute and return criticality score for an existing asset."""
    scorer = _get_scorer()
    try:
        return scorer.score_asset(org_id, asset_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.put("/assets/{asset_id}")
async def update_asset(
    asset_id: str,
    payload: AssetUpdate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Update asset attributes and recompute criticality score."""
    scorer = _get_scorer()
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    try:
        return scorer.update_asset(org_id, asset_id, updates)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/stats")
async def get_criticality_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get aggregated criticality stats: totals, by_tier, avg_score, internet_facing."""
    scorer = _get_scorer()
    return scorer.get_criticality_stats(org_id)


__all__ = ["router"]
