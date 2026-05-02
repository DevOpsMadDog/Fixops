"""Blast Radius Router — ALDECI (GAP-027 + GAP-046).

Surfaces the asset crown-jewel tagging + blast-radius scoring pipeline across
AssetCriticalityEngine, VulnerabilityScoringEngine, and RiskAggregatorEngine.

Prefix: /api/v1/blast-radius
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/blast-radius/crown-jewel                    tag_crown_jewel
  GET  /api/v1/blast-radius/crown-jewels                   list_crown_jewels
  POST /api/v1/blast-radius/compute                        compute_blast_radius_score
  GET  /api/v1/blast-radius/score-breakdown/{entity_ref}   get_score_breakdown
  GET  /api/v1/blast-radius/stats                          stats
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/blast-radius",
    tags=["Blast Radius"],
)

_asset_engine = None
_vuln_engine = None
_risk_engine = None


def _get_asset_engine():
    global _asset_engine
    if _asset_engine is None:
        from core.asset_criticality_engine import AssetCriticalityEngine
        _asset_engine = AssetCriticalityEngine()
    return _asset_engine


def _get_vuln_engine():
    global _vuln_engine
    if _vuln_engine is None:
        from core.vulnerability_scoring_engine import VulnerabilityScoringEngine
        _vuln_engine = VulnerabilityScoringEngine()
    return _vuln_engine


def _get_risk_engine():
    global _risk_engine
    if _risk_engine is None:
        from core.risk_aggregator_engine import RiskAggregatorEngine
        _risk_engine = RiskAggregatorEngine()
    return _risk_engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CrownJewelTag(BaseModel):
    org_id: str
    asset_ref: str
    reason: str = ""


class BlastRadiusCompute(BaseModel):
    org_id: str
    asset_ref: str
    max_hops: int = Field(default=3, ge=1, le=5)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/crown-jewel", dependencies=[Depends(api_key_auth)], status_code=201)
async def tag_crown_jewel(payload: CrownJewelTag) -> Dict[str, Any]:
    try:
        engine = _get_asset_engine()
        record = engine.tag_crown_jewel(
            org_id=payload.org_id,
            asset_ref=payload.asset_ref,
            reason=payload.reason,
        )
        return {"status": "tagged", "record": record}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/crown-jewels", dependencies=[Depends(api_key_auth)])
async def list_crown_jewels(org_id: str = Query(..., min_length=1)) -> Dict[str, Any]:
    engine = _get_asset_engine()
    tags = engine.list_crown_jewels(org_id)
    return {"org_id": org_id, "count": len(tags), "crown_jewels": tags}


@router.post("/compute", dependencies=[Depends(api_key_auth)])
async def compute_blast_radius(payload: BlastRadiusCompute) -> Dict[str, Any]:
    try:
        engine = _get_asset_engine()
        return engine.compute_blast_radius_score(
            org_id=payload.org_id,
            asset_ref=payload.asset_ref,
            max_hops=payload.max_hops,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/score-breakdown/{entity_ref}", dependencies=[Depends(api_key_auth)])
async def score_breakdown(
    entity_ref: str = Path(..., min_length=1),
    org_id: str = Query(..., min_length=1),
) -> Dict[str, Any]:
    engine = _get_risk_engine()
    return engine.get_score_breakdown(org_id, entity_ref)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
async def stats(org_id: str = Query(..., min_length=1)) -> Dict[str, Any]:
    asset_engine = _get_asset_engine()
    crown_jewels = asset_engine.list_crown_jewels(org_id)
    assets = asset_engine.list_assets(org_id)
    return {
        "org_id": org_id,
        "crown_jewel_count": len(crown_jewels),
        "registered_asset_count": len(assets),
        "top_crown_jewels": crown_jewels[:5],
    }
