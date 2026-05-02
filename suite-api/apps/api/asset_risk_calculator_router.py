"""Asset Risk Calculator Router — ALDECI.

Exposes CRUD for assets, risk score calculation, risk factors, and stats.
Prefix: /api/v1/asset-risk
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/asset-risk",
    tags=["Asset Risk Calculator"],
)

# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.asset_risk_calculator import AssetRiskCalculator
        _engine = AssetRiskCalculator()
    return _engine


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    name: str
    asset_type: str = "server"
    criticality: str = "medium"
    exposure: str = "internal"
    owner: str = ""
    tags: List[str] = Field(default_factory=list)


class RiskFactorCreate(BaseModel):
    factor_type: str = "vulnerability"
    factor_name: str
    impact: float = 0.0
    description: str = ""


class RiskCalculateRequest(BaseModel):
    factors: List[Dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "List of score dicts with optional keys: "
            "vuln_score, threat_score, exposure_score, compliance_score (0-100)"
        ),
    )


# ---------------------------------------------------------------------------
# Asset endpoints
# ---------------------------------------------------------------------------

@router.post("/assets", dependencies=[Depends(api_key_auth)], status_code=201)
def create_asset(body: AssetCreate, org_id: str = Query(..., description="Organisation ID")):
    """Register a new asset profile."""
    try:
        return _get_engine().register_asset(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_assets(
     org_id: str = Query(default="default"),
    asset_type: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
):
    """List assets for an org with optional filters."""
    return _get_engine().list_assets(org_id, asset_type=asset_type, criticality=criticality)


@router.get("/assets/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_asset(asset_id: str, org_id: str = Query(default="default")):
    """Fetch a single asset by ID."""
    asset = _get_engine().get_asset(org_id, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


# ---------------------------------------------------------------------------
# Risk score endpoints
# ---------------------------------------------------------------------------

@router.post("/assets/{asset_id}/calculate", dependencies=[Depends(api_key_auth)])
def calculate_risk(
    asset_id: str,
    body: RiskCalculateRequest,
     org_id: str = Query(default="default"),
):
    """Calculate and persist a composite risk score for an asset."""
    try:
        return _get_engine().calculate_risk(org_id, asset_id, body.factors)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/assets/{asset_id}/score", dependencies=[Depends(api_key_auth)])
def get_latest_score(asset_id: str, org_id: str = Query(default="default")):
    """Return the most recent risk score for an asset."""
    score = _get_engine().get_latest_score(org_id, asset_id)
    if not score:
        raise HTTPException(status_code=404, detail="No score found for this asset")
    return score


@router.get("/scores", dependencies=[Depends(api_key_auth)])
def list_scores(
     org_id: str = Query(default="default"),
    risk_level: Optional[str] = Query(None),
):
    """Return latest score per asset for an org (optionally filtered by risk_level)."""
    return _get_engine().list_scores(org_id, risk_level=risk_level)


# ---------------------------------------------------------------------------
# Risk factor endpoints
# ---------------------------------------------------------------------------

@router.post("/assets/{asset_id}/factors", dependencies=[Depends(api_key_auth)], status_code=201)
def add_risk_factor(
    asset_id: str,
    body: RiskFactorCreate,
     org_id: str = Query(default="default"),
):
    """Add a risk factor for a specific asset."""
    try:
        return _get_engine().add_risk_factor(org_id, asset_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assets/{asset_id}/factors", dependencies=[Depends(api_key_auth)])
def list_risk_factors(asset_id: str, org_id: str = Query(default="default")):
    """List all risk factors for a specific asset."""
    return _get_engine().list_risk_factors(org_id, asset_id)


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_risk_stats(org_id: str = Query(default="default")):
    """Return aggregate risk statistics for an org."""
    return _get_engine().get_risk_stats(org_id)
