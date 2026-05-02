"""Threat Exposure Router — ALDECI.

Correlates threat intelligence with asset exposure to compute actual threat
exposure per asset.

Prefix: /api/v1/threat-exposure
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/threat-exposure/assets                      register_asset
  GET    /api/v1/threat-exposure/assets                      list_assets
  GET    /api/v1/threat-exposure/assets/{asset_id}           get_asset
  POST   /api/v1/threat-exposure/correlations                correlate_threat
  GET    /api/v1/threat-exposure/correlations                list_correlations
  POST   /api/v1/threat-exposure/assets/{asset_id}/calculate calculate_exposure
  GET    /api/v1/threat-exposure/assets/{asset_id}/history   get_exposure_history
  GET    /api/v1/threat-exposure/top-exposed                 get_top_exposed_assets
  GET    /api/v1/threat-exposure/stats                       get_exposure_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-exposure",
    tags=["Threat Exposure"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_exposure_engine import ThreatExposureEngine
        _engine = ThreatExposureEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterAssetRequest(BaseModel):
    org_id: str = Field(default="default")
    asset_id: str = Field(..., description="Unique asset identifier")
    asset_name: str = Field(..., description="Human-readable asset name")
    asset_type: str = Field(
        default="host",
        description="host/application/network/cloud/user/api",
    )
    vuln_count: int = Field(default=0, ge=0, description="Known vulnerability count")


class CorrelateThreatRequest(BaseModel):
    org_id: str = Field(default="default")
    asset_id: str = Field(..., description="Asset to correlate threat against")
    threat_id: Optional[str] = Field(default=None, description="Threat identifier (auto-generated if omitted)")
    threat_type: str = Field(
        default="exploit",
        description="malware/apt/ransomware/phishing/exploit/insider",
    )
    confidence: float = Field(default=50.0, ge=0.0, le=100.0, description="Confidence 0-100")
    severity: str = Field(default="medium", description="critical/high/medium/low")
    ioc_matched: bool = Field(default=False, description="Whether an IOC matched")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/assets", dependencies=[Depends(api_key_auth)], status_code=201)
def register_asset(req: RegisterAssetRequest) -> Dict[str, Any]:
    """Register a new asset for exposure tracking."""
    try:
        return _get_engine().register_asset(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_asset failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_assets(
    org_id: str = Query(default="default"),
    asset_type: Optional[str] = Query(default=None),
    exposure_level: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List assets with optional type and exposure_level filters."""
    try:
        return _get_engine().list_assets(org_id, asset_type=asset_type, exposure_level=exposure_level)
    except Exception as exc:
        _logger.exception("list_assets failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/top-exposed", dependencies=[Depends(api_key_auth)])
def get_top_exposed_assets(
    org_id: str = Query(default="default"),
    limit: int = Query(default=10, ge=1, le=100),
) -> List[Dict[str, Any]]:
    """Return top-N assets by exposure score."""
    try:
        return _get_engine().get_top_exposed_assets(org_id, limit=limit)
    except Exception as exc:
        _logger.exception("get_top_exposed_assets failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_exposure_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregated exposure statistics."""
    try:
        return _get_engine().get_exposure_stats(org_id)
    except Exception as exc:
        _logger.exception("get_exposure_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/assets/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_asset(asset_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get a single asset by asset_id."""
    try:
        result = _get_engine().get_asset(org_id, asset_id)
        if not result:
            raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("get_asset failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/correlations", dependencies=[Depends(api_key_auth)], status_code=201)
def correlate_threat(req: CorrelateThreatRequest) -> Dict[str, Any]:
    """Correlate a threat with an asset."""
    try:
        return _get_engine().correlate_threat(req.org_id, req.model_dump(exclude={"org_id"}))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("correlate_threat failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/correlations", dependencies=[Depends(api_key_auth)])
def list_correlations(
    org_id: str = Query(default="default"),
    asset_id: Optional[str] = Query(default=None),
    threat_type: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List threat correlations with optional filters."""
    try:
        return _get_engine().list_correlations(org_id, asset_id=asset_id, threat_type=threat_type)
    except Exception as exc:
        _logger.exception("list_correlations failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/assets/{asset_id}/calculate", dependencies=[Depends(api_key_auth)])
def calculate_exposure(asset_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Recalculate exposure score for an asset from all correlations."""
    try:
        result = _get_engine().calculate_exposure(org_id, asset_id)
        if not result:
            raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("calculate_exposure failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/assets/{asset_id}/history", dependencies=[Depends(api_key_auth)])
def get_exposure_history(
    asset_id: str,
    org_id: str = Query(default="default"),
    limit: int = Query(default=30, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """Return exposure history for an asset."""
    try:
        return _get_engine().get_exposure_history(org_id, asset_id, limit=limit)
    except Exception as exc:
        _logger.exception("get_exposure_history failed")
        raise HTTPException(status_code=500, detail=str(exc))
