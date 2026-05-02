"""Threat Geolocation Router — ALDECI.

Geographic threat event tracking, impossible travel detection, and country-level
block rule management.

Prefix: /api/v1/threat-geolocation
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/threat-geolocation/events              record_geo_event
  GET    /api/v1/threat-geolocation/events              list_geo_events
  GET    /api/v1/threat-geolocation/heatmap             get_country_heatmap
  POST   /api/v1/threat-geolocation/impossible-travel   detect_impossible_travel
  POST   /api/v1/threat-geolocation/block-rules         create_geo_block_rule
  GET    /api/v1/threat-geolocation/block-rules         list_geo_block_rules
  POST   /api/v1/threat-geolocation/check-ip            check_ip_allowed
  GET    /api/v1/threat-geolocation/stats               get_geo_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-geolocation",
    tags=["Threat Geolocation"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_geolocation_engine import ThreatGeolocationEngine
        _engine = ThreatGeolocationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class GeoEventRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    ip: str = Field(..., description="Source IP address")
    country_code: str = Field(..., description="ISO 3166-1 alpha-2 country code")
    country_name: str = Field(..., description="Human-readable country name")
    city: str = Field(default="", description="City name")
    lat: float = Field(default=0.0, description="Latitude")
    lon: float = Field(default=0.0, description="Longitude")
    event_type: str = Field(default="access", description="One of: login, scan, attack, access")
    risk_level: str = Field(default="low", description="One of: low, medium, high, critical")
    user_id: str = Field(default="", description="Associated user ID")


class ImpossibleTravelRequest(BaseModel):
    org_id: str = Field(default="default")
    user_id: str = Field(..., description="User identifier")
    events: List[Dict[str, Any]] = Field(
        ..., description="List of geo events with lat, lon, created_at fields"
    )


class GeoBlockRuleRequest(BaseModel):
    org_id: str = Field(default="default")
    country_code: str = Field(..., description="ISO 3166-1 alpha-2 country code to block")
    reason: str = Field(default="", description="Reason for blocking")
    severity: str = Field(default="high", description="Severity: low, medium, high, critical")


class CheckIPRequest(BaseModel):
    org_id: str = Field(default="default")
    ip: str = Field(..., description="IP address to check")
    country_code: str = Field(..., description="Country code for the IP")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/events", dependencies=[Depends(api_key_auth)])
def record_geo_event(req: GeoEventRequest) -> Dict[str, Any]:
    """Record a geographic threat event."""
    try:
        return _get_engine().record_geo_event(req.org_id, req.model_dump(exclude={"org_id"}))
    except Exception as exc:
        _logger.exception("record_geo_event failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/events", dependencies=[Depends(api_key_auth)])
def list_geo_events(
    org_id: str = Query(default="default"),
    country_code: Optional[str] = Query(default=None),
    risk_level: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """List geo events with optional filters."""
    try:
        return _get_engine().list_geo_events(org_id, country_code, risk_level, limit)
    except Exception as exc:
        _logger.exception("list_geo_events failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/heatmap", dependencies=[Depends(api_key_auth)])
def get_country_heatmap(
    org_id: str = Query(default="default"),
    hours: int = Query(default=24, ge=1, le=8760),
) -> List[Dict[str, Any]]:
    """Return country-level event heatmap for the last N hours."""
    try:
        return _get_engine().get_country_heatmap(org_id, hours)
    except Exception as exc:
        _logger.exception("get_country_heatmap failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/impossible-travel", dependencies=[Depends(api_key_auth)])
def detect_impossible_travel(req: ImpossibleTravelRequest) -> Dict[str, Any]:
    """Detect impossible travel patterns in a list of geo events."""
    try:
        return _get_engine().detect_impossible_travel(req.org_id, req.user_id, req.events)
    except Exception as exc:
        _logger.exception("detect_impossible_travel failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/block-rules", dependencies=[Depends(api_key_auth)])
def create_geo_block_rule(req: GeoBlockRuleRequest) -> Dict[str, Any]:
    """Create a country-level block rule."""
    try:
        return _get_engine().create_geo_block_rule(req.org_id, req.model_dump(exclude={"org_id"}))
    except Exception as exc:
        _logger.exception("create_geo_block_rule failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/block-rules", dependencies=[Depends(api_key_auth)])
def list_geo_block_rules(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    """List all geo block rules for the org."""
    try:
        return _get_engine().list_geo_block_rules(org_id)
    except Exception as exc:
        _logger.exception("list_geo_block_rules failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/check-ip", dependencies=[Depends(api_key_auth)])
def check_ip_allowed(req: CheckIPRequest) -> Dict[str, Any]:
    """Check whether an IP from a given country is permitted."""
    try:
        return _get_engine().check_ip_allowed(req.org_id, req.ip, req.country_code)
    except Exception as exc:
        _logger.exception("check_ip_allowed failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_geo_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return geo statistics for the org."""
    try:
        return _get_engine().get_geo_stats(org_id)
    except Exception as exc:
        _logger.exception("get_geo_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
