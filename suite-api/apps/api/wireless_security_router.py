"""Wireless Security Router — ALDECI.

Access point management and wireless threat tracking.

Prefix: /api/v1/wireless-security
Auth: api_key_auth dependency

Routes:
  POST  /api/v1/wireless-security/access-points                  register_access_point
  GET   /api/v1/wireless-security/access-points                  list_access_points
  GET   /api/v1/wireless-security/access-points/{ap_id}          get_access_point
  POST  /api/v1/wireless-security/threats                        record_wireless_threat
  GET   /api/v1/wireless-security/threats                        list_wireless_threats
  PUT   /api/v1/wireless-security/threats/{threat_id}/resolve    resolve_threat
  GET   /api/v1/wireless-security/stats                          get_wireless_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/wireless-security",
    tags=["Wireless Security"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.wireless_security_engine import WirelessSecurityEngine
        _engine = WirelessSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterAPRequest(BaseModel):
    org_id: str = Field(default="default")
    name: str = Field(..., description="Access point name")
    band: str = Field(..., description="Frequency band: 2.4ghz, 5ghz, 6ghz, dual_band")
    security_protocol: str = Field(default="wpa2", description="Security protocol: open, wep, wpa, wpa2, wpa3")
    ssid: Optional[str] = Field(default=None)
    bssid: Optional[str] = Field(default=None)
    location: Optional[str] = Field(default=None)


class RecordThreatRequest(BaseModel):
    org_id: str = Field(default="default")
    threat_type: str = Field(..., description="Type: rogue_ap, evil_twin, deauth_attack, krack, pmkid, wardriving, eavesdropping")
    severity: str = Field(..., description="Severity: low, medium, high, critical")
    ap_id: Optional[str] = Field(default=None)
    bssid: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None)


class ResolveThreatRequest(BaseModel):
    org_id: str = Field(default="default")
    resolution: str = Field(..., description="Resolution description")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/access-points", dependencies=[Depends(api_key_auth)])
def register_access_point(req: RegisterAPRequest) -> Dict[str, Any]:
    """Register a new wireless access point."""
    try:
        return _get_engine().register_access_point(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_access_point failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/access-points", dependencies=[Depends(api_key_auth)])
def list_access_points(
    org_id: str = Query(default="default"),
    band: Optional[str] = Query(default=None),
    security_protocol: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List wireless access points."""
    try:
        return _get_engine().list_access_points(org_id, band=band, security_protocol=security_protocol)
    except Exception as exc:
        _logger.exception("list_access_points failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/access-points/{ap_id}", dependencies=[Depends(api_key_auth)])
def get_access_point(ap_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get a single access point by ID."""
    try:
        return _get_engine().get_access_point(org_id, ap_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("get_access_point failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/threats", dependencies=[Depends(api_key_auth)])
def record_wireless_threat(req: RecordThreatRequest) -> Dict[str, Any]:
    """Record a wireless threat event."""
    try:
        return _get_engine().record_wireless_threat(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("record_wireless_threat failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/threats", dependencies=[Depends(api_key_auth)])
def list_wireless_threats(
    org_id: str = Query(default="default"),
    threat_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List wireless threats."""
    try:
        return _get_engine().list_wireless_threats(org_id, threat_type=threat_type, status=status)
    except Exception as exc:
        _logger.exception("list_wireless_threats failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/threats/{threat_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_threat(threat_id: str, req: ResolveThreatRequest) -> Dict[str, Any]:
    """Resolve a wireless threat."""
    try:
        return _get_engine().resolve_threat(req.org_id, threat_id, req.resolution)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("resolve_threat failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_wireless_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get wireless security stats for org."""
    try:
        return _get_engine().get_wireless_stats(org_id)
    except Exception as exc:
        _logger.exception("get_wireless_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
