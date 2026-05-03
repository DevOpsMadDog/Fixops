"""Passive DNS Router — ALDECI.

REST endpoints for historical DNS tracking, fast-flux detection, and domain reputation.

Prefix: /api/v1/passive-dns
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/passive-dns/resolutions                  list_resolutions
  POST   /api/v1/passive-dns/resolutions                  record_resolution
  GET    /api/v1/passive-dns/domains/{domain}/history     get_domain_history
  GET    /api/v1/passive-dns/ips/{ip}/history             get_ip_history
  GET    /api/v1/passive-dns/domains/{domain}/fast-flux   detect_fast_flux
  GET    /api/v1/passive-dns/threats                      list_threats
  POST   /api/v1/passive-dns/threats                      add_threat
  GET    /api/v1/passive-dns/domains/{domain}/reputation  check_reputation
  GET    /api/v1/passive-dns/stats                        get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/passive-dns",
    tags=["Passive DNS"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.passive_dns_engine import PassiveDNSEngine
        _engine = PassiveDNSEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RecordResolutionRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    domain: str = Field(..., description="Domain name (e.g. example.com)")
    resolved_ip: str = Field(..., description="IP address the domain resolved to")
    record_type: str = Field("A", description="DNS record type: A/AAAA/MX/NS/CNAME/TXT")
    ttl: int = Field(3600, ge=0, description="Time-to-live in seconds")
    first_seen: Optional[str] = Field(None, description="ISO8601 first seen timestamp")
    last_seen: Optional[str] = Field(None, description="ISO8601 last seen timestamp")
    source: str = Field("query", description="Data source: sensor/feed/query")


class AddDomainThreatRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    domain: str = Field(..., description="Domain to mark as malicious")
    threat_type: str = Field(..., description="Threat type: c2/phishing/malware/spam/botnet")
    confidence: float = Field(0.5, ge=0.0, le=1.0, description="Confidence score 0-1")
    source: str = Field("manual", description="Source of the intelligence")
    iocs: List[str] = Field(default_factory=list, description="Associated IOCs")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_passive_dns_root(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return aggregate Passive DNS stats and capability summary for the org."""
    engine = _get_engine()
    stats = engine.get_dns_stats(org_id)
    return {
        "service": "passive-dns",
        "version": "1.0",
        "org_id": org_id,
        "capabilities": [
            "resolution-tracking",
            "fast-flux-detection",
            "domain-reputation",
            "threat-classification",
            "subsidiary-discovery",
        ],
        "stats": stats,
    }


@router.post("/resolutions", dependencies=[Depends(api_key_auth)], status_code=201)
def record_resolution(req: RecordResolutionRequest) -> Dict[str, Any]:
    """Record a DNS resolution event."""
    try:
        return _get_engine().record_resolution(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/resolutions", dependencies=[Depends(api_key_auth)])
def list_resolutions(
    org_id: str = Query("default"),
    domain: Optional[str] = Query(None),
    resolved_ip: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """List DNS resolutions with optional domain or IP filter."""
    return _get_engine().list_resolutions(
        org_id, domain=domain, resolved_ip=resolved_ip, limit=limit
    )


@router.get("/domains/{domain}/history", dependencies=[Depends(api_key_auth)])
def get_domain_history(
    domain: str,
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """Get all historical IPs for a domain, ordered by last_seen descending."""
    return _get_engine().get_domain_history(org_id, domain)


@router.get("/ips/{ip}/history", dependencies=[Depends(api_key_auth)])
def get_ip_history(
    ip: str,
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """Get all domains that ever resolved to this IP address."""
    return _get_engine().get_ip_history(org_id, ip)


@router.get("/domains/{domain}/fast-flux", dependencies=[Depends(api_key_auth)])
def detect_fast_flux(
    domain: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Detect fast-flux DNS patterns for a domain."""
    return _get_engine().detect_fast_flux(org_id, domain)


@router.post("/threats", dependencies=[Depends(api_key_auth)], status_code=201)
def add_domain_threat(req: AddDomainThreatRequest) -> Dict[str, Any]:
    """Mark a domain as malicious with threat classification."""
    try:
        return _get_engine().add_domain_threat(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/threats", dependencies=[Depends(api_key_auth)])
def list_domain_threats(
    org_id: str = Query("default"),
    threat_type: Optional[str] = Query(None),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
) -> List[Dict[str, Any]]:
    """List domain threats with optional type and confidence filters."""
    return _get_engine().list_domain_threats(
        org_id, threat_type=threat_type, min_confidence=min_confidence
    )


@router.get("/domains/{domain}/reputation", dependencies=[Depends(api_key_auth)])
def check_domain_reputation(
    domain: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Check domain reputation against recorded threats and resolution history."""
    return _get_engine().check_domain_reputation(org_id, domain)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_dns_stats(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get aggregate DNS statistics for an organisation."""
    return _get_engine().get_dns_stats(org_id)
