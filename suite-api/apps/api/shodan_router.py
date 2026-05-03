"""Shodan Threat-Intel Lookup Router — ALDECI.

Wraps ``core.shodan_lookup_engine.ShodanLookupEngine`` with REST endpoints
for host lookups, search, honeyscore, count, and DNS resolution.

Prefix: /api/v1/shodan
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/shodan/                       capability summary
  GET  /api/v1/shodan/host/{ip}              host enrichment
  GET  /api/v1/shodan/search?q=&page=        full-text query
  GET  /api/v1/shodan/honeyscore/{ip}        0..1 honeypot probability
  GET  /api/v1/shodan/count?q=               result count + facets
  GET  /api/v1/shodan/dns/resolve?hostnames= hostname → IP map

NO MOCKS rule: when SHODAN_API_KEY is missing the capability summary
returns ``status="unavailable"`` and every live-lookup endpoint returns
HTTP 503. We do not fabricate IPs/hosts/scores.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/shodan",
    tags=["Shodan Threat Intel"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch the module-level engine via reset_shodan_lookup_engine().
    from core.shodan_lookup_engine import get_shodan_lookup_engine

    return get_shodan_lookup_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    api_key_present: bool
    status: str  # ok | empty | unavailable
    cache_size: int = 0


class HostService(BaseModel):
    port: Optional[int] = None
    protocol: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


class HostResponse(BaseModel):
    ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    hostnames: List[str] = Field(default_factory=list)
    services: List[HostService] = Field(default_factory=list)
    vulns: List[str] = Field(default_factory=list)


class SearchLocation(BaseModel):
    country_name: Optional[str] = None
    city: Optional[str] = None


class SearchMatch(BaseModel):
    ip_str: Optional[str] = None
    port: Optional[int] = None
    hostnames: List[str] = Field(default_factory=list)
    location: SearchLocation = Field(default_factory=SearchLocation)
    product: Optional[str] = None


class SearchResponse(BaseModel):
    total: int
    matches: List[SearchMatch] = Field(default_factory=list)
    facets: Optional[Dict[str, Any]] = None


class HoneyscoreResponse(BaseModel):
    ip: str
    honeyscore: float = Field(..., ge=0.0, le=1.0)


class CountResponse(BaseModel):
    total: int
    facets: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run a Shodan call, translating engine errors to HTTP responses.

    ShodanUnavailableError -> 503 (auth missing, network, upstream error)
    ValueError             -> 422 (input validation)
    """
    from core.shodan_lookup_engine import ShodanUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ShodanUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without an API key."""
    eng = _engine()
    api_key_present = eng.api_key_present()
    cache_size = eng.cache_size()
    if not api_key_present:
        status = "unavailable"
    elif cache_size == 0:
        status = "empty"
    else:
        status = "ok"
    return CapabilityResponse(
        service="Shodan",
        endpoints=[
            "/host/{ip}",
            "/search",
            "/honeyscore/{ip}",
            "/count",
            "/dns/resolve",
        ],
        api_key_present=api_key_present,
        status=status,
        cache_size=cache_size,
    )


@router.get("/host/{ip}", response_model=HostResponse)
async def host_lookup(
    ip: str = Path(..., description="IPv4 / IPv6 address to look up"),
) -> HostResponse:
    eng = _engine()
    data = _serve(lambda: eng.lookup_host(ip))
    return HostResponse(**data)


@router.get("/search", response_model=SearchResponse)
async def search(
    q: str = Query(..., min_length=1, description="Shodan search query"),
    page: int = Query(1, ge=1, le=1000),
) -> SearchResponse:
    eng = _engine()
    data = _serve(lambda: eng.search(q, page=page))
    return SearchResponse(**data)


@router.get("/honeyscore/{ip}", response_model=HoneyscoreResponse)
async def honeyscore(
    ip: str = Path(..., description="IP to score against the honeypot model"),
) -> HoneyscoreResponse:
    eng = _engine()
    data = _serve(lambda: eng.honeyscore(ip))
    return HoneyscoreResponse(**data)


@router.get("/count", response_model=CountResponse)
async def count(
    q: str = Query(..., min_length=1, description="Shodan search query"),
) -> CountResponse:
    eng = _engine()
    data = _serve(lambda: eng.count(q))
    return CountResponse(**data)


@router.get("/dns/resolve")
async def dns_resolve(
    hostnames: str = Query(
        ..., min_length=1, description="Comma-separated list of hostnames to resolve"
    ),
) -> Dict[str, Optional[str]]:
    eng = _engine()
    parts = [h.strip() for h in hostnames.split(",") if h.strip()]
    if not parts:
        raise HTTPException(status_code=422, detail="hostnames must not be empty")
    return _serve(lambda: eng.dns_resolve(parts))


__all__ = ["router"]
