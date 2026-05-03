"""Censys Threat-Intel Lookup Router — ALDECI.

Wraps ``core.censys_lookup_engine.CensysLookupEngine`` with REST endpoints
for host lookups, certificate lookups, and host search against the
Censys v2 API.

Prefix: /api/v1/censys
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/censys/                              capability summary
  GET  /api/v1/censys/v2/hosts/{ip}                 host enrichment
  GET  /api/v1/censys/v2/certificates/{fingerprint} certificate detail
  GET  /api/v1/censys/v2/hosts/search?q=&per_page=  host search

NO MOCKS rule: when CENSYS_API_ID or CENSYS_API_SECRET is missing the
capability summary returns ``status="unavailable"`` and every
live-lookup endpoint returns HTTP 503. We do not fabricate data.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/censys",
    tags=["Censys Threat Intel"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch via reset_censys_lookup_engine().
    from core.censys_lookup_engine import get_censys_lookup_engine

    return get_censys_lookup_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    api_id_present: bool
    api_secret_present: bool
    status: str  # ok | empty | unavailable
    cache_size: int = 0


class HostService(BaseModel):
    port: Optional[int] = None
    protocol: Optional[str] = None
    software: List[Any] = Field(default_factory=list)


class HostLocation(BaseModel):
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    continent: Optional[str] = None


class AutonomousSystem(BaseModel):
    asn: Optional[int] = None
    name: Optional[str] = None
    country_code: Optional[str] = None


class HostResponse(BaseModel):
    ip: Optional[str] = None
    services: List[HostService] = Field(default_factory=list)
    location: HostLocation = Field(default_factory=HostLocation)
    autonomous_system: AutonomousSystem = Field(default_factory=AutonomousSystem)
    last_updated_at: Optional[str] = None


class ValidityPeriod(BaseModel):
    start: Optional[str] = None
    end: Optional[str] = None
    length_seconds: Optional[int] = None


class CertParsed(BaseModel):
    subject: Optional[Any] = None
    issuer: Optional[Any] = None
    validity_period: ValidityPeriod = Field(default_factory=ValidityPeriod)
    names: List[str] = Field(default_factory=list)


class CertificateResponse(BaseModel):
    fingerprint: Optional[str] = None
    parsed: CertParsed = Field(default_factory=CertParsed)
    ct_logs: List[Any] = Field(default_factory=list)


class SearchServiceSummary(BaseModel):
    port: Optional[int] = None
    service_name: Optional[str] = None


class SearchHit(BaseModel):
    ip: Optional[str] = None
    name: Optional[str] = None
    services_summary: List[SearchServiceSummary] = Field(default_factory=list)


class SearchResultBlock(BaseModel):
    total: int = 0
    hits: List[SearchHit] = Field(default_factory=list)


class SearchResponse(BaseModel):
    result: SearchResultBlock = Field(default_factory=SearchResultBlock)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run a Censys call, translating engine errors to HTTP responses.

    CensysUnavailableError -> 503 (auth missing, network, upstream error)
    ValueError             -> 422 (input validation)
    """
    from core.censys_lookup_engine import CensysUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CensysUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without credentials."""
    eng = _engine()
    api_id_present = eng.api_id_present()
    api_secret_present = eng.api_secret_present()
    creds_ok = api_id_present and api_secret_present
    cache_size = eng.cache_size()
    if not creds_ok:
        status = "unavailable"
    elif cache_size == 0:
        status = "empty"
    else:
        status = "ok"
    return CapabilityResponse(
        service="Censys",
        endpoints=[
            "/v2/hosts/{ip}",
            "/v2/certificates/{fingerprint}",
            "/v2/hosts/search",
        ],
        api_id_present=api_id_present,
        api_secret_present=api_secret_present,
        status=status,
        cache_size=cache_size,
    )


@router.get("/v2/hosts/search", response_model=SearchResponse)
async def hosts_search(
    q: str = Query(..., min_length=1, description="Censys search query"),
    per_page: int = Query(25, ge=1, le=100),
) -> SearchResponse:
    """Host search.

    NOTE: This route MUST be registered BEFORE ``/v2/hosts/{ip}``. FastAPI
    matches routes in registration order, so a path-parameter route declared
    first would swallow ``/v2/hosts/search`` (capturing ``ip="search"``) and
    cause this endpoint to 404. Do not reorder.
    """
    eng = _engine()
    data = _serve(lambda: eng.search_hosts(q, per_page=per_page))
    return SearchResponse(**data)


@router.get("/v2/hosts/{ip}", response_model=HostResponse)
async def host_lookup(
    ip: str = Path(..., description="IPv4 / IPv6 address to look up"),
) -> HostResponse:
    eng = _engine()
    data = _serve(lambda: eng.lookup_host(ip))
    return HostResponse(**data)


@router.get(
    "/v2/certificates/{fingerprint}", response_model=CertificateResponse
)
async def certificate_lookup(
    fingerprint: str = Path(
        ..., description="SHA-256 certificate fingerprint (hex)"
    ),
) -> CertificateResponse:
    eng = _engine()
    data = _serve(lambda: eng.lookup_certificate(fingerprint))
    return CertificateResponse(**data)


__all__ = ["router"]
