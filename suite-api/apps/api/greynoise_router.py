"""GreyNoise Threat-Intel Lookup Router — ALDECI.

Wraps ``core.greynoise_lookup_engine.GreyNoiseLookupEngine`` with REST endpoints
for community-tier, context, and RIOT lookups.

Prefix: /api/v1/greynoise
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/greynoise/                          capability summary
  GET  /api/v1/greynoise/v3/community/{ip}          free-tier classification
  GET  /api/v1/greynoise/v2/noise/context/{ip}      paid context (tags, CVE, ASN…)
  GET  /api/v1/greynoise/v2/riot/{ip}               paid RIOT (known-good services)

NO MOCKS rule:
  * Community endpoint works without GREYNOISE_API_KEY (free public tier).
  * Context + RIOT endpoints require GREYNOISE_API_KEY — when missing, the
    capability summary surfaces ``status="unavailable"`` and the live endpoints
    return HTTP 503. We do not fabricate payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/greynoise",
    tags=["GreyNoise Threat Intel"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch the module-level engine via
    # reset_greynoise_lookup_engine() then re-create with tmp_path DB.
    from core.greynoise_lookup_engine import get_greynoise_lookup_engine

    return get_greynoise_lookup_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    api_key_present: bool
    status: str  # ok | empty | unavailable
    cache_size: int = 0


class CommunityResponse(BaseModel):
    ip: str
    noise: bool = False
    riot: bool = False
    classification: str = "unknown"
    name: str = ""
    link: str = ""
    last_seen: str = ""
    message: str = ""


class ContextRawData(BaseModel):
    scan: List[Dict[str, Any]] = Field(default_factory=list)
    web: Dict[str, Any] = Field(default_factory=dict)
    ja3: List[Dict[str, Any]] = Field(default_factory=list)


class ContextResponse(BaseModel):
    ip: str
    seen: bool = False
    classification: str = "unknown"
    first_seen: str = ""
    last_seen: str = ""
    actor: str = ""
    tags: List[str] = Field(default_factory=list)
    cve: List[str] = Field(default_factory=list)
    asn: str = ""
    organization: str = ""
    raw_data: ContextRawData = Field(default_factory=ContextRawData)


class RiotResponse(BaseModel):
    ip: str
    riot: bool = False
    name: str = ""
    category: str = ""
    description: str = ""
    explanation: str = ""
    last_updated: str = ""
    reference: str = ""
    trust_level: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run a GreyNoise call, translating engine errors to HTTP responses.

    GreyNoiseUnavailableError -> 503 (key missing, network, upstream error)
    ValueError                -> 422 (input validation)
    """
    from core.greynoise_lookup_engine import GreyNoiseUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except GreyNoiseUnavailableError as exc:
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
        service="GreyNoise",
        endpoints=[
            "/v3/community/{ip} (free)",
            "/v2/noise/context/{ip} (paid)",
            "/v2/riot/{ip}",
        ],
        api_key_present=api_key_present,
        status=status,
        cache_size=cache_size,
    )


@router.get("/v3/community/{ip}", response_model=CommunityResponse)
async def community_lookup(
    ip: str = Path(..., description="IPv4 / IPv6 address to look up (free tier)"),
) -> CommunityResponse:
    """Community v3 classification (works without API key, rate-limited)."""
    eng = _engine()
    data = _serve(lambda: eng.community(ip))
    return CommunityResponse(**data)


@router.get("/v2/noise/context/{ip}", response_model=ContextResponse)
async def noise_context_lookup(
    ip: str = Path(..., description="IPv4 / IPv6 address (paid context endpoint)"),
) -> ContextResponse:
    """Context v2 — paid tier (tags, CVEs, ASN, raw scan/web/ja3)."""
    eng = _engine()
    data = _serve(lambda: eng.context(ip))
    return ContextResponse(**data)


@router.get("/v2/riot/{ip}", response_model=RiotResponse)
async def riot_lookup(
    ip: str = Path(..., description="IPv4 / IPv6 address (RIOT known-good check)"),
) -> RiotResponse:
    """RIOT v2 — paid tier (known-good services lookup)."""
    eng = _engine()
    data = _serve(lambda: eng.riot(ip))
    return RiotResponse(**data)


__all__ = ["router"]
