"""VirusTotal v3 Threat-Intel Lookup Router — ALDECI.

Wraps ``core.virustotal_lookup_engine.VirusTotalLookupEngine`` with REST
endpoints mirroring the VirusTotal v3 surface.

Prefix: /api/v1/virustotal
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET /api/v1/virustotal/                            capability summary
  GET /api/v1/virustotal/v3/files/{hash}             file enrichment
  GET /api/v1/virustotal/v3/urls/{url_id}            URL analysis
  GET /api/v1/virustotal/v3/domains/{domain}         domain enrichment
  GET /api/v1/virustotal/v3/ip_addresses/{ip}        IP enrichment

NO MOCKS rule: when VT_API_KEY (or VIRUSTOTAL_API_KEY) is missing the
capability summary returns ``status="unavailable"`` and every live-lookup
endpoint returns HTTP 503. We do not fabricate analysis results.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/virustotal",
    tags=["VirusTotal Threat Intel"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch via reset_virustotal_lookup_engine().
    from core.virustotal_lookup_engine import get_virustotal_lookup_engine

    return get_virustotal_lookup_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    api_key_present: bool
    status: str  # ok | empty | unavailable
    cache_size: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run a VT call, translating engine errors to HTTP responses.

    VirusTotalUnavailableError -> 503 (auth missing, network, upstream error)
    ValueError                 -> 422 (input validation)
    """
    from core.virustotal_lookup_engine import VirusTotalUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except VirusTotalUnavailableError as exc:
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
        service="VirusTotal",
        endpoints=[
            "/v3/files/{hash}",
            "/v3/urls/{url_id}",
            "/v3/domains/{domain}",
            "/v3/ip_addresses/{ip}",
        ],
        api_key_present=api_key_present,
        status=status,
        cache_size=cache_size,
    )


@router.get("/v3/files/{hash}")
async def file_lookup(
    hash: str = Path(..., description="MD5 / SHA1 / SHA256 file hash"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(lambda: eng.lookup_file(hash))


@router.get("/v3/urls/{url_id}")
async def url_lookup(
    url_id: str = Path(..., description="VirusTotal URL identifier (sha256 or base64)"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(lambda: eng.lookup_url(url_id))


@router.get("/v3/domains/{domain}")
async def domain_lookup(
    domain: str = Path(..., description="Fully-qualified domain name"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(lambda: eng.lookup_domain(domain))


@router.get("/v3/ip_addresses/{ip}")
async def ip_lookup(
    ip: str = Path(..., description="IPv4 / IPv6 address"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(lambda: eng.lookup_ip(ip))


__all__ = ["router"]
