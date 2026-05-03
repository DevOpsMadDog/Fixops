"""AbuseIPDB Threat-Intel Router — ALDECI.

Combines two surfaces under prefix ``/api/v1/abuseipdb``:

  1. v2 lookup API (NEW — 2026-05-04) — wraps ``core.abuseipdb_lookup_engine``
     - GET  /                — capability summary
     - GET  /v2/check        — IP reputation lookup
     - GET  /v2/blacklist    — top-N abusive IP export
     - POST /v2/report       — submit an abuse report

  2. ET / AbuseIPDB blocklist importer (legacy — kept for back-compat)
     - POST /import          — pull ET compromised-ips + AbuseIPDB blacklist
     - GET  /ips             — list blocklisted IPs
     - GET  /check/{ip}      — single-IP blocklist lookup
     - GET  /stats           — store stats

NO MOCKS rule
-------------
* When ABUSEIPDB_API_KEY is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - GET /v2/check, GET /v2/blacklist, POST /v2/report → HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/abuseipdb",
    tags=["AbuseIPDB"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.abuseipdb_lookup_engine import get_abuseipdb_lookup_engine

    return get_abuseipdb_lookup_engine()


def _serve(callable_):
    """Run an AbuseIPDB call, translating engine errors to HTTP responses.

    AbuseIPDBUnavailableError -> 503 (key missing, network, upstream error)
    ValueError                -> 422 (input validation)
    """
    from core.abuseipdb_lookup_engine import AbuseIPDBUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except AbuseIPDBUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _get_importer():
    """Lazy import legacy ET/AbuseIPDB blocklist importer."""
    from feeds.abuseipdb.importer import (  # type: ignore
        check_ip,
        get_store_stats,
        list_ips,
        run_import,
    )
    return run_import, list_ips, check_ip, get_store_stats


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    api_key_present: bool
    status: str  # ok | empty | unavailable
    cache_size: int = 0


class CheckData(BaseModel):
    ipAddress: str
    isPublic: bool = False
    ipVersion: int = 4
    isWhitelisted: bool = False
    abuseConfidenceScore: int = 0
    countryCode: str = ""
    usageType: str = ""
    isp: str = ""
    domain: str = ""
    totalReports: int = 0
    numDistinctUsers: int = 0
    lastReportedAt: str = ""


class CheckResponse(BaseModel):
    data: CheckData


class BlacklistEntry(BaseModel):
    ipAddress: str
    countryCode: str = ""
    abuseConfidenceScore: int = 0
    lastReportedAt: str = ""


class BlacklistMeta(BaseModel):
    generatedAt: str = ""


class BlacklistResponse(BaseModel):
    meta: BlacklistMeta
    data: List[BlacklistEntry]


class ReportRequest(BaseModel):
    ip: str = Field(..., description="Public IPv4 / IPv6 to report")
    categories: List[int] = Field(
        ..., description="AbuseIPDB category codes (e.g. [18, 22])"
    )
    comment: str = Field("", description="Free-text report notes (optional)")


class ReportData(BaseModel):
    ipAddress: str
    abuseConfidenceScore: int = 0


class ReportResponse(BaseModel):
    data: ReportData


# ---------------------------------------------------------------------------
# v2 endpoints (NEW — 2026-05-04)
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse, summary="AbuseIPDB capability summary")
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
        service="AbuseIPDB",
        endpoints=["/v2/check", "/v2/blacklist", "/v2/report"],
        api_key_present=api_key_present,
        status=status,
        cache_size=cache_size,
    )


@router.get("/v2/check", response_model=CheckResponse)
async def check_endpoint(
    ipAddress: str = Query(..., description="IPv4 / IPv6 to look up"),
    maxAgeInDays: int = Query(
        90, ge=1, le=365, description="Look-back window for abuse reports"
    ),
) -> CheckResponse:
    """AbuseIPDB v2 /check — IP reputation."""
    eng = _engine()
    data = _serve(lambda: eng.check(ipAddress, maxAgeInDays))
    return CheckResponse(**data)


@router.get("/v2/blacklist", response_model=BlacklistResponse)
async def blacklist_endpoint(
    confidenceMinimum: int = Query(
        90, ge=25, le=100, description="Minimum abuseConfidenceScore filter"
    ),
    limit: int = Query(
        10000, ge=1, le=500_000, description="Max IPs to return (paid tier)"
    ),
) -> BlacklistResponse:
    """AbuseIPDB v2 /blacklist — top-N abusive IPs."""
    eng = _engine()
    data = _serve(lambda: eng.blacklist(confidenceMinimum, limit))
    return BlacklistResponse(**data)


@router.post("/v2/report", response_model=ReportResponse)
async def report_endpoint(
    body: ReportRequest = Body(...),
) -> ReportResponse:
    """AbuseIPDB v2 /report — submit an abuse report."""
    eng = _engine()
    data = _serve(lambda: eng.report(body.ip, body.categories, body.comment))
    return ReportResponse(**data)


# ---------------------------------------------------------------------------
# Legacy ET / AbuseIPDB blocklist importer endpoints (kept for back-compat)
# ---------------------------------------------------------------------------


@router.post("/import")
def trigger_import() -> Dict[str, Any]:
    """Pull the ET compromised-ips list and (if ABUSEIPDB_API_KEY env is set)
    the AbuseIPDB top-10K blacklist. Returns import summary."""
    try:
        run_import, _l, _c, _s = _get_importer()
        return run_import()
    except Exception as exc:  # noqa: BLE001
        logger.exception("AbuseIPDB import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/ips")
def list_ips_endpoint(
    ip: Optional[str] = Query(default=None, description="Exact IP match"),
    confidence_min: Optional[int] = Query(
        default=None, ge=0, le=100,
        description="Minimum confidence_score (0-100)",
    ),
    last_seen_since: Optional[str] = Query(
        default=None,
        description="ISO 8601 timestamp; only IPs reported on or after this",
    ),
    source: Optional[str] = Query(
        default=None,
        description="Filter by source: 'et' or 'abuseipdb'",
    ),
    limit: int = Query(default=1000, ge=1, le=10_000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List blocklisted IPs with optional filters."""
    try:
        _r, list_ips, _c, _s = _get_importer()
        rows = list_ips(
            ip=ip,
            confidence_min=confidence_min,
            last_seen_since=last_seen_since,
            source=source,
            limit=limit,
            offset=offset,
        )
        return {
            "ips": rows,
            "total": len(rows),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to list AbuseIPDB IPs")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/check/{ip}")
def check_ip_endpoint(
    ip: str = Path(..., description="IPv4 dotted-quad address to look up"),
) -> Dict[str, Any]:
    """Single-IP blocklist lookup. Returns 404 if the IP is not on the blocklist."""
    try:
        _r, _l, check_ip, _s = _get_importer()
        entry = check_ip(ip)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"IP not on blocklist: {ip}")
        return {"ip": ip, "blocklisted": True, "entry": entry}
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to check IP %s", ip)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats")
def get_stats() -> Dict[str, Any]:
    """Return total IP count and by-source breakdown."""
    try:
        _r, _l, _c, get_store_stats = _get_importer()
        return get_store_stats()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to get AbuseIPDB stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


__all__ = ["router"]
