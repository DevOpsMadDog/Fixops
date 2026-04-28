"""GreyNoise Community IP intelligence router.

Endpoints:
    GET  /api/v1/greynoise/lookup/{ip}
        Proxy lookup via GreyNoise community API with a 5-min in-memory cache.
        Falls back to the stored DB record when the network is unavailable.

    POST /api/v1/greynoise/import-known-ips
        Bulk lookup against a caller-supplied IP list. Persists results to
        data/greynoise.db. Uses a 1-day per-IP cache; rate-limited to ~1 req/s
        on the free tier (suppressed when GREYNOISE_API_KEY is set).

Auth: none (public-tier data). Set GREYNOISE_API_KEY in the environment to
      unlock the paid tier.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException, Path as FPath

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/greynoise", tags=["GreyNoise Community Intel"])

# ---------------------------------------------------------------------------
# Path bootstrap — make suite-feeds importable inside the API process
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # apps/api -> suite-api -> Fixops
_SUITE_FEEDS = str(_PROJECT_ROOT / "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)

# ---------------------------------------------------------------------------
# 5-minute in-memory request cache (keyed by IP)
# ---------------------------------------------------------------------------

_LOOKUP_CACHE: Dict[str, Any] = {}          # {ip: record}
_LOOKUP_CACHE_TS: Dict[str, float] = {}     # {ip: unix_time_of_cache}
_LOOKUP_CACHE_TTL = 300                     # 5 minutes


def _cache_get(ip: str) -> Optional[Dict[str, Any]]:
    if ip not in _LOOKUP_CACHE_TS:
        return None
    if time.time() - _LOOKUP_CACHE_TS[ip] > _LOOKUP_CACHE_TTL:
        _LOOKUP_CACHE.pop(ip, None)
        _LOOKUP_CACHE_TS.pop(ip, None)
        return None
    return _LOOKUP_CACHE.get(ip)


def _cache_set(ip: str, record: Dict[str, Any]) -> None:
    _LOOKUP_CACHE[ip] = record
    _LOOKUP_CACHE_TS[ip] = time.time()


# ---------------------------------------------------------------------------
# GET /api/v1/greynoise/lookup/{ip}
# ---------------------------------------------------------------------------

@router.get(
    "/lookup/{ip}",
    summary="GreyNoise Community IP Lookup",
    description=(
        "Look up a single IP address against the GreyNoise Community API. "
        "Results are cached in memory for 5 minutes and persisted to the local "
        "greynoise.db store for 24 hours. "
        "Set GREYNOISE_API_KEY in the environment to use the paid tier."
    ),
    response_description="GreyNoise IP classification record",
)
async def lookup_ip(
    ip: str = FPath(
        ...,
        description="IPv4 or IPv6 address to look up",
        example="8.8.8.8",
    ),
) -> Dict[str, Any]:
    """Proxy a GreyNoise community lookup for a single IP with 5-min cache."""
    # 1. Try in-memory 5-min cache first
    cached = _cache_get(ip)
    if cached:
        return {**cached, "cache": "hit"}

    try:
        from feeds.greynoise.importer import lookup_ip as _lookup_ip
        record = _lookup_ip(ip)
        _cache_set(ip, record)
        return {**record, "cache": "miss"}
    except Exception as exc:  # noqa: BLE001
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status == 404:
            raise HTTPException(
                status_code=404,
                detail=f"IP {ip} not found in the GreyNoise dataset.",
            )
        logger.error("GreyNoise lookup error for %s: %s", ip, exc)
        raise HTTPException(
            status_code=502,
            detail=f"GreyNoise API error: {type(exc).__name__}: {exc}",
        )


# ---------------------------------------------------------------------------
# POST /api/v1/greynoise/import-known-ips
# ---------------------------------------------------------------------------

@router.post(
    "/import-known-ips",
    summary="Bulk GreyNoise IP Import",
    description=(
        "Submit a list of IP addresses for bulk GreyNoise community lookups. "
        "Each IP is checked against the local 24-hour cache before hitting the "
        "API. Results are persisted to data/greynoise.db. "
        "Returns lookup counts and classification breakdown."
    ),
    response_description="Bulk import summary with classification breakdown",
)
async def import_known_ips(
    ips: List[str] = Body(
        ...,
        description="List of IPv4/IPv6 addresses to look up",
        examples=[["8.8.8.8", "1.1.1.1", "198.51.100.1"]],
    ),
) -> Dict[str, Any]:
    """Bulk-import IP intelligence from GreyNoise community API."""
    if not ips:
        raise HTTPException(status_code=400, detail="ips list must not be empty.")

    try:
        from feeds.greynoise.importer import bulk_import
        result = bulk_import(ips)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("GreyNoise bulk import error: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Bulk import failed: {type(exc).__name__}: {exc}",
        )
