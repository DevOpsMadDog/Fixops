"""AbuseIPDB / EmergingThreats Blocklist Router — ALDECI.

Endpoints to import and query the unified IP blocklist (ET compromised-ips +
optional AbuseIPDB blacklist).

Prefix: /api/v1/abuseipdb
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/abuseipdb/import       trigger_import
  GET  /api/v1/abuseipdb/ips          list_ips_endpoint
  GET  /api/v1/abuseipdb/check/{ip}   check_ip_endpoint
  GET  /api/v1/abuseipdb/stats        get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query

from apps.api.auth_deps import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/abuseipdb",
    tags=["AbuseIPDB"],
)


def _get_importer():
    from feeds.abuseipdb.importer import (
        run_import,
        list_ips,
        check_ip,
        get_store_stats,
    )
    return run_import, list_ips, check_ip, get_store_stats


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import() -> Dict[str, Any]:
    """Pull the ET compromised-ips list and (if ABUSEIPDB_API_KEY env is set)
    the AbuseIPDB top-10K blacklist. Returns import summary."""
    try:
        run_import, _l, _c, _s = _get_importer()
        return run_import()
    except Exception as exc:
        logger.exception("AbuseIPDB import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/ips", dependencies=[Depends(api_key_auth)])
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
    except Exception as exc:
        logger.exception("Failed to list AbuseIPDB IPs")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/check/{ip}", dependencies=[Depends(api_key_auth)])
def check_ip_endpoint(
    ip: str = Path(..., description="IPv4 dotted-quad address to look up"),
) -> Dict[str, Any]:
    """Single-IP lookup. Returns 404 if the IP is not on the blocklist."""
    try:
        _r, _l, check_ip, _s = _get_importer()
        entry = check_ip(ip)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"IP not on blocklist: {ip}")
        return {"ip": ip, "blocklisted": True, "entry": entry}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to check IP %s", ip)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats() -> Dict[str, Any]:
    """Return total IP count and by-source breakdown."""
    try:
        _r, _l, _c, get_store_stats = _get_importer()
        return get_store_stats()
    except Exception as exc:
        logger.exception("Failed to get AbuseIPDB stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
