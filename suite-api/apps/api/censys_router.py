"""Censys CVE-to-host search router — ALDECI.

Endpoints:
  POST /api/v1/censys/search-cve   search_cve_endpoint
  GET  /api/v1/censys/hosts        list_hosts_endpoint
  GET  /api/v1/censys/check/{ip}   check_host_endpoint

Auth: api_key_auth dependency.

Prefix: /api/v1/censys

Notes:
    Requires CENSYS_API_ID + CENSYS_API_SECRET env vars for live imports.
    Without credentials the importer returns a structured warning and zero
    results (status=needs_credentials). Use the fixture_data arg in tests.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/censys",
    tags=["Censys"],
)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class SearchCveRequest(BaseModel):
    cve_id: str = Field(
        ...,
        description='CVE identifier to search (e.g. "CVE-2021-44228")',
        examples=["CVE-2021-44228"],
    )
    max_results: int = Field(
        default=100,
        ge=1,
        le=100,
        description="Maximum number of hosts to return (Censys page cap: 100)",
    )
    force: bool = Field(
        default=False,
        description="Skip 1-day TTL cache and force a live fetch",
    )


# ---------------------------------------------------------------------------
# Lazy importer loader
# ---------------------------------------------------------------------------

def _get_importer():
    from feeds.censys.importer import (
        run_import,
        list_hosts,
        check_host,
        get_store_stats,
    )
    return run_import, list_hosts, check_host, get_store_stats


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/search-cve", dependencies=[Depends(api_key_auth)])
def search_cve_endpoint(body: SearchCveRequest) -> Dict[str, Any]:
    """Search Censys for hosts observed with a given CVE.

    Requires CENSYS_API_ID and CENSYS_API_SECRET environment variables.
    Results are cached with a 1-day TTL per CVE. Use force=true to bypass.

    Returns a summary of imported hosts grouped by country and CVE.
    """
    try:
        run_import, _lh, _ch, _gs = _get_importer()
        result = run_import(
            cve_id=body.cve_id,
            max_results=body.max_results,
            force=body.force,
        )
        return result
    except Exception as exc:
        logger.exception("Censys search-cve failed for %s", body.cve_id)
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/hosts", dependencies=[Depends(api_key_auth)])
def list_hosts_endpoint(
    ip: Optional[str] = Query(default=None, description="Exact IP address match"),
    country: Optional[str] = Query(
        default=None,
        description="Filter by ISO country code (e.g. US, DE)",
    ),
    cve_id: Optional[str] = Query(
        default=None,
        description="Filter hosts that have this CVE in their cve_ids list",
    ),
    last_seen: Optional[str] = Query(
        default=None,
        description="ISO 8601 timestamp; only hosts with last_observation >= this",
    ),
    limit: int = Query(default=1000, ge=1, le=10_000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List cached Censys host records with optional filters."""
    try:
        _ri, list_hosts, _ch, _gs = _get_importer()
        rows: List[Dict[str, Any]] = list_hosts(
            ip=ip,
            country=country,
            cve_id=cve_id,
            last_seen=last_seen,
            limit=limit,
            offset=offset,
        )
        return {
            "hosts": rows,
            "total": len(rows),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Censys list_hosts failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/check/{ip}", dependencies=[Depends(api_key_auth)])
def check_host_endpoint(
    ip: str = Path(..., description="IPv4 address to look up"),
) -> Dict[str, Any]:
    """Proxy lookup: return cached Censys data for a single IP.

    Returns 404 if the IP has not been imported yet.
    """
    try:
        _ri, _lh, check_host, _gs = _get_importer()
        entry = check_host(ip)
        if entry is None:
            raise HTTPException(
                status_code=404,
                detail=f"No Censys data for IP: {ip}",
            )
        return {"ip": ip, "found": True, "entry": entry}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Censys check_host failed for %s", ip)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
