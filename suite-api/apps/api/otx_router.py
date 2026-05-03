"""AlienVault OTX (Open Threat Exchange) Router — ALDECI.

Endpoints to import and query OTX pulses + flattened indicators.

Prefix: /api/v1/otx
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/otx/import       trigger_import
  GET  /api/v1/otx/pulses       list_otx_pulses
  GET  /api/v1/otx/indicators   list_otx_indicators
  GET  /api/v1/otx/stats        get_stats
  GET  /api/v1/otx/feed-status  get_feed_status
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/otx",
    tags=["OTX"],
)


def _get_importer():
    from feeds.otx.importer import (
        get_store_stats,
        list_indicators,
        list_pulses,
        run_import,
    )
    return run_import, list_pulses, list_indicators, get_store_stats


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import(
    limit: int = Query(default=50, ge=1, le=200, description="Pulses per page"),
    max_pages: int = Query(default=1, ge=1, le=20, description="How many pages to walk"),
) -> Dict[str, Any]:
    """Pull AlienVault OTX pulses + indicators.

    When ``OTX_API_KEY`` is set in the environment, the subscribed feed is used;
    otherwise the importer falls back to the public activity feed (no auth).
    """
    try:
        run_import, _lp, _li, _s = _get_importer()
        return run_import(limit=limit, max_pages=max_pages)
    except Exception as exc:
        logger.exception("OTX import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/pulses", dependencies=[Depends(api_key_auth)])
def list_otx_pulses(
    pulse_id: Optional[str] = Query(default=None, description="Filter by pulse id (exact match)."),
    author: Optional[str] = Query(default=None, description="Filter by author_name (exact match)."),
    tag: Optional[str] = Query(default=None, description="Filter by tag (case-insensitive)."),
    since: Optional[str] = Query(
        default=None,
        description="Return pulses modified on/after this ISO-8601 timestamp.",
    ),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List OTX pulses from the local DB with optional filters."""
    try:
        _r, list_pulses, _li, _s = _get_importer()
        pulses = list_pulses(
            pulse_id=pulse_id,
            author=author,
            tag=tag,
            since=since,
            limit=limit,
            offset=offset,
        )
        return {
            "pulses": pulses,
            "total": len(pulses),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Failed to list OTX pulses")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/indicators", dependencies=[Depends(api_key_auth)])
def list_otx_indicators(
    pulse_id: Optional[str] = Query(default=None, description="Filter by parent pulse id."),
    indicator_type: Optional[str] = Query(
        default=None,
        description=(
            "Filter by indicator type: IPv4 | IPv6 | domain | hostname | URL | email | "
            "FileHash-MD5 | FileHash-SHA1 | FileHash-SHA256 | CVE | …"
        ),
    ),
    since: Optional[str] = Query(
        default=None,
        description="Return indicators created on/after this ISO-8601 timestamp.",
    ),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List flattened OTX indicators from the local DB with optional filters."""
    try:
        _r, _lp, list_indicators, _s = _get_importer()
        indicators = list_indicators(
            pulse_id=pulse_id,
            indicator_type=indicator_type,
            since=since,
            limit=limit,
            offset=offset,
        )
        return {
            "indicators": indicators,
            "total": len(indicators),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Failed to list OTX indicators")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats() -> Dict[str, Any]:
    """Return total pulse + indicator counts and indicator-type breakdown."""
    try:
        _r, _lp, _li, get_store_stats = _get_importer()
        return get_store_stats()
    except Exception as exc:
        logger.exception("Failed to get OTX stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/feed-status", dependencies=[Depends(api_key_auth)])
def get_feed_status() -> Dict[str, Any]:
    """Return AlienVault OTX feed health row.

    Response schema::

        {
            "feed": "alienvault-otx",
            "source_url": "https://otx.alienvault.com/api/v1/pulses/activity",
            "authenticated": <bool>,   # True when OTX_API_KEY env var is set
            "total_pulses": <int>,
            "total_indicators": <int>,
            "by_indicator_type": {"IPv4": N, "domain": N, ...},
            "with_attack_id": <int>,
            "status": "ok" | "empty"
        }
    """
    import os

    try:
        _r, _lp, _li, get_store_stats = _get_importer()
        stats = get_store_stats()
        api_key_set = bool(os.environ.get("OTX_API_KEY"))
        source_url = (
            "https://otx.alienvault.com/api/v1/pulses/subscribed"
            if api_key_set
            else "https://otx.alienvault.com/api/v1/pulses/activity"
        )
        status = "ok" if stats.get("total_pulses", 0) > 0 else "empty"
        return {
            "feed": "alienvault-otx",
            "source_url": source_url,
            "authenticated": api_key_set,
            "total_pulses": stats.get("total_pulses", 0),
            "total_indicators": stats.get("total_indicators", 0),
            "by_indicator_type": stats.get("by_indicator_type", {}),
            "with_attack_id": stats.get("with_attack_id", 0),
            "status": status,
        }
    except Exception as exc:
        logger.exception("Failed to get OTX feed status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
