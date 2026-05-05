"""URLhaus malicious-URL feed router — ALDECI.

Endpoints to import and query the URLhaus malicious-URL blocklist (abuse.ch).
No API key required — public feed.

Prefix: /api/v1/urlhaus
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/urlhaus/import        trigger_import
  GET  /api/v1/urlhaus/urls          list_urls_endpoint
  GET  /api/v1/urlhaus/check         check_url_endpoint  (?url=...)
  GET  /api/v1/urlhaus/stats         get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/urlhaus",
    tags=["URLhaus"],
)


def _get_importer():
    from feeds.urlhaus.importer import (
        check_url,
        get_store_stats,
        list_urls,
        run_import,
    )
    return run_import, list_urls, check_url, get_store_stats


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import(
    full: bool = Query(
        default=False,
        description="If true, download the full feed (~1M URLs). Defaults to recent (last 1000).",
    ),
) -> Dict[str, Any]:
    """Pull URLhaus CSV feed from abuse.ch and upsert into local DB.

    Returns import summary with total URL count, by-threat breakdown,
    and by-status breakdown.
    """
    try:
        run_import, _l, _c, _s = _get_importer()
        return run_import(full=full)
    except Exception as exc:
        logger.exception("URLhaus import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/urls", dependencies=[Depends(api_key_auth)])
def list_urls_endpoint(
    threat: Optional[str] = Query(
        default=None,
        description="Filter by threat type, e.g. 'malware_download'",
    ),
    url_status: Optional[str] = Query(
        default=None,
        description="Filter by URL status: 'online' or 'offline'",
    ),
    limit: int = Query(default=1000, ge=1, le=10_000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List malicious URLs with optional filters."""
    try:
        _r, list_urls, _c, _s = _get_importer()
        rows = list_urls(
            threat=threat,
            url_status=url_status,
            limit=limit,
            offset=offset,
        )
        return {
            "urls": rows,
            "total": len(rows),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Failed to list URLhaus URLs")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/check", dependencies=[Depends(api_key_auth)])
def check_url_endpoint(
    url: str = Query(..., description="Full URL to look up in the URLhaus blocklist"),
) -> Dict[str, Any]:
    """Membership check: returns the URLhaus entry if the URL is blocklisted.

    Returns 404 if the URL is not found in the local store.
    """
    try:
        _r, _l, check_url, _s = _get_importer()
        entry = check_url(url)
        if entry is None:
            raise HTTPException(
                status_code=404,
                detail=f"URL not found in URLhaus blocklist: {url}",
            )
        return {"url": url, "blocklisted": True, "entry": entry}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to check URL %s", url)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats() -> Dict[str, Any]:
    """Return total URL count, by-threat breakdown, and by-status breakdown."""
    try:
        _r, _l, _c, get_store_stats = _get_importer()
        return get_store_stats()
    except Exception as exc:
        logger.exception("Failed to get URLhaus stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/health")
def urlhaus_health() -> Dict[str, Any]:
    """Health check for the URLhaus threat feed service."""
    try:
        _r, _l, _c, get_store_stats = _get_importer()
        stats = get_store_stats()
        return {"status": "healthy", "service": "aldeci-urlhaus", "version": "1.0.0",
                "urls_tracked": stats.get("total", 0)}
    except Exception as exc:
        return {"status": "degraded", "service": "aldeci-urlhaus", "error": str(exc)}


@router.get("/status")
def urlhaus_status() -> Dict[str, Any]:
    """Status alias — delegates to /health."""
    return urlhaus_health()
