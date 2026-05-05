"""URLscan.io Public Feed Router — ALDECI.

Endpoints to import and query URLscan.io public scan results.

Prefix: /api/v1/urlscan
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/urlscan/import    trigger_import   (query param, default task.tags:phishing)
  GET  /api/v1/urlscan/results   list_results     (filters: domain, verdict, since)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/urlscan",
    tags=["URLscan"],
)


def _get_importer():
    from feeds.urlscan.importer import get_store_stats, list_results, run_import
    return run_import, list_results, get_store_stats


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import(
    query: str = Query(
        default="task.tags:phishing",
        description="URLscan.io search query (e.g. 'task.tags:phishing', 'page.domain:example.com')",
    ),
    size: int = Query(
        default=100,
        ge=1,
        le=10_000,
        description="Max results to fetch (free tier cap: 100)",
    ),
) -> Dict[str, Any]:
    """Pull URLscan.io public search results and upsert into local DB.

    Uses ``URLSCAN_API_KEY`` env var for higher rate limits if set.
    Returns import summary with result count and breakdowns by verdict and TLD.
    """
    try:
        run_import, _l, _s = _get_importer()
        return run_import(query=query, size=size)
    except Exception as exc:
        logger.exception("URLscan import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/results", dependencies=[Depends(api_key_auth)])
def list_results_endpoint(
    domain: Optional[str] = Query(
        default=None,
        description="Exact domain match (e.g. 'example.com')",
    ),
    verdict: Optional[str] = Query(
        default=None,
        description="Filter by verdict: 'malicious' or 'clean'",
    ),
    since: Optional[str] = Query(
        default=None,
        description="ISO 8601 timestamp; only entries indexed on or after this date",
    ),
    limit: int = Query(default=1000, ge=1, le=10_000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List stored URLscan results with optional filters."""
    try:
        _r, list_results, _s = _get_importer()
        rows = list_results(
            domain=domain,
            verdict=verdict,
            since=since,
            limit=limit,
            offset=offset,
        )
        return {
            "results": rows,
            "total": len(rows),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Failed to list URLscan results")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/health")
def urlscan_health() -> Dict[str, Any]:
    """Health check for the URLscan.io integration service."""
    try:
        from core.persistent_store import get_persistent_store
        store = get_persistent_store("urlscan_results")
        return {"status": "healthy", "service": "aldeci-urlscan", "version": "1.0.0",
                "results_cached": len(store)}
    except Exception as exc:
        return {"status": "degraded", "service": "aldeci-urlscan", "error": str(exc)}


@router.get("/status")
def urlscan_status() -> Dict[str, Any]:
    """Status alias — delegates to /health."""
    return urlscan_health()
