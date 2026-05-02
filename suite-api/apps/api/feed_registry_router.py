"""Global Feed Registry API Router.

Unified catalog for every threat-intel feed the platform consumes.

Endpoints:
    GET   /api/v1/feeds/registry            -- list all feeds
    GET   /api/v1/feeds/registry/{feed_id}  -- detail view
    POST  /api/v1/feeds/registry/{feed_id}/refresh  -- trigger import

Note: this router MUST be registered before ``feed_manager_router`` in
app.py, because feed_manager_router carries a ``/{feed_id}`` catch-all
under ``/api/v1/feeds`` that would otherwise swallow the registry paths.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/feeds/registry",
    tags=["feed-registry"],
    dependencies=[Depends(api_key_auth)],
)


def _registry():
    """Lazy import — keeps suite-feeds optional at app boot."""
    from feeds import registry as _r  # type: ignore[import-not-found]
    return _r


@router.get("")
async def list_registry() -> List[Dict[str, Any]]:
    """List every registered feed and its last-run state."""
    reg = _registry()
    return reg.list_feeds()


@router.get("/{feed_id}")
async def get_registry_entry(feed_id: str) -> Dict[str, Any]:
    """Return metadata + last-run state for a single feed."""
    reg = _registry()
    try:
        return reg.get_feed(feed_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown feed_id: {feed_id}")


@router.post("/{feed_id}/refresh")
async def refresh_registry_entry(feed_id: str) -> Dict[str, Any]:
    """Trigger the importer for *feed_id* and persist last-run state."""
    reg = _registry()
    try:
        result = reg.refresh_feed(feed_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown feed_id: {feed_id}")
    if result.get("status") == "error":
        # Surface importer failure as 502 so callers can tell apart from 404
        raise HTTPException(
            status_code=502,
            detail={
                "feed_id": feed_id,
                "error": result.get("error"),
                "imported_at": result.get("imported_at"),
            },
        )
    return result
