"""Feed Manager API Router — lifecycle management for threat intelligence feeds.

Endpoints:
    POST   /api/v1/feeds                    -- Register a new feed
    GET    /api/v1/feeds                    -- List feeds (optional status filter)
    GET    /api/v1/feeds/stats              -- Feed statistics
    GET    /api/v1/feeds/stale              -- Stale feed alerts
    GET    /api/v1/feeds/health             -- All feed health
    GET    /api/v1/feeds/iocs/search        -- Search IOCs
    POST   /api/v1/feeds/iocs/dedup         -- Deduplicate IOCs
    GET    /api/v1/feeds/{id}               -- Get feed details
    PUT    /api/v1/feeds/{id}               -- Update feed
    DELETE /api/v1/feeds/{id}              -- Delete feed
    POST   /api/v1/feeds/{id}/refresh       -- Trigger manual refresh
    GET    /api/v1/feeds/{id}/health        -- Feed health

Security:
    All endpoints require API key authentication via api_key_auth dependency.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/feeds",
    tags=["feed-manager"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy import of FeedManager to avoid circular imports at module load
# ---------------------------------------------------------------------------

def _get_manager():
    from core.feed_manager import get_feed_manager
    return get_feed_manager()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class RegisterFeedRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    url: str = Field(..., min_length=1, max_length=2048)
    type: str = Field(..., description="FeedType value")
    enabled: bool = True
    refresh_interval_minutes: int = Field(60, ge=1, le=10080)
    api_key: Optional[str] = Field(None, max_length=1024)


class UpdateFeedRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    url: Optional[str] = Field(None, min_length=1, max_length=2048)
    type: Optional[str] = None
    enabled: Optional[bool] = None
    refresh_interval_minutes: Optional[int] = Field(None, ge=1, le=10080)
    api_key: Optional[str] = Field(None, max_length=1024)


# ---------------------------------------------------------------------------
# Static routes (must come before /{id} to avoid path conflicts)
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_feed_stats(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return aggregate feed statistics for the org."""
    manager = _get_manager()
    return manager.get_feed_stats(org_id=org_id)


@router.get("/stale")
async def get_stale_feeds(
    threshold_hours: int = Query(24, ge=1, le=8760),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return feeds that haven't been successfully refreshed within threshold_hours."""
    manager = _get_manager()
    feeds = manager.get_stale_feeds(threshold_hours=threshold_hours)
    return [f.model_dump() for f in feeds]


@router.get("/health")
async def get_all_health(org_id: str = Depends(get_org_id)) -> List[Dict[str, Any]]:
    """Return health metrics for all feeds in the org."""
    manager = _get_manager()
    health_list = manager.get_all_health(org_id=org_id)
    return [h.model_dump() for h in health_list]


@router.get("/iocs/search")
async def search_iocs(
    q: Optional[str] = Query(None, description="Value substring match"),
    ioc_type: Optional[str] = Query(None, description="IOCType filter"),
    source_feed: Optional[str] = Query(None, description="Source feed name filter"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
) -> List[Dict[str, Any]]:
    """Search IOCs with optional filters."""
    from core.feed_manager import IOCType

    manager = _get_manager()

    parsed_type: Optional[IOCType] = None
    if ioc_type:
        try:
            parsed_type = IOCType(ioc_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid ioc_type: {ioc_type}")

    iocs = manager.search_iocs(
        query=q,
        ioc_type=parsed_type,
        source_feed=source_feed,
        min_confidence=min_confidence,
    )
    return [i.model_dump() for i in iocs]


@router.post("/iocs/dedup")
async def dedup_iocs(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Deduplicate IOCs across feeds for the org. Returns count of removed duplicates."""
    manager = _get_manager()
    removed = manager.dedup_iocs(org_id=org_id)
    return {"org_id": org_id, "removed": removed}


# ---------------------------------------------------------------------------
# Collection routes
# ---------------------------------------------------------------------------


@router.post("")
async def register_feed(
    body: RegisterFeedRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Register a new threat intelligence feed."""
    from core.feed_manager import FeedConfig, FeedType

    try:
        feed_type = FeedType(body.type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid feed type: {body.type}")

    config = FeedConfig(
        name=body.name,
        url=body.url,
        type=feed_type,
        enabled=body.enabled,
        refresh_interval_minutes=body.refresh_interval_minutes,
        api_key=body.api_key,
        org_id=org_id,
    )

    manager = _get_manager()
    result = manager.register_feed(config)
    # TrustGraph explicit indexing (fire-and-forget)
    try:
        from core.trustgraph_event_bus import EVENT_FINDING_CREATED
        from core.trustgraph_event_bus import get_event_bus as _get_eb
        _bus = _get_eb()
        if _bus and _bus.enabled:
            import asyncio as _asyncio
            _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                "finding_id": f"feed-registered-{body.name}",
                "type": "threat_intel_feed", "severity": "info",
                "source": "feed_manager_router",
                "data": {"name": body.name, "type": body.type, "org_id": org_id},
            }))
    except Exception:
        pass
    return result.model_dump()


@router.get("")
async def list_feeds(
    status: Optional[str] = Query(None, description="FeedStatus filter"),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List all feeds for the org, optionally filtered by status."""
    from core.feed_manager import FeedStatus

    parsed_status: Optional[FeedStatus] = None
    if status:
        try:
            parsed_status = FeedStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    manager = _get_manager()
    feeds = manager.list_feeds(org_id=org_id, status_filter=parsed_status)
    return [f.model_dump() for f in feeds]


# ---------------------------------------------------------------------------
# Health / Status — MUST be before /{feed_id} catch-all
# ---------------------------------------------------------------------------


@router.get("/health", summary="Feed manager health check")
async def feed_manager_health() -> Dict[str, Any]:
    """Health check for the feed manager service."""
    try:
        manager = _get_manager()
        feeds = manager.list_feeds()
        return {
            "status": "healthy",
            "engine": "feed-manager",
            "version": "1.0.0",
            "total_feeds": len(feeds),
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "degraded", "engine": "feed-manager", "error": str(exc)[:200]}


@router.get("/status", summary="Feed manager status alias")
async def feed_manager_status() -> Dict[str, Any]:
    """Status alias for /health — returns feed manager operational status."""
    return await feed_manager_health()


# ---------------------------------------------------------------------------
# Item routes
# ---------------------------------------------------------------------------


@router.get("/{feed_id}")
async def get_feed(feed_id: str) -> Dict[str, Any]:
    """Get feed details by ID."""
    manager = _get_manager()
    try:
        feed = manager.get_feed(feed_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return feed.model_dump()


@router.put("/{feed_id}")
async def update_feed(feed_id: str, body: UpdateFeedRequest) -> Dict[str, Any]:
    """Update feed configuration."""
    manager = _get_manager()
    try:
        updates = {k: v for k, v in body.model_dump().items() if v is not None}
        result = manager.update_feed(feed_id, updates)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return result.model_dump()


@router.delete("/{feed_id}")
async def delete_feed(feed_id: str) -> Dict[str, Any]:
    """Delete a feed and all its associated IOCs."""
    manager = _get_manager()
    try:
        manager.get_feed(feed_id)  # 404 check
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    manager.delete_feed(feed_id)
    return {"deleted": True, "feed_id": feed_id}


@router.post("/{feed_id}/refresh")
async def refresh_feed(feed_id: str) -> Dict[str, Any]:
    """Trigger a manual refresh for a feed."""
    manager = _get_manager()
    try:
        result = manager.refresh_feed(feed_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return result


@router.get("/{feed_id}/health")
async def get_feed_health(feed_id: str) -> Dict[str, Any]:
    """Get health metrics for a specific feed."""
    manager = _get_manager()
    try:
        manager.get_feed(feed_id)  # 404 check
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    health = manager.get_feed_health(feed_id)
    return health.model_dump()
