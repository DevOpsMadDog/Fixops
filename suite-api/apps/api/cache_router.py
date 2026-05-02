"""Cache management API router.

Endpoints:
    GET  /api/v1/cache/stats              — hit rates, sizes for all named caches
    POST /api/v1/cache/clear              — flush all named caches (admin)
    POST /api/v1/cache/clear/{cache_name} — flush a specific named cache (admin)

Protected by _verify_api_key (injected via app.include_router dependencies).
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from core.cache import named_cache_manager
from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cache", tags=["cache"])


@router.get("/stats", summary="Cache hit rates and sizes for all named caches")
async def cache_stats() -> Dict[str, Any]:
    """Return statistics for all named caches: hits, misses, hit_rate, size, evictions."""
    stats = named_cache_manager.all_stats()
    return {
        "caches": stats,
        "total_size": sum(v["size"] for v in stats.values()),
    }


@router.post("/clear", summary="Flush all named caches", status_code=200)
async def clear_all_caches() -> Dict[str, str]:
    """Flush every named cache (findings, dashboard, compliance, pipeline)."""
    named_cache_manager.clear_all()
    logger.info("All named caches cleared via admin API")
    return {"status": "ok", "message": "All caches cleared"}


@router.post(
    "/clear/{cache_name}",
    summary="Flush a specific named cache",
    status_code=200,
)
async def clear_named_cache(cache_name: str) -> Dict[str, str]:
    """Flush a specific named cache by name.

    Valid names: ``findings``, ``dashboard``, ``compliance``, ``pipeline``.
    """
    cache = named_cache_manager.get_cache(cache_name)
    if cache is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown cache '{cache_name}'. Valid names: findings, dashboard, compliance, pipeline",
        )
    cache.clear()
    logger.info("Named cache '%s' cleared via admin API", cache_name)
    return {"status": "ok", "message": f"Cache '{cache_name}' cleared"}
