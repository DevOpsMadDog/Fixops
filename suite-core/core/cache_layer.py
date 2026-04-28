"""
cache_layer.py — Response caching layer for ALDECI read endpoints.

Wraps the existing CacheManager / TTLCache infrastructure in cache.py and
provides a ready-to-use ``cache_endpoint`` decorator for FastAPI route
functions.

Architecture
------------
* Redis-backed when FIXOPS_CACHE_URL is set (e.g. redis://localhost:6379/0).
* Falls back to in-memory TTL cache with LRU eviction when Redis is absent.
* Cache key = ``"{org_id}:{endpoint_path}"`` (multi-tenant safe).
* A cache miss always returns fresh data — the endpoint is called normally.

TTL constants (seconds)
-----------------------
TTL_HEALTH   = 300   # Platform health / feed config — slow-changing
TTL_STATS    = 60    # Analytics / graph stats — moderate-changing
TTL_COMPLIANCE = 120 # Compliance status — slow-changing
TTL_DEFAULT  = 60    # Fallback for unlisted endpoints

Usage
-----
    from core.cache_layer import cache_endpoint, TTL_STATS

    @router.get("/stats")
    @cache_endpoint(ttl=TTL_STATS)
    async def get_stats(org_id: str = Query("default")):
        ...

The decorator extracts ``org_id`` from keyword arguments (FastAPI injects it
there) or falls back to ``"global"`` when no org_id is present.  The endpoint
path is taken from the decorated function's qualified name so that two
different routes never collide even if they share the same org_id.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TTL constants (seconds) — single source of truth for the whole codebase
# ---------------------------------------------------------------------------
TTL_HEALTH: int = 300     # /platform/health, /feeds/config
TTL_STATS: int = 60       # /analytics/dashboard/executive, /graph/stats
TTL_COMPLIANCE: int = 120  # /compliance/status
TTL_DEFAULT: int = 60     # fallback

# ---------------------------------------------------------------------------
# Backend — re-use the async CacheManager from cache.py
# ---------------------------------------------------------------------------
# Lazy import to avoid circular deps at import time.

def _get_cache_manager():
    from core.cache import cache_manager  # noqa: PLC0415
    return cache_manager


# ---------------------------------------------------------------------------
# Public helper: build a canonical cache key
# ---------------------------------------------------------------------------

def make_cache_key(org_id: str, endpoint: str) -> str:
    """Return ``"{org_id}:{endpoint}"`` — the canonical cache key format."""
    return f"{org_id}:{endpoint}"


# ---------------------------------------------------------------------------
# cache_endpoint decorator
# ---------------------------------------------------------------------------

def cache_endpoint(ttl: int = TTL_DEFAULT) -> Callable:
    """Decorator that caches the JSON-serialisable return value of an async
    FastAPI endpoint function.

    * ``org_id`` is extracted from the function's keyword arguments; defaults
      to ``"global"`` when absent (e.g. endpoints without multi-tenancy).
    * The cache key suffix is ``fn.__qualname__`` so different routes never
      share a bucket.
    * A cache miss silently calls the real function and stores the result.
    * Exceptions from the real function propagate unchanged (no error caching).

    Args:
        ttl: Time-to-live in seconds.  Use the module-level ``TTL_*`` constants.

    Example::

        @router.get("/health", dependencies=[Depends(api_key_auth)])
        @cache_endpoint(ttl=TTL_HEALTH)
        async def platform_health() -> Dict[str, Any]:
            ...
    """

    def decorator(fn: Callable) -> Callable:
        endpoint_id = fn.__qualname__  # e.g. "platform_health"

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            cache = _get_cache_manager()

            # Extract org_id from kwargs (FastAPI injects Query params as kwargs)
            org_id: str = str(kwargs.get("org_id", "global"))
            cache_key = make_cache_key(org_id, endpoint_id)

            # --- Cache lookup ---
            try:
                cached = await cache.get(cache_key)
                if cached is not None:
                    logger.debug(
                        "cache_layer.hit key=%s ttl=%d", cache_key, ttl
                    )
                    return cached
            except Exception as exc:  # noqa: BLE001 — never let cache break API
                logger.warning("cache_layer.get_error key=%s exc=%s", cache_key, exc)

            # --- Cache miss: call real function ---
            result = await _call(fn, args, kwargs)

            # --- Store result (best-effort) ---
            if result is not None:
                try:
                    await cache.set(cache_key, result, ttl=ttl)
                    logger.debug(
                        "cache_layer.stored key=%s ttl=%d", cache_key, ttl
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("cache_layer.set_error key=%s exc=%s", cache_key, exc)

            return result

        return wrapper

    return decorator


async def _call(fn: Callable, args: tuple, kwargs: dict) -> Any:
    """Call ``fn`` whether it is a coroutine function or a plain function."""
    if asyncio.iscoroutinefunction(fn):
        return await fn(*args, **kwargs)
    return fn(*args, **kwargs)


# ---------------------------------------------------------------------------
# Cache invalidation helper (for write endpoints that should bust the cache)
# ---------------------------------------------------------------------------

async def invalidate(org_id: str, pattern: str = "*") -> int:
    """Invalidate all cache entries matching ``"{org_id}:{pattern}"``.

    Args:
        org_id: Organisation identifier.
        pattern: Glob suffix (default ``"*"`` clears all entries for that org).

    Returns:
        Number of keys deleted.
    """
    cache = _get_cache_manager()
    full_pattern = f"{org_id}:{pattern}"
    try:
        count = await cache.invalidate_pattern(full_pattern)
        logger.info("cache_layer.invalidated org=%s pattern=%s count=%d", org_id, pattern, count)
        return count
    except Exception as exc:  # noqa: BLE001
        logger.warning("cache_layer.invalidate_error org=%s exc=%s", org_id, exc)
        return 0


# ---------------------------------------------------------------------------
# Stats endpoint helper (for /api/v1/cache/stats)
# ---------------------------------------------------------------------------

async def cache_stats() -> dict:
    """Return backend statistics dict (backend type, key counts, etc.)."""
    try:
        return await _get_cache_manager().stats()
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
