"""
FixOps Caching Layer — in-memory (default) + optional Redis backend.

Usage:
    from core.cache import cache_manager, cached

    # Decorator
    @cached(ttl=300, prefix="graph")
    async def get_graph_stats(org_id: str) -> dict: ...

    # Direct API
    await cache_manager.get("graph:stats:org1")
    await cache_manager.set("graph:stats:org1", data, ttl=300)
    await cache_manager.invalidate_pattern("graph:*")
"""
from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import os
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory backend (default, zero dependencies)
# ---------------------------------------------------------------------------

class _MemoryBackend:
    """Thread-safe in-memory cache with TTL eviction."""

    def __init__(self, max_size: int = 10_000):
        self._store: dict[str, tuple[Any, float]] = {}  # key -> (value, expires_at)
        self._max_size = max_size
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any:
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if expires_at and time.time() > expires_at:
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: Any, ttl: int = 300) -> None:
        async with self._lock:
            if len(self._store) >= self._max_size:
                self._evict()
            expires_at = time.time() + ttl if ttl > 0 else 0
            self._store[key] = (value, expires_at)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def invalidate_pattern(self, pattern: str) -> int:
        """Delete keys matching a prefix pattern (e.g., 'graph:*')."""
        prefix = pattern.rstrip("*")
        async with self._lock:
            keys = [k for k in self._store if k.startswith(prefix)]
            for k in keys:
                del self._store[k]
            return len(keys)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    async def stats(self) -> dict:
        async with self._lock:
            now = time.time()
            live = sum(1 for _, (_, exp) in self._store.items() if not exp or now <= exp)
            return {"backend": "memory", "total_keys": len(self._store), "live_keys": live,
                    "max_size": self._max_size}

    def _evict(self) -> None:
        """Evict expired entries, then LRU-style oldest 10%."""
        now = time.time()
        expired = [k for k, (_, exp) in self._store.items() if exp and now > exp]
        for k in expired:
            del self._store[k]
        if len(self._store) >= self._max_size:
            to_remove = max(1, self._max_size // 10)
            for k in list(self._store.keys())[:to_remove]:
                del self._store[k]


# ---------------------------------------------------------------------------
# Redis backend (optional)
# ---------------------------------------------------------------------------

class _RedisBackend:
    """Redis-backed cache. Falls back to memory if Redis unavailable."""

    def __init__(self, url: str):
        self._url = url
        self._redis: Any = None
        self._fallback = _MemoryBackend()
        self._connected = False

    async def _connect(self) -> None:
        if self._connected:
            return
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(self._url, decode_responses=True)
            await self._redis.ping()
            self._connected = True
            logger.info("Redis cache connected: %s", self._url)
        except Exception as exc:
            logger.warning("Redis unavailable (%s), using in-memory fallback", exc)
            self._redis = None

    async def get(self, key: str) -> Any:
        await self._connect()
        if not self._redis:
            return await self._fallback.get(key)
        raw = await self._redis.get(f"fixops:{key}")
        return json.loads(raw) if raw else None

    async def set(self, key: str, value: Any, ttl: int = 300) -> None:
        await self._connect()
        if not self._redis:
            return await self._fallback.set(key, value, ttl)
        await self._redis.setex(f"fixops:{key}", ttl, json.dumps(value, default=str))

    async def delete(self, key: str) -> None:
        await self._connect()
        if not self._redis:
            return await self._fallback.delete(key)
        await self._redis.delete(f"fixops:{key}")

    async def invalidate_pattern(self, pattern: str) -> int:
        await self._connect()
        if not self._redis:
            return await self._fallback.invalidate_pattern(pattern)
        keys = []
        async for k in self._redis.scan_iter(f"fixops:{pattern}"):
            keys.append(k)
        if keys:
            await self._redis.delete(*keys)
        return len(keys)



# ---------------------------------------------------------------------------
# CacheManager — singleton facade
# ---------------------------------------------------------------------------

class CacheManager:
    """Unified cache interface. Picks backend from FIXOPS_CACHE_URL env."""

    def __init__(self):
        redis_url = os.getenv("FIXOPS_CACHE_URL", "")
        if redis_url:
            self._backend = _RedisBackend(redis_url)
            logger.info("Cache backend: Redis (%s)", redis_url)
        else:
            max_size = int(os.getenv("FIXOPS_CACHE_MAX_SIZE", "10000"))
            self._backend = _MemoryBackend(max_size=max_size)
            logger.info("Cache backend: in-memory (max %d entries)", max_size)

    async def get(self, key: str) -> Any:
        return await self._backend.get(key)

    async def set(self, key: str, value: Any, ttl: int = 300) -> None:
        await self._backend.set(key, value, ttl)

    async def delete(self, key: str) -> None:
        await self._backend.delete(key)

    async def invalidate_pattern(self, pattern: str) -> int:
        return await self._backend.invalidate_pattern(pattern)

    async def clear(self) -> None:
        await self._backend.clear()

    async def stats(self) -> dict:
        return await self._backend.stats()


# Module-level singleton
cache_manager = CacheManager()


# ---------------------------------------------------------------------------
# @cached decorator
# ---------------------------------------------------------------------------

def cached(ttl: int = 300, prefix: str = "default"):
    """Decorator to cache async function results.

    Args:
        ttl: Time-to-live in seconds (default 5 min).
        prefix: Key prefix for grouping (enables pattern invalidation).
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            # Build cache key from function name + args hash
            key_data = f"{fn.__module__}.{fn.__qualname__}:{args}:{sorted(kwargs.items())}"
            key_hash = hashlib.md5(key_data.encode()).hexdigest()[:12]
            cache_key = f"{prefix}:{fn.__name__}:{key_hash}"

            # Try cache
            hit = await cache_manager.get(cache_key)
            if hit is not None:
                return hit

            # Miss — call function
            result = await fn(*args, **kwargs)
            if result is not None:
                await cache_manager.set(cache_key, result, ttl)
            return result
        return wrapper
    return decorator
