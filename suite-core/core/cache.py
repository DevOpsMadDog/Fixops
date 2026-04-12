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
from typing import Any, Callable

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
            live = sum(
                1 for _, (_, exp) in self._store.items() if not exp or now <= exp
            )
            return {
                "backend": "memory",
                "total_keys": len(self._store),
                "live_keys": live,
                "max_size": self._max_size,
            }

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
        except ImportError as exc:
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
            key_data = (
                f"{fn.__module__}.{fn.__qualname__}:{args}:{sorted(kwargs.items())}"
            )
            key_hash = hashlib.md5(key_data.encode(), usedforsecurity=False).hexdigest()[:12]
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


# ---------------------------------------------------------------------------
# Synchronous LRU+TTL cache (for hot-path, single-process performance)
# ---------------------------------------------------------------------------

import threading
from collections import OrderedDict
from typing import Optional


class TTLCache:
    """Thread-safe synchronous in-memory cache with LRU eviction and per-key TTL.

    Designed for hot-path API caching where async overhead is undesirable.
    Pure Python — no external dependencies.

    Args:
        maxsize: Maximum number of items before LRU eviction kicks in.
        ttl_seconds: Default time-to-live in seconds for cached entries.
    """

    def __init__(self, maxsize: int = 1000, ttl_seconds: float = 60.0) -> None:
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        # OrderedDict used as LRU: most-recently-used at the end
        self._store: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, key: str) -> Optional[Any]:
        """Return cached value if present and not expired, else None."""
        with self._lock:
            if key not in self._store:
                self._misses += 1
                return None
            value, expires_at = self._store[key]
            if time.monotonic() > expires_at:
                del self._store[key]
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            return value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Store *value* under *key* with optional per-key TTL override."""
        expires_at = time.monotonic() + (ttl if ttl is not None else self._ttl)
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, expires_at)
            while len(self._store) > self._maxsize:
                self._store.popitem(last=False)
                self._evictions += 1

    def delete(self, key: str) -> None:
        """Invalidate a specific key (no-op if not present)."""
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        """Flush the entire cache."""
        with self._lock:
            self._store.clear()

    def stats(self) -> dict:
        """Return cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = self._hits / total if total > 0 else 0.0
            size = len(self._store)
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(hit_rate, 4),
            "size": size,
            "maxsize": self._maxsize,
            "evictions": self._evictions,
        }


# ---------------------------------------------------------------------------
# cache_response FastAPI decorator (sync TTLCache-backed)
# ---------------------------------------------------------------------------


def cache_response(
    ttl: float,
    key_func: Callable,
    cache: Optional["TTLCache"] = None,
) -> Callable:
    """Decorator that caches FastAPI endpoint JSON responses in a TTLCache.

    The decorated coroutine must receive a ``Request`` object either as the
    first positional argument or as a ``request`` keyword argument.

    Args:
        ttl: Time-to-live in seconds.
        key_func: Callable ``(request) -> str`` that derives the cache key.
        cache: TTLCache instance; defaults to ``named_cache_manager.dashboard``.

    Example::

        @router.get("/findings")
        @cache_response(ttl=30, key_func=lambda req: req.url.path + str(req.query_params))
        async def list_findings(request: Request, ...):
            ...
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                from fastapi import Request as _Request
                from fastapi.responses import JSONResponse as _JSONResponse
            except ImportError:
                return await fn(*args, **kwargs)

            # Locate the Request argument — check isinstance first, then duck-type
            # (duck-type allows fake Request objects in tests)
            request = None
            for arg in args:
                if isinstance(arg, _Request) or hasattr(arg, "url"):
                    request = arg
                    break
            if request is None:
                request = kwargs.get("request")

            _cache: TTLCache = cache if cache is not None else named_cache_manager.dashboard

            if request is not None:
                cache_key = key_func(request)
                cached_val = _cache.get(cache_key)
                if cached_val is not None:
                    return _JSONResponse(content=cached_val)

            result = await fn(*args, **kwargs)

            if request is not None and isinstance(result, (dict, list)):
                _cache.set(cache_key, result, ttl=ttl)
            elif request is not None:
                try:
                    from fastapi.responses import JSONResponse as _JSONResponse
                    if isinstance(result, _JSONResponse):
                        import json as _json
                        body = _json.loads(result.body)
                        _cache.set(cache_key, body, ttl=ttl)
                except Exception:
                    pass

            return result

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# NamedCacheManager — singleton managing per-domain TTLCache instances
# ---------------------------------------------------------------------------


class NamedCacheManager:
    """Singleton managing named TTLCache instances for different hot paths.

    Named caches:
        findings   — maxsize=1000, ttl=30s   (frequent vulnerability queries)
        dashboard  — maxsize=100,  ttl=60s   (aggregate stats)
        compliance — maxsize=50,   ttl=120s  (compliance scores — slow-changing)
        pipeline   — maxsize=200,  ttl=15s   (pipeline status — fast-changing)
    """

    _instance: Optional["NamedCacheManager"] = None
    _init_lock = threading.Lock()

    def __new__(cls) -> "NamedCacheManager":
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    inst = super().__new__(cls)
                    inst._initialised = False
                    cls._instance = inst
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialised", False):
            return
        self.findings = TTLCache(maxsize=1000, ttl_seconds=30.0)
        self.dashboard = TTLCache(maxsize=100, ttl_seconds=60.0)
        self.compliance = TTLCache(maxsize=50, ttl_seconds=120.0)
        self.pipeline = TTLCache(maxsize=200, ttl_seconds=15.0)
        self._initialised = True

    def all_stats(self) -> dict:
        """Return stats for every named cache."""
        return {
            "findings": self.findings.stats(),
            "dashboard": self.dashboard.stats(),
            "compliance": self.compliance.stats(),
            "pipeline": self.pipeline.stats(),
        }

    def clear_all(self) -> None:
        """Flush every named cache."""
        for name in ("findings", "dashboard", "compliance", "pipeline"):
            getattr(self, name).clear()

    def get_cache(self, name: str) -> Optional[TTLCache]:
        """Return a named cache by name, or None if unknown."""
        return getattr(self, name, None)


# Module-level named-cache singleton (distinct from the async CacheManager above)
named_cache_manager = NamedCacheManager()
