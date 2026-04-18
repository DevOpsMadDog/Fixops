"""Tests for core.cache_layer — response caching layer.

Tests:
  1. cache_endpoint serves cached result on second call (no re-execution)
  2. cache miss returns fresh data and stores it
  3. org_id isolation — different org_ids get independent cache entries
  4. Cache backend error (get raises) does NOT break the endpoint
  5. Cache backend set error does NOT break the endpoint
  6. make_cache_key builds canonical "org_id:endpoint" key
  7. invalidate() clears matching entries
  8. cache_stats() returns a dict
  9. TTL constants have correct values
 10. Endpoint with no org_id kwarg uses "global" fallback

Run with:
    python -m pytest tests/test_cache_layer.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Optional
from unittest.mock import AsyncMock, patch

import pytest

# Ensure env is set before any app-module imports
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-at-least-32-chars-long")
os.environ.setdefault("FIXOPS_MODE", "dev")

from core.cache_layer import (  # noqa: E402
    cache_endpoint,
    cache_stats,
    invalidate,
    make_cache_key,
    TTL_HEALTH,
    TTL_STATS,
    TTL_COMPLIANCE,
    TTL_DEFAULT,
)


# ---------------------------------------------------------------------------
# Minimal in-process async cache — no asyncio.Lock, works across asyncio.run()
# ---------------------------------------------------------------------------

class _DictCache:
    """Simple dict-backed async cache (no asyncio.Lock) for test isolation."""

    def __init__(self):
        self._store: dict[str, Any] = {}

    async def get(self, key: str) -> Optional[Any]:
        return self._store.get(key)

    async def set(self, key: str, value: Any, ttl: int = 60) -> None:
        self._store[key] = value

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)

    async def invalidate_pattern(self, pattern: str) -> int:
        prefix = pattern.rstrip("*")
        keys = [k for k in self._store if k.startswith(prefix)]
        for k in keys:
            del self._store[k]
        return len(keys)

    async def stats(self) -> dict:
        return {"backend": "test_dict", "total_keys": len(self._store)}


@pytest.fixture(autouse=True)
def isolated_cache(monkeypatch):
    """Replace the cache_manager singleton with a fresh DictCache for each test."""
    test_cache = _DictCache()

    import core.cache as _cache_mod
    monkeypatch.setattr(_cache_mod, "cache_manager", test_cache)

    # Also patch the getter used by cache_layer
    import core.cache_layer as _layer_mod
    monkeypatch.setattr(_layer_mod, "_get_cache_manager", lambda: test_cache)

    return test_cache


# ---------------------------------------------------------------------------
# 1. cache_endpoint caches result — second call skips execution
# ---------------------------------------------------------------------------

class TestCacheEndpointHit:
    def test_second_call_served_from_cache(self):
        call_count = 0

        @cache_endpoint(ttl=60)
        async def my_endpoint(org_id: str = "default"):
            nonlocal call_count
            call_count += 1
            return {"value": call_count}

        async def _run():
            r1 = await my_endpoint(org_id="org1")
            r2 = await my_endpoint(org_id="org1")
            assert r1 == {"value": 1}
            assert r2 == {"value": 1}  # served from cache
            assert call_count == 1

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. cache miss returns fresh data
# ---------------------------------------------------------------------------

class TestCacheEndpointMiss:
    def test_first_call_executes_function(self):
        call_count = 0

        @cache_endpoint(ttl=60)
        async def fresh_endpoint(org_id: str = "default"):
            nonlocal call_count
            call_count += 1
            return {"count": call_count}

        async def _run():
            result = await fresh_endpoint(org_id="new-org")
            assert result == {"count": 1}
            assert call_count == 1

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 3. org_id isolation — different orgs get independent entries
# ---------------------------------------------------------------------------

class TestOrgIdIsolation:
    def test_different_org_ids_have_separate_cache_entries(self):
        call_log: list[str] = []

        @cache_endpoint(ttl=60)
        async def org_endpoint(org_id: str = "default"):
            call_log.append(org_id)
            return {"org": org_id, "seq": len(call_log)}

        async def _run():
            r1 = await org_endpoint(org_id="alpha")
            r2 = await org_endpoint(org_id="beta")
            r3 = await org_endpoint(org_id="alpha")  # cache hit
            r4 = await org_endpoint(org_id="beta")   # cache hit

            assert r1["org"] == "alpha"
            assert r2["org"] == "beta"
            assert r3["seq"] == r1["seq"]  # cached — seq unchanged
            assert r4["seq"] == r2["seq"]  # cached — seq unchanged
            assert call_log.count("alpha") == 1
            assert call_log.count("beta") == 1

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. Cache backend get error does NOT break the endpoint
# ---------------------------------------------------------------------------

class TestCacheBackendGetError:
    def test_get_error_still_returns_result(self, isolated_cache):
        async def broken_get(key):
            raise RuntimeError("Redis exploded")

        isolated_cache.get = broken_get

        call_count = 0

        @cache_endpoint(ttl=60)
        async def resilient_endpoint(org_id: str = "default"):
            nonlocal call_count
            call_count += 1
            return {"resilient": True}

        async def _run():
            result = await resilient_endpoint(org_id="err-org")
            assert result == {"resilient": True}
            assert call_count == 1

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 5. Cache backend set error does NOT break the endpoint
# ---------------------------------------------------------------------------

class TestCacheBackendSetError:
    def test_set_error_still_returns_result(self, isolated_cache):
        async def broken_set(key, value, ttl=60):
            raise RuntimeError("Cannot write to Redis")

        isolated_cache.set = broken_set

        @cache_endpoint(ttl=60)
        async def resilient_write_endpoint(org_id: str = "default"):
            return {"ok": True}

        async def _run():
            result = await resilient_write_endpoint(org_id="write-err-org")
            assert result == {"ok": True}

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 6. make_cache_key produces canonical format
# ---------------------------------------------------------------------------

class TestMakeCacheKey:
    def test_format_is_org_colon_endpoint(self):
        assert make_cache_key("my-org", "platform_health") == "my-org:platform_health"

    def test_global_fallback_key(self):
        assert make_cache_key("global", "get_feeds_status") == "global:get_feeds_status"

    def test_special_chars_preserved(self):
        assert make_cache_key("tenant/1", "stats") == "tenant/1:stats"


# ---------------------------------------------------------------------------
# 7. invalidate() clears matching entries
# ---------------------------------------------------------------------------

class TestInvalidate:
    def test_invalidate_removes_cached_entry(self):
        call_count = 0

        @cache_endpoint(ttl=300)
        async def cached_op(org_id: str = "default"):
            nonlocal call_count
            call_count += 1
            return {"n": call_count}

        async def _run():
            await cached_op(org_id="inv-org")
            assert call_count == 1

            await invalidate("inv-org")

            await cached_op(org_id="inv-org")
            assert call_count == 2  # cache was cleared, re-executed

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 8. cache_stats returns expected structure
# ---------------------------------------------------------------------------

class TestCacheStats:
    def test_returns_dict(self):
        async def _run():
            stats = await cache_stats()
            assert isinstance(stats, dict)
            assert len(stats) >= 1

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 9. TTL constants have correct values
# ---------------------------------------------------------------------------

class TestTTLConstants:
    def test_health_ttl(self):
        assert TTL_HEALTH == 300

    def test_stats_ttl(self):
        assert TTL_STATS == 60

    def test_compliance_ttl(self):
        assert TTL_COMPLIANCE == 120

    def test_default_ttl(self):
        assert TTL_DEFAULT == 60


# ---------------------------------------------------------------------------
# 10. Endpoint with no org_id kwarg uses "global" fallback
# ---------------------------------------------------------------------------

class TestGlobalOrgFallback:
    def test_no_org_id_uses_global(self, isolated_cache):
        call_count = 0

        @cache_endpoint(ttl=60)
        async def no_org_endpoint():
            nonlocal call_count
            call_count += 1
            return {"data": "value"}

        async def _run():
            await no_org_endpoint()
            await no_org_endpoint()
            # Key should start with "global:"
            keys = list(isolated_cache._store.keys())
            assert any(k.startswith("global:") for k in keys)
            assert call_count == 1  # second call served from cache

        asyncio.run(_run())
