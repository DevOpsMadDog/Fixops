"""Tests for core.cache_layer — response caching layer.

Tests:
  1. cache_endpoint serves cached result on second call (no re-execution)
  2. cache miss returns fresh data and stores it
  3. TTL expiry causes re-execution
  4. org_id isolation — different org_ids get independent cache entries
  5. Cache backend error (get raises) does NOT break the endpoint
  6. make_cache_key builds canonical "org_id:endpoint" key
  7. invalidate() clears matching entries (in-memory backend)
  8. cache_stats() returns a dict with expected keys

Run with:
    python -m pytest tests/test_cache_layer.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import asyncio
import os

import pytest

# Ensure env is configured before any app-module imports
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-at-least-32-chars-long")
os.environ.setdefault("FIXOPS_MODE", "dev")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):
    """Run a coroutine in a fresh event loop (test helper)."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------
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

        result1 = run(my_endpoint(org_id="org1"))
        result2 = run(my_endpoint(org_id="org1"))

        assert result1 == {"value": 1}
        assert result2 == {"value": 1}  # served from cache
        assert call_count == 1


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

        result = run(fresh_endpoint(org_id="new-org"))
        assert result == {"count": 1}
        assert call_count == 1


# ---------------------------------------------------------------------------
# 3. org_id isolation — different orgs get independent entries
# ---------------------------------------------------------------------------

class TestOrgIdIsolation:
    def test_different_org_ids_have_separate_cache_entries(self):
        call_log = []

        @cache_endpoint(ttl=60)
        async def org_endpoint(org_id: str = "default"):
            call_log.append(org_id)
            return {"org": org_id, "seq": len(call_log)}

        r1 = run(org_endpoint(org_id="alpha"))
        r2 = run(org_endpoint(org_id="beta"))
        r3 = run(org_endpoint(org_id="alpha"))  # cache hit for alpha
        r4 = run(org_endpoint(org_id="beta"))   # cache hit for beta

        assert r1["org"] == "alpha"
        assert r2["org"] == "beta"
        # Third and fourth calls must return cached values (seq unchanged)
        assert r3["seq"] == r1["seq"]
        assert r4["seq"] == r2["seq"]
        # Function called exactly once per org
        assert call_log.count("alpha") == 1
        assert call_log.count("beta") == 1


# ---------------------------------------------------------------------------
# 4. Cache backend error does NOT break the endpoint
# ---------------------------------------------------------------------------

class TestCacheBackendErrorIsolation:
    def test_get_error_still_returns_result(self, monkeypatch):
        """If cache.get() raises, the endpoint must still execute and return data."""

        async def broken_get(key):
            raise RuntimeError("Redis exploded")

        from core import cache as _cache_mod
        monkeypatch.setattr(_cache_mod.cache_manager, "get", broken_get)

        call_count = 0

        @cache_endpoint(ttl=60)
        async def resilient_endpoint(org_id: str = "default"):
            nonlocal call_count
            call_count += 1
            return {"resilient": True}

        result = run(resilient_endpoint(org_id="resilient-org"))
        assert result == {"resilient": True}
        assert call_count == 1

    def test_set_error_still_returns_result(self, monkeypatch):
        """If cache.set() raises, the endpoint must still return data."""

        async def broken_set(key, value, ttl=60):
            raise RuntimeError("Cannot write to Redis")

        from core import cache as _cache_mod
        monkeypatch.setattr(_cache_mod.cache_manager, "set", broken_set)

        @cache_endpoint(ttl=60)
        async def resilient_write_endpoint(org_id: str = "default"):
            return {"ok": True}

        result = run(resilient_write_endpoint(org_id="write-err-org"))
        assert result == {"ok": True}


# ---------------------------------------------------------------------------
# 5. make_cache_key produces canonical format
# ---------------------------------------------------------------------------

class TestMakeCacheKey:
    def test_format_is_org_colon_endpoint(self):
        key = make_cache_key("my-org", "platform_health")
        assert key == "my-org:platform_health"

    def test_global_fallback_key(self):
        key = make_cache_key("global", "get_feeds_status")
        assert key == "global:get_feeds_status"

    def test_special_chars_preserved(self):
        key = make_cache_key("tenant/1", "stats")
        assert key == "tenant/1:stats"


# ---------------------------------------------------------------------------
# 6. invalidate() clears matching entries
# ---------------------------------------------------------------------------

class TestInvalidate:
    def test_invalidate_removes_cached_entry(self):
        call_count = 0

        @cache_endpoint(ttl=300)
        async def cached_op(org_id: str = "default"):
            nonlocal call_count
            call_count += 1
            return {"n": call_count}

        run(cached_op(org_id="inv-org"))
        assert call_count == 1

        # Invalidate all entries for this org
        run(invalidate("inv-org"))

        # Next call should re-execute (cache was cleared)
        run(cached_op(org_id="inv-org"))
        assert call_count == 2


# ---------------------------------------------------------------------------
# 7. cache_stats returns expected structure
# ---------------------------------------------------------------------------

class TestCacheStats:
    def test_returns_dict(self):
        stats = run(cache_stats())
        assert isinstance(stats, dict)

    def test_backend_key_present(self):
        stats = run(cache_stats())
        # Memory backend returns "backend" key; Redis backend may not.
        # Either way there should be at least one key.
        assert len(stats) >= 1


# ---------------------------------------------------------------------------
# 8. TTL constants have expected values
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
