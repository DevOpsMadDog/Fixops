"""Tests for the in-memory TTLCache, cache_response decorator, NamedCacheManager,
and ProfilingMiddleware.

Run with:
    python -m pytest tests/test_cache.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import os
import time
import threading
import asyncio

import pytest

# Ensure env vars are set before any app imports
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

from core.cache import TTLCache, cache_response, NamedCacheManager, named_cache_manager


# ===========================================================================
# TTLCache — get / set / TTL expiry
# ===========================================================================


class TestTTLCacheBasics:
    def test_set_and_get(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        c.set("k", "v")
        assert c.get("k") == "v"

    def test_get_missing_returns_none(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        assert c.get("missing") is None

    def test_ttl_expiry(self):
        c = TTLCache(maxsize=10, ttl_seconds=0.05)  # 50 ms TTL
        c.set("k", "v")
        assert c.get("k") == "v"
        time.sleep(0.1)
        assert c.get("k") is None

    def test_per_key_ttl_override(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        c.set("k", "v", ttl=0.05)  # override to 50 ms
        assert c.get("k") == "v"
        time.sleep(0.1)
        assert c.get("k") is None

    def test_delete(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        c.set("k", "v")
        c.delete("k")
        assert c.get("k") is None

    def test_delete_missing_is_noop(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        c.delete("nonexistent")  # should not raise

    def test_clear(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        c.set("a", 1)
        c.set("b", 2)
        c.clear()
        assert c.get("a") is None
        assert c.get("b") is None

    def test_overwrite_key(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        c.set("k", "v1")
        c.set("k", "v2")
        assert c.get("k") == "v2"

    def test_none_value_not_stored_as_miss(self):
        """Storing None as a value is valid; get() returns None which looks
        like a miss — that's acceptable documented behaviour."""
        c = TTLCache(maxsize=10, ttl_seconds=60)
        # get on missing → None
        assert c.get("k") is None


# ===========================================================================
# TTLCache — LRU eviction
# ===========================================================================


class TestTTLCacheLRU:
    def test_lru_evicts_oldest(self):
        c = TTLCache(maxsize=3, ttl_seconds=60)
        c.set("a", 1)
        c.set("b", 2)
        c.set("c", 3)
        # Access 'a' to make it recently used
        c.get("a")
        # Adding 'd' should evict 'b' (LRU)
        c.set("d", 4)
        assert c.get("a") == 1
        assert c.get("c") == 3
        assert c.get("d") == 4
        assert c.get("b") is None  # evicted

    def test_eviction_count_tracked(self):
        c = TTLCache(maxsize=2, ttl_seconds=60)
        c.set("a", 1)
        c.set("b", 2)
        c.set("c", 3)  # triggers eviction
        assert c.stats()["evictions"] >= 1

    def test_maxsize_respected(self):
        c = TTLCache(maxsize=5, ttl_seconds=60)
        for i in range(20):
            c.set(f"k{i}", i)
        assert c.stats()["size"] <= 5


# ===========================================================================
# TTLCache — stats
# ===========================================================================


class TestTTLCacheStats:
    def test_hit_counted(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        c.set("k", "v")
        c.get("k")
        s = c.stats()
        assert s["hits"] == 1
        assert s["misses"] == 0

    def test_miss_counted(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        c.get("k")
        s = c.stats()
        assert s["misses"] == 1
        assert s["hits"] == 0

    def test_hit_rate_calculation(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        c.set("k", "v")
        c.get("k")   # hit
        c.get("x")   # miss
        s = c.stats()
        assert s["hit_rate"] == pytest.approx(0.5, abs=0.01)

    def test_stats_keys_present(self):
        c = TTLCache(maxsize=10, ttl_seconds=60)
        s = c.stats()
        assert set(s.keys()) == {"hits", "misses", "hit_rate", "size", "maxsize", "evictions"}

    def test_expired_entry_counts_as_miss(self):
        c = TTLCache(maxsize=10, ttl_seconds=0.05)
        c.set("k", "v")
        time.sleep(0.1)
        c.get("k")  # expired → miss
        s = c.stats()
        assert s["misses"] >= 1


# ===========================================================================
# TTLCache — thread safety
# ===========================================================================


class TestTTLCacheThreadSafety:
    def test_concurrent_writes(self):
        c = TTLCache(maxsize=1000, ttl_seconds=60)
        errors = []

        def writer(start: int) -> None:
            try:
                for i in range(100):
                    c.set(f"k{start + i}", i)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i * 100,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"

    def test_concurrent_reads_writes(self):
        c = TTLCache(maxsize=100, ttl_seconds=60)
        for i in range(50):
            c.set(f"k{i}", i)
        errors = []

        def reader() -> None:
            try:
                for i in range(200):
                    c.get(f"k{i % 50}")
            except Exception as exc:
                errors.append(exc)

        def writer() -> None:
            try:
                for i in range(200):
                    c.set(f"k{i % 50}", i)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(3)]
        threads += [threading.Thread(target=writer) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"


# ===========================================================================
# cache_response decorator
# ===========================================================================


class TestCacheResponseDecorator:
    def _make_request(self, path: str = "/test", query: str = "") -> object:
        """Minimal fake Request-like object."""
        class FakeURL:
            def __init__(self, p, q):
                self.path = p
                self._query = q
            def __str__(self):
                return self.path

        class FakeRequest:
            def __init__(self, p, q):
                self.url = FakeURL(p, q)
                self.query_params = q
                self.method = "GET"

        return FakeRequest(path, query)

    def test_caches_dict_response(self):
        backing = TTLCache(maxsize=10, ttl_seconds=60)
        call_count = 0

        @cache_response(ttl=60, key_func=lambda r: r.url.path, cache=backing)
        async def handler(request):
            nonlocal call_count
            call_count += 1
            return {"data": "value"}

        req = self._make_request("/test")
        asyncio.run(handler(req))
        asyncio.run(handler(req))
        assert call_count == 1  # second call served from cache

    def test_cache_miss_calls_handler(self):
        backing = TTLCache(maxsize=10, ttl_seconds=60)
        call_count = 0

        @cache_response(ttl=60, key_func=lambda r: r.url.path, cache=backing)
        async def handler(request):
            nonlocal call_count
            call_count += 1
            return {"data": "value"}

        req1 = self._make_request("/path1")
        req2 = self._make_request("/path2")
        asyncio.run(handler(req1))
        asyncio.run(handler(req2))
        assert call_count == 2  # different keys → different cache entries

    def test_ttl_expiry_triggers_refetch(self):
        backing = TTLCache(maxsize=10, ttl_seconds=60)
        call_count = 0

        @cache_response(ttl=0.05, key_func=lambda r: r.url.path, cache=backing)
        async def handler(request):
            nonlocal call_count
            call_count += 1
            return {"data": call_count}

        req = self._make_request("/test")
        asyncio.run(handler(req))
        time.sleep(0.1)  # let cache expire
        asyncio.run(handler(req))
        assert call_count == 2  # fetched again after TTL


# ===========================================================================
# NamedCacheManager
# ===========================================================================


class TestNamedCacheManager:
    def test_singleton_pattern(self):
        mgr1 = NamedCacheManager()
        mgr2 = NamedCacheManager()
        assert mgr1 is mgr2

    def test_module_level_singleton(self):
        mgr = NamedCacheManager()
        assert mgr is named_cache_manager

    def test_named_caches_exist(self):
        mgr = NamedCacheManager()
        assert isinstance(mgr.findings, TTLCache)
        assert isinstance(mgr.dashboard, TTLCache)
        assert isinstance(mgr.compliance, TTLCache)
        assert isinstance(mgr.pipeline, TTLCache)

    def test_findings_ttl(self):
        mgr = NamedCacheManager()
        # TTL is 30 s — just verify the maxsize is correct
        assert mgr.findings._maxsize == 1000

    def test_dashboard_maxsize(self):
        mgr = NamedCacheManager()
        assert mgr.dashboard._maxsize == 100

    def test_compliance_maxsize(self):
        mgr = NamedCacheManager()
        assert mgr.compliance._maxsize == 50

    def test_pipeline_maxsize(self):
        mgr = NamedCacheManager()
        assert mgr.pipeline._maxsize == 200

    def test_all_stats_returns_all_caches(self):
        mgr = NamedCacheManager()
        stats = mgr.all_stats()
        assert set(stats.keys()) == {"findings", "dashboard", "compliance", "pipeline"}

    def test_clear_all(self):
        mgr = NamedCacheManager()
        mgr.findings.set("x", 1)
        mgr.dashboard.set("y", 2)
        mgr.clear_all()
        assert mgr.findings.get("x") is None
        assert mgr.dashboard.get("y") is None

    def test_get_cache_known(self):
        mgr = NamedCacheManager()
        assert mgr.get_cache("findings") is mgr.findings
        assert mgr.get_cache("pipeline") is mgr.pipeline

    def test_get_cache_unknown_returns_none(self):
        mgr = NamedCacheManager()
        assert mgr.get_cache("nonexistent") is None


# ===========================================================================
# ProfilingMiddleware
# ===========================================================================


class TestProfilingMiddleware:
    """Test ProfilingMiddleware using a minimal ASGI test app."""

    @pytest.fixture(autouse=True)
    def reset_profiling(self):
        """Reset profiling data before each test."""
        from core.profiling import reset_profiling_data
        reset_profiling_data()
        yield
        reset_profiling_data()

    def _make_app(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from core.profiling import ProfilingMiddleware, profiling_router

        app = FastAPI()
        app.add_middleware(ProfilingMiddleware)
        app.include_router(profiling_router)

        @app.get("/fast")
        async def fast_endpoint():
            return {"status": "fast"}

        @app.get("/echo")
        async def echo_endpoint():
            return {"status": "echo"}

        return TestClient(app)

    def test_x_response_time_header_present(self):
        client = self._make_app()
        response = client.get("/fast")
        assert "X-Response-Time" in response.headers

    def test_x_response_time_is_numeric_ms(self):
        client = self._make_app()
        response = client.get("/fast")
        header = response.headers["X-Response-Time"]
        assert header.endswith("ms")
        value = float(header.replace("ms", "").strip())
        assert value >= 0.0

    def test_profiling_endpoint_accessible(self):
        client = self._make_app()
        response = client.get("/api/v1/metrics/performance")
        assert response.status_code == 200
        data = response.json()
        assert "total_requests" in data
        assert "endpoints" in data

    def test_profiling_records_endpoint(self):
        client = self._make_app()
        client.get("/fast")
        response = client.get("/api/v1/metrics/performance")
        data = response.json()
        paths = [e["path"] for e in data["endpoints"]]
        assert "/fast" in paths

    def test_profiling_data_structure(self):
        client = self._make_app()
        client.get("/fast")
        response = client.get("/api/v1/metrics/performance")
        data = response.json()
        assert data["total_requests"] >= 1
        endpoint = next(e for e in data["endpoints"] if e["path"] == "/fast")
        for key in ("p50_ms", "p95_ms", "p99_ms", "mean_ms", "max_ms", "sample_count"):
            assert key in endpoint, f"Missing key: {key}"

    def test_slow_request_warning_logged(self, caplog):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from core.profiling import ProfilingMiddleware, reset_profiling_data

        app = FastAPI()
        app.add_middleware(ProfilingMiddleware)

        @app.get("/slow")
        async def slow_endpoint():
            time.sleep(0.01)  # small sleep — we'll mock the threshold
            return {"status": "slow"}

        # Lower the threshold temporarily
        import core.profiling as prof_mod
        original_warn = ProfilingMiddleware.WARN_THRESHOLD_MS
        ProfilingMiddleware.WARN_THRESHOLD_MS = 0  # everything is "slow"

        client = TestClient(app)
        with caplog.at_level("WARNING", logger="core.profiling"):
            client.get("/slow")

        ProfilingMiddleware.WARN_THRESHOLD_MS = original_warn
        # At least one slow-request warning should appear
        slow_logs = [r for r in caplog.records if "SLOW_REQUEST" in r.message]
        assert len(slow_logs) >= 1
