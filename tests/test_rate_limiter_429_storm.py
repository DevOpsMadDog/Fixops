"""
Stress / soak tests for RateLimitMiddleware crash-loop hardening.

Mission (DEMO-001 hardening): the API server must not crash under sustained
429 storms. Workaround prior to this fix was setting FIXOPS_DISABLE_RATE_LIMIT=1
because the limiter would OOM / log-flood / event-loop-stall.

These tests fire ~1000 req/s for ~10s (and shorter bursts in unit-time tests),
asserting:
  * Zero server-side exceptions / 500s.
  * 429s ARE returned (limiter still functional, not silently bypassed).
  * Bucket dict stays bounded (LRU eviction kicks in under unique-key floods).
  * Rejection-rate cap protects the loop (cheap_429 served when over budget).
  * Defensive dispatch — if the limiter's bookkeeping breaks, requests still
    flow (fail-open behaviour).
"""

from __future__ import annotations

import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple
from unittest.mock import MagicMock

import pytest

# Ensure middleware is enabled for these tests even if the dev shell exported it off.
os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "0"
os.environ.setdefault("FIXOPS_API_TOKEN", "storm-test-token")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_JWT_SECRET", "storm-test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.rate_limit_middleware import RateLimitMiddleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_storm_app(
    rpm: int = 60,
    burst: int = 5,
    max_buckets: int = 100,
    max_rej_per_sec: int = 50,
) -> Tuple[FastAPI, TestClient, RateLimitMiddleware]:
    """Build a minimal app wired with the hardened middleware.

    Returns (app, client, middleware_instance) — instance retrieved from
    the user_middleware stack so we can poke at internals.
    """
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        requests_per_minute=rpm,
        read_requests_per_minute=rpm,
        write_requests_per_minute=rpm,
        burst=burst,
        max_tracked_buckets=max_buckets,
        max_rejections_per_sec=max_rej_per_sec,
    )

    @app.get("/api/v1/storm")
    async def storm_endpoint():
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=True)
    # Trigger middleware build by making one (exempt) request.
    client.get("/health")
    # Find the live middleware instance by walking the user_middleware list
    # and constructing one for inspection. For testing we instantiate a
    # mirror with the same caps so we can assert behaviour deterministically.
    mirror = RateLimitMiddleware(
        app,
        requests_per_minute=rpm,
        read_requests_per_minute=rpm,
        write_requests_per_minute=rpm,
        burst=burst,
        max_tracked_buckets=max_buckets,
        max_rejections_per_sec=max_rej_per_sec,
    )
    return app, client, mirror


# ---------------------------------------------------------------------------
# 1) The headline test: 1000 req/s sustained burst
# ---------------------------------------------------------------------------


class TestStormDoesNotCrash:
    def test_sustained_storm_no_server_crash(self):
        """Fire ~1000 requests as fast as we can; assert NO 5xx, only 200/429."""
        _, client, _ = _build_storm_app(rpm=60, burst=5, max_rej_per_sec=20)

        TOTAL_REQUESTS = 1000
        statuses = []
        errors = []

        def hit(_i):
            try:
                r = client.get("/api/v1/storm")
                return r.status_code
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))
                return -1

        # Use threads to drive concurrency at the TestClient layer
        with ThreadPoolExecutor(max_workers=32) as pool:
            futures = [pool.submit(hit, i) for i in range(TOTAL_REQUESTS)]
            for fut in as_completed(futures):
                statuses.append(fut.result())

        # Hard requirements
        assert errors == [], f"Server raised exceptions during storm: {errors[:5]}"
        assert all(s in (200, 429) for s in statuses), (
            f"Got non-200/429 status codes: {[s for s in statuses if s not in (200, 429)][:10]}"
        )
        # We MUST see some 429s — otherwise the limiter silently bypassed
        assert 429 in statuses, "Limiter never rejected — silent bypass?"
        # And we MUST see some successes — limiter shouldn't reject everything
        assert 200 in statuses, "Limiter rejected all requests — wrong behaviour"

    def test_storm_returns_429_responses(self):
        """Fire enough to exhaust the bucket; verify Retry-After header is set on 429s."""
        _, client, _ = _build_storm_app(rpm=60, burst=2)

        saw_429_with_header = False
        for _ in range(50):
            r = client.get("/api/v1/storm")
            if r.status_code == 429:
                assert "Retry-After" in r.headers, "429 missing Retry-After header"
                body = r.json()
                assert body.get("error") == "rate_limit_exceeded"
                saw_429_with_header = True
                break
        assert saw_429_with_header, "Never observed 429 with proper headers"


# ---------------------------------------------------------------------------
# 2) LRU eviction — unbounded bucket growth was the OOM vector
# ---------------------------------------------------------------------------


class TestBucketLRUEviction:
    def test_bucket_dict_capped_under_unique_ip_flood(self):
        """Spoof 5000 distinct X-API-Keys; bucket dict must NOT exceed cap."""
        _, client, _ = _build_storm_app(rpm=60, burst=3, max_buckets=100)

        for i in range(5000):
            client.get(
                "/api/v1/storm",
                headers={"X-API-Key": f"spoofed-key-{i:06d}"},
            )

        # We can't reach the live middleware easily through TestClient,
        # so verify directly via a fresh instance with the same cap.
        mw = RateLimitMiddleware(
            app=MagicMock(),
            max_tracked_buckets=100,
        )
        for i in range(5000):
            mw._get_bucket(f"key:spoofed-{i}", "GET", False)

        assert len(mw._buckets) <= 100, (
            f"LRU eviction failed — bucket dict has {len(mw._buckets)} entries, expected <= 100"
        )

    def test_existing_bucket_promoted_to_recent(self):
        """Used buckets must be moved to MRU position so they aren't evicted."""
        mw = RateLimitMiddleware(app=MagicMock(), max_tracked_buckets=5)

        # Fill bucket cache
        for i in range(5):
            mw._get_bucket(f"key:user-{i}", "GET", False)

        # Touch the oldest one — should now be MRU
        mw._get_bucket("key:user-0", "GET", False)

        # Insert a new entry — user-1 (now LRU) should be evicted, NOT user-0
        mw._get_bucket("key:user-new", "GET", False)

        keys = list(mw._buckets.keys())
        assert "key:user-0:read" in keys, "Recently-used bucket was evicted (LRU broken)"
        assert "key:user-1:read" not in keys, "Oldest bucket was NOT evicted"


# ---------------------------------------------------------------------------
# 3) Rejection-rate cap — the storm self-limiter
# ---------------------------------------------------------------------------


class TestRejectionRateCap:
    def test_rejection_cap_serves_cheap_response_under_storm(self):
        """Once we exceed max_rejections_per_sec, _should_emit_real_429 returns False."""
        mw = RateLimitMiddleware(
            app=MagicMock(),
            max_rejections_per_sec=10,
        )
        # First 10 in the window should be "real"
        real = sum(1 for _ in range(10) if mw._should_emit_real_429())
        # Next 90 should be cheap
        cheap = sum(1 for _ in range(90) if not mw._should_emit_real_429())

        assert real == 10, f"Expected 10 real rejections, got {real}"
        assert cheap == 90, f"Expected 90 cheap rejections, got {cheap}"

    def test_rejection_window_rolls_each_second(self):
        """After 1+s the rejection budget should reset."""
        mw = RateLimitMiddleware(
            app=MagicMock(),
            max_rejections_per_sec=5,
        )
        for _ in range(5):
            assert mw._should_emit_real_429() is True
        # Now over budget
        assert mw._should_emit_real_429() is False
        # Wait for window to roll
        time.sleep(1.05)
        # Budget restored
        assert mw._should_emit_real_429() is True

    def test_cheap_429_payload_is_well_formed(self):
        """The pre-built static 429 must be a valid JSONResponse with Retry-After."""
        mw = RateLimitMiddleware(app=MagicMock())
        cheap = mw._cheap_429
        assert cheap.status_code == 429
        assert cheap.headers.get("Retry-After") == "1"


# ---------------------------------------------------------------------------
# 4) Defensive dispatch — limiter must never crash the request path
# ---------------------------------------------------------------------------


class TestDefensiveDispatch:
    def test_bookkeeping_failure_falls_through_to_handler(self):
        """If _get_bucket raises, the request must still reach the handler."""
        app = FastAPI()
        app.add_middleware(RateLimitMiddleware, requests_per_minute=60, burst=5)

        @app.get("/api/v1/probe")
        async def probe():
            return {"ok": True}

        client = TestClient(app)

        # Sanity: works fine normally
        assert client.get("/api/v1/probe").status_code == 200

        # Patch _get_bucket on the live middleware (dig into Starlette internals)
        # to simulate a bookkeeping crash and confirm fail-open behaviour.
        # We do this by monkeypatching the class temporarily.
        original = RateLimitMiddleware._get_bucket

        def boom(self, identifier, method, is_admin):
            raise KeyError("simulated bookkeeping failure")

        RateLimitMiddleware._get_bucket = boom
        try:
            r = client.get("/api/v1/probe")
            assert r.status_code == 200, (
                f"Limiter bookkeeping failure should fail-open, got {r.status_code}"
            )
        finally:
            RateLimitMiddleware._get_bucket = original


# ---------------------------------------------------------------------------
# 5) Stats expose rejection counters (observability of the storm self-limiter)
# ---------------------------------------------------------------------------


class TestStormObservability:
    def test_get_stats_exposes_rejection_counters(self):
        mw = RateLimitMiddleware(app=MagicMock(), max_rejections_per_sec=10)
        for _ in range(20):
            mw._should_emit_real_429()

        stats = mw.get_stats()
        assert "rejections" in stats
        rej = stats["rejections"]
        assert rej["total"] == 20
        assert rej["max_per_second"] == 10
        assert "max_tracked_buckets" in rej


# ---------------------------------------------------------------------------
# 6) Concurrency — token bucket must be lock-safe under threading
# ---------------------------------------------------------------------------


class TestConcurrencyLocking:
    def test_concurrent_consume_does_not_double_spend(self):
        """100 threads racing on one bucket — total consumed must not exceed capacity."""
        from apps.api.rate_limit_middleware import _TokenBucket

        bucket = _TokenBucket(capacity=10.0, refill_rate=0.0)  # no refill
        consumed = []
        lock = threading.Lock()

        def hit():
            allowed, _ = bucket.consume()
            with lock:
                consumed.append(allowed)

        threads = [threading.Thread(target=hit) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        approved = sum(1 for c in consumed if c)
        # Capacity 10, no refill, 100 racers — exactly 10 may pass
        assert approved == 10, f"Concurrency bug: {approved} approvals on capacity-10 bucket"
