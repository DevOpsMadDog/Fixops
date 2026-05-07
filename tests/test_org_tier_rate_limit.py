"""Smoke tests for OrgTierRateLimitMiddleware.

Tests:
1. Starter org exhausts 1000/day quota → 429 with Retry-After
2. Enterprise org never gets 429 (unlimited)
3. DailyCounter rollover resets count
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")
# NOTE: do NOT set FIXOPS_DISABLE_TIER_RATE_LIMIT here — these tests exercise
# the middleware directly and need it enabled. Each test wraps the middleware
# as the ASGI app, so the kill-switch must be off for headers to appear.

from apps.api.org_tier_rate_limit_middleware import (
    _DailyCounter,
    _TIER_DAILY_LIMIT,
    OrgTierRateLimitMiddleware,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Shared factory: build app with middleware whose tier is always `tier`
# ---------------------------------------------------------------------------

def _build_client(tier: str) -> tuple:
    """Return (TestClient, middleware_instance) for the given tier."""
    app = FastAPI()

    # Patch _resolve_tier on the class so ALL instances for this test use it.
    OrgTierRateLimitMiddleware._resolve_tier = staticmethod(lambda org_id: tier)  # type: ignore

    mw = OrgTierRateLimitMiddleware(app)

    @app.get("/api/v1/ping")
    async def ping():
        return {"ok": True}

    # Manually build the middleware stack so we hold a reference to `mw`.
    from starlette.testclient import TestClient as _TC

    # Wrap mw directly as the ASGI app so TestClient talks to it.
    client = _TC(mw, raise_server_exceptions=False)
    return client, mw


# ---------------------------------------------------------------------------
# Test 1: Starter quota exhausted → 429
# ---------------------------------------------------------------------------

class TestStarterQuotaExhausted:
    def test_429_after_daily_limit(self):
        """After 1000 requests the 1001st must be 429."""
        limit = _TIER_DAILY_LIMIT["starter"]  # 1000
        client, mw = _build_client("starter")

        # Prime the counter with one real request so Starlette builds the stack.
        resp = client.get("/api/v1/ping", headers={"X-Org-ID": "org-starter"})
        assert resp.status_code == 200

        # Force counter to limit - 1 so next request takes the last slot.
        counter = mw._get_counter("org-starter")
        with counter._lock:
            counter._count = limit - 1

        # This request consumes the last token → should succeed.
        resp = client.get("/api/v1/ping", headers={"X-Org-ID": "org-starter"})
        assert resp.status_code == 200
        assert resp.headers.get("X-RateLimit-Daily-Limit") == str(limit)
        assert resp.headers.get("X-RateLimit-Daily-Remaining") == "0"

        # Next request must be rejected.
        resp = client.get("/api/v1/ping", headers={"X-Org-ID": "org-starter"})
        assert resp.status_code == 429
        body = resp.json()
        assert body["error"] == "daily_quota_exceeded"
        assert body["tier"] == "starter"
        assert body["daily_limit"] == limit
        assert int(resp.headers["Retry-After"]) >= 1


# ---------------------------------------------------------------------------
# Test 2: Enterprise org — unlimited, never 429
# ---------------------------------------------------------------------------

class TestEnterpriseUnlimited:
    def test_enterprise_never_429(self):
        """200 rapid requests for enterprise tier must all return 200."""
        client, _ = _build_client("enterprise")

        for i in range(200):
            resp = client.get("/api/v1/ping", headers={"X-Org-ID": "org-enterprise"})
            assert resp.status_code == 200, f"Request {i + 1} failed with {resp.status_code}"
            assert resp.headers.get("X-RateLimit-Daily-Limit") == "unlimited"
            assert resp.headers.get("X-RateLimit-Tier") == "enterprise"


# ---------------------------------------------------------------------------
# Test 3: DailyCounter unit — day rollover resets count
# ---------------------------------------------------------------------------

class TestDailyCounterRollover:
    def test_counter_resets_on_new_day(self):
        counter = _DailyCounter()
        limit = 1000

        # Fill to limit
        with counter._lock:
            counter._count = limit

        # Verify exhausted
        allowed, _ = counter.increment_and_check(limit)
        assert allowed is False

        # Simulate day rollover: set _day to yesterday
        with counter._lock:
            counter._day -= 1

        # Now should reset and allow
        allowed, retry_after = counter.increment_and_check(limit)
        assert allowed is True
        assert retry_after == 0
        assert counter.count == 1  # reset to 0 + 1 new request
