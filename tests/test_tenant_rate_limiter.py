"""
Tests for TenantRateLimiter — per-tenant sliding-window rate limiting.

Coverage:
- TenantQuota model defaults and validation
- set_quota: tier defaults, unknown tier raises ValueError, upsert
- get_quota: returns None for unknown org, returns TenantQuota after set
- check_limit: allowed when under limits, denied on per-minute/hour/day
- record_request: increments counters
- get_usage: correct counts per window
- get_all_quotas: returns all orgs
- reset_usage: clears counters
- cleanup_expired_windows: removes old entries only
- get_top_consumers: sorted by request count, respects limit param
- auto-register unknown org on check_limit (free tier)
- tier override (upsert updates limits)
- remaining counts decrease after requests
- denied_reason strings
- burst_limit stored correctly
- all four tiers have correct defaults
- thread-safety: concurrent record_request
- router: set_quota 200, invalid tier 422
- router: get_quota 200 and 404
- router: check_limit allowed/denied
- router: record_request 200
- router: reset_usage 200
- router: get_all_quotas list
- router: top-consumers
- router: cleanup
- router: 503 on limiter failure

Usage:
    pytest tests/test_tenant_rate_limiter.py -v --timeout=10
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on the path
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.tenant_rate_limiter import (
    TenantQuota,
    TenantRateLimiter,
    _TIER_DEFAULTS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def limiter(tmp_path):
    """Fresh TenantRateLimiter backed by a temp DB for each test."""
    db = str(tmp_path / "rate_limits.db")
    return TenantRateLimiter(db_path=db)


# ---------------------------------------------------------------------------
# TenantQuota model
# ---------------------------------------------------------------------------


def test_tenant_quota_defaults():
    q = TenantQuota(org_id="acme")
    assert q.tier == "free"
    assert q.requests_per_minute == 60
    assert q.requests_per_hour == 1_000
    assert q.requests_per_day == 10_000
    assert q.burst_limit == 10
    assert isinstance(q.current_usage, dict)


def test_tenant_quota_custom():
    q = TenantQuota(org_id="x", tier="pro", requests_per_minute=1000, requests_per_hour=20000, requests_per_day=200000, burst_limit=200)
    assert q.tier == "pro"
    assert q.burst_limit == 200


# ---------------------------------------------------------------------------
# Tier defaults
# ---------------------------------------------------------------------------


def test_tier_defaults_free():
    d = _TIER_DEFAULTS["free"]
    assert d["requests_per_minute"] == 60
    assert d["requests_per_hour"] == 1_000
    assert d["requests_per_day"] == 10_000
    assert d["burst_limit"] == 10


def test_tier_defaults_starter():
    d = _TIER_DEFAULTS["starter"]
    assert d["requests_per_minute"] == 300
    assert d["requests_per_hour"] == 5_000
    assert d["requests_per_day"] == 50_000
    assert d["burst_limit"] == 50


def test_tier_defaults_pro():
    d = _TIER_DEFAULTS["pro"]
    assert d["requests_per_minute"] == 1_000
    assert d["requests_per_hour"] == 20_000
    assert d["requests_per_day"] == 200_000
    assert d["burst_limit"] == 200


def test_tier_defaults_enterprise():
    d = _TIER_DEFAULTS["enterprise"]
    assert d["requests_per_minute"] == 5_000
    assert d["requests_per_hour"] == 100_000
    assert d["requests_per_day"] == 1_000_000
    assert d["burst_limit"] == 500


# ---------------------------------------------------------------------------
# set_quota
# ---------------------------------------------------------------------------


def test_set_quota_free(limiter):
    q = limiter.set_quota("org1", "free")
    assert q.org_id == "org1"
    assert q.tier == "free"
    assert q.requests_per_minute == 60
    assert q.burst_limit == 10


def test_set_quota_pro(limiter):
    q = limiter.set_quota("org2", "pro")
    assert q.tier == "pro"
    assert q.requests_per_minute == 1_000
    assert q.burst_limit == 200


def test_set_quota_enterprise(limiter):
    q = limiter.set_quota("org3", "enterprise")
    assert q.tier == "enterprise"
    assert q.requests_per_day == 1_000_000


def test_set_quota_unknown_tier_raises(limiter):
    with pytest.raises(ValueError, match="Unknown tier"):
        limiter.set_quota("org4", "platinum")


def test_set_quota_upsert_updates_tier(limiter):
    limiter.set_quota("org5", "free")
    q = limiter.set_quota("org5", "starter")
    assert q.tier == "starter"
    assert q.requests_per_minute == 300


def test_set_quota_case_insensitive(limiter):
    q = limiter.set_quota("org6", "PRO")
    assert q.tier == "pro"


# ---------------------------------------------------------------------------
# get_quota
# ---------------------------------------------------------------------------


def test_get_quota_none_for_unknown(limiter):
    result = limiter.get_quota("nonexistent")
    assert result is None


def test_get_quota_returns_tenant_quota(limiter):
    limiter.set_quota("acme", "starter")
    q = limiter.get_quota("acme")
    assert q is not None
    assert isinstance(q, TenantQuota)
    assert q.org_id == "acme"
    assert q.tier == "starter"


def test_get_quota_includes_usage(limiter):
    limiter.set_quota("acme2", "free")
    limiter.record_request("acme2")
    q = limiter.get_quota("acme2")
    assert q is not None
    assert q.current_usage["requests_last_minute"] >= 1


# ---------------------------------------------------------------------------
# check_limit
# ---------------------------------------------------------------------------


def test_check_limit_allowed_fresh_org(limiter):
    limiter.set_quota("fresh", "free")
    result = limiter.check_limit("fresh")
    assert result["allowed"] is True
    assert result["denied_reason"] is None
    assert result["remaining_minute"] == 60
    assert result["limit_minute"] == 60


def test_check_limit_auto_registers_unknown_org(limiter):
    result = limiter.check_limit("brand_new_org")
    assert result["allowed"] is True
    assert result["tier"] == "free"
    q = limiter.get_quota("brand_new_org")
    assert q is not None


def test_check_limit_denied_per_minute(limiter):
    limiter.set_quota("ratelimited", "free")
    # Fill up the minute window
    for _ in range(60):
        limiter.record_request("ratelimited")
    result = limiter.check_limit("ratelimited")
    assert result["allowed"] is False
    assert "minute" in result["denied_reason"]


def test_check_limit_remaining_decreases(limiter):
    limiter.set_quota("decr", "free")
    limiter.record_request("decr")
    limiter.record_request("decr")
    result = limiter.check_limit("decr")
    assert result["remaining_minute"] == 58
    assert result["remaining_hour"] == 998


def test_check_limit_org_id_in_result(limiter):
    limiter.set_quota("myorg", "pro")
    result = limiter.check_limit("myorg")
    assert result["org_id"] == "myorg"
    assert result["tier"] == "pro"


# ---------------------------------------------------------------------------
# record_request
# ---------------------------------------------------------------------------


def test_record_request_increments_minute(limiter):
    limiter.set_quota("rec", "free")
    limiter.record_request("rec")
    usage = limiter.get_usage("rec")
    assert usage["requests_last_minute"] == 1


def test_record_request_multiple(limiter):
    limiter.set_quota("rec2", "free")
    for _ in range(5):
        limiter.record_request("rec2")
    usage = limiter.get_usage("rec2")
    assert usage["requests_last_minute"] == 5
    assert usage["requests_last_hour"] == 5
    assert usage["requests_last_day"] == 5


# ---------------------------------------------------------------------------
# get_usage
# ---------------------------------------------------------------------------


def test_get_usage_zero_for_new_org(limiter):
    limiter.set_quota("new_usage", "free")
    usage = limiter.get_usage("new_usage")
    assert usage["requests_last_minute"] == 0
    assert usage["requests_last_hour"] == 0
    assert usage["requests_last_day"] == 0


def test_get_usage_returns_window_end(limiter):
    limiter.set_quota("wu", "free")
    usage = limiter.get_usage("wu")
    assert "window_end_minute" in usage
    assert "window_end_hour" in usage
    assert "window_end_day" in usage


# ---------------------------------------------------------------------------
# get_all_quotas
# ---------------------------------------------------------------------------


def test_get_all_quotas_empty(limiter):
    result = limiter.get_all_quotas()
    assert result == []


def test_get_all_quotas_multiple(limiter):
    limiter.set_quota("a1", "free")
    limiter.set_quota("b2", "pro")
    limiter.set_quota("c3", "enterprise")
    result = limiter.get_all_quotas()
    assert len(result) == 3
    org_ids = {q.org_id for q in result}
    assert {"a1", "b2", "c3"} == org_ids


# ---------------------------------------------------------------------------
# reset_usage
# ---------------------------------------------------------------------------


def test_reset_usage_clears_counters(limiter):
    limiter.set_quota("reset_org", "free")
    for _ in range(10):
        limiter.record_request("reset_org")
    assert limiter.get_usage("reset_org")["requests_last_minute"] == 10
    result = limiter.reset_usage("reset_org")
    assert result["status"] == "reset"
    assert result["deleted_entries"] == 10
    assert limiter.get_usage("reset_org")["requests_last_minute"] == 0


def test_reset_usage_only_affects_target_org(limiter):
    limiter.set_quota("org_a", "free")
    limiter.set_quota("org_b", "free")
    for _ in range(5):
        limiter.record_request("org_a")
    for _ in range(3):
        limiter.record_request("org_b")
    limiter.reset_usage("org_a")
    assert limiter.get_usage("org_a")["requests_last_minute"] == 0
    assert limiter.get_usage("org_b")["requests_last_minute"] == 3


# ---------------------------------------------------------------------------
# cleanup_expired_windows
# ---------------------------------------------------------------------------


def test_cleanup_expired_windows_removes_old_entries(limiter):
    import sqlite3

    limiter.set_quota("old_org", "free")
    # Insert a fake old request directly into the DB
    old_ts = 1000.0  # far in the past
    conn = sqlite3.connect(limiter._db_path)
    conn.execute("INSERT INTO request_log (org_id, ts) VALUES (?, ?)", ("old_org", old_ts))
    conn.commit()
    conn.close()

    result = limiter.cleanup_expired_windows()
    assert result["deleted_entries"] >= 1


def test_cleanup_expired_windows_keeps_recent_entries(limiter):
    limiter.set_quota("recent_org", "free")
    limiter.record_request("recent_org")
    result = limiter.cleanup_expired_windows()
    # Recent entries should remain
    assert limiter.get_usage("recent_org")["requests_last_minute"] == 1


# ---------------------------------------------------------------------------
# get_top_consumers
# ---------------------------------------------------------------------------


def test_get_top_consumers_empty(limiter):
    result = limiter.get_top_consumers()
    assert result == []


def test_get_top_consumers_sorted(limiter):
    limiter.set_quota("heavy", "pro")
    limiter.set_quota("light", "free")
    for _ in range(10):
        limiter.record_request("heavy")
    for _ in range(2):
        limiter.record_request("light")
    result = limiter.get_top_consumers()
    assert result[0]["org_id"] == "heavy"
    assert result[0]["requests_last_24h"] == 10
    assert result[1]["org_id"] == "light"


def test_get_top_consumers_limit(limiter):
    for i in range(5):
        limiter.set_quota(f"org_{i}", "free")
        for _ in range(i + 1):
            limiter.record_request(f"org_{i}")
    result = limiter.get_top_consumers(limit=3)
    assert len(result) == 3


def test_get_top_consumers_includes_tier(limiter):
    limiter.set_quota("tier_org", "starter")
    limiter.record_request("tier_org")
    result = limiter.get_top_consumers()
    assert result[0]["tier"] == "starter"


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


def test_concurrent_record_request(limiter):
    limiter.set_quota("concurrent", "enterprise")
    errors = []

    def worker():
        try:
            for _ in range(20):
                limiter.record_request("concurrent")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    usage = limiter.get_usage("concurrent")
    assert usage["requests_last_minute"] == 100


# ---------------------------------------------------------------------------
# Router tests
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path):
    """TestClient for the tenant_rate_limiter_router, with isolated DB."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Patch the singleton so router uses temp DB
    db = str(tmp_path / "router_test.db")
    test_limiter = TenantRateLimiter(db_path=db)

    from apps.api.tenant_rate_limiter_router import router, _limiter

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_limiter] = lambda: test_limiter

    return TestClient(app)


def test_router_set_quota_200(client):
    resp = client.post("/api/v1/rate-limits/acme", json={"tier": "pro"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["org_id"] == "acme"
    assert data["tier"] == "pro"
    assert data["requests_per_minute"] == 1_000


def test_router_set_quota_invalid_tier_422(client):
    resp = client.post("/api/v1/rate-limits/acme", json={"tier": "gold"})
    assert resp.status_code == 422


def test_router_get_quota_200(client):
    client.post("/api/v1/rate-limits/myorg", json={"tier": "starter"})
    resp = client.get("/api/v1/rate-limits/myorg")
    assert resp.status_code == 200
    assert resp.json()["tier"] == "starter"


def test_router_get_quota_404(client):
    resp = client.get("/api/v1/rate-limits/does_not_exist")
    assert resp.status_code == 404


def test_router_check_limit_allowed(client):
    client.post("/api/v1/rate-limits/checkorg", json={"tier": "free"})
    resp = client.get("/api/v1/rate-limits/checkorg/check")
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is True
    assert data["remaining_minute"] == 60


def test_router_check_limit_denied(client):
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from pathlib import Path
    import tempfile

    # Fresh limiter with tiny limit
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "tiny.db")
        tiny_limiter = TenantRateLimiter(db_path=db)
        tiny_limiter.set_quota("limited_org", "free")
        for _ in range(60):
            tiny_limiter.record_request("limited_org")

        from apps.api.tenant_rate_limiter_router import router, _limiter
        app2 = FastAPI()
        app2.include_router(router)
        app2.dependency_overrides[_limiter] = lambda: tiny_limiter
        c2 = TestClient(app2)

        resp = c2.get("/api/v1/rate-limits/limited_org/check")
        assert resp.status_code == 200
        assert resp.json()["allowed"] is False
        assert resp.json()["denied_reason"] is not None


def test_router_record_request_200(client):
    client.post("/api/v1/rate-limits/recorg", json={"tier": "free"})
    resp = client.post("/api/v1/rate-limits/recorg/record")
    assert resp.status_code == 200
    assert resp.json()["status"] == "recorded"


def test_router_reset_usage_200(client):
    client.post("/api/v1/rate-limits/resetorg", json={"tier": "free"})
    client.post("/api/v1/rate-limits/resetorg/record")
    resp = client.post("/api/v1/rate-limits/resetorg/reset")
    assert resp.status_code == 200
    assert resp.json()["status"] == "reset"


def test_router_get_all_quotas(client):
    client.post("/api/v1/rate-limits/org_a", json={"tier": "free"})
    client.post("/api/v1/rate-limits/org_b", json={"tier": "pro"})
    resp = client.get("/api/v1/rate-limits")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2


def test_router_top_consumers(client):
    client.post("/api/v1/rate-limits/bigconsumer", json={"tier": "enterprise"})
    for _ in range(5):
        client.post("/api/v1/rate-limits/bigconsumer/record")
    resp = client.get("/api/v1/rate-limits/top-consumers?limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    assert data[0]["org_id"] == "bigconsumer"


def test_router_cleanup(client):
    resp = client.post("/api/v1/rate-limits/cleanup")
    assert resp.status_code == 200
    assert "deleted_entries" in resp.json()


def test_router_503_on_limiter_failure():
    from fastapi import FastAPI, HTTPException, status
    from fastapi.testclient import TestClient
    from apps.api.tenant_rate_limiter_router import router, _limiter

    app3 = FastAPI()
    app3.include_router(router)

    def _bad_limiter():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TenantRateLimiter unavailable: DB offline",
        )

    app3.dependency_overrides[_limiter] = _bad_limiter
    c3 = TestClient(app3, raise_server_exceptions=False)
    resp = c3.get("/api/v1/rate-limits")
    assert resp.status_code == 503
