"""Tests for rate_limiter_v2 — sliding window rate limiting engine.

Covers:
- SlidingWindowCounter: get_count, increment, check, cleanup
- Sliding window: allows within limit, blocks over limit
- Burst allowance
- Window expiry
- Per-endpoint tiers (different limits per path)
- Per-key limits (overrides)
- Rate limit headers
- 429 behavior (check result)
- Cleanup
- Dashboard data
- Thread safety
- RateLimiterV2: check_rate_limit, record_request, get_headers, reset_key
- RateLimitMiddlewareV2 dispatch
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.rate_limiter_v2 import (
    RateLimitConfig,
    RateLimitMiddlewareV2,
    RateLimitResult,
    RateLimitTier,
    RateLimiterV2,
    SlidingWindowCounter,
    _TIER_LIMITS,
    get_rate_limiter,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(
    path: str = "/api/v1/findings",
    api_key_id: Optional[str] = None,
    client_ip: str = "127.0.0.1",
) -> MagicMock:
    """Build a minimal mock request object matching what RateLimiterV2 reads."""
    req = MagicMock()
    req.url.path = path
    req.client.host = client_ip
    state = SimpleNamespace(api_key_id=api_key_id)
    req.state = state
    return req


# ---------------------------------------------------------------------------
# SlidingWindowCounter — unit tests
# ---------------------------------------------------------------------------


class TestSlidingWindowCounter:
    def setup_method(self):
        self.counter = SlidingWindowCounter()

    def test_get_count_empty_key(self):
        assert self.counter.get_count("missing", 60) == 0

    def test_increment_and_get_count(self):
        self.counter.increment("k1")
        self.counter.increment("k1")
        assert self.counter.get_count("k1", 60) == 2

    def test_get_count_does_not_record(self):
        self.counter.get_count("k2", 60)
        assert self.counter.get_count("k2", 60) == 0

    def test_check_allowed_within_limit(self):
        for _ in range(3):
            self.counter.increment("k3")
        result = self.counter.check("k3", limit=5, window_seconds=60)
        assert result.allowed is True
        assert result.remaining == 2
        assert result.limit == 5
        assert result.retry_after_seconds is None

    def test_check_blocked_at_limit(self):
        for _ in range(5):
            self.counter.increment("k4")
        result = self.counter.check("k4", limit=5, window_seconds=60)
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after_seconds is not None
        assert result.retry_after_seconds >= 1

    def test_check_blocked_over_limit(self):
        for _ in range(10):
            self.counter.increment("k5")
        result = self.counter.check("k5", limit=5, window_seconds=60)
        assert result.allowed is False

    def test_check_returns_rate_limit_result(self):
        result = self.counter.check("k6", limit=10, window_seconds=60)
        assert isinstance(result, RateLimitResult)
        assert isinstance(result.reset_at, datetime)
        assert result.reset_at.tzinfo is not None  # tz-aware

    def test_window_expiry(self):
        """Timestamps older than window_seconds should not be counted."""
        key = "k_expiry"
        # Manually inject an old timestamp into the internal window
        cutoff_old = time.monotonic() - 120  # 2 minutes ago
        with self.counter._lock:
            self.counter._windows[key] = [cutoff_old]
        # Within a 60-second window, that old entry should not count
        result = self.counter.check(key, limit=1, window_seconds=60)
        assert result.allowed is True
        assert result.remaining == 1

    def test_check_empty_key_allowed(self):
        result = self.counter.check("never_used", limit=10, window_seconds=60)
        assert result.allowed is True
        assert result.remaining == 10

    def test_cleanup_removes_old_entries(self):
        key = "k_cleanup"
        # Inject timestamp older than 1 hour
        old_ts = time.monotonic() - 3700
        with self.counter._lock:
            self.counter._windows[key] = [old_ts, old_ts]
        pruned = self.counter.cleanup()
        assert pruned == 2
        with self.counter._lock:
            assert key not in self.counter._windows

    def test_cleanup_keeps_recent_entries(self):
        self.counter.increment("k_recent")
        self.counter.increment("k_recent")
        pruned = self.counter.cleanup()
        assert pruned == 0
        assert self.counter.get_count("k_recent", 60) == 2

    def test_cleanup_returns_zero_when_nothing_to_prune(self):
        assert self.counter.cleanup() == 0

    def test_thread_safety_concurrent_increments(self):
        """100 concurrent increments must all be recorded."""
        key = "k_threads"
        n = 100

        def increment_many():
            for _ in range(10):
                self.counter.increment(key)

        threads = [threading.Thread(target=increment_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert self.counter.get_count(key, 60) == n


# ---------------------------------------------------------------------------
# RateLimiterV2 — tier and config tests
# ---------------------------------------------------------------------------


class TestRateLimiterV2Config:
    def setup_method(self):
        self.limiter = RateLimiterV2()

    def test_default_tier_limits_present(self):
        for tier in RateLimitTier:
            assert tier in _TIER_LIMITS
            assert _TIER_LIMITS[tier] > 0

    def test_resolve_scan_tier(self):
        tier = self.limiter._resolve_tier_for_path("/api/v1/cicd/scan")
        assert tier == RateLimitTier.SCAN

    def test_resolve_query_tier(self):
        tier = self.limiter._resolve_tier_for_path("/api/v1/findings")
        assert tier == RateLimitTier.QUERY

    def test_resolve_write_tier(self):
        tier = self.limiter._resolve_tier_for_path("/api/v1/remediation/fix")
        assert tier == RateLimitTier.WRITE

    def test_resolve_admin_tier(self):
        tier = self.limiter._resolve_tier_for_path("/api/v1/auth/keys")
        assert tier == RateLimitTier.ADMIN

    def test_resolve_webhook_tier(self):
        tier = self.limiter._resolve_tier_for_path("/api/v1/slack/event")
        assert tier == RateLimitTier.WEBHOOK

    def test_resolve_default_tier_for_unknown_path(self):
        tier = self.limiter._resolve_tier_for_path("/api/v1/unknown/path")
        assert tier == RateLimitTier.DEFAULT

    def test_configure_endpoint_overrides_tier(self):
        self.limiter.configure_endpoint(r"^/api/v1/custom$", RateLimitTier.ADMIN)
        tier = self.limiter._resolve_tier_for_path("/api/v1/custom")
        assert tier == RateLimitTier.ADMIN

    def test_configure_endpoint_prepends_so_new_rule_wins(self):
        # Register the same pattern twice with different tiers
        self.limiter.configure_endpoint(r"^/api/v1/conflict$", RateLimitTier.SCAN)
        self.limiter.configure_endpoint(r"^/api/v1/conflict$", RateLimitTier.ADMIN)
        tier = self.limiter._resolve_tier_for_path("/api/v1/conflict")
        assert tier == RateLimitTier.ADMIN

    def test_resolve_limit_uses_per_key_override(self):
        self.limiter.configure_key_limit("key123", 999)
        limit, window = self.limiter._resolve_limit("/api/v1/findings", "key123")
        assert limit == 999
        assert window == 60

    def test_resolve_limit_removes_override_when_zero(self):
        self.limiter.configure_key_limit("key456", 50)
        self.limiter.configure_key_limit("key456", 0)
        limit, window = self.limiter._resolve_limit("/api/v1/findings", "key456")
        # Should fall back to tier limit
        assert limit == _TIER_LIMITS[RateLimitTier.QUERY]

    def test_resolve_limit_removes_override_when_negative(self):
        self.limiter.configure_key_limit("key789", 50)
        self.limiter.configure_key_limit("key789", -1)
        limit, _ = self.limiter._resolve_limit("/api/v1/findings", "key789")
        assert limit == _TIER_LIMITS[RateLimitTier.QUERY]

    def test_get_endpoint_configs_returns_list(self):
        configs = self.limiter.get_endpoint_configs()
        assert isinstance(configs, list)
        assert len(configs) > 0
        first = configs[0]
        assert "pattern" in first
        assert "tier" in first
        assert "requests_per_minute" in first

    def test_burst_allowance_adds_to_limit(self):
        self.limiter._tier_configs[RateLimitTier.SCAN] = RateLimitConfig(
            tier=RateLimitTier.SCAN,
            requests_per_minute=10,
            burst_allowance=5,
            window_seconds=60,
        )
        limit, _ = self.limiter._resolve_limit("/api/v1/cicd/scan", None)
        assert limit == 15  # 10 + 5


# ---------------------------------------------------------------------------
# RateLimiterV2 — check_rate_limit / record_request
# ---------------------------------------------------------------------------


class TestRateLimiterV2CheckAndRecord:
    def setup_method(self):
        self.limiter = RateLimiterV2()

    def test_allows_first_request(self):
        req = _make_request("/api/v1/findings", api_key_id="key1")
        result = self.limiter.check_rate_limit(req)
        assert result.allowed is True

    def test_blocks_after_limit_exceeded(self):
        """Send requests up to SCAN tier limit (10/min) — next must be blocked."""
        self.limiter.configure_endpoint(r"^/api/v1/cicd/scan$", RateLimitTier.SCAN)
        req = _make_request("/api/v1/cicd/scan", api_key_id="scan_key")
        scan_limit = _TIER_LIMITS[RateLimitTier.SCAN]

        for _ in range(scan_limit):
            result = self.limiter.check_rate_limit(req)
            assert result.allowed is True
            self.limiter.record_request(req)

        result = self.limiter.check_rate_limit(req)
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after_seconds is not None

    def test_different_keys_tracked_separately(self):
        req_a = _make_request("/api/v1/cicd/scan", api_key_id="key_a")
        req_b = _make_request("/api/v1/cicd/scan", api_key_id="key_b")
        scan_limit = _TIER_LIMITS[RateLimitTier.SCAN]

        for _ in range(scan_limit):
            self.limiter.record_request(req_a)

        result_a = self.limiter.check_rate_limit(req_a)
        result_b = self.limiter.check_rate_limit(req_b)
        assert result_a.allowed is False
        assert result_b.allowed is True

    def test_falls_back_to_ip_when_no_key(self):
        req = _make_request("/api/v1/findings", api_key_id=None, client_ip="10.0.0.1")
        result = self.limiter.check_rate_limit(req)
        assert result.allowed is True

    def test_falls_back_to_anonymous_when_no_ip(self):
        req = MagicMock()
        req.url.path = "/api/v1/findings"
        req.client = None
        req.state = SimpleNamespace(api_key_id=None)
        result = self.limiter.check_rate_limit(req)
        assert result.allowed is True

    def test_handles_missing_url_attribute(self):
        req = MagicMock(spec=[])  # no url attribute
        # Should not raise
        result = self.limiter.check_rate_limit(req)
        assert isinstance(result, RateLimitResult)

    def test_reset_key_clears_window(self):
        req = _make_request("/api/v1/cicd/scan", api_key_id="reset_key")
        scan_limit = _TIER_LIMITS[RateLimitTier.SCAN]
        for _ in range(scan_limit):
            self.limiter.record_request(req)

        result_before = self.limiter.check_rate_limit(req)
        assert result_before.allowed is False

        self.limiter.reset_key("reset_key")

        result_after = self.limiter.check_rate_limit(req)
        assert result_after.allowed is True


# ---------------------------------------------------------------------------
# Rate limit headers
# ---------------------------------------------------------------------------


class TestRateLimitHeaders:
    def setup_method(self):
        self.limiter = RateLimiterV2()

    def test_headers_present_when_allowed(self):
        req = _make_request("/api/v1/findings", api_key_id="hdr_key")
        result = self.limiter.check_rate_limit(req)
        headers = self.limiter.get_headers(result)
        assert "X-RateLimit-Limit" in headers
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers
        assert "Retry-After" not in headers

    def test_retry_after_header_when_blocked(self):
        req = _make_request("/api/v1/cicd/scan", api_key_id="hdr_block_key")
        scan_limit = _TIER_LIMITS[RateLimitTier.SCAN]
        for _ in range(scan_limit):
            self.limiter.record_request(req)

        result = self.limiter.check_rate_limit(req)
        headers = self.limiter.get_headers(result)
        assert "Retry-After" in headers
        assert int(headers["Retry-After"]) >= 1

    def test_header_values_are_strings(self):
        req = _make_request("/api/v1/findings", api_key_id="str_key")
        result = self.limiter.check_rate_limit(req)
        headers = self.limiter.get_headers(result)
        for v in headers.values():
            assert isinstance(v, str)

    def test_x_ratelimit_reset_is_unix_timestamp(self):
        req = _make_request("/api/v1/findings", api_key_id="ts_key")
        result = self.limiter.check_rate_limit(req)
        headers = self.limiter.get_headers(result)
        reset_ts = int(headers["X-RateLimit-Reset"])
        now_ts = int(datetime.now(timezone.utc).timestamp())
        # Reset should be within a 2-minute window
        assert abs(reset_ts - now_ts) <= 120


# ---------------------------------------------------------------------------
# Dashboard data
# ---------------------------------------------------------------------------


class TestDashboardData:
    def setup_method(self):
        self.limiter = RateLimiterV2()

    def test_dashboard_returns_expected_keys(self):
        data = self.limiter.get_quota_dashboard("org_test")
        assert "org_id" in data
        assert "tracked_keys" in data
        assert "top_consumers" in data
        assert "endpoint_tiers" in data
        assert "per_key_overrides" in data

    def test_dashboard_org_id_matches(self):
        data = self.limiter.get_quota_dashboard("my_org")
        assert data["org_id"] == "my_org"

    def test_dashboard_top_consumers_sorted(self):
        req = _make_request("/api/v1/findings", api_key_id="heavy_user")
        for _ in range(5):
            self.limiter.record_request(req)
        req2 = _make_request("/api/v1/findings", api_key_id="light_user")
        self.limiter.record_request(req2)

        data = self.limiter.get_quota_dashboard("org_x")
        consumers = data["top_consumers"]
        if len(consumers) >= 2:
            assert consumers[0]["requests_last_60s"] >= consumers[1]["requests_last_60s"]

    def test_dashboard_tracked_keys_increments(self):
        before = self.limiter.get_quota_dashboard("org_y")["tracked_keys"]
        req = _make_request("/api/v1/findings", api_key_id="brand_new_key")
        self.limiter.record_request(req)
        after = self.limiter.get_quota_dashboard("org_y")["tracked_keys"]
        assert after == before + 1

    def test_dashboard_per_key_overrides_shown(self):
        self.limiter.configure_key_limit("vip_key", 500)
        data = self.limiter.get_quota_dashboard("org_z")
        assert "vip_key" in data["per_key_overrides"]
        assert data["per_key_overrides"]["vip_key"] == 500


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


def test_get_rate_limiter_singleton():
    limiter_a = get_rate_limiter()
    limiter_b = get_rate_limiter()
    assert limiter_a is limiter_b


# ---------------------------------------------------------------------------
# RateLimitMiddlewareV2
# ---------------------------------------------------------------------------


class TestRateLimitMiddlewareV2:
    def setup_method(self):
        self.limiter = RateLimiterV2()
        mock_app = MagicMock()
        self.middleware = RateLimitMiddlewareV2(mock_app, limiter=self.limiter)

    @pytest.mark.asyncio
    async def test_dispatch_allowed_calls_next(self):
        req = _make_request("/api/v1/findings", api_key_id="mw_key")
        mock_response = MagicMock()
        mock_response.headers = {}
        call_next = AsyncMock(return_value=mock_response)
        response = await self.middleware.dispatch(req, call_next)
        call_next.assert_awaited_once_with(req)
        assert response is mock_response

    @pytest.mark.asyncio
    async def test_dispatch_sets_rate_limit_headers_on_allowed(self):
        req = _make_request("/api/v1/findings", api_key_id="mw_hdr_key")
        mock_response = MagicMock()
        mock_response.headers = {}
        call_next = AsyncMock(return_value=mock_response)
        await self.middleware.dispatch(req, call_next)
        assert "X-RateLimit-Limit" in mock_response.headers

    @pytest.mark.asyncio
    async def test_dispatch_returns_429_when_blocked(self):
        req = _make_request("/api/v1/cicd/scan", api_key_id="mw_block_key")
        scan_limit = _TIER_LIMITS[RateLimitTier.SCAN]
        for _ in range(scan_limit):
            self.limiter.record_request(req)

        call_next = AsyncMock()
        response = await self.middleware.dispatch(req, call_next)
        assert response.status_code == 429
        call_next.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_dispatch_records_request_on_success(self):
        req = _make_request("/api/v1/findings", api_key_id="mw_record_key")
        mock_response = MagicMock()
        mock_response.headers = {}
        call_next = AsyncMock(return_value=mock_response)
        await self.middleware.dispatch(req, call_next)

        count = self.limiter._counter.get_count("mw_record_key", 60)
        assert count == 1
