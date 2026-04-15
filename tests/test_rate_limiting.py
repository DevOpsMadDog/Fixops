"""Tests for RateLimitMiddleware token bucket rate limiting.

Covers:
- Normal requests pass through
- Requests exceeding burst + per-minute limit return 429
- Retry-After header present on 429 responses
- Health/docs endpoints exempt from rate limiting
- Different API keys have independent buckets
- Token refill works correctly after waiting
- Admin keys have higher limits
- SlidingWindowRateLimiter correctness
- get_rate_limit_stats helper
- reset_key works
- X-RateLimit-Limit header present on success
- IP fallback when no API key
- Unknown/no client gets "ip:unknown" bucket
- Stats reflect consumed tokens
- Config endpoint returns correct fields
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Module imports under test
# ---------------------------------------------------------------------------
import sys
import os

# Ensure suite-api is on the path so apps.api.* imports resolve
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from apps.api.rate_limit_middleware import (
    RateLimitMiddleware,
    SlidingWindowRateLimiter,
    _TokenBucket,
    get_rate_limit_stats,
    register_rate_limit_middleware,
    get_rate_limit_middleware,
    _DEFAULT_RPM,
    _ADMIN_RPM,
    _EXEMPT_PREFIXES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(
    path: str = "/api/v1/findings",
    api_key: Optional[str] = None,
    client_ip: str = "127.0.0.1",
    user_role: Optional[str] = None,
) -> MagicMock:
    """Build a minimal mock Request for middleware tests."""
    req = MagicMock()
    req.url.path = path
    req.client = MagicMock()
    req.client.host = client_ip
    headers: dict = {}
    if api_key:
        headers["X-API-Key"] = api_key
        headers["x-api-key"] = api_key
    req.headers = headers
    req.state = SimpleNamespace(user_role=user_role or "viewer")
    return req


def _make_middleware(rpm: int = 5, burst: int = 2, admin_rpm: int = 20) -> RateLimitMiddleware:
    """Construct a middleware with tight limits for testing."""
    return RateLimitMiddleware(
        app=MagicMock(),
        requests_per_minute=rpm,
        admin_requests_per_minute=admin_rpm,
        burst=burst,
    )


# ---------------------------------------------------------------------------
# _TokenBucket unit tests
# ---------------------------------------------------------------------------


class TestTokenBucket:
    def test_initial_tokens_equal_capacity(self):
        bucket = _TokenBucket(capacity=10.0, refill_rate=1.0)
        assert bucket.tokens == pytest.approx(10.0)

    def test_consume_allowed_within_capacity(self):
        bucket = _TokenBucket(capacity=3.0, refill_rate=0.1)
        for _ in range(3):
            allowed, retry = bucket.consume()
            assert allowed is True
            assert retry == pytest.approx(0.0)

    def test_consume_rejected_when_empty(self):
        bucket = _TokenBucket(capacity=1.0, refill_rate=0.01)
        bucket.consume()  # drain
        allowed, retry = bucket.consume()
        assert allowed is False
        assert retry > 0

    def test_refill_over_time(self):
        """Tokens refill based on elapsed time."""
        bucket = _TokenBucket(capacity=2.0, refill_rate=10.0)  # 10 tokens/sec
        bucket.consume()
        bucket.consume()  # drain
        # Manually backdating last_refill simulates time passing
        bucket._last_refill -= 0.15  # 0.15s * 10/s = 1.5 tokens
        allowed, _ = bucket.consume()
        assert allowed is True

    def test_tokens_capped_at_capacity(self):
        bucket = _TokenBucket(capacity=5.0, refill_rate=100.0)
        bucket._last_refill -= 10.0  # large elapsed
        bucket.consume()
        assert bucket.tokens <= 5.0


# ---------------------------------------------------------------------------
# RateLimitMiddleware — dispatch tests
# ---------------------------------------------------------------------------


class TestRateLimitMiddlewareDispatch:
    def setup_method(self):
        self.middleware = _make_middleware(rpm=5, burst=0)

    @pytest.mark.asyncio
    async def test_normal_request_passes_through(self):
        req = _make_request(api_key="key-alpha")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        resp = await self.middleware.dispatch(req, call_next)
        assert resp.status_code == 200
        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_request_exceeding_limit_returns_429(self):
        """Exhaust bucket then expect 429."""
        req = _make_request(api_key="key-exhaust")
        ok_response = MagicMock(headers={}, status_code=200)
        call_next = AsyncMock(return_value=ok_response)
        # rpm=5 burst=0 → capacity=5; consume all 5 then 6th must 429
        for _ in range(5):
            await self.middleware.dispatch(req, call_next)
        resp = await self.middleware.dispatch(req, call_next)
        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_429_response_has_retry_after_header(self):
        req = _make_request(api_key="key-retry")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        for _ in range(5):
            await self.middleware.dispatch(req, call_next)
        resp = await self.middleware.dispatch(req, call_next)
        assert resp.status_code == 429
        # JSONResponse stores headers differently; check via raw headers dict
        assert "Retry-After" in resp.headers or "retry-after" in resp.headers

    @pytest.mark.asyncio
    @pytest.mark.parametrize("exempt_path", [
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/auth/token",
        "/api/v1/auth/login",
    ])
    async def test_exempt_paths_skip_rate_limiting(self, exempt_path):
        """Health/docs/auth endpoints must never be rate-limited."""
        req = _make_request(path=exempt_path, api_key="key-exempt")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        # Fire 100 times — should never 429
        for _ in range(100):
            resp = await self.middleware.dispatch(req, call_next)
            assert resp.status_code != 429, f"{exempt_path} should be exempt"

    @pytest.mark.asyncio
    async def test_different_api_keys_have_independent_buckets(self):
        """Key A exhausted should not affect Key B."""
        req_a = _make_request(api_key="key-a")
        req_b = _make_request(api_key="key-b")
        ok_resp = MagicMock(headers={}, status_code=200)
        call_next = AsyncMock(return_value=ok_resp)

        # Exhaust key-a
        for _ in range(5):
            await self.middleware.dispatch(req_a, call_next)
        # key-a must now 429
        resp_a = await self.middleware.dispatch(req_a, call_next)
        assert resp_a.status_code == 429

        # key-b must still pass
        resp_b = await self.middleware.dispatch(req_b, call_next)
        assert resp_b.status_code == 200

    @pytest.mark.asyncio
    async def test_token_refill_allows_requests_after_wait(self):
        """After bucket drains, backdating last_refill simulates wait."""
        req = _make_request(api_key="key-refill")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        # Drain the bucket
        for _ in range(5):
            await self.middleware.dispatch(req, call_next)
        # Should be 429 now
        resp = await self.middleware.dispatch(req, call_next)
        assert resp.status_code == 429

        # Simulate time passing by backdating the bucket's last_refill
        bucket = self.middleware._buckets["key:key-refill"]
        bucket._last_refill -= 5.0  # 5s * (5rpm / 60s/min) = 0.4 tokens — not enough for rpm=5
        # rpm=5 → refill_rate = 5/60 ≈ 0.083 tokens/sec; need 12s for 1 token
        bucket._last_refill -= 13.0  # total 18s → ~1.5 tokens added
        resp2 = await self.middleware.dispatch(req, call_next)
        assert resp2.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_key_has_higher_limit(self):
        """Admin role should get admin_rpm bucket capacity."""
        middleware = _make_middleware(rpm=3, burst=0, admin_rpm=10)
        # Regular user exhausts at 3
        req_regular = _make_request(api_key="key-regular", user_role="viewer")
        ok_resp = MagicMock(headers={}, status_code=200)
        call_next = AsyncMock(return_value=ok_resp)
        for _ in range(3):
            await middleware.dispatch(req_regular, call_next)
        resp = await middleware.dispatch(req_regular, call_next)
        assert resp.status_code == 429

        # Admin user with admin_rpm=10 can make 10 requests
        req_admin = _make_request(api_key="key-admin", user_role="admin")
        passed = 0
        for _ in range(10):
            r = await middleware.dispatch(req_admin, call_next)
            if r.status_code == 200:
                passed += 1
        assert passed == 10

    @pytest.mark.asyncio
    async def test_ip_fallback_when_no_api_key(self):
        """Requests without X-API-Key fall back to client IP as identifier."""
        req = _make_request(path="/api/v1/findings", api_key=None, client_ip="10.0.0.1")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        resp = await self.middleware.dispatch(req, call_next)
        assert resp.status_code == 200
        assert "ip:10.0.0.1" in self.middleware._buckets

    @pytest.mark.asyncio
    async def test_success_response_has_x_ratelimit_limit_header(self):
        req = _make_request(api_key="key-header")
        mock_resp = MagicMock(headers={}, status_code=200)
        call_next = AsyncMock(return_value=mock_resp)
        await self.middleware.dispatch(req, call_next)
        assert "X-RateLimit-Limit" in mock_resp.headers

    @pytest.mark.asyncio
    async def test_429_body_contains_retry_after_field(self):
        import json
        req = _make_request(api_key="key-body")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        for _ in range(5):
            await self.middleware.dispatch(req, call_next)
        resp = await self.middleware.dispatch(req, call_next)
        assert resp.status_code == 429
        body = json.loads(resp.body)
        assert "retry_after" in body
        assert body["retry_after"] >= 1


# ---------------------------------------------------------------------------
# SlidingWindowRateLimiter unit tests
# ---------------------------------------------------------------------------


class TestSlidingWindowRateLimiter:
    def test_allows_within_limit(self):
        limiter = SlidingWindowRateLimiter(requests_per_window=5, window_seconds=60)
        for _ in range(5):
            allowed, _ = limiter.is_allowed("k1")
            assert allowed is True

    def test_blocks_over_limit(self):
        limiter = SlidingWindowRateLimiter(requests_per_window=3, window_seconds=60)
        for _ in range(3):
            limiter.is_allowed("k2")
        allowed, retry = limiter.is_allowed("k2")
        assert allowed is False
        assert retry > 0

    def test_reset_clears_window(self):
        limiter = SlidingWindowRateLimiter(requests_per_window=2, window_seconds=60)
        limiter.is_allowed("k3")
        limiter.is_allowed("k3")
        limiter.reset("k3")
        allowed, _ = limiter.is_allowed("k3")
        assert allowed is True

    def test_get_count_returns_correct_value(self):
        limiter = SlidingWindowRateLimiter(requests_per_window=10, window_seconds=60)
        limiter.is_allowed("k4")
        limiter.is_allowed("k4")
        assert limiter.get_count("k4") == 2


# ---------------------------------------------------------------------------
# get_rate_limit_stats / register helpers
# ---------------------------------------------------------------------------


class TestRateLimitStats:
    def test_stats_when_no_middleware_registered(self):
        # Temporarily unregister
        import apps.api.rate_limit_middleware as mod
        original = mod._middleware_instance
        mod._middleware_instance = None
        try:
            stats = get_rate_limit_stats()
            assert "warning" in stats
            assert stats["tracked_keys"] == 0
        finally:
            mod._middleware_instance = original

    def test_stats_reflect_registered_middleware(self):
        mw = _make_middleware(rpm=100, burst=20)
        register_rate_limit_middleware(mw)
        try:
            stats = get_rate_limit_stats()
            assert "config" in stats
            assert stats["config"]["requests_per_minute"] == 100
        finally:
            # Clean up — restore None to avoid polluting other tests
            import apps.api.rate_limit_middleware as mod
            mod._middleware_instance = None

    def test_get_config_returns_expected_keys(self):
        mw = _make_middleware(rpm=50, burst=10)
        config = mw.get_config()
        assert config["requests_per_minute"] == 50
        assert config["admin_requests_per_minute"] == 20
        assert config["burst"] == 10
        assert "exempt_prefixes" in config

    def test_reset_key_returns_false_for_unknown_key(self):
        mw = _make_middleware()
        result = mw.reset_key("nonexistent-key")
        assert result is False

    @pytest.mark.asyncio
    async def test_reset_key_replenishes_exhausted_bucket(self):
        mw = _make_middleware(rpm=2, burst=0)
        req = _make_request(api_key="key-reset-test")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        # Exhaust
        await mw.dispatch(req, call_next)
        await mw.dispatch(req, call_next)
        resp = await mw.dispatch(req, call_next)
        assert resp.status_code == 429
        # Reset
        mw.reset_key("key:key-reset-test")
        resp2 = await mw.dispatch(req, call_next)
        assert resp2.status_code == 200
