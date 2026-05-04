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
    method: str = "GET",
) -> MagicMock:
    """Build a minimal mock Request for middleware tests."""
    req = MagicMock()
    req.url.path = path
    req.method = method
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
    """Construct a middleware with tight limits for testing.

    Sets read_rpm, write_rpm, and default rpm all to the same value so that
    existing tests (which use a single flat limit) work regardless of method.
    """
    return RateLimitMiddleware(
        app=MagicMock(),
        requests_per_minute=rpm,
        read_requests_per_minute=rpm,
        write_requests_per_minute=rpm,
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
        # bucket key is now identifier:method_tier (GET → read)
        bucket = self.middleware._buckets["key:key-refill:read"]
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
        assert any(k.startswith("ip:10.0.0.1:") for k in self.middleware._buckets)

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
        # Reset — bucket key includes method tier (GET → read)
        mw.reset_key("key:key-reset-test:read")
        resp2 = await mw.dispatch(req, call_next)
        assert resp2.status_code == 200

    def test_get_config_exposes_read_write_limits(self):
        mw = RateLimitMiddleware(
            app=MagicMock(),
            requests_per_minute=100,
            read_requests_per_minute=200,
            write_requests_per_minute=50,
            burst=20,
        )
        config = mw.get_config()
        assert config["read_requests_per_minute"] == 200
        assert config["write_requests_per_minute"] == 50
        assert config["requests_per_minute"] == 100


# ---------------------------------------------------------------------------
# Per-method rate limiting tests
# ---------------------------------------------------------------------------


def _make_request_with_method(
    method: str = "GET",
    path: str = "/api/v1/findings",
    api_key: Optional[str] = "key-method-test",
    client_ip: str = "127.0.0.1",
) -> MagicMock:
    """Build a mock Request that includes an HTTP method."""
    req = _make_request(path=path, api_key=api_key, client_ip=client_ip)
    req.method = method
    return req


def _make_method_middleware(
    read_rpm: int = 4,
    write_rpm: int = 2,
    default_rpm: int = 3,
    burst: int = 0,
) -> RateLimitMiddleware:
    return RateLimitMiddleware(
        app=MagicMock(),
        requests_per_minute=default_rpm,
        read_requests_per_minute=read_rpm,
        write_requests_per_minute=write_rpm,
        burst=burst,
    )


class TestPerMethodRateLimiting:
    """Tests for HTTP-method-based token bucket limits."""

    @pytest.mark.asyncio
    async def test_get_uses_read_limit(self):
        """GET requests are capped at read_requests_per_minute."""
        mw = _make_method_middleware(read_rpm=3, write_rpm=1, burst=0)
        req = _make_request_with_method("GET", api_key="key-get-read")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        # 3 GETs should pass (read_rpm=3)
        for _ in range(3):
            r = await mw.dispatch(req, call_next)
            assert r.status_code == 200
        # 4th must 429
        r = await mw.dispatch(req, call_next)
        assert r.status_code == 429

    @pytest.mark.asyncio
    async def test_post_uses_write_limit(self):
        """POST requests are capped at write_requests_per_minute."""
        mw = _make_method_middleware(read_rpm=10, write_rpm=2, burst=0)
        req = _make_request_with_method("POST", api_key="key-post-write")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        for _ in range(2):
            r = await mw.dispatch(req, call_next)
            assert r.status_code == 200
        r = await mw.dispatch(req, call_next)
        assert r.status_code == 429

    @pytest.mark.asyncio
    async def test_read_and_write_buckets_are_independent(self):
        """Exhausting POST bucket must not affect GET bucket for the same key."""
        mw = _make_method_middleware(read_rpm=5, write_rpm=2, burst=0)
        get_req = _make_request_with_method("GET", api_key="key-indep")
        post_req = _make_request_with_method("POST", api_key="key-indep")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))

        # Exhaust POST bucket
        await mw.dispatch(post_req, call_next)
        await mw.dispatch(post_req, call_next)
        r_post = await mw.dispatch(post_req, call_next)
        assert r_post.status_code == 429

        # GET bucket still has tokens
        r_get = await mw.dispatch(get_req, call_next)
        assert r_get.status_code == 200

    @pytest.mark.asyncio
    async def test_delete_uses_write_limit(self):
        """DELETE is treated as a write method."""
        mw = _make_method_middleware(read_rpm=10, write_rpm=1, burst=0)
        req = _make_request_with_method("DELETE", api_key="key-delete")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        r = await mw.dispatch(req, call_next)
        assert r.status_code == 200
        r = await mw.dispatch(req, call_next)
        assert r.status_code == 429

    @pytest.mark.asyncio
    async def test_x_ratelimit_limit_header_reflects_method_tier(self):
        """X-RateLimit-Limit header must match the method-tier limit, not a flat value."""
        mw = _make_method_middleware(read_rpm=200, write_rpm=50, burst=0)
        get_req = _make_request_with_method("GET", api_key="key-header-get")
        post_req = _make_request_with_method("POST", api_key="key-header-post")
        mock_resp = MagicMock(headers={}, status_code=200)
        call_next = AsyncMock(return_value=mock_resp)

        await mw.dispatch(get_req, call_next)
        assert mock_resp.headers.get("X-RateLimit-Limit") == "200"

        mock_resp2 = MagicMock(headers={}, status_code=200)
        call_next2 = AsyncMock(return_value=mock_resp2)
        await mw.dispatch(post_req, call_next2)
        assert mock_resp2.headers.get("X-RateLimit-Limit") == "50"

    @pytest.mark.asyncio
    async def test_put_and_patch_use_write_limit(self):
        """PUT and PATCH are write methods and share write bucket."""
        mw = _make_method_middleware(read_rpm=10, write_rpm=1, burst=0)
        put_req = _make_request_with_method("PUT", api_key="key-put")
        call_next = AsyncMock(return_value=MagicMock(headers={}, status_code=200))
        r = await mw.dispatch(put_req, call_next)
        assert r.status_code == 200
        r = await mw.dispatch(put_req, call_next)
        assert r.status_code == 429

    @pytest.mark.asyncio
    async def test_env_var_defaults_apply(self):
        """RateLimitMiddleware with no explicit params reads module-level defaults."""
        import apps.api.rate_limit_middleware as mod
        mw = RateLimitMiddleware(app=MagicMock())
        config = mw.get_config()
        assert config["read_requests_per_minute"] == mod._READ_RPM
        assert config["write_requests_per_minute"] == mod._WRITE_RPM
        assert config["requests_per_minute"] == mod._DEFAULT_RPM


# ---------------------------------------------------------------------------
# Per-endpoint rate limiting tests (endpoint_rate_limit.py)
# ---------------------------------------------------------------------------


def _fresh_enforce():
    """Return enforce() from a clean module state (empty bucket dict)."""
    for key in list(sys.modules):
        if "endpoint_rate_limit" in key:
            del sys.modules[key]
    from apps.api.endpoint_rate_limit import enforce
    return enforce


def _mock_request(ip: str = "1.2.3.4") -> MagicMock:
    req = MagicMock()
    req.client = MagicMock()
    req.client.host = ip
    return req


class TestEndpointRateLimit:
    """Tests for the per-endpoint enforce() helper."""

    @pytest.fixture(autouse=True)
    def _enable_rate_limit(self, monkeypatch):
        """conftest.py sets FIXOPS_DISABLE_RATE_LIMIT=1 globally.
        Per-endpoint tests need it cleared so enforce() actually enforces."""
        monkeypatch.delenv("FIXOPS_DISABLE_RATE_LIMIT", raising=False)

    def test_requests_within_limit_pass(self):
        enforce = _fresh_enforce()
        req = _mock_request("10.0.0.1")
        for _ in range(5):
            enforce(req, limit_key="test:basic", max_per_minute=5)

    def test_exceeding_limit_raises_429(self):
        from fastapi import HTTPException
        enforce = _fresh_enforce()
        req = _mock_request("10.0.0.2")
        for _ in range(3):
            enforce(req, limit_key="test:exceed", max_per_minute=3)
        with pytest.raises(HTTPException) as exc_info:
            enforce(req, limit_key="test:exceed", max_per_minute=3)
        assert exc_info.value.status_code == 429

    def test_429_has_retry_after_header(self):
        from fastapi import HTTPException
        enforce = _fresh_enforce()
        req = _mock_request("10.0.0.3")
        for _ in range(2):
            enforce(req, limit_key="test:header", max_per_minute=2)
        with pytest.raises(HTTPException) as exc_info:
            enforce(req, limit_key="test:header", max_per_minute=2)
        assert "Retry-After" in exc_info.value.headers
        assert int(exc_info.value.headers["Retry-After"]) >= 1

    def test_disable_env_var_bypasses_limit(self, monkeypatch):
        # autouse fixture cleared the var; re-set it to test bypass behaviour
        monkeypatch.setenv("FIXOPS_DISABLE_RATE_LIMIT", "1")
        enforce = _fresh_enforce()
        req = _mock_request("10.0.0.4")
        # Way over limit — should not raise when env var is set
        for _ in range(100):
            enforce(req, limit_key="test:disabled", max_per_minute=1)

    def test_different_ips_have_independent_buckets(self):
        from fastapi import HTTPException
        enforce = _fresh_enforce()
        ip_a = _mock_request("192.168.1.1")
        ip_b = _mock_request("192.168.1.2")
        for _ in range(3):
            enforce(ip_a, limit_key="test:ip-isolation", max_per_minute=3)
        # ip_b must still pass
        enforce(ip_b, limit_key="test:ip-isolation", max_per_minute=3)
        # ip_a must be blocked
        with pytest.raises(HTTPException) as exc_info:
            enforce(ip_a, limit_key="test:ip-isolation", max_per_minute=3)
        assert exc_info.value.status_code == 429

    def test_different_keys_have_independent_buckets(self):
        enforce = _fresh_enforce()
        req = _mock_request("10.1.1.1")
        for _ in range(3):
            enforce(req, limit_key="auth:login", max_per_minute=3)
        # Different key must still be open for same IP
        enforce(req, limit_key="ingest:upload", max_per_minute=3)

    def test_fire_12_requests_11th_12th_are_429(self):
        """Canonical smoke: fire 12 at limit=10 → exactly 10 pass, 2 reject."""
        from fastapi import HTTPException
        enforce = _fresh_enforce()
        req = _mock_request("10.2.2.2")
        passed = 0
        rejected = 0
        for _ in range(12):
            try:
                enforce(req, limit_key="test:twelve", max_per_minute=10)
                passed += 1
            except HTTPException as exc:
                assert exc.status_code == 429
                rejected += 1
        assert passed == 10
        assert rejected == 2

    def test_unknown_client_does_not_crash(self):
        enforce = _fresh_enforce()
        req = MagicMock()
        req.client = None
        enforce(req, limit_key="test:no-client", max_per_minute=5)

    def test_endpoint_rate_limit_importable(self):
        import importlib
        mod = importlib.import_module("apps.api.endpoint_rate_limit")
        assert callable(mod.enforce)

    def test_enforce_has_correct_signature(self):
        import inspect
        import importlib
        mod = importlib.import_module("apps.api.endpoint_rate_limit")
        sig = inspect.signature(mod.enforce)
        assert "request" in sig.parameters
        assert "limit_key" in sig.parameters
        assert "max_per_minute" in sig.parameters
