"""Token bucket rate limiting middleware for ALDECI API."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exempt path prefixes — never rate-limited
# ---------------------------------------------------------------------------
_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/auth/",
)

# ---------------------------------------------------------------------------
# Requests-per-minute limits by key tier
# ---------------------------------------------------------------------------
_ADMIN_RPM = 1000
_DEFAULT_RPM = 100


# ---------------------------------------------------------------------------
# Token bucket implementation
# ---------------------------------------------------------------------------


class _TokenBucket:
    """Thread-safe token bucket for a single key."""

    __slots__ = ("_tokens", "_last_refill", "_capacity", "_refill_rate", "_lock")

    def __init__(self, capacity: float, refill_rate: float) -> None:
        # capacity   — max tokens (== burst ceiling)
        # refill_rate — tokens added per second
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._tokens: float = capacity
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()

    def consume(self) -> tuple[bool, float]:
        """
        Attempt to consume one token.

        Returns:
            (allowed, retry_after_seconds) — retry_after is 0.0 when allowed.
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self._capacity, self._tokens + elapsed * self._refill_rate
            )
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True, 0.0

            # Time until the bucket has one token
            needed = 1.0 - self._tokens
            retry_after = needed / self._refill_rate
            return False, retry_after

    @property
    def tokens(self) -> float:
        with self._lock:
            return self._tokens

    @property
    def capacity(self) -> float:
        return self._capacity


# ---------------------------------------------------------------------------
# RateLimitMiddleware
# ---------------------------------------------------------------------------


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-API-key token bucket rate limiter.

    Default: 100 req/min for regular keys, 1000 req/min for admin keys.
    Burst: ``burst`` extra tokens above the per-minute rate.
    Exempt: /health, /docs, /openapi.json, /api/v1/auth/
    """

    def __init__(
        self,
        app: Any,
        requests_per_minute: int = _DEFAULT_RPM,
        admin_requests_per_minute: int = _ADMIN_RPM,
        burst: int = 20,
    ) -> None:
        super().__init__(app)
        self._rpm = requests_per_minute
        self._admin_rpm = admin_requests_per_minute
        self._burst = burst
        # identifier -> _TokenBucket
        self._buckets: Dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_identifier(self, request: Request) -> str:
        """Extract rate limit identifier: X-API-Key header, then client IP."""
        api_key = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
        if api_key:
            return f"key:{api_key}"
        if request.client:
            return f"ip:{request.client.host}"
        return "ip:unknown"

    def _is_admin_key(self, request: Request) -> bool:
        """Detect admin role set by auth middleware on request.state."""
        role = getattr(getattr(request, "state", None), "user_role", None)
        return role == "admin"

    def _get_bucket(self, identifier: str, is_admin: bool) -> _TokenBucket:
        with self._lock:
            if identifier not in self._buckets:
                rpm = self._admin_rpm if is_admin else self._rpm
                capacity = float(rpm + self._burst)
                refill_rate = rpm / 60.0
                self._buckets[identifier] = _TokenBucket(capacity, refill_rate)
            return self._buckets[identifier]

    @staticmethod
    def _is_exempt(path: str) -> bool:
        return any(path.startswith(p) for p in _EXEMPT_PREFIXES)

    # ------------------------------------------------------------------
    # Middleware dispatch
    # ------------------------------------------------------------------

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if self._is_exempt(request.url.path):
            return await call_next(request)

        identifier = self._get_identifier(request)
        is_admin = self._is_admin_key(request)
        bucket = self._get_bucket(identifier, is_admin)
        allowed, retry_after = bucket.consume()

        if not allowed:
            retry_int = max(1, int(retry_after) + 1)
            logger.warning(
                "rate_limit_exceeded path=%s identifier=%s retry_after=%s",
                request.url.path,
                identifier,
                retry_int,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": retry_int,
                },
                headers={"Retry-After": str(retry_int)},
            )

        response = await call_next(request)
        rpm = self._admin_rpm if is_admin else self._rpm
        response.headers["X-RateLimit-Limit"] = str(rpm)
        response.headers["X-RateLimit-Remaining"] = str(int(bucket.tokens))
        return response

    # ------------------------------------------------------------------
    # Stats helpers (used by rate_limit_router endpoints)
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return per-bucket usage snapshot for monitoring."""
        with self._lock:
            snapshot = {
                identifier: {
                    "tokens_remaining": round(bucket.tokens, 2),
                    "capacity": bucket.capacity,
                }
                for identifier, bucket in self._buckets.items()
            }
        return {
            "tracked_keys": len(snapshot),
            "buckets": snapshot,
            "config": self.get_config(),
        }

    def get_config(self) -> Dict[str, Any]:
        """Return current rate limit configuration."""
        return {
            "requests_per_minute": self._rpm,
            "admin_requests_per_minute": self._admin_rpm,
            "burst": self._burst,
            "exempt_prefixes": list(_EXEMPT_PREFIXES),
        }

    def reset_key(self, key: str) -> bool:
        """
        Reset the token bucket for *key* (full refill).

        Returns True if the key existed and was reset, False if not found.
        """
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return False
            # Replace with a fresh full bucket
            self._buckets[key] = _TokenBucket(bucket.capacity, bucket._refill_rate)
        logger.info("rate_limit_reset key=%s", key)
        return True


# ---------------------------------------------------------------------------
# Sliding window counter (alternative algorithm — standalone utility)
# ---------------------------------------------------------------------------


class SlidingWindowRateLimiter:
    """
    Sliding window counter for more accurate rate limiting.

    Uses a deque of timestamps per key; counts requests in the last
    ``window_seconds`` without rounding to fixed minute boundaries.
    Thread-safe.
    """

    def __init__(self, requests_per_window: int = 100, window_seconds: int = 60) -> None:
        self._limit = requests_per_window
        self._window = window_seconds
        # key -> list of monotonic timestamps (sorted, oldest first)
        self._windows: Dict[str, list] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> tuple[bool, int]:
        """
        Check (and record) a request for *key*.

        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            if key not in self._windows:
                self._windows[key] = []
            timestamps = self._windows[key]

            # Evict expired entries
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)

            if len(timestamps) < self._limit:
                timestamps.append(now)
                return True, 0

            # Oldest request in window tells us when a slot opens
            oldest = timestamps[0]
            retry_after = int(self._window - (now - oldest)) + 1
            return False, retry_after

    def reset(self, key: str) -> None:
        """Clear all tracked requests for *key*."""
        with self._lock:
            self._windows.pop(key, None)

    def get_count(self, key: str) -> int:
        """Current request count within the window for *key*."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            timestamps = self._windows.get(key, [])
            return sum(1 for t in timestamps if t >= cutoff)


# ---------------------------------------------------------------------------
# Module-level singleton — shared between middleware and router
# ---------------------------------------------------------------------------

_middleware_instance: Optional[RateLimitMiddleware] = None
_instance_lock = threading.Lock()


def get_rate_limit_middleware() -> Optional[RateLimitMiddleware]:
    """Return the registered RateLimitMiddleware instance (set by app startup)."""
    return _middleware_instance


def register_rate_limit_middleware(instance: RateLimitMiddleware) -> None:
    """Register the middleware instance so the router can access its stats."""
    global _middleware_instance
    with _instance_lock:
        _middleware_instance = instance


def get_rate_limit_stats() -> Dict[str, Any]:
    """Return current rate limit stats for monitoring."""
    instance = get_rate_limit_middleware()
    if instance is None:
        return {
            "tracked_keys": 0,
            "buckets": {},
            "config": {
                "requests_per_minute": _DEFAULT_RPM,
                "admin_requests_per_minute": _ADMIN_RPM,
                "burst": 20,
                "exempt_prefixes": list(_EXEMPT_PREFIXES),
            },
            "warning": "RateLimitMiddleware not registered",
        }
    return instance.get_stats()
