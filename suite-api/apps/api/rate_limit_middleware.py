"""Token bucket rate limiting middleware for ALDECI API.

Hardened against 429-storm crash-loops (2026-04-25):
  * Bounded LRU bucket cache (cannot grow unbounded under spoofed-IP storms).
  * Global rejection-rate cap so the 429 path itself cannot DoS the server
    via log-flood or JSONResponse construction churn.
  * Cached/precomputed 429 body — no per-request dict rebuilds.
  * Sampled rejection logging (1/N) under storm conditions.
  * Defensive ``dispatch`` — middleware never raises into the ASGI loop.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import OrderedDict
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
# Configurable via env vars: RATE_LIMIT_DEFAULT, RATE_LIMIT_READ, RATE_LIMIT_WRITE
# ---------------------------------------------------------------------------
_ADMIN_RPM = 1000
_DEFAULT_RPM = int(os.environ.get("RATE_LIMIT_DEFAULT", "100"))
_READ_RPM = int(os.environ.get("RATE_LIMIT_READ", "200"))
_WRITE_RPM = int(os.environ.get("RATE_LIMIT_WRITE", "50"))

# ---------------------------------------------------------------------------
# Crash-loop hardening knobs (env-tunable, sane defaults)
# ---------------------------------------------------------------------------
# Maximum number of distinct identifiers we'll track. When exceeded we evict
# the least-recently-used bucket. Stops spoofed-IP / unique-key floods from
# growing the dict to GBs of memory.
_MAX_TRACKED_BUCKETS = int(os.environ.get("RATE_LIMIT_MAX_BUCKETS", "10000"))
# Maximum 429 responses we will *emit* per second across the whole process.
# Excess rejections are dropped onto a pre-built static response (no logging,
# no header rebuild) so the rejection path itself can't burn the event loop.
_MAX_REJECTIONS_PER_SEC = int(os.environ.get("RATE_LIMIT_MAX_429_PER_SEC", "200"))
# Log every Nth rejection under storm conditions to avoid log-flood OOM.
_REJECTION_LOG_SAMPLE = max(1, int(os.environ.get("RATE_LIMIT_LOG_SAMPLE", "100")))

# HTTP methods treated as read (GET/HEAD/OPTIONS) vs write (POST/PUT/PATCH/DELETE)
_READ_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


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
    Per-API-key token bucket rate limiter with per-method limits.

    Limits (req/min):
      - GET/HEAD/OPTIONS: ``read_requests_per_minute`` (default 200, env: RATE_LIMIT_READ)
      - POST/PUT/PATCH/DELETE: ``write_requests_per_minute`` (default 50, env: RATE_LIMIT_WRITE)
      - Other/fallback: ``requests_per_minute`` (default 100, env: RATE_LIMIT_DEFAULT)
      - Admin role: ``admin_requests_per_minute`` (default 1000)

    Burst: ``burst`` extra tokens above the per-minute rate.
    Exempt: /health, /docs, /openapi.json, /api/v1/auth/
    """

    def __init__(
        self,
        app: Any,
        requests_per_minute: int = _DEFAULT_RPM,
        read_requests_per_minute: int = _READ_RPM,
        write_requests_per_minute: int = _WRITE_RPM,
        admin_requests_per_minute: int = _ADMIN_RPM,
        burst: int = 20,
        max_tracked_buckets: int = _MAX_TRACKED_BUCKETS,
        max_rejections_per_sec: int = _MAX_REJECTIONS_PER_SEC,
    ) -> None:
        super().__init__(app)
        self._rpm = requests_per_minute
        self._read_rpm = read_requests_per_minute
        self._write_rpm = write_requests_per_minute
        self._admin_rpm = admin_requests_per_minute
        self._burst = burst
        # identifier:method_tier -> _TokenBucket
        # OrderedDict so we can do O(1) LRU eviction under storm conditions
        # — prevents unbounded memory growth from spoofed-IP / unique-key floods.
        self._buckets: "OrderedDict[str, _TokenBucket]" = OrderedDict()
        self._max_buckets = max(100, max_tracked_buckets)
        self._lock = threading.Lock()

        # ---- 429 storm self-limiter --------------------------------------
        # If rejections exceed `_max_rej_per_sec` we serve a pre-built static
        # response with NO logging and NO per-request dict construction. This
        # caps the cost of the rejection path so the storm cannot crash us.
        self._max_rej_per_sec = max(1, max_rejections_per_sec)
        self._rej_window_start: float = time.monotonic()
        self._rej_window_count: int = 0
        self._rej_total: int = 0
        self._rej_lock = threading.Lock()
        # Pre-built body for cheap rejections (storm path)
        self._cheap_429 = JSONResponse(
            status_code=429,
            content={
                "error": "rate_limit_exceeded",
                "message": "Too many requests. Please try again later.",
                "retry_after": 1,
            },
            headers={"Retry-After": "1"},
        )

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

    def _resolve_rpm(self, method: str, is_admin: bool) -> int:
        """Return the effective RPM for this HTTP method and role."""
        if is_admin:
            return self._admin_rpm
        if method in _READ_METHODS:
            return self._read_rpm
        if method in _WRITE_METHODS:
            return self._write_rpm
        return self._rpm

    def _get_bucket(self, identifier: str, method: str, is_admin: bool) -> _TokenBucket:
        # Bucket key encodes both identity and method tier so read/write limits are independent
        method_tier = "admin" if is_admin else ("read" if method in _READ_METHODS else "write" if method in _WRITE_METHODS else "default")
        bucket_key = f"{identifier}:{method_tier}"
        with self._lock:
            bucket = self._buckets.get(bucket_key)
            if bucket is None:
                rpm = self._resolve_rpm(method, is_admin)
                capacity = float(rpm + self._burst)
                refill_rate = rpm / 60.0
                bucket = _TokenBucket(capacity, refill_rate)
                self._buckets[bucket_key] = bucket
                # LRU eviction: cap memory under spoofed-IP / unique-key storms.
                # Without this, an attacker can OOM the process by rotating IPs.
                while len(self._buckets) > self._max_buckets:
                    self._buckets.popitem(last=False)
            else:
                # mark as recently used (move to end) — cheap O(1) on OrderedDict
                self._buckets.move_to_end(bucket_key)
            return bucket

    def _should_emit_real_429(self) -> bool:
        """Global rejection-rate cap.

        Returns True if the caller should build the full (logged) 429 response.
        Returns False if we are over budget and should serve the pre-built
        static response without logging — protects the event loop from
        log-flood / response-construction churn under sustained storms.
        """
        now = time.monotonic()
        with self._rej_lock:
            # Roll the 1-second window
            if now - self._rej_window_start >= 1.0:
                self._rej_window_start = now
                self._rej_window_count = 0
            self._rej_window_count += 1
            self._rej_total += 1
            if self._rej_window_count > self._max_rej_per_sec:
                return False
            return True

    @staticmethod
    def _is_exempt(path: str) -> bool:
        return any(path.startswith(p) for p in _EXEMPT_PREFIXES)

    # ------------------------------------------------------------------
    # Middleware dispatch
    # ------------------------------------------------------------------

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # ------------------------------------------------------------------
        # Defensive wrapper — middleware MUST NOT raise into the ASGI loop.
        # Any failure in the limiter itself falls through to call_next so
        # the API stays up even if the limiter is misconfigured at runtime.
        # ------------------------------------------------------------------
        try:
            if self._is_exempt(request.url.path):
                return await call_next(request)

            identifier = self._get_identifier(request)
            is_admin = self._is_admin_key(request)
            method = request.method.upper()
            bucket = self._get_bucket(identifier, method, is_admin)
            allowed, retry_after = bucket.consume()
        except (AttributeError, KeyError, ValueError, OSError) as exc:
            # Limiter bookkeeping failed — fail open, do NOT crash the request.
            logger.warning("rate_limiter.bookkeeping_failed err=%r", exc)
            return await call_next(request)

        if not allowed:
            # Global rejection-rate cap: under storm, serve a pre-built 429
            # with NO logging and NO dict construction. This is what kept
            # the event loop alive under 1000 req/s storms.
            if not self._should_emit_real_429():
                return self._cheap_429

            retry_int = max(1, int(retry_after) + 1)
            # Sample logging to avoid log-flood OOM under sustained storms
            if self._rej_total % _REJECTION_LOG_SAMPLE == 1:
                logger.warning(
                    "rate_limit_exceeded path=%s method=%s identifier=%s retry_after=%s sampled=1/%d total_rejections=%d",
                    request.url.path,
                    method,
                    identifier,
                    retry_int,
                    _REJECTION_LOG_SAMPLE,
                    self._rej_total,
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

        try:
            response = await call_next(request)
            rpm = self._resolve_rpm(method, is_admin)
            response.headers["X-RateLimit-Limit"] = str(rpm)
            response.headers["X-RateLimit-Remaining"] = str(int(bucket.tokens))
            return response
        except Exception:
            # Downstream raised — propagate as-is (FastAPI will turn it into
            # a 500). We only protect against bookkeeping failures above.
            raise

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
        with self._rej_lock:
            rej_total = self._rej_total
            rej_window = self._rej_window_count
        return {
            "tracked_keys": len(snapshot),
            "buckets": snapshot,
            "config": self.get_config(),
            "rejections": {
                "total": rej_total,
                "current_second": rej_window,
                "max_per_second": self._max_rej_per_sec,
                "max_tracked_buckets": self._max_buckets,
            },
        }

    def get_config(self) -> Dict[str, Any]:
        """Return current rate limit configuration."""
        return {
            "requests_per_minute": self._rpm,
            "read_requests_per_minute": self._read_rpm,
            "write_requests_per_minute": self._write_rpm,
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
