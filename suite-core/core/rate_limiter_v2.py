"""
Rate Limiter V2 — per-endpoint sliding window rate limiting with per-key quotas.

Provides:
- RateLimitTier: endpoint tier presets (SCAN, QUERY, WRITE, ADMIN, WEBHOOK, DEFAULT)
- RateLimitConfig: Pydantic config model
- RateLimitResult: result of a rate limit check
- SlidingWindowCounter: thread-safe in-memory sliding window
- RateLimiterV2: main engine with endpoint routing + per-key overrides
- RateLimitMiddlewareV2: Starlette BaseHTTPMiddleware integration

Usage::

    limiter = RateLimiterV2()
    result = limiter.check_rate_limit(request)
    if not result.allowed:
        # return 429
        ...
    headers = limiter.get_headers(result)
"""

from __future__ import annotations

import bisect
import re
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field

_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RateLimitTier(str, Enum):
    """Predefined rate limit tiers mapped to request/minute limits."""

    SCAN = "scan"
    QUERY = "query"
    WRITE = "write"
    ADMIN = "admin"
    WEBHOOK = "webhook"
    DEFAULT = "default"


_TIER_LIMITS: Dict[RateLimitTier, int] = {
    RateLimitTier.SCAN: 10,
    RateLimitTier.QUERY: 100,
    RateLimitTier.WRITE: 30,
    RateLimitTier.ADMIN: 5,
    RateLimitTier.WEBHOOK: 20,
    RateLimitTier.DEFAULT: 60,
}

# Default path-pattern → tier mapping (checked in order, first match wins)
_DEFAULT_ENDPOINT_TIERS: List[Tuple[str, RateLimitTier]] = [
    (r"^/api/v1/cicd/scan$", RateLimitTier.SCAN),
    (r"^/api/v1/findings", RateLimitTier.QUERY),
    (r"^/api/v1/remediation", RateLimitTier.WRITE),
    (r"^/api/v1/auth/keys", RateLimitTier.ADMIN),
    (r"^/api/v1/slack/", RateLimitTier.WEBHOOK),
]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RateLimitConfig(BaseModel):
    """Configuration for a rate limit tier."""

    tier: RateLimitTier
    requests_per_minute: int = Field(..., ge=1)
    burst_allowance: int = Field(0, ge=0)  # extra requests above limit
    window_seconds: int = Field(60, ge=1)

    model_config = {"arbitrary_types_allowed": True}


class RateLimitResult(BaseModel):
    """Result of a rate limit check."""

    allowed: bool
    remaining: int
    limit: int
    reset_at: datetime
    retry_after_seconds: Optional[int] = None

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Sliding window counter
# ---------------------------------------------------------------------------


class SlidingWindowCounter:
    """
    Thread-safe in-memory sliding window counter.

    Each key maps to a sorted list of float timestamps (monotonic seconds).
    All operations are O(log n) via bisect.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key → sorted list of monotonic timestamps
        self._windows: Dict[str, List[float]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_count(self, key: str, window_seconds: int) -> int:
        """Return the number of requests for *key* in the last *window_seconds*."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            timestamps = self._windows.get(key)
            if not timestamps:
                return 0
            # bisect_left gives the index of first timestamp > cutoff
            idx = bisect.bisect_left(timestamps, cutoff)
            return len(timestamps) - idx

    def increment(self, key: str) -> None:
        """Record one request for *key* at the current time."""
        now = time.monotonic()
        with self._lock:
            if key not in self._windows:
                self._windows[key] = []
            bisect.insort(self._windows[key], now)

    def check(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        """
        Evaluate whether a new request for *key* is within *limit* over
        *window_seconds*.

        Does NOT record the request — call increment() separately.
        """
        now_mono = time.monotonic()
        cutoff = now_mono - window_seconds
        with self._lock:
            timestamps = self._windows.get(key, [])
            idx = bisect.bisect_left(timestamps, cutoff)
            count = len(timestamps) - idx

        now_wall = datetime.now(timezone.utc)
        # Reset time: when the oldest request in the window will expire
        with self._lock:
            timestamps = self._windows.get(key, [])
            idx = bisect.bisect_left(timestamps, cutoff)
            in_window = timestamps[idx:]
            if in_window:
                oldest = in_window[0]
                secs_until_reset = max(0.0, window_seconds - (now_mono - oldest))
            else:
                secs_until_reset = 0.0

        reset_at = datetime.fromtimestamp(
            now_wall.timestamp() + secs_until_reset, tz=timezone.utc
        )
        remaining = max(0, limit - count)
        allowed = count < limit

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            limit=limit,
            reset_at=reset_at,
            retry_after_seconds=None if allowed else int(secs_until_reset) + 1,
        )

    def cleanup(self) -> int:
        """
        Remove all timestamps older than the maximum possible window (1 hour).
        Returns the number of entries pruned.
        """
        cutoff = time.monotonic() - 3600
        pruned = 0
        with self._lock:
            for key in list(self._windows.keys()):
                timestamps = self._windows[key]
                idx = bisect.bisect_left(timestamps, cutoff)
                if idx > 0:
                    pruned += idx
                    self._windows[key] = timestamps[idx:]
                if not self._windows[key]:
                    del self._windows[key]
        return pruned


# ---------------------------------------------------------------------------
# Main rate limiter
# ---------------------------------------------------------------------------


class RateLimiterV2:
    """
    Per-endpoint sliding window rate limiter with per-key overrides.

    Thread-safe.  All state is in-memory; restarts clear counters.
    """

    def __init__(self) -> None:
        self._counter = SlidingWindowCounter()
        self._lock = threading.Lock()

        # Compiled (pattern, tier) pairs — checked in order
        self._endpoint_patterns: List[Tuple[re.Pattern[str], RateLimitTier]] = [
            (re.compile(pat), tier)
            for pat, tier in _DEFAULT_ENDPOINT_TIERS
        ]
        # path_pattern_str → tier (for serialisation / admin API)
        self._endpoint_map: Dict[str, RateLimitTier] = {
            pat: tier for pat, tier in _DEFAULT_ENDPOINT_TIERS
        }

        # api_key_id → requests_per_minute override
        self._key_limits: Dict[str, int] = {}

        # Build tier → RateLimitConfig lookup
        self._tier_configs: Dict[RateLimitTier, RateLimitConfig] = {
            tier: RateLimitConfig(
                tier=tier,
                requests_per_minute=rpm,
                burst_allowance=0,
                window_seconds=60,
            )
            for tier, rpm in _TIER_LIMITS.items()
        }

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure_endpoint(self, path_pattern: str, tier: RateLimitTier) -> None:
        """Register (or overwrite) a path regex pattern → tier mapping."""
        compiled = re.compile(path_pattern)
        with self._lock:
            # Remove old entry with same pattern if present
            self._endpoint_patterns = [
                (p, t) for p, t in self._endpoint_patterns if p.pattern != path_pattern
            ]
            # Prepend so newer rules win
            self._endpoint_patterns.insert(0, (compiled, tier))
            self._endpoint_map[path_pattern] = tier

    def configure_key_limit(self, api_key_id: str, requests_per_minute: int) -> None:
        """Set a per-key override (requests/min).  0 or negative removes the override."""
        with self._lock:
            if requests_per_minute > 0:
                self._key_limits[api_key_id] = requests_per_minute
            else:
                self._key_limits.pop(api_key_id, None)

    # ------------------------------------------------------------------
    # Core check
    # ------------------------------------------------------------------

    def _resolve_tier_for_path(self, path: str) -> RateLimitTier:
        with self._lock:
            patterns = list(self._endpoint_patterns)
        for compiled, tier in patterns:
            if compiled.match(path):
                return tier
        return RateLimitTier.DEFAULT

    def _resolve_limit(self, path: str, api_key_id: Optional[str]) -> Tuple[int, int]:
        """Return (effective_limit, window_seconds) for this request."""
        # Per-key override takes priority
        if api_key_id:
            with self._lock:
                key_rpm = self._key_limits.get(api_key_id)
            if key_rpm is not None:
                return key_rpm, 60

        tier = self._resolve_tier_for_path(path)
        cfg = self._tier_configs[tier]
        limit = cfg.requests_per_minute + cfg.burst_allowance
        return limit, cfg.window_seconds

    def check_rate_limit(self, request: Any) -> RateLimitResult:  # noqa: ANN401
        """
        Evaluate *request* against all applicable limits.

        Extracts path from ``request.url.path`` and API key ID from
        ``request.state.api_key_id`` (set by auth middleware, if present).
        Falls back to client IP when no key ID is available.

        Does NOT record the request — call this first, then record on success.
        """
        try:
            path: str = request.url.path
        except AttributeError:
            path = "/"

        api_key_id: Optional[str] = getattr(
            getattr(request, "state", None), "api_key_id", None
        )
        client_ip: str = ""
        try:
            client_ip = request.client.host if request.client else ""
        except AttributeError:
            pass

        bucket_key = api_key_id or client_ip or "anonymous"
        limit, window_seconds = self._resolve_limit(path, api_key_id)

        return self._counter.check(bucket_key, limit, window_seconds)

    def record_request(self, request: Any) -> None:  # noqa: ANN401
        """Record a request in the sliding window (call after check passes)."""
        try:
            pass
        except AttributeError:
            pass

        api_key_id: Optional[str] = getattr(
            getattr(request, "state", None), "api_key_id", None
        )
        client_ip: str = ""
        try:
            client_ip = request.client.host if request.client else ""
        except AttributeError:
            pass

        bucket_key = api_key_id or client_ip or "anonymous"
        self._counter.increment(bucket_key)

    # ------------------------------------------------------------------
    # Headers
    # ------------------------------------------------------------------

    def get_headers(self, result: RateLimitResult) -> Dict[str, str]:
        """Build standard rate limit response headers from a RateLimitResult."""
        headers: Dict[str, str] = {
            "X-RateLimit-Limit": str(result.limit),
            "X-RateLimit-Remaining": str(result.remaining),
            "X-RateLimit-Reset": str(int(result.reset_at.timestamp())),
        }
        if result.retry_after_seconds is not None:
            headers["Retry-After"] = str(result.retry_after_seconds)
        return headers

    # ------------------------------------------------------------------
    # Admin / dashboard
    # ------------------------------------------------------------------

    def get_quota_dashboard(self, org_id: str) -> Dict[str, Any]:
        """
        Return usage dashboard for *org_id*.

        Since counter keys are API key IDs (not org-scoped), this returns a
        snapshot of all tracked keys and their current window counts.
        """
        now_mono = time.monotonic()
        with self._counter._lock:  # noqa: SLF001 — intentional
            snapshot = {
                key: list(ts) for key, ts in self._counter._windows.items()  # noqa: SLF001
            }

        usage: List[Dict[str, Any]] = []
        for key, timestamps in snapshot.items():
            cutoff = now_mono - 60
            count_1m = sum(1 for t in timestamps if t >= cutoff)
            usage.append({"key": key, "requests_last_60s": count_1m})

        usage.sort(key=lambda x: x["requests_last_60s"], reverse=True)

        return {
            "org_id": org_id,
            "tracked_keys": len(snapshot),
            "top_consumers": usage[:10],
            "endpoint_tiers": self.get_endpoint_configs(),
            "per_key_overrides": dict(self._key_limits),
        }

    def get_endpoint_configs(self) -> List[Dict[str, Any]]:
        """Return current endpoint→tier assignments."""
        with self._lock:
            patterns = list(self._endpoint_patterns)
            dict(self._endpoint_map)

        configs: List[Dict[str, Any]] = []
        for compiled, tier in patterns:
            cfg = self._tier_configs[tier]
            configs.append(
                {
                    "pattern": compiled.pattern,
                    "tier": tier.value,
                    "requests_per_minute": cfg.requests_per_minute,
                    "burst_allowance": cfg.burst_allowance,
                    "window_seconds": cfg.window_seconds,
                }
            )
        return configs

    def reset_key(self, api_key_id: str) -> None:
        """Clear all sliding window entries for *api_key_id*."""
        with self._counter._lock:  # noqa: SLF001
            self._counter._windows.pop(api_key_id, None)  # noqa: SLF001
        _logger.info("rate_limiter_v2.key_reset", api_key_id=api_key_id)


# ---------------------------------------------------------------------------
# Starlette middleware
# ---------------------------------------------------------------------------

try:
    import json as _json

    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request as StarletteRequest
    from starlette.responses import JSONResponse, Response

    class RateLimitMiddlewareV2(BaseHTTPMiddleware):
        """
        Starlette middleware that enforces rate limits on every request and
        injects rate limit headers into every response.

        Returns HTTP 429 with Retry-After when limits are exceeded.
        """

        def __init__(self, app: Any, limiter: Optional[RateLimiterV2] = None) -> None:
            super().__init__(app)
            self._limiter = limiter or RateLimiterV2()

        async def dispatch(
            self, request: StarletteRequest, call_next: Any
        ) -> Response:
            result = self._limiter.check_rate_limit(request)
            headers = self._limiter.get_headers(result)

            if not result.allowed:
                _logger.warning(
                    "rate_limit_exceeded",
                    path=request.url.path,
                    api_key_id=getattr(
                        getattr(request, "state", None), "api_key_id", None
                    ),
                    retry_after=result.retry_after_seconds,
                )
                body = _json.dumps(
                    {
                        "detail": "Rate limit exceeded",
                        "retry_after_seconds": result.retry_after_seconds,
                    }
                ).encode()
                return Response(
                    content=body,
                    status_code=429,
                    media_type="application/json",
                    headers=headers,
                )

            self._limiter.record_request(request)
            response = await call_next(request)
            for header_name, header_value in headers.items():
                response.headers[header_name] = header_value
            return response

except ImportError:
    # Starlette not available (e.g. pure unit-test environment)
    class RateLimitMiddlewareV2:  # type: ignore[no-redef]
        """Stub when Starlette is not installed."""

        def __init__(self, app: Any, limiter: Optional[RateLimiterV2] = None) -> None:
            self.app = app
            self._limiter = limiter or RateLimiterV2()


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------

_singleton: Optional[RateLimiterV2] = None
_singleton_lock = threading.Lock()


def get_rate_limiter() -> RateLimiterV2:
    """Return the process-wide singleton RateLimiterV2."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = RateLimiterV2()
    return _singleton
