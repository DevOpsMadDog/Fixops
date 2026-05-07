"""Org-tier daily token-bucket rate limit middleware.

Enforces per-org API call quotas based on billing tier:
    Starter    — 1,000 requests / day
    Pro        — 10,000 requests / day
    Enterprise — unlimited

The daily window is a rolling 24-hour counter anchored to wall-clock UTC
midnight (resets at 00:00 UTC each day).

Returns HTTP 429 with Retry-After (seconds until midnight UTC) when the
daily quota is exhausted.

Exempt paths: /health, /status, /docs, /redoc, /openapi.json, /api/v1/auth/
Disabled by: FIXOPS_DISABLE_TIER_RATE_LIMIT=1 (used in CI)
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Kill-switch: FIXOPS_DISABLE_TIER_RATE_LIMIT=1 disables middleware entirely.
# Set in CI / perf tests to eliminate per-request DB overhead.
# Read live per-dispatch (not cached at import time) so test suites that set
# the env var after import still see the correct value.
# ---------------------------------------------------------------------------

def _is_globally_disabled() -> bool:
    return os.environ.get("FIXOPS_DISABLE_TIER_RATE_LIMIT", "0").strip() == "1"

# ---------------------------------------------------------------------------
# Tier daily limits
# ---------------------------------------------------------------------------

_TIER_DAILY_LIMIT: Dict[str, Optional[int]] = {
    "starter":    1_000,
    "pro":        10_000,
    "enterprise": None,   # unlimited
}
_DEFAULT_TIER_LIMIT = 1_000  # fallback when tier unknown

# ---------------------------------------------------------------------------
# Exempt prefixes — never counted against quota
# ---------------------------------------------------------------------------

_EXEMPT_PREFIXES: Tuple[str, ...] = (
    "/health",
    "/status",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/auth/",
    "/api/v1/billing/",
)


# ---------------------------------------------------------------------------
# Per-org daily counter (in-memory, resets at UTC midnight)
# ---------------------------------------------------------------------------

class _DailyCounter:
    """Thread-safe daily counter for one org."""

    __slots__ = ("_count", "_day", "_lock")

    def __init__(self) -> None:
        self._count: int = 0
        self._day: int = self._today()
        self._lock = threading.Lock()

    @staticmethod
    def _today() -> int:
        """Return today's UTC date as an integer YYYYMMDD."""
        return int(datetime.now(timezone.utc).strftime("%Y%m%d"))

    def increment_and_check(self, limit: Optional[int]) -> Tuple[bool, int]:
        """
        Increment counter; return (allowed, retry_after_seconds).

        retry_after is 0 when allowed, or seconds until next UTC midnight.
        """
        with self._lock:
            today = self._today()
            if today != self._day:
                # New day — reset
                self._count = 0
                self._day = today

            if limit is None:
                # Enterprise — unlimited
                self._count += 1
                return True, 0

            if self._count >= limit:
                retry_after = self._seconds_until_midnight()
                return False, retry_after

            self._count += 1
            return True, 0

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    @staticmethod
    def _seconds_until_midnight() -> int:
        now = datetime.now(timezone.utc)
        next_midnight = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
        # Roll to next day
        from datetime import timedelta
        next_midnight += timedelta(days=1)
        return max(1, int((next_midnight - now).total_seconds()))


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

_TIER_CACHE_TTL_S: float = 60.0  # seconds before re-querying DB for org tier


class OrgTierRateLimitMiddleware(BaseHTTPMiddleware):
    """Daily quota enforcement middleware keyed by org billing tier.

    Reads org_id from request.state.org_id (set by OrgIdMiddleware) then
    calls billing_router.get_org_tier() to resolve the tier.  Falls back to
    'starter' limits on any error so the middleware never crashes the API.

    Tier lookups are cached for _TIER_CACHE_TTL_S seconds (default 60s) to
    avoid a SQLite round-trip on every request.

    Disabled entirely when FIXOPS_DISABLE_TIER_RATE_LIMIT=1 (CI / perf tests).

    Usage in create_app():
        app.add_middleware(OrgTierRateLimitMiddleware)
    """

    def __init__(self, app: Any, max_tracked_orgs: int = 5_000) -> None:
        super().__init__(app)
        self._counters: Dict[str, _DailyCounter] = {}
        self._max_orgs = max(100, max_tracked_orgs)
        self._lock = threading.Lock()
        # Tier cache: org_id -> (tier_str, expiry_monotonic)
        self._tier_cache: Dict[str, Tuple[str, float]] = {}
        self._tier_cache_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_exempt(path: str) -> bool:
        return any(path.startswith(p) for p in _EXEMPT_PREFIXES)

    def _get_counter(self, org_id: str) -> _DailyCounter:
        with self._lock:
            counter = self._counters.get(org_id)
            if counter is None:
                # Evict oldest entry if at capacity (simple FIFO — not LRU,
                # but sufficient for O(5K) orgs and daily resets).
                if len(self._counters) >= self._max_orgs:
                    oldest = next(iter(self._counters))
                    del self._counters[oldest]
                counter = _DailyCounter()
                self._counters[org_id] = counter
            return counter

    @staticmethod
    def _resolve_org_id(request: Request) -> str:
        """Extract org_id from request state (set by OrgIdMiddleware) or header."""
        org_id = getattr(getattr(request, "state", None), "org_id", None)
        if not org_id:
            org_id = request.headers.get("X-Org-ID") or request.query_params.get("org_id")
        return org_id or "default"

    def _resolve_tier(self, org_id: str) -> str:
        """Look up billing tier for org with 60s in-memory TTL cache; never raises."""
        now = time.monotonic()
        with self._tier_cache_lock:
            cached = self._tier_cache.get(org_id)
            if cached is not None and now < cached[1]:
                return cached[0]
        # Cache miss or expired — do the DB lookup outside the lock.
        try:
            from apps.api.billing_router import get_org_tier
            tier = get_org_tier(org_id)
        except Exception:
            tier = "starter"
        with self._tier_cache_lock:
            self._tier_cache[org_id] = (tier, now + _TIER_CACHE_TTL_S)
        return tier

    @staticmethod
    def _resolve_limit(tier: str) -> Optional[int]:
        return _TIER_DAILY_LIMIT.get(tier.lower(), _DEFAULT_TIER_LIMIT)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if _is_globally_disabled():
            return await call_next(request)

        try:
            if self._is_exempt(request.url.path):
                return await call_next(request)

            org_id = self._resolve_org_id(request)
            tier   = self._resolve_tier(org_id)
            limit  = self._resolve_limit(tier)
            counter = self._get_counter(org_id)
            allowed, retry_after = counter.increment_and_check(limit)
        except Exception as exc:
            # Middleware bookkeeping error — fail open, never crash the API.
            logger.warning("org_tier_rate_limit.bookkeeping_error err=%r", exc)
            return await call_next(request)

        if not allowed:
            limit_str = str(limit) if limit is not None else "unlimited"
            logger.warning(
                "org_tier_rate_limit.exceeded org=%s tier=%s daily_limit=%s retry_after=%ds",
                org_id, tier, limit_str, retry_after,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "daily_quota_exceeded",
                    "message": (
                        f"Daily API quota exhausted for tier '{tier}'. "
                        f"Limit: {limit_str} requests/day."
                    ),
                    "tier": tier,
                    "daily_limit": limit,
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        response = await call_next(request)
        # Inform callers of their quota position
        if limit is not None:
            remaining = max(0, limit - counter.count)
            response.headers["X-RateLimit-Daily-Limit"] = str(limit)
            response.headers["X-RateLimit-Daily-Remaining"] = str(remaining)
        else:
            response.headers["X-RateLimit-Daily-Limit"] = "unlimited"
        response.headers["X-RateLimit-Tier"] = tier
        return response

    # ------------------------------------------------------------------
    # Stats (for monitoring endpoints)
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "tracked_orgs": len(self._counters),
                "orgs": {
                    org_id: {
                        "count_today": counter.count,
                        "tier": self._resolve_tier(org_id),
                    }
                    for org_id, counter in self._counters.items()
                },
            }
