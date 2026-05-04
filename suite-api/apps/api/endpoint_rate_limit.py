"""Per-endpoint rate limiting for high-risk public-facing endpoints.

Complements the global RateLimitMiddleware (which covers all routes at
write=50 req/min) with tighter per-endpoint limits on:
  - /api/v1/auth/dev-token      10/min per IP  (JWT minting — brute-force risk)
  - /api/v1/auth login          10/min per IP  (credential endpoint)
  - webhook receivers           60/min per IP  (jira/sn/gitlab/az/gh)
  - scanner-ingest/upload       30/min per IP  (heavy CPU/IO — DoS risk)
  - scanner-ingest/webhook      30/min per IP  (same concern)

Usage in a handler::

    from apps.api.endpoint_rate_limit import enforce

    async def my_handler(request: Request, ...):
        enforce(request, limit_key="auth:dev-token", max_per_minute=10)
        ...

Disabled when ``FIXOPS_DISABLE_RATE_LIMIT=1`` (CI/test environments).
"""

from __future__ import annotations

import os
import time
import threading
from collections import defaultdict

from fastapi import HTTPException, Request

# --------------------------------------------------------------------------- #
# Internal state — module-level so all handlers share the same buckets         #
# --------------------------------------------------------------------------- #

_lock = threading.Lock()
# key → list of epoch timestamps (float) in the last 60s
_buckets: dict[str, list[float]] = defaultdict(list)
# Cap on distinct keys to prevent unbounded memory under IP-spoofing storms
_MAX_KEYS = 4_000


def _prune_keys() -> None:
    """Drop the oldest 20% of keys when the dict grows too large."""
    if len(_buckets) < _MAX_KEYS:
        return
    cutoff = int(_MAX_KEYS * 0.8)
    # Remove keys with the fewest recent hits (least active)
    sorted_keys = sorted(_buckets, key=lambda k: len(_buckets[k]))
    for k in sorted_keys[: len(_buckets) - cutoff]:
        del _buckets[k]


# --------------------------------------------------------------------------- #
# Public API                                                                    #
# --------------------------------------------------------------------------- #


def enforce(request: Request, *, limit_key: str, max_per_minute: int) -> None:
    """Raise HTTP 429 if *request* exceeds *max_per_minute* for *limit_key*.

    The bucket key is ``{limit_key}:{client_ip}`` so each IP gets its own
    independent counter per endpoint group.

    Args:
        request: The incoming FastAPI request.
        limit_key: Logical name for the rate-limit bucket (e.g. ``"auth:login"``).
        max_per_minute: Maximum requests allowed in a rolling 60-second window.

    Raises:
        HTTPException: 429 with ``Retry-After`` header when limit is exceeded.
    """
    if os.getenv("FIXOPS_DISABLE_RATE_LIMIT") == "1":
        return

    client_ip = "unknown"
    if request.client and request.client.host:
        client_ip = request.client.host

    bucket_key = f"{limit_key}:{client_ip}"
    now = time.monotonic()
    window_start = now - 60.0

    with _lock:
        _prune_keys()
        hits = _buckets[bucket_key]
        # Evict timestamps outside the rolling 60s window
        hits[:] = [t for t in hits if t > window_start]

        if len(hits) >= max_per_minute:
            # Earliest hit tells us when a slot will free up
            retry_after = max(1, int(hits[0] - window_start) + 1)
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please retry later.",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        hits.append(now)
