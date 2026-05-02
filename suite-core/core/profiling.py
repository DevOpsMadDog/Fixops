"""Request profiling middleware for ALDECI FastAPI application.

Measures per-request latency, adds X-Response-Time header to every response,
logs slow requests, and tracks per-endpoint P50/P95/P99 percentiles in memory.

Usage (in app.py)::

    from core.profiling import ProfilingMiddleware, profiling_router
    app.add_middleware(ProfilingMiddleware)
    app.include_router(profiling_router)
"""

from __future__ import annotations

import logging
import math
import statistics
import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List

from fastapi import APIRouter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory latency store
# ---------------------------------------------------------------------------

# Keep the last N samples per endpoint path to bound memory usage.
_MAX_SAMPLES: int = 1000

# Thread-safe per-endpoint sample deques: path -> deque[float] (ms)
_latency_samples: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=_MAX_SAMPLES))
_latency_lock = threading.Lock()

# Total request counter (all endpoints combined)
_total_requests: int = 0
_total_slow: int = 0  # >1000 ms


def _record(path: str, duration_ms: float) -> None:
    """Record a latency sample for *path*."""
    global _total_requests, _total_slow
    with _latency_lock:
        _latency_samples[path].append(duration_ms)
        _total_requests += 1
        if duration_ms > 1000:
            _total_slow += 1


def _percentile(samples: List[float], pct: float) -> float:
    """Compute *pct*-th percentile (0-100) from a sorted list of samples."""
    if not samples:
        return 0.0
    k = (len(samples) - 1) * pct / 100.0
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return samples[lo]
    return samples[lo] + (samples[hi] - samples[lo]) * (k - lo)


def get_profiling_data() -> Dict[str, Any]:
    """Return current profiling data snapshot (thread-safe)."""
    with _latency_lock:
        # Snapshot to avoid holding lock during computation
        snapshot = {path: list(samples) for path, samples in _latency_samples.items()}
        total_reqs = _total_requests
        total_slow = _total_slow

    endpoints: List[Dict[str, Any]] = []
    for path, samples in snapshot.items():
        if not samples:
            continue
        sorted_s = sorted(samples)
        endpoints.append(
            {
                "path": path,
                "sample_count": len(sorted_s),
                "p50_ms": round(_percentile(sorted_s, 50), 2),
                "p95_ms": round(_percentile(sorted_s, 95), 2),
                "p99_ms": round(_percentile(sorted_s, 99), 2),
                "mean_ms": round(statistics.mean(sorted_s), 2),
                "max_ms": round(max(sorted_s), 2),
            }
        )

    # Sort by P99 descending so the slowest endpoints surface first
    endpoints.sort(key=lambda e: e["p99_ms"], reverse=True)

    return {
        "total_requests": total_reqs,
        "slow_requests_over_1s": total_slow,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
    }


def reset_profiling_data() -> None:
    """Clear all recorded latency samples (useful in tests)."""
    global _total_requests, _total_slow
    with _latency_lock:
        _latency_samples.clear()
        _total_requests = 0
        _total_slow = 0


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class ProfilingMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that measures request duration.

    - Adds ``X-Response-Time: <ms>`` header to every response.
    - Logs a WARNING for requests that take >1 000 ms.
    - Logs an ERROR for requests that take >5 000 ms.
    - Records per-endpoint samples for P50/P95/P99 tracking.
    """

    WARN_THRESHOLD_MS: float = 1000.0
    ERROR_THRESHOLD_MS: float = 5000.0

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        start = time.perf_counter()
        response: Response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000.0

        # Add timing header
        response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

        # Log slow requests
        path = request.url.path
        method = request.method
        status = response.status_code

        if duration_ms >= self.ERROR_THRESHOLD_MS:
            logger.error(
                "VERY_SLOW_REQUEST method=%s path=%s status=%s duration_ms=%.2f",
                method,
                path,
                status,
                duration_ms,
            )
        elif duration_ms >= self.WARN_THRESHOLD_MS:
            logger.warning(
                "SLOW_REQUEST method=%s path=%s status=%s duration_ms=%.2f",
                method,
                path,
                status,
                duration_ms,
            )

        # Record sample
        _record(path, duration_ms)

        return response


# ---------------------------------------------------------------------------
# Router: GET /api/v1/metrics/performance
# ---------------------------------------------------------------------------

profiling_router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"])


@profiling_router.get("/performance", summary="Per-endpoint P50/P95/P99 latency metrics")
async def get_performance_metrics() -> Dict[str, Any]:
    """Return in-memory profiling data: total request count, slow request count,
    and per-endpoint P50/P95/P99 latency percentiles (sorted by P99 desc).
    """
    return get_profiling_data()
