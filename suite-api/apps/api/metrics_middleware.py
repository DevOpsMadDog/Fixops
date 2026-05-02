"""Prometheus metrics middleware for ALdeci/FixOps API.

Exposes a /metrics endpoint in Prometheus text format and tracks:
- Request count by endpoint, method, status (fixops_http_requests_total)
- Request latency histogram (fixops_http_request_duration_seconds)
- Active connections gauge (fixops_active_connections)
- Pipeline execution count and duration (fixops_pipeline_executions_total, fixops_pipeline_duration_seconds)
- Error count by type (fixops_errors_total)

Design: prometheus_client is an optional dependency.  When it is not installed
the middleware silently falls back to a no-op and the /metrics route returns a
plain JSON summary instead of Prometheus text format.  This keeps the app fully
functional in environments where prometheus_client has not been pip-installed yet.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Match

# ---------------------------------------------------------------------------
# Optional prometheus_client import — graceful degradation when absent
# ---------------------------------------------------------------------------
try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        REGISTRY,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    _PROMETHEUS_AVAILABLE = True

    # ------------------------------------------------------------------
    # Metric definitions
    # All metrics are registered once at module import time (process-level
    # singletons).  Using a try/except around each definition lets the
    # module reload safely in test environments where the default
    # CollectorRegistry may already contain the metric.
    # ------------------------------------------------------------------

    def _get_or_create_counter(name: str, documentation: str, labelnames: list) -> Counter:
        try:
            return Counter(name, documentation, labelnames)
        except ValueError:
            # Already registered — return the existing metric
            return REGISTRY._names_to_collectors.get(name) or Counter(  # type: ignore[attr-defined]
                name, documentation, labelnames
            )

    def _get_or_create_histogram(
        name: str, documentation: str, labelnames: list, buckets: Optional[list] = None
    ) -> Histogram:
        kwargs = {}
        if buckets:
            kwargs["buckets"] = buckets
        try:
            return Histogram(name, documentation, labelnames, **kwargs)
        except ValueError:
            return REGISTRY._names_to_collectors.get(name) or Histogram(  # type: ignore[attr-defined]
                name, documentation, labelnames, **kwargs
            )

    def _get_or_create_gauge(name: str, documentation: str, labelnames: Optional[list] = None) -> Gauge:
        try:
            return Gauge(name, documentation, labelnames or [])
        except ValueError:
            return REGISTRY._names_to_collectors.get(name) or Gauge(  # type: ignore[attr-defined]
                name, documentation, labelnames or []
            )

    HTTP_REQUESTS_TOTAL = _get_or_create_counter(
        "fixops_http_requests_total",
        "Total HTTP requests handled by the ALdeci API",
        ["method", "endpoint", "status_code"],
    )

    HTTP_REQUEST_DURATION_SECONDS = _get_or_create_histogram(
        "fixops_http_request_duration_seconds",
        "HTTP request latency in seconds (p50/p95/p99 derivable from histogram)",
        ["method", "endpoint"],
        buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )

    ACTIVE_CONNECTIONS = _get_or_create_gauge(
        "fixops_active_connections",
        "Number of currently active HTTP connections",
    )

    PIPELINE_EXECUTIONS_TOTAL = _get_or_create_counter(
        "fixops_pipeline_executions_total",
        "Total Brain Pipeline executions",
        ["status"],  # success | error
    )

    PIPELINE_DURATION_SECONDS = _get_or_create_histogram(
        "fixops_pipeline_duration_seconds",
        "Brain Pipeline execution duration in seconds",
        [],
        buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0],
    )

    ERRORS_TOTAL = _get_or_create_counter(
        "fixops_errors_total",
        "Total application errors by type",
        ["error_type"],
    )

except ImportError:
    _PROMETHEUS_AVAILABLE = False

    # Stub objects so the middleware can reference them without branching everywhere
    class _NoOpMetric:
        def labels(self, **_kw):
            return self

        def inc(self, *_a, **_kw):
            pass

        def observe(self, *_a, **_kw):
            pass

        def set(self, *_a, **_kw):
            pass

        def time(self):
            import contextlib
            return contextlib.nullcontext()

    HTTP_REQUESTS_TOTAL = _NoOpMetric()  # type: ignore[assignment]
    HTTP_REQUEST_DURATION_SECONDS = _NoOpMetric()  # type: ignore[assignment]
    ACTIVE_CONNECTIONS = _NoOpMetric()  # type: ignore[assignment]
    PIPELINE_EXECUTIONS_TOTAL = _NoOpMetric()  # type: ignore[assignment]
    PIPELINE_DURATION_SECONDS = _NoOpMetric()  # type: ignore[assignment]
    ERRORS_TOTAL = _NoOpMetric()  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Public helpers — called from app.py and pipeline code
# ---------------------------------------------------------------------------

def record_pipeline_execution(status: str, duration_seconds: float) -> None:
    """Record a Brain Pipeline execution event.

    Call this from the pipeline code after each run:
        record_pipeline_execution("success", elapsed)
        record_pipeline_execution("error", elapsed)
    """
    if _PROMETHEUS_AVAILABLE:
        PIPELINE_EXECUTIONS_TOTAL.labels(status=status).inc()  # type: ignore[union-attr]
        PIPELINE_DURATION_SECONDS.observe(duration_seconds)  # type: ignore[union-attr]


def record_error(error_type: str) -> None:
    """Increment the error counter for a specific error class."""
    if _PROMETHEUS_AVAILABLE:
        ERRORS_TOTAL.labels(error_type=error_type).inc()  # type: ignore[union-attr]


def prometheus_available() -> bool:
    """Return True if prometheus_client is installed and metrics are live."""
    return _PROMETHEUS_AVAILABLE


# ---------------------------------------------------------------------------
# Starlette middleware
# ---------------------------------------------------------------------------

def _normalise_path(request: Request) -> str:
    """
    Collapse path parameters to prevent high-cardinality label explosion.

    e.g. /api/v1/findings/abc-123-def → /api/v1/findings/{id}

    Strategy: use Starlette's own route matching to get the route template
    (which already has {param} placeholders).  Fall back to a simple regex
    collapse for unmatched paths.
    """
    for route in request.app.routes:
        match, _ = route.matches({"type": "http", "path": request.url.path, "method": request.method})
        if match == Match.FULL and hasattr(route, "path"):
            return route.path  # already has {id} etc.
    return request.url.path  # fallback — unmatched routes stay verbatim


class PrometheusMetricsMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that records Prometheus metrics for every HTTP request.

    Added to the FastAPI app via ``app.add_middleware(PrometheusMetricsMiddleware)``
    in ``create_app()``.  When prometheus_client is not installed this middleware
    is still safe to add — it runs as a zero-cost pass-through.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not _PROMETHEUS_AVAILABLE:
            return await call_next(request)

        ACTIVE_CONNECTIONS.inc()  # type: ignore[union-attr]
        start = time.perf_counter()
        response: Optional[Response] = None

        try:
            response = await call_next(request)
            return response
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            record_error(type(exc).__name__)
            raise
        finally:
            elapsed = time.perf_counter() - start
            ACTIVE_CONNECTIONS.dec()  # type: ignore[union-attr]

            status_code = str(response.status_code) if response is not None else "500"
            endpoint = _normalise_path(request)

            HTTP_REQUESTS_TOTAL.labels(  # type: ignore[union-attr]
                method=request.method,
                endpoint=endpoint,
                status_code=status_code,
            ).inc()

            HTTP_REQUEST_DURATION_SECONDS.labels(  # type: ignore[union-attr]
                method=request.method,
                endpoint=endpoint,
            ).observe(elapsed)

            if response is not None and response.status_code >= 500:
                record_error(f"HTTP_{status_code}")


# ---------------------------------------------------------------------------
# /metrics route handler
# ---------------------------------------------------------------------------

def metrics_response() -> Response:
    """
    Return a Response suitable for mounting at /metrics.

    Returns Prometheus text format when prometheus_client is available,
    otherwise returns a JSON summary so the endpoint always works.
    """
    if _PROMETHEUS_AVAILABLE:
        data = generate_latest()
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)

    # Fallback: minimal JSON metrics when prometheus_client is not installed
    import json
    import os
    from datetime import datetime, timezone

    payload = {
        "prometheus_available": False,
        "message": "Install prometheus_client>=0.20 to enable Prometheus text format",
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "service": "fixops-api",
        "version": os.getenv("FIXOPS_VERSION", "0.1.0"),
    }
    return Response(
        content=json.dumps(payload),
        media_type="application/json",
        status_code=200,
    )


__all__ = [
    "PrometheusMetricsMiddleware",
    "metrics_response",
    "record_pipeline_execution",
    "record_error",
    "prometheus_available",
    "HTTP_REQUESTS_TOTAL",
    "HTTP_REQUEST_DURATION_SECONDS",
    "ACTIVE_CONNECTIONS",
    "PIPELINE_EXECUTIONS_TOTAL",
    "PIPELINE_DURATION_SECONDS",
    "ERRORS_TOTAL",
]
