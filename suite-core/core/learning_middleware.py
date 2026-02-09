"""Learning Middleware — captures all API traffic for ML intelligence.

Intercepts every FastAPI request/response, measures timing, extracts metadata,
and streams records to the APILearningStore for anomaly detection, threat
assessment, and performance prediction.

Phase 6 of FixOps Transformation Plan (R1).
"""
from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Paths to skip (health checks, static, docs)
_SKIP_PREFIXES = (
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/favicon.ico",
    "/static/",
)


class LearningMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that captures API traffic for the ML learning layer.

    For every request it:
    1. Measures wall-clock duration
    2. Extracts method, path, status, client IP, user-agent, correlation-id
    3. Runs real-time anomaly detection & threat assessment
    4. Adds X-Anomaly-Score and X-Threat-Level response headers
    5. Streams a TrafficRecord to the APILearningStore (non-blocking)

    The store accumulates records in an in-memory batch and flushes to SQLite
    every 500 records (configurable).
    """

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self._enabled = enabled
        self._store = None  # lazy init to avoid import cycles at module level

    def _get_store(self):
        """Lazy-load the learning store singleton."""
        if self._store is None:
            try:
                from core.api_learning_store import get_learning_store
                self._store = get_learning_store()
            except Exception as exc:
                logger.warning("Could not initialise learning store: %s", exc)
                self._enabled = False
        return self._store

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Fast path: skip if disabled or path is excluded
        if not self._enabled:
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(p) for p in _SKIP_PREFIXES):
            return await call_next(request)

        store = self._get_store()
        if store is None:
            return await call_next(request)

        method = request.method
        client_ip = request.client.host if request.client else ""
        user_agent = request.headers.get("user-agent", "")
        correlation_id = request.headers.get("x-correlation-id", "")
        query_params = str(dict(request.query_params)) if request.query_params else ""

        # Approximate request body size from content-length header
        request_size = int(request.headers.get("content-length", 0))

        start = time.perf_counter()
        error_type = ""
        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code

            duration_ms = (time.perf_counter() - start) * 1000

            # Approximate response size from content-length header
            response_size = int(response.headers.get("content-length", 0))

            # ---- Real-time ML scoring (non-blocking best-effort) ----
            anomaly_score = 0.0
            threat_level = "low"
            try:
                anomaly = store.detect_anomaly(
                    method=method,
                    path=path,
                    status_code=status_code,
                    duration_ms=duration_ms,
                    request_size=request_size,
                    response_size=response_size,
                )
                anomaly_score = anomaly.score

                threat = store.assess_threat(
                    method=method,
                    path=path,
                    client_ip=client_ip,
                    status_code=status_code,
                    duration_ms=duration_ms,
                    user_agent=user_agent,
                )
                threat_level = threat.risk_level

                # Record threat indicators for high/critical
                if threat.threat_score >= 0.4:
                    store.record_threat(
                        indicator_type="realtime_detection",
                        description="; ".join(threat.indicators) or "Elevated threat",
                        severity=threat.risk_level,
                        source_ip=client_ip,
                        target_path=path,
                        details={
                            "method": method,
                            "status": status_code,
                            "duration_ms": round(duration_ms, 2),
                            "anomaly_score": round(anomaly_score, 4),
                        },
                    )

                # Mark anomaly flag for DB storage
                is_anomaly = anomaly.is_anomaly
            except Exception:
                is_anomaly = False

            # Inject ML headers
            response.headers["X-Anomaly-Score"] = f"{anomaly_score:.4f}"
            response.headers["X-Threat-Level"] = threat_level

            # ---- Stream to learning store ----
            from core.api_learning_store import TrafficRecord
            store.record(TrafficRecord(
                method=method,
                path=path,
                status_code=status_code,
                duration_ms=round(duration_ms, 2),
                request_size=request_size,
                response_size=response_size,
                client_ip=client_ip,
                user_agent=user_agent,
                correlation_id=correlation_id,
                query_params=query_params,
                error_type=error_type,
            ))

            return response

        except Exception as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            error_type = type(exc).__name__

            # Still record the failed request
            try:
                from core.api_learning_store import TrafficRecord
                store.record(TrafficRecord(
                    method=method,
                    path=path,
                    status_code=500,
                    duration_ms=round(duration_ms, 2),
                    request_size=request_size,
                    response_size=0,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    correlation_id=correlation_id,
                    query_params=query_params,
                    error_type=error_type,
                ))
            except Exception:
                pass  # Never let middleware recording break the request

            raise


__all__ = ["LearningMiddleware"]

