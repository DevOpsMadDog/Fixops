"""Middleware for correlation IDs, request logging, security headers, and observability."""

from __future__ import annotations

import time
import uuid
from typing import Callable

from core.logging_config import clear_correlation_id, get_logger, set_correlation_id
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all HTTP responses.

    Sets industry-standard security headers recommended by OWASP:
    - X-Content-Type-Options: Prevents MIME-type sniffing attacks
    - X-Frame-Options: Prevents clickjacking attacks
    - Referrer-Policy: Controls referrer information leakage
    - Permissions-Policy: Restricts browser feature access
    - Cache-Control: Prevents caching of sensitive API responses
    - X-Permitted-Cross-Domain-Policies: Prevents Flash/PDF cross-domain data loading

    Compliance mapping:
    - SOC2 CC6.1 (Logical Access Security)
    - PCI-DSS Req 6.5.9 (Cross-Site Request Forgery)
    - OWASP A05:2021 (Security Misconfiguration)
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Prevent MIME-type sniffing (OWASP A05)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking (OWASP A05, PCI-DSS 6.5.9)
        response.headers["X-Frame-Options"] = "DENY"

        # Control referrer information leakage
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Restrict browser feature access
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # Prevent caching of API responses containing sensitive data
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"

        # Prevent Flash/PDF cross-domain data loading
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # Content-Security-Policy: differentiate API vs SPA responses
        _path = request.url.path
        _is_api = _path.startswith("/api/") or _path == "/health" or _path.startswith("/openapi")
        if _is_api:
            # API endpoints: strict lockdown — no resource loading
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'"
            )
        else:
            # SPA pages: allow own assets, no inline scripts for XSS safety
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: blob:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'"
            )

        # X-XSS-Protection: legacy header, still respected by some browsers
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # HSTS: enforce HTTPS for 1 year (FedRAMP/NIST 800-53 SC-8)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Hide server identity to prevent reconnaissance (NIST 800-53 SC-7)
        if "server" in response.headers:
            del response.headers["server"]
        response.headers["Server"] = "FixOps"

        # Cross-Origin isolation headers (defense-grade)
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if _is_api:
            response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        # Demo-mode visibility header — signals to clients/proxies that auth is bypassed.
        # auth_deps.py sets request.state.demo_mode=True when FIXOPS_MODE=demo/dev.
        if getattr(request.state, "demo_mode", False):
            response.headers["X-Demo-Mode"] = "true"

        return response


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add correlation IDs to all requests for distributed tracing.

    Correlation IDs are extracted from X-Correlation-ID header or generated if not present.
    The correlation ID is added to all logs and responses for end-to-end traceability.
    """

    def __init__(self, app, header_name: str = "X-Correlation-ID"):
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        correlation_id = request.headers.get(self.header_name)
        if not correlation_id:
            correlation_id = str(uuid.uuid4())

        set_correlation_id(correlation_id)

        request.state.correlation_id = correlation_id

        try:
            response = await call_next(request)

            response.headers[self.header_name] = correlation_id

            return response
        finally:
            clear_correlation_id()


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log all HTTP requests and responses with timing information.

    Logs include:
    - Request method, path, query parameters
    - Response status code
    - Request duration in milliseconds
    - Correlation ID for tracing
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()

        logger.info(
            "request.started",
            extra={
                "method": request.method,
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "client_host": request.client.host if request.client else None,
            },
        )

        try:
            response = await call_next(request)

            duration_ms = (time.perf_counter() - start_time) * 1000

            logger.info(
                "request.completed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": round(duration_ms, 2),
                },
            )

            response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

            return response
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "request.failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": round(duration_ms, 2),
                    "error": type(exc).__name__,
                    "error_type": type(exc).__name__,
                },
            )
            raise


class RequestTracingMiddleware(BaseHTTPMiddleware):
    """
    Simple request tracing middleware — adds X-Request-ID and X-Correlation-ID
    headers when OpenTelemetry is not available or as a lightweight alternative.

    X-Request-ID:     unique per-request UUID (always generated fresh)
    X-Correlation-ID: propagated from the client or generated (handled by
                      CorrelationIdMiddleware); this middleware mirrors it onto
                      the response so callers always see both headers together.

    Both IDs are logged at request start so they appear in every log line
    generated during the request lifetime, enabling full traceability in
    Splunk/ELK/CloudWatch without a full OpenTelemetry stack.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Always create a fresh per-request ID (not the correlation ID which may
        # be reused across retries by the client).
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Correlation ID may already be set by CorrelationIdMiddleware (which runs
        # outermost when added last).  Mirror it here as a fallback.
        correlation_id = getattr(request.state, "correlation_id", None) or str(uuid.uuid4())

        logger.info(
            "request.tracing",
            extra={
                "request_id": request_id,
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.url.path,
            },
        )

        response = await call_next(request)

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Correlation-ID"] = correlation_id

        return response


# Re-export LearningMiddleware for convenience
try:
    from core.learning_middleware import LearningMiddleware  # noqa: F401
except ImportError:
    LearningMiddleware = None  # type: ignore[assignment,misc]

__all__ = [
    "CorrelationIdMiddleware",
    "RequestLoggingMiddleware",
    "RequestTracingMiddleware",
    "SecurityHeadersMiddleware",
    "LearningMiddleware",
]
