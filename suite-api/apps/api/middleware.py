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
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "request.failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": round(duration_ms, 2),
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            )
            raise


# Re-export LearningMiddleware for convenience
try:
    from core.learning_middleware import LearningMiddleware  # noqa: F401
except ImportError:
    LearningMiddleware = None  # type: ignore[assignment,misc]

__all__ = [
    "CorrelationIdMiddleware",
    "RequestLoggingMiddleware",
    "SecurityHeadersMiddleware",
    "LearningMiddleware",
]
