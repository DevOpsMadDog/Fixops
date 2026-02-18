"""
Enterprise middleware for performance, security, and monitoring
"""

import asyncio
import gzip
import os
import time
from typing import Any, Callable, MutableMapping, Optional, Tuple

import structlog
from fastapi import HTTPException
from pydantic import FieldInfo
from src.config.settings import get_settings
from src.services.metrics import FixOpsMetrics
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp

logger = structlog.get_logger()
settings = get_settings()


class PerformanceMiddleware(BaseHTTPMiddleware):  # pragma: no cover
    """Performance monitoring and optimization middleware"""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()

        # Add correlation ID for request tracking
        correlation_id = f"req_{int(time.time() * 1000000)}"
        request.state.correlation_id = correlation_id

        if settings.ENABLE_METRICS:
            FixOpsMetrics.request_started(request.url.path)

        # Process request
        response: Optional[Response] = None
        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
        except HTTPException as exc:
            status_code = exc.status_code
            raise
        except Exception:
            raise
        finally:
            duration = time.perf_counter() - start_time

            if settings.ENABLE_METRICS:
                FixOpsMetrics.record_request(
                    endpoint=request.url.path,
                    method=request.method,
                    status=status_code,
                    duration=duration,
                )
                FixOpsMetrics.request_finished(request.url.path)

            process_time_us = duration * 1_000_000

        if response is None:
            # Re-raise the original exception if we reach this point without a response
            raise

        # Add performance headers
        response.headers["X-Process-Time"] = f"{duration:.6f}"
        response.headers["X-Process-Time-US"] = f"{process_time_us:.2f}"
        response.headers["X-Correlation-ID"] = correlation_id

        # Log slow requests
        if process_time_us > 1000:  # > 1ms
            logger.warning(
                "Slow request detected",
                path=request.url.path,
                method=request.method,
                duration_us=process_time_us,
                correlation_id=correlation_id,
            )

        # Log hot path performance
        if request.url.path in ["/health", "/ready", "/api/v1/incidents/*/status"]:
            if process_time_us > settings.HOT_PATH_TARGET_LATENCY_US:
                logger.error(
                    "Hot path latency exceeded target",
                    path=request.url.path,
                    target_us=settings.HOT_PATH_TARGET_LATENCY_US,
                    actual_us=process_time_us,
                    correlation_id=correlation_id,
                )

        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):  # pragma: no cover
    """Add enterprise security headers"""

    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'"
        ),
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        ),
    }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Add security headers
        for header, value in self.SECURITY_HEADERS.items():
            response.headers[header] = value

        # Remove server identification headers
        if "server" in response.headers:
            del response.headers["server"]

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Lightweight token bucket rate limiting per client IP."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._buckets: MutableMapping[str, Tuple[float, float]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        config_values = {}
        if hasattr(settings, "model_dump"):
            try:
                config_values = settings.model_dump()
            except Exception:  # pragma: no cover - defensive fallback
                config_values = {}

        enabled_value = config_values.get("FIXOPS_RL_ENABLED")
        self.enabled = self._normalize_bool(
            enabled_value, getattr(settings, "FIXOPS_RL_ENABLED", True)
        )

        configured_limit = config_values.get("FIXOPS_RL_REQ_PER_MIN")
        env_override = os.getenv("FIXOPS_RL_REQ_PER_MIN")
        if env_override is not None:
            configured_limit = env_override
        fallback_limit = config_values.get(
            "RATE_LIMIT_REQUESTS", getattr(settings, "RATE_LIMIT_REQUESTS", 60)
        )
        self.capacity = max(
            1,
            self._normalize_int(
                configured_limit,
                getattr(settings, "FIXOPS_RL_REQ_PER_MIN", fallback_limit),
                fallback_limit,
            ),
        )
        self.refill_per_second = self.capacity / 60.0

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled or request.url.path in {"/health", "/ready", "/metrics"}:
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        allowed, retry_after = await self._consume_token(client_ip)
        if not allowed:
            logger.warning(
                "Rate limit exceeded", client_ip=client_ip, path=request.url.path
            )
            FixOpsMetrics.rate_limit_triggered()
            return PlainTextResponse(
                "Rate limit exceeded. Please try again later.",
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    async def _consume_token(self, client_ip: str) -> Tuple[bool, int]:
        now = time.monotonic()
        async with self._lock:
            tokens, last_refill = self._buckets.get(
                client_ip, (float(self.capacity), now)
            )
            elapsed = now - last_refill
            tokens = min(
                float(self.capacity), tokens + elapsed * self.refill_per_second
            )
            if tokens < 1.0:
                retry = max(1, int((1.0 - tokens) / self.refill_per_second))
                self._buckets[client_ip] = (tokens, now)
                return False, retry
            tokens -= 1.0
            self._buckets[client_ip] = (tokens, now)
        return True, 0

    @staticmethod
    def _normalize_bool(value: Any, default: bool) -> bool:
        candidate = RateLimitMiddleware._unwrap_field(value, default)
        if isinstance(candidate, str):
            lowered = candidate.strip().lower()
            if lowered in {"0", "false", "no", "off"}:
                return False
            if lowered in {"1", "true", "yes", "on"}:
                return True
        return bool(candidate)

    @staticmethod
    def _normalize_int(value: Any, primary_default: Any, secondary_default: Any) -> int:
        candidate = RateLimitMiddleware._unwrap_field(value, primary_default)
        try:
            return int(candidate)
        except (TypeError, ValueError):
            fallback = RateLimitMiddleware._unwrap_field(secondary_default, 60)
            return int(fallback)

    @staticmethod
    def _unwrap_field(value: Any, default: Any) -> Any:
        if isinstance(value, FieldInfo):
            extracted = value.default
            return extracted if extracted is not None else default
        if value in (None, ...):
            return default
        return value


class CompressionMiddleware(BaseHTTPMiddleware):  # pragma: no cover
    """Response compression for performance optimization"""

    COMPRESSIBLE_TYPES = {
        "application/json",
        "application/javascript",
        "text/html",
        "text/css",
        "text/plain",
        "text/xml",
    }

    MIN_SIZE = 500  # Minimum response size to compress

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Check if compression should be applied
        if not self._should_compress(request, response):
            return response

        # Compress response body
        if hasattr(response, "body"):
            original_body = response.body
            if len(original_body) >= self.MIN_SIZE:
                compressed_body = gzip.compress(original_body)

                # Only use compressed version if it's actually smaller
                if len(compressed_body) < len(original_body):
                    response.headers["Content-Encoding"] = "gzip"
                    response.headers["Content-Length"] = str(len(compressed_body))
                    # Create new response with compressed body
                    new_response = Response(
                        content=compressed_body,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        media_type=response.media_type,
                    )
                    return new_response

        return response

    def _should_compress(self, request: Request, response: Response) -> bool:
        """Determine if response should be compressed"""
        # Check if client accepts gzip
        accept_encoding = request.headers.get("accept-encoding", "")
        if "gzip" not in accept_encoding.lower():
            return False

        # Check content type
        content_type = response.headers.get("content-type", "")
        media_type = content_type.split(";")[0].strip().lower()

        return media_type in self.COMPRESSIBLE_TYPES


class AuditLoggingMiddleware(BaseHTTPMiddleware):  # pragma: no cover
    """Enterprise audit logging for compliance"""

    SENSITIVE_PATHS = [
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/users",
        "/api/v1/admin",
    ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Capture request details for audit
        audit_data = {
            "timestamp": time.time(),
            "method": request.method,
            "path": request.url.path,
            "client_ip": self._get_client_ip(request),
            "user_agent": request.headers.get("user-agent"),
            "correlation_id": getattr(request.state, "correlation_id", None),
        }

        # Process request
        response = await call_next(request)

        # Add response details
        audit_data.update(
            {
                "status_code": response.status_code,
                "response_size": len(getattr(response, "body", b"")),
            }
        )

        # Log sensitive operations
        if any(sensitive in request.url.path for sensitive in self.SENSITIVE_PATHS):
            logger.info(
                "Audit log entry", **audit_data, event_type="sensitive_operation"
            )

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP for audit logging"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        return request.client.host if request.client else "unknown"
