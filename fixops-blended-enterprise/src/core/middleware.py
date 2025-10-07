"""
Enterprise middleware for performance, security, and monitoring
"""

import asyncio
import time
import gzip
from typing import Callable, Dict, Any, Optional
import structlog
from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse
from starlette.types import ASGIApp
import orjson

from src.services.cache_service import CacheService
from src.config.settings import get_settings
from src.services.metrics import FixOpsMetrics

logger = structlog.get_logger()
settings = get_settings()


class PerformanceMiddleware(BaseHTTPMiddleware):
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
                correlation_id=correlation_id
            )
        
        # Log hot path performance
        if request.url.path in ["/health", "/ready", "/api/v1/incidents/*/status"]:
            if process_time_us > settings.HOT_PATH_TARGET_LATENCY_US:
                logger.error(
                    "Hot path latency exceeded target",
                    path=request.url.path,
                    target_us=settings.HOT_PATH_TARGET_LATENCY_US,
                    actual_us=process_time_us,
                    correlation_id=correlation_id
                )
        
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
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
        )
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
    """Distributed rate limiting with Redis"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/ready", "/metrics"]:
            return await call_next(request)
        
        # Get client IP (considering proxy headers)
        client_ip = self._get_client_ip(request)
        
        # Check rate limit
        if await self._is_rate_limited(client_ip, request.url.path):
            return PlainTextResponse(
                "Rate limit exceeded. Please try again later.",
                status_code=429,
                headers={"Retry-After": "60"}
            )
        
        return await call_next(request)
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP considering proxy headers"""
        # Check for forwarded IP headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    async def _is_rate_limited(self, client_ip: str, path: str) -> bool:
        """Check if client is rate limited using sliding window"""
        cache = CacheService.get_instance()
        current_time = int(time.time())
        window_start = current_time - settings.RATE_LIMIT_WINDOW
        
        # Create rate limit key
        rate_limit_key = f"rate_limit:{client_ip}:{path}"
        
        try:
            # Get request timestamps from sliding window
            timestamps = await cache.get(rate_limit_key) or []
            
            # Remove old timestamps outside the window
            timestamps = [ts for ts in timestamps if ts > window_start]
            
            # Check if limit exceeded
            if len(timestamps) >= settings.RATE_LIMIT_REQUESTS:
                logger.warning(
                    "Rate limit exceeded",
                    client_ip=client_ip,
                    path=path,
                    requests=len(timestamps),
                    limit=settings.RATE_LIMIT_REQUESTS
                )
                return True
            
            # Add current timestamp
            timestamps.append(current_time)
            await cache.set(rate_limit_key, timestamps, ttl=settings.RATE_LIMIT_WINDOW)
            
            return False
            
        except Exception as e:
            logger.error(f"Rate limiting error: {str(e)}")
            # Fail open - don't block requests if rate limiting fails
            return False


class CompressionMiddleware(BaseHTTPMiddleware):
    """Response compression for performance optimization"""
    
    COMPRESSIBLE_TYPES = {
        "application/json",
        "application/javascript",
        "text/html",
        "text/css",
        "text/plain",
        "text/xml"
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
                        media_type=response.media_type
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


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """Enterprise audit logging for compliance"""
    
    SENSITIVE_PATHS = [
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/users",
        "/api/v1/admin"
    ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Capture request details for audit
        audit_data = {
            "timestamp": time.time(),
            "method": request.method,
            "path": request.url.path,
            "client_ip": self._get_client_ip(request),
            "user_agent": request.headers.get("user-agent"),
            "correlation_id": getattr(request.state, "correlation_id", None)
        }
        
        # Process request
        response = await call_next(request)
        
        # Add response details
        audit_data.update({
            "status_code": response.status_code,
            "response_size": len(getattr(response, "body", b"")),
        })
        
        # Log sensitive operations
        if any(sensitive in request.url.path for sensitive in self.SENSITIVE_PATHS):
            logger.info(
                "Audit log entry",
                **audit_data,
                event_type="sensitive_operation"
            )
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP for audit logging"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        return request.client.host if request.client else "unknown"