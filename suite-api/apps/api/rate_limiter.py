"""Rate limiting middleware for API endpoints."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Callable, Dict

from core.logging_config import get_logger
from fastapi import HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

logger = get_logger(__name__)


class RateLimiter:
    """Simple in-memory rate limiter using token bucket algorithm."""

    def __init__(
        self,
        *,
        requests_per_minute: int = 60,
        burst_size: int = 10,
    ):
        """
        Initialize rate limiter.

        Args:
            requests_per_minute: Maximum requests per minute per client
            burst_size: Maximum burst size (tokens in bucket)
        """
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.refill_rate = requests_per_minute / 60.0  # tokens per second

        self.buckets: Dict[str, tuple[float, float]] = defaultdict(
            lambda: (float(burst_size), time.time())
        )

    def _get_client_id(self, request: Request) -> str:
        """
        Get client identifier from request.

        Args:
            request: FastAPI request

        Returns:
            Client identifier (IP address or user ID)
        """
        if hasattr(request.state, "user_id"):
            return f"user:{request.state.user_id}"

        if request.client:
            return f"ip:{request.client.host}"

        return "unknown"

    def _refill_bucket(self, client_id: str) -> float:
        """
        Refill the token bucket based on elapsed time.

        Args:
            client_id: Client identifier

        Returns:
            Current number of tokens in bucket
        """
        tokens, last_refill = self.buckets[client_id]
        now = time.time()
        elapsed = now - last_refill

        tokens = min(self.burst_size, tokens + (elapsed * self.refill_rate))

        self.buckets[client_id] = (tokens, now)
        return tokens

    def check_rate_limit(self, request: Request) -> bool:
        """
        Check if request is within rate limit.

        Args:
            request: FastAPI request

        Returns:
            True if request is allowed, False if rate limited
        """
        client_id = self._get_client_id(request)

        tokens = self._refill_bucket(client_id)

        if tokens >= 1.0:
            self.buckets[client_id] = (tokens - 1.0, self.buckets[client_id][1])
            return True

        return False

    def get_retry_after(self, request: Request) -> int:
        """
        Get retry-after time in seconds.

        Args:
            request: FastAPI request

        Returns:
            Seconds until next token is available
        """
        client_id = self._get_client_id(request)
        tokens = self._refill_bucket(client_id)

        if tokens >= 1.0:
            return 0

        tokens_needed = 1.0 - tokens
        seconds_needed = tokens_needed / self.refill_rate
        return int(seconds_needed) + 1


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce rate limits on API endpoints."""

    def __init__(
        self,
        app,
        *,
        requests_per_minute: int = 60,
        burst_size: int = 10,
        exempt_paths: list[str] | None = None,
    ):
        """
        Initialize rate limit middleware.

        Args:
            app: FastAPI application
            requests_per_minute: Maximum requests per minute per client
            burst_size: Maximum burst size
            exempt_paths: List of paths exempt from rate limiting (e.g., health checks)
        """
        super().__init__(app)
        self.rate_limiter = RateLimiter(
            requests_per_minute=requests_per_minute,
            burst_size=burst_size,
        )
        self.exempt_paths = exempt_paths or [
            "/api/v1/health",
            "/api/v1/ready",
            "/api/v1/version",
            "/api/v1/metrics",
        ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with rate limiting.

        Args:
            request: FastAPI request
            call_next: Next middleware in chain

        Returns:
            Response

        Raises:
            HTTPException: If rate limit exceeded
        """
        if any(request.url.path.startswith(path) for path in self.exempt_paths):
            return await call_next(request)

        if not self.rate_limiter.check_rate_limit(request):
            retry_after = self.rate_limiter.get_retry_after(request)

            logger.warning(
                "rate_limit.exceeded",
                path=request.url.path,
                client=self.rate_limiter._get_client_id(request),
                retry_after=retry_after,
            )

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(
            self.rate_limiter.requests_per_minute
        )

        return response
