"""
Rate limiting middleware for FastAPI to prevent brute force attacks and API abuse.

This module provides a simple in-memory rate limiter that can be used to protect
API endpoints from excessive requests.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Callable, Dict, Tuple

from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    
    requests_per_window: int = 10  # Maximum requests per time window
    window_seconds: int = 60  # Time window in seconds
    enabled: bool = True  # Enable/disable rate limiting


@dataclass
class ClientRequestTracker:
    """Track request counts and timestamps for a single client."""
    
    request_count: int = 0
    window_start: float = field(default_factory=time.time)
    
    def is_rate_limited(self, config: RateLimitConfig) -> bool:
        """Check if client has exceeded rate limit."""
        current_time = time.time()
        
        # Reset window if expired
        if current_time - self.window_start >= config.window_seconds:
            self.window_start = current_time
            self.request_count = 0
        
        # Check if limit exceeded
        if self.request_count >= config.requests_per_window:
            return True
        
        return False
    
    def increment(self):
        """Increment request count."""
        self.request_count += 1


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce rate limiting on API requests.
    
    Tracks requests per IP address and enforces configurable rate limits.
    Uses in-memory storage with periodic cleanup of stale entries.
    """
    
    def __init__(self, app, config: RateLimitConfig):
        super().__init__(app)
        self.config = config
        self._trackers: Dict[str, ClientRequestTracker] = defaultdict(ClientRequestTracker)
        self._lock = Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # Cleanup every 5 minutes
    
    def _get_client_identifier(self, request: Request) -> str:
        """
        Extract client identifier from request.
        
        Uses X-Forwarded-For header if present (for proxied requests),
        otherwise falls back to client IP.
        """
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP in the chain
            return forwarded.split(",")[0].strip()
        
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _cleanup_stale_trackers(self):
        """Remove trackers that haven't been used recently."""
        current_time = time.time()
        
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
        
        with self._lock:
            stale_keys = [
                key for key, tracker in self._trackers.items()
                if current_time - tracker.window_start > self.config.window_seconds * 2
            ]
            for key in stale_keys:
                del self._trackers[key]
            
            self._last_cleanup = current_time
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and enforce rate limiting.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            Response object
            
        Raises:
            HTTPException: If rate limit is exceeded
        """
        if not self.config.enabled:
            return await call_next(request)
        
        # Periodic cleanup
        self._cleanup_stale_trackers()
        
        # Get client identifier
        client_id = self._get_client_identifier(request)
        
        # Check rate limit
        with self._lock:
            tracker = self._trackers[client_id]
            
            if tracker.is_rate_limited(self.config):
                # Calculate retry-after time
                time_until_reset = self.config.window_seconds - (
                    time.time() - tracker.window_start
                )
                
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "Rate limit exceeded",
                        "retry_after_seconds": int(time_until_reset) + 1,
                        "limit": self.config.requests_per_window,
                        "window_seconds": self.config.window_seconds,
                    },
                    headers={
                        "Retry-After": str(int(time_until_reset) + 1),
                        "X-RateLimit-Limit": str(self.config.requests_per_window),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(tracker.window_start + self.config.window_seconds)),
                    }
                )
            
            # Increment request count
            tracker.increment()
            
            # Calculate remaining requests
            remaining = self.config.requests_per_window - tracker.request_count
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        response.headers["X-RateLimit-Limit"] = str(self.config.requests_per_window)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(
            int(tracker.window_start + self.config.window_seconds)
        )
        
        return response


def create_rate_limiter(
    requests_per_window: int = 100,
    window_seconds: int = 60,
    enabled: bool = True
) -> RateLimitMiddleware:
    """
    Factory function to create a rate limiter middleware.
    
    Args:
        requests_per_window: Maximum requests allowed per time window
        window_seconds: Time window duration in seconds
        enabled: Whether rate limiting is enabled
        
    Returns:
        Configured RateLimitMiddleware instance
    """
    config = RateLimitConfig(
        requests_per_window=requests_per_window,
        window_seconds=window_seconds,
        enabled=enabled
    )
    
    def middleware_factory(app):
        return RateLimitMiddleware(app, config)
    
    return middleware_factory
