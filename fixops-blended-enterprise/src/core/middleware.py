"""Runtime middleware used by the FastAPI application."""

from __future__ import annotations

import asyncio
import time
from typing import MutableMapping, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp

from src.config.settings import get_settings, resolve_allowed_origins


class PerformanceMiddleware(BaseHTTPMiddleware):  # pragma: no cover - trivial wrapper
    """Attach simple performance headers to responses."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        response.headers["X-Process-Time"] = f"{duration:.6f}"
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):  # pragma: no cover - trivial wrapper
    """Add a conservative set of security headers to each response."""

    _HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response = await call_next(request)
        for key, value in self._HEADERS.items():
            response.headers.setdefault(key, value)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Minimal token bucket rate limiter keyed by client IP."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        settings = get_settings()
        resolve_allowed_origins(settings)  # ensure production safety checks still run
        self.enabled = bool(getattr(settings, "FIXOPS_RL_ENABLED", True))
        capacity = int(getattr(settings, "FIXOPS_RL_REQ_PER_MIN", 60))
        self.capacity = max(1, capacity)
        self.refill_per_second = self.capacity / 60.0
        self._buckets: MutableMapping[str, Tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        if not self.enabled or request.url.path in {"/health", "/ready"}:
            return await call_next(request)
        client_ip = self._client_ip(request)
        allowed, retry_after = await self._consume_token(client_ip)
        if not allowed:
            return PlainTextResponse(
                "Rate limit exceeded. Please try again later.",
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

    def _client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "unknown"

    async def _consume_token(self, client_ip: str) -> Tuple[bool, int]:
        now = time.monotonic()
        async with self._lock:
            tokens, last_refill = self._buckets.get(client_ip, (float(self.capacity), now))
            elapsed = now - last_refill
            tokens = min(float(self.capacity), tokens + elapsed * self.refill_per_second)
            if tokens < 1.0:
                retry_after = max(1, int((1.0 - tokens) / self.refill_per_second))
                self._buckets[client_ip] = (tokens, now)
                return False, retry_after
            tokens -= 1.0
            self._buckets[client_ip] = (tokens, now)
            return True, 0

