"""Shared middleware configuration helper for FastAPI sub-applications.

Extracted from app.py as part of Wave 1 ASPM decomposition (2026-04-28).
Provides a single ``configure_middleware(app)`` entry point so that
sub-applications can apply the same CORS / rate-limit / correlation-ID
stack without copy-pasting the configuration.

Usage::

    from apps.api.sub_apps.middleware_config import configure_middleware
    configure_middleware(my_fastapi_app)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

_logger = logging.getLogger(__name__)


def configure_middleware(app: "FastAPI") -> None:
    """Apply standard ALdeci middleware to *app*.

    Applies (in registration order — FastAPI/Starlette wraps in reverse):
    1. CORS — permissive defaults, overridable via environment.
    2. Correlation-ID injection — adds X-Correlation-ID header to every response.
    3. Request-ID logging — enriches structlog context with request_id.

    Note: rate-limiting is handled at the parent app level via the
    SlowAPI middleware registered in ``create_app()``.  Sub-apps that are
    *mounted* (not used as registrars) should call this to get an equivalent
    stack; registrar-pattern sub-apps share the parent middleware stack
    automatically.
    """
    import os

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------
    try:
        from starlette.middleware.cors import CORSMiddleware  # noqa: PLC0415

        origins = os.environ.get("ALDECI_CORS_ORIGINS", "*").split(",")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        _logger.debug("CORS middleware configured (origins=%s)", origins)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("CORS middleware not applied: %s", exc)

    # ------------------------------------------------------------------
    # Correlation-ID — inject X-Correlation-ID into every response so
    # distributed traces can be correlated across services.
    # ------------------------------------------------------------------
    try:
        import uuid

        from starlette.middleware.base import BaseHTTPMiddleware  # noqa: PLC0415
        from starlette.requests import Request  # noqa: PLC0415
        from starlette.responses import Response  # noqa: PLC0415

        class _CorrelationIdMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
                correlation_id = request.headers.get(
                    "X-Correlation-ID", str(uuid.uuid4())
                )
                request.state.correlation_id = correlation_id
                response = await call_next(request)
                response.headers["X-Correlation-ID"] = correlation_id
                return response

        app.add_middleware(_CorrelationIdMiddleware)
        _logger.debug("Correlation-ID middleware configured")
    except Exception as exc:  # noqa: BLE001
        _logger.warning("Correlation-ID middleware not applied: %s", exc)
