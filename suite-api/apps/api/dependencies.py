"""
Shared FastAPI dependencies for org_id and correlation_id extraction.

This module provides reusable dependencies for multi-tenancy (org_id) and
distributed tracing (correlation_id) across all API routers.

The ``get_org_id`` and ``get_org_id_required`` dependencies are re-exported
from ``org_middleware`` so that existing callers that import from this module
continue to work without modification.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from fastapi import Depends, Header, HTTPException, Query, Request, status

# Re-export from org_middleware — single source of truth for org_id resolution.
# Callers can import from either module; behaviour is identical.
from apps.api.org_middleware import (  # noqa: F401
    get_current_org_id,
    get_org_id,
    get_org_id_required,
)


def get_correlation_id(request: Request) -> Optional[str]:
    """
    Extract correlation_id from request state (set by CorrelationIdMiddleware).

    Args:
        request: FastAPI request object

    Returns:
        Correlation ID string or None if not set
    """
    return getattr(request.state, "correlation_id", None)


# Re-export get_settings so tests can monkeypatch it on this module.
try:
    from config.enterprise.settings import get_settings  # noqa: F401
except ImportError:
    def get_settings():  # type: ignore[misc]
        return None

# ---------------------------------------------------------------------------
# Payload validation
# ---------------------------------------------------------------------------

_DEFAULT_MAX_PAYLOAD = 10 * 1024 * 1024  # 10 MiB


async def validated_payload(request: Request) -> Dict[str, Any]:
    """Read, validate, and return the JSON request body.

    Checks:
    * Content-Type must be ``application/json``
    * Body must be valid JSON
    * Top-level value must be a JSON object (dict)
    * Body size must not exceed ``FIXOPS_MAX_PAYLOAD_BYTES``
    """
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" not in content_type:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Content-Type must be application/json",
        )

    body = await request.body()

    max_bytes = int(os.getenv("FIXOPS_MAX_PAYLOAD_BYTES", str(_DEFAULT_MAX_PAYLOAD)))
    try:
        settings = get_settings()
        if settings is not None:
            max_bytes = getattr(settings, "FIXOPS_MAX_PAYLOAD_BYTES", max_bytes)
    except Exception:
        pass

    if len(body) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload exceeds {max_bytes} bytes",
        )

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON body",
        ) from exc

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be a JSON object",
        )

    request.state.payload = data
    return data


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


async def authenticate(request: Request) -> None:
    """Validate the ``Authorization: Bearer <token>`` header.

    Raises:
    * 401 if the header is missing
    * 403 if the token does not match ``FIXOPS_API_KEY``
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
        )

    token = parts[1].strip()
    expected = os.getenv("FIXOPS_API_KEY", "")
    if not expected or token != expected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API token",
        )

    request.state.user_role = "admin"
    request.state.user_scopes = ["admin:all"]


async def authenticated_payload(
    payload: Dict[str, Any] = Depends(validated_payload),
    _: None = Depends(authenticate),
) -> Dict[str, Any]:
    """Combined dependency: validates the JSON body *and* authenticates."""
    return payload


__all__ = [
    "get_org_id",
    "get_org_id_required",
    "get_current_org_id",
    "get_correlation_id",
    "validated_payload",
    "authenticate",
    "authenticated_payload",
]
