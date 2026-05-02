"""
Shared FastAPI dependencies for org_id and correlation_id extraction.

This module provides reusable dependencies for multi-tenancy (org_id) and
distributed tracing (correlation_id) across all API routers.

The ``get_org_id`` and ``get_org_id_required`` dependencies are re-exported
from ``org_middleware`` so that existing callers that import from this module
continue to work without modification.
"""

from typing import Optional

# Re-export from org_middleware — single source of truth for org_id resolution.
# Callers can import from either module; behaviour is identical.
from apps.api.org_middleware import (  # noqa: F401
    get_current_org_id,
    get_org_id,
    get_org_id_required,
)
from fastapi import Request


def get_correlation_id(request: Request) -> Optional[str]:
    """
    Extract correlation_id from request state (set by CorrelationIdMiddleware).

    Args:
        request: FastAPI request object

    Returns:
        Correlation ID string or None if not set
    """
    return getattr(request.state, "correlation_id", None)


__all__ = ["get_org_id", "get_org_id_required", "get_current_org_id", "get_correlation_id"]
