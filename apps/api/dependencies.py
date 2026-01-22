"""
Shared FastAPI dependencies for org_id and correlation_id extraction.

This module provides reusable dependencies for multi-tenancy (org_id) and
distributed tracing (correlation_id) across all API routers.
"""

from typing import Optional

from fastapi import Header, Query, Request


def get_org_id(
    org_id: Optional[str] = Query(
        None, description="Organization ID for multi-tenancy (query param)"
    ),
    x_org_id: Optional[str] = Header(
        None, alias="X-Org-ID", description="Organization ID for multi-tenancy (header)"
    ),
) -> str:
    """
    Extract org_id from query parameter or X-Org-ID header.

    Priority: query parameter > header > default

    Args:
        org_id: Organization ID from query parameter
        x_org_id: Organization ID from X-Org-ID header

    Returns:
        Organization ID string (defaults to "default" if not provided)
    """
    return org_id or x_org_id or "default"


def get_org_id_required(
    org_id: Optional[str] = Query(
        None, description="Organization ID for multi-tenancy (query param)"
    ),
    x_org_id: Optional[str] = Header(
        None, alias="X-Org-ID", description="Organization ID for multi-tenancy (header)"
    ),
) -> str:
    """
    Extract org_id from query parameter or X-Org-ID header (required).

    Priority: query parameter > header

    Args:
        org_id: Organization ID from query parameter
        x_org_id: Organization ID from X-Org-ID header

    Returns:
        Organization ID string

    Raises:
        HTTPException: 400 error if no org_id is provided
    """
    result = org_id or x_org_id
    if not result:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=400,
            detail="org_id is required (provide via query param or X-Org-ID header)",
        )
    return result


def get_correlation_id(request: Request) -> Optional[str]:
    """
    Extract correlation_id from request state (set by CorrelationIdMiddleware).

    Args:
        request: FastAPI request object

    Returns:
        Correlation ID string or None if not set
    """
    return getattr(request.state, "correlation_id", None)


__all__ = ["get_org_id", "get_org_id_required", "get_correlation_id"]
