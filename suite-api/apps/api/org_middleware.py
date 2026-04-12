"""
Org ID middleware and context variable for multi-tenancy.

Every authenticated request carries an ``org_id`` that scopes all database
reads and writes to a single tenant.  This module provides:

1. ``OrgIdMiddleware`` — Starlette middleware that extracts ``org_id`` from
   the authenticated request and stores it in a ``ContextVar`` so that any
   code running in the same async task can retrieve it without passing the
   request object around.

2. ``get_current_org_id()`` — retrieve the current request's org_id from
   anywhere in the call stack (business logic, domain services, connectors).

3. ``get_org_id`` — FastAPI dependency (for use with ``Depends``) that reads
   org_id from the contextvar set by the middleware.

Source precedence (highest first):
    1. JWT claim ``org_id`` (set by auth layer into ``request.state.org_id``)
    2. ``X-Org-ID`` request header
    3. ``org_id`` query parameter
    4. Default: ``"default"`` (single-tenant / dev mode)

Usage::

    # In a FastAPI route:
    from apps.api.org_middleware import get_org_id
    from fastapi import Depends

    @router.get("/findings")
    async def list_findings(org: str = Depends(get_org_id)):
        return db.query(org_id=org)

    # In domain service code (no request object available):
    from apps.api.org_middleware import get_current_org_id

    def _record_audit(action: str) -> None:
        org = get_current_org_id()
        audit_log.write(org_id=org, action=action)
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Callable, Optional

import structlog
from fastapi import Header, Query, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)
_structlog = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# ContextVar — holds org_id for the duration of a single request task
# ---------------------------------------------------------------------------

_org_id_var: ContextVar[str] = ContextVar("org_id", default="default")


def get_current_org_id() -> str:
    """
    Return the org_id for the currently executing request.

    Safe to call from anywhere in the synchronous or async call stack that
    runs within a request handler.  Returns ``"default"`` if called outside
    a request context (e.g. background tasks, startup hooks).

    Returns:
        org_id string — never None, never empty.
    """
    return _org_id_var.get()


def set_current_org_id(org_id: str) -> None:
    """
    Explicitly set the org_id for the current task context.

    Normally called by ``OrgIdMiddleware``.  Can also be used in tests or
    background tasks that need to impersonate a specific org.

    Args:
        org_id: Organisation identifier string.
    """
    if not org_id or not org_id.strip():
        org_id = "default"
    _org_id_var.set(org_id.strip())


# ---------------------------------------------------------------------------
# Middleware — sets org_id contextvar on every request
# ---------------------------------------------------------------------------

class OrgIdMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that extracts and stores the org_id contextvar.

    Must be added to the FastAPI application **after** authentication
    middleware so that ``request.state.org_id`` (set by the auth layer)
    is available when this middleware runs.

    Middleware order in app.py (outer → inner, i.e. added last = runs first):
        app.add_middleware(CorrelationIdMiddleware)   # outermost
        app.add_middleware(SecurityHeadersMiddleware)
        app.add_middleware(RateLimitMiddleware)
        app.add_middleware(RequestLoggingMiddleware)
        app.add_middleware(OrgIdMiddleware)           # innermost — runs after auth

    Note: In Starlette, middleware added *last* wraps innermost, meaning it
    executes *first* in the request pipeline and *last* in the response
    pipeline.  To ensure org_id is available to all route handlers, add
    ``OrgIdMiddleware`` after all auth and correlation middleware.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        org_id = _extract_org_id(request)
        token = _org_id_var.set(org_id)
        # Also write back to request.state for middleware/handlers that read it there
        request.state.org_id = org_id

        # Bind org_id into structlog context so all log lines for this request
        # automatically carry the tenant identifier.
        _structlog.bind(org_id=org_id)

        # Sync TenantContext (thread-local) so core modules that use
        # TenantContext.get() see the correct org without async ContextVar.
        try:
            from core.tenant_isolation import TenantContext as _TenantContext
            _TenantContext.set(org_id)
        except ImportError:  # pragma: no cover
            pass  # tenant_isolation not available — graceful degradation

        try:
            response = await call_next(request)
        finally:
            # Reset the contextvar after the request completes so the context
            # does not leak into the next request handled by the same thread/task.
            _org_id_var.reset(token)

            # Clear TenantContext so the thread can be reused without stale org_id.
            try:
                from core.tenant_isolation import TenantContext as _TenantContext
                _TenantContext.clear()
            except ImportError:  # pragma: no cover
                pass

        return response


# ---------------------------------------------------------------------------
# Internal helper — org_id extraction logic
# ---------------------------------------------------------------------------

def _extract_org_id(request: Request) -> str:
    """
    Extract org_id from the request using the precedence chain.

    Precedence (highest first):
    1. ``request.state.org_id`` — set by auth layer from JWT claim
    2. ``X-Org-ID`` request header
    3. ``org_id`` query parameter
    4. Default: ``"default"``
    """
    # 1. JWT claim (set by _verify_api_key in app.py)
    state_org = getattr(request.state, "org_id", None)
    if state_org and str(state_org).strip():
        return str(state_org).strip()

    # 2. X-Org-ID header
    header_org = request.headers.get("X-Org-ID", "").strip()
    if header_org:
        return header_org

    # 3. org_id query parameter
    param_org = request.query_params.get("org_id", "").strip()
    if param_org:
        return param_org

    return "default"


# ---------------------------------------------------------------------------
# FastAPI dependency — preferred injection method for route handlers
# ---------------------------------------------------------------------------

def get_org_id(
    request: Request,
    org_id_param: Optional[str] = Query(
        None,
        alias="org_id",
        description="Organization ID (query parameter, overrides header)",
    ),
    x_org_id: Optional[str] = Header(
        None,
        alias="X-Org-ID",
        description="Organization ID (header)",
    ),
) -> str:
    """
    FastAPI dependency that returns the current request's org_id.

    Reads from the ContextVar set by OrgIdMiddleware (preferred) and falls
    back to direct extraction from query param / header if the middleware
    has not run (e.g. in unit tests that call the dependency directly).

    Usage::

        @router.get("/findings")
        async def list_findings(org: str = Depends(get_org_id)):
            ...

    Priority: contextvar (from JWT/middleware) > query param > header > default
    """
    # If the middleware ran, prefer the contextvar (already fully resolved)
    ctx_org = _org_id_var.get()
    if ctx_org and ctx_org != "default":
        return ctx_org

    # Direct fallback for test environments or routes that bypass middleware
    return org_id_param or x_org_id or _extract_org_id(request)


def get_org_id_required(
    request: Request,
    org_id_param: Optional[str] = Query(
        None,
        alias="org_id",
        description="Organization ID (required)",
    ),
    x_org_id: Optional[str] = Header(
        None,
        alias="X-Org-ID",
        description="Organization ID (required header)",
    ),
) -> str:
    """
    FastAPI dependency that requires a non-default org_id.

    Raises HTTP 400 if org_id resolves to ``"default"`` or is empty.
    Use this dependency on endpoints that must be tenant-scoped.

    Raises:
        HTTPException: 400 if org_id is not provided.
    """
    from fastapi import HTTPException

    resolved = get_org_id(request, org_id_param, x_org_id)
    if not resolved or resolved == "default":
        raise HTTPException(
            status_code=400,
            detail=(
                "org_id is required for this endpoint. "
                "Provide it via ?org_id= query parameter or X-Org-ID header."
            ),
        )
    return resolved


__all__ = [
    "OrgIdMiddleware",
    "get_current_org_id",
    "set_current_org_id",
    "get_org_id",
    "get_org_id_required",
]
