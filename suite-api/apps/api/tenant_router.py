"""Tenant management API router.

Provides admin-level endpoints for multi-tenant data management:

    GET    /api/v1/tenants              — list all org directories (admin only)
    GET    /api/v1/tenants/current      — current request tenant info
    GET    /api/v1/tenants/{org_id}/stats — statistics for a specific tenant
    DELETE /api/v1/tenants/{org_id}     — delete all tenant data (admin only)

Security:
    All endpoints require API key authentication via ``_verify_api_key``.
    Destructive operations (DELETE) are additionally gated by admin scope.

Usage::

    # In app.py (already wired):
    from apps.api.tenant_router import router as tenant_router
    app.include_router(tenant_router, dependencies=[Depends(_verify_api_key)])
"""

from __future__ import annotations

import logging
from typing import Dict, List

from apps.api.dependencies import get_current_org_id, get_org_id
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class TenantListResponse(BaseModel):
    """Response model for the tenant list endpoint."""

    tenants: List[str] = Field(..., description="List of org_id strings")
    count: int = Field(..., description="Total number of tenants")


class TenantStatsResponse(BaseModel):
    """Response model for tenant statistics."""

    org_id: str = Field(..., description="Organisation identifier")
    data_dir: str = Field(..., description="Absolute path to tenant data directory")
    exists: bool = Field(..., description="Whether the tenant directory exists")
    databases: Dict[str, int] = Field(
        ..., description="Mapping of database filename → size in bytes"
    )
    total_size_bytes: int = Field(..., description="Total size of all tenant files")
    database_count: int = Field(..., description="Number of .db files")


class CurrentTenantResponse(BaseModel):
    """Response model for the current tenant info endpoint."""

    org_id: str = Field(..., description="Current request org_id")
    is_default: bool = Field(..., description="True if org_id is 'default' (dev mode)")


class DeleteTenantResponse(BaseModel):
    """Response model for tenant deletion."""

    org_id: str = Field(..., description="Deleted organisation identifier")
    status: str = Field(default="deleted", description="Deletion status")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/current",
    response_model=CurrentTenantResponse,
    summary="Current tenant info",
    description="Return the org_id for the currently authenticated request.",
)
async def get_current_tenant(
    org_id: str = Depends(get_org_id),
) -> CurrentTenantResponse:
    """Return information about the current request's tenant context."""
    return CurrentTenantResponse(
        org_id=org_id,
        is_default=(org_id == "default"),
    )


@router.get(
    "",
    response_model=TenantListResponse,
    summary="List all tenants",
    description="List all org directories. Requires admin access.",
)
async def list_tenants_endpoint(
    request: Request,
) -> TenantListResponse:
    """List all tenant org_id directories (admin only)."""
    _require_admin(request)

    from core.tenant_isolation import list_tenants

    tenants = list_tenants()
    logger.info("Admin listed tenants: count=%d", len(tenants))
    return TenantListResponse(tenants=tenants, count=len(tenants))


@router.get(
    "/{org_id}/stats",
    response_model=TenantStatsResponse,
    summary="Tenant statistics",
    description="Return database sizes and file counts for a specific tenant.",
)
async def get_tenant_stats_endpoint(
    org_id: str,
    request: Request,
) -> TenantStatsResponse:
    """Return statistics for the specified tenant's data directory."""
    _require_admin_or_self(request, org_id)

    from core.tenant_isolation import get_tenant_stats

    stats = get_tenant_stats(org_id)
    return TenantStatsResponse(**stats)


@router.delete(
    "/{org_id}",
    response_model=DeleteTenantResponse,
    summary="Delete tenant data",
    description=(
        "Permanently delete all data for the specified tenant. "
        "This operation is irreversible. Requires admin access."
    ),
)
async def delete_tenant_endpoint(
    org_id: str,
    request: Request,
) -> DeleteTenantResponse:
    """Delete all data for the specified tenant (admin only, irreversible)."""
    _require_admin(request)

    from core.tenant_isolation import delete_tenant_data

    try:
        delete_tenant_data(org_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Tenant '{org_id}' not found",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    logger.warning("Admin deleted tenant data: org_id=%s", org_id)
    return DeleteTenantResponse(org_id=org_id, status="deleted")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _is_platform_operator(request: Request) -> bool:
    """Is this an OPERATOR of the platform, rather than an admin of one tenant?

    admin:all is a globally-scoped permission, and self-service signup hands it
    to every new account: the first user of an org is made admin so they can
    administer THEIR org, and that role carries admin:all. Measured on a
    freshly-signed-up account:

        scopes ['admin:all']   role admin
        GET /api/v1/tenants/victim-corp/stats -> 200, victim's data dir returned

    So an org-scoped role was granting a cross-tenant permission — the same
    class of mistake as a Maven coordinate used where a groupId was meant. Every
    guard reading admin:all inherited it.

    An operator is a credential that is not pinned to a customer tenant: the
    FIXOPS_API_TOKEN path, which resolves to the unpinned "default" org and is
    what resolve_tenant already treats as allowed to name any tenant. A tenant
    admin holds admin:all for their own org and is not an operator.
    """
    scopes: List[str] = getattr(request.state, "user_scopes", [])
    if "admin:all" not in scopes:
        return False
    return _caller_org(request) in ("", "default")


def _caller_org(request: Request) -> str:
    """The tenant this request's CREDENTIAL belongs to.

    request.state first, contextvar second, and the order matters. The
    contextvar is populated by OrgIdMiddleware, which runs BEFORE the auth
    dependency that reads the JWT — so for a logged-in user it still holds
    "default" long after the real org is known. Measured inside this guard on a
    request from org-1bfc06f2…:

        get_current_org_id() -> 'default'
        request.state.org_id -> 'org-1bfc06f2-5026-4a10-8868-fd4cb8156c5c'

    Reading the contextvar made every JWT caller look like the unpinned operator
    AND broke the "own org" comparison below, which was matching 'default'
    against a real org id and never succeeding. The admin:all bypass was the
    only reason those endpoints answered at all.
    """
    state_org = (getattr(request.state, "org_id", "") or "").strip()
    if state_org:
        return state_org
    return (get_current_org_id() or "").strip()


def _require_admin(request: Request) -> None:
    """Raise HTTP 403 unless the caller is a platform operator."""
    if not _is_platform_operator(request):
        raise HTTPException(
            status_code=403,
            detail="platform operator credential required for this operation",
        )


def _require_admin_or_self(request: Request, resource_org_id: str) -> None:
    """Raise HTTP 403 unless the caller is admin OR accessing their own org."""
    if _is_platform_operator(request):
        return
    # Allow access to own org stats
    current_org = _caller_org(request)
    if current_org == resource_org_id:
        return
    raise HTTPException(
        status_code=403,
        detail="admin:all scope required or org_id must match current tenant",
    )


__all__ = ["router"]
