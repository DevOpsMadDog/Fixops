"""Multi-tenant RBAC API router.

Endpoints:
    POST   /api/v1/rbac/assign              — assign role to user
    DELETE /api/v1/rbac/revoke              — revoke role from user
    GET    /api/v1/rbac/users/{user_id}/roles  — roles for user in org
    GET    /api/v1/rbac/users/{user_id}/scopes — effective scopes for user
    POST   /api/v1/rbac/check               — check if user has scope
    GET    /api/v1/rbac/org/{org_id}/users  — list users in org
    GET    /api/v1/rbac/roles               — list all role definitions
    GET    /api/v1/rbac/audit               — query audit trail
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.rbac_engine import ROLES, RBACEngine
from types import SimpleNamespace

from fastapi import Depends, APIRouter, HTTPException, Query
from apps.api.dependencies import get_org_id  # SPEC-034
from apps.api.tenant_resolution import resolve_tenant
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rbac", tags=["rbac"])

# Module-level engine instance (SQLite-backed, safe to share)
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = RBACEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class AssignRoleRequest(BaseModel):
    user_id: str = Field(..., description="User identifier")
    role: str = Field(..., description="Role name to assign")
    org_id: str = Field(..., description="Organisation identifier")
    assigned_by: str = Field(default="system", description="Who is assigning the role")


class RevokeRoleRequest(BaseModel):
    user_id: str = Field(..., description="User identifier")
    role: str = Field(..., description="Role name to revoke")
    org_id: str = Field(..., description="Organisation identifier")


class CheckPermissionRequest(BaseModel):
    user_id: str = Field(..., description="User identifier")
    org_id: str = Field(..., description="Organisation identifier")
    scope: str = Field(..., description="Scope/permission string to check")


class CheckPermissionResponse(BaseModel):
    user_id: str
    org_id: str
    scope: str
    allowed: bool


class RoleListResponse(BaseModel):
    roles: Dict[str, Any] = Field(..., description="Role name → definition")


class AuditLogResponse(BaseModel):
    entries: List[Dict[str, Any]]
    count: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/assign",
    summary="Assign role to user",
    description="Assign a named ALDECI role to a user within an organisation.",
)
async def assign_role(
    body: AssignRoleRequest, credential_org: str = Depends(get_org_id)
) -> Dict[str, Any]:
    """Assign a role. Returns the assignment record."""
    tenant = resolve_tenant(credential_org, body)
    try:
        record = _get_engine().assign_role(
            user_id=body.user_id,
            role=body.role,
            org_id=tenant,
            assigned_by=body.assigned_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # Log the EFFECTIVE tenant. Recording the requested one makes the audit
    # trail disagree with the write it is auditing.
    logger.info("rbac assign: user=%s role=%s org=%s", body.user_id, body.role, tenant)
    return record


@router.delete(
    "/revoke",
    summary="Revoke role from user",
    description="Remove a role assignment for a user in an organisation.",
)
async def revoke_role(
    body: RevokeRoleRequest, credential_org: str = Depends(get_org_id)
) -> Dict[str, Any]:
    """Revoke a role. Returns status."""
    tenant = resolve_tenant(credential_org, body)
    revoked = _get_engine().revoke_role(
        user_id=body.user_id,
        role=body.role,
        org_id=tenant,
    )
    if not revoked:
        raise HTTPException(
            status_code=404,
            detail=f"No assignment found for user={body.user_id} role={body.role} org={tenant}",
        )
    # Echo the tenant that was ACTED ON, not the one that was asked for —
    # otherwise the response tells the caller a write happened somewhere it
    # did not.
    return {"status": "revoked", "user_id": body.user_id, "role": body.role, "org_id": tenant}


@router.get(
    "/users/{user_id}/roles",
    summary="Get user roles",
    description="List all roles assigned to a user within an organisation.",
)
async def get_user_roles(
    user_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    roles = _get_engine().get_user_roles(user_id=user_id, org_id=org_id)
    return {"user_id": user_id, "org_id": org_id, "roles": roles}


@router.get(
    "/users/{user_id}/scopes",
    summary="Get user effective scopes",
    description="Return all effective scopes for a user, including inherited ones.",
)
async def get_user_scopes(
    user_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    scopes = _get_engine().get_user_scopes(user_id=user_id, org_id=org_id)
    return {"user_id": user_id, "org_id": org_id, "scopes": scopes}


@router.post(
    "/check",
    response_model=CheckPermissionResponse,
    summary="Check permission",
    description="Verify whether a user has a given scope in an organisation.",
)
async def check_permission(
    body: CheckPermissionRequest, credential_org: str = Depends(get_org_id)
) -> CheckPermissionResponse:
    tenant = resolve_tenant(credential_org, body)
    allowed = _get_engine().check_permission(
        user_id=body.user_id,
        org_id=tenant,
        required_scope=body.scope,
    )
    return CheckPermissionResponse(
        user_id=body.user_id,
        org_id=tenant,
        scope=body.scope,
        allowed=allowed,
    )


@router.get(
    "/org/{org_id}/users",
    summary="List users in org",
    description="Return all user-role assignments for an organisation.",
)
async def list_org_users(
    org_id: str, credential_org: str = Depends(get_org_id)
) -> Dict[str, Any]:
    """List role assignments for an org.

    The org arrives as a PATH parameter here, which is the same trust problem as
    a body field wearing different clothes: any authenticated caller could name
    another tenant in the URL and read its entire role table — who is an admin,
    who can approve, who to target. resolve_tenant takes a caller-supplied value
    the same way regardless of where it came from, so the credential wins
    whenever it pins a real tenant.
    """
    tenant = resolve_tenant(credential_org, SimpleNamespace(org_id=org_id))
    users = _get_engine().list_users_in_org(org_id=tenant)
    return {"org_id": tenant, "users": users, "count": len(users)}


@router.get(
    "/roles",
    response_model=RoleListResponse,
    summary="List role definitions",
    description="Return all 6 ALDECI role definitions including scopes and inheritance.",
)
async def list_roles() -> RoleListResponse:
    return RoleListResponse(roles=ROLES)


@router.get(
    "/audit",
    response_model=AuditLogResponse,
    summary="Query audit trail",
    description="Retrieve RBAC access-check audit log entries.",
)
async def get_audit_log(
    user_id: Optional[str] = Query(default=None, description="Filter by user_id"),
    org_id: str = Depends(get_org_id),
    limit: int = Query(default=100, ge=1, le=1000, description="Max entries to return"),
) -> AuditLogResponse:
    entries = _get_engine().get_audit_log(user_id=user_id, org_id=org_id, limit=limit)
    return AuditLogResponse(entries=entries, count=len(entries))


__all__ = ["router"]
