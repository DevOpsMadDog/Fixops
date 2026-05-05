"""
Access Control Matrix API endpoints.

Provides CRUD for access rules, access-check queries, ACL inspection,
effective-permission lookup, and access statistics.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from core.access_matrix import (
    AccessLevel,
    AccessMatrix,
    ResourceType,
    get_access_matrix,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/access-matrix", tags=["access-matrix"])


def _matrix() -> AccessMatrix:
    return get_access_matrix()


# ============================================================================
# Request / Response models
# ============================================================================


class GrantAccessRequest(BaseModel):
    role: str = Field(..., description="ALDECI role name")
    resource_type: ResourceType
    access_level: AccessLevel
    resource_id: Optional[str] = Field(None, description="None = all resources of type")
    conditions: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = "default"


class CheckAccessRequest(BaseModel):
    user_role: str
    resource_type: ResourceType
    resource_id: Optional[str] = None
    org_id: str = "default"


class CheckAccessResponse(BaseModel):
    user_role: str
    resource_type: str
    resource_id: Optional[str]
    access_level: str
    granted: bool
    org_id: str


# ============================================================================
# Endpoints
# ============================================================================


@router.get("/", response_model=Dict[str, Any])
async def index(org_id: str = Query("default")):
    """Access Matrix index — returns stats and available resource types."""
    stats = _matrix().get_access_stats(org_id=org_id)
    return {
        "service": "access-matrix",
        "org_id": org_id,
        "resource_types": [rt.value for rt in ResourceType],
        "stats": stats,
    }


@router.post("/rules", response_model=Dict[str, Any], status_code=201)
async def grant_access(body: GrantAccessRequest):
    """Grant access: create or replace an access rule."""
    rule = _matrix().grant_access(
        role=body.role,
        resource_type=body.resource_type,
        access_level=body.access_level,
        resource_id=body.resource_id,
        conditions=body.conditions,
        org_id=body.org_id,
    )
    return rule.to_dict()


@router.delete("/rules/{rule_id}")
async def revoke_access(rule_id: str):
    """Revoke an access rule by ID."""
    deleted = _matrix().revoke_access(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return {"deleted": True, "rule_id": rule_id}


@router.get("/rules", response_model=Dict[str, Any])
async def list_rules(
    role: Optional[str] = None,
    resource_type: Optional[ResourceType] = None,
    org_id: Optional[str] = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List access rules with optional filtering."""
    rules = _matrix().list_rules(
        role=role,
        resource_type=resource_type,
        org_id=org_id,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [r.to_dict() for r in rules],
        "total": len(rules),
        "limit": limit,
        "offset": offset,
    }


@router.post("/check", response_model=CheckAccessResponse)
async def check_access(body: CheckAccessRequest):
    """
    Check what access level a role has on a resource.

    Returns the resolved AccessLevel (none/read/write/admin/owner).
    """
    level = _matrix().check_access(
        user_role=body.user_role,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        org_id=body.org_id,
        audit=True,
    )
    return CheckAccessResponse(
        user_role=body.user_role,
        resource_type=body.resource_type.value,
        resource_id=body.resource_id,
        access_level=level.value,
        granted=(level != AccessLevel.NONE),
        org_id=body.org_id,
    )


@router.get("/permissions/{role}", response_model=Dict[str, Any])
async def get_effective_permissions(
    role: str,
    org_id: str = Query("default"),
):
    """Return all effective (wildcard) permissions for a role."""
    perms = _matrix().get_effective_permissions(user_role=role, org_id=org_id)
    return {
        "role": role,
        "org_id": org_id,
        "permissions": perms,
    }


@router.get("/acl/{resource_type}", response_model=Dict[str, Any])
async def get_resource_acl(
    resource_type: ResourceType,
    resource_id: Optional[str] = Query(None),
    org_id: str = Query("default"),
):
    """Return the ACL for a resource type (and optionally a specific resource ID)."""
    acl = _matrix().get_resource_acl(
        resource_type=resource_type,
        resource_id=resource_id,
        org_id=org_id,
    )
    return {
        "resource_type": resource_type.value,
        "resource_id": resource_id,
        "org_id": org_id,
        "acl": acl,
        "total": len(acl),
    }


@router.get("/stats", response_model=Dict[str, Any])
async def get_access_stats(org_id: str = Query("default")):
    """Return aggregated access-check statistics."""
    return _matrix().get_access_stats(org_id=org_id)


@router.get("/matrix", response_model=Dict[str, Any])
async def get_full_matrix(org_id: str = Query("default")):
    """
    Return the complete access matrix — all roles x all resource types.

    Useful for rendering a permissions grid in the UI.
    """
    matrix: Dict[str, Dict[str, str]] = {}
    for role in [
        "viewer",
        "developer",
        "security_analyst",
        "compliance_officer",
        "admin",
        "super_admin",
    ]:
        matrix[role] = _matrix().get_effective_permissions(
            user_role=role, org_id=org_id
        )
    return {
        "org_id": org_id,
        "roles": list(matrix.keys()),
        "resource_types": [rt.value for rt in ResourceType],
        "matrix": matrix,
    }
