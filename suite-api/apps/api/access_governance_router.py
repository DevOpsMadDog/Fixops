"""Access Governance Router — ALDECI.

IGA: entitlements, SoD violations, role management, certification campaigns.

Prefix: /api/v1/access-governance
Auth: api_key_auth

Routes:
  POST   /api/v1/access-governance/entitlements                    grant_entitlement
  POST   /api/v1/access-governance/entitlements/{id}/revoke        revoke_entitlement
  POST   /api/v1/access-governance/sod/detect                      detect_sod_violations
  POST   /api/v1/access-governance/violations/{id}/acknowledge      acknowledge_violation
  POST   /api/v1/access-governance/roles                           create_role
  POST   /api/v1/access-governance/roles/{id}/assign               assign_role_to_user
  GET    /api/v1/access-governance/users/{user_id}/entitlements     get_user_entitlements
  GET    /api/v1/access-governance/expiring                         get_expiring_entitlements
  GET    /api/v1/access-governance/summary                          get_access_summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/access-governance",
    tags=["Access Governance"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.access_governance_engine import AccessGovernanceEngine
        _engine = AccessGovernanceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class GrantEntitlementRequest(BaseModel):
    user_id: str = Field(..., description="User to grant access to")
    resource_id: str = Field(..., description="Resource identifier")
    resource_type: str = Field(
        ...,
        description=(
            "application | database | server | network | "
            "cloud-service | api | data-store | vault"
        ),
    )
    access_level: str = Field(
        ...,
        description="read | write | admin | execute | delete | full-control",
    )
    granted_by: str = Field(default="", description="Approver username")
    expires_at: Optional[str] = Field(
        default=None, description="ISO 8601 expiry timestamp (optional)"
    )


class SodRule(BaseModel):
    rule_name: str
    entitlement_ids: List[str]
    severity: str = "medium"


class DetectSodRequest(BaseModel):
    user_id: str = Field(..., description="User ID to check")
    sod_rules: List[SodRule] = Field(..., description="List of SoD rules to evaluate")


class AcknowledgeViolationRequest(BaseModel):
    acknowledged_by: str = Field(..., description="Who acknowledged the violation")


class CreateRoleRequest(BaseModel):
    role_name: str = Field(..., description="Unique role name")
    role_type: str = Field(
        ...,
        description="business | technical | privileged | service-account | emergency",
    )
    permissions: List[str] = Field(
        default_factory=list, description="List of permission strings"
    )
    owner: str = Field(default="", description="Role owner")
    risk_level: str = Field(
        default="medium", description="critical | high | medium | low"
    )


class AssignRoleRequest(BaseModel):
    user_id: str = Field(..., description="User ID to assign role to")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_access_governance(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get access governance summary for the org."""
    return _get_engine().get_access_summary(org_id)


@router.post("/entitlements", dependencies=[Depends(api_key_auth)])
def grant_entitlement(
    req: GrantEntitlementRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Grant an entitlement to a user for a resource."""
    try:
        return _get_engine().grant_entitlement(
            org_id=org_id,
            user_id=req.user_id,
            resource_id=req.resource_id,
            resource_type=req.resource_type,
            access_level=req.access_level,
            granted_by=req.granted_by,
            expires_at=req.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/entitlements/{entitlement_id}/revoke", dependencies=[Depends(api_key_auth)])
def revoke_entitlement(
    entitlement_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Revoke an entitlement by ID."""
    try:
        return _get_engine().revoke_entitlement(entitlement_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/sod/detect", dependencies=[Depends(api_key_auth)])
def detect_sod_violations(
    req: DetectSodRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """Detect SoD violations for a user against provided rules."""
    rules = [r.model_dump() for r in req.sod_rules]
    return _get_engine().detect_sod_violations(
        org_id=org_id,
        user_id=req.user_id,
        sod_rules=rules,
    )


@router.post("/violations/{violation_id}/acknowledge", dependencies=[Depends(api_key_auth)])
def acknowledge_violation(
    violation_id: str,
    req: AcknowledgeViolationRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Acknowledge a SoD violation."""
    try:
        return _get_engine().acknowledge_violation(
            violation_id=violation_id,
            org_id=org_id,
            acknowledged_by=req.acknowledged_by,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/roles", dependencies=[Depends(api_key_auth)])
def create_role(
    req: CreateRoleRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a new role definition."""
    try:
        return _get_engine().create_role(
            org_id=org_id,
            role_name=req.role_name,
            role_type=req.role_type,
            permissions=req.permissions,
            owner=req.owner,
            risk_level=req.risk_level,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/roles/{role_id}/assign", dependencies=[Depends(api_key_auth)])
def assign_role_to_user(
    role_id: str,
    req: AssignRoleRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Assign a role to a user (increments user_count, grants permissions)."""
    try:
        return _get_engine().assign_role_to_user(
            role_id=role_id,
            org_id=org_id,
            user_id=req.user_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/users/{user_id}/entitlements", dependencies=[Depends(api_key_auth)])
def get_user_entitlements(
    user_id: str,
    org_id: str = Query(..., description="Organization ID"),
    status: Optional[str] = Query(
        default=None, description="Filter: active | revoked | expired"
    ),
) -> List[Dict[str, Any]]:
    """Return all entitlements for a user."""
    return _get_engine().get_user_entitlements(
        org_id=org_id, user_id=user_id, status=status
    )


@router.get("/expiring", dependencies=[Depends(api_key_auth)])
def get_expiring_entitlements(
    org_id: str = Query(..., description="Organization ID"),
    days_ahead: int = Query(
        default=30, ge=1, description="Look-ahead window in days"
    ),
) -> List[Dict[str, Any]]:
    """Return active entitlements expiring within days_ahead days."""
    return _get_engine().get_expiring_entitlements(
        org_id=org_id, days_ahead=days_ahead
    )


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_access_summary(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return access governance summary statistics."""
    return _get_engine().get_access_summary(org_id)
