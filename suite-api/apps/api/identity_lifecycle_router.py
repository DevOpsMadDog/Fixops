"""Identity Lifecycle Router — ALDECI.

Manages identity provisioning, deprovisioning, suspension, and entitlements.

Prefix: /api/v1/identity-lifecycle
Auth: api_key_auth dependency

Routes:
  POST /api/v1/identity-lifecycle/accounts                        provision_account
  GET  /api/v1/identity-lifecycle/accounts                        list_accounts
  GET  /api/v1/identity-lifecycle/accounts/{account_id}           get_account
  POST /api/v1/identity-lifecycle/accounts/{account_id}/deprovision  deprovision_account
  POST /api/v1/identity-lifecycle/accounts/{account_id}/suspend      suspend_account
  POST /api/v1/identity-lifecycle/accounts/{account_id}/reactivate   reactivate_account
  POST /api/v1/identity-lifecycle/accounts/{account_id}/access       grant_access
  POST /api/v1/identity-lifecycle/entitlements/{ent_id}/revoke       revoke_access
  GET  /api/v1/identity-lifecycle/orphans                         get_orphan_accounts
  GET  /api/v1/identity-lifecycle/summary                         get_entitlement_summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/identity-lifecycle",
    tags=["Identity Lifecycle"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.identity_lifecycle_engine import IdentityLifecycleEngine
        _engine = IdentityLifecycleEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class ProvisionAccountBody(BaseModel):
    username: str = Field(..., description="Unique username for the account")
    display_name: str = Field(default="", description="Human-readable display name")
    email: str = Field(default="", description="Email address")
    account_type: str = Field(
        default="employee",
        description="employee | contractor | service | system | bot | vendor | temp",
    )
    department: str = Field(default="", description="Department or team")
    manager: str = Field(default="", description="Manager username or ID")


class DeprovisionBody(BaseModel):
    performed_by: str = Field(default="", description="User performing the action")


class SuspendBody(BaseModel):
    performed_by: str = Field(default="", description="User performing the action")


class ReactivateBody(BaseModel):
    performed_by: str = Field(default="", description="User performing the action")


class GrantAccessBody(BaseModel):
    system_name: str = Field(..., description="Target system name")
    role: str = Field(..., description="Role to grant")
    access_level: str = Field(default="read", description="read | write | admin | owner")
    expires_at: str = Field(default="", description="ISO datetime for expiry (empty = never)")
    granted_by: str = Field(default="", description="Approver username or ID")


class RevokeEntitlementBody(BaseModel):
    performed_by: str = Field(default="", description="User performing revocation")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/")
def list_identity_lifecycle(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get identity lifecycle entitlement summary for the org."""
    return _get_engine().get_entitlement_summary(org_id)


@router.post("/accounts")
def provision_account(
    body: ProvisionAccountBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Provision a new identity account."""
    try:
        return _get_engine().provision_account(
            org_id=org_id,
            username=body.username,
            display_name=body.display_name,
            email=body.email,
            account_type=body.account_type,
            department=body.department,
            manager=body.manager,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/accounts")
def list_accounts(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    department: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List identity accounts, optionally filtered by status and department."""
    return _get_engine().list_accounts(org_id, status=status, department=department)


@router.get("/accounts/{account_id}")
def get_account(
    account_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Fetch a single account with events and active entitlements."""
    result = _get_engine().get_account(account_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return result


@router.post("/accounts/{account_id}/deprovision")
def deprovision_account(
    account_id: str,
    body: DeprovisionBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Deprovision an account and revoke all entitlements."""
    try:
        return _get_engine().deprovision_account(account_id, org_id, body.performed_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/accounts/{account_id}/suspend")
def suspend_account(
    account_id: str,
    body: SuspendBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Suspend an identity account."""
    try:
        return _get_engine().suspend_account(account_id, org_id, body.performed_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/accounts/{account_id}/reactivate")
def reactivate_account(
    account_id: str,
    body: ReactivateBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Reactivate a suspended or deprovisioned account."""
    try:
        return _get_engine().reactivate_account(account_id, org_id, body.performed_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/accounts/{account_id}/access")
def grant_access(
    account_id: str,
    body: GrantAccessBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Grant a system access entitlement to an account."""
    try:
        return _get_engine().grant_access(
            account_id=account_id,
            org_id=org_id,
            system_name=body.system_name,
            role=body.role,
            access_level=body.access_level,
            expires_at=body.expires_at,
            granted_by=body.granted_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/entitlements/{entitlement_id}/revoke")
def revoke_access(
    entitlement_id: str,
    body: RevokeEntitlementBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Revoke a specific access entitlement."""
    try:
        return _get_engine().revoke_access(entitlement_id, org_id, body.performed_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/orphans")
def get_orphan_accounts(
    org_id: str = Query(default="default"),
    days_inactive: int = Query(default=90, description="Inactivity threshold in days"),
) -> List[Dict[str, Any]]:
    """Return active accounts inactive for >= days_inactive days."""
    return _get_engine().get_orphan_accounts(org_id, days_inactive=days_inactive)


@router.get("/summary")
def get_entitlement_summary(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return aggregate identity and entitlement summary for the org."""
    return _get_engine().get_entitlement_summary(org_id)
