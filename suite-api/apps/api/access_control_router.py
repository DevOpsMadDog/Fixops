"""Access Control Router — ALDECI.

Policy management, grant lifecycle, and access check endpoints.

Prefix: /api/v1/access-control
Auth: api_key_auth dependency

Routes:
  POST  /api/v1/access-control/policies                  create_access_policy
  GET   /api/v1/access-control/policies                  list_access_policies
  GET   /api/v1/access-control/policies/{policy_id}      get_access_policy
  POST  /api/v1/access-control/grants                    grant_access
  GET   /api/v1/access-control/grants                    list_grants
  PUT   /api/v1/access-control/grants/{grant_id}/revoke  revoke_access
  GET   /api/v1/access-control/check                     check_access
  GET   /api/v1/access-control/stats                     get_access_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/access-control",
    tags=["Access Control"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.access_control_engine import AccessControlEngine
        _engine = AccessControlEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateAccessPolicyRequest(BaseModel):
    name: str = Field(..., description="Policy name")
    resource_type: str = Field(
        ..., description="file | api | database | network | application | service"
    )
    action: str = Field(..., description="read | write | execute | delete | admin")
    effect: str = Field(default="allow", description="allow | deny")
    conditions: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional policy conditions"
    )


class GrantAccessRequest(BaseModel):
    subject_id: str = Field(..., description="User or group receiving access")
    resource_id: str = Field(..., description="Resource being accessed")
    policy_id: str = Field(..., description="Policy governing this grant")
    granted_by: str = Field(..., description="User granting access")
    expires_at: Optional[str] = Field(
        default=None, description="ISO expiry timestamp (optional)"
    )


class RevokeAccessRequest(BaseModel):
    revoked_by: str = Field(..., description="User revoking access")
    reason: str = Field(default="", description="Reason for revocation")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/policies", dependencies=[Depends(api_key_auth)], status_code=201)
def create_access_policy(
    body: CreateAccessPolicyRequest,
    org_id: str = Query(default="default"),
):
    """Create a new access control policy."""
    try:
        from core.access_control_engine import AccessPolicyCreate
        return _get_engine().create_access_policy(
            org_id,
            AccessPolicyCreate(**body.model_dump()),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating access policy")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/policies", dependencies=[Depends(api_key_auth)])
def list_access_policies(
    org_id: str = Query(default="default"),
    resource_type: Optional[str] = Query(default=None),
    effect: Optional[str] = Query(default=None),
):
    """List access policies, optionally filtered by resource_type or effect."""
    return _get_engine().list_access_policies(
        org_id, resource_type=resource_type, effect=effect
    )


@router.get("/policies/{policy_id}", dependencies=[Depends(api_key_auth)])
def get_access_policy(
    policy_id: str,
    org_id: str = Query(default="default"),
):
    """Get a specific access policy by ID."""
    try:
        return _get_engine().get_access_policy(org_id, policy_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error fetching access policy")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/grants", dependencies=[Depends(api_key_auth)], status_code=201)
def grant_access(
    body: GrantAccessRequest,
    org_id: str = Query(default="default"),
):
    """Grant access to a subject for a resource."""
    try:
        from core.access_control_engine import GrantCreate
        return _get_engine().grant_access(
            org_id,
            GrantCreate(**body.model_dump()),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error granting access")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/grants", dependencies=[Depends(api_key_auth)])
def list_grants(
    org_id: str = Query(default="default"),
    subject_id: Optional[str] = Query(default=None),
    resource_id: Optional[str] = Query(default=None),
):
    """List grants, optionally filtered by subject or resource."""
    return _get_engine().list_grants(
        org_id, subject_id=subject_id, resource_id=resource_id
    )


@router.put("/grants/{grant_id}/revoke", dependencies=[Depends(api_key_auth)])
def revoke_access(
    grant_id: str,
    body: RevokeAccessRequest,
    org_id: str = Query(default="default"),
):
    """Revoke an active access grant."""
    try:
        return _get_engine().revoke_access(
            org_id, grant_id, body.revoked_by, body.reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error revoking access grant")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/check", dependencies=[Depends(api_key_auth)])
def check_access(
    org_id: str = Query(default="default"),
    subject_id: str = Query(..., description="Subject to check"),
    resource_id: str = Query(..., description="Resource to check"),
):
    """Check active grants for a subject+resource pair."""
    return _get_engine().check_access(org_id, subject_id, resource_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_access_stats(org_id: str = Query(default="default")):
    """Return access control overview stats."""
    return _get_engine().get_access_stats(org_id)


@router.get("/", dependencies=[Depends(api_key_auth)])
def get_access_control_status(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return access control engine health and summary stats."""
    try:
        stats = _get_engine().get_access_stats(org_id)
        return {
            "status": "healthy",
            "engine": "access-control",
            "org_id": org_id,
            "total_policies": stats.get("total_policies", 0),
            "active_grants": stats.get("active_grants", 0),
            "revoked_grants": stats.get("revoked_grants", 0),
            "expired_grants": stats.get("expired_grants", 0),
        }
    except Exception as exc:
        _logger.exception("Error fetching access control status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
