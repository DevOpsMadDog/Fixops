"""Cloud Identity Router — ALDECI.

Manages cloud identities, federated access, and cross-cloud permission analysis
via REST endpoints.

Prefix: /api/v1/cloud-identity

Endpoints:
  POST   /identities                          — Register a cloud identity
  GET    /identities                          — List identities (type, provider, privilege_level)
  GET    /identities/{id}                     — Get a single identity
  PUT    /identities/{id}/permissions         — Update permissions (recalculates privilege_level)
  POST   /reviews                             — Record an access review
  GET    /reviews                             — List reviews (identity_id, outcome)
  POST   /permission-changes                  — Record a permission change
  GET    /permission-changes                  — List permission changes (identity_id, approved)
  GET    /stats                               — Cloud identity statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-identity",
    tags=["cloud-identity"],
)


# ---------------------------------------------------------------------------
# Lazy engine loader
# ---------------------------------------------------------------------------


def _get_engine():
    try:
        from core.cloud_identity_engine import CloudIdentityEngine
        return CloudIdentityEngine()
    except ImportError as exc:
        logger.error("cloud_identity_engine import failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail=f"cloud_identity unavailable: {exc}",
        )


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterIdentityRequest(BaseModel):
    org_id: str = "default"
    identity_name: str
    identity_type: str = "user"
    cloud_provider: str = "aws"
    account_id: str = ""
    permissions: List[str] = []
    privilege_level: str = "none"
    is_federated: bool = False
    mfa_enabled: bool = False
    last_activity: Optional[str] = None


class UpdatePermissionsRequest(BaseModel):
    permissions: List[str]


class RecordAccessReviewRequest(BaseModel):
    org_id: str = "default"
    identity_id: str
    reviewer: str = ""
    review_type: str = "periodic"
    outcome: str = "no_action"
    findings: List[str] = []
    reviewed_at: Optional[str] = None


class RecordPermissionChangeRequest(BaseModel):
    org_id: str = "default"
    identity_id: str
    change_type: str = "grant"
    permission_name: str
    changed_by: str = ""
    changed_at: Optional[str] = None
    approved: bool = False


# ---------------------------------------------------------------------------
# Endpoints — Identities
# ---------------------------------------------------------------------------


@router.post("/identities", status_code=201)
def register_identity(body: RegisterIdentityRequest) -> Dict[str, Any]:
    """Register a new cloud identity."""
    engine = _get_engine()
    try:
        return engine.register_identity(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/identities")
def list_identities(
    org_id: str = Query(default="default"),
    identity_type: Optional[str] = Query(default=None),
    cloud_provider: Optional[str] = Query(default=None),
    privilege_level: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List cloud identities with optional filters."""
    engine = _get_engine()
    return engine.list_identities(
        org_id,
        identity_type=identity_type,
        cloud_provider=cloud_provider,
        privilege_level=privilege_level,
    )


@router.get("/identities/{identity_id}")
def get_identity(
    identity_id: str, org_id: str = Query(default="default")
) -> Dict[str, Any]:
    """Get a single cloud identity by ID."""
    engine = _get_engine()
    identity = engine.get_identity(org_id, identity_id)
    if identity is None:
        raise HTTPException(status_code=404, detail=f"Identity {identity_id!r} not found.")
    return identity


@router.put("/identities/{identity_id}/permissions")
def update_permissions(
    identity_id: str,
    body: UpdatePermissionsRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Update permissions for a cloud identity (recalculates privilege_level)."""
    engine = _get_engine()
    result = engine.update_permissions(org_id, identity_id, body.permissions)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Identity {identity_id!r} not found.")
    return result


# ---------------------------------------------------------------------------
# Endpoints — Access Reviews
# ---------------------------------------------------------------------------


@router.post("/reviews", status_code=201)
def record_access_review(body: RecordAccessReviewRequest) -> Dict[str, Any]:
    """Record an access review for a cloud identity."""
    engine = _get_engine()
    try:
        return engine.record_access_review(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/reviews")
def list_access_reviews(
    org_id: str = Query(default="default"),
    identity_id: Optional[str] = Query(default=None),
    outcome: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List access reviews with optional filters."""
    engine = _get_engine()
    return engine.list_access_reviews(org_id, identity_id=identity_id, outcome=outcome)


# ---------------------------------------------------------------------------
# Endpoints — Permission Changes
# ---------------------------------------------------------------------------


@router.post("/permission-changes", status_code=201)
def record_permission_change(body: RecordPermissionChangeRequest) -> Dict[str, Any]:
    """Record a permission change for a cloud identity."""
    engine = _get_engine()
    try:
        return engine.record_permission_change(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/permission-changes")
def list_permission_changes(
    org_id: str = Query(default="default"),
    identity_id: Optional[str] = Query(default=None),
    approved: Optional[bool] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List permission changes with optional filters."""
    engine = _get_engine()
    return engine.list_permission_changes(org_id, identity_id=identity_id, approved=approved)


# ---------------------------------------------------------------------------
# Endpoints — Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_cloud_identity_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregated cloud identity statistics."""
    engine = _get_engine()
    return engine.get_cloud_identity_stats(org_id)
