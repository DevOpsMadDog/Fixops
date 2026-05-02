"""Org Hierarchy Router — ALDECI (GAP-005).

Endpoints for the Org Hierarchy engine.

Prefix: /api/v1/orgs
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/orgs                                   create_org
  GET    /api/v1/orgs/{pk}/children                     list_children
  GET    /api/v1/orgs/{pk}/ancestors                    get_ancestors
  POST   /api/v1/orgs/{pk}/policies                     attach_policy
  POST   /api/v1/orgs/{pk}/waivers                      attach_waiver
  GET    /api/v1/orgs/{pk}/effective-policies           effective_policies
  GET    /api/v1/orgs/{pk}/effective-waivers            effective_waivers
  PUT    /api/v1/orgs/{pk}/parent                       move_org
  DELETE /api/v1/orgs/{pk}                              delete_org
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/orgs",
    tags=["Org Hierarchy"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.org_hierarchy_engine import OrgHierarchyEngine
        _engine = OrgHierarchyEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class OrgCreate(BaseModel):
    name: str = Field(..., description="Human-readable org name")
    parent_org_id: Optional[str] = Field(
        default=None, description="Parent org surrogate id (None for root)"
    )


class PolicyAttach(BaseModel):
    policy_ref: str = Field(..., description="Policy identifier / ref")


class WaiverAttach(BaseModel):
    waiver_ref: str = Field(..., description="Waiver identifier / ref")


class ParentUpdate(BaseModel):
    new_parent_id: Optional[str] = Field(
        default=None, description="New parent surrogate id (None to promote to root)"
    )


# ---------------------------------------------------------------------------
# CRUD / traversal
# ---------------------------------------------------------------------------


@router.post("", dependencies=[Depends(api_key_auth)], status_code=201)
def create_org(
    body: OrgCreate,
    org_id: str = Query(..., description="Tenant ID"),
) -> Dict[str, Any]:
    """Create an organisation node."""
    try:
        return _get_engine().create_org(
            org_id=org_id, name=body.name, parent_org_id=body.parent_org_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{pk}/children", dependencies=[Depends(api_key_auth)])
def list_children(
    pk: str,
    org_id: str = Query(..., description="Tenant ID"),
    depth: int = Query(default=5, ge=1, le=50, description="Max BFS depth"),
) -> List[Dict[str, Any]]:
    """BFS — list descendants up to the given depth."""
    try:
        return _get_engine().list_children(org_id, pk, depth=depth)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{pk}/ancestors", dependencies=[Depends(api_key_auth)])
def get_ancestors(
    pk: str,
    org_id: str = Query(..., description="Tenant ID"),
) -> List[Dict[str, Any]]:
    """Walk up — return ancestors, immediate parent first."""
    try:
        return _get_engine().get_ancestors(org_id, pk)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{pk}/policies", dependencies=[Depends(api_key_auth)], status_code=201
)
def attach_policy(
    pk: str,
    body: PolicyAttach,
    org_id: str = Query(..., description="Tenant ID"),
) -> Dict[str, Any]:
    """Attach a policy ref to an org node (idempotent)."""
    try:
        return _get_engine().attach_policy(org_id, pk, body.policy_ref)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/{pk}/waivers", dependencies=[Depends(api_key_auth)], status_code=201
)
def attach_waiver(
    pk: str,
    body: WaiverAttach,
    org_id: str = Query(..., description="Tenant ID"),
) -> Dict[str, Any]:
    """Attach a waiver ref to an org node (idempotent)."""
    try:
        return _get_engine().attach_waiver(org_id, pk, body.waiver_ref)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{pk}/effective-policies", dependencies=[Depends(api_key_auth)])
def effective_policies(
    pk: str,
    org_id: str = Query(..., description="Tenant ID"),
) -> List[Dict[str, Any]]:
    """Return union of own + inherited policies from all ancestors."""
    try:
        return _get_engine().effective_policies(org_id, pk)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{pk}/effective-waivers", dependencies=[Depends(api_key_auth)])
def effective_waivers(
    pk: str,
    org_id: str = Query(..., description="Tenant ID"),
) -> List[Dict[str, Any]]:
    """Return union of own + inherited waivers from all ancestors."""
    try:
        return _get_engine().effective_waivers(org_id, pk)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/{pk}/parent", dependencies=[Depends(api_key_auth)])
def move_org(
    pk: str,
    body: ParentUpdate,
    org_id: str = Query(..., description="Tenant ID"),
) -> Dict[str, Any]:
    """Re-parent an org, with cycle detection."""
    try:
        return _get_engine().move_org(org_id, pk, body.new_parent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{pk}", dependencies=[Depends(api_key_auth)])
def delete_org(
    pk: str,
    org_id: str = Query(..., description="Tenant ID"),
    cascade: bool = Query(
        default=False, description="If True, cascades to delete all descendants"
    ),
) -> Dict[str, Any]:
    """Delete an org (optionally cascade to descendants)."""
    try:
        return _get_engine().delete_org(org_id, pk, cascade=cascade)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats/summary", dependencies=[Depends(api_key_auth)])
def stats(
    org_id: Optional[str] = Query(default=None, description="Tenant filter"),
) -> Dict[str, Any]:
    """Return platform-wide or per-tenant stats."""
    return _get_engine().stats(org_id)
