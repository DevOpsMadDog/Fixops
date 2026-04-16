"""Asset Group API Router — ALDECI.

Endpoints (all under /api/v1/asset-groups):

  Groups:
    POST   /groups                          — create group
    GET    /groups                          — list groups
    GET    /groups/{id}                     — get group with members + policies

  Members:
    POST   /groups/{id}/members             — add member
    DELETE /groups/{id}/members/{asset_id}  — remove member
    POST   /groups/{id}/bulk-members        — bulk add members

  Policies:
    POST   /groups/{id}/policies            — add policy
    POST   /groups/{id}/policies/{p_id}/toggle — toggle policy enabled

  Reverse lookup:
    GET    /assets/{asset_id}/groups        — groups containing this asset

  Stats:
    GET    /stats                           — group statistics

Auth: _verify_api_key
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/asset-groups", tags=["asset-groups"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.asset_group_engine import AssetGroupEngine
        _engine = AssetGroupEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateGroupRequest(BaseModel):
    group_name: str = Field(..., min_length=1)
    group_type: str = Field(default="functional")
    description: str = Field(default="")
    owner: str = Field(default="")
    criticality: str = Field(default="medium")


class AddMemberRequest(BaseModel):
    asset_id: str = Field(..., min_length=1)
    asset_type: str = Field(...)
    added_by: str = Field(default="")


class AddPolicyRequest(BaseModel):
    policy_name: str = Field(..., min_length=1)
    policy_type: str = Field(...)
    config: Dict[str, Any] = Field(default_factory=dict)


class BulkAddMembersRequest(BaseModel):
    asset_ids: List[str] = Field(..., min_length=1)
    asset_type: str = Field(...)
    added_by: str = Field(default="")


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

@router.post("/groups", summary="Create an asset group")
def create_group(req: CreateGroupRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().create_group(
            org_id=org_id,
            group_name=req.group_name,
            group_type=req.group_type,
            description=req.description,
            owner=req.owner,
            criticality=req.criticality,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/groups", summary="List asset groups")
def list_groups(
    group_type: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_groups(org_id, group_type=group_type, criticality=criticality)


@router.get("/groups/{group_id}", summary="Get group with members and policies")
def get_group(group_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    result = _get_engine().get_group(group_id, org_id)
    if not result:
        raise HTTPException(status_code=404, detail="Group not found")
    return result


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------

@router.post("/groups/{group_id}/members", summary="Add a member to a group")
def add_member(group_id: str, req: AddMemberRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().add_member(
            group_id=group_id,
            org_id=org_id,
            asset_id=req.asset_id,
            asset_type=req.asset_type,
            added_by=req.added_by,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/groups/{group_id}/members/{asset_id}", summary="Remove a member from a group")
def remove_member(group_id: str, asset_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().remove_member(group_id, org_id, asset_id)


@router.post("/groups/{group_id}/bulk-members", summary="Bulk add members to a group")
def bulk_add_members(group_id: str, req: BulkAddMembersRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().bulk_add_members(
            group_id=group_id,
            org_id=org_id,
            asset_ids=req.asset_ids,
            asset_type=req.asset_type,
            added_by=req.added_by,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@router.post("/groups/{group_id}/policies", summary="Add a policy to a group")
def add_policy(group_id: str, req: AddPolicyRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().add_policy(
            group_id=group_id,
            org_id=org_id,
            policy_name=req.policy_name,
            policy_type=req.policy_type,
            config=req.config,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post(
    "/groups/{group_id}/policies/{policy_id}/toggle",
    summary="Toggle policy enabled/disabled",
)
def toggle_policy(group_id: str, policy_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().toggle_policy(policy_id, group_id, org_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ---------------------------------------------------------------------------
# Reverse lookup
# ---------------------------------------------------------------------------

@router.get("/assets/{asset_id}/groups", summary="Get all groups containing an asset")
def get_asset_groups(asset_id: str, org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    return _get_engine().get_asset_groups(org_id, asset_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", summary="Group statistics")
def get_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_group_stats(org_id)
