"""Asset Tagging Router — ALDECI.

Endpoints for the Asset Tagging engine.

Prefix: /api/v1/asset-tags
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/asset-tags/tags                           create_tag
  GET   /api/v1/asset-tags/tags                           list_tags
  GET   /api/v1/asset-tags/tags/{tag_id}                  get_tag
  POST  /api/v1/asset-tags/assets                         register_asset
  GET   /api/v1/asset-tags/assets                         list_assets
  GET   /api/v1/asset-tags/assets/{asset_id}              get_asset
  POST  /api/v1/asset-tags/assets/{asset_id}/assign       assign_tag
  GET   /api/v1/asset-tags/assets/{asset_id}/tags         list_asset_tags
  POST  /api/v1/asset-tags/bulk-assign                    bulk_tag_assets
  GET   /api/v1/asset-tags/stats                          get_tag_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/asset-tags",
    tags=["Asset Tagging"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.asset_tagging_engine import AssetTaggingEngine
        _engine = AssetTaggingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TagCreate(BaseModel):
    tag_key: str = Field(..., description="Tag key (e.g. 'env', 'team')")
    tag_value: str = Field(..., description="Tag value (e.g. 'production', 'security')")
    tag_category: str = Field(
        default="environment",
        description=(
            "environment | criticality | data_classification | owner | "
            "compliance | technology | location | department"
        ),
    )
    description: str = Field(default="")


class AssetRegister(BaseModel):
    asset_id: Optional[str] = Field(default=None, description="Optional external asset ID")
    asset_name: str = Field(..., description="Human-readable asset name")
    asset_type: str = Field(
        default="server",
        description=(
            "server | workstation | network | application | database | "
            "cloud | iot | mobile | container"
        ),
    )
    criticality: str = Field(
        default="medium",
        description="mission_critical | high | medium | low",
    )
    owner: str = Field(default="")
    environment: str = Field(default="")


class AssignTagRequest(BaseModel):
    tag_id: str = Field(..., description="ID of the tag to assign")
    assigned_by: str = Field(default="system")


class BulkAssignRequest(BaseModel):
    asset_ids: List[str] = Field(..., description="List of asset_ids to tag")
    tag_id: str = Field(..., description="Tag ID to assign to all assets")
    assigned_by: str = Field(default="system")


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

@router.post("/tags", dependencies=[Depends(api_key_auth)], status_code=201)
def create_tag(
    body: TagCreate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a new asset tag."""
    try:
        return _get_engine().create_tag(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/tags", dependencies=[Depends(api_key_auth)])
def list_tags(
    org_id: str = Query(..., description="Organization ID"),
    tag_category: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List tags with optional category filter."""
    return _get_engine().list_tags(org_id, tag_category=tag_category)


@router.get("/tags/{tag_id}", dependencies=[Depends(api_key_auth)])
def get_tag(
    tag_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single tag by ID."""
    tag = _get_engine().get_tag(org_id, tag_id)
    if tag is None:
        raise HTTPException(status_code=404, detail=f"Tag '{tag_id}' not found")
    return tag


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

@router.post("/assets", dependencies=[Depends(api_key_auth)], status_code=201)
def register_asset(
    body: AssetRegister,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Register a new asset."""
    try:
        return _get_engine().register_asset(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_assets(
    org_id: str = Query(..., description="Organization ID"),
    asset_type: Optional[str] = Query(default=None),
    criticality: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List assets with optional filters."""
    return _get_engine().list_assets(
        org_id,
        asset_type=asset_type,
        criticality=criticality,
        environment=environment,
    )


@router.get("/assets/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_asset(
    asset_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single asset by asset_id."""
    asset = _get_engine().get_asset(org_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return asset


# ---------------------------------------------------------------------------
# Assignments
# ---------------------------------------------------------------------------

@router.post("/assets/{asset_id}/assign", dependencies=[Depends(api_key_auth)], status_code=201)
def assign_tag(
    asset_id: str,
    body: AssignTagRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Assign a tag to an asset."""
    try:
        return _get_engine().assign_tag(
            org_id, asset_id, body.tag_id, assigned_by=body.assigned_by
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assets/{asset_id}/tags", dependencies=[Depends(api_key_auth)])
def list_asset_tags(
    asset_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """List all tags assigned to an asset."""
    return _get_engine().list_asset_tags(org_id, asset_id)


@router.post("/bulk-assign", dependencies=[Depends(api_key_auth)], status_code=201)
def bulk_tag_assets(
    body: BulkAssignRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """Assign a tag to multiple assets at once."""
    return _get_engine().bulk_tag_assets(
        org_id, body.asset_ids, body.tag_id, assigned_by=body.assigned_by
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_tag_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregated asset tagging statistics."""
    return _get_engine().get_tag_stats(org_id)
