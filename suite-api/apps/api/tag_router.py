"""Unified Tag Management API Router.

Endpoints for creating, listing, updating, deleting, applying, and searching
tags across all ALDECI entity types (findings, assets, vendors, incidents,
SBOMs, evidence, reports).

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.tag_manager import (
    AutoTagRule,
    EntityType,
    Tag,
    TagManager,
    get_tag_manager,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tags", tags=["tags"])


def _mgr() -> TagManager:
    return get_tag_manager()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CreateTagRequest(BaseModel):
    name: str = Field(..., description="Tag name")
    color: str = Field("#6B7280", description="Hex color code (e.g. #FF0000)")
    description: str = Field("", description="Optional description")
    parent_id: Optional[str] = Field(None, description="Parent tag ID for hierarchy")
    org_id: str = Field("default", description="Organisation ID")


class UpdateTagRequest(BaseModel):
    name: Optional[str] = None
    color: Optional[str] = None
    description: Optional[str] = None
    parent_id: Optional[str] = None


class ApplyTagRequest(BaseModel):
    entity_type: EntityType = Field(..., description="Entity type")
    entity_id: str = Field(..., description="Entity ID")
    tag_id: str = Field(..., description="Tag ID to apply")


class RemoveTagRequest(BaseModel):
    entity_type: EntityType = Field(..., description="Entity type")
    entity_id: str = Field(..., description="Entity ID")
    tag_id: str = Field(..., description="Tag ID to remove")


class BulkApplyRequest(BaseModel):
    entity_type: EntityType = Field(..., description="Entity type")
    entity_ids: List[str] = Field(..., description="List of entity IDs")
    tag_ids: List[str] = Field(..., description="List of tag IDs to apply")


class CreateAutoRuleRequest(BaseModel):
    name: str = Field(..., description="Rule name")
    conditions: Dict[str, Any] = Field(default_factory=dict, description="Conditions dict")
    tags_to_apply: List[str] = Field(default_factory=list, description="Tag IDs to apply")
    entity_type: EntityType = Field(..., description="Entity type this rule applies to")
    enabled: bool = Field(True, description="Whether the rule is active")
    org_id: str = Field("default", description="Organisation ID")


class MergeTagsRequest(BaseModel):
    source_tag_id: str = Field(..., description="Tag to merge from (will be deleted)")
    target_tag_id: str = Field(..., description="Tag to merge into (will be kept)")


# ---------------------------------------------------------------------------
# Tag CRUD endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=Tag, status_code=201)
def create_tag(req: CreateTagRequest) -> Tag:
    """Create a new tag."""
    try:
        return _mgr().create_tag(
            name=req.name,
            color=req.color,
            description=req.description,
            parent_id=req.parent_id,
            org_id=req.org_id,
        )
    except Exception as exc:
        logger.exception("Failed to create tag: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("", response_model=List[Tag])
def list_tags(
    org_id: str = Query("default", description="Organisation ID"),
    parent_id: Optional[str] = Query(None, description="Filter by parent tag ID"),
) -> List[Tag]:
    """List tags for an organisation, optionally filtered by parent."""
    return _mgr().list_tags(org_id=org_id, parent_id=parent_id)


@router.get("/search", response_model=List[Tag])
def search_tags(
    q: str = Query(..., description="Search query"),
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Tag]:
    """Full-text search tags by name or description."""
    return _mgr().search_tags(query=q, org_id=org_id)


@router.get("/hierarchy", response_model=List[Dict[str, Any]])
def get_tag_hierarchy(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Dict[str, Any]]:
    """Return the full tag hierarchy as a tree."""
    return _mgr().get_tag_hierarchy(org_id=org_id)


@router.get("/analytics", response_model=Dict[str, Any])
def get_tag_analytics(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return tag analytics: most used, trending, usage by entity type."""
    return _mgr().get_tag_analytics(org_id=org_id)


@router.get("/entity/{entity_type}/{entity_id}", response_model=List[Tag])
def get_entity_tags(entity_type: EntityType, entity_id: str) -> List[Tag]:
    """Get all tags applied to a specific entity."""
    return _mgr().get_entity_tags(entity_type=entity_type, entity_id=entity_id)


@router.get("/{tag_id}", response_model=Tag)
def get_tag(tag_id: str) -> Tag:
    """Get a tag by ID."""
    tag = _mgr().get_tag(tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail=f"Tag {tag_id!r} not found")
    return tag


@router.put("/{tag_id}", response_model=Tag)
def update_tag(tag_id: str, req: UpdateTagRequest) -> Tag:
    """Update a tag's name, color, description, or parent."""
    updates = req.model_dump(exclude_none=True)
    tag = _mgr().update_tag(tag_id, updates)
    if not tag:
        raise HTTPException(status_code=404, detail=f"Tag {tag_id!r} not found")
    return tag


@router.delete("/{tag_id}", status_code=204)
def delete_tag(tag_id: str) -> None:
    """Delete a tag and cascade-remove it from all entities."""
    deleted = _mgr().delete_tag(tag_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Tag {tag_id!r} not found")


# ---------------------------------------------------------------------------
# Apply / remove / bulk
# ---------------------------------------------------------------------------

@router.post("/apply", status_code=204)
def apply_tag(req: ApplyTagRequest) -> None:
    """Apply a tag to an entity."""
    tag = _mgr().get_tag(req.tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail=f"Tag {req.tag_id!r} not found")
    _mgr().apply_tag(entity_type=req.entity_type, entity_id=req.entity_id, tag_id=req.tag_id)


@router.post("/remove", status_code=204)
def remove_tag(req: RemoveTagRequest) -> None:
    """Remove a tag from an entity."""
    _mgr().remove_tag(entity_type=req.entity_type, entity_id=req.entity_id, tag_id=req.tag_id)


@router.post("/bulk-apply", status_code=204)
def bulk_apply(req: BulkApplyRequest) -> None:
    """Apply one or more tags to multiple entities in a single call."""
    _mgr().bulk_apply(
        entity_type=req.entity_type,
        entity_ids=req.entity_ids,
        tag_ids=req.tag_ids,
    )


# ---------------------------------------------------------------------------
# Auto-tag rules
# ---------------------------------------------------------------------------

@router.post("/auto-rules", response_model=AutoTagRule, status_code=201)
def create_auto_rule(req: CreateAutoRuleRequest) -> AutoTagRule:
    """Create an auto-tagging rule."""
    rule = AutoTagRule(
        name=req.name,
        conditions=req.conditions,
        tags_to_apply=req.tags_to_apply,
        entity_type=req.entity_type,
        enabled=req.enabled,
        org_id=req.org_id,
    )
    return _mgr().create_auto_rule(rule)


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

@router.post("/merge", status_code=204)
def merge_tags(req: MergeTagsRequest) -> None:
    """Merge source tag into target tag. Source is deleted after merge."""
    for tag_id in (req.source_tag_id, req.target_tag_id):
        if not _mgr().get_tag(tag_id):
            raise HTTPException(status_code=404, detail=f"Tag {tag_id!r} not found")
    _mgr().merge_tags(source_tag_id=req.source_tag_id, target_tag_id=req.target_tag_id)
