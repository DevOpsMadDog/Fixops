"""
Playbook Marketplace API router.

Exposes 10 endpoints for publishing, browsing, installing, rating,
exporting and importing shareable security playbook templates.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

# Ensure suite-core is importable
_suite_core = Path(__file__).parent.parent.parent.parent / "suite-core"
if str(_suite_core) not in sys.path:
    sys.path.insert(0, str(_suite_core))

from core.playbook_marketplace import (
    PlaybookCategory,
    PlaybookMarketplace,
    PlaybookTemplate,
)

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/playbook-marketplace", tags=["playbook-marketplace"])

# Module-level singleton — one DB per process
_marketplace: Optional[PlaybookMarketplace] = None


def _get_marketplace() -> PlaybookMarketplace:
    global _marketplace
    if _marketplace is None:
        _marketplace = PlaybookMarketplace()
    return _marketplace


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class PublishRequest(BaseModel):
    name: str
    description: str
    category: PlaybookCategory
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    author: str = "community"
    version: str = "1.0.0"
    tags: List[str] = Field(default_factory=list)
    org_id: Optional[str] = None


class RateRequest(BaseModel):
    rating: float = Field(ge=1.0, le=5.0, description="Rating from 1.0 to 5.0")
    rater_id: str = "anonymous"


class ImportRequest(BaseModel):
    json_data: str = Field(description="Exported playbook JSON string")
    org_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/publish", status_code=status.HTTP_201_CREATED)
async def publish_playbook(request: PublishRequest) -> Dict[str, Any]:
    """Publish a new playbook template to the marketplace."""
    marketplace = _get_marketplace()
    template = PlaybookTemplate(**request.model_dump())
    try:
        result = marketplace.publish_playbook(template)
    except Exception as exc:
        _logger.exception("Failed to publish playbook")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return result


@router.get("/list")
async def list_playbooks(
    category: Optional[str] = Query(None, description="Filter by category: incident_response|remediation|compliance|hardening"),
    search: Optional[str] = Query(None, description="Full-text search on name and description"),
    tags: Optional[str] = Query(None, description="Comma-separated tag filter"),
) -> Dict[str, Any]:
    """Browse marketplace playbooks with optional filtering."""
    marketplace = _get_marketplace()
    tag_list: Optional[List[str]] = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    items = marketplace.list_playbooks(category=category, search=search, tags=tag_list)
    return {"items": items, "total": len(items)}


@router.get("/popular")
async def get_popular(
    limit: int = Query(10, ge=1, le=100, description="Number of results to return"),
) -> Dict[str, Any]:
    """Return the most-downloaded playbook templates."""
    marketplace = _get_marketplace()
    items = marketplace.get_popular(limit=limit)
    return {"items": items, "total": len(items)}


@router.get("/stats")
async def get_marketplace_stats() -> Dict[str, Any]:
    """Return aggregate marketplace statistics."""
    marketplace = _get_marketplace()
    return marketplace.get_marketplace_stats()


@router.get("/{playbook_id}")
async def get_playbook(playbook_id: str) -> Dict[str, Any]:
    """Get full details of a specific playbook template."""
    marketplace = _get_marketplace()
    tpl = marketplace.get_playbook(playbook_id)
    if not tpl:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Playbook not found: {playbook_id}")
    return tpl


@router.post("/{playbook_id}/install")
async def install_playbook(
    playbook_id: str,
    org_id: str = Query(..., description="Organisation ID to install into"),
) -> Dict[str, Any]:
    """Install a playbook template into an organisation."""
    marketplace = _get_marketplace()
    try:
        result = marketplace.install_playbook(playbook_id, org_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return result


@router.post("/{playbook_id}/rate")
async def rate_playbook(playbook_id: str, request: RateRequest) -> Dict[str, Any]:
    """Submit or update a rating for a playbook template."""
    marketplace = _get_marketplace()
    try:
        result = marketplace.rate_playbook(playbook_id, request.rating, request.rater_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return result


@router.get("/{playbook_id}/export")
async def export_playbook(playbook_id: str) -> Dict[str, Any]:
    """Export a playbook template as JSON."""
    marketplace = _get_marketplace()
    try:
        json_str = marketplace.export_playbook(playbook_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"playbook_id": playbook_id, "json_data": json_str}


@router.post("/import", status_code=status.HTTP_201_CREATED)
async def import_playbook(request: ImportRequest) -> Dict[str, Any]:
    """Import a playbook template from an exported JSON string."""
    marketplace = _get_marketplace()
    try:
        result = marketplace.import_playbook(request.json_data, request.org_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return result


@router.get("/installed/{org_id}")
async def get_installed(org_id: str) -> Dict[str, Any]:
    """Return all playbooks installed by an organisation."""
    marketplace = _get_marketplace()
    items = marketplace.get_installed(org_id)
    return {"org_id": org_id, "items": items, "total": len(items)}


__all__ = ["router"]
