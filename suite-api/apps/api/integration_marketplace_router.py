"""
Integration Marketplace REST API.

Endpoints for browsing, installing, configuring, and managing
integrations with external security tools, ticketing systems,
notification channels, cloud platforms, and more.

Prefix: /api/v1/integrations
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from core.marketplace import (
    InstalledApp,
    IntegrationCategory,
    Marketplace,
    MarketplaceApp,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/integrations",
    tags=["integration-marketplace"],
    dependencies=[Depends(api_key_auth)],
)

# Module-level singleton — SQLite is thread-safe for concurrent reads
_marketplace = Marketplace()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class InstallRequest(BaseModel):
    """Request body for installing a marketplace app."""

    config: Dict[str, Any] = Field(
        default_factory=dict, description="App-specific configuration"
    )
    installed_by: str = Field(
        ..., min_length=1, description="User or service account performing install"
    )


class UpdateConfigRequest(BaseModel):
    """Request body for updating installed app configuration."""

    config: Dict[str, Any] = Field(..., description="Updated configuration dict")


class RateAppRequest(BaseModel):
    """Request body for rating an app."""

    user_id: str = Field(..., min_length=1)
    score: float = Field(..., ge=1.0, le=5.0, description="Rating between 1.0 and 5.0")
    comment: Optional[str] = Field(None, description="Optional review comment")


class RegisterCustomAppRequest(BaseModel):
    """Request body for registering a custom/private integration."""

    id: str = Field(..., min_length=1, description="Unique slug for this app")
    name: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    category: IntegrationCategory
    version: str = Field(default="1.0")
    author: str = Field(..., min_length=1)
    icon_url: Optional[str] = None
    config_schema: Dict[str, Any] = Field(default_factory=dict)
    required_scopes: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/apps",
    response_model=List[MarketplaceApp],
    summary="List available integrations",
)
async def list_apps(
    category: Optional[IntegrationCategory] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Text search on name and description"),
    org_id: str = Depends(get_org_id),
) -> List[MarketplaceApp]:
    """Browse the integration marketplace catalog.

    Returns all public integrations plus any private apps registered by this org.
    Optionally filter by category or text search.
    """
    return _marketplace.list_apps(category=category, search=search, org_id=org_id)


@router.get(
    "/apps/{app_id}",
    response_model=MarketplaceApp,
    summary="Get integration details",
)
async def get_app(app_id: str) -> MarketplaceApp:
    """Return full details for a specific integration."""
    app = _marketplace.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail=f"App '{app_id}' not found")
    return app


@router.post(
    "/apps/{app_id}/install",
    response_model=InstalledApp,
    status_code=201,
    summary="Install an integration",
)
async def install_app(
    app_id: str,
    body: InstallRequest,
    org_id: str = Depends(get_org_id),
) -> InstalledApp:
    """Install a marketplace integration for the current organization.

    The configuration provided must satisfy the app's ``config_schema``.
    Returns the created ``InstalledApp`` record.
    """
    try:
        return _marketplace.install_app(
            app_id=app_id,
            org_id=org_id,
            config=body.config,
            installed_by=body.installed_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.delete(
    "/apps/{app_id}/install",
    status_code=204,
    summary="Uninstall an integration",
)
async def uninstall_app(
    app_id: str,
    org_id: str = Depends(get_org_id),
) -> None:
    """Remove an installed integration from the current organization."""
    removed = _marketplace.uninstall_app(app_id=app_id, org_id=org_id)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"App '{app_id}' is not installed for this organization",
        )


@router.patch(
    "/apps/{app_id}/config",
    response_model=InstalledApp,
    summary="Update integration configuration",
)
async def update_config(
    app_id: str,
    body: UpdateConfigRequest,
    org_id: str = Depends(get_org_id),
) -> InstalledApp:
    """Update configuration settings for an already-installed integration."""
    try:
        return _marketplace.update_config(
            app_id=app_id, org_id=org_id, config=body.config
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/installed",
    response_model=List[InstalledApp],
    summary="List installed integrations",
)
async def list_installed(org_id: str = Depends(get_org_id)) -> List[InstalledApp]:
    """Return all integrations currently installed by this organization."""
    return _marketplace.list_installed(org_id=org_id)


@router.get(
    "/apps/{app_id}/health",
    summary="Check installed integration health",
)
async def get_app_health(
    app_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Perform a lightweight health check on an installed integration.

    Validates that required configuration fields are present and the app is
    active. Returns a health report with status and details.
    """
    try:
        return _marketplace.get_app_health(app_id=app_id, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/apps/{app_id}/rate",
    summary="Rate an integration",
)
async def rate_app(
    app_id: str,
    body: RateAppRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Submit or update a rating for a marketplace integration.

    Each user can rate an app once per organization; re-submitting updates
    the existing rating. Returns the new average rating.
    """
    try:
        return _marketplace.rate_app(
            app_id=app_id,
            org_id=org_id,
            user_id=body.user_id,
            score=body.score,
            comment=body.comment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/apps",
    response_model=MarketplaceApp,
    status_code=201,
    summary="Register a custom integration",
)
async def register_custom_app(
    body: RegisterCustomAppRequest,
    org_id: str = Depends(get_org_id),
) -> MarketplaceApp:
    """Register a private/custom integration visible only to this organization.

    Useful for internal tools or custom webhook receivers not in the public catalog.
    """
    app = MarketplaceApp(
        id=body.id,
        name=body.name,
        description=body.description,
        category=body.category,
        version=body.version,
        author=body.author,
        icon_url=body.icon_url,
        config_schema=body.config_schema,
        required_scopes=body.required_scopes,
        install_count=0,
        rating=0.0,
        org_id=org_id,
    )
    try:
        return _marketplace.register_custom_app(app)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/categories",
    response_model=List[str],
    summary="List integration categories",
)
async def list_categories() -> List[str]:
    """Return all available integration category names."""
    return [c.value for c in IntegrationCategory]


@router.get(
    "/catalog/stats",
    summary="Integration catalog statistics",
)
async def catalog_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return aggregate statistics for the integration catalog.

    Includes total app count, per-category breakdown, total install count
    across all catalog apps, the average rating, and the most-installed app.
    Private apps registered by this org are included in the counts.
    """
    return _marketplace.get_catalog_stats(org_id=org_id)
