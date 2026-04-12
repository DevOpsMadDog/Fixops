"""
Trust Center API — public-facing security/compliance page endpoints.

Provides 12 endpoints:
  PUBLIC (no auth):
    GET  /api/v1/trust/{org_id}/public          — full public trust page
    GET  /api/v1/trust/{org_id}/report          — downloadable security report

  ADMIN (auth required):
    POST /api/v1/trust/configure                — upsert trust page config
    GET  /api/v1/trust/{org_id}/config          — get current config
    GET  /api/v1/trust/{org_id}/stats           — aggregate trust stats

    POST /api/v1/trust/{org_id}/badges          — add compliance badge
    GET  /api/v1/trust/{org_id}/badges          — list badges
    DELETE /api/v1/trust/{org_id}/badges/{badge_id} — remove badge

    POST /api/v1/trust/{org_id}/controls        — add security control
    GET  /api/v1/trust/{org_id}/controls        — list controls
    DELETE /api/v1/trust/{org_id}/controls/{control_id} — remove control

    POST /api/v1/trust/{org_id}/subprocessors   — add sub-processor
    GET  /api/v1/trust/{org_id}/subprocessors   — list sub-processors
    DELETE /api/v1/trust/{org_id}/subprocessors/{entry_id} — remove entry
"""
from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from core.trust_center import (
    ComplianceBadge,
    SecurityControl,
    SubprocessorEntry,
    TrustCenterData,
    TrustCenterManager,
    TrustPageConfig,
)
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/trust", tags=["trust-center"])

# Process-wide manager (in-memory for default; override db_path for persistence)
_manager = TrustCenterManager()


def _get_manager() -> TrustCenterManager:
    """Return the shared TrustCenterManager instance."""
    return _manager


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------


class ConfigureRequest(BaseModel):
    org_name: str
    logo_url: Optional[str] = None
    brand_color: str = "#0066CC"
    enabled_sections: List[str] = ["compliance", "controls", "subprocessors"]
    custom_message: Optional[str] = None
    contact_email: Optional[str] = None


# ---------------------------------------------------------------------------
# PUBLIC endpoints — no auth required
# ---------------------------------------------------------------------------


@router.get("/{org_id}/public", response_model=TrustCenterData)
async def get_public_page(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> TrustCenterData:
    """Return full public trust center page for customers — no auth required."""
    page = mgr.get_public_page(org_id)
    if page is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trust center not configured for org '{org_id}'",
        )
    return page


@router.get("/{org_id}/report")
async def get_security_report(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> dict:
    """Return a downloadable security overview report — no auth required."""
    config = mgr.get_config(org_id)
    if config is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trust center not configured for org '{org_id}'",
        )
    return mgr.generate_security_report(org_id)


# ---------------------------------------------------------------------------
# ADMIN endpoints — auth required
# ---------------------------------------------------------------------------


@router.post("/configure", response_model=TrustPageConfig, dependencies=[Depends(api_key_auth)])
async def configure_trust_page(
    org_id: str,
    body: ConfigureRequest,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> TrustPageConfig:
    """Create or update the trust page configuration for an org."""
    config = TrustPageConfig(org_id=org_id, **body.model_dump())
    return mgr.configure(config)


@router.get("/{org_id}/config", response_model=TrustPageConfig, dependencies=[Depends(api_key_auth)])
async def get_config(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> TrustPageConfig:
    """Return trust page configuration for an org (admin only)."""
    config = mgr.get_config(org_id)
    if config is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trust center not configured for org '{org_id}'",
        )
    return config


@router.get("/{org_id}/stats", dependencies=[Depends(api_key_auth)])
async def get_trust_stats(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> dict:
    """Return aggregate statistics for an org's trust center."""
    config = mgr.get_config(org_id)
    if config is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trust center not configured for org '{org_id}'",
        )
    return mgr.get_trust_stats(org_id)


# ---------------------------------------------------------------------------
# Badges
# ---------------------------------------------------------------------------


@router.post("/{org_id}/badges", response_model=ComplianceBadge, dependencies=[Depends(api_key_auth)])
async def add_badge(
    org_id: str,
    badge: ComplianceBadge,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> ComplianceBadge:
    """Add a compliance badge for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.add_badge(badge, org_id)


@router.get("/{org_id}/badges", response_model=List[ComplianceBadge], dependencies=[Depends(api_key_auth)])
async def list_badges(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> List[ComplianceBadge]:
    """List all compliance badges for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.list_badges(org_id)


@router.delete("/{org_id}/badges/{badge_id}", dependencies=[Depends(api_key_auth)])
async def delete_badge(
    org_id: str,
    badge_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> dict:
    """Remove a compliance badge."""
    _ensure_org_exists(org_id, mgr)
    deleted = mgr.delete_badge(badge_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Badge '{badge_id}' not found")
    return {"deleted": True, "badge_id": badge_id}


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


@router.post("/{org_id}/controls", response_model=SecurityControl, dependencies=[Depends(api_key_auth)])
async def add_control(
    org_id: str,
    control: SecurityControl,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> SecurityControl:
    """Add a security control for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.add_control(control, org_id)


@router.get("/{org_id}/controls", response_model=List[SecurityControl], dependencies=[Depends(api_key_auth)])
async def list_controls(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> List[SecurityControl]:
    """List all security controls for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.list_controls(org_id)


@router.delete("/{org_id}/controls/{control_id}", dependencies=[Depends(api_key_auth)])
async def delete_control(
    org_id: str,
    control_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> dict:
    """Remove a security control."""
    _ensure_org_exists(org_id, mgr)
    deleted = mgr.delete_control(control_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found")
    return {"deleted": True, "control_id": control_id}


# ---------------------------------------------------------------------------
# Subprocessors
# ---------------------------------------------------------------------------


@router.post("/{org_id}/subprocessors", response_model=SubprocessorEntry, dependencies=[Depends(api_key_auth)])
async def add_subprocessor(
    org_id: str,
    entry: SubprocessorEntry,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> SubprocessorEntry:
    """Add a sub-processor entry for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.add_subprocessor(entry, org_id)


@router.get("/{org_id}/subprocessors", response_model=List[SubprocessorEntry], dependencies=[Depends(api_key_auth)])
async def list_subprocessors(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> List[SubprocessorEntry]:
    """List all sub-processor entries for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.list_subprocessors(org_id)


@router.delete("/{org_id}/subprocessors/{entry_id}", dependencies=[Depends(api_key_auth)])
async def delete_subprocessor(
    org_id: str,
    entry_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> dict:
    """Remove a sub-processor entry."""
    _ensure_org_exists(org_id, mgr)
    deleted = mgr.delete_subprocessor(entry_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Subprocessor '{entry_id}' not found")
    return {"deleted": True, "entry_id": entry_id}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ensure_org_exists(org_id: str, mgr: TrustCenterManager) -> None:
    """Raise 404 if the org has no trust center configured."""
    if mgr.get_config(org_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trust center not configured for org '{org_id}'. Call POST /configure first.",
        )
