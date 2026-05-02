"""Patch Manager API Router.

Endpoints for discovering, scheduling, deploying, rolling back, and
reporting on security patches across managed assets.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.patch_manager import (
    Patch,
    PatchManager,
    PatchPriority,
    PatchStatus,
    get_patch_manager,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/patches", tags=["patch-management"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AddPatchRequest(BaseModel):
    cve_id: Optional[str] = Field(None, description="CVE identifier, e.g. CVE-2024-1234")
    package_name: str = Field(..., description="Package or component name")
    current_version: str = Field(..., description="Currently installed version")
    fixed_version: str = Field(..., description="Version that resolves the vulnerability")
    priority: PatchPriority = Field(PatchPriority.MEDIUM, description="Patch urgency")
    affected_assets: List[str] = Field(default_factory=list, description="Asset IDs affected")
    notes: Optional[str] = Field(None, description="Change ticket or free-form notes")
    org_id: str = Field("default", description="Organisation ID")


class SchedulePatchRequest(BaseModel):
    scheduled_date: str = Field(..., description="ISO-8601 date/time for deployment")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pm() -> PatchManager:
    return get_patch_manager()


def _require_patch(patch_id: str) -> Patch:
    patch = _pm().get_patch(patch_id)
    if not patch:
        raise HTTPException(status_code=404, detail=f"Patch '{patch_id}' not found")
    return patch


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/discover", response_model=List[Patch], summary="Discover available patches")
def discover_patches(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Patch]:
    """Scan for available patches for the organisation and persist any new ones."""
    try:
        return _pm().discover_patches(org_id)
    except Exception as exc:
        logger.exception("Patch discovery failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Discovery failed: {exc}") from exc


@router.post("", response_model=Patch, summary="Add patch record")
def add_patch(req: AddPatchRequest) -> Patch:
    """Manually register a patch record (e.g. from an external scanner)."""
    patch = Patch(
        cve_id=req.cve_id,
        package_name=req.package_name,
        current_version=req.current_version,
        fixed_version=req.fixed_version,
        priority=req.priority,
        affected_assets=req.affected_assets,
        notes=req.notes,
        org_id=req.org_id,
    )
    try:
        return _pm().add_patch(patch)
    except Exception as exc:
        logger.exception("Failed to add patch: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to add patch: {exc}") from exc


@router.get("", response_model=List[Patch], summary="List patches")
def list_patches(
    org_id: str = Query("default", description="Organisation ID"),
    priority: Optional[PatchPriority] = Query(None, description="Filter by priority"),
    status: Optional[PatchStatus] = Query(None, description="Filter by status"),
    package_name: Optional[str] = Query(None, description="Filter by package name"),
) -> List[Patch]:
    """Return all patches for an organisation with optional filters."""
    return _pm().list_patches(
        org_id,
        priority=priority.value if priority else None,
        status=status.value if status else None,
        package_name=package_name,
    )


@router.get("/stats", summary="Patch statistics")
def get_patch_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return patch counts grouped by priority, status, and package."""
    return _pm().get_patch_stats(org_id)


@router.get("/compliance", summary="Patch SLA compliance")
def get_patch_compliance(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return the percentage of patches deployed within their SLA window."""
    return _pm().get_patch_compliance(org_id)


@router.get("/overdue", response_model=List[Patch], summary="Overdue patches")
def get_overdue_patches(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Patch]:
    """Return patches that have exceeded their SLA window without being deployed."""
    return _pm().get_overdue_patches(org_id)


@router.get("/velocity", summary="Patch deployment velocity")
def get_patch_velocity(
    org_id: str = Query("default", description="Organisation ID"),
    weeks: int = Query(8, ge=1, le=52, description="Number of weeks to trend"),
) -> Dict[str, Any]:
    """Return patches-per-week deployment trend."""
    return _pm().get_patch_velocity(org_id, weeks=weeks)


@router.get("/{patch_id}", response_model=Patch, summary="Get patch")
def get_patch(patch_id: str) -> Patch:
    """Return a single patch by ID."""
    return _require_patch(patch_id)


@router.post("/{patch_id}/schedule", response_model=Patch, summary="Schedule patch")
def schedule_patch(patch_id: str, req: SchedulePatchRequest) -> Patch:
    """Schedule a patch for deployment on a specific date."""
    try:
        return _pm().schedule_patch(patch_id, req.scheduled_date)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to schedule patch %s: %s", patch_id, exc)
        raise HTTPException(status_code=500, detail=f"Schedule failed: {exc}") from exc


@router.post("/{patch_id}/deploy", response_model=Patch, summary="Deploy patch")
def deploy_patch(patch_id: str) -> Patch:
    """Mark a patch as deployed (records deployment timestamp)."""
    try:
        return _pm().deploy_patch(patch_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to deploy patch %s: %s", patch_id, exc)
        raise HTTPException(status_code=500, detail=f"Deploy failed: {exc}") from exc


@router.post("/{patch_id}/rollback", response_model=Patch, summary="Rollback patch")
def rollback_patch(patch_id: str) -> Patch:
    """Roll back a deployed patch."""
    try:
        return _pm().rollback_patch(patch_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to rollback patch %s: %s", patch_id, exc)
        raise HTTPException(status_code=500, detail=f"Rollback failed: {exc}") from exc
