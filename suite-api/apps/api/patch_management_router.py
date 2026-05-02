"""Patch Management Router — ALDECI.

Endpoints for the Patch Management engine.

Prefix: /api/v1/patch-management
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/patch-management/patches                    register_patch
  GET   /api/v1/patch-management/patches                    list_patches
  GET   /api/v1/patch-management/patches/{patch_id}         get_patch
  PATCH /api/v1/patch-management/patches/{patch_id}/status  update_patch_status
  POST  /api/v1/patch-management/patches/{patch_id}/deployments  record_deployment
  GET   /api/v1/patch-management/deployments                list_deployments
  GET   /api/v1/patch-management/stats                      get_patch_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/patch-management",
    tags=["Patch Management"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.patch_management_engine import PatchManagementEngine
        _engine = PatchManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class PatchCreate(BaseModel):
    title: str
    cve_ids: List[str] = []
    patch_type: str = "security"
    severity: str = "medium"
    vendor: str = ""
    affected_os: str = ""
    version: str = ""
    release_date: Optional[str] = None


class PatchStatusUpdate(BaseModel):
    status: str
    notes: str = ""


class DeploymentCreate(BaseModel):
    asset_id: str = ""
    hostname: str = ""
    os_type: str = "linux"
    status: str = "pending"
    failure_reason: str = ""
    deployed_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Patches
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_patch_management(org_id: str = Query("default")) -> Dict[str, Any]:
    """List patches for the org."""
    patches = _get_engine().list_patches(org_id=org_id)
    return {"org_id": org_id, "patches": patches, "total": len(patches)}


@router.post("/patches", dependencies=[Depends(api_key_auth)], status_code=201)
def register_patch(body: PatchCreate, org_id: str = Query(default="default")):
    """Register a new patch."""
    try:
        return _get_engine().register_patch(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/patches", dependencies=[Depends(api_key_auth)])
def list_patches(
     org_id: str = Query(default="default"),
    patch_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List patches with optional filters."""
    return _get_engine().list_patches(
        org_id, patch_type=patch_type, severity=severity, status=status
    )


@router.get("/patches/{patch_id}", dependencies=[Depends(api_key_auth)])
def get_patch(patch_id: str, org_id: str = Query(default="default")):
    """Get a single patch by ID."""
    patch = _get_engine().get_patch(org_id, patch_id)
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found")
    return patch


@router.patch("/patches/{patch_id}/status", dependencies=[Depends(api_key_auth)])
def update_patch_status(patch_id: str, body: PatchStatusUpdate, org_id: str = Query(default="default")):
    """Update patch lifecycle status."""
    try:
        return _get_engine().update_patch_status(
            org_id, patch_id, body.status, notes=body.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Deployments
# ---------------------------------------------------------------------------

@router.post("/patches/{patch_id}/deployments", dependencies=[Depends(api_key_auth)], status_code=201)
def record_deployment(patch_id: str, body: DeploymentCreate, org_id: str = Query(default="default")):
    """Record a per-asset patch deployment."""
    try:
        return _get_engine().record_deployment(org_id, patch_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/deployments", dependencies=[Depends(api_key_auth)])
def list_deployments(
     org_id: str = Query(default="default"),
    patch_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    os_type: Optional[str] = Query(None),
):
    """List deployment records with optional filters."""
    return _get_engine().list_deployments(
        org_id, patch_id=patch_id, status=status, os_type=os_type
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_patch_stats(org_id: str = Query(default="default")):
    """Return aggregated patch management statistics."""
    return _get_engine().get_patch_stats(org_id)
