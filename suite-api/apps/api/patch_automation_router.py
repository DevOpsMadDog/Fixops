"""Patch Automation Router — ALDECI.

Endpoints for automated patch management with CVE correlation.

Prefix: /api/v1/patch-automation
Auth:   api_key_auth dependency

Routes:
  POST   /patches                              add_patch
  GET    /patches                              list_patches
  PATCH  /patches/{patch_id}/approve          approve_patch
  POST   /deployments                          deploy_patch
  PATCH  /deployments/{deployment_id}/status  update_deployment
  GET    /deployments                          list_deployments
  POST   /exceptions                           add_exception
  GET    /exceptions                           list_exceptions
  POST   /windows                              create_patch_window
  GET    /windows                              list_patch_windows
  GET    /cve/{cve_id}/patches                get_cve_patch_map
  GET    /stats                                get_patch_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/patch-automation",
    tags=["patch-automation"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------
_engine_org_cache: Dict[str, Any] = {}


def _get_engine(org_id: str):
    """Return (or create) a PatchAutomationEngine instance for the org."""
    if org_id not in _engine_org_cache:
        from core.patch_automation_engine import get_engine
        _engine_org_cache[org_id] = get_engine(org_id)
    return _engine_org_cache[org_id]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class PatchIn(BaseModel):
    patch_id: str
    vendor: str = ""
    product: str = ""
    version: str = ""
    patch_type: str = "security"
    cves_addressed: List[str] = Field(default_factory=list)
    severity: str = "medium"
    release_date: Optional[str] = None
    kb_article: str = ""
    download_url: str = ""
    status: str = "available"


class DeployPatchIn(BaseModel):
    patch_id: str
    asset_id: str
    asset_name: str = ""
    deployed_by: str = ""
    deployment_type: str = "manual"


class UpdateDeploymentIn(BaseModel):
    status: str
    error_msg: Optional[str] = None


class ExceptionIn(BaseModel):
    patch_id: str
    asset_id: str
    reason: str = ""
    approved_by: str = ""
    expires_at: Optional[str] = None


class PatchWindowIn(BaseModel):
    name: str
    schedule_cron: str = ""
    asset_groups: List[str] = Field(default_factory=list)
    auto_approve: bool = False
    max_batch_pct: int = 20


# ---------------------------------------------------------------------------
# Patch Catalog
# ---------------------------------------------------------------------------

@router.post("/patches", summary="Add a patch to the catalog")
def add_patch(
    body: PatchIn,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    try:
        return engine.add_patch(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/patches", summary="List patches from catalog")
def list_patches(
    org_id: str = Query(..., description="Organization ID"),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    vendor: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    engine = _get_engine(org_id)
    return engine.list_patches(org_id, status=status, severity=severity, vendor=vendor)


@router.patch("/patches/{patch_id}/approve", summary="Approve a patch")
def approve_patch(
    patch_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    updated = engine.approve_patch(org_id, patch_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Patch not found.")
    return {"patch_id": patch_id, "status": "approved"}


# ---------------------------------------------------------------------------
# Deployments
# ---------------------------------------------------------------------------

@router.post("/deployments", summary="Create a patch deployment record")
def deploy_patch(
    body: DeployPatchIn,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    try:
        return engine.deploy_patch(
            org_id,
            patch_id=body.patch_id,
            asset_id=body.asset_id,
            asset_name=body.asset_name,
            deployed_by=body.deployed_by,
            deployment_type=body.deployment_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.patch("/deployments/{deployment_id}/status", summary="Update deployment status")
def update_deployment(
    deployment_id: str,
    body: UpdateDeploymentIn,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    try:
        updated = engine.update_deployment(
            org_id, deployment_id, status=body.status, error_msg=body.error_msg
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="Deployment not found.")
    return {"deployment_id": deployment_id, "status": body.status}


@router.get("/deployments", summary="List patch deployments")
def list_deployments(
    org_id: str = Query(..., description="Organization ID"),
    status: Optional[str] = Query(None),
    patch_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    engine = _get_engine(org_id)
    return engine.list_deployments(org_id, status=status, patch_id=patch_id, limit=limit)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

@router.post("/exceptions", summary="Create a patch exception")
def add_exception(
    body: ExceptionIn,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    try:
        return engine.add_exception(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/exceptions", summary="List patch exceptions")
def list_exceptions(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    engine = _get_engine(org_id)
    return engine.list_exceptions(org_id)


# ---------------------------------------------------------------------------
# Maintenance Windows
# ---------------------------------------------------------------------------

@router.post("/windows", summary="Create a maintenance window")
def create_patch_window(
    body: PatchWindowIn,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    try:
        return engine.create_patch_window(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/windows", summary="List maintenance windows")
def list_patch_windows(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    engine = _get_engine(org_id)
    return engine.list_patch_windows(org_id)


# ---------------------------------------------------------------------------
# CVE → Patch Mapping
# ---------------------------------------------------------------------------

@router.get("/cve/{cve_id}/patches", summary="Find patches addressing a specific CVE")
def get_cve_patch_map(
    cve_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    engine = _get_engine(org_id)
    return engine.get_cve_patch_map(org_id, cve_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", summary="Get patch management stats for org")
def get_patch_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    return engine.get_patch_stats(org_id)
