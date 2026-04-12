"""Asset Inventory and CMDB Integration API Router.

Endpoints for registering, discovering, managing lifecycle, ownership,
tags, search, CMDB sync, and bulk import of managed assets.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.asset_inventory import (
    AssetCriticality,
    AssetInventory,
    AssetLifecycle,
    CMDBSyncRecord,
    Environment,
    ManagedAsset,
    get_asset_inventory,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/assets", tags=["asset-inventory"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterAssetRequest(BaseModel):
    name: str = Field(..., description="Asset name or identifier")
    asset_type: str = Field(..., description="Asset type (server, container, domain, etc.)")
    hostname: Optional[str] = Field(None, description="Hostname")
    ip_address: Optional[str] = Field(None, description="IP address")
    owner_email: Optional[str] = Field(None, description="Asset owner email")
    team: Optional[str] = Field(None, description="Owning team")
    criticality: AssetCriticality = Field(AssetCriticality.MEDIUM, description="Asset criticality")
    environment: Environment = Field(Environment.PRODUCTION, description="Deployment environment")
    lifecycle: AssetLifecycle = Field(AssetLifecycle.DISCOVERED, description="Lifecycle state")
    tags: List[str] = Field(default_factory=list, description="Free-form tags")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    org_id: str = Field("default", description="Organisation ID")


class UpdateAssetRequest(BaseModel):
    name: Optional[str] = None
    asset_type: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    owner_email: Optional[str] = None
    team: Optional[str] = None
    criticality: Optional[AssetCriticality] = None
    environment: Optional[Environment] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    risk_score: Optional[float] = None
    finding_count: Optional[int] = None


class DiscoverFromFindingsRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="Pipeline findings to extract assets from")
    org_id: str = Field("default", description="Organisation ID")


class LifecycleTransitionRequest(BaseModel):
    new_state: AssetLifecycle = Field(..., description="Target lifecycle state")


class AssignOwnerRequest(BaseModel):
    owner_email: str = Field(..., description="Owner email address")
    team: Optional[str] = Field(None, description="Owning team")


class TagAssetRequest(BaseModel):
    tags: List[str] = Field(..., description="Tags to add")


class CMDBSyncRequest(BaseModel):
    cmdb_system: str = Field(..., description="CMDB system name (e.g. ServiceNow, Jira)")
    external_id: str = Field(..., description="Asset ID in the external CMDB")
    changes: Dict[str, Any] = Field(default_factory=dict, description="Fields changed in this sync")


class BulkImportRequest(BaseModel):
    assets: List[Dict[str, Any]] = Field(..., description="List of asset dicts to import")
    org_id: str = Field("default", description="Organisation ID")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inv() -> AssetInventory:
    return get_asset_inventory()


def _require_asset(asset_id: str) -> ManagedAsset:
    asset = _inv().get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return asset


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=ManagedAsset, summary="Register asset")
def register_asset(req: RegisterAssetRequest) -> ManagedAsset:
    """Create or update an asset in the centralized inventory."""
    asset = ManagedAsset(
        name=req.name,
        asset_type=req.asset_type,
        hostname=req.hostname,
        ip_address=req.ip_address,
        owner_email=req.owner_email,
        team=req.team,
        criticality=req.criticality,
        environment=req.environment,
        lifecycle=req.lifecycle,
        tags=req.tags,
        metadata=req.metadata,
        org_id=req.org_id,
    )
    try:
        return _inv().register_asset(asset)
    except Exception as exc:
        logger.exception("Failed to register asset: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to register asset: {exc}") from exc


@router.get("/stats", summary="Inventory stats")
def get_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return asset counts grouped by type, criticality, lifecycle, and environment."""
    return _inv().get_inventory_stats(org_id)


@router.get("/unowned", response_model=List[ManagedAsset], summary="Unowned assets")
def get_unowned_assets(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[ManagedAsset]:
    """Return assets with no assigned owner."""
    return _inv().get_unowned_assets(org_id)


@router.get("/stale", response_model=List[ManagedAsset], summary="Stale assets")
def get_stale_assets(
    org_id: str = Query("default", description="Organisation ID"),
    days: int = Query(30, ge=1, le=3650, description="Not seen in this many days"),
) -> List[ManagedAsset]:
    """Return assets not seen within the specified number of days."""
    return _inv().get_stale_assets(org_id, days=days)


@router.get("", response_model=List[ManagedAsset], summary="List assets")
def list_assets(
    org_id: str = Query("default", description="Organisation ID"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    criticality: Optional[AssetCriticality] = Query(None, description="Filter by criticality"),
    environment: Optional[Environment] = Query(None, description="Filter by environment"),
    lifecycle: Optional[AssetLifecycle] = Query(None, description="Filter by lifecycle state"),
    owner_email: Optional[str] = Query(None, description="Filter by owner email"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    search: Optional[str] = Query(None, description="Full-text search query"),
) -> List[ManagedAsset]:
    """List assets for an org with optional filters and full-text search."""
    if search:
        return _inv().search_assets(search, org_id)
    return _inv().list_assets(
        org_id,
        asset_type=asset_type,
        criticality=criticality.value if criticality else None,
        environment=environment.value if environment else None,
        lifecycle=lifecycle.value if lifecycle else None,
        owner_email=owner_email,
        tag=tag,
    )


@router.post("/discover", response_model=List[ManagedAsset], summary="Discover assets from findings")
def discover_from_findings(req: DiscoverFromFindingsRequest) -> List[ManagedAsset]:
    """Auto-extract and register assets from pipeline scan findings."""
    try:
        return _inv().discover_from_findings(req.findings, req.org_id)
    except Exception as exc:
        logger.exception("Asset discovery failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Discovery failed: {exc}") from exc


@router.post("/bulk-import", summary="Bulk import assets")
def bulk_import(req: BulkImportRequest) -> Dict[str, Any]:
    """Import assets from a list of dicts (parsed from CSV/JSON)."""
    try:
        count = _inv().bulk_import(req.assets, req.org_id)
        return {"imported": count, "org_id": req.org_id}
    except Exception as exc:
        logger.exception("Bulk import failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Bulk import failed: {exc}") from exc


@router.get("/{asset_id}", response_model=ManagedAsset, summary="Get asset")
def get_asset(asset_id: str) -> ManagedAsset:
    """Retrieve a single asset by ID."""
    return _require_asset(asset_id)


@router.put("/{asset_id}", response_model=ManagedAsset, summary="Update asset")
def update_asset(asset_id: str, req: UpdateAssetRequest) -> ManagedAsset:
    """Apply partial updates to an existing asset."""
    _require_asset(asset_id)
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    # Coerce enum values to their string representation for storage
    for field in ("criticality", "environment"):
        if field in updates and hasattr(updates[field], "value"):
            updates[field] = updates[field].value
    updated = _inv().update_asset(asset_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return updated


@router.delete("/{asset_id}", summary="Delete asset")
def delete_asset(asset_id: str) -> Dict[str, Any]:
    """Remove an asset from the inventory."""
    deleted = _inv().delete_asset(asset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return {"deleted": True, "asset_id": asset_id}


@router.post("/{asset_id}/lifecycle", response_model=ManagedAsset, summary="Transition lifecycle")
def transition_lifecycle(asset_id: str, req: LifecycleTransitionRequest) -> ManagedAsset:
    """Transition an asset to a new lifecycle state (validated state machine)."""
    try:
        asset = _inv().transition_lifecycle(asset_id, req.new_state)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return asset


@router.post("/{asset_id}/owner", response_model=ManagedAsset, summary="Assign owner")
def assign_owner(asset_id: str, req: AssignOwnerRequest) -> ManagedAsset:
    """Assign an owner (and optionally a team) to an asset."""
    _require_asset(asset_id)
    asset = _inv().assign_owner(asset_id, req.owner_email, req.team)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return asset


@router.post("/{asset_id}/tags", response_model=ManagedAsset, summary="Tag asset")
def tag_asset(asset_id: str, req: TagAssetRequest) -> ManagedAsset:
    """Add tags to an asset."""
    _require_asset(asset_id)
    asset = _inv().tag_asset(asset_id, req.tags)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return asset


@router.post("/{asset_id}/sync", response_model=CMDBSyncRecord, summary="Sync to CMDB")
def sync_to_cmdb(asset_id: str, req: CMDBSyncRequest) -> CMDBSyncRecord:
    """Record a CMDB sync event for an asset."""
    _require_asset(asset_id)
    try:
        return _inv().sync_to_cmdb(
            asset_id=asset_id,
            cmdb_system=req.cmdb_system,
            external_id=req.external_id,
            changes=req.changes,
        )
    except Exception as exc:
        logger.exception("CMDB sync failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"CMDB sync failed: {exc}") from exc


@router.get("/{asset_id}/sync", response_model=List[CMDBSyncRecord], summary="CMDB sync history")
def get_sync_history(asset_id: str) -> List[CMDBSyncRecord]:
    """Return all CMDB sync records for an asset (newest first)."""
    _require_asset(asset_id)
    return _inv().get_sync_history(asset_id)
