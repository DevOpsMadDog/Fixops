"""Asset Inventory and CMDB Integration API Router.

Endpoints for registering, discovering, managing lifecycle, ownership,
tags, compliance tagging, relationship mapping, search, CMDB sync,
impact graph traversal, and bulk import of managed assets.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.asset_inventory import (
    AssetCriticality,
    AssetInventory,
    AssetLifecycle,
    AssetRelationship,
    CMDBSyncRecord,
    ComplianceFramework,
    CriticalityTier,
    DataClassification,
    Environment,
    ManagedAsset,
    RelationshipType,
    get_asset_inventory,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/assets", tags=["asset-inventory"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterAssetRequest(BaseModel):
    name: str = Field(..., description="Asset name or identifier")
    asset_type: str = Field(..., description="Asset type (server, container, cloud_resource, application, database, api, repository, network_device, user, certificate, etc.)")
    hostname: Optional[str] = Field(None)
    ip_address: Optional[str] = Field(None)
    cloud_provider: Optional[str] = Field(None, description="aws, gcp, azure, on-prem")
    region: Optional[str] = Field(None)
    cloud_resource_id: Optional[str] = Field(None, description="ARN, resource ID, etc.")
    owner_email: Optional[str] = Field(None)
    owner_name: Optional[str] = Field(None)
    team: Optional[str] = Field(None)
    business_unit: Optional[str] = Field(None)
    cost_center: Optional[str] = Field(None)
    criticality: AssetCriticality = Field(AssetCriticality.MEDIUM)
    criticality_tier: CriticalityTier = Field(CriticalityTier.T3)
    data_classification: DataClassification = Field(DataClassification.INTERNAL)
    compliance_scope: List[str] = Field(default_factory=list)
    environment: Environment = Field(Environment.PRODUCTION)
    lifecycle: AssetLifecycle = Field(AssetLifecycle.DISCOVERED)
    discovery_source: Optional[str] = Field(None)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = Field("default")


class UpdateAssetRequest(BaseModel):
    name: Optional[str] = None
    asset_type: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    cloud_provider: Optional[str] = None
    region: Optional[str] = None
    cloud_resource_id: Optional[str] = None
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    team: Optional[str] = None
    business_unit: Optional[str] = None
    cost_center: Optional[str] = None
    criticality: Optional[AssetCriticality] = None
    criticality_tier: Optional[CriticalityTier] = None
    data_classification: Optional[DataClassification] = None
    compliance_scope: Optional[List[str]] = None
    environment: Optional[Environment] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    risk_score: Optional[float] = None
    finding_count: Optional[int] = None


class DiscoverFromFindingsRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="Pipeline findings to extract assets from")
    org_id: str = Field("default")
    discovery_source: str = Field("scanner", description="Source: cloud_discovery, k8s_scan, container_scan, network_scan, api_scan, manual")


class LifecycleTransitionRequest(BaseModel):
    new_state: AssetLifecycle = Field(..., description="Target lifecycle state")


class AssignOwnerRequest(BaseModel):
    owner_email: str = Field(...)
    owner_name: Optional[str] = Field(None)
    team: Optional[str] = Field(None)
    business_unit: Optional[str] = Field(None)
    cost_center: Optional[str] = Field(None)


class TagAssetRequest(BaseModel):
    tags: List[str] = Field(..., description="Tags to add")


class ComplianceScopeRequest(BaseModel):
    frameworks: List[str] = Field(..., description="Compliance framework values to apply: pci, hipaa, sox, itar, gdpr, nist, iso27001")


class AddRelationshipRequest(BaseModel):
    source_asset_id: str = Field(...)
    target_asset_id: str = Field(...)
    relationship_type: RelationshipType = Field(...)
    org_id: str = Field("default")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CMDBSyncRequest(BaseModel):
    cmdb_system: str = Field(..., description="CMDB system name (e.g. ServiceNow, Jira)")
    external_id: str = Field(..., description="Asset ID in the external CMDB")
    changes: Dict[str, Any] = Field(default_factory=dict)


class BulkImportRequest(BaseModel):
    assets: List[Dict[str, Any]] = Field(..., description="List of asset dicts to import")
    org_id: str = Field("default")


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
# Endpoints — collection-level (must come before /{asset_id} routes)
# ---------------------------------------------------------------------------

@router.get("/stats", summary="Inventory stats")
def get_stats(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return asset counts grouped by type, criticality, tier, lifecycle,
    environment, cloud provider, and data classification."""
    return _inv().get_inventory_stats(org_id)


@router.get("/unowned", response_model=List[ManagedAsset], summary="Unowned assets")
def get_unowned_assets(
    org_id: str = Query("default"),
) -> List[ManagedAsset]:
    """Return assets with no assigned owner."""
    return _inv().get_unowned_assets(org_id)


@router.get("/stale", response_model=List[ManagedAsset], summary="Stale assets")
def get_stale_assets(
    org_id: str = Query("default"),
    days: int = Query(30, ge=1, le=3650, description="Not seen in this many days"),
) -> List[ManagedAsset]:
    """Return assets not seen within the specified number of days."""
    return _inv().get_stale_assets(org_id, days=days)


@router.get("/exposed", response_model=List[ManagedAsset], summary="Internet-exposed high-risk assets")
def get_exposed_assets(
    org_id: str = Query("default"),
) -> List[ManagedAsset]:
    """Return internet-facing assets with a risk score >= 6.0 (high or critical).

    An asset is treated as internet-facing when metadata['internet_facing'] is truthy.
    """
    return _inv().find_exposed_assets(org_id)


@router.get("/compliance/{framework}", response_model=List[ManagedAsset], summary="Assets by compliance scope")
def get_assets_by_compliance(
    framework: ComplianceFramework,
    org_id: str = Query("default"),
) -> List[ManagedAsset]:
    """Return all assets tagged with a specific compliance framework."""
    return _inv().get_assets_in_compliance_scope(org_id, framework.value)


@router.get("", response_model=List[ManagedAsset], summary="List assets")
def list_assets(
    org_id: str = Query("default"),
    asset_type: Optional[str] = Query(None),
    criticality: Optional[AssetCriticality] = Query(None),
    criticality_tier: Optional[CriticalityTier] = Query(None),
    environment: Optional[Environment] = Query(None),
    lifecycle: Optional[AssetLifecycle] = Query(None),
    owner_email: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    business_unit: Optional[str] = Query(None),
    cloud_provider: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    data_classification: Optional[DataClassification] = Query(None),
    compliance_scope: Optional[str] = Query(None, description="Filter by compliance framework value"),
    search: Optional[str] = Query(None, description="Full-text search query"),
) -> List[ManagedAsset]:
    """List assets for an org with optional filters and full-text search."""
    if search:
        return _inv().search_assets(search, org_id)
    return _inv().list_assets(
        org_id,
        asset_type=asset_type,
        criticality=criticality.value if criticality else None,
        criticality_tier=criticality_tier.value if criticality_tier else None,
        environment=environment.value if environment else None,
        lifecycle=lifecycle.value if lifecycle else None,
        owner_email=owner_email,
        tag=tag,
        business_unit=business_unit,
        cloud_provider=cloud_provider,
        region=region,
        data_classification=data_classification.value if data_classification else None,
        compliance_scope=compliance_scope,
    )


@router.post("", response_model=ManagedAsset, summary="Register asset")
def register_asset(req: RegisterAssetRequest) -> ManagedAsset:
    """Create or update an asset in the centralized inventory.

    Compliance scope is auto-applied from data_classification if not set explicitly.
    """
    asset = ManagedAsset(
        name=req.name,
        asset_type=req.asset_type,
        hostname=req.hostname,
        ip_address=req.ip_address,
        cloud_provider=req.cloud_provider,
        region=req.region,
        cloud_resource_id=req.cloud_resource_id,
        owner_email=req.owner_email,
        owner_name=req.owner_name,
        team=req.team,
        business_unit=req.business_unit,
        cost_center=req.cost_center,
        criticality=req.criticality,
        criticality_tier=req.criticality_tier,
        data_classification=req.data_classification,
        compliance_scope=req.compliance_scope,
        environment=req.environment,
        lifecycle=req.lifecycle,
        discovery_source=req.discovery_source,
        tags=req.tags,
        metadata=req.metadata,
        org_id=req.org_id,
    )
    try:
        registered = _inv().register_asset(asset)
    except Exception as exc:
        logger.exception("Failed to register asset: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to register asset: {exc}") from exc
    # TrustGraph async indexing (fire-and-forget, non-blocking)
    try:
        import asyncio
        import threading

        from core.trustgraph_event_bus import EVENT_ASSET_DISCOVERED, get_event_bus
        bus = get_event_bus()
        if bus and bus.enabled:
            result = registered.model_dump(mode="json") if hasattr(registered, "model_dump") else {}
            payload = {
                "asset_id": str(result.get("id", "")),
                "type": result.get("asset_type", "asset"),
                "severity": result.get("criticality", "medium"),
                "source": "asset_inventory_router",
                "data": result,
            }
            # Run async emit in a background thread to avoid coroutine-never-awaited
            # warning when called from a sync FastAPI route handler.
            def _emit_in_thread(b=bus, e=EVENT_ASSET_DISCOVERED, p=payload) -> None:
                try:
                    loop = asyncio.new_event_loop()
                    loop.run_until_complete(b.emit(e, p))
                    loop.close()
                except Exception:
                    pass
            threading.Thread(target=_emit_in_thread, daemon=True).start()
    except Exception:
        pass  # event bus is best-effort
    return registered


@router.post("/discover", response_model=List[ManagedAsset], summary="Discover assets from findings")
def discover_from_findings(req: DiscoverFromFindingsRequest) -> List[ManagedAsset]:
    """Auto-extract and register assets from pipeline scan findings.

    Supports cloud_discovery, k8s_scan, container_scan, network_scan, api_scan sources.
    """
    try:
        return _inv().discover_from_findings(req.findings, req.org_id, discovery_source=req.discovery_source)
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


@router.post("/relationships", response_model=AssetRelationship, summary="Add relationship")
def add_relationship(req: AddRelationshipRequest) -> AssetRelationship:
    """Create a directed relationship between two assets.

    Relationship types: depends_on, runs_on, deployed_in, exposed_by,
    owned_by, connects_to, backs_up_to, replicates_to, hosted_on, managed_by.
    """
    try:
        return _inv().add_relationship(
            source_asset_id=req.source_asset_id,
            target_asset_id=req.target_asset_id,
            relationship_type=req.relationship_type,
            org_id=req.org_id,
            metadata=req.metadata,
        )
    except Exception as exc:
        logger.exception("Failed to add relationship: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to add relationship: {exc}") from exc


# ---------------------------------------------------------------------------
# Endpoints — per-asset
# ---------------------------------------------------------------------------

@router.get("/{asset_id}", response_model=ManagedAsset, summary="Get asset")
def get_asset(asset_id: str) -> ManagedAsset:
    """Retrieve a single asset by ID."""
    return _require_asset(asset_id)


@router.put("/{asset_id}", response_model=ManagedAsset, summary="Update asset")
def update_asset(asset_id: str, req: UpdateAssetRequest) -> ManagedAsset:
    """Apply partial updates to an existing asset."""
    _require_asset(asset_id)
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    for field in ("criticality", "criticality_tier", "environment", "data_classification"):
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
    """Assign owner (email, name, team, business unit, cost center) to an asset."""
    _require_asset(asset_id)
    asset = _inv().assign_owner(
        asset_id,
        owner_email=req.owner_email,
        owner_name=req.owner_name,
        team=req.team,
        business_unit=req.business_unit,
        cost_center=req.cost_center,
    )
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


@router.post("/{asset_id}/compliance", response_model=ManagedAsset, summary="Apply compliance scope")
def apply_compliance_scope(asset_id: str, req: ComplianceScopeRequest) -> ManagedAsset:
    """Explicitly tag an asset with compliance frameworks (additive merge).

    Valid values: pci, hipaa, sox, itar, gdpr, nist, iso27001.
    """
    _require_asset(asset_id)
    try:
        asset = _inv().apply_compliance_scope(asset_id, req.frameworks)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return asset


@router.get("/{asset_id}/relationships", response_model=List[AssetRelationship], summary="Get relationships")
def get_relationships(
    asset_id: str,
    direction: str = Query("both", description="outbound | inbound | both"),
    relationship_type: Optional[RelationshipType] = Query(None),
) -> List[AssetRelationship]:
    """Return relationships for an asset (outbound, inbound, or both directions)."""
    _require_asset(asset_id)
    return _inv().get_relationships(asset_id, direction=direction, relationship_type=relationship_type)


@router.get("/{asset_id}/impact", summary="Impact graph")
def get_impact_graph(
    asset_id: str,
    max_depth: int = Query(3, ge=1, le=10, description="Max BFS hops"),
) -> Dict[str, Any]:
    """Return the blast-radius dependency graph starting from this asset.

    Performs BFS traversal across all relationship types up to max_depth hops.
    Returns nodes (asset IDs) and edges (source, target, type).
    """
    _require_asset(asset_id)
    return _inv().get_impact_graph(asset_id, max_depth=max_depth)


@router.get("/{asset_id}/risk-score", summary="Risk score for asset")
def get_risk_score(
    asset_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Compute and return a 0-10 risk score for an asset.

    Score factors: criticality weight + internet exposure + vuln count + patch age.
    Returns: {score, factors, risk_level}.
    """
    _require_asset(asset_id)
    result = _inv().calculate_risk_score(asset_id, org_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found in org '{org_id}'")
    return result


@router.get("/{asset_id}/timeline", summary="Asset event history")
def get_asset_timeline(
    asset_id: str,
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """Return chronological history of changes and security events for an asset.

    Merges discovery event, CMDB sync records, lifecycle transitions, and
    finding updates into a single ascending timeline.
    """
    _require_asset(asset_id)
    return _inv().get_asset_timeline(asset_id, org_id)


@router.delete("/relationships/{rel_id}", summary="Delete relationship")
def delete_relationship(rel_id: str) -> Dict[str, Any]:
    """Remove a relationship by ID."""
    deleted = _inv().delete_relationship(rel_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Relationship '{rel_id}' not found")
    return {"deleted": True, "rel_id": rel_id}


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


@router.get("/", summary="Asset inventory index", tags=["asset-inventory"])
def asset_index(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return asset inventory summary stats and top assets for the org."""
    inv = _inv()
    try:
        stats = inv.get_stats(org_id=org_id) if hasattr(inv, "get_stats") else {}
    except Exception:
        stats = {}
    try:
        assets = inv.list_assets(org_id=org_id)
        items = [a.model_dump() for a in assets[:50]]
    except Exception:
        items = []
    return {"router": "assets", "org_id": org_id, "stats": stats, "items": items, "count": len(items)}
