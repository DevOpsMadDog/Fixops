"""Multi-Cloud Asset Discovery API Router.

Endpoints:
    POST   /api/v1/cloud/discover/aws          -- Trigger AWS asset discovery
    POST   /api/v1/cloud/discover/azure        -- Trigger Azure asset discovery
    POST   /api/v1/cloud/discover/gcp          -- Trigger GCP asset discovery
    POST   /api/v1/cloud/discover/all          -- Trigger all-cloud discovery
    GET    /api/v1/cloud/inventory             -- Full asset inventory with filters
    GET    /api/v1/cloud/assets/unmanaged      -- Shadow IT / unmanaged assets
    GET    /api/v1/cloud/assets/public         -- Internet-exposed assets
    GET    /api/v1/cloud/assets/drift          -- New/removed asset drift
    GET    /api/v1/cloud/stats                 -- Discovery stats by provider/type/region

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.cloud_discovery import (
    CloudDiscovery,
    get_cloud_discovery,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cloud", tags=["cloud-discovery"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class DiscoverRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")


class RegisterCMDBRequest(BaseModel):
    resource_id: str = Field(..., description="Cloud resource ID to mark as managed")
    org_id: str = Field("default", description="Organisation ID")


class DiscoverResponse(BaseModel):
    provider: str
    org_id: str
    discovered: int
    assets: List[Dict[str, Any]]


class DriftResponse(BaseModel):
    lookback_days: int
    new_count: int
    removed_count: int
    new_assets: List[Dict[str, Any]]
    removed_assets: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _discovery() -> CloudDiscovery:
    return get_cloud_discovery()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/discover/aws", response_model=DiscoverResponse, summary="Discover AWS assets")
def discover_aws(body: DiscoverRequest) -> DiscoverResponse:
    """Enumerate AWS resources and store them in the inventory."""
    try:
        assets = _discovery().discover_aws(body.org_id)
    except Exception as exc:
        logger.exception("cloud_discovery.discover_aws.error")
        raise HTTPException(status_code=500, detail=f"AWS discovery failed: {exc}") from exc
    return DiscoverResponse(
        provider="aws",
        org_id=body.org_id,
        discovered=len(assets),
        assets=[a.model_dump() for a in assets],
    )


@router.post("/discover/azure", response_model=DiscoverResponse, summary="Discover Azure assets")
def discover_azure(body: DiscoverRequest) -> DiscoverResponse:
    """Enumerate Azure resources and store them in the inventory."""
    try:
        assets = _discovery().discover_azure(body.org_id)
    except Exception as exc:
        logger.exception("cloud_discovery.discover_azure.error")
        raise HTTPException(status_code=500, detail=f"Azure discovery failed: {exc}") from exc
    return DiscoverResponse(
        provider="azure",
        org_id=body.org_id,
        discovered=len(assets),
        assets=[a.model_dump() for a in assets],
    )


@router.post("/discover/gcp", response_model=DiscoverResponse, summary="Discover GCP assets")
def discover_gcp(body: DiscoverRequest) -> DiscoverResponse:
    """Enumerate GCP resources and store them in the inventory."""
    try:
        assets = _discovery().discover_gcp(body.org_id)
    except Exception as exc:
        logger.exception("cloud_discovery.discover_gcp.error")
        raise HTTPException(status_code=500, detail=f"GCP discovery failed: {exc}") from exc
    return DiscoverResponse(
        provider="gcp",
        org_id=body.org_id,
        discovered=len(assets),
        assets=[a.model_dump() for a in assets],
    )


@router.post("/discover/all", summary="Discover assets across all cloud providers")
def discover_all(body: DiscoverRequest) -> Dict[str, Any]:
    """Trigger discovery across AWS, Azure, and GCP simultaneously."""
    try:
        assets = _discovery().discover_all(body.org_id)
    except Exception as exc:
        logger.exception("cloud_discovery.discover_all.error")
        raise HTTPException(status_code=500, detail=f"Multi-cloud discovery failed: {exc}") from exc

    by_provider: Dict[str, int] = {}
    for a in assets:
        by_provider[a.provider] = by_provider.get(a.provider, 0) + 1

    return {
        "org_id": body.org_id,
        "total_discovered": len(assets),
        "by_provider": by_provider,
        "assets": [a.model_dump() for a in assets],
    }


@router.get("/inventory", summary="Get full cloud asset inventory")
def get_inventory(
    org_id: str = Query("default", description="Organisation ID"),
    provider: Optional[str] = Query(None, description="Filter by provider: aws | azure | gcp"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    region: Optional[str] = Query(None, description="Filter by region"),
    account_id: Optional[str] = Query(None, description="Filter by account/subscription/project ID"),
) -> Dict[str, Any]:
    """Return full asset inventory with optional filters."""
    assets = _discovery().get_asset_inventory(
        org_id=org_id,
        provider=provider,
        asset_type=asset_type,
        region=region,
        account_id=account_id,
    )
    return {
        "org_id": org_id,
        "total": len(assets),
        "filters": {
            "provider": provider,
            "asset_type": asset_type,
            "region": region,
            "account_id": account_id,
        },
        "assets": [a.model_dump() for a in assets],
    }


@router.get("/assets/unmanaged", summary="Get unmanaged (shadow IT) assets")
def get_unmanaged_assets(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return assets not present in the CMDB."""
    assets = _discovery().get_unmanaged_assets(org_id=org_id)
    return {
        "org_id": org_id,
        "total": len(assets),
        "assets": [a.model_dump() for a in assets],
    }


@router.get("/assets/public", summary="Get internet-exposed assets")
def get_public_assets(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return assets with a public IP address."""
    assets = _discovery().get_public_assets(org_id=org_id)
    return {
        "org_id": org_id,
        "total": len(assets),
        "assets": [a.model_dump() for a in assets],
    }


@router.get("/assets/drift", response_model=DriftResponse, summary="Get asset drift")
def get_asset_drift(
    org_id: str = Query("default", description="Organisation ID"),
    days: int = Query(7, ge=1, le=365, description="Lookback window in days"),
) -> DriftResponse:
    """Return new and removed assets within the lookback window."""
    result = _discovery().get_asset_drift(org_id=org_id, days=days)
    return DriftResponse(**result)


@router.get("/stats", summary="Get discovery statistics")
def get_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregated discovery stats by provider, asset type, and region."""
    return _discovery().get_discovery_stats(org_id=org_id)


@router.post("/cmdb/register", summary="Register asset as managed in CMDB")
def register_cmdb(body: RegisterCMDBRequest) -> Dict[str, Any]:
    """Mark a cloud resource as known/managed so it no longer appears as unmanaged."""
    _discovery().register_cmdb_asset(resource_id=body.resource_id, org_id=body.org_id)
    return {"status": "registered", "resource_id": body.resource_id, "org_id": body.org_id}
