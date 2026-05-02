"""Data Classification API Router — SCIF-grade asset classification endpoints.

Endpoints:
    POST   /api/v1/classification/assets              -- Classify an asset
    GET    /api/v1/classification/assets              -- List classified assets
    GET    /api/v1/classification/assets/{asset_id}   -- Get asset classification
    POST   /api/v1/classification/assets/{asset_id}/auto-classify  -- Auto-classify by content
    POST   /api/v1/classification/assets/{asset_id}/upgrade        -- Upgrade classification
    POST   /api/v1/classification/assets/{asset_id}/downgrade      -- Downgrade (with approval)
    GET    /api/v1/classification/stats               -- Classification statistics
    GET    /api/v1/classification/audit               -- Audit trail of changes
    GET    /api/v1/classification/handling/{level}    -- Get handling instructions

Security:
    - All endpoints require API key authentication (injected by app.py)
    - Downgrade requires explicit approval_id and reason
    - All changes are audit-logged
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.data_classification import (
    AutoClassifyResult,
    ClassificationChange,
    ClassificationLevel,
    ClassifiedAsset,
    DataCategory,
    DataClassificationEngine,
    get_classification_engine,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/classification", tags=["data-classification"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ClassifyAssetRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=512)
    path: Optional[str] = Field(None, max_length=2048)
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    categories: List[DataCategory] = Field(default_factory=list)
    owner: Optional[str] = Field(None, max_length=254)
    handling_instructions: Optional[str] = Field(None, max_length=4096)
    retention_days: int = Field(365, ge=1, le=36500)
    encryption_required: bool = False


class AutoClassifyRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=1_000_000)
    apply: bool = True


class UpgradeRequest(BaseModel):
    new_level: ClassificationLevel
    reason: Optional[str] = Field(None, max_length=2048)
    changed_by: str = Field("api-user", max_length=254)


class DowngradeRequest(BaseModel):
    new_level: ClassificationLevel
    approval_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=2048)
    changed_by: str = Field(..., min_length=1, max_length=254)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _engine() -> DataClassificationEngine:
    return get_classification_engine()


@router.post("/assets", response_model=ClassifiedAsset, status_code=201)
def classify_asset(
    body: ClassifyAssetRequest,
    org_id: str = Depends(get_org_id),
    engine: DataClassificationEngine = Depends(_engine),
) -> ClassifiedAsset:
    """Create or update the classification of a data asset."""
    asset = ClassifiedAsset(
        name=body.name,
        path=body.path,
        classification_level=body.classification_level,
        categories=body.categories,
        owner=body.owner,
        handling_instructions=body.handling_instructions,
        retention_days=body.retention_days,
        encryption_required=body.encryption_required,
        org_id=org_id,
    )
    return engine.classify_asset(asset, changed_by="api-user")


@router.get("/assets", response_model=List[ClassifiedAsset])
def list_classified_assets(
    level: Optional[ClassificationLevel] = Query(None),
    category: Optional[DataCategory] = Query(None),
    org_id: str = Depends(get_org_id),
    engine: DataClassificationEngine = Depends(_engine),
) -> List[ClassifiedAsset]:
    """List classified assets, optionally filtered by level and/or category."""
    return engine.list_classified_assets(org_id, level=level, category=category)


@router.get("/assets/{asset_id}", response_model=ClassifiedAsset)
def get_asset_classification(
    asset_id: str,
    engine: DataClassificationEngine = Depends(_engine),
) -> ClassifiedAsset:
    """Retrieve the classification record for a specific asset."""
    asset = engine.get_asset_classification(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")
    return asset


@router.post("/assets/{asset_id}/auto-classify", response_model=AutoClassifyResult)
def auto_classify_asset(
    asset_id: str,
    body: AutoClassifyRequest,
    org_id: str = Depends(get_org_id),
    engine: DataClassificationEngine = Depends(_engine),
) -> AutoClassifyResult:
    """Scan content for PII/PHI/PCI patterns and auto-assign classification."""
    return engine.auto_classify(
        content=body.content,
        asset_id=asset_id,
        org_id=org_id,
        changed_by="api-user",
        apply=body.apply,
    )


@router.post("/assets/{asset_id}/upgrade", response_model=ClassifiedAsset)
def upgrade_classification(
    asset_id: str,
    body: UpgradeRequest,
    engine: DataClassificationEngine = Depends(_engine),
) -> ClassifiedAsset:
    """Escalate an asset's classification to a higher level."""
    try:
        return engine.upgrade_classification(
            asset_id=asset_id,
            new_level=body.new_level,
            changed_by=body.changed_by,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/assets/{asset_id}/downgrade", response_model=ClassifiedAsset)
def downgrade_classification(
    asset_id: str,
    body: DowngradeRequest,
    engine: DataClassificationEngine = Depends(_engine),
) -> ClassifiedAsset:
    """Lower an asset's classification level. Requires approval_id and reason."""
    try:
        return engine.downgrade_classification(
            asset_id=asset_id,
            new_level=body.new_level,
            changed_by=body.changed_by,
            approval_id=body.approval_id,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats", response_model=Dict[str, Any])
def get_classification_stats(
    org_id: str = Depends(get_org_id),
    engine: DataClassificationEngine = Depends(_engine),
) -> Dict[str, Any]:
    """Return classification statistics aggregated by level and category."""
    return engine.get_classification_stats(org_id)


@router.get("/audit", response_model=List[ClassificationChange])
def audit_classification_changes(
    asset_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    engine: DataClassificationEngine = Depends(_engine),
) -> List[ClassificationChange]:
    """Return audit trail of classification changes."""
    return engine.audit_classification_changes(
        asset_id=asset_id, action=action, limit=limit
    )


@router.get("/handling/{level}", response_model=Dict[str, str])
def get_handling_instructions(
    level: ClassificationLevel,
    engine: DataClassificationEngine = Depends(_engine),
) -> Dict[str, str]:
    """Return handling instructions for the specified classification level."""
    return {
        "level": level.value,
        "instructions": engine.get_handling_instructions(level),
    }
