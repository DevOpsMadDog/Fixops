"""
Threat Intelligence Sharing API Router — ALDECI.

REST API for STIX/TAXII-lite threat intel sharing:
- Sharing groups management
- Indicator sharing and retrieval
- STIX 2.1 bundle export/import
- Sharing policies

Prefix: /api/v1/threat-sharing
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-sharing",
    tags=["threat-sharing"],
)

# Lazy-load engine singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_intel_sharing_engine import ThreatIntelSharingEngine
        _engine = ThreatIntelSharingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateGroupRequest(BaseModel):
    name: str = Field(..., min_length=1)
    trust_level: str = Field(default="closed")
    members: List[str] = Field(default_factory=list)


class ShareIndicatorRequest(BaseModel):
    indicator_type: str = Field(default="ip")
    value: str = Field(..., min_length=1)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    severity: str = Field(default="medium")
    tlp_marking: str = Field(default="AMBER")
    source: str = Field(default="aldeci")
    expires_at: Optional[str] = None


class ImportBundleRequest(BaseModel):
    bundle: Dict[str, Any] = Field(...)
    source_name: str = Field(..., min_length=1)


class CreatePolicyRequest(BaseModel):
    name: str = Field(..., min_length=1)
    auto_share_severity: str = Field(default="critical")
    require_tlp: str = Field(default="AMBER")
    anonymize_source: bool = Field(default=False)
    enabled: bool = Field(default=True)


# ---------------------------------------------------------------------------
# Sharing Groups
# ---------------------------------------------------------------------------


@router.post("/groups", summary="Create a sharing group")
def create_group(req: CreateGroupRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().create_group(org_id, req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/groups", summary="List sharing groups")
def list_groups(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    return _get_engine().list_groups(org_id)


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------


@router.post("/groups/{group_id}/indicators", summary="Share an indicator")
def share_indicator(group_id: str, req: ShareIndicatorRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().share_indicator(org_id, group_id, req.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/indicators", summary="List shared indicators")
def list_indicators(
    group_id: Optional[str] = Query(None),
    indicator_type: Optional[str] = Query(None),
    tlp: Optional[str] = Query(None),
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_indicators(
        org_id, group_id=group_id, indicator_type=indicator_type, tlp=tlp
    )


# ---------------------------------------------------------------------------
# STIX Bundle Export / Import
# ---------------------------------------------------------------------------


@router.get("/groups/{group_id}/export/stix", summary="Export indicators as STIX 2.1 bundle")
def export_stix_bundle(group_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().export_stix_bundle(org_id, group_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/import/stix", summary="Import a STIX 2.1 bundle")
def import_stix_bundle(req: ImportBundleRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().import_stix_bundle(org_id, req.bundle, req.source_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.post("/policies", summary="Create a sharing policy")
def create_policy(req: CreatePolicyRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().create_policy(org_id, req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", summary="Get threat sharing statistics")
def get_sharing_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_sharing_stats(org_id)
