"""Data Governance Router — ALDECI.

REST API for managing data assets, governance policies, policy violations,
and data flows. Prefix: /api/v1/data-governance.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.data_governance_engine import DataGovernanceEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/data-governance",
    tags=["Data Governance"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = DataGovernanceEngine()
    return _engine


# ------------------------------------------------------------------
# Request / Response models
# ------------------------------------------------------------------


class RegisterAssetRequest(BaseModel):
    name: str
    description: str = ""
    asset_type: str = "database"
    classification: str = "internal"
    owner: str = ""
    data_categories: List[str] = Field(default_factory=list)
    retention_days: int = 365
    location: str = ""
    encrypted: bool = False
    last_audited: Optional[str] = None


class UpdateClassificationRequest(BaseModel):
    classification: str


class CreatePolicyRequest(BaseModel):
    name: str
    description: str = ""
    policy_type: str = "retention"
    applies_to_classification: str = ""
    requirement: str = ""
    enforcement: str = "advisory"
    status: str = "draft"


class LogViolationRequest(BaseModel):
    asset_id: str = ""
    policy_id: str = ""
    violation_type: str = ""
    description: str = ""
    severity: str = "medium"
    detected_at: Optional[str] = None


class ResolveViolationRequest(BaseModel):
    resolved_by: str


class AddDataFlowRequest(BaseModel):
    source_asset_id: str = ""
    destination: str = ""
    flow_type: str = "internal"
    data_categories: List[str] = Field(default_factory=list)
    encrypted: bool = False
    approved: bool = False


# ------------------------------------------------------------------
# Assets
# ------------------------------------------------------------------


@router.post("/assets", status_code=201, summary="Register a data asset")
def register_asset(
    body: RegisterAssetRequest,
    org_id: str = Query(default="default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().register_asset(org_id, body.model_dump())
    except Exception as exc:
        _logger.error("Failed to register asset: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/assets", summary="List data assets")
def list_assets(
    org_id: str = Query(default="default"),
    classification: Optional[str] = Query(default=None),
    asset_type: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    return _get_engine().list_assets(org_id, classification=classification, asset_type=asset_type)


@router.get("/assets/{asset_id}", summary="Get a data asset")
def get_asset(
    asset_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    asset = _get_engine().get_asset(org_id, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.patch("/assets/{asset_id}/classification", summary="Update asset classification")
def update_asset_classification(
    asset_id: str,
    body: UpdateClassificationRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    updated = _get_engine().update_asset_classification(org_id, asset_id, body.classification)
    if not updated:
        raise HTTPException(status_code=404, detail="Asset not found or invalid classification")
    return {"updated": True, "asset_id": asset_id, "classification": body.classification}


# ------------------------------------------------------------------
# Governance Policies
# ------------------------------------------------------------------


@router.post("/policies", status_code=201, summary="Create a governance policy")
def create_policy(
    body: CreatePolicyRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    try:
        return _get_engine().create_policy(org_id, body.model_dump())
    except Exception as exc:
        _logger.error("Failed to create policy: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/policies", summary="List governance policies")
def list_policies(
    org_id: str = Query(default="default"),
    policy_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    return _get_engine().list_policies(org_id, policy_type=policy_type, status=status)


# ------------------------------------------------------------------
# Policy Violations
# ------------------------------------------------------------------


@router.post("/violations", status_code=201, summary="Log a policy violation")
def log_violation(
    body: LogViolationRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    try:
        return _get_engine().log_violation(org_id, body.model_dump())
    except Exception as exc:
        _logger.error("Failed to log violation: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/violations", summary="List policy violations")
def list_violations(
    org_id: str = Query(default="default"),
    resolved: bool = Query(default=False),
    severity: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    return _get_engine().list_violations(org_id, resolved=resolved, severity=severity)


@router.post("/violations/{violation_id}/resolve", summary="Resolve a policy violation")
def resolve_violation(
    violation_id: str,
    body: ResolveViolationRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    resolved = _get_engine().resolve_violation(org_id, violation_id, body.resolved_by)
    if not resolved:
        raise HTTPException(status_code=404, detail="Violation not found or already resolved")
    return {"resolved": True, "violation_id": violation_id, "resolved_by": body.resolved_by}


# ------------------------------------------------------------------
# Data Flows
# ------------------------------------------------------------------


@router.post("/flows", status_code=201, summary="Add a data flow")
def add_data_flow(
    body: AddDataFlowRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    try:
        return _get_engine().add_data_flow(org_id, body.model_dump())
    except Exception as exc:
        _logger.error("Failed to add data flow: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/flows", summary="List data flows")
def list_data_flows(
    org_id: str = Query(default="default"),
    flow_type: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    return _get_engine().list_data_flows(org_id, flow_type=flow_type)


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------


@router.get("/stats", summary="Get governance statistics for an org")
def get_governance_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    return _get_engine().get_governance_stats(org_id)
