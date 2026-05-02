"""
FedRAMP Compliance Controls API endpoints.

Provides 10 endpoints for managing FedRAMP control implementation status,
gap analysis, SSP generation, POA&M, and ALDECI feature mapping.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.fedramp_controls import (
    ControlFamily,
    ControlStatus,
    FedRAMPBaseline,
    FedRAMPControl,
    FedRAMPManager,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/fedramp", tags=["fedramp"])

_manager = None  # lazy-initialised on first request


def _get_manager():
    global _manager
    if _manager is None:
        _manager = FedRAMPManager()
    return _manager


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ControlStatusUpdate(BaseModel):
    """Request body for updating a control's implementation status."""

    status: ControlStatus
    implementation_notes: str = ""
    evidence_ids: Optional[List[str]] = None


class AddControlRequest(BaseModel):
    """Request body for adding a custom control."""

    id: str = Field(..., description="Control identifier, e.g. AC-99")
    family: ControlFamily
    title: str
    description: str
    baseline: List[FedRAMPBaseline] = Field(default_factory=list)
    status: ControlStatus = ControlStatus.PLANNED
    evidence_ids: List[str] = Field(default_factory=list)
    implementation_notes: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/controls", response_model=List[Dict[str, Any]])
async def list_controls(
    family: Optional[str] = Query(None, description="Filter by control family (e.g. AC, AU)"),
    baseline: Optional[str] = Query(None, description="Filter by baseline: LOW, MODERATE, HIGH"),
    status: Optional[str] = Query(None, description="Filter by status: implemented, partial, planned, not_applicable"),
):
    """List FedRAMP controls with optional filters by family, baseline, and status."""
    family_enum: Optional[ControlFamily] = None
    baseline_enum: Optional[FedRAMPBaseline] = None
    status_enum: Optional[ControlStatus] = None

    if family:
        try:
            family_enum = ControlFamily(family.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid family: {family}")

    if baseline:
        try:
            baseline_enum = FedRAMPBaseline(baseline.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid baseline: {baseline}")

    if status:
        try:
            status_enum = ControlStatus(status.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    controls = _get_manager().list_controls(
        family=family_enum, baseline=baseline_enum, status=status_enum
    )
    return [c.model_dump() for c in controls]


@router.get("/controls/{control_id}", response_model=Dict[str, Any])
async def get_control(control_id: str):
    """Retrieve a single FedRAMP control by its ID (e.g. AC-1)."""
    ctrl = _get_manager().get_control(control_id.upper())
    if ctrl is None:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return ctrl.model_dump()


@router.post("/controls", response_model=Dict[str, Any], status_code=201)
async def add_control(body: AddControlRequest):
    """Add a custom FedRAMP control to the registry."""
    control = FedRAMPControl(
        id=body.id.upper(),
        family=body.family,
        title=body.title,
        description=body.description,
        baseline=body.baseline,
        status=body.status,
        evidence_ids=body.evidence_ids,
        implementation_notes=body.implementation_notes,
    )
    created = _get_manager().add_control(control)
    return created.model_dump()


@router.patch("/controls/{control_id}/status", response_model=Dict[str, Any])
async def update_control_status(control_id: str, body: ControlStatusUpdate):
    """Update the implementation status of a FedRAMP control."""
    updated = _get_manager().update_status(
        control_id=control_id.upper(),
        status=body.status,
        implementation_notes=body.implementation_notes,
        evidence_ids=body.evidence_ids,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return updated.model_dump()


@router.get("/score/{baseline}", response_model=Dict[str, Any])
async def get_compliance_score(baseline: str):
    """Get compliance score for a given FedRAMP baseline (LOW, MODERATE, HIGH)."""
    try:
        baseline_enum = FedRAMPBaseline(baseline.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid baseline: {baseline}")
    score = _get_manager().get_compliance_score(baseline_enum)
    return score.model_dump()


@router.get("/gap-analysis/{baseline}", response_model=Dict[str, Any])
async def get_gap_analysis(baseline: str):
    """Return gap analysis showing controls not yet implemented for a baseline."""
    try:
        baseline_enum = FedRAMPBaseline(baseline.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid baseline: {baseline}")
    gap = _get_manager().get_gap_analysis(baseline_enum)
    return gap.model_dump()


@router.get("/ssp/{baseline}", response_model=Dict[str, Any])
async def generate_ssp(
    baseline: str,
    system_name: str = Query("ALDECI", description="System name for the SSP"),
    system_owner: str = Query("DevOpsMadDog", description="System owner"),
):
    """Generate System Security Plan (SSP) data for the specified baseline."""
    try:
        baseline_enum = FedRAMPBaseline(baseline.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid baseline: {baseline}")
    ssp = _get_manager().generate_ssp_data(
        baseline=baseline_enum,
        system_name=system_name,
        system_owner=system_owner,
    )
    return ssp.model_dump()


@router.get("/feature-mapping", response_model=Dict[str, List[str]])
async def get_feature_mapping():
    """Return the mapping of ALDECI features to FedRAMP control IDs."""
    return _get_manager().map_aldeci_features_to_controls()


@router.get("/feature-mapping/{feature_name}", response_model=List[Dict[str, Any]])
async def get_controls_for_feature(feature_name: str):
    """Return FedRAMP controls associated with a specific ALDECI feature."""
    controls = _get_manager().get_controls_for_feature(feature_name)
    if not controls:
        raise HTTPException(
            status_code=404,
            detail=f"Feature '{feature_name}' not found or has no mapped controls",
        )
    return [c.model_dump() for c in controls]


@router.get("/poam", response_model=List[Dict[str, Any]])
async def get_poam(
    baseline: Optional[str] = Query(None, description="Filter POA&M by baseline"),
):
    """Return Plan of Action and Milestones for unimplemented controls."""
    baseline_enum: Optional[FedRAMPBaseline] = None
    if baseline:
        try:
            baseline_enum = FedRAMPBaseline(baseline.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid baseline: {baseline}")
    items = _get_manager().get_poam(baseline=baseline_enum)
    return [item.model_dump() for item in items]


@router.get("/stats", response_model=Dict[str, Any])
async def get_fedramp_stats():
    """Return aggregate FedRAMP compliance statistics across all controls."""
    stats = _get_manager().get_fedramp_stats()
    return stats.model_dump()
