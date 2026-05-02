"""
Compliance Planner API — gap remediation planning endpoints.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
Supports 7 frameworks: SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF, CIS, GDPR.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.compliance_planner import (
    CompliancePlanner,
    ImplementationStatus,
    RemediationPriority,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/compliance-planner", tags=["compliance-planner"])

_planner = CompliancePlanner()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class GapInput(BaseModel):
    control_id: str
    control_name: str
    gap_description: str
    findings_that_fix: List[str] = Field(default_factory=list)


class GeneratePlanRequest(BaseModel):
    gaps: List[GapInput]


class UpdateStatusRequest(BaseModel):
    status: ImplementationStatus
    notes: str = ""


class AssignRequest(BaseModel):
    assigned_to: str
    target_date: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=Dict[str, Any], summary="Compliance planner summary")
async def get_planner_summary(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return planner stats: plan count, remediation counts by status/priority, effort summary."""
    try:
        return _planner.get_planner_stats(org_id=org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/generate/{framework}", response_model=Dict[str, Any], status_code=201)
async def generate_plan(
    framework: str,
    body: GeneratePlanRequest,
    org_id: str = Depends(get_org_id),
):
    """Generate (or regenerate) a remediation plan for the given framework."""
    gaps = [g.model_dump() for g in body.gaps]
    plan = _planner.generate_plan(framework=framework, gaps=gaps, org_id=org_id)
    return plan.model_dump(mode="json")


@router.get("/plans", response_model=Dict[str, Any])
async def list_plans(org_id: str = Depends(get_org_id)):
    """List all remediation plans for the org."""
    plans = _planner.list_plans(org_id=org_id)
    return {
        "items": [p.model_dump(mode="json") for p in plans],
        "total": len(plans),
    }


@router.get("/plans/{framework}", response_model=Dict[str, Any])
async def get_plan(framework: str, org_id: str = Depends(get_org_id)):
    """Get a remediation plan for a specific framework."""
    plan = _planner.get_plan(framework=framework, org_id=org_id)
    if plan is None:
        raise HTTPException(status_code=404, detail=f"No plan found for framework: {framework}")
    return plan.model_dump(mode="json")


@router.get("/remediations", response_model=Dict[str, Any])
async def list_remediations(
    org_id: str = Depends(get_org_id),
    framework: Optional[str] = Query(default=None),
    status: Optional[ImplementationStatus] = Query(default=None),
    priority: Optional[RemediationPriority] = Query(default=None),
):
    """List remediation items with optional filters."""
    items = _planner.list_remediations(
        org_id=org_id,
        framework=framework,
        status_filter=status,
        priority_filter=priority,
    )
    return {
        "items": [r.model_dump(mode="json") for r in items],
        "total": len(items),
    }


@router.get("/remediations/{remediation_id}", response_model=Dict[str, Any])
async def get_remediation(
    remediation_id: str,
    org_id: str = Depends(get_org_id),
):
    """Get a single remediation item by ID."""
    rem = _planner.get_remediation(remediation_id)
    if rem is None or rem.org_id != org_id:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return rem.model_dump(mode="json")


@router.put("/remediations/{remediation_id}/status", response_model=Dict[str, Any])
async def update_status(
    remediation_id: str,
    body: UpdateStatusRequest,
    org_id: str = Depends(get_org_id),
):
    """Update the implementation status of a remediation item."""
    existing = _planner.get_remediation(remediation_id)
    if existing is None or existing.org_id != org_id:
        raise HTTPException(status_code=404, detail="Remediation not found")
    updated = _planner.update_remediation_status(
        remediation_id=remediation_id,
        status=body.status,
        notes=body.notes,
    )
    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to update remediation status")
    return updated.model_dump(mode="json")


@router.put("/remediations/{remediation_id}/assign", response_model=Dict[str, Any])
async def assign_remediation(
    remediation_id: str,
    body: AssignRequest,
    org_id: str = Depends(get_org_id),
):
    """Assign a remediation item to a person with an optional target date."""
    existing = _planner.get_remediation(remediation_id)
    if existing is None or existing.org_id != org_id:
        raise HTTPException(status_code=404, detail="Remediation not found")
    updated = _planner.assign_remediation(
        remediation_id=remediation_id,
        assigned_to=body.assigned_to,
        target_date=body.target_date,
    )
    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to assign remediation")
    return updated.model_dump(mode="json")


@router.get("/effort", response_model=Dict[str, Any])
async def get_effort_summary(org_id: str = Depends(get_org_id)):
    """Get total estimated effort hours by framework and priority."""
    return _planner.get_effort_summary(org_id=org_id)


@router.get("/blocked", response_model=Dict[str, Any])
async def get_blocked_items(org_id: str = Depends(get_org_id)):
    """Get all remediations currently in BLOCKED status."""
    items = _planner.get_blocked_items(org_id=org_id)
    return {
        "items": [r.model_dump(mode="json") for r in items],
        "total": len(items),
    }


@router.get("/overdue", response_model=Dict[str, Any])
async def get_overdue_items(org_id: str = Depends(get_org_id)):
    """Get all remediations past their target date and not yet completed."""
    items = _planner.get_overdue_items(org_id=org_id)
    return {
        "items": [r.model_dump(mode="json") for r in items],
        "total": len(items),
    }


@router.get("/stats", response_model=Dict[str, Any])
async def get_planner_stats(org_id: str = Depends(get_org_id)):
    """Get aggregate planner statistics: by framework, by status, completion rates."""
    return _planner.get_planner_stats(org_id=org_id)
