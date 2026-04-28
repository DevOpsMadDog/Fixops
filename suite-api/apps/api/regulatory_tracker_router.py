"""
Regulatory Change Tracker API endpoints.

8 endpoints for tracking compliance regulation changes and assessing
organisational impact (GDPR, PCI DSS v4, SEC, NIS2, DORA, AI Act, etc.).

Compliance: SOC2 CC6.1, ISO27001 A.18.1
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.regulatory_tracker import Regulation, RegulatoryTracker
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/regulatory", tags=["regulatory"])

# Module-level tracker — uses file-based SQLite in production, memory in tests
_DB_PATH = os.environ.get("REGULATORY_DB_PATH", "regulatory_tracker.db")
_tracker: Optional[RegulatoryTracker] = None


def _get_tracker() -> RegulatoryTracker:
    global _tracker
    if _tracker is None:
        _tracker = RegulatoryTracker(db_path=_DB_PATH)
    return _tracker


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class RegulationCreate(BaseModel):
    """Request body for adding a regulation."""

    framework: str = Field(..., min_length=1, description="e.g. GDPR, PCI-DSS, NIS2")
    title: str = Field(..., min_length=1)
    description: str = Field(default="")
    effective_date: str = Field(..., description="ISO-8601 date e.g. 2024-03-31")
    impact: str = Field(..., description="high | medium | low")
    affected_controls: List[str] = Field(default_factory=list)
    status: str = Field(default="upcoming", description="upcoming | active | superseded")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/regulations", response_model=Dict[str, str], status_code=201)
async def add_regulation(
    body: RegulationCreate,
    org_id: str = Depends(get_org_id),
) -> Dict[str, str]:
    """
    Track a new regulatory change.

    Returns the assigned regulation ID.
    """
    if body.impact not in ("high", "medium", "low"):
        raise HTTPException(status_code=422, detail="impact must be 'high', 'medium', or 'low'")
    if body.status not in ("upcoming", "active", "superseded"):
        raise HTTPException(
            status_code=422,
            detail="status must be 'upcoming', 'active', or 'superseded'",
        )

    tracker = _get_tracker()
    regulation = Regulation(
        framework=body.framework,
        title=body.title,
        description=body.description,
        effective_date=body.effective_date,
        impact=body.impact,
        affected_controls=body.affected_controls,
        status=body.status,
        org_id=org_id,
    )
    reg_id = tracker.add_regulation(regulation)
    return {"regulation_id": reg_id}


@router.get("/regulations/upcoming", response_model=List[Dict[str, Any]])
async def get_upcoming_regulations(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return regulations coming into effect (status=upcoming)."""
    tracker = _get_tracker()
    regulations = tracker.get_upcoming(org_id)
    return [r.model_dump() for r in regulations]


@router.get("/regulations/active", response_model=List[Dict[str, Any]])
async def get_active_regulations(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return currently enforced regulations (status=active)."""
    tracker = _get_tracker()
    regulations = tracker.get_active(org_id)
    return [r.model_dump() for r in regulations]


@router.get("/regulations/timeline", response_model=List[Dict[str, Any]])
async def get_regulatory_timeline(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Chronological view of all regulations ordered by effective date."""
    tracker = _get_tracker()
    return tracker.get_regulatory_timeline(org_id)


@router.get("/impact/summary", response_model=Dict[str, Any])
async def get_impact_summary(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Total regulatory exposure: gaps, effort days, high-impact count."""
    tracker = _get_tracker()
    return tracker.get_impact_summary(org_id)


@router.post("/impact/{regulation_id}", response_model=Dict[str, Any])
async def assess_impact(
    regulation_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Analyse the impact of a specific regulation on the organisation.

    Returns gap count, affected controls, remediation flag, and effort estimate.
    """
    tracker = _get_tracker()
    try:
        impact = tracker.assess_impact(regulation_id, org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return impact.model_dump()


@router.get("/action-plan/{regulation_id}", response_model=Dict[str, Any])
async def get_action_plan(
    regulation_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Generate a prioritised action plan to comply with a regulation.

    Returns ordered steps with owners, effort estimates, and priorities.
    """
    tracker = _get_tracker()
    try:
        plan = tracker.generate_action_plan(regulation_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return plan


@router.get("/stats", response_model=Dict[str, Any])
async def get_tracker_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Statistics grouped by framework and impact level."""
    tracker = _get_tracker()
    return tracker.get_tracker_stats(org_id)
