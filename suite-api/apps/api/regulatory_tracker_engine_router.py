"""
Regulatory Change Tracker Engine API router.

Endpoints for tracking regulatory changes, compliance obligations, and assessments.

Prefix: /api/v1/regulatory-tracker
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/regulatory-tracker", tags=["regulatory-tracker"])

# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.regulatory_tracker_engine import RegulatoryTrackerEngine
        db_path = os.environ.get(
            "REGULATORY_ENGINE_DB_PATH",
            "regulatory_tracker_engine.db",
        )
        _engine = RegulatoryTrackerEngine(db_path=db_path)
    return _engine


# ------------------------------------------------------------------
# Request models
# ------------------------------------------------------------------


class RegulationCreate(BaseModel):
    name: str = Field(..., min_length=1)
    jurisdiction: str = Field(default="")
    category: str = Field(default="cybersecurity")
    version: str = Field(default="")
    effective_date: str = Field(default="")
    status: str = Field(default="enacted")
    url: str = Field(default="")


class ChangeCreate(BaseModel):
    change_type: str = Field(default="new_requirement")
    title: str = Field(..., min_length=1)
    description: str = Field(default="")
    impact_level: str = Field(default="medium")
    affected_domains: List[str] = Field(default_factory=list)
    published_at: str = Field(default="")
    effective_at: str = Field(default="")
    action_required: bool = Field(default=True)


class ObligationCreate(BaseModel):
    reg_id: str = Field(..., min_length=1)
    change_id: Optional[str] = Field(default=None)
    title: str = Field(..., min_length=1)
    description: str = Field(default="")
    obligation_type: str = Field(default="technical")
    deadline: str = Field(default="")
    status: str = Field(default="pending")
    owner: str = Field(default="")


class ObligationStatusUpdate(BaseModel):
    status: str = Field(..., description="pending|in_progress|compliant|exempt")
    owner: Optional[str] = Field(default=None)


class AssessmentCreate(BaseModel):
    reg_id: str = Field(..., min_length=1)
    assessed_at: str = Field(default="")
    compliance_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    gaps_count: int = Field(default=0, ge=0)
    critical_gaps: int = Field(default=0, ge=0)
    assessor: str = Field(default="")
    notes: str = Field(default="")


# ------------------------------------------------------------------
# Regulations
# ------------------------------------------------------------------


@router.post("/regulations", status_code=201, response_model=Dict[str, Any])
async def add_regulation(
    body: RegulationCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Add a new regulation to track."""
    engine = _get_engine()
    return engine.add_regulation(org_id, body.model_dump())


@router.get("/regulations", response_model=List[Dict[str, Any]])
async def list_regulations(
    org_id: str = Query(default="default"),
    category: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List regulations for an org, optionally filtered by category and/or status."""
    engine = _get_engine()
    return engine.list_regulations(org_id, category=category, status=status)


# ------------------------------------------------------------------
# Regulatory Changes
# ------------------------------------------------------------------


@router.post("/regulations/{reg_id}/changes", status_code=201, response_model=Dict[str, Any])
async def add_change(
    reg_id: str,
    body: ChangeCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Add a regulatory change to a tracked regulation."""
    engine = _get_engine()
    data = body.model_dump()
    return engine.add_change(org_id, reg_id, data)


@router.get("/changes", response_model=List[Dict[str, Any]])
async def list_changes(
    org_id: str = Query(default="default"),
    impact_level: Optional[str] = Query(default=None),
    action_required: bool = Query(default=True),
) -> List[Dict[str, Any]]:
    """List regulatory changes ordered by effective_at ascending."""
    engine = _get_engine()
    return engine.list_changes(org_id, impact_level=impact_level, action_required=action_required)


@router.get("/changes/upcoming", response_model=List[Dict[str, Any]])
async def get_upcoming_changes(
    org_id: str = Query(default="default"),
    days_ahead: int = Query(default=90, ge=1, le=730),
) -> List[Dict[str, Any]]:
    """Return changes effective within the next N days (default 90)."""
    engine = _get_engine()
    return engine.get_upcoming_changes(org_id, days_ahead=days_ahead)


# ------------------------------------------------------------------
# Compliance Obligations
# ------------------------------------------------------------------


@router.post("/obligations", status_code=201, response_model=Dict[str, Any])
async def add_obligation(
    body: ObligationCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Add a compliance obligation."""
    engine = _get_engine()
    return engine.add_obligation(org_id, body.model_dump())


@router.get("/obligations", response_model=List[Dict[str, Any]])
async def list_obligations(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    deadline_before: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List compliance obligations, optionally filtered by status and/or deadline."""
    engine = _get_engine()
    return engine.list_obligations(org_id, status=status, deadline_before=deadline_before)


@router.patch("/obligations/{obligation_id}/status", response_model=Dict[str, Any])
async def update_obligation_status(
    obligation_id: str,
    body: ObligationStatusUpdate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Update the status (and optionally owner) of a compliance obligation."""
    engine = _get_engine()
    updated = engine.update_obligation_status(
        org_id, obligation_id, body.status, owner=body.owner
    )
    if not updated:
        raise HTTPException(
            status_code=404,
            detail=f"Obligation '{obligation_id}' not found for org '{org_id}' or invalid status.",
        )
    return {"obligation_id": obligation_id, "status": body.status, "updated": True}


# ------------------------------------------------------------------
# Assessments
# ------------------------------------------------------------------


@router.post("/assessments", status_code=201, response_model=Dict[str, Any])
async def record_assessment(
    body: AssessmentCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Record a compliance assessment for a regulation."""
    engine = _get_engine()
    return engine.record_assessment(org_id, body.model_dump())


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------


@router.get("/stats", response_model=Dict[str, Any])
async def get_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Aggregate regulatory stats for an org."""
    engine = _get_engine()
    return engine.get_regulatory_stats(org_id)
