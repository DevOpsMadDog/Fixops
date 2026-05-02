"""Risk Treatment Router — ALDECI.

Endpoints for the RiskTreatmentEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/risk-treatment
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/risk-treatment/treatments                              create_treatment
  GET    /api/v1/risk-treatment/treatments                              list_treatments
  GET    /api/v1/risk-treatment/treatments/{treatment_id}               get_treatment
  PATCH  /api/v1/risk-treatment/treatments/{treatment_id}/status        update_treatment_status
  POST   /api/v1/risk-treatment/treatments/{treatment_id}/notes         add_progress_note
  GET    /api/v1/risk-treatment/treatments/{treatment_id}/notes         list_progress_notes
  GET    /api/v1/risk-treatment/stats                                   get_treatment_stats
"""
from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/risk-treatment",
    tags=["Risk Treatment"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.risk_treatment_engine import RiskTreatmentEngine
        _engine = RiskTreatmentEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TreatmentCreate(BaseModel):
    title: str
    risk_id: str = ""
    description: str = ""
    treatment_type: str = "mitigate"
    treatment_status: str = "planned"
    risk_level: str = "medium"
    owner: str = ""
    due_date: str = ""
    cost_estimate: float = 0.0
    actual_cost: float = 0.0
    residual_risk_level: str = ""
    progress_pct: int = 0


class TreatmentStatusUpdate(BaseModel):
    new_status: str
    progress_pct: Optional[int] = None


class ProgressNoteCreate(BaseModel):
    note: str
    author: str
    progress_pct_at_note: int = 0


# ---------------------------------------------------------------------------
# Treatments
# ---------------------------------------------------------------------------

@router.post("/treatments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_treatment(body: TreatmentCreate, org_id: str = Query(default="default")):
    """Create a new risk treatment record."""
    try:
        return _get_engine().create_treatment(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/treatments", dependencies=[Depends(api_key_auth)])
def list_treatments(
    org_id: str = Query(default="default"),
    treatment_type: Optional[str] = Query(None),
    treatment_status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List treatments (canonical envelope, batch-6).

    Class-c contract: empty IS correct for fresh tenants — risk treatments
    are a manual/policy-driven workflow, not a feed-importable artifact.
    Always returns full envelope with pagination context + filters echo +
    actionable hint when empty.
    """
    rows = _get_engine().list_treatments(
        org_id,
        treatment_type=treatment_type,
        treatment_status=treatment_status,
        risk_level=risk_level,
    ) or []
    paged = rows[offset : offset + limit] if offset else rows[:limit]
    envelope = {
        "items": paged,
        "treatments": paged,  # legacy key preserved
        "total": len(rows),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
        "filters_applied": {
            "treatment_type": treatment_type,
            "treatment_status": treatment_status,
            "risk_level": risk_level,
        },
    }
    if not rows:
        envelope["hint"] = (
            "Create a risk treatment via POST /api/v1/risk-treatment/treatments "
            "once risks are identified. This is a manual/policy-driven workflow; "
            "empty IS the correct response for a fresh tenant."
        )
    return envelope


@router.get("/treatments/{treatment_id}", dependencies=[Depends(api_key_auth)])
def get_treatment(treatment_id: str, org_id: str = Query(default="default")):
    """Get a single treatment by ID."""
    result = _get_engine().get_treatment(org_id, treatment_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Treatment not found")
    return result


@router.patch("/treatments/{treatment_id}/status", dependencies=[Depends(api_key_auth)])
def update_treatment_status(
    treatment_id: str,
    body: TreatmentStatusUpdate,
     org_id: str = Query(default="default"),
):
    """Update treatment status and optionally progress_pct."""
    try:
        return _get_engine().update_treatment_status(
            org_id, treatment_id, body.new_status, progress_pct=body.progress_pct
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Progress Notes
# ---------------------------------------------------------------------------

@router.post(
    "/treatments/{treatment_id}/notes",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_progress_note(
    treatment_id: str,
    body: ProgressNoteCreate,
     org_id: str = Query(default="default"),
):
    """Add a progress note to a treatment."""
    try:
        return _get_engine().add_progress_note(org_id, treatment_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/treatments/{treatment_id}/notes", dependencies=[Depends(api_key_auth)])
def list_progress_notes(treatment_id: str, org_id: str = Query(default="default")):
    """List all progress notes for a treatment, ordered by created_at DESC."""
    return _get_engine().list_progress_notes(org_id, treatment_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_treatment_stats(org_id: str = Query(default="default")):
    """Return aggregated treatment statistics for an org."""
    return _get_engine().get_treatment_stats(org_id)
