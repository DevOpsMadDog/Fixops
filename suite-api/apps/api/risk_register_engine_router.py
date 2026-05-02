"""Risk Register Engine Router — ALDECI.

Endpoints for the RiskRegisterEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/risk-register-engine
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/risk-register-engine/risks                       create_risk
  GET   /api/v1/risk-register-engine/risks                       list_risks
  GET   /api/v1/risk-register-engine/risks/{risk_id}             get_risk
  PATCH /api/v1/risk-register-engine/risks/{risk_id}/status      update_risk_status
  POST  /api/v1/risk-register-engine/risks/{risk_id}/treatments  add_risk_treatment
  GET   /api/v1/risk-register-engine/treatments                  list_treatments
  GET   /api/v1/risk-register-engine/stats                       get_risk_stats
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/risk-register-engine",
    tags=["Risk Register Engine"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.risk_register_engine import RiskRegisterEngine
        _engine = RiskRegisterEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RiskCreate(BaseModel):
    name: str
    risk_category: str = "operational"
    description: str = ""
    likelihood: str = "possible"
    impact: str = "moderate"
    owner: str = ""


class RiskStatusUpdate(BaseModel):
    status: str
    treatment_plan: str = ""


class TreatmentCreate(BaseModel):
    treatment_type: str = "mitigate"
    description: str = ""
    cost_estimate: float = 0.0
    timeline_days: int = 0
    owner: str = ""


# ---------------------------------------------------------------------------
# Risks
# ---------------------------------------------------------------------------

@router.post("/risks", dependencies=[Depends(api_key_auth)], status_code=201)
def create_risk(body: RiskCreate, org_id: str = Query(default="default")):
    """Create a new risk with auto-computed risk_score and risk_level."""
    try:
        return _get_engine().create_risk(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/risks", dependencies=[Depends(api_key_auth)])
def list_risks(
     org_id: str = Query(default="default"),
    risk_category: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List risks with optional category, level, and status filters."""
    return _get_engine().list_risks(
        org_id,
        risk_category=risk_category,
        risk_level=risk_level,
        status=status,
    )


@router.get("/risks/{risk_id}", dependencies=[Depends(api_key_auth)])
def get_risk(risk_id: str, org_id: str = Query(default="default")):
    """Get a single risk by ID."""
    risk = _get_engine().get_risk(org_id, risk_id)
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    return risk


@router.patch("/risks/{risk_id}/status", dependencies=[Depends(api_key_auth)])
def update_risk_status(risk_id: str, body: RiskStatusUpdate, org_id: str = Query(default="default")):
    """Update risk status and optional treatment plan."""
    try:
        result = _get_engine().update_risk_status(
            org_id, risk_id, body.status, treatment_plan=body.treatment_plan
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Risk not found")
    return result


@router.post(
    "/risks/{risk_id}/treatments",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_risk_treatment(risk_id: str, body: TreatmentCreate, org_id: str = Query(default="default")):
    """Add a treatment record to a risk."""
    try:
        return _get_engine().add_risk_treatment(org_id, risk_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Treatments
# ---------------------------------------------------------------------------

@router.get("/treatments", dependencies=[Depends(api_key_auth)])
def list_treatments(
     org_id: str = Query(default="default"),
    risk_id: Optional[str] = Query(None),
):
    """List all treatments for an org, optionally filtered by risk_id."""
    return _get_engine().list_treatments(org_id, risk_id=risk_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_risk_stats(org_id: str = Query(default="default")):
    """Return aggregated risk statistics for an org."""
    return _get_engine().get_risk_stats(org_id)


@router.get("/risks/{risk_id}/context", dependencies=[Depends(api_key_auth)])
def get_risk_context(
    risk_id: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return TrustGraph cross-domain context for a risk (related findings, assets, incidents)."""
    return _get_engine().get_risk_context(org_id, risk_id)
