"""CTEM Router — ALDECI.

Endpoints for the Continuous Threat Exposure Management engine.

Prefix: /api/v1/ctem
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/ctem/cycles                               start_cycle
  GET    /api/v1/ctem/cycles                               list_cycles
  GET    /api/v1/ctem/cycles/{cycle_id}                    get_cycle
  POST   /api/v1/ctem/cycles/{cycle_id}/advance            advance_stage
  POST   /api/v1/ctem/cycles/{cycle_id}/exposures          add_exposure
  GET    /api/v1/ctem/cycles/{cycle_id}/exposures          get_exposures
  PATCH  /api/v1/ctem/exposures/{exposure_id}              update_exposure
  POST   /api/v1/ctem/cycles/{cycle_id}/scope              scope_assets
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ctem",
    tags=["CTEM Engine"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.ctem_engine import CTEMEngine
        _engine = CTEMEngine()
    return _engine


def _cycle_to_dict(cycle) -> Dict[str, Any]:
    """Serialize a CTEMCycle Pydantic model to a plain dict."""
    return cycle.model_dump()


def _exposure_to_dict(exposure) -> Dict[str, Any]:
    """Serialize an Exposure Pydantic model to a plain dict."""
    return exposure.model_dump()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CycleCreate(BaseModel):
    name: str


class ExposureCreate(BaseModel):
    title: str
    description: str = ""
    asset_id: Optional[str] = None
    severity: str = "medium"
    exposure_type: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    business_impact: str = ""
    owner: str = ""


class ExposureUpdate(BaseModel):
    status: Optional[str] = None
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    owner: Optional[str] = None
    remediation_plan: Optional[str] = None


class ScopeAssets(BaseModel):
    asset_ids: List[str]


# ---------------------------------------------------------------------------
# Cycle routes
# ---------------------------------------------------------------------------

@router.post("/cycles", dependencies=[Depends(api_key_auth)], status_code=201)
def start_cycle(body: CycleCreate, org_id: str = Query(default="default")):
    """Create and start a new CTEM cycle at SCOPING stage."""
    try:
        cycle = _get_engine().start_cycle(body.name, org_id=org_id)
        return _cycle_to_dict(cycle)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/cycles", dependencies=[Depends(api_key_auth)])
def list_cycles(org_id: str = Query(default="default")):
    """List all CTEM cycles for an org, newest first."""
    cycles = _get_engine().list_cycles(org_id)
    return [_cycle_to_dict(c) for c in cycles]


@router.get("/cycles/{cycle_id}", dependencies=[Depends(api_key_auth)])
def get_cycle(cycle_id: str):
    """Get a single CTEM cycle by ID."""
    try:
        cycle = _get_engine().get_cycle(cycle_id)
        return _cycle_to_dict(cycle)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stage advancement
# ---------------------------------------------------------------------------

@router.post("/cycles/{cycle_id}/advance", dependencies=[Depends(api_key_auth)])
def advance_stage(cycle_id: str):
    """Advance a CTEM cycle to its next stage."""
    try:
        cycle = _get_engine().advance_stage(cycle_id)
        return _cycle_to_dict(cycle)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Exposure routes
# ---------------------------------------------------------------------------

@router.post(
    "/cycles/{cycle_id}/exposures",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_exposure(
    cycle_id: str,
    body: ExposureCreate,
    org_id: str = Query(default="default"),
):
    """Add an exposure to a CTEM cycle."""
    try:
        from core.ctem_engine import Exposure

        # Verify cycle exists and get org_id from it if not provided
        cycle = _get_engine().get_cycle(cycle_id)

        assets = [body.asset_id] if body.asset_id else []
        exposure = Exposure(
            title=body.title,
            description=body.description,
            assets=assets,
            risk_score=body.risk_score,
            business_impact=body.business_impact,
            owner=body.owner,
            org_id=cycle.org_id,
        )
        result = _get_engine().add_exposure(exposure)
        return _exposure_to_dict(result)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/cycles/{cycle_id}/exposures", dependencies=[Depends(api_key_auth)])
def get_exposures(cycle_id: str):
    """Return all exposures linked to a CTEM cycle."""
    try:
        exposures = _get_engine().get_exposures(cycle_id)
        return [_exposure_to_dict(e) for e in exposures]
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Exposure update
# ---------------------------------------------------------------------------

@router.patch("/exposures/{exposure_id}", dependencies=[Depends(api_key_auth)])
def update_exposure(exposure_id: str, body: ExposureUpdate):
    """Apply partial updates (status, risk_score, owner, remediation_plan) to an exposure."""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update provided")
    try:
        result = _get_engine().update_exposure(exposure_id, updates)
        return _exposure_to_dict(result)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Scope assets
# ---------------------------------------------------------------------------

@router.post("/cycles/{cycle_id}/scope", dependencies=[Depends(api_key_auth)])
def scope_assets(cycle_id: str, body: ScopeAssets):
    """Stage 1 — define the asset scope for this CTEM cycle."""
    try:
        cycle = _get_engine().scope_assets(cycle_id, body.asset_ids)
        return _cycle_to_dict(cycle)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
