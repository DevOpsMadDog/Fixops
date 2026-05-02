"""Digital Twin Security Router — ALDECI.

Endpoints for the Digital Twin Security engine.

Prefix: /api/v1/digital-twin
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/digital-twin/twins                            create_twin
  GET   /api/v1/digital-twin/twins                            list_twins
  GET   /api/v1/digital-twin/twins/{id}                       get_twin
  POST  /api/v1/digital-twin/twins/{id}/simulations           run_simulation
  GET   /api/v1/digital-twin/simulations                      list_simulations
  POST  /api/v1/digital-twin/simulations/{id}/findings        add_finding
  GET   /api/v1/digital-twin/findings                         list_findings
  GET   /api/v1/digital-twin/stats                            get_twin_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/digital-twin",
    tags=["Digital Twin Security"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.digital_twin_security_engine import DigitalTwinSecurityEngine
        _engine = DigitalTwinSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TwinCreate(BaseModel):
    name: str
    twin_type: str = "network"
    description: str = ""
    asset_count: int = 0
    fidelity_level: str = "medium"
    sync_status: str = "stale"


class SimulationCreate(BaseModel):
    simulation_type: str = "attack_path"
    parameters_json: dict = {}


class FindingCreate(BaseModel):
    title: str
    severity: str = "medium"
    description: str = ""
    remediation: str = ""
    twin_id: str = ""


# ---------------------------------------------------------------------------
# Twins
# ---------------------------------------------------------------------------

@router.post("/twins", dependencies=[Depends(api_key_auth)], status_code=201)
def create_twin(body: TwinCreate, org_id: str = Query(default="default")):
    """Create a new digital twin."""
    try:
        return _get_engine().create_twin(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/twins", dependencies=[Depends(api_key_auth)])
def list_twins(
     org_id: str = Query(default="default"),
    twin_type: Optional[str] = Query(None),
):
    """List digital twins with optional type filter."""
    return _get_engine().list_twins(org_id, twin_type=twin_type)


@router.get("/twins/{twin_id}", dependencies=[Depends(api_key_auth)])
def get_twin(twin_id: str, org_id: str = Query(default="default")):
    """Get a single digital twin by ID."""
    twin = _get_engine().get_twin(org_id, twin_id)
    if not twin:
        raise HTTPException(status_code=404, detail="Twin not found")
    return twin


# ---------------------------------------------------------------------------
# Simulations
# ---------------------------------------------------------------------------

@router.post("/twins/{twin_id}/simulations", dependencies=[Depends(api_key_auth)], status_code=201)
def run_simulation(twin_id: str, body: SimulationCreate, org_id: str = Query(default="default")):
    """Run a simulation on a digital twin."""
    try:
        return _get_engine().run_simulation(org_id, twin_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/simulations", dependencies=[Depends(api_key_auth)])
def list_simulations(
     org_id: str = Query(default="default"),
    twin_id: Optional[str] = Query(None),
    simulation_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List simulations with optional filters."""
    return _get_engine().list_simulations(
        org_id,
        twin_id=twin_id,
        simulation_type=simulation_type,
        status=status,
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@router.post("/simulations/{simulation_id}/findings", dependencies=[Depends(api_key_auth)], status_code=201)
def add_finding(simulation_id: str, body: FindingCreate, org_id: str = Query(default="default")):
    """Add a finding to a simulation."""
    try:
        return _get_engine().add_finding(org_id, simulation_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
     org_id: str = Query(default="default"),
    twin_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List findings with optional filters."""
    return _get_engine().list_findings(
        org_id,
        twin_id=twin_id,
        severity=severity,
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_twin_stats(org_id: str = Query(default="default")):
    """Return aggregated digital twin statistics."""
    return _get_engine().get_twin_stats(org_id)
