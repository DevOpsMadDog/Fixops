"""Threat Simulation Router — ALDECI.

Endpoints for the Threat Simulation engine.

Prefix: /api/v1/threat-simulation
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/threat-simulation/scenarios                          create_scenario
  GET   /api/v1/threat-simulation/scenarios                          list_scenarios
  GET   /api/v1/threat-simulation/scenarios/{scenario_id}            get_scenario
  POST  /api/v1/threat-simulation/simulations                        start_simulation
  POST  /api/v1/threat-simulation/simulations/{sim_id}/detections    record_detection
  PUT   /api/v1/threat-simulation/simulations/{sim_id}/complete      complete_simulation
  GET   /api/v1/threat-simulation/simulations                        list_simulations
  GET   /api/v1/threat-simulation/stats                              get_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-simulation",
    tags=["Threat Simulation"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_simulation_engine import ThreatSimulationEngine
        _engine = ThreatSimulationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScenarioCreate(BaseModel):
    name: str
    scenario_type: str
    difficulty: str = "medium"
    description: str = ""
    mitre_techniques: List[str] = Field(default_factory=list)


class SimulationStart(BaseModel):
    scenario_id: str
    initiated_by: str
    target_systems: List[str] = Field(default_factory=list)


class DetectionRecord(BaseModel):
    technique: str
    detected_by: str
    detection_time_seconds: int = 0
    true_positive: bool = True


class SimulationComplete(BaseModel):
    total_techniques_executed: int = 0
    techniques_detected: int = 0
    dwell_time_seconds: Optional[int] = None


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

@router.post("/scenarios", dependencies=[Depends(api_key_auth)], status_code=201)
def create_scenario(body: ScenarioCreate, org_id: str = Query(default="default")):
    """Create a new threat simulation scenario."""
    try:
        return _get_engine().create_scenario(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/scenarios", dependencies=[Depends(api_key_auth)])
def list_scenarios(
     org_id: str = Query(default="default"),
    scenario_type: Optional[str] = Query(None),
    difficulty: Optional[str] = Query(None),
):
    """List scenarios with optional filters."""
    return _get_engine().list_scenarios(
        org_id, scenario_type=scenario_type, difficulty=difficulty
    )


@router.get("/scenarios/{scenario_id}", dependencies=[Depends(api_key_auth)])
def get_scenario(scenario_id: str, org_id: str = Query(default="default")):
    """Get a single scenario by ID."""
    scenario = _get_engine().get_scenario(org_id, scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario


# ---------------------------------------------------------------------------
# Simulations
# ---------------------------------------------------------------------------

@router.post("/simulations", dependencies=[Depends(api_key_auth)], status_code=201)
def start_simulation(body: SimulationStart, org_id: str = Query(default="default")):
    """Start a new simulation run."""
    try:
        return _get_engine().start_simulation(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/simulations/{sim_id}/detections",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def record_detection(sim_id: str, body: DetectionRecord, org_id: str = Query(default="default")):
    """Record a technique detection within a simulation."""
    try:
        result = _get_engine().record_detection(org_id, sim_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return result


@router.put("/simulations/{sim_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_simulation(sim_id: str, body: SimulationComplete, org_id: str = Query(default="default")):
    """Mark a simulation as completed and compute metrics."""
    result = _get_engine().complete_simulation(org_id, sim_id, body.model_dump())
    if result is None:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return result


@router.get("/simulations", dependencies=[Depends(api_key_auth)])
def list_simulations(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    scenario_id: Optional[str] = Query(None),
):
    """List simulations with optional filters."""
    return _get_engine().list_simulations(
        org_id, status=status, scenario_id=scenario_id
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_simulation_stats(org_id: str = Query(default="default")):
    """Return aggregated simulation statistics for the org."""
    return _get_engine().get_simulation_stats(org_id)
