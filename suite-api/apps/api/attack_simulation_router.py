"""Attack Simulation Router — ALDECI.

Endpoints for the AttackSimulationDbEngine (SQLite-backed, multi-tenant).

Prefix: /api/v1/attack-sim
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/attack-sim/simulations                            create_simulation
  GET    /api/v1/attack-sim/simulations                            list_simulations
  GET    /api/v1/attack-sim/simulations/{sim_id}                   get_simulation
  POST   /api/v1/attack-sim/simulations/{sim_id}/attack-paths      add_attack_path
  GET    /api/v1/attack-sim/simulations/{sim_id}/attack-paths      list_attack_paths
  POST   /api/v1/attack-sim/simulations/{sim_id}/findings          create_finding
  GET    /api/v1/attack-sim/findings                               list_findings
  GET    /api/v1/attack-sim/mitre-coverage                         get_mitre_coverage
  GET    /api/v1/attack-sim/stats                                  get_simulation_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/attack-sim",
    tags=["Attack Simulation"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.attack_simulation_engine import AttackSimulationDbEngine
        _engine = AttackSimulationDbEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SimulationCreate(BaseModel):
    name: str = "Unnamed Simulation"
    simulation_type: str = Field(default="BAS", description="BAS | RedTeam | PenTest | Tabletop")
    scope: str = ""
    target_profile: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="planned", description="planned | running | completed | failed | cancelled")
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class AttackPathCreate(BaseModel):
    tactic: str = ""
    technique_id: str = ""
    technique_name: str = ""
    success: bool = False
    detection_time_seconds: Optional[float] = None


class FindingCreate(BaseModel):
    technique_id: str = ""
    title: str = "Unnamed Finding"
    severity: str = Field(default="medium", description="critical | high | medium | low | info")
    remediation_priority: Optional[int] = None


# ---------------------------------------------------------------------------
# Simulation routes
# ---------------------------------------------------------------------------

@router.post("/simulations", dependencies=[Depends(api_key_auth)], status_code=201)
def create_simulation(body: SimulationCreate, org_id: str = Query(default="default")):
    """Create a new simulation run."""
    try:
        return _get_engine().create_simulation(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/simulations", dependencies=[Depends(api_key_auth)])
def list_simulations(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
):
    """List simulation runs for an org, optionally filtered by status."""
    return _get_engine().list_simulations(org_id, status=status)


@router.get("/simulations/{sim_id}", dependencies=[Depends(api_key_auth)])
def get_simulation(sim_id: str, org_id: str = Query(default="default")):
    """Get a single simulation run by ID."""
    sim = _get_engine().get_simulation(org_id, sim_id)
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return sim


# ---------------------------------------------------------------------------
# Attack path routes
# ---------------------------------------------------------------------------

@router.post(
    "/simulations/{sim_id}/attack-paths",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_attack_path(
    sim_id: str,
    body: AttackPathCreate,
     org_id: str = Query(default="default"),
):
    """Add an attack path step to a simulation. Also upserts MITRE coverage."""
    try:
        return _get_engine().add_attack_path(org_id, sim_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/simulations/{sim_id}/attack-paths", dependencies=[Depends(api_key_auth)])
def list_attack_paths(sim_id: str, org_id: str = Query(default="default")):
    """List all attack paths for a simulation."""
    return _get_engine().list_attack_paths(org_id, sim_id)


# ---------------------------------------------------------------------------
# Finding routes
# ---------------------------------------------------------------------------

@router.post(
    "/simulations/{sim_id}/findings",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def create_finding(
    sim_id: str,
    body: FindingCreate,
     org_id: str = Query(default="default"),
):
    """Create a simulation finding."""
    try:
        return _get_engine().create_finding(org_id, sim_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
     org_id: str = Query(default="default"),
    sim_id: Optional[str] = Query(None),
):
    """List findings for an org, optionally filtered by sim_id."""
    return _get_engine().list_findings(org_id, sim_id=sim_id)


# ---------------------------------------------------------------------------
# MITRE coverage
# ---------------------------------------------------------------------------

@router.get("/mitre-coverage", dependencies=[Depends(api_key_auth)])
def get_mitre_coverage(org_id: str = Query(default="default")):
    """Return per-tactic MITRE ATT&CK coverage percentage across all simulations."""
    return _get_engine().get_mitre_coverage(org_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_simulation_stats(org_id: str = Query(default="default")):
    """Return aggregate simulation statistics for an org."""
    return _get_engine().get_simulation_stats(org_id)
