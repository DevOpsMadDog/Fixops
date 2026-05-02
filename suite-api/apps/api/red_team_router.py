"""Red Team Simulation API Router.

Automated adversary simulation using MITRE ATT&CK techniques.
Simulations are deterministic (seeded random) — not actually attacking anything.

Prefix: /api/v1/red-team
"""
from __future__ import annotations

import logging
from typing import Optional

from core.red_team_engine import INTENSITY_LEVELS, TACTICS, RedTeamEngine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/red-team", tags=["red-team"])

# ---------------------------------------------------------------------------
# Singleton engine
# ---------------------------------------------------------------------------

_engine: Optional[RedTeamEngine] = None


def _get_engine() -> RedTeamEngine:
    global _engine
    if _engine is None:
        _engine = RedTeamEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateSimulationRequest(BaseModel):
    name: str = Field(..., description="Human-readable simulation name")
    target_profile: dict = Field(
        default_factory=dict, description="Optional metadata about target scope"
    )
    tactics: list[str] = Field(
        default_factory=list,
        description=(
            f"MITRE ATT&CK tactics to include. Empty = all. "
            f"Valid: {list(TACTICS.keys())}"
        ),
    )
    intensity: str = Field(
        "medium",
        description=f"Simulation intensity: {list(INTENSITY_LEVELS)}",
    )
    org_id: str = Field("default", description="Organisation ID")


class RunSimulationRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/simulations", summary="Create a new red team simulation")
def create_simulation(req: CreateSimulationRequest) -> dict:
    try:
        sim_id = _get_engine().create_simulation(
            org_id=req.org_id,
            sim={
                "name": req.name,
                "target_profile": req.target_profile,
                "tactics": req.tactics,
                "intensity": req.intensity,
            },
        )
        return {"simulation_id": sim_id, "status": "created"}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create simulation")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/simulations/{simulation_id}/run",
    summary="Execute a simulation and return results",
)
def run_simulation(simulation_id: str, req: RunSimulationRequest) -> dict:
    try:
        return _get_engine().run_simulation(
            org_id=req.org_id,
            simulation_id=simulation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to run simulation")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/simulations", summary="List all simulations for an org")
def list_simulations(
    org_id: str = Query("default", description="Organisation ID"),
) -> list[dict]:
    try:
        return _get_engine().list_simulations(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to list simulations")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/simulations/{simulation_id}/results",
    summary="Get latest execution results for a simulation",
)
def get_simulation_results(
    simulation_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> dict:
    try:
        return _get_engine().get_simulation_results(
            org_id=org_id,
            simulation_id=simulation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to get simulation results")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/attack-surface-score", summary="Aggregate attack surface score across all simulations")
def attack_surface_score(
    org_id: str = Query("default", description="Organisation ID"),
) -> dict:
    try:
        return _get_engine().get_attack_surface_score(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to compute attack surface score")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/mitre-coverage", summary="MITRE ATT&CK detection coverage per tactic")
def mitre_coverage(
    org_id: str = Query("default", description="Organisation ID"),
) -> dict:
    try:
        return _get_engine().get_mitre_coverage(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to compute MITRE coverage")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
