"""
FixOps Breach Simulation API Router.

REST API for breach simulation capabilities:
- Run attack scenarios against defenses
- Retrieve scenario step definitions
- Evaluate defense coverage per org
- Query simulation history
- Get gap analysis and defense coverage
- Compare simulations over time
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.breach_simulation import (
    AttackScenario,
    DefenseCoverage,
    GapAnalysis,
    SimulationResult,
    get_breach_simulator,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/breach-sim", tags=["breach-simulation"])


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class RunSimulationRequest(BaseModel):
    """Request to run a breach simulation."""

    scenario: AttackScenario = Field(..., description="Attack scenario to simulate")
    org_id: str = Field(..., description="Organisation identifier")


class CompareSimulationsRequest(BaseModel):
    """Request to compare multiple simulations."""

    sim_ids: List[str] = Field(
        ..., min_length=2, description="Simulation IDs to compare (min 2)"
    )


class SimulationResultResponse(BaseModel):
    """API response for a simulation result."""

    id: str
    scenario: str
    steps_executed: int
    steps_blocked: int
    detection_time_seconds: float
    containment_time_seconds: float
    data_at_risk: str
    defenses_tested: List[str]
    gaps_found: List[str]
    score: float
    org_id: str
    simulated_at: str

    @classmethod
    def from_result(cls, r: SimulationResult) -> "SimulationResultResponse":
        return cls(
            id=r.id,
            scenario=r.scenario.value,
            steps_executed=r.steps_executed,
            steps_blocked=r.steps_blocked,
            detection_time_seconds=r.detection_time_seconds,
            containment_time_seconds=r.containment_time_seconds,
            data_at_risk=r.data_at_risk,
            defenses_tested=r.defenses_tested,
            gaps_found=r.gaps_found,
            score=r.score,
            org_id=r.org_id,
            simulated_at=r.simulated_at,
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/run", response_model=SimulationResultResponse)
async def run_simulation(req: RunSimulationRequest):
    """Run a breach simulation scenario against current defenses.

    Executes all attack steps for the chosen scenario, evaluates which
    defenses trigger, and returns a scored SimulationResult with gaps
    and timing metrics. Result is persisted to SQLite.
    """
    sim = get_breach_simulator()
    result = sim.run_simulation(scenario=req.scenario, org_id=req.org_id)
    return SimulationResultResponse.from_result(result)


@router.get("/scenarios", response_model=List[Dict[str, Any]])
async def list_scenarios():
    """List all available attack scenarios with metadata."""
    return [
        {
            "scenario": s.value,
            "name": s.value.replace("_", " ").title(),
            "step_count": len(get_breach_simulator().get_scenario_steps(s)),
        }
        for s in AttackScenario
    ]


@router.get("/scenarios/{scenario}/steps")
async def get_scenario_steps(scenario: str):
    """Get the attack steps for a specific scenario."""
    try:
        attack_scenario = AttackScenario(scenario)
    except ValueError:
        valid = [s.value for s in AttackScenario]
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario '{scenario}'. Valid: {valid}",
        )
    sim = get_breach_simulator()
    steps = sim.get_scenario_steps(attack_scenario)
    return {
        "scenario": scenario,
        "step_count": len(steps),
        "steps": [s.model_dump() for s in steps],
    }


@router.get("/scenarios/{scenario}/evaluate")
async def evaluate_defenses(
    scenario: str,
    org_id: str = Query(..., description="Organisation ID to evaluate defenses for"),
):
    """Evaluate which defenses would trigger for a scenario without persisting."""
    try:
        attack_scenario = AttackScenario(scenario)
    except ValueError:
        valid = [s.value for s in AttackScenario]
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario '{scenario}'. Valid: {valid}",
        )
    sim = get_breach_simulator()
    evaluated = sim.evaluate_defenses(attack_scenario, org_id)
    blocked = [s for s in evaluated if s.blocked]
    return {
        "scenario": scenario,
        "org_id": org_id,
        "total_steps": len(evaluated),
        "blocked_count": len(blocked),
        "pass_rate": round(100.0 * len(blocked) / max(len(evaluated), 1), 2),
        "steps": [s.model_dump() for s in evaluated],
    }


@router.get("/history/{org_id}", response_model=List[SimulationResultResponse])
async def get_simulation_history(
    org_id: str,
    limit: int = Query(50, ge=1, le=500, description="Max results to return"),
):
    """Get simulation history for an organisation, newest first."""
    sim = get_breach_simulator()
    history = sim.get_simulation_history(org_id=org_id, limit=limit)
    return [SimulationResultResponse.from_result(r) for r in history]


@router.get("/coverage/{org_id}", response_model=DefenseCoverage)
async def get_defense_coverage(org_id: str):
    """Get defense coverage summary — which attack types have been tested."""
    sim = get_breach_simulator()
    return sim.get_defense_coverage(org_id=org_id)


@router.get("/gaps/{org_id}", response_model=GapAnalysis)
async def get_gap_analysis(org_id: str):
    """Get gap analysis — where defenses are weakest across all simulations."""
    sim = get_breach_simulator()
    return sim.get_gap_analysis(org_id=org_id)


@router.post("/compare")
async def compare_simulations(req: CompareSimulationsRequest):
    """Compare multiple simulations to track improvement over time."""
    sim = get_breach_simulator()
    return sim.compare_simulations(sim_ids=req.sim_ids)


@router.get("/health")
async def breach_sim_health():
    """Health check for the breach simulation engine."""
    get_breach_simulator()
    return {
        "status": "healthy",
        "engine": "BreachSimulator",
        "scenarios_available": len(list(AttackScenario)),
        "scenarios": [s.value for s in AttackScenario],
        "features": [
            "8_attack_scenarios",
            "defense_evaluation",
            "gap_analysis",
            "simulation_history",
            "coverage_tracking",
            "simulation_comparison",
            "sqlite_persistence",
        ],
    }
