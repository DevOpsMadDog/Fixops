"""Risk Scenario Router — ALDECI.

Endpoints for RiskScenarioEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/risk-scenarios
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/risk-scenarios/scenarios                                    create_scenario
  GET  /api/v1/risk-scenarios/scenarios                                    list_scenarios
  GET  /api/v1/risk-scenarios/scenarios/{id}                               get_scenario
  POST /api/v1/risk-scenarios/scenarios/{id}/mitigations                   add_mitigation
  POST /api/v1/risk-scenarios/scenarios/{id}/mitigations/{m_id}/implement  implement_mitigation
  POST /api/v1/risk-scenarios/scenarios/{id}/reviews                       review_scenario
  GET  /api/v1/risk-scenarios/top-risks                                    get_top_risks
  GET  /api/v1/risk-scenarios/risk-reduction                               get_risk_reduction_summary
  GET  /api/v1/risk-scenarios/stats                                        get_scenario_stats
"""
from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/risk-scenarios",
    tags=["Risk Scenarios"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.risk_scenario_engine import RiskScenarioEngine
        _engine = RiskScenarioEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScenarioCreate(BaseModel):
    scenario_name: str
    threat_category: str
    description: str = ""
    likelihood: float
    impact: float
    owner: str = ""


class MitigationCreate(BaseModel):
    mitigation_name: str
    mitigation_type: str = "technical"
    effectiveness: float = 0.5
    cost_estimate: float = 0.0


class ScenarioReview(BaseModel):
    reviewer: str
    likelihood_adjustment: float = 0.0
    impact_adjustment: float = 0.0
    notes: str = ""


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

@router.post("/scenarios", dependencies=[Depends(api_key_auth)], status_code=201)
def create_scenario(body: ScenarioCreate, org_id: str = Query(default="default")):
    """Create a new risk scenario with auto-computed inherent and residual risk."""
    try:
        return _get_engine().create_scenario(
            org_id,
            body.scenario_name,
            body.threat_category,
            body.description,
            body.likelihood,
            body.impact,
            owner=body.owner,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/scenarios", dependencies=[Depends(api_key_auth)])
def list_scenarios(
     org_id: str = Query(default="default"),
    risk_level: Optional[str] = Query(None),
    threat_category: Optional[str] = Query(None),
):
    """List scenarios with optional filters."""
    return _get_engine().list_scenarios(
        org_id, risk_level=risk_level, threat_category=threat_category
    )


@router.get("/scenarios/{scenario_id}", dependencies=[Depends(api_key_auth)])
def get_scenario(scenario_id: str, org_id: str = Query(default="default")):
    """Get a scenario with its mitigations and reviews."""
    result = _get_engine().get_scenario(scenario_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return result


@router.post(
    "/scenarios/{scenario_id}/mitigations",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_mitigation(scenario_id: str, body: MitigationCreate, org_id: str = Query(default="default")):
    """Add a mitigation to a scenario."""
    try:
        return _get_engine().add_mitigation(
            scenario_id,
            org_id,
            body.mitigation_name,
            mitigation_type=body.mitigation_type,
            effectiveness=body.effectiveness,
            cost_estimate=body.cost_estimate,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/scenarios/{scenario_id}/mitigations/{mitigation_id}/implement",
    dependencies=[Depends(api_key_auth)],
)
def implement_mitigation(scenario_id: str, mitigation_id: str, org_id: str = Query(default="default")):
    """Mark a mitigation as implemented and recompute residual risk."""
    result = _get_engine().implement_mitigation(mitigation_id, scenario_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Mitigation not found")
    return result


@router.post(
    "/scenarios/{scenario_id}/reviews",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def review_scenario(scenario_id: str, body: ScenarioReview, org_id: str = Query(default="default")):
    """Submit a review that adjusts scenario likelihood/impact."""
    return _get_engine().review_scenario(
        scenario_id,
        org_id,
        body.reviewer,
        body.likelihood_adjustment,
        body.impact_adjustment,
        notes=body.notes,
    )


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

@router.get("/top-risks", dependencies=[Depends(api_key_auth)])
def get_top_risks(org_id: str = Query(default="default"), limit: int = Query(10)):
    """Return top N scenarios ordered by residual risk."""
    return _get_engine().get_top_risks(org_id, limit=limit)


@router.get("/risk-reduction", dependencies=[Depends(api_key_auth)])
def get_risk_reduction_summary(org_id: str = Query(default="default")):
    """Return per-scenario inherent vs residual risk with reduction percentage."""
    return _get_engine().get_risk_reduction_summary(org_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_scenario_stats(org_id: str = Query(default="default")):
    """Return aggregated scenario statistics for an org."""
    return _get_engine().get_scenario_stats(org_id)


@router.get("", dependencies=[Depends(api_key_auth)])
def get_root(org_id: str = Query(default="default")):
    """Root endpoint — returns scenarios list for dashboard health-checks."""
    return _get_engine().list_scenarios(org_id)
