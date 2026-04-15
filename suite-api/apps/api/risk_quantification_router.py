"""Risk Quantification API Router — ALDECI.

FAIR-inspired financial risk quantification: scenarios, Monte Carlo simulation,
risk treatments, and financial impact recording.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/risk-quantification", tags=["risk-quantification"])

# ---------------------------------------------------------------------------
# Lazy engine singleton
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.risk_quantification_engine import RiskQuantificationEngine
            _engine = RiskQuantificationEngine()
        except Exception as exc:
            logger.error("Failed to initialise RiskQuantificationEngine: %s", exc)
            raise HTTPException(status_code=503, detail="Risk quantification engine unavailable")
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScenarioCreate(BaseModel):
    name: str = Field(..., description="Scenario name")
    threat_actor: str = Field("cybercriminal", description="nation_state/cybercriminal/insider/hacktivist/opportunist")
    attack_vector: str = Field("phishing", description="phishing/supply_chain/zero_day/credential/physical")
    target_asset_type: str = Field("data", description="data/infrastructure/application/personnel")
    likelihood_pct: float = Field(50.0, ge=0.0, le=100.0, description="Likelihood of occurrence (0-100%)")
    minimum_loss: float = Field(0.0, ge=0.0, description="Minimum financial loss ($)")
    maximum_loss: float = Field(0.0, ge=0.0, description="Maximum financial loss ($)")


class ScenarioUpdate(BaseModel):
    name: Optional[str] = None
    threat_actor: Optional[str] = None
    attack_vector: Optional[str] = None
    target_asset_type: Optional[str] = None
    likelihood_pct: Optional[float] = Field(None, ge=0.0, le=100.0)
    minimum_loss: Optional[float] = Field(None, ge=0.0)
    maximum_loss: Optional[float] = Field(None, ge=0.0)


class MonteCarloRequest(BaseModel):
    iterations: int = Field(1000, ge=1, le=100000, description="Number of simulation iterations")


class TreatmentCreate(BaseModel):
    scenario_id: str = Field(..., description="Parent scenario ID")
    treatment_type: str = Field("mitigate", description="accept/mitigate/transfer/avoid")
    description: str = Field("", description="Treatment description")
    cost: float = Field(0.0, ge=0.0, description="Implementation cost ($)")
    risk_reduction_pct: float = Field(0.0, ge=0.0, le=100.0, description="Expected risk reduction (%)")
    status: str = Field("proposed", description="proposed/approved/implemented")


class FinancialImpactCreate(BaseModel):
    incident_type: str = Field(..., description="Type of incident")
    direct_cost: float = Field(0.0, ge=0.0)
    regulatory_fines: float = Field(0.0, ge=0.0)
    remediation_cost: float = Field(0.0, ge=0.0)
    business_disruption_cost: float = Field(0.0, ge=0.0)
    reputational_cost: float = Field(0.0, ge=0.0)
    incident_date: Optional[str] = Field(None, description="ISO date string (defaults to now)")
    fiscal_year: Optional[int] = Field(None, description="Fiscal year (defaults to current year)")


# ---------------------------------------------------------------------------
# Endpoints — Scenarios
# ---------------------------------------------------------------------------

@router.get("/scenarios")
def list_scenarios(org_id: str = Query("default", description="Organisation ID")) -> List[Dict[str, Any]]:
    """List all risk scenarios for an org."""
    return _get_engine().list_scenarios(org_id)


@router.post("/scenarios", status_code=201)
def create_scenario(
    payload: ScenarioCreate,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Create a new FAIR risk scenario."""
    try:
        return _get_engine().create_scenario(org_id, payload.model_dump())
    except Exception as exc:
        logger.exception("Error creating risk scenario")
        raise HTTPException(status_code=500, detail=str(exc))


@router.patch("/scenarios/{scenario_id}")
def update_scenario(
    scenario_id: str,
    payload: ScenarioUpdate,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Update an existing risk scenario."""
    data = {k: v for k, v in payload.model_dump().items() if v is not None}
    updated = _get_engine().update_scenario(org_id, scenario_id, data)
    if not updated:
        raise HTTPException(status_code=404, detail="Scenario not found")
    scenario = _get_engine().get_scenario(org_id, scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario


# ---------------------------------------------------------------------------
# Endpoints — Monte Carlo
# ---------------------------------------------------------------------------

@router.post("/scenarios/{scenario_id}/monte-carlo")
def run_monte_carlo(
    scenario_id: str,
    payload: MonteCarloRequest,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Run a Monte Carlo loss simulation on the scenario."""
    try:
        return _get_engine().run_monte_carlo(org_id, scenario_id, payload.iterations)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception("Monte Carlo simulation failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints — Treatments
# ---------------------------------------------------------------------------

@router.get("/treatments")
def list_treatments(
    org_id: str = Query("default", description="Organisation ID"),
    scenario_id: Optional[str] = Query(None, description="Filter by scenario"),
) -> List[Dict[str, Any]]:
    """List risk treatments, optionally filtered by scenario."""
    return _get_engine().list_treatments(org_id, scenario_id)


@router.post("/treatments", status_code=201)
def create_treatment(
    payload: TreatmentCreate,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Create a risk treatment with auto-computed ROI."""
    try:
        return _get_engine().create_treatment(org_id, payload.scenario_id, payload.model_dump())
    except Exception as exc:
        logger.exception("Error creating treatment")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints — Financial Impacts
# ---------------------------------------------------------------------------

@router.get("/financial-impacts")
def list_financial_impacts(
    org_id: str = Query("default", description="Organisation ID"),
    fiscal_year: Optional[int] = Query(None, description="Filter by fiscal year"),
) -> List[Dict[str, Any]]:
    """List financial impacts, optionally filtered by fiscal year."""
    return _get_engine().list_financial_impacts(org_id, fiscal_year)


@router.post("/financial-impacts", status_code=201)
def record_financial_impact(
    payload: FinancialImpactCreate,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Record the financial impact of an actual security incident."""
    try:
        return _get_engine().record_financial_impact(org_id, payload.model_dump())
    except Exception as exc:
        logger.exception("Error recording financial impact")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints — Stats
# ---------------------------------------------------------------------------

@router.get("/stats")
def get_risk_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregate risk statistics for the org."""
    return _get_engine().get_risk_stats(org_id)
