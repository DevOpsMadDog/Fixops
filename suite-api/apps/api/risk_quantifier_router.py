"""
Risk Quantification REST API — FAIR-based financial risk modeling endpoints.

Endpoints:
    POST /api/v1/risk-quantifier/scenarios          - Create risk scenario
    GET  /api/v1/risk-quantifier/scenarios          - List scenarios for org
    GET  /api/v1/risk-quantifier/scenarios/{id}     - Get scenario by ID
    POST /api/v1/risk-quantifier/scenarios/{id}/quantify  - Run Monte Carlo quantification
    POST /api/v1/risk-quantifier/findings/quantify  - Auto-quantify from finding
    GET  /api/v1/risk-quantifier/portfolio          - Total org risk exposure
    GET  /api/v1/risk-quantifier/roi                - Investment vs risk reduction ROI
    POST /api/v1/risk-quantifier/compare            - Side-by-side scenario comparison
    GET  /api/v1/risk-quantifier/heatmap            - Probability × impact heatmap
    GET  /api/v1/risk-quantifier/asset-templates    - List built-in asset value templates
    GET  /api/v1/risk-quantifier/health             - Service health check

Compliance: SOC2 CC3.2 (Risk Assessment), CC9.1 (Risk Mitigation)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from apps.api.billing_router import requires_tier
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/risk-quantifier", tags=["Risk Quantification"])

# ---------------------------------------------------------------------------
# Lazy import helper — avoids import-time failures if pydantic not available
# ---------------------------------------------------------------------------

def _get_engine():
    """Return the RiskQuantifier singleton."""
    from core.risk_quantifier import get_risk_quantifier

    db_path = os.environ.get("RISK_QUANTIFIER_DB", "risk_quantifier.db")
    return get_risk_quantifier(db_path=db_path)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateScenarioRequest(BaseModel):
    """Request body for creating a risk scenario."""

    name: str = Field(..., description="Human-readable scenario name")
    threat_event: str = Field(..., description="Description of the threat event")
    asset_value_usd: float = Field(..., ge=0, description="Asset value in USD")
    loss_magnitude_low: float = Field(..., ge=0, description="Minimum loss estimate (USD)")
    loss_magnitude_high: float = Field(..., ge=0, description="Maximum loss estimate (USD)")
    probability_low: float = Field(..., ge=0.0, le=1.0, description="Min annual probability")
    probability_high: float = Field(..., ge=0.0, le=1.0, description="Max annual probability")
    annual_loss_expectancy: Optional[float] = Field(None, description="Optional ALE override")
    scenario_id: Optional[str] = Field(None, description="Optional explicit scenario ID")


class QuantifyFindingRequest(BaseModel):
    """Request body for auto-quantifying a finding."""

    id: Optional[str] = None
    title: Optional[str] = None
    severity: str = "medium"
    asset_type: Optional[str] = None
    asset_value_usd: Optional[float] = None
    description: Optional[str] = None


class CompareRequest(BaseModel):
    """Request body for scenario comparison."""

    scenario_ids: List[str] = Field(..., min_length=2, description="IDs of scenarios to compare")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scenarios")
async def create_scenario(
    req: CreateScenarioRequest,
    org_id: str = Depends(requires_tier("pro")),
) -> Dict[str, Any]:
    """
    Create a new FAIR risk scenario with financial parameters.

    Returns the created scenario with its assigned ID.
    """
    try:
        engine = _get_engine()
        scenario = engine.create_scenario(
            name=req.name,
            threat_event=req.threat_event,
            asset_value_usd=req.asset_value_usd,
            loss_magnitude_low=req.loss_magnitude_low,
            loss_magnitude_high=req.loss_magnitude_high,
            probability_low=req.probability_low,
            probability_high=req.probability_high,
            annual_loss_expectancy=req.annual_loss_expectancy,
            org_id=org_id,
            scenario_id=req.scenario_id,
        )
        return {"status": "created", "scenario": scenario.model_dump()}
    except Exception as exc:
        logger.exception("Error creating risk scenario")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/scenarios")
async def list_scenarios(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    List all risk scenarios for the organization.
    """
    try:
        engine = _get_engine()
        scenarios = engine.list_scenarios(org_id=org_id)
        return {
            "status": "ok",
            "org_id": org_id,
            "count": len(scenarios),
            "scenarios": [s.model_dump() for s in scenarios],
        }
    except Exception as exc:
        logger.exception("Error listing risk scenarios")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/scenarios/{scenario_id}")
async def get_scenario(
    scenario_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Retrieve a risk scenario by ID.
    """
    try:
        engine = _get_engine()
        scenario = engine.get_scenario(scenario_id)
        if scenario is None:
            raise HTTPException(status_code=404, detail=f"Scenario not found: {scenario_id}")
        return {"status": "ok", "scenario": scenario.model_dump()}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error fetching scenario %s", scenario_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/scenarios/{scenario_id}/quantify")
async def quantify_scenario(
    scenario_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Run Monte Carlo simulation (1000 iterations) to quantify ALE for a scenario.

    Returns ALE at 10th, 50th, 90th percentiles, risk tier, and recommended
    control investment.
    """
    try:
        engine = _get_engine()
        result = engine.quantify(scenario_id)
        return {"status": "ok", "quantified_risk": result.model_dump()}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error quantifying scenario %s", scenario_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/findings/quantify")
async def quantify_finding(
    req: QuantifyFindingRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Auto-create a risk scenario from a finding and quantify it.

    Derives financial parameters from severity and asset_type using built-in
    templates. Useful for bulk triage without manual scenario definition.
    """
    try:
        engine = _get_engine()
        result = engine.quantify_finding(finding=req.model_dump(), org_id=org_id)
        return {"status": "ok", "quantified_risk": result.model_dump()}
    except Exception as exc:
        logger.exception("Error quantifying finding")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/portfolio")
async def portfolio_risk(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Get total financial risk exposure for the organization.

    Aggregates latest ALE estimates across all scenarios, with tier
    breakdown and top-10 highest-risk scenarios.
    """
    try:
        engine = _get_engine()
        portfolio = engine.get_portfolio_risk(org_id=org_id)
        return {"status": "ok", **portfolio}
    except Exception as exc:
        logger.exception("Error computing portfolio risk for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/roi")
async def roi_analysis(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Return investment vs risk reduction ROI analysis.

    Computes net benefit, ROI%, and payback period for recommended controls.
    Assumes 70% control effectiveness (industry-standard FAIR assumption).
    """
    try:
        engine = _get_engine()
        roi = engine.get_roi_analysis(org_id=org_id)
        return {"status": "ok", **roi}
    except Exception as exc:
        logger.exception("Error computing ROI for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/compare")
async def compare_scenarios(
    req: CompareRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Side-by-side comparison of multiple risk scenarios.

    Returns scenarios sorted by ALE descending with full financial breakdown.
    """
    try:
        engine = _get_engine()
        comparison = engine.compare_scenarios(req.scenario_ids)
        return {
            "status": "ok",
            "org_id": org_id,
            "count": len(comparison),
            "scenarios": comparison,
        }
    except Exception as exc:
        logger.exception("Error comparing scenarios")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/heatmap")
async def risk_heatmap(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Return probability × impact matrix data for heatmap visualization.

    Organizes scenarios into a 5×5 grid by probability band and loss magnitude
    band. Each cell contains scenario count and cumulative ALE.
    """
    try:
        engine = _get_engine()
        heatmap = engine.get_risk_heatmap(org_id=org_id)
        return {"status": "ok", **heatmap}
    except Exception as exc:
        logger.exception("Error generating heatmap for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/asset-templates")
async def asset_templates(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    List built-in asset value templates.

    Returns asset types and their default USD valuations for use when creating
    scenarios without explicit asset_value_usd.
    """
    from core.risk_quantifier import ASSET_VALUE_TEMPLATES

    return {
        "status": "ok",
        "templates": [
            {"asset_type": k, "default_value_usd": v}
            for k, v in sorted(ASSET_VALUE_TEMPLATES.items())
        ],
        "count": len(ASSET_VALUE_TEMPLATES),
    }


@router.get("/health")
async def health(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Risk quantification service health check."""
    return {
        "status": "healthy",
        "engine": "risk_quantifier",
        "methodology": "FAIR",
        "monte_carlo_iterations": 1000,
        "version": "1.0.0",
    }


__all__ = ["router"]
