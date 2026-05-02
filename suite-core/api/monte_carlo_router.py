"""Monte Carlo Risk Simulation Router — /api/v1/risk/simulate.

Exposes the FAIR-based MonteCarloRiskEngine for stochastic
risk quantification, CVE-specific risk, and portfolio simulation.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/risk/simulate", tags=["Monte Carlo Risk"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class FAIRSimulationRequest(BaseModel):
    """Full FAIR model simulation request."""
    tef_min: float = Field(0.1, description="Min threat event frequency (per year)")
    tef_max: float = Field(10.0, description="Max threat event frequency")
    tef_mode: float = Field(2.0, description="Most likely threat event frequency")
    vuln_min: float = Field(0.1, description="Min vulnerability probability")
    vuln_max: float = Field(0.9, description="Max vulnerability probability")
    vuln_mode: float = Field(0.5, description="Most likely vulnerability probability")
    primary_loss_min: float = Field(10000, description="Min primary loss ($)")
    primary_loss_max: float = Field(1000000, description="Max primary loss ($)")
    primary_loss_mode: float = Field(100000, description="Most likely primary loss ($)")
    secondary_loss_min: float = Field(50000, description="Min secondary loss ($)")
    secondary_loss_max: float = Field(5000000, description="Max secondary loss ($)")
    secondary_loss_mode: float = Field(500000, description="Most likely secondary loss ($)")
    slef_probability: float = Field(0.3, description="Secondary loss event probability")
    asset_value: float = Field(1000000, description="Asset value ($)")
    iterations: int = Field(10000, ge=100, le=100000, description="Monte Carlo iterations")


class CVSSSimulationRequest(BaseModel):
    """Simplified simulation from CVSS score."""
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSS score")
    asset_value: float = Field(1000000, description="Asset value ($)")
    has_exploit: bool = False
    is_internet_facing: bool = False
    industry: str = Field("technology", description="Industry vertical")
    iterations: int = Field(10000, ge=100, le=100000)


class CVERiskRequest(BaseModel):
    """CVE-specific risk quantification."""
    cve_id: str
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    epss_score: float = Field(0.0, ge=0.0, le=1.0)
    kev_listed: bool = False
    asset_value: float = 1000000
    is_reachable: bool = True


class PortfolioRiskRequest(BaseModel):
    """Portfolio-level risk simulation across multiple CVEs."""
    cves: List[CVERiskRequest]
    correlation_factor: float = Field(
        0.3, ge=0.0, le=1.0,
        description="Assumed correlation between CVE losses (0=independent, 1=fully correlated)",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/fair", summary="Full FAIR model simulation")
async def simulate_fair(req: FAIRSimulationRequest) -> Dict[str, Any]:
    """Run a full FAIR Monte Carlo simulation with custom parameters."""
    from core.monte_carlo import FAIRInputs, MonteCarloRiskEngine

    engine = MonteCarloRiskEngine(iterations=req.iterations)
    inputs = FAIRInputs(
        tef_min=req.tef_min, tef_max=req.tef_max, tef_mode=req.tef_mode,
        vuln_min=req.vuln_min, vuln_max=req.vuln_max, vuln_mode=req.vuln_mode,
        primary_loss_min=req.primary_loss_min, primary_loss_max=req.primary_loss_max,
        primary_loss_mode=req.primary_loss_mode,
        secondary_loss_min=req.secondary_loss_min, secondary_loss_max=req.secondary_loss_max,
        secondary_loss_mode=req.secondary_loss_mode,
        slef_probability=req.slef_probability, asset_value=req.asset_value,
    )
    result = engine.simulate(inputs)
    return result.to_dict()


@router.post("/cvss", summary="Simulate from CVSS score")
async def simulate_from_cvss(req: CVSSSimulationRequest) -> Dict[str, Any]:
    """Derive FAIR inputs from a CVSS score and run simulation."""
    from core.monte_carlo import simulate_risk_for_cve

    return simulate_risk_for_cve(
        cvss_score=req.cvss_score,
        asset_value=req.asset_value,
        has_exploit=req.has_exploit,
        is_internet_facing=req.is_internet_facing,
        industry=req.industry,
        iterations=req.iterations,
    )


@router.post("/cve", summary="CVE-specific risk quantification")
async def quantify_cve(req: CVERiskRequest) -> Dict[str, Any]:
    """Quantify financial risk for a specific CVE using FAIR + threat intelligence."""
    from core.monte_carlo import quantify_cve_risk

    return quantify_cve_risk(
        cve_id=req.cve_id,
        cvss_score=req.cvss_score,
        epss_score=req.epss_score,
        kev_listed=req.kev_listed,
        asset_value=req.asset_value,
        is_reachable=req.is_reachable,
    )


@router.post("/portfolio", summary="Portfolio risk aggregation")
async def portfolio_risk(req: PortfolioRiskRequest) -> Dict[str, Any]:
    """Aggregate risk across multiple CVEs with correlation."""
    from core.monte_carlo import quantify_cve_risk

    individual_results = []
    total_mean_loss = 0.0
    total_var95 = 0.0

    for cve in req.cves:
        result = quantify_cve_risk(
            cve_id=cve.cve_id, cvss_score=cve.cvss_score,
            epss_score=cve.epss_score, kev_listed=cve.kev_listed,
            asset_value=cve.asset_value, is_reachable=cve.is_reachable,
        )
        individual_results.append(result)
        total_mean_loss += result.get("mean_annual_loss", 0)
        total_var95 += result.get("value_at_risk", {}).get("var_95", 0)

    # Apply correlation factor (simple square-root-of-sum-of-squares approach)
    import math
    n = len(req.cves)
    corr = req.correlation_factor
    diversification = math.sqrt(n + n * (n - 1) * corr) / n if n > 0 else 1.0

    return {
        "portfolio_mean_annual_loss": round(total_mean_loss * diversification, 2),
        "portfolio_var_95": round(total_var95 * diversification, 2),
        "diversification_factor": round(diversification, 4),
        "correlation_factor": corr,
        "cve_count": n,
        "individual_results": individual_results,
    }

