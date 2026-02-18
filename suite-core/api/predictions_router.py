"""Predictive analytics router for security state prediction.

Provides API endpoints for Markov Chain and Bayesian Network based
security predictions and risk trajectory analysis.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/predictions", tags=["predictions"])


# ============================================================================
# Request/Response Models
# ============================================================================


class AttackChainRequest(BaseModel):
    """Request for attack chain prediction."""

    cve_id: str = Field(..., description="CVE identifier")
    cvss_score: float = Field(7.5, ge=0, le=10, description="CVSS score (0-10)")
    has_exploit: bool = Field(False, description="Whether an exploit is available")
    is_network_exposed: bool = Field(
        True, description="Whether vulnerability is network-accessible"
    )


class RiskTrajectoryRequest(BaseModel):
    """Request for risk trajectory calculation."""

    current_state: str = Field("Initial", description="Current security state")
    horizon_steps: int = Field(
        10, ge=1, le=50, description="Number of steps to predict"
    )


class SimulationRequest(BaseModel):
    """Request for attack path simulation."""

    start_state: str = Field("Initial", description="Starting security state")
    max_steps: int = Field(20, ge=1, le=100, description="Maximum simulation steps")
    seed: Optional[int] = Field(None, description="Random seed for reproducibility")


class BayesianUpdateRequest(BaseModel):
    """Request for Bayesian probability update."""

    components: List[Dict[str, Any]] = Field(
        ..., description="Component definitions with optional observed states"
    )
    network: Dict[str, Any] = Field(
        ..., description="Bayesian network definition with nodes and CPTs"
    )


class VulnerabilityRiskRequest(BaseModel):
    """Request for vulnerability risk assessment using Bayesian Network."""

    exploitation: str = Field(
        "none", description="Exploitation status: none, poc, active"
    )
    exposure: str = Field(
        "controlled", description="Exposure level: controlled, limited, open"
    )
    utility: str = Field(
        "laborious", description="Attack utility: laborious, efficient, super_effective"
    )
    safety_impact: str = Field(
        "negligible",
        description="Safety impact: negligible, marginal, major, hazardous",
    )
    mission_impact: str = Field(
        "degraded", description="Mission impact: degraded, crippled, mev"
    )


# ============================================================================
# Markov Chain Endpoints
# ============================================================================


@router.post("/attack-chain")
def predict_attack_chain(request: AttackChainRequest) -> Dict[str, Any]:
    """Predict attack chain progression for a specific CVE.

    Uses Markov Chain modeling based on MITRE ATT&CK kill chain to predict
    likely attack progression and time-to-impact.
    """
    try:
        from core.models.markov_chain import create_attack_chain_for_cve

        result = create_attack_chain_for_cve(
            cve_id=request.cve_id,
            cvss_score=request.cvss_score,
            has_exploit=request.has_exploit,
            is_network_exposed=request.is_network_exposed,
        )

        return {
            "status": "success",
            "prediction": result,
        }
    except ImportError as e:
        raise HTTPException(
            status_code=503, detail=f"Markov Chain module not available: {e}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Attack chain prediction failed: {e}"
        )


@router.post("/risk-trajectory")
def calculate_risk_trajectory(request: RiskTrajectoryRequest) -> Dict[str, Any]:
    """Calculate risk trajectory over time horizon.

    Computes n-step transition probabilities to predict risk evolution.
    """
    try:
        from core.models.markov_chain import SecurityMarkovChain

        chain = SecurityMarkovChain()
        trajectory = chain.calculate_risk_trajectory(
            current_state=request.current_state,
            horizon_steps=request.horizon_steps,
        )

        return {
            "status": "success",
            "trajectory": trajectory,
        }
    except ImportError as e:
        raise HTTPException(
            status_code=503, detail=f"Markov Chain module not available: {e}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Risk trajectory calculation failed: {e}"
        )


@router.post("/simulate-attack")
def simulate_attack_path(request: SimulationRequest) -> Dict[str, Any]:
    """Simulate an attack path from starting state.

    Runs Monte Carlo simulation of attack progression through security states.
    """
    try:
        from core.models.markov_chain import SecurityMarkovChain

        chain = SecurityMarkovChain()
        attack_path = chain.simulate_attack_path(
            start_state=request.start_state,
            max_steps=request.max_steps,
            seed=request.seed,
        )

        return {
            "status": "success",
            "simulation": {
                "start_state": request.start_state,
                "max_steps": request.max_steps,
                "path": attack_path,
                "total_steps": len(attack_path),
                "final_state": attack_path[-1]["state"]
                if attack_path
                else request.start_state,
            },
        }
    except ImportError as e:
        raise HTTPException(
            status_code=503, detail=f"Markov Chain module not available: {e}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack simulation failed: {e}")


@router.get("/markov/states")
def get_markov_states() -> Dict[str, Any]:
    """Get all security states in the Markov Chain model."""
    try:
        from core.models.markov_chain import SecurityMarkovChain

        chain = SecurityMarkovChain()
        chain_dict = chain.to_dict()

        return {
            "status": "success",
            "states": chain_dict["states"],
            "n_states": chain_dict["n_states"],
        }
    except ImportError as e:
        raise HTTPException(
            status_code=503, detail=f"Markov Chain module not available: {e}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve states: {e}")


@router.get("/markov/transitions")
def get_markov_transitions() -> Dict[str, Any]:
    """Get all state transitions with probabilities."""
    try:
        from core.models.markov_chain import SecurityMarkovChain

        chain = SecurityMarkovChain()
        chain_dict = chain.to_dict()

        return {
            "status": "success",
            "transitions": chain_dict["transitions"],
            "n_transitions": len(chain_dict["transitions"]),
        }
    except ImportError as e:
        raise HTTPException(
            status_code=503, detail=f"Markov Chain module not available: {e}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve transitions: {e}"
        )


# ============================================================================
# Bayesian Network Endpoints
# ============================================================================


@router.post("/bayesian/update")
def bayesian_update(request: BayesianUpdateRequest) -> Dict[str, Any]:
    """Update probabilities using Bayesian inference.

    Computes posterior probabilities for components given observed states
    and network structure.
    """
    try:
        from new_backend.processing.bayesian import (
            attach_component_posterior,
            update_probabilities,
        )

        posteriors = update_probabilities(request.components, request.network)
        updated_components = attach_component_posterior(request.components, posteriors)

        return {
            "status": "success",
            "posteriors": posteriors,
            "components": updated_components,
        }
    except ImportError as e:
        raise HTTPException(
            status_code=503, detail=f"Bayesian module not available: {e}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bayesian update failed: {e}")


@router.post("/bayesian/risk-assessment")
def bayesian_risk_assessment(request: VulnerabilityRiskRequest) -> Dict[str, Any]:
    """Assess vulnerability risk using Bayesian Network model.

    Uses pgmpy-based Bayesian Network with SSVC-inspired factors to compute
    risk probability distribution.
    """
    try:
        from core.models.bayesian_network import PGMPY_AVAILABLE, BayesianNetworkModel

        # Prepare input features as context
        context = {
            "exploitation": request.exploitation,
            "exposure": request.exposure,
            "utility": request.utility,
            "safety_impact": request.safety_impact,
            "mission_impact": request.mission_impact,
        }

        if not PGMPY_AVAILABLE:
            # Return fallback if pgmpy not installed
            return {
                "status": "degraded",
                "message": "Bayesian Network requires pgmpy library (pip install pgmpy)",
                "input_features": context,
                "fallback_risk": _compute_fallback_risk(request),
            }

        model = BayesianNetworkModel()

        # Run prediction with proper kwargs
        prediction = model.predict(
            sbom_components=[],
            sarif_findings=[],
            cve_records=[{"id": "test"}],  # Need at least one record
            context=context,
            enrichment_map={
                "test": {
                    "kev_listed": request.exploitation == "active",
                    "exploitdb_refs": 1 if request.exploitation == "poc" else 0,
                }
            },
        )

        return {
            "status": "success",
            "input_features": context,
            "prediction": {
                "verdict": prediction.verdict,
                "confidence": round(prediction.confidence, 4),
                "risk_score": round(prediction.risk_score, 4),
                "risk_distribution": prediction.explanation.get(
                    "risk_distribution", {}
                ),
                "most_likely_level": prediction.explanation.get("most_likely_level"),
            },
            "model_info": {
                "model_id": model.metadata.model_id,
                "version": model.metadata.version,
                "type": str(model.metadata.model_type),
            },
            "execution_time_ms": round(prediction.execution_time_ms, 2),
        }
    except ImportError as e:
        raise HTTPException(
            status_code=503, detail=f"Bayesian Network module not available: {e}"
        )
    except RuntimeError as e:
        # Handle case where pgmpy isn't installed
        return {
            "status": "degraded",
            "message": str(e),
            "input_features": {
                "exploitation": request.exploitation,
                "exposure": request.exposure,
                "utility": request.utility,
                "safety_impact": request.safety_impact,
                "mission_impact": request.mission_impact,
            },
            "fallback_risk": _compute_fallback_risk(request),
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Bayesian risk assessment failed: {e}"
        )


def _compute_fallback_risk(request: VulnerabilityRiskRequest) -> Dict[str, Any]:
    """Compute fallback risk when Bayesian Network unavailable."""
    # Simple weighted scoring fallback
    exploitation_weights = {"none": 0.1, "poc": 0.5, "active": 0.9}
    exposure_weights = {"controlled": 0.2, "limited": 0.5, "open": 0.9}
    utility_weights = {"laborious": 0.2, "efficient": 0.5, "super_effective": 0.9}
    safety_weights = {
        "negligible": 0.1,
        "marginal": 0.3,
        "major": 0.7,
        "hazardous": 0.95,
    }
    mission_weights = {"degraded": 0.3, "crippled": 0.6, "mev": 0.9}

    score = (
        exploitation_weights.get(request.exploitation, 0.5) * 0.25
        + exposure_weights.get(request.exposure, 0.5) * 0.20
        + utility_weights.get(request.utility, 0.5) * 0.15
        + safety_weights.get(request.safety_impact, 0.5) * 0.20
        + mission_weights.get(request.mission_impact, 0.5) * 0.20
    )

    if score < 0.3:
        verdict = "low"
    elif score < 0.5:
        verdict = "medium"
    elif score < 0.7:
        verdict = "high"
    else:
        verdict = "critical"

    return {
        "verdict": verdict,
        "confidence": 0.7,
        "score": round(score, 3),
        "method": "weighted_fallback",
    }


# ============================================================================
# Combined Predictions
# ============================================================================


@router.post("/combined-analysis")
def combined_risk_analysis(
    cve_id: str,
    cvss_score: float = 7.5,
    exploitation: str = "none",
    exposure: str = "controlled",
) -> Dict[str, Any]:
    """Perform combined Markov Chain and Bayesian Network analysis.

    Provides comprehensive risk assessment using both predictive models.
    """
    try:
        # Markov Chain analysis
        from core.models.markov_chain import create_attack_chain_for_cve

        markov_result = create_attack_chain_for_cve(
            cve_id=cve_id,
            cvss_score=cvss_score,
            has_exploit=(exploitation == "active"),
            is_network_exposed=(exposure == "open"),
        )

        # Bayesian fallback (in case pgmpy not available)
        bayesian_result = _compute_fallback_risk(
            VulnerabilityRiskRequest(
                exploitation=exploitation,
                exposure=exposure,
                utility="efficient",
                safety_impact="marginal",
                mission_impact="degraded",
            )
        )

        return {
            "status": "success",
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "markov_analysis": {
                "time_to_impact_hours": markov_result.get("time_to_impact_hours", 0),
                "final_impact_probability": markov_result.get(
                    "risk_trajectory", {}
                ).get("final_impact_probability", 0),
                "recommendations": markov_result.get("recommendations", [])[:3],
            },
            "bayesian_analysis": bayesian_result,
            "combined_verdict": _combine_verdicts(markov_result, bayesian_result),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Combined analysis failed: {e}")


def _combine_verdicts(markov_result: Dict, bayesian_result: Dict) -> Dict[str, Any]:
    """Combine Markov and Bayesian verdicts."""
    impact_prob = markov_result.get("risk_trajectory", {}).get(
        "final_impact_probability", 0
    )
    bayesian_score = bayesian_result.get("score", 0.5)

    # Weighted combination
    combined_score = (impact_prob * 0.4) + (bayesian_score * 0.6)

    if combined_score < 0.25:
        verdict = "low"
        urgency = "routine"
    elif combined_score < 0.5:
        verdict = "medium"
        urgency = "scheduled"
    elif combined_score < 0.75:
        verdict = "high"
        urgency = "out-of-cycle"
    else:
        verdict = "critical"
        urgency = "immediate"

    return {
        "verdict": verdict,
        "urgency": urgency,
        "combined_score": round(combined_score, 3),
        "confidence": round(
            (
                markov_result.get("risk_trajectory", {}).get(
                    "final_containment_probability", 0.5
                )
                + bayesian_result.get("confidence", 0.7)
            )
            / 2,
            2,
        ),
    }


__all__ = ["router"]
