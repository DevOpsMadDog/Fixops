"""Causal Inference API Router — /api/v1/analytics/causal.

Exposes the CausalInferenceEngine for root cause analysis,
counterfactual reasoning, and SHAP-based explainability.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/analytics/causal", tags=["Causal Inference"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CausalAnalysisRequest(BaseModel):
    """Request for causal vulnerability analysis."""
    has_exploit: bool = False
    is_reachable: bool = True
    is_internet_facing: bool = False
    has_waf: bool = False
    is_patched: bool = False
    has_auth: bool = True


class CounterfactualRequest(BaseModel):
    """Request for counterfactual what-if analysis."""
    evidence: Dict[str, bool] = Field(
        default_factory=dict,
        description="Map of SecurityFactor names to their boolean state",
    )
    intervention_factor: str = Field(
        ..., description="SecurityFactor to intervene on"
    )
    intervention_value: bool = True
    outcome_factor: str = Field(
        default="attack_successful",
        description="SecurityFactor to measure outcome on",
    )


class RootCauseRequest(BaseModel):
    """Request for root cause identification."""
    symptom: str = Field(
        default="attack_successful",
        description="SecurityFactor symptom to trace back from",
    )
    evidence: Dict[str, bool] = Field(
        default_factory=dict,
        description="Map of SecurityFactor names to their boolean state",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_factor(name: str):
    """Resolve a factor name string to SecurityFactor enum."""
    from core.causal_inference import SecurityFactor

    name_upper = name.upper().replace("-", "_").replace(" ", "_")
    try:
        return SecurityFactor(name_upper.lower())
    except ValueError:
        # Try matching by name
        for member in SecurityFactor:
            if member.name == name_upper:
                return member
        raise HTTPException(
            status_code=400,
            detail=f"Unknown SecurityFactor: {name}. Valid: {[m.value for m in SecurityFactor]}",
        )


def _evidence_to_factors(evidence: Dict[str, bool]) -> dict:
    """Convert string-keyed evidence to SecurityFactor-keyed dict."""
    return {_resolve_factor(k): v for k, v in evidence.items()}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/analyze", summary="Causal vulnerability analysis")
async def analyze_vulnerability(req: CausalAnalysisRequest) -> Dict[str, Any]:
    """Run full causal analysis including root causes and counterfactuals."""
    from core.causal_inference import analyze_vulnerability_causes

    return analyze_vulnerability_causes(
        has_exploit=req.has_exploit,
        is_reachable=req.is_reachable,
        is_internet_facing=req.is_internet_facing,
        has_waf=req.has_waf,
        is_patched=req.is_patched,
        has_auth=req.has_auth,
    )


@router.post("/counterfactual", summary="What-if counterfactual analysis")
async def counterfactual(req: CounterfactualRequest) -> Dict[str, Any]:
    """Evaluate a counterfactual scenario: 'What if factor X were different?'"""
    from core.causal_inference import CausalInferenceEngine

    engine = CausalInferenceEngine()
    evidence = _evidence_to_factors(req.evidence)
    intervention = _resolve_factor(req.intervention_factor)
    outcome = _resolve_factor(req.outcome_factor)

    result = engine.counterfactual_analysis(
        outcome, evidence, intervention, req.intervention_value,
    )
    return result.to_dict()


@router.post("/root-causes", summary="Root cause identification")
async def root_causes(req: RootCauseRequest) -> Dict[str, Any]:
    """Identify root causes of a security symptom via causal graph traversal."""
    from core.causal_inference import CausalInferenceEngine

    engine = CausalInferenceEngine()
    symptom = _resolve_factor(req.symptom)
    evidence = _evidence_to_factors(req.evidence)

    result = engine.identify_root_causes(symptom, evidence)
    return result.to_dict()


@router.get("/graph", summary="Get causal graph structure")
async def get_graph() -> Dict[str, Any]:
    """Return the default causal security graph structure."""
    from core.causal_inference import CausalSecurityGraph

    graph = CausalSecurityGraph()
    return graph.to_dict()


@router.get("/factors", summary="List all security factors")
async def list_factors() -> List[str]:
    """List all available SecurityFactor values."""
    from core.causal_inference import SecurityFactor

    return [f.value for f in SecurityFactor]

