"""Enhanced decision API routes exposing the multi-LLM consensus engine."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from core.enhanced_decision import EnhancedDecisionEngine

router = APIRouter(prefix="/api/v1/enhanced", tags=["enhanced"])


def _get_engine(request: Request) -> EnhancedDecisionEngine:
    engine = getattr(request.app.state, "enhanced_engine", None)
    if engine is None:
        raise HTTPException(
            status_code=503,
            detail="Enhanced decision engine unavailable",
        )
    return engine


class EnhancedDecisionRequest(BaseModel):
    service_name: str = Field(
        ..., description="Primary service or application identifier"
    )
    environment: str = Field("production", description="Deployment environment")
    business_context: Dict[str, Any] = Field(default_factory=dict)
    security_findings: List[Dict[str, Any]] = Field(default_factory=list)
    compliance_requirements: List[str] = Field(default_factory=list)
    cnapp: Optional[Dict[str, Any]] = None
    exploitability: Optional[Dict[str, Any]] = None
    ai_agent_analysis: Optional[Dict[str, Any]] = None
    marketplace_recommendations: Optional[List[Dict[str, Any]]] = None


@router.post("/analysis")
def run_enhanced_analysis(
    payload: EnhancedDecisionRequest,
    engine: EnhancedDecisionEngine = Depends(_get_engine),
) -> Mapping[str, Any]:
    """Return multi-LLM consensus analysis for the supplied findings payload."""

    result = engine.analyse_payload(payload.model_dump())
    return result


class CompareLLMsRequest(BaseModel):
    service_name: str
    security_findings: List[Dict[str, Any]]
    business_context: Dict[str, Any] = Field(default_factory=dict)


@router.post("/compare-llms")
def compare_llms(
    payload: CompareLLMsRequest,
    engine: EnhancedDecisionEngine = Depends(_get_engine),
) -> Mapping[str, Any]:
    """Compare individual model verdicts and consensus metadata."""

    base_payload = payload.model_dump()
    result = engine.analyse_payload(base_payload)
    return {
        "service_analyzed": payload.service_name,
        "models_compared": len(result.get("individual_analyses", [])),
        "consensus": {
            "decision": result.get("final_decision"),
            "confidence": result.get("consensus_confidence"),
            "method": result.get("method"),
        },
        "individual_analyses": result.get("individual_analyses", []),
        "disagreement_areas": result.get("disagreement_areas", []),
        "expert_validation_required": result.get("expert_validation_required", False),
    }


@router.get("/capabilities")
def enhanced_capabilities(
    engine: EnhancedDecisionEngine = Depends(_get_engine),
) -> Mapping[str, Any]:
    """Expose engine telemetry and supported providers."""

    capabilities = engine.capabilities()
    capabilities["signals"] = engine.signals()
    return capabilities


@router.get("/signals")
def enhanced_signals(
    verdict: str = "allow",
    confidence: float = 0.9,
    engine: EnhancedDecisionEngine = Depends(_get_engine),
) -> Mapping[str, Any]:
    """Return the latest feed badges and SSVC label for the enhanced engine."""

    return engine.signals(verdict=verdict, confidence=confidence)
