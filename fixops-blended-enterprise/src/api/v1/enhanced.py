"""
FixOps Enhanced API - Multi-LLM Decision Engine
Advanced security decision API with GPT-4, Claude, Gemini integration
"""

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import structlog

from src.services.enhanced_decision_engine import enhanced_decision_engine

logger = structlog.get_logger()
router = APIRouter(prefix="/enhanced", tags=["enhanced-decision-engine"])

class EnhancedAnalysisModel(BaseModel):
    name: str
    verdict: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    evidence: List[Dict[str, Any]] = []
    mitre_ttps: List[str] = []
    latency_ms: Optional[float] = None
    cost: Optional[float] = None

class EnhancedConsensus(BaseModel):
    verdict: str
    confidence: float = Field(ge=0.0, le=1.0)
    method: str

class EnhancedStandardResponse(BaseModel):
    models: List[EnhancedAnalysisModel]
    consensus: EnhancedConsensus

class EnhancedDecisionRequest(BaseModel):
    service_name: str
    environment: str = "production"
    business_context: Dict[str, Any] = {}
    security_findings: List[Dict[str, Any]] = []
    compliance_requirements: List[str] = []
    enable_mitre_analysis: bool = True
    enable_multi_llm: bool = True
    require_expert_validation: bool = False
    llm_providers: Optional[List[str]] = None

@router.post("/analysis", response_model=EnhancedStandardResponse)
async def enhanced_analysis_standard(request: EnhancedDecisionRequest):
    """
    Returns standardized multi-LLM analysis schema:
    {models:[{name, verdict, confidence, rationale, evidence[], mitre_ttps[], latency_ms, cost}],
     consensus:{verdict, confidence, method}}
    """
    try:
        # Use existing enhanced engine to get analyses
        llm_result = await enhanced_decision_engine.llm_engine.enhanced_security_analysis(
            {
                "service_name": request.service_name,
                "environment": request.environment,
                "business_context": request.business_context,
                "compliance_requirements": request.compliance_requirements,
            },
            request.security_findings,
        )

        # Map to standardized model list
        models: List[EnhancedAnalysisModel] = []
        for analysis in llm_result.individual_analyses:
            models.append(
                EnhancedAnalysisModel(
                    name=analysis.provider.value,
                    verdict=analysis.recommended_action,
                    confidence=analysis.confidence,
                    rationale=analysis.reasoning,
                    evidence=getattr(analysis, "evidence", []) or [],
                    mitre_ttps=getattr(analysis, "mitre_techniques", []) or [],
                    latency_ms=getattr(analysis, "processing_time_ms", None),
                    cost=getattr(analysis, "cost", None),
                )
            )

        # Build consensus
        consensus = EnhancedConsensus(
            verdict=llm_result.final_decision,
            confidence=llm_result.consensus_confidence,
            method="multi-llm-weighted-consensus",
        )

        return EnhancedStandardResponse(models=models, consensus=consensus)

    except Exception as e:
        logger.error(f"Enhanced analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail={"error": "analysis_failed", "message": str(e)})

# Keep previous endpoints for capabilities and comparisons
class CapabilitiesResponse(BaseModel):
    status: str
    data: Dict[str, Any]

@router.get("/capabilities", response_model=CapabilitiesResponse)
async def get_enhanced_capabilities():
    try:
        metrics = await enhanced_decision_engine.get_enhanced_metrics()
        return CapabilitiesResponse(
            status="success",
            data={
                **metrics,
                "api_version": "enhanced_v1.0",
                "capabilities": {
                    "multi_llm_consensus": "Analysis from multiple AI models for higher accuracy",
                    "mitre_attack_mapping": "Vulnerability to attack technique mapping",
                    "compliance_automation": "Automated compliance framework validation",
                    "marketplace_integration": "Leverage community security intelligence",
                    "risk_amplification": "Business context-aware risk scoring",
                    "expert_validation": "Automated detection of cases requiring human review",
                },
                "supported_llms": {
                    "emergent_gpt5": "Balanced comprehensive analysis",
                    "openai_gpt4": "Deep reasoning and context understanding",
                    "anthropic_claude": "Conservative and reliable assessment",
                    "google_gemini": "Fast multimodal analysis",
                    "specialized_cyber": "Security-focused threat analysis",
                },
            },
        )
    except Exception as e:
        logger.error(f"Enhanced capabilities query failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

class CompareLLMsRequest(BaseModel):
    service_name: str
    security_findings: List[Dict[str, Any]]
    business_context: Dict[str, Any] = {}

@router.post("/compare-llms")
async def compare_llm_analyses(payload: CompareLLMsRequest):
    try:
        context = {
            "service_name": payload.service_name,
            "environment": "analysis",
            "business_context": payload.business_context,
        }
        llm_result = await enhanced_decision_engine.llm_engine.enhanced_security_analysis(
            context, payload.security_findings
        )

        comparison = {
            "service_analyzed": payload.service_name,
            "findings_count": len(payload.security_findings),
            "models_compared": len(llm_result.individual_analyses),
            "consensus_confidence": llm_result.consensus_confidence,
            "final_decision": llm_result.final_decision,
            "individual_analyses": [
                {
                    "provider": a.provider.value,
                    "provider_name": a.provider.value.replace('_', ' ').title(),
                    "confidence": a.confidence,
                    "risk_assessment": getattr(a, 'risk_assessment', 'medium'),
                    "recommended_action": a.recommended_action,
                    "reasoning": a.reasoning,
                    "attack_vectors": getattr(a, 'attack_vectors', []),
                    "mitre_techniques": getattr(a, 'mitre_techniques', []),
                    "compliance_concerns": getattr(a, 'compliance_concerns', []),
                    "processing_time_ms": getattr(a, 'processing_time_ms', None),
                }
                for a in llm_result.individual_analyses
            ],
            "disagreement_analysis": {
                "areas_of_disagreement": llm_result.disagreement_areas,
                "confidence_variance": (max([a.confidence for a in llm_result.individual_analyses]) - min([a.confidence for a in llm_result.individual_analyses])) if llm_result.individual_analyses else 0,
                "decision_split": len(set([a.recommended_action for a in llm_result.individual_analyses])) > 1,
                "expert_validation_needed": llm_result.expert_validation_required,
            },
            "llm_strengths": {
                "gpt4": "Deep contextual reasoning and comprehensive analysis",
                "claude": "Conservative assessment with minimal false positives",
                "gemini": "Fast processing with multimodal capabilities",
                "emergent": "Balanced analysis with strong general capabilities",
                "cyber_specialized": "Security-focused with domain expertise",
            },
        }
        return {"status": "success", "data": comparison}
    except Exception as e:
        logger.error(f"LLM comparison failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/mitre-mapping/{vulnerability_type}")
async def get_mitre_mapping(vulnerability_type: str):
    try:
        mappings = {
            "sql_injection": ["T1190", "T1212"],
            "xss": ["T1190", "T1059"],
            "auth_bypass": ["T1078", "T1190"],
            "privilege_escalation": ["T1068", "T1055"],
            "data_exposure": ["T1005", "T1041"],
            "weak_crypto": ["T1555", "T1003"],
            "injection": ["T1190", "T1059", "T1055"],
            "deserialization": ["T1190", "T1055"],
            "path_traversal": ["T1083", "T1190"],
            "weak_authentication": ["T1078", "T1110"],
        }
        techniques = mappings.get(vulnerability_type.lower(), [])

        technique_details = []
        if hasattr(enhanced_decision_engine, 'mitre_techniques'):
            for tech_id in techniques:
                if tech_id in enhanced_decision_engine.mitre_techniques:
                    technique_details.append({
                        "id": tech_id,
                        **enhanced_decision_engine.mitre_techniques[tech_id],
                    })
        return {
            "status": "success",
            "data": {
                "vulnerability_type": vulnerability_type,
                "mitre_techniques": technique_details,
                "attack_path_severity": "critical" if len(techniques) >= 3 else "high" if len(techniques) >= 2 else "medium",
                "business_risk_factors": [d["business_impact"] for d in technique_details],
            },
        }
    except Exception as e:
        logger.error(f"MITRE mapping failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
