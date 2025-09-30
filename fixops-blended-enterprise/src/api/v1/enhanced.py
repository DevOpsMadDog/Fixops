"""
FixOps Enhanced API - Multi-LLM Decision Engine
Advanced security decision API with GPT-4, Claude, Gemini integration
"""

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import structlog

from src.services.enhanced_decision_engine import enhanced_decision_engine
from src.config.settings import get_settings

logger = structlog.get_logger()
router = APIRouter(prefix="/enhanced", tags=["enhanced-decision-engine"])

class EnhancedDecisionRequest(BaseModel):
    """Enhanced decision request with additional intelligence parameters"""
    service_name: str
    environment: str = "production"
    business_context: Dict[str, Any] = {}
    security_findings: List[Dict[str, Any]] = []
    compliance_requirements: List[str] = []
    
    # Enhanced parameters
    enable_mitre_analysis: bool = True
    enable_multi_llm: bool = True
    require_expert_validation: bool = False
    llm_providers: Optional[List[str]] = None  # Specific LLMs to use

class EnhancedDecisionResponse(BaseModel):
    """Enhanced decision response with multi-LLM analysis"""
    decision: str
    confidence_score: float
    evidence_id: str
    processing_time_ms: float
    
    # Enhanced analysis
    multi_llm_analysis: Dict[str, Any]
    mitre_attack_analysis: Dict[str, Any] 
    compliance_analysis: Dict[str, Any]
    enhanced_reasoning: str
    recommendations: List[str]
    marketplace_intelligence: Dict[str, Any]

@router.post("/decision", response_model=EnhancedDecisionResponse)
async def make_enhanced_decision(request: EnhancedDecisionRequest):
    """
    Make enhanced security decision using multi-LLM analysis
    
    Leverages:
    - GPT-4: Deep reasoning and context analysis
    - Claude: Conservative and reliable assessment  
    - Gemini: Fast multimodal analysis
    - Emergent: Balanced comprehensive analysis
    - Specialized Cyber LLM: Security-focused analysis
    """
    try:
        result = await enhanced_decision_engine.make_enhanced_decision(
            service_name=request.service_name,
            environment=request.environment,
            business_context=request.business_context,
            security_findings=request.security_findings,
            compliance_requirements=request.compliance_requirements
        )
        
        return EnhancedDecisionResponse(**result)
        
    except Exception as e:
        logger.error(f"Enhanced decision failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Enhanced decision engine failure",
                "message": str(e),
                "fallback_recommendation": "Manual expert review required"
            }
        )

@router.get("/capabilities")
async def get_enhanced_capabilities():
    """Get enhanced decision engine capabilities"""
    try:
        metrics = await enhanced_decision_engine.get_enhanced_metrics()
        
        return {
            "status": "success",
            "data": {
                **metrics,
                "api_version": "enhanced_v1.0",
                "capabilities": {
                    "multi_llm_consensus": "Analysis from multiple AI models for higher accuracy",
                    "mitre_attack_mapping": "Vulnerability to attack technique mapping",
                    "compliance_automation": "Automated compliance framework validation",
                    "marketplace_integration": "Leverage community security intelligence",
                    "risk_amplification": "Business context-aware risk scoring",
                    "expert_validation": "Automated detection of cases requiring human review"
                },
                "supported_llms": {
                    "emergent_gpt5": "Balanced comprehensive analysis",
                    "openai_gpt4": "Deep reasoning and context understanding", 
                    "anthropic_claude": "Conservative and reliable assessment",
                    "google_gemini": "Fast multimodal analysis",
                    "specialized_cyber": "Security-focused threat analysis"
                }
            }
        }
        
    except Exception as e:
        logger.error(f"Enhanced capabilities query failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/compare-llms")
async def compare_llm_analyses(
    service_name: str,
    security_findings: List[Dict[str, Any]],
    business_context: Dict[str, Any] = {}
):
    """
    Compare analysis results from different LLMs side-by-side
    Useful for understanding LLM strengths and weaknesses
    """
    try:
        # Get multi-LLM analysis
        context = {
            "service_name": service_name,
            "environment": "analysis",
            "business_context": business_context
        }
        
        llm_result = await enhanced_decision_engine.llm_engine.enhanced_security_analysis(
            context, security_findings
        )
        
        # Format comparison
        comparison = {
            "service_analyzed": service_name,
            "findings_count": len(security_findings),
            "models_compared": len(llm_result.individual_analyses),
            "consensus_confidence": llm_result.consensus_confidence,
            "final_decision": llm_result.final_decision,
            
            "individual_analyses": [
                {
                    "provider": analysis.provider.value,
                    "provider_name": analysis.provider.value.replace('_', ' ').title(),
                    "confidence": analysis.confidence,
                    "risk_assessment": analysis.risk_assessment,
                    "recommended_action": analysis.recommended_action,
                    "reasoning": analysis.reasoning,
                    "attack_vectors": analysis.attack_vectors,
                    "mitre_techniques": analysis.mitre_techniques,
                    "compliance_concerns": analysis.compliance_concerns,
                    "processing_time_ms": analysis.processing_time_ms
                }
                for analysis in llm_result.individual_analyses
            ],
            
            "disagreement_analysis": {
                "areas_of_disagreement": llm_result.disagreement_areas,
                "confidence_variance": max([a.confidence for a in llm_result.individual_analyses]) - min([a.confidence for a in llm_result.individual_analyses]) if llm_result.individual_analyses else 0,
                "decision_split": len(set([a.recommended_action for a in llm_result.individual_analyses])) > 1,
                "expert_validation_needed": llm_result.expert_validation_required
            },
            
            "llm_strengths": {
                "gpt4": "Deep contextual reasoning and comprehensive analysis",
                "claude": "Conservative assessment with minimal false positives",
                "gemini": "Fast processing with multimodal capabilities",
                "emergent": "Balanced analysis with strong general capabilities",
                "cyber_specialized": "Security-focused with domain expertise"
            }
        }
        
        return {"status": "success", "data": comparison}
        
    except Exception as e:
        logger.error(f"LLM comparison failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/mitre-mapping/{vulnerability_type}")
async def get_mitre_mapping(vulnerability_type: str):
    """Get MITRE ATT&CK technique mapping for vulnerability type"""
    try:
        # Enhanced MITRE mapping based on vulnerability type
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
            "weak_authentication": ["T1078", "T1110"]
        }
        
        techniques = mappings.get(vulnerability_type.lower(), [])
        
        # Get technique details
        technique_details = []
        for tech_id in techniques:
            if tech_id in enhanced_decision_engine.mitre_techniques:
                technique_details.append({
                    "id": tech_id,
                    **enhanced_decision_engine.mitre_techniques[tech_id]
                })
        
        return {
            "status": "success",
            "data": {
                "vulnerability_type": vulnerability_type,
                "mitre_techniques": technique_details,
                "attack_path_severity": "critical" if len(techniques) >= 3 else "high" if len(techniques) >= 2 else "medium",
                "business_risk_factors": [
                    detail["business_impact"] for detail in technique_details
                ]
            }
        }
        
    except Exception as e:
        logger.error(f"MITRE mapping failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))