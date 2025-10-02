"""
Enhanced Decision Engine - Multi-LLM Analysis and Consensus
Provides advanced security decision making with multiple AI models
"""

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import structlog

from src.config.settings import get_settings
from src.services.cache_service import CacheService

logger = structlog.get_logger()
settings = get_settings()

class LLMProvider(Enum):
    EMERGENT_GPT5 = "emergent_gpt5"
    OPENAI_GPT4 = "openai_gpt4"
    ANTHROPIC_CLAUDE = "anthropic_claude"
    GOOGLE_GEMINI = "google_gemini"
    SPECIALIZED_CYBER = "specialized_cyber"

@dataclass
class LLMAnalysisResult:
    provider: str  # Changed from LLMProvider enum to string
    recommended_action: str
    confidence: float
    reasoning: str
    processing_time_ms: float

@dataclass
class MultiLLMResult:
    individual_analyses: List[LLMAnalysisResult]
    final_decision: str
    consensus_confidence: float
    disagreement_areas: List[str]
    expert_validation_required: bool

class AdvancedLLMEngine:
    """Advanced LLM Engine for multi-model consensus analysis"""
    
    def __init__(self):
        self.cache = CacheService.get_instance()
        self.llm_client = None
        self.enabled_providers = []
        self.initialized = False
        self._initialize_llm_client()
    
    async def initialize(self):
        """Initialize the advanced LLM engine - required by enhanced_decision_engine"""
        if not self.initialized:
            self._initialize_llm_client()
            self.initialized = True
            logger.info("✅ Advanced LLM Engine initialized")
    
    def _initialize_llm_client(self):
        """Initialize LLM client for multi-model analysis"""
        try:
            if settings.EMERGENT_LLM_KEY:
                from emergentintegrations import EmergentIntegrations
                self.llm_client = EmergentIntegrations(api_key=settings.EMERGENT_LLM_KEY)
                self.enabled_providers = [
                    "emergent_gpt5",
                    "specialized_cyber"
                ]
                logger.info("✅ Enhanced LLM Engine initialized with Emergent LLM")
            else:
                logger.warning("No EMERGENT_LLM_KEY found, using demo mode")
                self.enabled_providers = [
                    "emergent_gpt5",
                    "openai_gpt4", 
                    "anthropic_claude",
                    "google_gemini",
                    "specialized_cyber"
                ]
        except Exception as e:
            logger.error(f"LLM client initialization failed: {e}")
            self.llm_client = None
            # Demo mode providers
            self.enabled_providers = [
                "emergent_gpt5",
                "specialized_cyber"
            ]

    async def get_supported_llms(self) -> Dict[str, Dict[str, Any]]:
        """Get supported LLM providers and their capabilities"""
        return {
            "emergent_gpt5": {
                "name": "Emergent GPT-5",
                "available": "emergent_gpt5" in self.enabled_providers,
                "specialties": ["security_analysis", "code_review", "threat_modeling"],
                "description": "Latest GPT model via Emergent platform"
            },
            "openai_gpt4": {
                "name": "OpenAI GPT-4",
                "available": "openai_gpt4" in self.enabled_providers,
                "specialties": ["general_analysis", "reasoning", "explanation"],
                "description": "OpenAI's flagship model for analysis"
            },
            "anthropic_claude": {
                "name": "Anthropic Claude",
                "available": "anthropic_claude" in self.enabled_providers,
                "specialties": ["safety_analysis", "risk_assessment", "compliance"],
                "description": "Claude model specialized in safety and risk"
            },
            "google_gemini": {
                "name": "Google Gemini",
                "available": "google_gemini" in self.enabled_providers,
                "specialties": ["multimodal_analysis", "code_understanding"],
                "description": "Google's multimodal AI model"
            },
            "specialized_cyber": {
                "name": "Specialized Cyber LLM",
                "available": "specialized_cyber" in self.enabled_providers,
                "specialties": ["vulnerability_analysis", "exploit_detection", "remediation"],
                "description": "Cybersecurity-specialized language model"
            }
        }

    async def enhanced_security_analysis(self, context: Dict[str, Any], security_findings: List[Dict[str, Any]]) -> MultiLLMResult:
        """Perform enhanced security analysis using multiple LLMs"""
        try:
            individual_analyses = []
            
            # Analyze with each enabled provider
            for provider in self.enabled_providers:
                analysis = await self._analyze_with_llm(provider, context, security_findings)
                individual_analyses.append(analysis)
            
            # Generate consensus
            final_decision, consensus_confidence, disagreement_areas = self._generate_consensus(individual_analyses)
            
            # Determine if expert validation is required
            expert_validation_required = (
                consensus_confidence < 0.7 or
                len(disagreement_areas) > 2 or
                any(analysis.confidence < 0.6 for analysis in individual_analyses)
            )
            
            return MultiLLMResult(
                individual_analyses=individual_analyses,
                final_decision=final_decision,
                consensus_confidence=consensus_confidence,
                disagreement_areas=disagreement_areas,
                expert_validation_required=expert_validation_required
            )
            
        except Exception as e:
            logger.error(f"Enhanced security analysis failed: {e}")
            # Return fallback result
            return MultiLLMResult(
                individual_analyses=[],
                final_decision="defer",
                consensus_confidence=0.0,
                disagreement_areas=["analysis_error"],
                expert_validation_required=True
            )

    async def _analyze_with_llm(self, provider: str, context: Dict[str, Any], findings: List[Dict[str, Any]]) -> LLMAnalysisResult:
        """Analyze with a specific LLM provider"""
        start_time = time.time()
        
        try:
            if provider == "emergent_gpt5" and self.llm_client:
                # Real LLM analysis
                prompt = self._build_analysis_prompt(context, findings)
                response = await self.llm_client.generate_text(
                    model="gpt-5",
                    prompt=prompt,
                    max_tokens=500,
                    temperature=0.3
                )
                
                # Parse LLM response
                analysis_text = response.get("content", "")
                recommended_action, confidence, reasoning = self._parse_llm_response(analysis_text)
                
            else:
                # Demo mode analysis
                recommended_action, confidence, reasoning = self._generate_demo_analysis(provider, context, findings)
            
            processing_time = (time.time() - start_time) * 1000
            
            return LLMAnalysisResult(
                provider=provider,  # Just use string instead of enum
                recommended_action=recommended_action,
                confidence=confidence,
                reasoning=reasoning,
                processing_time_ms=processing_time
            )
            
        except Exception as e:
            logger.error(f"LLM analysis failed for {provider}: {e}")
            processing_time = (time.time() - start_time) * 1000
            
            return LLMAnalysisResult(
                provider=provider,  # Just use string instead of enum
                recommended_action="defer",
                confidence=0.0,
                reasoning=f"Analysis error: {str(e)}",
                processing_time_ms=processing_time
            )

    def _build_analysis_prompt(self, context: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """Build analysis prompt for LLM"""
        prompt = f"""
        Security Decision Analysis for CI/CD Pipeline:
        
        Service: {context.get('service_name', 'unknown')}
        Environment: {context.get('environment', 'unknown')}
        Business Context: {context.get('business_context', {})}
        
        Security Findings: {json.dumps(findings, indent=2)}
        
        Provide a security decision recommendation:
        - Action: "allow", "block", or "defer"  
        - Confidence: 0.0 to 1.0
        - Reasoning: Brief explanation
        
        Format: ACTION|CONFIDENCE|REASONING
        """
        return prompt

    def _parse_llm_response(self, response: str) -> Tuple[str, float, str]:
        """Parse LLM response into structured data"""
        try:
            parts = response.strip().split('|')
            if len(parts) >= 3:
                action = parts[0].strip().lower()
                confidence = float(parts[1].strip())
                reasoning = parts[2].strip()
                
                if action in ['allow', 'block', 'defer']:
                    return action, confidence, reasoning
        except (ValueError, IndexError):
            pass
        
        # Fallback parsing
        response_lower = response.lower()
        if 'block' in response_lower:
            return 'block', 0.8, 'Security risk detected'
        elif 'allow' in response_lower:
            return 'allow', 0.7, 'No significant risk identified'
        else:
            return 'defer', 0.5, 'Manual review recommended'

    def _generate_demo_analysis(self, provider: str, context: Dict[str, Any], findings: List[Dict[str, Any]]) -> Tuple[str, float, str]:
        """Generate demo analysis for providers"""
        high_severity = any(f.get('severity', '').upper() in ['CRITICAL', 'HIGH'] for f in findings)
        
        if provider == LLMProvider.OPENAI_GPT4.value:
            if high_severity:
                return 'defer', 0.75, 'High severity findings require manual review for business context'
            return 'allow', 0.85, 'No critical vulnerabilities detected, deployment approved'
        
        elif provider == LLMProvider.ANTHROPIC_CLAUDE.value:
            if high_severity:
                return 'block', 0.9, 'Critical security risk in production environment'
            return 'allow', 0.8, 'Risk assessment completed, deployment safe'
        
        elif provider == LLMProvider.GOOGLE_GEMINI.value:
            return 'defer', 0.7, 'Multimodal analysis suggests caution for deployment'
        
        elif provider == LLMProvider.SPECIALIZED_CYBER.value:
            if high_severity:
                return 'block', 0.95, 'Cybersecurity analysis identifies critical exploit risk'
            return 'allow', 0.9, 'Cyber threat assessment passed'
        
        else:  # EMERGENT_GPT5
            if high_severity:
                return 'defer', 0.8, 'GPT-5 analysis recommends manual security review'
            return 'allow', 0.88, 'GPT-5 security analysis approved for deployment'

    def _generate_consensus(self, analyses: List[LLMAnalysisResult]) -> Tuple[str, float, List[str]]:
        """Generate consensus from multiple LLM analyses"""
        if not analyses:
            return "defer", 0.0, ["no_analysis"]
        
        # Count votes for each action
        votes = {"allow": 0, "block": 0, "defer": 0}
        confidence_sum = 0
        
        for analysis in analyses:
            votes[analysis.recommended_action] += 1
            confidence_sum += analysis.confidence
        
        # Determine consensus action
        final_decision = max(votes, key=votes.get)
        
        # Calculate consensus confidence
        consensus_confidence = confidence_sum / len(analyses)
        
        # Identify disagreement areas
        disagreement_areas = []
        unique_actions = set(analysis.recommended_action for analysis in analyses)
        if len(unique_actions) > 1:
            disagreement_areas.append("recommended_action")
        
        confidence_variance = max(analysis.confidence for analysis in analyses) - min(analysis.confidence for analysis in analyses)
        if confidence_variance > 0.3:
            disagreement_areas.append("confidence_level")
        
        return final_decision, consensus_confidence, disagreement_areas

# Global enhanced decision engine instance
enhanced_decision_engine = AdvancedLLMEngine()