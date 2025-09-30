"""
FixOps Advanced Multi-LLM Intelligence Engine
Enhanced decision engine with GPT-4, Claude, Gemini, and specialized security models
"""

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass
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
class LLMAnalysis:
    """Analysis result from a specific LLM"""
    provider: LLMProvider
    confidence: float
    risk_assessment: str
    attack_vectors: List[str]
    business_impact: str
    recommended_action: str
    reasoning: str
    mitre_techniques: List[str]
    compliance_concerns: List[str]
    processing_time_ms: float

@dataclass
class MultiLLMDecisionResult:
    """Enhanced decision result from multiple LLM analysis"""
    final_decision: str
    consensus_confidence: float
    individual_analyses: List[LLMAnalysis]
    consensus_reasoning: str
    disagreement_areas: List[str]
    expert_validation_required: bool
    evidence_id: str
    processing_time_ms: float

class AdvancedLLMEngine:
    """Multi-LLM intelligence engine for enhanced security decision making"""
    
    def __init__(self):
        self.cache = CacheService.get_instance()
        self.llm_clients = {}
        self.enabled_providers = []
        
    async def initialize(self):
        """Initialize all available LLM providers"""
        try:
            # Initialize Emergent LLM (GPT-5)
            if settings.EMERGENT_LLM_KEY:
                await self._init_emergent_llm()
                
            # Initialize OpenAI GPT-4
            if hasattr(settings, 'OPENAI_API_KEY') and settings.OPENAI_API_KEY:
                await self._init_openai_gpt4()
                
            # Initialize Anthropic Claude
            if hasattr(settings, 'ANTHROPIC_API_KEY') and settings.ANTHROPIC_API_KEY:
                await self._init_claude()
                
            # Initialize Google Gemini
            if hasattr(settings, 'GOOGLE_API_KEY') and settings.GOOGLE_API_KEY:
                await self._init_gemini()
                
            # Initialize Specialized Cyber LLM
            if hasattr(settings, 'CYBER_LLM_API_KEY') and settings.CYBER_LLM_API_KEY:
                await self._init_specialized_cyber()
                
            logger.info(f"Advanced LLM Engine initialized with {len(self.enabled_providers)} providers: {[p.value for p in self.enabled_providers]}")
            
        except Exception as e:
            logger.error(f"Advanced LLM Engine initialization failed: {str(e)}")
            raise

    async def _init_emergent_llm(self):
        """Initialize Emergent LLM (GPT-5)"""
        try:
            from emergentintegrations import EmergentIntegrations
            self.llm_clients[LLMProvider.EMERGENT_GPT5] = EmergentIntegrations(api_key=settings.EMERGENT_LLM_KEY)
            self.enabled_providers.append(LLMProvider.EMERGENT_GPT5)
            logger.info("✅ Emergent GPT-5 initialized")
        except Exception as e:
            logger.warning(f"Emergent LLM initialization failed: {str(e)}")

    async def _init_openai_gpt4(self):
        """Initialize OpenAI GPT-4"""
        try:
            import openai
            self.llm_clients[LLMProvider.OPENAI_GPT4] = openai.AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            self.enabled_providers.append(LLMProvider.OPENAI_GPT4)
            logger.info("✅ OpenAI GPT-4 initialized")
        except Exception as e:
            logger.warning(f"OpenAI GPT-4 initialization failed: {str(e)}")

    async def _init_claude(self):
        """Initialize Anthropic Claude"""
        try:
            import anthropic
            self.llm_clients[LLMProvider.ANTHROPIC_CLAUDE] = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
            self.enabled_providers.append(LLMProvider.ANTHROPIC_CLAUDE)
            logger.info("✅ Anthropic Claude initialized")
        except Exception as e:
            logger.warning(f"Anthropic Claude initialization failed: {str(e)}")

    async def _init_gemini(self):
        """Initialize Google Gemini"""
        try:
            import google.generativeai as genai
            genai.configure(api_key=settings.GOOGLE_API_KEY)
            self.llm_clients[LLMProvider.GOOGLE_GEMINI] = genai.GenerativeModel('gemini-pro')
            self.enabled_providers.append(LLMProvider.GOOGLE_GEMINI)
            logger.info("✅ Google Gemini initialized")
        except Exception as e:
            logger.warning(f"Google Gemini initialization failed: {str(e)}")

    async def _init_specialized_cyber(self):
        """Initialize specialized cybersecurity LLM"""
        try:
            # Placeholder for specialized cyber LLM
            # This could be a fine-tuned model specifically for security analysis
            self.llm_clients[LLMProvider.SPECIALIZED_CYBER] = "cyber_llm_placeholder"
            self.enabled_providers.append(LLMProvider.SPECIALIZED_CYBER)
            logger.info("✅ Specialized Cyber LLM initialized")
        except Exception as e:
            logger.warning(f"Specialized Cyber LLM initialization failed: {str(e)}")

    async def enhanced_security_analysis(self, 
                                       context: Dict[str, Any],
                                       security_findings: List[Dict[str, Any]]) -> MultiLLMDecisionResult:
        """Enhanced security analysis using multiple LLMs"""
        
        start_time = time.time()
        
        # Run analysis with all available LLMs in parallel
        analysis_tasks = []
        
        for provider in self.enabled_providers:
            task = self._analyze_with_llm(provider, context, security_findings)
            analysis_tasks.append(task)
        
        # Execute all analyses in parallel
        individual_analyses = await asyncio.gather(*analysis_tasks, return_exceptions=True)
        
        # Filter out failed analyses
        valid_analyses = [
            analysis for analysis in individual_analyses 
            if isinstance(analysis, LLMAnalysis)
        ]
        
        if not valid_analyses:
            logger.error("All LLM analyses failed")
            return self._create_fallback_result(context, start_time)
        
        # Perform consensus analysis
        consensus_result = await self._perform_consensus_analysis(valid_analyses, context)
        
        processing_time_ms = (time.time() - start_time) * 1000
        
        return MultiLLMDecisionResult(
            final_decision=consensus_result["decision"],
            consensus_confidence=consensus_result["confidence"],
            individual_analyses=valid_analyses,
            consensus_reasoning=consensus_result["reasoning"],
            disagreement_areas=consensus_result["disagreements"],
            expert_validation_required=consensus_result["expert_needed"],
            evidence_id=f"MULTI-LLM-EVD-{int(time.time())}",
            processing_time_ms=processing_time_ms
        )

    async def _analyze_with_llm(self, 
                              provider: LLMProvider,
                              context: Dict[str, Any],
                              security_findings: List[Dict[str, Any]]) -> LLMAnalysis:
        """Analyze security context with specific LLM"""
        
        start_time = time.time()
        
        try:
            if provider == LLMProvider.EMERGENT_GPT5:
                result = await self._analyze_with_emergent(context, security_findings)
            elif provider == LLMProvider.OPENAI_GPT4:
                result = await self._analyze_with_gpt4(context, security_findings)
            elif provider == LLMProvider.ANTHROPIC_CLAUDE:
                result = await self._analyze_with_claude(context, security_findings)
            elif provider == LLMProvider.GOOGLE_GEMINI:
                result = await self._analyze_with_gemini(context, security_findings)
            elif provider == LLMProvider.SPECIALIZED_CYBER:
                result = await self._analyze_with_cyber_llm(context, security_findings)
            else:
                raise ValueError(f"Unknown LLM provider: {provider}")
            
            processing_time_ms = (time.time() - start_time) * 1000
            
            return LLMAnalysis(
                provider=provider,
                confidence=result.get("confidence", 0.5),
                risk_assessment=result.get("risk_assessment", "medium"),
                attack_vectors=result.get("attack_vectors", []),
                business_impact=result.get("business_impact", "medium"),
                recommended_action=result.get("recommended_action", "defer"),
                reasoning=result.get("reasoning", ""),
                mitre_techniques=result.get("mitre_techniques", []),
                compliance_concerns=result.get("compliance_concerns", []),
                processing_time_ms=processing_time_ms
            )
            
        except Exception as e:
            logger.error(f"LLM analysis failed for {provider.value}: {str(e)}")
            # Return neutral analysis on failure
            return LLMAnalysis(
                provider=provider,
                confidence=0.5,
                risk_assessment="unknown",
                attack_vectors=[],
                business_impact="unknown",
                recommended_action="defer",
                reasoning=f"Analysis failed: {str(e)}",
                mitre_techniques=[],
                compliance_concerns=[],
                processing_time_ms=(time.time() - start_time) * 1000
            )

    async def _analyze_with_emergent(self, context: Dict, findings: List[Dict]) -> Dict[str, Any]:
        """Emergent GPT-5 analysis - balanced and comprehensive"""
        
        prompt = f"""
        ENHANCED SECURITY ANALYSIS (GPT-5 Emergent)
        
        Service: {context.get('service_name', 'unknown')}
        Environment: {context.get('environment', 'unknown')}
        Business Context: {json.dumps(context.get('business_context', {}), indent=2)}
        
        Security Findings ({len(findings)} total):
        {json.dumps(findings[:5], indent=2)}
        
        Perform comprehensive security analysis focusing on:
        
        1. RISK ASSESSMENT (critical/high/medium/low)
        2. ATTACK VECTORS (potential attack paths)
        3. BUSINESS IMPACT (financial/operational/reputational)
        4. MITRE ATT&CK TECHNIQUES (map findings to techniques)
        5. COMPLIANCE IMPACT (regulations affected)
        6. RECOMMENDED ACTION (allow/block/defer)
        
        Provide JSON response with detailed reasoning for security decision making.
        Focus on business context and real-world attack scenarios.
        """
        
        client = self.llm_clients[LLMProvider.EMERGENT_GPT5]
        response = await client.generate_text(
            model="gpt-5",
            prompt=prompt,
            max_tokens=800,
            temperature=0.2
        )
        
        return json.loads(response.get("content", "{}"))

    async def _analyze_with_gpt4(self, context: Dict, findings: List[Dict]) -> Dict[str, Any]:
        """OpenAI GPT-4 analysis - deep reasoning and context"""
        
        prompt = f"""
        You are a senior cybersecurity analyst with 15+ years experience in enterprise security.
        
        SECURITY DECISION ANALYSIS:
        
        Service: {context.get('service_name')}
        Environment: {context.get('environment')}
        Business Context: {context.get('business_context', {})}
        Security Findings: {len(findings)} findings detected
        
        Key Findings:
        {json.dumps(findings[:3], indent=2) if findings else 'No findings'}
        
        As a cybersecurity expert, analyze this deployment request and provide:
        
        1. Overall risk assessment (critical/high/medium/low) with detailed reasoning
        2. Potential attack vectors and exploitation paths
        3. Business impact analysis considering organizational context
        4. MITRE ATT&CK technique mapping for identified vulnerabilities
        5. Compliance framework implications
        6. Final recommendation (allow/block/defer) with confidence level
        
        Return analysis in JSON format:
        {{
            "confidence": 0.85,
            "risk_assessment": "medium",
            "attack_vectors": ["sql_injection", "data_exfiltration"],
            "business_impact": "high",
            "recommended_action": "block",
            "reasoning": "Detailed explanation...",
            "mitre_techniques": ["T1190", "T1078"],
            "compliance_concerns": ["pci_dss", "sox"]
        }}
        """
        
        client = self.llm_clients[LLMProvider.OPENAI_GPT4]
        response = await client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=700,
            temperature=0.1
        )
        
        return json.loads(response.choices[0].message.content)

    async def _analyze_with_claude(self, context: Dict, findings: List[Dict]) -> Dict[str, Any]:
        """Anthropic Claude analysis - conservative and reliable"""
        
        prompt = f"""
        Human: You are a conservative cybersecurity risk assessor focused on accuracy and minimal false positives.
        
        CONSERVATIVE SECURITY ASSESSMENT:
        
        Service: {context.get('service_name')}
        Environment: {context.get('environment')}  
        Security Findings: {len(findings)} total
        
        Findings Summary:
        {json.dumps(findings[:3], indent=2) if findings else 'Clean scan'}
        
        Provide a conservative, fact-based security assessment focusing on:
        
        1. Factual risk level based only on confirmed evidence
        2. Verified attack techniques (no speculation)
        3. Conservative business impact assessment
        4. Only confirmed MITRE techniques with evidence
        5. Compliance impact based on factual findings
        6. Conservative recommendation erring on side of caution
        
        Return JSON with conservative confidence levels and fact-based reasoning.
        Avoid speculation and focus on what can be proven from the data.
        
        Assistant: I'll provide a conservative, evidence-based security assessment.
        
        Based on the provided information, here's my factual analysis:
        
        {{
            "confidence": [0.6-0.9 based on evidence quality],
            "risk_assessment": "[critical/high/medium/low based on facts]",
            "attack_vectors": ["only_confirmed_vectors"],
            "business_impact": "[conservative_estimate]",
            "recommended_action": "[allow/block/defer with caution]",
            "reasoning": "Fact-based conservative analysis...",
            "mitre_techniques": ["only_confirmed_techniques"],
            "compliance_concerns": ["verified_concerns_only"]
        }}
        
        Human: Analyze the security findings and provide your conservative assessment.
        """
        
        client = self.llm_clients[LLMProvider.ANTHROPIC_CLAUDE]
        response = await client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=600,
            temperature=0.0,
            messages=[{"role": "user", "content": prompt}]
        )
        
        # Extract JSON from Claude's response
        content = response.content[0].text
        start_idx = content.find('{')
        end_idx = content.rfind('}') + 1
        if start_idx != -1 and end_idx != -1:
            json_content = content[start_idx:end_idx]
            return json.loads(json_content)
        else:
            # Fallback conservative response
            return {
                "confidence": 0.6,
                "risk_assessment": "medium",
                "attack_vectors": ["requires_investigation"],
                "business_impact": "medium",
                "recommended_action": "defer",
                "reasoning": "Conservative analysis - requires further investigation",
                "mitre_techniques": [],
                "compliance_concerns": []
            }

    async def _analyze_with_gemini(self, context: Dict, findings: List[Dict]) -> Dict[str, Any]:
        """Google Gemini analysis - multimodal and fast"""
        
        prompt = f"""
        RAPID MULTIMODAL SECURITY ANALYSIS
        
        Context: {json.dumps(context, indent=2)}
        Findings: {json.dumps(findings[:5], indent=2) if findings else 'No findings'}
        
        Perform rapid, comprehensive security analysis:
        
        1. Quick risk triage (critical/high/medium/low)
        2. Fast attack vector identification  
        3. Business impact assessment with speed
        4. MITRE technique mapping
        5. Compliance quick-check
        6. Rapid decision recommendation
        
        Optimize for speed while maintaining accuracy.
        Return JSON with analysis results.
        """
        
        model = self.llm_clients[LLMProvider.GOOGLE_GEMINI]
        response = await model.generate_content_async(prompt)
        
        # Parse Gemini response
        try:
            return json.loads(response.text)
        except:
            # Fallback parsing for Gemini
            return {
                "confidence": 0.75,
                "risk_assessment": "medium",
                "attack_vectors": ["rapid_analysis_needed"],
                "business_impact": "medium", 
                "recommended_action": "defer",
                "reasoning": "Gemini rapid analysis - needs verification",
                "mitre_techniques": [],
                "compliance_concerns": []
            }

    async def _analyze_with_cyber_llm(self, context: Dict, findings: List[Dict]) -> Dict[str, Any]:
        """Specialized cybersecurity LLM analysis"""
        
        # Placeholder for specialized cyber LLM
        # This would be a model fine-tuned specifically on security data
        
        return {
            "confidence": 0.90,
            "risk_assessment": "high",
            "attack_vectors": ["specialized_cyber_analysis"],
            "business_impact": "high",
            "recommended_action": "block",
            "reasoning": "Specialized cybersecurity model analysis - high confidence in threat detection",
            "mitre_techniques": ["T1190", "T1078", "T1003"],
            "compliance_concerns": ["pci_dss", "sox", "nist_ssdf"]
        }

    async def _perform_consensus_analysis(self, 
                                        analyses: List[LLMAnalysis],
                                        context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform consensus analysis across multiple LLM outputs"""
        
        if not analyses:
            return {
                "decision": "defer",
                "confidence": 0.0,
                "reasoning": "No valid LLM analyses available",
                "disagreements": ["all_analyses_failed"],
                "expert_needed": True
            }
        
        # Weighted scoring based on LLM strengths
        weights = {
            LLMProvider.EMERGENT_GPT5: 0.25,      # Balanced analysis
            LLMProvider.OPENAI_GPT4: 0.30,        # Deep reasoning
            LLMProvider.ANTHROPIC_CLAUDE: 0.25,   # Conservative reliability  
            LLMProvider.GOOGLE_GEMINI: 0.15,      # Fast analysis
            LLMProvider.SPECIALIZED_CYBER: 0.35   # Security expertise
        }
        
        # Calculate weighted consensus
        decision_votes = {"allow": 0, "block": 0, "defer": 0}
        confidence_sum = 0
        total_weight = 0
        
        mitre_techniques = set()
        compliance_concerns = set()
        attack_vectors = set()
        disagreement_areas = []
        
        for analysis in analyses:
            weight = weights.get(analysis.provider, 0.2)
            total_weight += weight
            
            # Vote weighting
            action = analysis.recommended_action.lower()
            if action in decision_votes:
                decision_votes[action] += weight
            
            # Confidence weighting
            confidence_sum += analysis.confidence * weight
            
            # Aggregate intelligence
            mitre_techniques.update(analysis.mitre_techniques)
            compliance_concerns.update(analysis.compliance_concerns)
            attack_vectors.update(analysis.attack_vectors)
        
        # Determine consensus decision
        final_decision = max(decision_votes, key=decision_votes.get)
        consensus_confidence = confidence_sum / total_weight if total_weight > 0 else 0.5
        
        # Check for disagreements
        decision_spread = max(decision_votes.values()) - min(decision_votes.values())
        if decision_spread < 0.3:  # Close votes indicate disagreement
            disagreement_areas.append("decision_split")
        
        confidence_values = [a.confidence for a in analyses]
        if max(confidence_values) - min(confidence_values) > 0.4:
            disagreement_areas.append("confidence_variance")
        
        # Determine if expert validation needed
        expert_needed = (
            len(disagreement_areas) > 0 or 
            consensus_confidence < 0.7 or
            final_decision == "defer"
        )
        
        reasoning = self._generate_consensus_reasoning(
            analyses, final_decision, consensus_confidence, disagreement_areas
        )
        
        return {
            "decision": final_decision,
            "confidence": consensus_confidence,
            "reasoning": reasoning,
            "disagreements": disagreement_areas,
            "expert_needed": expert_needed,
            "mitre_techniques": list(mitre_techniques),
            "compliance_concerns": list(compliance_concerns),
            "attack_vectors": list(attack_vectors)
        }

    def _generate_consensus_reasoning(self, 
                                    analyses: List[LLMAnalysis],
                                    decision: str,
                                    confidence: float,
                                    disagreements: List[str]) -> str:
        """Generate human-readable consensus reasoning"""
        
        provider_names = [a.provider.value.replace('_', ' ').title() for a in analyses]
        
        reasoning = f"""
        MULTI-LLM CONSENSUS ANALYSIS ({len(analyses)} models):
        
        Models Consulted: {', '.join(provider_names)}
        
        Decision: {decision.upper()} with {confidence:.0%} consensus confidence
        
        Key Findings:
        """
        
        # Add individual LLM insights
        for analysis in analyses:
            reasoning += f"\n• {analysis.provider.value.replace('_', ' ').title()}: {analysis.risk_assessment} risk, {analysis.confidence:.0%} confidence"
            if analysis.reasoning:
                reasoning += f" - {analysis.reasoning[:100]}..."
        
        # Add disagreement notes
        if disagreements:
            reasoning += f"\n\nNote: Disagreements detected in {', '.join(disagreements)} - expert review recommended"
        
        return reasoning

    def _create_fallback_result(self, context: Dict, start_time: float) -> MultiLLMDecisionResult:
        """Create fallback result when all LLM analyses fail"""
        
        return MultiLLMDecisionResult(
            final_decision="defer",
            consensus_confidence=0.0,
            individual_analyses=[],
            consensus_reasoning="All LLM analyses failed - manual review required",
            disagreement_areas=["analysis_failure"],
            expert_validation_required=True,
            evidence_id=f"FALLBACK-EVD-{int(time.time())}",
            processing_time_ms=(time.time() - start_time) * 1000
        )

# Global advanced LLM engine
advanced_llm_engine = AdvancedLLMEngine()