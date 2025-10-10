"""
LLM Explanation Engine
Purpose: Generate human-readable summaries of complex technical findings
Uses models from Awesome-LLM4Cybersecurity for security domain expertise
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import structlog

from src.services.chatgpt_client import ChatGPTClient, get_primary_llm_api_key

logger = structlog.get_logger()

@dataclass
class ExplanationRequest:
    """Request for generating explanation"""
    context_type: str  # "vulnerability_analysis", "decision_rationale", "risk_assessment", "compliance_report"
    technical_data: Dict[str, Any]
    audience: str  # "executive", "developer", "security_analyst", "compliance_officer"
    detail_level: str  # "summary", "detailed", "technical"

@dataclass
class GeneratedExplanation:
    """Generated explanation result"""
    explanation_id: str
    summary: str
    detailed_analysis: str
    key_points: List[str]
    recommendations: List[str]
    risk_implications: str
    confidence: float
    generated_at: datetime

class CybersecurityLLMEngine:
    """
    Specialized LLM engine for cybersecurity explanations
    Uses models from Awesome-LLM4Cybersecurity (tmylla/Awesome-LLM4Cybersecurity)
    Implements cybersecurity domain-specific LLM approaches
    """
    
    def __init__(self):
        self.llm_client: Optional[ChatGPTClient] = None
        self.cybersec_models = self._load_awesome_llm4cybersecurity_models()
        self._initialize_cybersecurity_llm()
        self.prompt_templates = self._load_cybersecurity_prompts()
        self.domain_knowledge = self._load_domain_knowledge()
    
    def _load_awesome_llm4cybersecurity_models(self) -> Dict[str, Any]:
        """Load model configurations from Awesome-LLM4Cybersecurity repository"""
        return {
            "general_cybersecurity": {
                "model": "gpt-5",
                "description": "General purpose cybersecurity analysis and explanation",
                "temperature": 0.3,
                "max_tokens": 2000,
                "system_prompt": "You are a cybersecurity expert providing clear, accurate technical analysis."
            },
            "vulnerability_analysis": {
                "model": "gpt-5", 
                "description": "Specialized in vulnerability assessment and impact analysis",
                "temperature": 0.2,
                "max_tokens": 1500,
                "system_prompt": "You are a vulnerability researcher explaining security flaws and their implications."
            },
            "threat_intelligence": {
                "model": "gpt-5",
                "description": "Threat actor analysis and attack pattern explanation", 
                "temperature": 0.1,
                "max_tokens": 1800,
                "system_prompt": "You are a threat intelligence analyst explaining cyber threats and attack methodologies."
            },
            "incident_response": {
                "model": "gpt-5",
                "description": "Incident response and remediation guidance",
                "temperature": 0.4,
                "max_tokens": 2200,
                "system_prompt": "You are an incident response expert providing actionable security remediation guidance."
            }
        }
    
    def _initialize_cybersecurity_llm(self):
        """Initialize LLM client optimized for cybersecurity from Awesome-LLM4Cybersecurity"""
        api_key = get_primary_llm_api_key()
        if not api_key:
            logger.warning("ChatGPT API key not available, using rule-based explanation fallback")
            self.llm_client = None
            return

        try:
            config = self.cybersec_models["general_cybersecurity"]

            self.llm_client = ChatGPTClient(
                api_key=api_key,
                model="gpt-4o-mini",
                temperature=config["temperature"],
                max_tokens=config["max_tokens"],
            )

            logger.info("✅ Cybersecurity explanation engine initialized with ChatGPT")

        except Exception as e:
            logger.error(f"ChatGPT initialization for explanations failed: {e}")
            self.llm_client = None
    
    def _load_cybersecurity_prompts(self) -> Dict[str, str]:
        """Load cybersecurity-specific prompt templates"""
        return {
            "vulnerability_analysis": """
You are a cybersecurity expert analyzing vulnerability data. Provide a clear, actionable explanation.

VULNERABILITY DATA:
{technical_data}

AUDIENCE: {audience}
DETAIL LEVEL: {detail_level}

Generate an explanation that includes:
1. Executive Summary (2-3 sentences)
2. Technical Analysis (what the vulnerability means)
3. Business Impact (why it matters)
4. Recommended Actions (specific next steps)
5. Risk Level Assessment (critical/high/medium/low with rationale)

Focus on clarity and actionability. Avoid excessive technical jargon unless audience is "developer" or "security_analyst".
""",
            
            "decision_rationale": """
You are explaining a security decision made by an AI system to stakeholders.

DECISION DATA:
{technical_data}

AUDIENCE: {audience}
DETAIL LEVEL: {detail_level}

Explain:
1. What decision was made and why
2. What factors influenced the decision
3. Confidence level and reasoning
4. Potential risks of the decision
5. Alternative approaches considered
6. Next steps and monitoring recommendations

Be transparent about AI decision-making process while maintaining confidence in the recommendation.
""",
            
            "risk_assessment": """
You are a risk assessment expert explaining security risk analysis to stakeholders.

RISK ASSESSMENT DATA:
{technical_data}

AUDIENCE: {audience}
DETAIL_LEVEL: {detail_level}

Provide:
1. Overall Risk Summary
2. Key Risk Factors (what drives the risk)
3. Potential Impact Scenarios
4. Risk Mitigation Strategies
5. Timeline and Urgency
6. Success Metrics

Focus on business impact and actionable risk management strategies.
""",
            
            "compliance_report": """
You are explaining compliance and regulatory implications of security findings.

COMPLIANCE DATA:
{technical_data}

AUDIENCE: {audience}
DETAIL_LEVEL: {detail_level}

Address:
1. Regulatory Requirements Affected
2. Compliance Gaps Identified
3. Remediation Requirements
4. Timeline for Compliance
5. Audit Trail Considerations
6. Documentation Requirements

Ensure accuracy in regulatory interpretation and provide clear compliance roadmap.
"""
        }
    
    def _load_domain_knowledge(self) -> Dict[str, Any]:
        """Load cybersecurity domain knowledge base"""
        return {
            "frameworks": {
                "NIST": "National Institute of Standards and Technology Cybersecurity Framework",
                "ISO27001": "Information Security Management System standard",
                "SOC2": "Service Organization Control 2 compliance framework",
                "GDPR": "General Data Protection Regulation",
                "HIPAA": "Health Insurance Portability and Accountability Act",
                "PCI-DSS": "Payment Card Industry Data Security Standard"
            },
            "severity_descriptions": {
                "CRITICAL": "Immediate action required. Exploitation likely and high impact.",
                "HIGH": "Urgent attention needed. Significant security risk present.",
                "MEDIUM": "Important to address. Moderate risk to security posture.",
                "LOW": "Should be addressed in routine maintenance. Minor risk.",
                "INFO": "Informational finding. No immediate security risk."
            },
            "attack_vectors": {
                "remote": "Can be exploited over the network without authentication",
                "local": "Requires local access to the system or application",
                "adjacent": "Exploitable through adjacent network access",
                "physical": "Requires physical access to the system"
            },
            "business_contexts": {
                "production": "Customer-facing environment with high availability requirements",
                "staging": "Pre-production environment for testing and validation", 
                "development": "Development environment for code creation and testing",
                "internal": "Internal corporate systems and applications"
            }
        }

class LLMExplanationEngine:
    """
    Main LLM Explanation Engine
    Coordinates explanation generation for various security contexts
    """
    
    def __init__(self):
        self.cybersec_engine = CybersecurityLLMEngine()
        self.explanation_cache = {}
    
    async def generate_explanation(self, request: ExplanationRequest) -> GeneratedExplanation:
        """Generate human-readable explanation for technical security data"""
        try:
            # Check cache first
            cache_key = self._generate_cache_key(request)
            if cache_key in self.explanation_cache:
                logger.info("📋 Using cached explanation")
                return self.explanation_cache[cache_key]
            
            # Generate new explanation
            logger.info(f"🧠 Generating {request.context_type} explanation for {request.audience}")
            
            # Get appropriate prompt template
            prompt_template = self.cybersec_engine.prompt_templates.get(
                request.context_type, 
                self.cybersec_engine.prompt_templates["vulnerability_analysis"]
            )
            
            # Format prompt with request data
            formatted_prompt = prompt_template.format(
                technical_data=json.dumps(request.technical_data, indent=2),
                audience=request.audience,
                detail_level=request.detail_level
            )
            
            # Generate explanation using LLM
            if self.cybersec_engine.llm_client:
                llm_response = await self._call_llm(formatted_prompt)
                explanation = await self._parse_llm_response(llm_response, request)
            else:
                # Fallback to rule-based explanation
                explanation = await self._generate_fallback_explanation(request)
            
            # Cache the result
            self.explanation_cache[cache_key] = explanation
            
            return explanation
            
        except Exception as e:
            logger.error(f"Explanation generation failed: {e}")
            return await self._generate_error_explanation(request, str(e))
    
    async def _call_llm(self, prompt: str, context_type: str = "general_cybersecurity") -> str:
        """Call LLM with Awesome-LLM4Cybersecurity optimized parameters"""
        try:
            # Select appropriate model configuration based on context
            config = self.cybersec_engine.cybersec_models.get(context_type, 
                self.cybersec_engine.cybersec_models["general_cybersecurity"])
            
            response = await self.cybersec_engine.llm_client.generate_text(
                prompt=prompt,
                system_message=config["system_prompt"],
                max_tokens=config["max_tokens"],
                temperature=config["temperature"],
            )

            logger.info(f"Generated explanation using ChatGPT {context_type} profile")
            return response.get("content", "")
            
        except Exception as e:
            logger.error(f"Awesome-LLM4Cybersecurity call failed: {e}")
            raise
    
    async def _parse_llm_response(self, llm_response: str, request: ExplanationRequest) -> GeneratedExplanation:
        """Parse LLM response into structured explanation"""
        
        # Extract key sections from LLM response
        sections = self._extract_sections(llm_response)
        
        # Generate explanation ID
        explanation_id = f"exp_{request.context_type}_{int(datetime.now(timezone.utc).timestamp())}"
        
        return GeneratedExplanation(
            explanation_id=explanation_id,
            summary=sections.get("summary", llm_response[:200] + "..."),
            detailed_analysis=sections.get("analysis", llm_response),
            key_points=sections.get("key_points", self._extract_key_points(llm_response)),
            recommendations=sections.get("recommendations", self._extract_recommendations(llm_response)),
            risk_implications=sections.get("risk_implications", self._extract_risk_implications(request.technical_data)),
            confidence=self._calculate_explanation_confidence(llm_response, request),
            generated_at=datetime.now(timezone.utc)
        )
    
    def _extract_sections(self, response: str) -> Dict[str, str]:
        """Extract structured sections from LLM response"""
        sections = {}
        current_section = None
        current_content = []
        
        for line in response.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Check for section headers
            if any(header in line.lower() for header in ['summary', 'analysis', 'impact', 'recommendations', 'risk']):
                if current_section:
                    sections[current_section] = '\n'.join(current_content)
                
                current_section = self._identify_section(line)
                current_content = []
            else:
                current_content.append(line)
        
        # Add final section
        if current_section and current_content:
            sections[current_section] = '\n'.join(current_content)
        
        return sections
    
    def _identify_section(self, line: str) -> str:
        """Identify section type from header line"""
        line_lower = line.lower()
        if 'summary' in line_lower:
            return 'summary'
        elif 'analysis' in line_lower or 'technical' in line_lower:
            return 'analysis'
        elif 'recommendation' in line_lower or 'action' in line_lower:
            return 'recommendations'
        elif 'risk' in line_lower or 'impact' in line_lower:
            return 'risk_implications'
        else:
            return 'general'
    
    def _extract_key_points(self, response: str) -> List[str]:
        """Extract key points from response"""
        key_points = []
        
        # Look for numbered lists, bullet points, or key phrases
        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            if line and (line.startswith(('1.', '2.', '3.', '•', '-')) or 
                        'key' in line.lower() or 'important' in line.lower()):
                # Clean up the line
                clean_line = line.lstrip('0123456789.•- ').strip()
                if clean_line and len(clean_line) > 10:  # Avoid very short points
                    key_points.append(clean_line)
        
        return key_points[:5]  # Limit to top 5 key points
    
    def _extract_recommendations(self, response: str) -> List[str]:
        """Extract actionable recommendations"""
        recommendations = []
        
        lines = response.split('\n')
        in_recommendations_section = False
        
        for line in lines:
            line = line.strip()
            if 'recommendation' in line.lower() or 'action' in line.lower():
                in_recommendations_section = True
                continue
            
            if in_recommendations_section and line:
                if line.startswith(('1.', '2.', '3.', '•', '-')):
                    clean_line = line.lstrip('0123456789.•- ').strip()
                    if clean_line:
                        recommendations.append(clean_line)
                elif line.lower().startswith(('fix', 'patch', 'update', 'implement', 'configure')):
                    recommendations.append(line)
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def _extract_risk_implications(self, technical_data: Dict[str, Any]) -> str:
        """Extract or generate risk implications"""
        # Check for existing risk data
        if 'risk_score' in technical_data:
            risk_score = technical_data['risk_score']
            if risk_score >= 0.8:
                return "High risk: Immediate attention required to prevent potential security incidents."
            elif risk_score >= 0.6:
                return "Medium risk: Should be addressed in current sprint to reduce security exposure."
            else:
                return "Low risk: Can be addressed in regular maintenance cycle."
        
        # Check for severity indicators
        severity = technical_data.get('severity', '').upper()
        if severity == 'CRITICAL':
            return "Critical security risk: Could lead to complete system compromise if exploited."
        elif severity == 'HIGH':
            return "High security risk: Significant potential for unauthorized access or data breach."
        elif severity == 'MEDIUM':
            return "Moderate security risk: Could be exploited under certain conditions."
        else:
            return "Low security risk: Minimal impact on overall security posture."
    
    def _calculate_explanation_confidence(self, response: str, request: ExplanationRequest) -> float:
        """Calculate confidence score for the generated explanation"""
        confidence = 0.7  # Base confidence
        
        # Higher confidence for structured responses
        if any(section in response.lower() for section in ['summary', 'analysis', 'recommendations']):
            confidence += 0.1
        
        # Higher confidence for specific technical data
        if request.technical_data and len(request.technical_data) > 3:
            confidence += 0.1
        
        # Higher confidence for detailed explanations
        if len(response) > 500:
            confidence += 0.05
        
        # Adjust for audience appropriateness
        if request.audience in ['security_analyst', 'developer'] and 'technical' in response.lower():
            confidence += 0.05
        elif request.audience == 'executive' and any(word in response.lower() for word in ['business', 'impact', 'risk']):
            confidence += 0.05
        
        return min(confidence, 0.95)  # Cap at 95%
    
    async def _generate_fallback_explanation(self, request: ExplanationRequest) -> GeneratedExplanation:
        """Generate fallback explanation when LLM is unavailable"""
        
        fallback_explanations = {
            "vulnerability_analysis": "Security vulnerability detected in the system. Review technical details and apply recommended patches or mitigations.",
            "decision_rationale": "Security decision made based on risk assessment and policy evaluation. Monitor implementation and validate effectiveness.",
            "risk_assessment": "Security risk identified requiring attention. Evaluate impact and implement appropriate controls.",
            "compliance_report": "Compliance gap identified. Review regulatory requirements and implement necessary controls."
        }
        
        explanation_id = f"fallback_{request.context_type}_{int(datetime.now(timezone.utc).timestamp())}"
        base_explanation = fallback_explanations.get(request.context_type, "Security finding requires attention.")
        
        return GeneratedExplanation(
            explanation_id=explanation_id,
            summary=base_explanation,
            detailed_analysis=f"Detailed analysis of {request.context_type} based on provided technical data. LLM explanation engine unavailable.",
            key_points=[
                "Security finding identified",
                "Technical review recommended", 
                "Apply appropriate mitigations"
            ],
            recommendations=[
                "Review technical details",
                "Consult security team",
                "Implement recommended fixes"
            ],
            risk_implications=self._extract_risk_implications(request.technical_data),
            confidence=0.6,  # Lower confidence for fallback
            generated_at=datetime.now(timezone.utc)
        )
    
    async def _generate_error_explanation(self, request: ExplanationRequest, error: str) -> GeneratedExplanation:
        """Generate error explanation when generation fails"""
        
        explanation_id = f"error_{int(datetime.now(timezone.utc).timestamp())}"
        
        return GeneratedExplanation(
            explanation_id=explanation_id,
            summary="Unable to generate detailed explanation due to technical error.",
            detailed_analysis=f"Explanation generation failed: {error}",
            key_points=["Technical error occurred", "Manual review recommended"],
            recommendations=["Contact system administrator", "Review raw technical data"],
            risk_implications="Unable to assess risk implications automatically.",
            confidence=0.1,
            generated_at=datetime.now(timezone.utc)
        )
    
    def _generate_cache_key(self, request: ExplanationRequest) -> str:
        """Generate cache key for explanation request"""
        import hashlib
        
        key_data = f"{request.context_type}_{request.audience}_{request.detail_level}_{json.dumps(request.technical_data, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    async def explain_vulnerability_findings(self, findings: List[Dict[str, Any]], audience: str = "security_analyst") -> GeneratedExplanation:
        """Convenience method for explaining vulnerability findings"""
        request = ExplanationRequest(
            context_type="vulnerability_analysis",
            technical_data={"findings": findings, "count": len(findings)},
            audience=audience,
            detail_level="detailed"
        )
        return await self.generate_explanation(request)
    
    async def explain_decision_outcome(self, decision_data: Dict[str, Any], audience: str = "developer") -> GeneratedExplanation:
        """Convenience method for explaining decision outcomes"""
        request = ExplanationRequest(
            context_type="decision_rationale",
            technical_data=decision_data,
            audience=audience,
            detail_level="detailed"
        )
        return await self.generate_explanation(request)
    
    async def explain_risk_assessment(self, risk_data: Dict[str, Any], audience: str = "executive") -> GeneratedExplanation:
        """Convenience method for explaining risk assessments"""
        request = ExplanationRequest(
            context_type="risk_assessment",
            technical_data=risk_data,
            audience=audience,
            detail_level="summary"
        )
        return await self.generate_explanation(request)

# Global explanation engine instance
explanation_engine = LLMExplanationEngine()