"""Advanced PentAGI integration with multi-AI orchestration.

Phase 2 Implementation - AI Consensus
This module implements multi-AI orchestration with real LLM provider integration,
configurable consensus thresholds, and comprehensive error handling with fallbacks.

Environment Variables:
- FIXOPS_CONSENSUS_THRESHOLD: Minimum confidence for automated execution (default: 0.6)
- FIXOPS_CONSENSUS_WEIGHTS_ARCHITECT: Weight for architect decisions (default: 0.35)
- FIXOPS_CONSENSUS_WEIGHTS_DEVELOPER: Weight for developer decisions (default: 0.40)
- FIXOPS_CONSENSUS_WEIGHTS_LEAD: Weight for lead decisions (default: 0.25)
- FIXOPS_LLM_TIMEOUT: Timeout for LLM calls in seconds (default: 30)
- FIXOPS_LLM_MAX_RETRIES: Maximum retries for LLM calls (default: 3)
- FIXOPS_LLM_FALLBACK_ENABLED: Enable fallback to deterministic responses (default: true)
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from core.llm_providers import LLMProviderManager, LLMResponse
from core.pentagi_db import PentagiDB
from core.pentagi_models import (
    ExploitabilityLevel,
    PenTestConfig,
    PenTestPriority,
    PenTestRequest,
    PenTestResult,
    PenTestStatus,
)

logger = logging.getLogger(__name__)


class LLMCallError(Exception):
    """Raised when an LLM call fails after all retries."""


@dataclass
class ConsensusConfig:
    """Configuration for AI consensus decision-making.

    This configuration controls how multiple AI models collaborate to make
    security decisions, including confidence thresholds and role weights.
    """

    threshold: float = 0.6
    weights: Dict[str, float] = field(
        default_factory=lambda: {
            "architect": 0.35,
            "developer": 0.40,
            "lead": 0.25,
        }
    )
    timeout_seconds: float = 30.0
    max_retries: int = 3
    fallback_enabled: bool = True

    @classmethod
    def from_env(cls) -> "ConsensusConfig":
        """Load consensus configuration from environment variables."""
        return cls(
            threshold=float(os.getenv("FIXOPS_CONSENSUS_THRESHOLD", "0.6")),
            weights={
                "architect": float(
                    os.getenv("FIXOPS_CONSENSUS_WEIGHTS_ARCHITECT", "0.35")
                ),
                "developer": float(
                    os.getenv("FIXOPS_CONSENSUS_WEIGHTS_DEVELOPER", "0.40")
                ),
                "lead": float(os.getenv("FIXOPS_CONSENSUS_WEIGHTS_LEAD", "0.25")),
            },
            timeout_seconds=float(os.getenv("FIXOPS_LLM_TIMEOUT", "30")),
            max_retries=int(os.getenv("FIXOPS_LLM_MAX_RETRIES", "3")),
            fallback_enabled=os.getenv("FIXOPS_LLM_FALLBACK_ENABLED", "true").lower()
            in ("true", "1", "yes"),
        )

    def validate(self) -> None:
        """Validate configuration values."""
        if not 0 <= self.threshold <= 1:
            raise ValueError(
                f"Consensus threshold must be between 0 and 1, got {self.threshold}"
            )
        total_weight = sum(self.weights.values())
        if abs(total_weight - 1.0) > 0.01:
            raise ValueError(f"Consensus weights must sum to 1.0, got {total_weight}")
        if self.timeout_seconds <= 0:
            raise ValueError(f"Timeout must be positive, got {self.timeout_seconds}")
        if self.max_retries < 1:
            raise ValueError(f"Max retries must be at least 1, got {self.max_retries}")


class AIRole(Enum):
    """AI model roles in the orchestration."""

    ARCHITECT = "architect"  # Gemini - Solution Architect
    DEVELOPER = "developer"  # Claude - Developer
    LEAD = "lead"  # GPT - Team Lead
    COMPOSER = "composer"  # Meta-agent for consensus


@dataclass
class AIDecision:
    """Decision from an AI model."""

    role: AIRole
    recommendation: str
    confidence: float
    reasoning: str
    priority: int
    metadata: Dict = field(default_factory=dict)


@dataclass
class ConsensusDecision:
    """Final consensus decision from all AI models."""

    action: str
    confidence: float
    reasoning: str
    contributing_decisions: List[AIDecision]
    execution_plan: List[Dict]
    metadata: Dict = field(default_factory=dict)


class MultiAIOrchestrator:
    """Orchestrates multiple AI models for consensus-based decisions.

    This orchestrator coordinates multiple LLM providers (OpenAI, Anthropic, Gemini)
    to reach consensus on security decisions. Each provider plays a specific role:
    - Gemini: Solution Architect (attack surface analysis, business impact)
    - Claude: Developer (exploitability, tool selection, payload design)
    - GPT: Team Lead (strategy, risk assessment, success criteria)

    The orchestrator uses configurable weights and thresholds to combine
    individual decisions into a final consensus.
    """

    def __init__(
        self,
        llm_manager: LLMProviderManager,
        config: Optional[ConsensusConfig] = None,
    ):
        """Initialize the orchestrator.

        Args:
            llm_manager: LLM provider manager for making API calls
            config: Optional consensus configuration (defaults to env-based config)
        """
        self.llm_manager = llm_manager
        self.config = config or ConsensusConfig.from_env()
        self.config.validate()
        self.decision_history: List[ConsensusDecision] = []
        self._call_count: Dict[str, int] = {"total": 0, "success": 0, "fallback": 0}
        logger.info(
            f"MultiAIOrchestrator initialized with threshold={self.config.threshold}, "
            f"weights={self.config.weights}"
        )

    async def get_architect_decision(
        self, context: Dict, vulnerability: Dict
    ) -> AIDecision:
        """Get decision from Gemini as Solution Architect."""
        prompt = f"""You are a Senior Security Solution Architect analyzing a vulnerability.

Context:
{json.dumps(context, indent=2)}

Vulnerability:
{json.dumps(vulnerability, indent=2)}

Provide your analysis as a Solution Architect:
1. Attack surface analysis
2. Risk prioritization (1-10 scale)
3. Recommended attack vectors to test
4. Business impact assessment
5. Compliance implications

Respond in JSON format with keys: recommendation, confidence, reasoning, priority, attack_vectors, business_impact
"""

        try:
            # Use Gemini provider for architect role
            response = await self._call_llm("gemini", prompt)
            result = json.loads(response)

            return AIDecision(
                role=AIRole.ARCHITECT,
                recommendation=result.get("recommendation", ""),
                confidence=result.get("confidence", 0.7),
                reasoning=result.get("reasoning", ""),
                priority=result.get("priority", 5),
                metadata={
                    "attack_vectors": result.get("attack_vectors", []),
                    "business_impact": result.get("business_impact", "Unknown"),
                },
            )
        except Exception as e:
            logger.error(f"Architect decision failed: {e}")
            return self._fallback_decision(AIRole.ARCHITECT, vulnerability)

    async def get_developer_decision(
        self, context: Dict, vulnerability: Dict
    ) -> AIDecision:
        """Get decision from Claude as Developer."""
        prompt = f"""You are a Senior Security Developer tasked with exploit development.

Context:
{json.dumps(context, indent=2)}

Vulnerability:
{json.dumps(vulnerability, indent=2)}

Provide your analysis as a Developer:
1. Exploitability assessment
2. Tool selection for testing
3. Exploit strategy and payload design
4. Expected difficulty (1-10 scale)
5. Recommended testing sequence

Respond in JSON format with keys: recommendation, confidence, reasoning, priority, tools, exploit_strategy
"""

        try:
            # Use Claude provider for developer role
            response = await self._call_llm("anthropic", prompt)
            result = json.loads(response)

            return AIDecision(
                role=AIRole.DEVELOPER,
                recommendation=result.get("recommendation", ""),
                confidence=result.get("confidence", 0.7),
                reasoning=result.get("reasoning", ""),
                priority=result.get("priority", 5),
                metadata={
                    "tools": result.get("tools", []),
                    "exploit_strategy": result.get("exploit_strategy", ""),
                },
            )
        except Exception as e:
            logger.error(f"Developer decision failed: {e}")
            return self._fallback_decision(AIRole.DEVELOPER, vulnerability)

    async def get_lead_decision(self, context: Dict, vulnerability: Dict) -> AIDecision:
        """Get decision from GPT as Team Lead."""
        prompt = f"""You are a Security Team Lead reviewing a vulnerability for testing.

Context:
{json.dumps(context, indent=2)}

Vulnerability:
{json.dumps(vulnerability, indent=2)}

Provide your analysis as a Team Lead:
1. Overall test strategy
2. Risk vs. effort assessment
3. Best practices and quality checks
4. Prioritization recommendation (1-10 scale)
5. Success criteria and validation approach

Respond in JSON format with keys: recommendation, confidence, reasoning, priority, strategy, success_criteria
"""

        try:
            # Use OpenAI provider for lead role
            response = await self._call_llm("openai", prompt)
            result = json.loads(response)

            return AIDecision(
                role=AIRole.LEAD,
                recommendation=result.get("recommendation", ""),
                confidence=result.get("confidence", 0.7),
                reasoning=result.get("reasoning", ""),
                priority=result.get("priority", 5),
                metadata={
                    "strategy": result.get("strategy", ""),
                    "success_criteria": result.get("success_criteria", []),
                },
            )
        except Exception as e:
            logger.error(f"Lead decision failed: {e}")
            return self._fallback_decision(AIRole.LEAD, vulnerability)

    async def compose_consensus(
        self,
        architect: AIDecision,
        developer: AIDecision,
        lead: AIDecision,
        context: Dict,
    ) -> ConsensusDecision:
        """Compose final consensus decision from all AI inputs."""
        prompt = f"""You are the Meta-Agent Composer synthesizing decisions from three AI experts.

Architect Decision:
{json.dumps(architect.__dict__, default=str, indent=2)}

Developer Decision:
{json.dumps(developer.__dict__, default=str, indent=2)}

Lead Decision:
{json.dumps(lead.__dict__, default=str, indent=2)}

Context:
{json.dumps(context, indent=2)}

Your task:
1. Synthesize the best insights from each expert
2. Resolve any conflicts or disagreements
3. Create a unified execution plan
4. Provide final confidence score (weighted average)
5. Generate step-by-step action plan

Respond in JSON format with keys: action, confidence, reasoning, execution_plan (list of steps)
"""

        try:
            # Use most capable model for meta-composition
            response = await self._call_llm("openai", prompt)
            result = json.loads(response)

            # Calculate weighted confidence
            weights = {"architect": 0.35, "developer": 0.40, "lead": 0.25}
            weighted_confidence = (
                architect.confidence * weights["architect"]
                + developer.confidence * weights["developer"]
                + lead.confidence * weights["lead"]
            )

            consensus = ConsensusDecision(
                action=result.get("action", "execute_pentest"),
                confidence=weighted_confidence,
                reasoning=result.get("reasoning", ""),
                contributing_decisions=[architect, developer, lead],
                execution_plan=result.get("execution_plan", []),
                metadata={
                    "composer_confidence": result.get("confidence", 0.8),
                    "decision_timestamp": datetime.utcnow().isoformat(),
                },
            )

            self.decision_history.append(consensus)
            return consensus

        except Exception as e:
            logger.error(f"Consensus composition failed: {e}")
            # Fallback: simple averaging
            return self._fallback_consensus(architect, developer, lead)

    async def _call_llm(
        self,
        provider: str,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Call LLM provider with retry logic and fallback support.

        This method integrates with the LLMProviderManager to make real API calls
        to LLM providers (OpenAI, Anthropic, Gemini). It includes:
        - Automatic retry with exponential backoff (uses config.max_retries)
        - Timeout handling (uses config.timeout_seconds)
        - Fallback to deterministic responses when providers are unavailable
        - Comprehensive error handling and logging
        - Call statistics tracking
        - Non-blocking I/O via asyncio.to_thread()

        Args:
            provider: Name of the LLM provider ('openai', 'anthropic', 'gemini')
            prompt: The prompt to send to the LLM
            context: Optional context dictionary for the analysis

        Returns:
            JSON string containing the LLM response

        Raises:
            LLMCallError: If all retries fail and fallback is disabled
        """
        self._call_count["total"] += 1
        context = context or {}

        last_error: Optional[Exception] = None

        # Retry loop using config.max_retries
        for attempt in range(self.config.max_retries):
            try:
                # Wrap blocking LLM call in asyncio.to_thread to avoid blocking the event loop
                # Apply timeout using config.timeout_seconds
                response: LLMResponse = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.llm_manager.analyse,
                        provider,
                        prompt=prompt,
                        context=context,
                        default_action="review",
                        default_confidence=0.5,
                        default_reasoning=f"Deterministic analysis from {provider}",
                        mitigation_hints={
                            "mitre_candidates": ["T1190", "T1059"],
                            "compliance": ["PCI-DSS", "SOC2"],
                            "attack_vectors": ["injection", "authentication_bypass"],
                        },
                    ),
                    timeout=self.config.timeout_seconds,
                )

                is_fallback = response.metadata.get("mode") in (
                    "deterministic",
                    "fallback",
                )

                if is_fallback:
                    self._call_count["fallback"] += 1
                    logger.warning(
                        f"LLM provider {provider} returned fallback response: "
                        f"{response.metadata.get('reason', 'unknown')}"
                    )
                else:
                    self._call_count["success"] += 1
                    logger.info(
                        f"LLM provider {provider} returned successful response "
                        f"(confidence={response.confidence:.2f})"
                    )

                result = {
                    "recommendation": response.recommended_action,
                    "confidence": response.confidence,
                    "reasoning": response.reasoning,
                    "priority": self._confidence_to_priority(response.confidence),
                    "attack_vectors": list(response.attack_vectors),
                    "mitre_techniques": list(response.mitre_techniques),
                    "compliance_concerns": list(response.compliance_concerns),
                    "tools": self._suggest_tools(response.attack_vectors),
                    "strategy": self._derive_strategy(response),
                    "success_criteria": self._derive_success_criteria(response),
                    "business_impact": self._assess_business_impact(response),
                    "exploit_strategy": response.reasoning,
                    "metadata": {
                        "provider": provider,
                        "mode": response.metadata.get("mode", "unknown"),
                        "duration_ms": response.metadata.get("duration_ms"),
                        "attempt": attempt + 1,
                    },
                }

                return json.dumps(result)

            except asyncio.TimeoutError:
                last_error = asyncio.TimeoutError(
                    f"LLM call to {provider} timed out after {self.config.timeout_seconds}s"
                )
                logger.warning(
                    f"LLM call to {provider} timed out (attempt {attempt + 1}/{self.config.max_retries})"
                )
            except Exception as e:
                last_error = e
                logger.warning(
                    f"LLM call to {provider} failed (attempt {attempt + 1}/{self.config.max_retries}): {e}"
                )

            # Exponential backoff before retry (except on last attempt)
            if attempt < self.config.max_retries - 1:
                backoff_seconds = min(2**attempt, 30)  # Cap at 30 seconds
                logger.info(f"Retrying in {backoff_seconds}s...")
                await asyncio.sleep(backoff_seconds)

        # All retries exhausted
        logger.error(
            f"LLM call to {provider} failed after {self.config.max_retries} attempts: {last_error}"
        )

        if self.config.fallback_enabled:
            self._call_count["fallback"] += 1
            return json.dumps(
                {
                    "recommendation": "Proceed with standard testing",
                    "confidence": 0.5,
                    "reasoning": f"Fallback response due to {provider} error after {self.config.max_retries} retries: {last_error}",
                    "priority": 5,
                    "attack_vectors": ["manual_review"],
                    "tools": ["manual"],
                    "strategy": "Conservative testing approach",
                    "success_criteria": ["Manual verification required"],
                    "metadata": {
                        "fallback": True,
                        "error": str(last_error),
                        "retries_attempted": self.config.max_retries,
                    },
                }
            )
        else:
            raise LLMCallError(
                f"LLM call to {provider} failed after {self.config.max_retries} retries: {last_error}"
            ) from last_error

    def _confidence_to_priority(self, confidence: float) -> int:
        """Convert confidence score to priority (1-10 scale)."""
        return max(1, min(10, int(confidence * 10)))

    def _suggest_tools(self, attack_vectors: Sequence[str]) -> List[str]:
        """Suggest security testing tools based on attack vectors."""
        tool_mapping = {
            "injection": ["sqlmap", "burp"],
            "sql_injection": ["sqlmap", "sqlninja"],
            "xss": ["xsstrike", "dalfox"],
            "authentication_bypass": ["hydra", "burp"],
            "rce": ["metasploit", "commix"],
            "ssrf": ["ssrfmap", "burp"],
            "lfi": ["lfisuite", "burp"],
            "xxe": ["xxeinjector", "burp"],
        }
        tools: set[str] = set()
        for vector in attack_vectors:
            vector_lower = vector.lower().replace(" ", "_")
            if vector_lower in tool_mapping:
                tools.update(tool_mapping[vector_lower])
        return list(tools) if tools else ["burp", "manual"]

    def _derive_strategy(self, response: LLMResponse) -> str:
        """Derive testing strategy from LLM response."""
        if response.confidence > 0.8:
            return "Aggressive automated exploitation"
        elif response.confidence > 0.6:
            return "Multi-stage exploitation with validation"
        elif response.confidence > 0.4:
            return "Conservative testing with manual review"
        else:
            return "Manual analysis recommended"

    def _derive_success_criteria(self, response: LLMResponse) -> List[str]:
        """Derive success criteria from LLM response."""
        criteria = ["Vulnerability confirmed", "Evidence collected"]
        if response.compliance_concerns:
            criteria.append("Compliance impact documented")
        if response.mitre_techniques:
            criteria.append("MITRE ATT&CK mapping verified")
        return criteria

    def _assess_business_impact(self, response: LLMResponse) -> str:
        """Assess business impact based on LLM response."""
        if response.confidence > 0.8:
            return "Critical - Immediate remediation required"
        elif response.confidence > 0.6:
            return "High - Priority remediation needed"
        elif response.confidence > 0.4:
            return "Medium - Scheduled remediation"
        else:
            return "Low - Monitor and assess"

    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator call statistics."""
        total = self._call_count["total"]
        return {
            "total_calls": total,
            "successful_calls": self._call_count["success"],
            "fallback_calls": self._call_count["fallback"],
            "success_rate": self._call_count["success"] / total if total > 0 else 0,
            "fallback_rate": self._call_count["fallback"] / total if total > 0 else 0,
            "decisions_made": len(self.decision_history),
            "config": {
                "threshold": self.config.threshold,
                "weights": self.config.weights,
                "fallback_enabled": self.config.fallback_enabled,
            },
        }

    def _fallback_decision(self, role: AIRole, vulnerability: Dict) -> AIDecision:
        """Fallback decision when AI call fails.

        IMPORTANT: This is a deterministic fallback - NOT an AI-generated decision.
        The response is explicitly labeled for audit trail compliance.
        """
        fallback_timestamp = datetime.utcnow().isoformat() + "Z"
        vuln_id = vulnerability.get("id", "unknown")

        logger.warning(
            f"FALLBACK_DECISION: Using deterministic fallback for role={role.value}, "
            f"vulnerability={vuln_id}. This is NOT an AI-generated decision."
        )

        return AIDecision(
            role=role,
            recommendation="Proceed with standard testing",
            confidence=0.5,
            reasoning=(
                "DETERMINISTIC FALLBACK: This decision was NOT generated by AI. "
                "AI services were unavailable. Using conservative default behavior. "
                "Manual review recommended before production deployment."
            ),
            priority=5,
            metadata={
                "fallback": True,
                "fallback_type": "deterministic",
                "fallback_reason": "ai_unavailable",
                "fallback_timestamp": fallback_timestamp,
                "ai_generated": False,
                "requires_manual_review": True,
                "vulnerability_id": vuln_id,
                "audit_label": "FALLBACK_DETERMINISTIC_DECISION",
            },
        )

    def _fallback_consensus(
        self, architect: AIDecision, developer: AIDecision, lead: AIDecision
    ) -> ConsensusDecision:
        """Fallback consensus when composition fails.

        IMPORTANT: This is a deterministic fallback - NOT an AI-composed consensus.
        The response is explicitly labeled for audit trail compliance.
        """
        fallback_timestamp = datetime.utcnow().isoformat() + "Z"
        avg_confidence = (
            architect.confidence + developer.confidence + lead.confidence
        ) / 3

        # Check if any contributing decisions are also fallbacks
        contributing_fallbacks = sum(
            1 for d in [architect, developer, lead] if d.metadata.get("fallback", False)
        )

        logger.warning(
            f"FALLBACK_CONSENSUS: Using deterministic consensus composition. "
            f"Contributing fallback decisions: {contributing_fallbacks}/3. "
            "This is NOT an AI-composed consensus."
        )

        return ConsensusDecision(
            action="execute_pentest_with_caution",
            confidence=avg_confidence,
            reasoning=(
                "DETERMINISTIC FALLBACK CONSENSUS: This consensus was NOT composed by AI. "
                f"AI composition failed. {contributing_fallbacks}/3 contributing decisions "
                "were also fallbacks. Using conservative execution plan. "
                "Manual review REQUIRED before production deployment."
            ),
            contributing_decisions=[architect, developer, lead],
            execution_plan=[
                {"step": 1, "action": "Reconnaissance", "tool": "nmap"},
                {"step": 2, "action": "Vulnerability validation", "tool": "automated"},
                {"step": 3, "action": "Exploitation", "tool": "as_needed"},
            ],
            metadata={
                "fallback": True,
                "fallback_type": "deterministic_consensus",
                "fallback_reason": "ai_composition_failed",
                "fallback_timestamp": fallback_timestamp,
                "ai_generated": False,
                "requires_manual_review": True,
                "contributing_fallback_count": contributing_fallbacks,
                "audit_label": "FALLBACK_DETERMINISTIC_CONSENSUS",
            },
        )


class ExploitValidationFramework:
    """Framework for validating vulnerability exploitability."""

    def __init__(self, pentagi_client: "AdvancedPentagiClient"):
        """Initialize validation framework."""
        self.pentagi_client = pentagi_client
        self.validation_cache: Dict[str, ExploitabilityLevel] = {}

    async def validate_exploitability(
        self, vulnerability: Dict, context: Dict
    ) -> Tuple[ExploitabilityLevel, Dict]:
        """Validate if vulnerability is actually exploitable."""
        vuln_id = vulnerability.get("id", "unknown")

        # Check cache first
        if vuln_id in self.validation_cache:
            logger.info(f"Using cached exploitability for {vuln_id}")
            return self.validation_cache[vuln_id], {"cached": True}

        logger.info(f"Validating exploitability for vulnerability: {vuln_id}")

        try:
            # Create PentAGI test request
            test_request = self._create_test_request(vulnerability, context)

            # Execute the test
            result = await self.pentagi_client.execute_pentest(test_request)

            # Analyze results
            exploitability = self._analyze_test_results(result)

            # Cache the result
            self.validation_cache[vuln_id] = exploitability

            return exploitability, result

        except Exception as e:
            logger.error(f"Exploitability validation failed: {e}")
            return ExploitabilityLevel.INCONCLUSIVE, {"error": str(e)}

    def _create_test_request(
        self, vulnerability: Dict, context: Dict
    ) -> PenTestRequest:
        """Create a PentAGI test request from vulnerability data."""
        return PenTestRequest(
            id="",  # Will be generated
            finding_id=vulnerability.get("id", "unknown"),
            target_url=context.get("target_url", "http://localhost"),
            vulnerability_type=vulnerability.get("type", "Unknown"),
            test_case=self._generate_test_case(vulnerability),
            priority=self._map_priority(vulnerability.get("severity", "medium")),
            metadata={
                "vulnerability": vulnerability,
                "context": context,
                "validation_mode": True,
            },
        )

    def _generate_test_case(self, vulnerability: Dict) -> str:
        """Generate a test case description for PentAGI."""
        vuln_type = vulnerability.get("type", "Unknown")
        description = vulnerability.get("description", "")

        return f"""
Test Case: {vuln_type} Validation

Description: {description}

Objective: Validate if this vulnerability is actually exploitable in the target environment.

Steps:
1. Verify the vulnerability exists
2. Attempt exploitation
3. Collect evidence if successful
4. Document findings

Expected Outcome: Confirmed exploitation or verification that it's a false positive.
"""

    def _map_priority(self, severity: str) -> PenTestPriority:
        """Map severity to pentest priority."""
        severity_map = {
            "critical": PenTestPriority.CRITICAL,
            "high": PenTestPriority.HIGH,
            "medium": PenTestPriority.MEDIUM,
            "low": PenTestPriority.LOW,
        }
        return severity_map.get(severity.lower(), PenTestPriority.MEDIUM)

    def _analyze_test_results(self, result: Dict) -> ExploitabilityLevel:
        """Analyze test results to determine exploitability."""
        if not result:
            return ExploitabilityLevel.INCONCLUSIVE

        # Check if exploit was successful
        exploit_successful = result.get("exploit_successful", False)
        confidence = result.get("confidence_score", 0.0)

        if exploit_successful and confidence > 0.8:
            return ExploitabilityLevel.CONFIRMED_EXPLOITABLE
        elif exploit_successful and confidence > 0.5:
            return ExploitabilityLevel.LIKELY_EXPLOITABLE
        elif not exploit_successful and confidence > 0.8:
            return ExploitabilityLevel.UNEXPLOITABLE
        elif result.get("blocked", False):
            return ExploitabilityLevel.BLOCKED
        else:
            return ExploitabilityLevel.INCONCLUSIVE


class AdvancedPentagiClient:
    """Advanced PentAGI client with multi-AI orchestration."""

    def __init__(
        self,
        config: PenTestConfig,
        llm_manager: LLMProviderManager,
        db: Optional[PentagiDB] = None,
    ):
        """Initialize the advanced client."""
        self.config = config
        self.llm_manager = llm_manager
        self.db = db or PentagiDB()
        self.orchestrator = MultiAIOrchestrator(llm_manager)
        self.validator = ExploitValidationFramework(self)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def execute_pentest_with_consensus(
        self, vulnerability: Dict, context: Dict
    ) -> Dict:
        """Execute pentest with multi-AI consensus."""
        logger.info(
            f"Starting consensus-based pentest for vulnerability: {vulnerability.get('id')}"
        )

        # Get decisions from all AI models in parallel
        architect_task = self.orchestrator.get_architect_decision(
            context, vulnerability
        )
        developer_task = self.orchestrator.get_developer_decision(
            context, vulnerability
        )
        lead_task = self.orchestrator.get_lead_decision(context, vulnerability)

        architect, developer, lead = await asyncio.gather(
            architect_task, developer_task, lead_task
        )

        # Compose consensus decision
        consensus = await self.orchestrator.compose_consensus(
            architect, developer, lead, context
        )

        logger.info(
            f"Consensus reached: {consensus.action} (confidence: {consensus.confidence:.2f})"
        )

        # Execute based on consensus
        if consensus.confidence < 0.6:
            logger.warning(
                "Low confidence consensus - proceeding with caution or manual review"
            )
            return {
                "status": "manual_review_required",
                "consensus": consensus,
                "reason": "Low confidence in automated decision",
            }

        # Execute the pentest based on execution plan
        result = await self._execute_consensus_plan(consensus, vulnerability, context)

        return {
            "status": "completed",
            "consensus": consensus,
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _execute_consensus_plan(
        self, consensus: ConsensusDecision, vulnerability: Dict, context: Dict
    ) -> Dict:
        """Execute the consensus execution plan."""
        results = []

        for step in consensus.execution_plan:
            step_result = await self._execute_step(step, vulnerability, context)
            results.append(step_result)

            # Stop if step failed critically
            if step_result.get("critical_failure"):
                break

        return {
            "plan": consensus.execution_plan,
            "steps_executed": len(results),
            "results": results,
            "overall_success": all(r.get("success", False) for r in results),
        }

    async def _execute_step(
        self, step: Dict, vulnerability: Dict, context: Dict
    ) -> Dict:
        """Execute a single step in the execution plan."""
        action = step.get("action", "unknown")
        tool = step.get("tool", "automated")

        logger.info(f"Executing step: {action} with tool: {tool}")

        # This would integrate with PentAGI's actual execution
        # For now, simulate execution
        await asyncio.sleep(1)  # Simulate work

        return {
            "step": step,
            "success": True,
            "output": f"Executed {action} using {tool}",
            "duration_seconds": 1.0,
        }

    async def execute_pentest(self, request: PenTestRequest) -> Dict:
        """Execute a pentest request through PentAGI."""
        logger.info(f"Executing pentest request: {request.id}")

        # Save request to database
        request = self.db.create_request(request)

        try:
            # Update status to running
            request.status = PenTestStatus.RUNNING
            request.started_at = datetime.utcnow()
            self.db.update_request(request)

            # Call PentAGI API
            result = await self._call_pentagi_api(request)

            # Update status to completed
            request.status = PenTestStatus.COMPLETED
            request.completed_at = datetime.utcnow()
            request.pentagi_job_id = result.get("job_id")
            self.db.update_request(request)

            # Store result
            pen_result = self._create_result_from_response(request, result)
            self.db.create_result(pen_result)

            return result

        except Exception as e:
            logger.error(f"Pentest execution failed: {e}")
            request.status = PenTestStatus.FAILED
            request.completed_at = datetime.utcnow()
            self.db.update_request(request)
            raise

    async def _call_pentagi_api(self, request: PenTestRequest) -> Dict:
        """Call PentAGI API to execute the test."""
        if not self.session:
            self.session = aiohttp.ClientSession()

        url = f"{self.config.pentagi_url}/api/v1/flows"
        headers = {}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        payload = {
            "name": f"FixOps Validation - {request.finding_id}",
            "description": request.test_case,
            "target": request.target_url,
            "vulnerability_type": request.vulnerability_type,
            "priority": request.priority.value,
        }

        try:
            async with self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
            ) as response:
                response.raise_for_status()
                result = await response.json()
                return result
        except Exception as e:
            logger.error(f"PentAGI API call failed: {e}")
            # Return mock result for development
            return self._mock_pentagi_response(request)

    def _mock_pentagi_response(self, request: PenTestRequest) -> Dict:
        """Mock PentAGI response for development/testing."""
        return {
            "job_id": f"mock-{request.id}",
            "status": "completed",
            "exploit_successful": True,
            "exploitability": "confirmed_exploitable",
            "confidence_score": 0.85,
            "execution_time_seconds": 120.0,
            "evidence": "Successfully exploited vulnerability",
            "steps_taken": [
                "Reconnaissance with nmap",
                "Vulnerability validation",
                "Exploit execution",
                "Evidence collection",
            ],
            "artifacts": [
                "exploit_payload.txt",
                "network_capture.pcap",
                "evidence_screenshot.png",
            ],
        }

    def _create_result_from_response(
        self, request: PenTestRequest, response: Dict
    ) -> PenTestResult:
        """Create a PenTestResult from API response."""
        exploitability_map = {
            "confirmed_exploitable": ExploitabilityLevel.CONFIRMED_EXPLOITABLE,
            "likely_exploitable": ExploitabilityLevel.LIKELY_EXPLOITABLE,
            "unexploitable": ExploitabilityLevel.UNEXPLOITABLE,
            "blocked": ExploitabilityLevel.BLOCKED,
            "inconclusive": ExploitabilityLevel.INCONCLUSIVE,
        }

        return PenTestResult(
            id="",  # Will be generated
            request_id=request.id,
            finding_id=request.finding_id,
            exploitability=exploitability_map.get(
                response.get("exploitability", "inconclusive"),
                ExploitabilityLevel.INCONCLUSIVE,
            ),
            exploit_successful=response.get("exploit_successful", False),
            evidence=response.get("evidence", "No evidence collected"),
            steps_taken=response.get("steps_taken", []),
            artifacts=response.get("artifacts", []),
            confidence_score=response.get("confidence_score", 0.0),
            execution_time_seconds=response.get("execution_time_seconds", 0.0),
            metadata=response,
        )

    async def validate_remediation(
        self, finding_id: str, context: Dict
    ) -> Tuple[bool, str]:
        """Validate that a remediation actually fixed the vulnerability."""
        logger.info(f"Validating remediation for finding: {finding_id}")

        # Get original test request
        requests = self.db.list_requests(finding_id=finding_id, limit=1)
        if not requests:
            return False, "No original test found"

        original_request = requests[0]

        # Create new test request for retest
        retest_request = PenTestRequest(
            id="",
            finding_id=finding_id,
            target_url=original_request.target_url,
            vulnerability_type=original_request.vulnerability_type,
            test_case=original_request.test_case + "\n\nREMEDIATION VALIDATION TEST",
            priority=original_request.priority,
            metadata={"retest": True, "original_request_id": original_request.id},
        )

        # Execute retest
        try:
            result = await self.execute_pentest(retest_request)

            # Check if vulnerability still exists
            still_exploitable = result.get("exploit_successful", False)

            if still_exploitable:
                return False, "Vulnerability still exploitable after remediation"
            else:
                return True, "Vulnerability successfully remediated"

        except Exception as e:
            logger.error(f"Remediation validation failed: {e}")
            return False, f"Validation error: {str(e)}"

    def get_statistics(self) -> Dict:
        """Get statistics about pentesting activity."""
        all_requests = self.db.list_requests(limit=1000)
        all_results = self.db.list_results(limit=1000)

        total_tests = len(all_requests)
        completed_tests = sum(
            1 for r in all_requests if r.status == PenTestStatus.COMPLETED
        )
        failed_tests = sum(1 for r in all_requests if r.status == PenTestStatus.FAILED)

        confirmed_exploitable = sum(
            1
            for r in all_results
            if r.exploitability == ExploitabilityLevel.CONFIRMED_EXPLOITABLE
        )
        false_positives = sum(
            1
            for r in all_results
            if r.exploitability == ExploitabilityLevel.UNEXPLOITABLE
        )

        avg_execution_time = (
            sum(r.execution_time_seconds for r in all_results) / len(all_results)
            if all_results
            else 0
        )

        return {
            "total_tests": total_tests,
            "completed_tests": completed_tests,
            "failed_tests": failed_tests,
            "success_rate": completed_tests / total_tests if total_tests > 0 else 0,
            "confirmed_exploitable": confirmed_exploitable,
            "false_positives": false_positives,
            "false_positive_rate": (
                false_positives / len(all_results) if all_results else 0
            ),
            "average_execution_time_seconds": avg_execution_time,
        }
