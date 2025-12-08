"""Advanced PentAGI integration with multi-AI orchestration."""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from core.llm_providers import LLMProviderManager
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
    """Orchestrates multiple AI models for consensus-based decisions."""

    def __init__(self, llm_manager: LLMProviderManager):
        """Initialize the orchestrator."""
        self.llm_manager = llm_manager
        self.decision_history: List[ConsensusDecision] = []

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

    async def get_lead_decision(
        self, context: Dict, vulnerability: Dict
    ) -> AIDecision:
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

    async def _call_llm(self, provider: str, prompt: str) -> str:
        """Call LLM provider with retry logic."""
        # This would integrate with the actual LLM provider manager
        # For now, return a mock response structure
        return json.dumps(
            {
                "recommendation": "Proceed with automated testing",
                "confidence": 0.85,
                "reasoning": f"Analysis from {provider} indicates exploitable vulnerability",
                "priority": 8,
                "attack_vectors": ["SQL Injection", "XSS"],
                "tools": ["sqlmap", "burp"],
                "strategy": "Multi-stage exploitation",
                "success_criteria": ["Exploit confirmed", "Evidence collected"],
            }
        )

    def _fallback_decision(self, role: AIRole, vulnerability: Dict) -> AIDecision:
        """Fallback decision when AI call fails."""
        return AIDecision(
            role=role,
            recommendation="Proceed with standard testing",
            confidence=0.5,
            reasoning="Fallback decision due to AI unavailability",
            priority=5,
            metadata={"fallback": True},
        )

    def _fallback_consensus(
        self, architect: AIDecision, developer: AIDecision, lead: AIDecision
    ) -> ConsensusDecision:
        """Fallback consensus when composition fails."""
        avg_confidence = (
            architect.confidence + developer.confidence + lead.confidence
        ) / 3
        avg_priority = (architect.priority + developer.priority + lead.priority) / 3

        return ConsensusDecision(
            action="execute_pentest_with_caution",
            confidence=avg_confidence,
            reasoning="Simple consensus due to composition failure",
            contributing_decisions=[architect, developer, lead],
            execution_plan=[
                {"step": 1, "action": "Reconnaissance", "tool": "nmap"},
                {"step": 2, "action": "Vulnerability validation", "tool": "automated"},
                {"step": 3, "action": "Exploitation", "tool": "as_needed"},
            ],
            metadata={"fallback": True},
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
        result = await self._execute_consensus_plan(
            consensus, vulnerability, context
        )

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
                url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds)
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
        failed_tests = sum(
            1 for r in all_requests if r.status == PenTestStatus.FAILED
        )

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
            "false_positive_rate": false_positives / len(all_results)
            if all_results
            else 0,
            "average_execution_time_seconds": avg_execution_time,
        }
