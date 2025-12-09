"""Automated remediation suggestion and verification system."""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List

from core.llm_providers import LLMProviderManager
from core.pentagi_advanced import AdvancedPentagiClient

logger = logging.getLogger(__name__)


class RemediationType(Enum):
    """Types of remediation actions."""

    CODE_PATCH = "code_patch"
    CONFIGURATION_CHANGE = "configuration_change"
    DEPENDENCY_UPDATE = "dependency_update"
    WAF_RULE = "waf_rule"
    NETWORK_CONTROL = "network_control"
    ACCESS_CONTROL = "access_control"
    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"


class RemediationPriority(Enum):
    """Priority levels for remediation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationStatus(Enum):
    """Status of remediation."""

    SUGGESTED = "suggested"
    IN_PROGRESS = "in_progress"
    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"
    REJECTED = "rejected"


@dataclass
class RemediationSuggestion:
    """Remediation suggestion from AI."""

    id: str
    finding_id: str
    remediation_type: RemediationType
    priority: RemediationPriority
    title: str
    description: str
    code_changes: List[Dict] = field(default_factory=list)
    config_changes: List[Dict] = field(default_factory=list)
    testing_guidance: str = ""
    risk_assessment: str = ""
    effort_estimate: str = ""
    success_probability: float = 0.8
    ai_confidence: float = 0.0
    status: RemediationStatus = RemediationStatus.SUGGESTED
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "remediation_type": self.remediation_type.value,
            "priority": self.priority.value,
            "title": self.title,
            "description": self.description,
            "code_changes": self.code_changes,
            "config_changes": self.config_changes,
            "testing_guidance": self.testing_guidance,
            "risk_assessment": self.risk_assessment,
            "effort_estimate": self.effort_estimate,
            "success_probability": self.success_probability,
            "ai_confidence": self.ai_confidence,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class RemediationVerification:
    """Verification result for a remediation."""

    id: str
    suggestion_id: str
    finding_id: str
    verified: bool
    still_exploitable: bool
    verification_evidence: str
    regression_detected: bool
    regression_details: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    verification_time_seconds: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "suggestion_id": self.suggestion_id,
            "finding_id": self.finding_id,
            "verified": self.verified,
            "still_exploitable": self.still_exploitable,
            "verification_evidence": self.verification_evidence,
            "regression_detected": self.regression_detected,
            "regression_details": self.regression_details,
            "confidence_score": self.confidence_score,
            "verification_time_seconds": self.verification_time_seconds,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }


class AutomatedRemediationEngine:
    """Engine for automated remediation suggestions and verification."""

    def __init__(
        self, llm_manager: LLMProviderManager, pentagi_client: AdvancedPentagiClient
    ):
        """Initialize the remediation engine."""
        self.llm_manager = llm_manager
        self.pentagi_client = pentagi_client
        self.suggestions: Dict[str, RemediationSuggestion] = {}
        self.verifications: Dict[str, RemediationVerification] = {}

    async def generate_remediation_suggestions(
        self, finding: Dict, context: Dict
    ) -> List[RemediationSuggestion]:
        """Generate multiple remediation suggestions for a finding."""
        logger.info(
            f"Generating remediation suggestions for finding: {finding.get('id')}"
        )

        # Get suggestions from multiple AI models
        architect_task = self._get_architect_remediation(finding, context)
        developer_task = self._get_developer_remediation(finding, context)
        lead_task = self._get_lead_remediation(finding, context)

        (
            architect_suggestions,
            developer_suggestions,
            lead_suggestions,
        ) = await asyncio.gather(architect_task, developer_task, lead_task)

        # Combine and deduplicate suggestions
        all_suggestions = (
            architect_suggestions + developer_suggestions + lead_suggestions
        )

        # Rank by AI consensus
        ranked_suggestions = self._rank_suggestions(all_suggestions)

        # Store suggestions
        for suggestion in ranked_suggestions:
            self.suggestions[suggestion.id] = suggestion

        return ranked_suggestions

    async def _get_architect_remediation(
        self, finding: Dict, context: Dict
    ) -> List[RemediationSuggestion]:
        """Get strategic remediation from Gemini (architect)."""
        prompt = f"""You are a Senior Security Architect providing strategic remediation guidance.

Finding:
{json.dumps(finding, indent=2)}

Context:
{json.dumps(context, indent=2)}

Provide strategic remediation recommendations:
1. High-level architecture changes
2. Security control improvements
3. Defense-in-depth strategies
4. Long-term security improvements

For each recommendation, provide:
- Title (brief)
- Description (detailed)
- Type (code_patch, configuration_change, etc.)
- Priority (critical, high, medium, low)
- Risk assessment
- Effort estimate (hours)

Respond in JSON format with key "suggestions" containing an array of remediation objects.
"""

        try:
            response = await self._call_llm("gemini", prompt)
            result = json.loads(response)
            suggestions = result.get("suggestions", [])

            return [
                self._create_suggestion(s, finding, "architect") for s in suggestions
            ]
        except Exception as e:
            logger.error(f"Architect remediation failed: {e}")
            return []

    async def _get_developer_remediation(
        self, finding: Dict, context: Dict
    ) -> List[RemediationSuggestion]:
        """Get tactical remediation from Claude (developer)."""
        prompt = f"""You are a Senior Security Developer providing tactical remediation code.

Finding:
{json.dumps(finding, indent=2)}

Context:
{json.dumps(context, indent=2)}

Provide specific code-level remediations:
1. Exact code changes needed
2. Before/after code examples
3. Input validation improvements
4. Output encoding fixes

For each remediation, provide:
- Title (brief)
- Description (detailed)
- Code changes (file, line, old_code, new_code)
- Testing guidance
- Type (code_patch, input_validation, etc.)
- Priority (critical, high, medium, low)

Respond in JSON format with key "suggestions" containing an array of remediation objects.
"""

        try:
            response = await self._call_llm("anthropic", prompt)
            result = json.loads(response)
            suggestions = result.get("suggestions", [])

            return [
                self._create_suggestion(s, finding, "developer") for s in suggestions
            ]
        except Exception as e:
            logger.error(f"Developer remediation failed: {e}")
            return []

    async def _get_lead_remediation(
        self, finding: Dict, context: Dict
    ) -> List[RemediationSuggestion]:
        """Get best practices remediation from GPT-4 (lead)."""
        prompt = f"""You are a Security Team Lead reviewing remediation quality and best practices.

Finding:
{json.dumps(finding, indent=2)}

Context:
{json.dumps(context, indent=2)}

Provide remediation recommendations based on best practices:
1. Industry standard approaches
2. Framework-specific fixes
3. Security patterns and anti-patterns
4. Configuration hardening

For each recommendation, provide:
- Title (brief)
- Description (detailed)
- Configuration changes (if applicable)
- Type (configuration_change, waf_rule, etc.)
- Priority (critical, high, medium, low)
- Success probability (0.0-1.0)

Respond in JSON format with key "suggestions" containing an array of remediation objects.
"""

        try:
            response = await self._call_llm("openai", prompt)
            result = json.loads(response)
            suggestions = result.get("suggestions", [])

            return [self._create_suggestion(s, finding, "lead") for s in suggestions]
        except Exception as e:
            logger.error(f"Lead remediation failed: {e}")
            return []

    def _create_suggestion(
        self, data: Dict, finding: Dict, source: str
    ) -> RemediationSuggestion:
        """Create a RemediationSuggestion from AI response."""
        import hashlib

        suggestion_id = hashlib.sha256(
            f"{finding.get('id')}-{data.get('title')}-{source}".encode()
        ).hexdigest()[:16]

        type_map = {
            "code_patch": RemediationType.CODE_PATCH,
            "configuration_change": RemediationType.CONFIGURATION_CHANGE,
            "dependency_update": RemediationType.DEPENDENCY_UPDATE,
            "waf_rule": RemediationType.WAF_RULE,
            "network_control": RemediationType.NETWORK_CONTROL,
            "access_control": RemediationType.ACCESS_CONTROL,
            "input_validation": RemediationType.INPUT_VALIDATION,
            "output_encoding": RemediationType.OUTPUT_ENCODING,
        }

        priority_map = {
            "critical": RemediationPriority.CRITICAL,
            "high": RemediationPriority.HIGH,
            "medium": RemediationPriority.MEDIUM,
            "low": RemediationPriority.LOW,
        }

        return RemediationSuggestion(
            id=suggestion_id,
            finding_id=finding.get("id", "unknown"),
            remediation_type=type_map.get(
                data.get("type", "code_patch").lower(), RemediationType.CODE_PATCH
            ),
            priority=priority_map.get(
                data.get("priority", "medium").lower(), RemediationPriority.MEDIUM
            ),
            title=data.get("title", "Untitled remediation"),
            description=data.get("description", ""),
            code_changes=data.get("code_changes", []),
            config_changes=data.get("config_changes", []),
            testing_guidance=data.get("testing_guidance", ""),
            risk_assessment=data.get("risk_assessment", ""),
            effort_estimate=data.get("effort_estimate", "Unknown"),
            success_probability=data.get("success_probability", 0.8),
            ai_confidence=data.get("confidence", 0.7),
            metadata={"source": source, "raw_data": data},
        )

    def _rank_suggestions(
        self, suggestions: List[RemediationSuggestion]
    ) -> List[RemediationSuggestion]:
        """Rank suggestions by priority, confidence, and success probability."""
        priority_scores = {
            RemediationPriority.CRITICAL: 4,
            RemediationPriority.HIGH: 3,
            RemediationPriority.MEDIUM: 2,
            RemediationPriority.LOW: 1,
        }

        # Calculate composite score for each suggestion
        scored_suggestions = []
        for suggestion in suggestions:
            score = (
                priority_scores[suggestion.priority] * 3  # Weight priority heavily
                + suggestion.ai_confidence * 2  # Weight confidence
                + suggestion.success_probability * 1  # Weight success probability
            )
            scored_suggestions.append((score, suggestion))

        # Sort by score (highest first)
        scored_suggestions.sort(key=lambda x: x[0], reverse=True)

        return [s[1] for s in scored_suggestions]

    async def verify_remediation(
        self, suggestion: RemediationSuggestion, context: Dict
    ) -> RemediationVerification:
        """Verify that a remediation was effective."""
        logger.info(f"Verifying remediation: {suggestion.id}")

        start_time = datetime.utcnow()

        try:
            # Use PentAGI to retest the vulnerability
            verified, evidence = await self.pentagi_client.validate_remediation(
                suggestion.finding_id, context
            )

            # Check for regressions
            regressions = await self._check_for_regressions(suggestion, context)

            execution_time = (datetime.utcnow() - start_time).total_seconds()

            verification = RemediationVerification(
                id=self._generate_verification_id(),
                suggestion_id=suggestion.id,
                finding_id=suggestion.finding_id,
                verified=verified,
                still_exploitable=not verified,
                verification_evidence=evidence,
                regression_detected=len(regressions) > 0,
                regression_details=regressions,
                confidence_score=0.9 if verified else 0.5,
                verification_time_seconds=execution_time,
                metadata={"context": context},
            )

            self.verifications[verification.id] = verification

            # Update suggestion status
            if verified and not regressions:
                suggestion.status = RemediationStatus.VERIFIED
            elif not verified:
                suggestion.status = RemediationStatus.FAILED
            else:
                suggestion.status = RemediationStatus.APPLIED

            return verification

        except Exception as e:
            logger.error(f"Remediation verification failed: {e}")
            return self._failed_verification(suggestion, str(e))

    async def _check_for_regressions(
        self, suggestion: RemediationSuggestion, context: Dict
    ) -> List[str]:
        """Check if remediation introduced regressions."""
        regressions = []

        # Use GPT-4 to analyze potential regressions
        prompt = f"""You are a security expert analyzing potential regressions from a security fix.

Remediation Applied:
{json.dumps(suggestion.to_dict(), indent=2)}

Context:
{json.dumps(context, indent=2)}

Analyze if this remediation could have introduced:
1. New security vulnerabilities
2. Broken functionality
3. Performance issues
4. Compatibility problems

Respond in JSON format with key "regressions" containing an array of regression descriptions.
If no regressions are likely, return empty array.
"""

        try:
            response = await self._call_llm("openai", prompt)
            result = json.loads(response)
            regressions = result.get("regressions", [])
        except Exception as e:
            logger.error(f"Regression check failed: {e}")

        return regressions

    async def generate_remediation_plan(
        self, findings: List[Dict], context: Dict
    ) -> Dict:
        """Generate a comprehensive remediation plan for multiple findings."""
        logger.info(f"Generating remediation plan for {len(findings)} findings")

        # Generate suggestions for all findings
        all_suggestions = []
        for finding in findings:
            suggestions = await self.generate_remediation_suggestions(finding, context)
            all_suggestions.extend(suggestions)

        # Group by priority
        by_priority = {
            RemediationPriority.CRITICAL: [],
            RemediationPriority.HIGH: [],
            RemediationPriority.MEDIUM: [],
            RemediationPriority.LOW: [],
        }

        for suggestion in all_suggestions:
            by_priority[suggestion.priority].append(suggestion)

        # Generate execution timeline
        timeline = self._generate_timeline(by_priority)

        plan = {
            "total_findings": len(findings),
            "total_suggestions": len(all_suggestions),
            "by_priority": {
                "critical": len(by_priority[RemediationPriority.CRITICAL]),
                "high": len(by_priority[RemediationPriority.HIGH]),
                "medium": len(by_priority[RemediationPriority.MEDIUM]),
                "low": len(by_priority[RemediationPriority.LOW]),
            },
            "suggestions": [s.to_dict() for s in all_suggestions],
            "timeline": timeline,
            "estimated_total_effort": self._calculate_total_effort(all_suggestions),
        }

        return plan

    def _generate_timeline(
        self, by_priority: Dict[RemediationPriority, List[RemediationSuggestion]]
    ) -> List[Dict]:
        """Generate an execution timeline for remediations."""
        timeline = []
        week = 1

        # Critical - immediate (week 1)
        if by_priority[RemediationPriority.CRITICAL]:
            timeline.append(
                {
                    "week": week,
                    "priority": "critical",
                    "items": len(by_priority[RemediationPriority.CRITICAL]),
                    "suggestions": [
                        s.id for s in by_priority[RemediationPriority.CRITICAL]
                    ],
                }
            )
            week += 1

        # High - weeks 2-3
        if by_priority[RemediationPriority.HIGH]:
            timeline.append(
                {
                    "week": week,
                    "priority": "high",
                    "items": len(by_priority[RemediationPriority.HIGH]),
                    "suggestions": [
                        s.id for s in by_priority[RemediationPriority.HIGH]
                    ],
                }
            )
            week += 2

        # Medium - weeks 4-6
        if by_priority[RemediationPriority.MEDIUM]:
            timeline.append(
                {
                    "week": week,
                    "priority": "medium",
                    "items": len(by_priority[RemediationPriority.MEDIUM]),
                    "suggestions": [
                        s.id for s in by_priority[RemediationPriority.MEDIUM]
                    ],
                }
            )
            week += 3

        # Low - weeks 7+
        if by_priority[RemediationPriority.LOW]:
            timeline.append(
                {
                    "week": week,
                    "priority": "low",
                    "items": len(by_priority[RemediationPriority.LOW]),
                    "suggestions": [s.id for s in by_priority[RemediationPriority.LOW]],
                }
            )

        return timeline

    def _calculate_total_effort(self, suggestions: List[RemediationSuggestion]) -> str:
        """Calculate total effort estimate."""
        total_hours = 0

        for suggestion in suggestions:
            # Parse effort estimate (e.g., "2-4 hours", "1 day")
            estimate = suggestion.effort_estimate.lower()

            if "hour" in estimate:
                # Extract numbers
                import re

                numbers = re.findall(r"\d+", estimate)
                if numbers:
                    # Use average if range
                    total_hours += sum(int(n) for n in numbers) / len(numbers)
            elif "day" in estimate:
                import re

                numbers = re.findall(r"\d+", estimate)
                if numbers:
                    # 8 hours per day
                    total_hours += sum(int(n) for n in numbers) / len(numbers) * 8
            else:
                # Unknown - assume 4 hours
                total_hours += 4

        days = total_hours / 8
        weeks = days / 5

        if weeks >= 1:
            return f"{weeks:.1f} weeks ({total_hours:.0f} hours)"
        elif days >= 1:
            return f"{days:.1f} days ({total_hours:.0f} hours)"
        else:
            return f"{total_hours:.0f} hours"

    async def _call_llm(self, provider: str, prompt: str) -> str:
        """Call LLM provider."""
        # Mock response for now
        import json

        if "regression" in prompt.lower():
            return json.dumps({"regressions": []})
        else:
            return json.dumps(
                {
                    "suggestions": [
                        {
                            "title": "Input validation enhancement",
                            "description": "Add comprehensive input validation",
                            "type": "code_patch",
                            "priority": "high",
                            "code_changes": [
                                {
                                    "file": "app.py",
                                    "line": 42,
                                    "old_code": "query = request.args.get('q')",
                                    "new_code": "query = sanitize_input(request.args.get('q'))",
                                }
                            ],
                            "testing_guidance": "Test with SQL injection payloads",
                            "risk_assessment": "Low risk change",
                            "effort_estimate": "2 hours",
                            "success_probability": 0.9,
                            "confidence": 0.85,
                        }
                    ]
                }
            )

    def _failed_verification(
        self, suggestion: RemediationSuggestion, error: str
    ) -> RemediationVerification:
        """Create a failed verification result."""
        return RemediationVerification(
            id=self._generate_verification_id(),
            suggestion_id=suggestion.id,
            finding_id=suggestion.finding_id,
            verified=False,
            still_exploitable=True,
            verification_evidence=f"Verification failed: {error}",
            regression_detected=False,
            regression_details=[],
            confidence_score=0.0,
            verification_time_seconds=0.0,
            metadata={"error": error},
        )

    def _generate_verification_id(self) -> str:
        """Generate a unique verification ID."""
        import uuid

        return f"ver-{uuid.uuid4().hex[:16]}"
