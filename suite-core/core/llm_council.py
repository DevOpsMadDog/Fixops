"""LLM Council Engine — Karpathy 3-stage decision synthesis.

Implements Andrej Karpathy's council pattern for LLM decision-making:
1. Independent Analysis — Each council member analyzes independently (no cross-talk)
2. Anonymous Peer Review — Members review others' analyses anonymously, can revise
3. Chairman Synthesis — Strongest model synthesizes into final verdict

The council composition uses cheap/free models (Qwen, DeepSeek, Gemma, Llama via
OpenRouter/Ollama/vLLM) plus optional Opus escalation for high-disagreement cases.

Usage:
    from core.llm_council import LLMCouncilEngine, CouncilMember
    from core.llm_providers import AnthropicMessagesProvider

    members = [
        CouncilMember(
            provider=QwenProvider("qwen"),
            expertise="vulnerability_assessment",
            weight=1.0,
        ),
        ...
    ]

    council = LLMCouncilEngine(members=members)
    verdict = council.convene(finding={"cve": "CVE-2024-1234"}, context={...})
    print(verdict.action)  # "remediate_critical", "accept_risk", etc
"""

from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)

from core.llm_providers import BaseLLMProvider, LLMResponse
# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises.

    Hub-level emit so this engine module participates in second-brain coverage.
    Downstream callers are AQUA via blast-radius (depth ≤ 2).
    """
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# Module-load heartbeat — fires once per process so this file is observable
# in the TrustGraph second-brain, even if no public method is called yet.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


__all__ = [
    "CouncilMember",
    "MemberAnalysis",
    "PositionChange",
    "MemberVote",
    "CouncilVerdict",
    "LLMCouncilEngine",
    "CouncilFactory",
]


@dataclass
class CouncilMember:
    """A council member with expertise focus and voting weight.

    Attributes:
        provider: BaseLLMProvider instance for this member
        expertise: Focus area (vulnerability_assessment, threat_modeling, compliance_mapping, code_analysis)
        weight: Voting weight in final synthesis (typically 1.0 for equal weight)
        name: Optional override name (defaults to provider.name)
    """

    provider: BaseLLMProvider
    expertise: str
    weight: float = 1.0
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.provider.name


@dataclass
class MemberAnalysis:
    """Output of a council member's analysis.

    Attributes:
        member_name: Name of the member who performed analysis
        expertise: Expertise focus
        stage: Which stage (1_independent, 2_review, 3_synthesis)
        position: Recommended action (remediate_critical, accept_risk, etc)
        confidence: Confidence in position (0-1)
        reasoning: Detailed reasoning chain
        mitre_mappings: MITRE ATT&CK techniques identified
        compliance_impact: Framework -> impact mapping
        metadata: Additional structured data (cost, latency, etc)
    """

    member_name: str
    expertise: str
    stage: str
    position: str
    confidence: float
    reasoning: str
    mitre_mappings: List[str] = field(default_factory=list)
    compliance_impact: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PositionChange:
    """Track position changes during peer review stage.

    Attributes:
        member_name: Who changed position
        original_position: Position before peer review
        new_position: Position after peer review
        reason: Why they changed (or empty if no change)
    """

    member_name: str
    original_position: str
    new_position: str
    reason: str = ""


@dataclass
class MemberVote:
    """A council member's vote on the final verdict.

    Attributes:
        member_name: Name of voter
        expertise: Expertise focus
        action: Voted action
        confidence: Confidence in vote
        weight: Voting weight
    """

    member_name: str
    expertise: str
    action: str
    confidence: float
    weight: float


@dataclass
class CouncilVerdict:
    """Final output from LLM Council.

    Attributes:
        action: Recommended action (remediate_critical, remediate_high, accept_risk, defer, investigate, false_positive)
        confidence: Overall confidence (0-1)
        reasoning: Chain-of-thought reasoning from chairman synthesis
        mitre_mappings: Aggregated MITRE techniques
        compliance_impact: Framework -> impact from all members
        member_votes: Individual member votes
        peer_review_changes: Position changes during stage 2
        escalated: Was decision escalated to Opus?
        escalation_reason: Why escalation occurred
        cost_usd: Total API cost (providers + Opus if escalated)
        latency_ms: Total wall-clock latency
        raw_analyses: Full MemberAnalysis objects from all stages (for debugging)
    """

    action: str
    confidence: float
    reasoning: str
    mitre_mappings: List[str] = field(default_factory=list)
    compliance_impact: Dict[str, str] = field(default_factory=dict)
    member_votes: List[MemberVote] = field(default_factory=list)
    peer_review_changes: List[PositionChange] = field(default_factory=list)
    escalated: bool = False
    escalation_reason: Optional[str] = None
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    raw_analyses: List[MemberAnalysis] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dict."""
        return {
            "action": self.action,
            "confidence": round(self.confidence, 3),
            "reasoning": self.reasoning,
            "mitre_mappings": self.mitre_mappings,
            "compliance_impact": self.compliance_impact,
            "member_votes": [
                {
                    "member": v.member_name,
                    "expertise": v.expertise,
                    "action": v.action,
                    "confidence": round(v.confidence, 3),
                    "weight": round(v.weight, 3),
                }
                for v in self.member_votes
            ],
            "peer_review_changes": [
                {
                    "member": c.member_name,
                    "original": c.original_position,
                    "new": c.new_position,
                    "reason": c.reason,
                }
                for c in self.peer_review_changes
            ],
            "escalated": self.escalated,
            "escalation_reason": self.escalation_reason,
            "cost_usd": round(self.cost_usd, 6),
            "latency_ms": round(self.latency_ms, 2),
        }


class LLMCouncilEngine:
    """Karpathy 3-stage council for security decision-making.

    Stage 1 — Independent Analysis:
        Each council member analyzes the finding independently.
        No member sees other members' responses.

    Stage 2 — Anonymous Peer Review:
        Each member reviews OTHER members' analyses (anonymized).
        Members can update their position based on peer input.
        Tracks position changes for transparency.

    Stage 3 — Chairman Synthesis:
        A designated chairman (strongest model) synthesizes all analyses
        into a final verdict with confidence score and reasoning chain.

    Optional Escalation:
        If verdict confidence < 0.7 or disagreement > 2 members,
        escalate to Claude Opus for final decision.
    """

    def __init__(
        self,
        members: Sequence[CouncilMember],
        *,
        chairman: Optional[BaseLLMProvider] = None,
        escalation_provider: Optional[BaseLLMProvider] = None,
        confidence_threshold: float = 0.7,
        max_disagreement: int = 2,
        max_workers: int = 4,
    ) -> None:
        """Initialize council engine.

        Args:
            members: Sequence of CouncilMember instances
            chairman: Provider for stage 3 synthesis (default: strongest available)
            escalation_provider: Provider for escalation (default: Claude Opus if available)
            confidence_threshold: Escalate if verdict confidence below this
            max_disagreement: Escalate if more than N members disagree
            max_workers: Thread pool size for parallel analysis
        """
        self.members = list(members)
        self.chairman = chairman
        self.escalation_provider = escalation_provider
        self.confidence_threshold = confidence_threshold
        self.max_disagreement = max_disagreement
        self.max_workers = max_workers
        self._history: List[CouncilVerdict] = []

        if not self.members:
            raise ValueError("Council requires at least one member")

    def convene(
        self,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> CouncilVerdict:
        """Convene the council to analyze a security finding.

        Executes all 3 stages (or escalates if needed).

        Args:
            finding: Security finding dict (title, severity, cve_id, etc)
            context: Contextual data (service_name, risk_score, etc)

        Returns:
            CouncilVerdict with final action and reasoning.
        """
        wall_start = time.perf_counter()

        # Stage 1: Independent Analysis
        stage1_analyses = self._stage_independent_analysis(finding, context)

        # Stage 2: Peer Review
        stage2_analyses = self._stage_peer_review(stage1_analyses, finding, context)

        # Stage 3: Chairman Synthesis
        verdict = self._stage_chairman_synthesis(
            stage1_analyses, stage2_analyses, finding, context
        )

        # Check if escalation needed
        if self.should_escalate(verdict):
            verdict = self._escalate_to_cto(finding, context, verdict)
            verdict.escalated = True

        verdict.latency_ms = (time.perf_counter() - wall_start) * 1000
        self._history.append(verdict)

        logger.info(
            "Council verdict: action=%s, confidence=%.2f, escalated=%s, latency=%.0fms",
            verdict.action,
            verdict.confidence,
            verdict.escalated,
            verdict.latency_ms,
        )

        return verdict

    def _stage_independent_analysis(
        self,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> List[MemberAnalysis]:
        """Stage 1: Each member analyzes independently.

        Returns:
            List of MemberAnalysis from each member.
        """
        logger.debug("Council Stage 1: Independent Analysis (%d members)", len(self.members))

        prompt = self._build_analysis_prompt(finding, context)

        analyses: List[MemberAnalysis] = []
        errors: Dict[str, str] = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {}
            for member in self.members:
                future = pool.submit(
                    self._query_member,
                    member,
                    prompt,
                    finding,
                    context,
                    stage="1_independent",
                )
                futures[future] = member

            for future in as_completed(futures):
                member = futures[future]
                try:
                    analysis = future.result()
                    analyses.append(analysis)
                except (OSError, ValueError, KeyError, RuntimeError) as exc:
                    logger.warning(
                        "Member %s failed in stage 1: %s",
                        member.name,
                        exc,
                    )
                    errors[member.name] = str(exc)

        if not analyses:
            raise RuntimeError("All council members failed in stage 1 analysis")

        return analyses

    def _stage_peer_review(
        self,
        analyses: List[MemberAnalysis],
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> List[MemberAnalysis]:
        """Stage 2: Members review others' analyses anonymously.

        Each member sees a summary of other members' positions and reasoning,
        but not their identities (anonymous). Members can revise their position.

        Returns:
            Updated MemberAnalysis list from stage 2 (with position changes tracked).
        """
        logger.debug("Council Stage 2: Peer Review (%d members)", len(self.members))

        # Build anonymous summary of other analyses
        anonymous_summary = self._build_peer_summary(analyses)

        updated_analyses: List[MemberAnalysis] = []
        position_changes: Dict[str, PositionChange] = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {}
            for member, original_analysis in zip(self.members, analyses):
                future = pool.submit(
                    self._query_member_review,
                    member,
                    original_analysis,
                    anonymous_summary,
                    finding,
                    context,
                )
                futures[future] = (member, original_analysis)

            for future in as_completed(futures):
                member, original = futures[future]
                try:
                    updated = future.result()
                    updated_analyses.append(updated)

                    # Track position changes
                    if updated.position != original.position:
                        position_changes[member.name] = PositionChange(
                            member_name=member.name,
                            original_position=original.position,
                            new_position=updated.position,
                            reason=f"Peer review: {updated.reasoning[:100]}",
                        )

                except (OSError, ValueError, KeyError, RuntimeError) as exc:
                    logger.warning(
                        "Member %s failed in stage 2 review: %s",
                        member.name,
                        exc,
                    )
                    # Fall back to original analysis if review fails
                    updated_analyses.append(original)

        return updated_analyses

    def _stage_chairman_synthesis(
        self,
        stage1: List[MemberAnalysis],
        stage2: List[MemberAnalysis],
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> CouncilVerdict:
        """Stage 3: Chairman synthesizes all analyses into final verdict.

        Args:
            stage1: Original independent analyses
            stage2: Updated analyses after peer review
            finding: The security finding
            context: Context dict

        Returns:
            CouncilVerdict with final action and reasoning.
        """
        logger.debug("Council Stage 3: Chairman Synthesis")

        # Determine chairman (strongest available model)
        chairman = self.chairman
        if not chairman:
            # Default: use strongest member's provider
            chairman = max(self.members, key=lambda m: m.weight).provider

        # Build synthesis prompt with all analyses
        synthesis_prompt = self._build_synthesis_prompt(stage1, stage2, finding, context)

        # Query chairman
        start = time.perf_counter()
        try:
            chairman_response = chairman.analyse(
                prompt=synthesis_prompt,
                context=context,
                default_action="review",
                default_confidence=0.5,
                default_reasoning="Chairman synthesis inconclusive",
                mitigation_hints={
                    "mitre_candidates": list(
                        dict.fromkeys(
                            m for analysis in stage2
                            for m in analysis.mitre_mappings
                        )
                    ),
                    "compliance": list(
                        dict.fromkeys(
                            c for analysis in stage2
                            for c in analysis.compliance_impact.keys()
                        )
                    ),
                },
            )
        except Exception as exc:
            logger.error("Chairman synthesis failed: %s", exc)
            # Fallback to majority vote
            return self._fallback_to_majority_vote(stage2)

        duration = (time.perf_counter() - start) * 1000

        # Extract member votes for transparency
        member_votes: List[MemberVote] = [
            MemberVote(
                member_name=member.name,
                expertise=member.expertise,
                action=analysis.position,
                confidence=analysis.confidence,
                weight=member.weight,
            )
            for member, analysis in zip(self.members, stage2)
        ]

        # Collect all analyses for debugging
        all_analyses = stage1 + stage2

        # Build verdict
        verdict = CouncilVerdict(
            action=chairman_response.recommended_action,
            confidence=chairman_response.confidence,
            reasoning=chairman_response.reasoning,
            mitre_mappings=list(chairman_response.mitre_techniques or []),
            compliance_impact={
                c: "to_review"
                for c in list(chairman_response.compliance_concerns or [])
            },
            member_votes=member_votes,
            cost_usd=self._calculate_total_cost(),
            raw_analyses=all_analyses,
        )

        return verdict

    def should_escalate(self, verdict: CouncilVerdict) -> bool:
        """Determine if verdict should escalate to Opus CTO.

        Escalates if:
        - Confidence < threshold
        - More than max_disagreement members disagree
        - Any member very low confidence

        Args:
            verdict: The CouncilVerdict to evaluate

        Returns:
            True if escalation recommended.
        """
        # Check confidence threshold
        if verdict.confidence < self.confidence_threshold:
            return True

        # Check disagreement count
        if not verdict.member_votes:
            return False

        winning_action = verdict.action
        dissenters = [
            v for v in verdict.member_votes
            if v.action != winning_action
        ]
        if len(dissenters) > self.max_disagreement:
            return True

        # Check for very low confidence from any member
        if any(v.confidence < 0.3 for v in verdict.member_votes):
            return True

        return False

    def _escalate_to_cto(
        self,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
        verdict: CouncilVerdict,
    ) -> CouncilVerdict:
        """Escalate disagreement to Claude Opus for final decision.

        Args:
            finding: Security finding
            context: Context
            verdict: The disputed verdict

        Returns:
            Updated CouncilVerdict with Opus escalation result.
        """
        logger.info("Escalating to Opus CTO: %s", verdict.action)

        if not self.escalation_provider:
            # No escalation provider configured; return original verdict
            return verdict

        # Build escalation prompt with full context
        escalation_prompt = self._build_escalation_prompt(
            finding, context, verdict
        )

        start = time.perf_counter()
        try:
            escalation_response = self.escalation_provider.analyse(
                prompt=escalation_prompt,
                context=context,
                default_action=verdict.action,
                default_confidence=verdict.confidence,
                default_reasoning="Council escalation inconclusive",
            )
        except Exception as exc:
            logger.error("Opus escalation failed: %s", exc)
            return verdict  # Return original verdict if escalation fails

        duration = (time.perf_counter() - start) * 1000

        # Update verdict with escalation result
        verdict.action = escalation_response.recommended_action
        verdict.confidence = escalation_response.confidence
        verdict.reasoning = (
            f"Opus CTO escalation decision:\n{escalation_response.reasoning}"
        )
        verdict.escalation_reason = (
            f"Confidence {verdict.confidence:.2f} < threshold {self.confidence_threshold}"
        )
        verdict.cost_usd += getattr(escalation_response.metadata.get("cost_usd", 0), "__float__", lambda: 0)()

        return verdict

    # -----------------------------------------------------------------------
    # Prompting & Synthesis Helpers
    # -----------------------------------------------------------------------

    def _build_analysis_prompt(
        self,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> str:
        """Build the initial analysis prompt for stage 1."""
        title = finding.get("title", "Unknown Finding")
        severity = finding.get("severity", "unknown")
        cve = finding.get("cve_id", "N/A")
        risk_score = finding.get("risk_score", 0)

        prompt = (
            f"Analyze this security finding for remediation decision:\n\n"
            f"Title: {title}\n"
            f"Severity: {severity}\n"
            f"CVE: {cve}\n"
            f"Risk Score: {risk_score:.2f}\n"
            f"Service: {context.get('service_name', 'unknown')}\n\n"
            f"Provide your independent assessment in JSON with keys:\n"
            f"  - recommended_action: one of [remediate_critical, remediate_high, "
            f"accept_risk, defer, investigate, false_positive]\n"
            f"  - confidence: 0.0-1.0 confidence in this decision\n"
            f"  - reasoning: detailed explanation (chain of thought)\n"
            f"  - mitre_techniques: relevant MITRE ATT&CK techniques\n"
            f"  - compliance_concerns: relevant compliance frameworks affected\n"
            f"  - attack_vectors: how this could be exploited\n\n"
            f"Do NOT consider other members' opinions. Analyze independently."
        )
        return prompt

    def _build_peer_summary(self, analyses: List[MemberAnalysis]) -> str:
        """Build anonymous summary of peer analyses for stage 2."""
        summary = "Anonymous peer analysis summary:\n\n"
        for i, analysis in enumerate(analyses, 1):
            summary += (
                f"Member {i} ({analysis.expertise}):\n"
                f"  - Action: {analysis.position}\n"
                f"  - Confidence: {analysis.confidence:.2f}\n"
                f"  - Key reasoning: {analysis.reasoning[:200]}...\n\n"
            )
        return summary

    def _query_member(
        self,
        member: CouncilMember,
        prompt: str,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
        stage: str,
    ) -> MemberAnalysis:
        """Query a single council member."""
        start = time.perf_counter()
        response = member.provider.analyse(
            prompt=prompt,
            context=context,
            default_action="review",
            default_confidence=0.5,
            default_reasoning="Analysis inconclusive",
        )
        duration = (time.perf_counter() - start) * 1000

        return MemberAnalysis(
            member_name=member.name or member.provider.name,
            expertise=member.expertise,
            stage=stage,
            position=response.recommended_action,
            confidence=response.confidence,
            reasoning=response.reasoning,
            mitre_mappings=list(response.mitre_techniques or []),
            compliance_impact={
                c: "review"
                for c in (response.compliance_concerns or [])
            },
            metadata={
                "duration_ms": round(duration, 2),
                "mode": response.metadata.get("mode", "unknown"),
            },
        )

    def _query_member_review(
        self,
        member: CouncilMember,
        original_analysis: MemberAnalysis,
        peer_summary: str,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> MemberAnalysis:
        """Query member for peer review (stage 2)."""
        prompt = (
            f"You previously analyzed a security finding and reached this decision:\n\n"
            f"Action: {original_analysis.position}\n"
            f"Confidence: {original_analysis.confidence:.2f}\n"
            f"Reasoning: {original_analysis.reasoning}\n\n"
            f"Now review peer analyses (anonymized) and decide if you want to "
            f"change your position or stick with your original assessment.\n\n"
            f"{peer_summary}\n\n"
            f"Provide updated JSON response with keys: recommended_action, confidence, "
            f"reasoning. You MAY keep your original position if you still believe it's "
            f"correct, or UPDATE if peer insights changed your mind."
        )

        return self._query_member(
            member,
            prompt,
            finding,
            context,
            stage="2_peer_review",
        )

    def _build_synthesis_prompt(
        self,
        stage1: List[MemberAnalysis],
        stage2: List[MemberAnalysis],
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> str:
        """Build synthesis prompt for chairman (stage 3)."""
        prompt = (
            f"You are the chairman of a security council. "
            f"Your role is to synthesize the council's analysis into a final verdict.\n\n"
            f"Council member analyses (post-peer-review):\n\n"
        )

        for analysis in stage2:
            prompt += (
                f"Member ({analysis.expertise}):\n"
                f"  Action: {analysis.position}\n"
                f"  Confidence: {analysis.confidence:.2f}\n"
                f"  Reasoning: {analysis.reasoning}\n\n"
            )

        prompt += (
            f"Finding: {finding.get('title', 'Unknown')}\n"
            f"Severity: {finding.get('severity', 'unknown')}\n"
            f"CVE: {finding.get('cve_id', 'N/A')}\n\n"
            f"Synthesize the council's input into a final decision. "
            f"Return JSON with keys: recommended_action, confidence, reasoning, "
            f"mitre_techniques, compliance_concerns."
        )
        return prompt

    def _build_escalation_prompt(
        self,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
        verdict: CouncilVerdict,
    ) -> str:
        """Build prompt for Opus escalation."""
        prompt = (
            f"A security council analyzed this finding and reached a verdict, "
            f"but with low confidence or disagreement. "
            f"As Opus CTO, provide the final decision.\n\n"
            f"Finding: {finding.get('title', 'Unknown')}\n"
            f"Severity: {finding.get('severity', 'unknown')}\n"
            f"Risk Score: {finding.get('risk_score', 0):.2f}\n\n"
            f"Council verdict: {verdict.action}\n"
            f"Confidence: {verdict.confidence:.2f}\n"
            f"Reasoning: {verdict.reasoning}\n\n"
            f"Member votes:\n"
        )

        for vote in verdict.member_votes:
            prompt += f"  - {vote.member_name} ({vote.expertise}): {vote.action}\n"

        prompt += (
            f"\nConsider the conflicting opinions and provide your authoritative "
            f"decision in JSON format (recommended_action, confidence, reasoning)."
        )
        return prompt

    def _fallback_to_majority_vote(
        self,
        analyses: List[MemberAnalysis],
    ) -> CouncilVerdict:
        """Fallback when chairman synthesis fails: majority vote."""
        action_counts: Dict[str, float] = {}
        confidence_sum: Dict[str, float] = {}

        for analysis in analyses:
            action = analysis.position
            action_counts[action] = action_counts.get(action, 0) + 1
            confidence_sum[action] = confidence_sum.get(action, 0) + analysis.confidence

        winning_action = max(action_counts, key=action_counts.get)
        avg_confidence = confidence_sum[winning_action] / action_counts[winning_action]

        member_votes = [
            MemberVote(
                member_name=analysis.member_name,
                expertise=analysis.expertise,
                action=analysis.position,
                confidence=analysis.confidence,
                weight=1.0,
            )
            for analysis in analyses
        ]

        return CouncilVerdict(
            action=winning_action,
            confidence=avg_confidence,
            reasoning=f"Fallback majority vote: {winning_action} ({action_counts[winning_action]}/{len(analyses)} members)",
            member_votes=member_votes,
            raw_analyses=analyses,
        )

    def _calculate_total_cost(self) -> float:
        """Calculate total cost from all member queries."""
        total = 0.0
        for member in self.members:
            if hasattr(member.provider, "cost_usd"):
                total += member.provider.cost_usd
        return total

    # -----------------------------------------------------------------------
    # History & Stats
    # -----------------------------------------------------------------------

    @property
    def history(self) -> List[CouncilVerdict]:
        """Get all council verdicts."""
        return list(self._history)

    def stats(self) -> Dict[str, Any]:
        """Aggregate statistics across all council convocations."""
        if not self._history:
            return {"total_convocations": 0}

        total_cost = sum(v.cost_usd for v in self._history)
        avg_latency = sum(v.latency_ms for v in self._history) / len(self._history)
        escalation_count = sum(1 for v in self._history if v.escalated)

        action_dist: Dict[str, int] = {}
        for verdict in self._history:
            action_dist[verdict.action] = action_dist.get(verdict.action, 0) + 1

        return {
            "total_convocations": len(self._history),
            "escalations": escalation_count,
            "total_cost_usd": round(total_cost, 6),
            "average_latency_ms": round(avg_latency, 2),
            "average_confidence": round(
                sum(v.confidence for v in self._history) / len(self._history), 3
            ),
            "action_distribution": action_dist,
        }


# ---------------------------------------------------------------------------
# Council Factory — Preset Configurations
# ---------------------------------------------------------------------------


class CouncilFactory:
    """Factory for creating pre-configured council engines.

    Provides templates for common security analysis scenarios:
    - Security Council: Focused on vulnerability remediation
    - Compliance Council: Focused on regulatory impact
    - Threat Council: Focused on exploitation and attack vectors
    - Full Council: All available perspectives
    """

    def __init__(self, manager: Optional[Any] = None) -> None:
        """Initialize factory with optional LLMProviderManager.

        Args:
            manager: LLMProviderManager instance (defaults to creating new instance)
        """
        # Import here to avoid circular dependency
        from core.llm_providers import (
            LLMProviderManager,
            AnthropicMessagesProvider,
        )

        self.manager = manager or LLMProviderManager()
        self.opus = AnthropicMessagesProvider(
            "claude-opus",
            model="claude-opus-4-1-20250805",
        )

    def create_security_council(
        self,
        *,
        confidence_threshold: float = 0.75,
        max_disagreement: int = 2,
    ) -> LLMCouncilEngine:
        """Create a security-focused council for vulnerability triage.

        Members:
        - Vulnerability Analyst (GPT-5): CVE/vulnerability assessment
        - Threat Modeler (Claude): Attack vectors and exploitation
        - Compliance Expert (Gemini): Regulatory/compliance impact
        - Code Analyst (OpenRouter): Technical depth and implementation

        Args:
            confidence_threshold: Escalation threshold for confidence
            max_disagreement: Max dissenters before escalation

        Returns:
            LLMCouncilEngine configured for security analysis
        """
        members = [
            CouncilMember(
                provider=self.manager.get_provider("openai"),
                expertise="vulnerability_assessment",
                weight=1.0,
                name="Vulnerability Analyst (GPT-5)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("anthropic"),
                expertise="threat_modeling",
                weight=0.95,
                name="Threat Modeler (Claude)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("gemini"),
                expertise="compliance_mapping",
                weight=0.9,
                name="Compliance Expert (Gemini)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("openrouter"),
                expertise="code_analysis",
                weight=0.85,
                name="Code Analyst (OpenRouter)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("deepseek"),
                expertise="vulnerability_research",
                weight=0.9,
                name="Vulnerability Researcher (DeepSeek R1)",
            ),
        ]

        # Chairman: use strongest provider (GPT-5)
        chairman = self.manager.get_provider("openai")

        return LLMCouncilEngine(
            members=members,
            chairman=chairman,
            escalation_provider=self.opus,
            confidence_threshold=confidence_threshold,
            max_disagreement=max_disagreement,
            max_workers=5,
        )

    def create_compliance_council(
        self,
        *,
        confidence_threshold: float = 0.8,
        max_disagreement: int = 1,
    ) -> LLMCouncilEngine:
        """Create a compliance-focused council for regulatory analysis.

        Members:
        - Compliance Mapper (Claude): SOC2, ISO27001, PCI-DSS
        - Risk Assessor (GPT-5): Risk scoring and impact
        - Auditor (Gemini): Evidence and audit trail requirements
        - Incident Responder (OpenRouter): Incident management impact

        Args:
            confidence_threshold: Escalation threshold (higher = stricter)
            max_disagreement: Max dissenters before escalation

        Returns:
            LLMCouncilEngine configured for compliance analysis
        """
        members = [
            CouncilMember(
                provider=self.manager.get_provider("anthropic"),
                expertise="compliance_mapping",
                weight=1.0,
                name="Compliance Mapper (Claude)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("openai"),
                expertise="risk_assessment",
                weight=0.95,
                name="Risk Assessor (GPT-5)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("gemini"),
                expertise="audit_requirements",
                weight=0.9,
                name="Auditor (Gemini)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("openrouter"),
                expertise="incident_response",
                weight=0.85,
                name="Incident Responder (OpenRouter)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("deepseek"),
                expertise="regulatory_analysis",
                weight=0.88,
                name="Regulatory Analyst (DeepSeek R1)",
            ),
        ]

        # Chairman: use Anthropic for compliance (strongest on regulatory)
        chairman = self.manager.get_provider("anthropic")

        return LLMCouncilEngine(
            members=members,
            chairman=chairman,
            escalation_provider=self.opus,
            confidence_threshold=confidence_threshold,
            max_disagreement=max_disagreement,
            max_workers=5,
        )

    def create_threat_council(
        self,
        *,
        confidence_threshold: float = 0.7,
        max_disagreement: int = 2,
    ) -> LLMCouncilEngine:
        """Create a threat-focused council for exploitation and attack analysis.

        Members:
        - Exploit Researcher (GPT-5): Known exploits and POC availability
        - Threat Intelligence (Claude): Threat actor capabilities
        - Network Analyst (Gemini): Network attack surface
        - Adversary Modeler (OpenRouter): ATT&CK and TTPs

        Args:
            confidence_threshold: Escalation threshold
            max_disagreement: Max dissenters before escalation

        Returns:
            LLMCouncilEngine configured for threat analysis
        """
        members = [
            CouncilMember(
                provider=self.manager.get_provider("openai"),
                expertise="exploit_research",
                weight=1.0,
                name="Exploit Researcher (GPT-5)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("anthropic"),
                expertise="threat_intelligence",
                weight=0.95,
                name="Threat Intelligence (Claude)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("gemini"),
                expertise="network_analysis",
                weight=0.9,
                name="Network Analyst (Gemini)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("openrouter"),
                expertise="adversary_modeling",
                weight=0.85,
                name="Adversary Modeler (OpenRouter)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("deepseek"),
                expertise="attack_chain_analysis",
                weight=0.92,
                name="Attack Chain Analyst (DeepSeek R1)",
            ),
        ]

        # Chairman: use GPT-5 for threat analysis
        chairman = self.manager.get_provider("openai")

        return LLMCouncilEngine(
            members=members,
            chairman=chairman,
            escalation_provider=self.opus,
            confidence_threshold=confidence_threshold,
            max_disagreement=max_disagreement,
            max_workers=5,
        )

    def create_full_council(
        self,
        *,
        confidence_threshold: float = 0.75,
        max_disagreement: int = 3,
    ) -> LLMCouncilEngine:
        """Create a comprehensive council with all available perspectives.

        Uses all enabled providers in the manager, each with distinct expertise.

        Args:
            confidence_threshold: Escalation threshold
            max_disagreement: Max dissenters before escalation

        Returns:
            LLMCouncilEngine with all available providers
        """
        members: List[CouncilMember] = []
        provider_specs = [
            ("openai", "vulnerability_assessment", 1.0),
            ("anthropic", "threat_modeling", 0.95),
            ("deepseek", "vulnerability_research", 0.92),
            ("gemini", "compliance_mapping", 0.9),
            ("mulerouter", "code_analysis", 0.88),
            ("openrouter", "adversary_modeling", 0.85),
            ("sentinel", "threat_intelligence", 0.8),
            ("vllm", "risk_assessment", 0.75),
            ("ollama", "network_analysis", 0.7),
        ]

        for provider_name, expertise, weight in provider_specs:
            try:
                provider = self.manager.get_provider(provider_name)
                members.append(
                    CouncilMember(
                        provider=provider,
                        expertise=expertise,
                        weight=weight,
                        name=f"{provider_name.capitalize()} ({expertise})",
                    )
                )
            except Exception as exc:
                logger.warning(
                    "Could not load provider %s for full council: %s",
                    provider_name,
                    exc,
                )

        if not members:
            raise RuntimeError("No providers available for full council creation")

        # Chairman: strongest available provider
        chairman = members[0].provider if members else None

        return LLMCouncilEngine(
            members=members,
            chairman=chairman,
            escalation_provider=self.opus,
            confidence_threshold=confidence_threshold,
            max_disagreement=max_disagreement,
            max_workers=min(6, len(members)),
        )

    def create_custom_council(
        self,
        provider_names: Sequence[str],
        expertises: Sequence[str],
        *,
        weights: Optional[Sequence[float]] = None,
        chairman_name: Optional[str] = None,
        confidence_threshold: float = 0.75,
        max_disagreement: int = 2,
    ) -> LLMCouncilEngine:
        """Create a custom council with specified providers and expertise.

        Args:
            provider_names: Names of providers to include (e.g., ["openai", "anthropic"])
            expertises: Expertise focus for each provider (must match length of provider_names)
            weights: Optional weights for each member (defaults to 1.0 each)
            chairman_name: Optional chairman provider name (defaults to first provider)
            confidence_threshold: Escalation threshold
            max_disagreement: Max dissenters before escalation

        Returns:
            LLMCouncilEngine with custom configuration

        Raises:
            ValueError: If lengths don't match or providers not found
        """
        if len(provider_names) != len(expertises):
            raise ValueError(
                f"Provider names ({len(provider_names)}) must match "
                f"expertises ({len(expertises)})"
            )

        if weights is None:
            weights = [1.0] * len(provider_names)
        elif len(weights) != len(provider_names):
            raise ValueError(
                f"Weights ({len(weights)}) must match providers ({len(provider_names)})"
            )

        members: List[CouncilMember] = []
        chairman_provider = None

        for provider_name, expertise, weight in zip(provider_names, expertises, weights):
            try:
                provider = self.manager.get_provider(provider_name)
                members.append(
                    CouncilMember(
                        provider=provider,
                        expertise=expertise,
                        weight=weight,
                        name=provider_name,
                    )
                )
                if provider_name == chairman_name or (
                    chairman_name is None and len(members) == 1
                ):
                    chairman_provider = provider
            except Exception as exc:
                raise ValueError(f"Provider '{provider_name}' not found: {exc}") from exc

        if not members:
            raise ValueError("At least one provider must be configured")

        return LLMCouncilEngine(
            members=members,
            chairman=chairman_provider,
            escalation_provider=self.opus,
            confidence_threshold=confidence_threshold,
            max_disagreement=max_disagreement,
            max_workers=min(4, len(members)),
        )
