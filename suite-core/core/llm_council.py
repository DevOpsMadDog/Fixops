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

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)

from core.llm_providers import BaseLLMProvider

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
        org_id: str = "default",
    ) -> CouncilVerdict:
        """Convene the council to analyze a security finding.

        Executes all 3 stages (or escalates if needed).

        Args:
            finding: Security finding dict (title, severity, cve_id, etc)
            context: Contextual data (service_name, risk_score, etc)
            org_id: Tenant org ID, used for TrustGraph enrichment scoping.

        Returns:
            CouncilVerdict with final action and reasoning.
        """
        wall_start = time.perf_counter()

        # Augment context with similar past decisions from AgentDB (RAG-over-TrustGraph).
        # Best-effort: never block convene if the bridge is unavailable.
        context = self._augment_with_similar_decisions(finding, context)

        # Enrich the finding with TrustGraph blast radius + CVE correlation.
        # Best-effort: returns the original finding shape on any failure.
        enriched_finding = self._enrich_with_trustgraph(dict(finding), context, org_id)

        # Stage 1: Independent Analysis
        stage1_analyses = self._stage_independent_analysis(enriched_finding, context)

        # Stage 2: Peer Review
        stage2_analyses = self._stage_peer_review(stage1_analyses, enriched_finding, context)

        # Stage 3: Chairman Synthesis
        verdict = self._stage_chairman_synthesis(
            stage1_analyses, stage2_analyses, enriched_finding, context
        )

        # Check if escalation needed
        if self.should_escalate(verdict):
            verdict = self._escalate_to_cto(enriched_finding, context, verdict)
            verdict.escalated = True

        verdict.latency_ms = (time.perf_counter() - wall_start) * 1000
        self._history.append(verdict)

        # Persist verdict back to AgentDB so future convene() calls can find it.
        # Best-effort, never blocks the verdict return.
        self._persist_verdict_to_agentdb(enriched_finding, verdict)

        logger.info(
            "Council verdict: action=%s, confidence=%.2f, escalated=%s, latency=%.0fms",
            verdict.action,
            verdict.confidence,
            verdict.escalated,
            verdict.latency_ms,
        )

        return verdict

    def _enrich_with_trustgraph(
        self,
        finding: dict,
        context: Mapping[str, Any],
        org_id: str,
    ) -> dict:
        """Enrich finding with blast radius, attack paths, CVE correlation.

        Pulls TrustGraph context (impact analysis + cross-domain correlation) so
        the council prompts can reason about real organisational blast radius and
        dollar risk instead of just the raw scanner finding payload.

        NEVER raises — returns the original finding shape on any error so the
        council remains operational even if TrustGraph is unavailable.

        Args:
            finding: Mutable copy of the security finding dict.
            context: Council context (currently unused but kept for future
                cross-context enrichment, e.g. service criticality).
            org_id: Tenant org ID for TrustGraph scoping.

        Returns:
            New dict with enrichment fields (blast_radius, dollar_risk_estimate,
            etc.) merged onto the original finding payload.
        """
        enriched = dict(finding)
        try:
            from core.trustgraph_integrations import (
                CrossDomainCorrelator,
                ImpactAnalyzer,
            )

            asset_id = finding.get("asset_id")
            cve_id = finding.get("cve_id")

            if asset_id:
                analyzer = ImpactAnalyzer(org_id=org_id)
                impact = analyzer.blast_radius(asset_id)
                enriched["blast_radius"] = impact.blast_radius
                enriched["upstream_dependencies"] = [
                    d.get("id") for d in impact.upstream_dependencies[:5]
                ]
                enriched["compliance_impact"] = [
                    c.get("framework") for c in impact.compliance_impact[:3]
                ]
                enriched["risk_weight"] = impact.risk_weight

            if cve_id:
                correlator = CrossDomainCorrelator(org_id=org_id)
                chain = correlator.correlate_cve(cve_id)
                enriched["affected_containers"] = len(chain.containers)
                enriched["affected_namespaces"] = len(chain.namespaces)
                enriched["dollar_risk_estimate"] = chain.dollar_risk_estimate
                enriched["compliance_controls_violated"] = [
                    c.get("control_id") for c in chain.compliance_controls[:5]
                ]
        except Exception as exc:  # noqa: BLE001 — enrichment must never break convene
            logger.debug("TrustGraph enrichment skipped: %s", exc)
        return enriched

    def _augment_with_similar_decisions(
        self,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Look up past similar council verdicts via AgentDB semantic search.

        Adds a ``similar_past_decisions`` key to the context dict so the prompt
        builder can render "we faced N similar decisions, here's what we ruled."
        Always returns a fresh dict (never mutates the caller's mapping).
        Best-effort: silently degrades to the original context on any failure.

        Non-blocking by design: the lookup is dispatched to a daemon thread
        and the result is only used if it completes within _AGENTDB_AUGMENT_MS.
        This prevents MiniLM lazy-load (up to several seconds) or slow SQLite
        reads from stalling the council on bulk ingestion paths.
        """
        import threading as _threading

        _AGENTDB_AUGMENT_MS = 5  # hard cap — must not affect bulk throughput

        ctx_out: Dict[str, Any] = dict(context)
        result_box: Dict[str, Any] = {}
        done_event = _threading.Event()

        def _do_augment() -> None:
            try:
                from trustgraph import agentdb_bridge as _agentdb_mod
                # Skip if bridge not yet warm — avoids 80MB MiniLM load stalling hot path
                if getattr(_agentdb_mod, "_bridge", None) is None:
                    return
                bridge = _agentdb_mod.get_agentdb_bridge()
                similar = bridge.find_similar_decisions(finding=finding, k=5, min_similarity=0.30)
                if similar:
                    result_box["similar_past_decisions"] = [
                        {
                            "key": s.key,
                            "similarity": round(s.similarity, 3),
                            "summary": (s.content or "")[:280],
                            "metadata": s.metadata,
                        }
                        for s in similar
                    ]
            except Exception as exc:  # noqa: BLE001
                logger.debug("Council: AgentDB augmentation skipped: %s", exc)
            finally:
                done_event.set()

        t = _threading.Thread(target=_do_augment, daemon=True, name="agentdb-augment")
        t.start()
        # Wait only _AGENTDB_AUGMENT_MS — if bridge is warm and fast, we get
        # the result; if cold/slow, we return the plain context immediately.
        if done_event.wait(timeout=_AGENTDB_AUGMENT_MS / 1000):
            ctx_out.update(result_box)
            if result_box:
                logger.debug(
                    "Council: augmented context with %d similar past decisions",
                    len(result_box.get("similar_past_decisions", [])),
                )
        else:
            logger.debug(
                "Council: AgentDB augmentation timed out (>%dms) — skipped", _AGENTDB_AUGMENT_MS
            )
        return ctx_out

    def _persist_verdict_to_agentdb(
        self,
        finding: Mapping[str, Any],
        verdict: "CouncilVerdict",
    ) -> None:
        """Enqueue the verdict for asynchronous AgentDB write.

        HOT PATH — must complete in < 1ms. Performs a single SQLite INSERT
        into the persistent ``agentdb_write_queue`` and returns. The actual
        AgentDB write (MiniLM encode + memory_entries insert) is performed
        by the background daemon ``scripts/agentdb_async_worker.py``.

        This replaces the previous fire-and-forget daemon-thread pattern,
        which spawned one thread per verdict — under load (1000+ events) the
        thread pool grew unbounded and each thread paid the full ~430ms
        MiniLM compute cost, dragging council throughput down even though
        the main thread didn't block on join.

        See ``docs/load_test_llm_loop_2026-04-26.md`` Bottleneck #1
        (AgentDB write moves OUT of the council hot path).

        Falls back to direct in-thread write if the queue is unavailable so
        we don't silently lose verdicts.
        """
        try:
            from trustgraph.agentdb_bridge import enqueue_council_verdict

            verdict_dict = verdict.to_dict() if hasattr(verdict, "to_dict") else {
                "action": getattr(verdict, "action", "unknown"),
                "confidence": getattr(verdict, "confidence", 0.0),
                "reasoning": getattr(verdict, "reasoning", ""),
            }
            org_id = str(finding.get("tenant", finding.get("org_id", "default")))

            enqueued = enqueue_council_verdict(
                finding=dict(finding),
                verdict=verdict_dict,
                org_id=org_id,
            )
            if enqueued:
                return

            # Queue unavailable — fall back to inline daemon thread so the
            # verdict isn't lost. Logged at debug because falling through to
            # a daemon thread is an OK degraded mode, not an error.
            logger.debug(
                "Council: AgentDB queue unavailable — falling back to daemon thread"
            )
            self._spawn_legacy_persist_thread(finding, verdict_dict, org_id)
        except Exception as exc:  # noqa: BLE001 — verdict persist must never break convene
            logger.debug("Council: AgentDB enqueue skipped: %s", exc)

    @staticmethod
    def _spawn_legacy_persist_thread(
        finding: Mapping[str, Any],
        verdict_dict: Mapping[str, Any],
        org_id: str,
    ) -> None:
        """Legacy fire-and-forget AgentDB write. Only used as a fallback when
        the async queue is unavailable (e.g. read-only filesystem in tests).
        """
        import threading as _threading

        def _do_persist() -> None:
            try:
                from trustgraph.agentdb_bridge import get_agentdb_bridge

                bridge = get_agentdb_bridge()
                bridge.write_council_verdict(
                    finding=dict(finding),
                    verdict=dict(verdict_dict),
                    org_id=org_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Council: AgentDB verdict persist skipped: %s", exc)

        _threading.Thread(target=_do_persist, daemon=True, name="agentdb-persist").start()

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

        # Derive chairman defaults from majority vote among stage2 analyses so
        # that the air-gapped fallback reflects member consensus rather than a
        # hardcoded "review"/0.5 that erases all member divergence.
        if stage2:
            from collections import Counter as _Counter
            vote_counts = _Counter(a.position for a in stage2)
            _majority_action = vote_counts.most_common(1)[0][0]
            _majority_conf = round(
                sum(a.confidence for a in stage2) / len(stage2), 3
            )
            _majority_reasoning = (
                f"Chairman synthesis: majority ({vote_counts[_majority_action]}/{len(stage2)}) "
                f"recommends '{_majority_action}' (avg confidence {_majority_conf:.2f}). "
                + "; ".join(
                    f"{a.member_name}: {a.position} ({a.confidence:.2f})"
                    for a in stage2
                )
            )
        else:
            _majority_action, _majority_conf, _majority_reasoning = (
                "review", 0.5, "Chairman synthesis inconclusive — no member analyses"
            )

        # Query chairman
        start = time.perf_counter()
        try:
            chairman_response = chairman.analyse(
                prompt=synthesis_prompt,
                context=context,
                default_action=_majority_action,
                default_confidence=_majority_conf,
                default_reasoning=_majority_reasoning,
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

        (time.perf_counter() - start) * 1000

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

        (time.perf_counter() - start) * 1000

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

        # Render similar past decisions block (RAG-over-TrustGraph).
        similar = context.get("similar_past_decisions") or []
        if similar:
            similar_lines = [
                f"\nPast similar council decisions (top {len(similar)} from TrustGraph/AgentDB):"
            ]
            for i, s in enumerate(similar, 1):
                similar_lines.append(
                    f"  {i}. similarity={s.get('similarity', 0):.2f} "
                    f"key={s.get('key', '?')} — {s.get('summary', '')[:160]}"
                )
            similar_block = "\n".join(similar_lines) + "\n"
        else:
            similar_block = ""

        prompt = (
            f"Analyze this security finding for remediation decision:\n\n"
            f"Title: {title}\n"
            f"Severity: {severity}\n"
            f"CVE: {cve}\n"
            f"Risk Score: {risk_score:.2f}\n"
            f"Service: {context.get('service_name', 'unknown')}\n"
            f"{similar_block}\n"
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

    @staticmethod
    def _derive_member_defaults(
        member: "CouncilMember",
        finding: Mapping[str, Any],
    ) -> tuple[str, float, str]:
        """Derive expertise-driven fallback defaults from finding severity.

        When LLM providers are unavailable (air-gapped / no API keys), each
        member still produces a *different* deterministic verdict based on
        their security expertise focus and the finding's risk level.  This
        ensures the council demonstrates real divergence even without live
        LLM calls — a genuine air-gapped council, not a uniform stub.

        Returns:
            (default_action, default_confidence, default_reasoning)
        """
        risk = str(finding.get("risk_level", finding.get("severity", "medium"))).lower()
        cvss = float(finding.get("cvss_score", 0.0))
        expertise = (member.expertise or "").lower()

        # Severity tier: critical>=9, high>=7, medium>=4, low<4
        if cvss >= 9.0 or risk == "critical":
            tier = "critical"
        elif cvss >= 7.0 or risk == "high":
            tier = "high"
        elif cvss >= 4.0 or risk == "medium":
            tier = "medium"
        else:
            tier = "low"

        # Each expertise focus applies a different lens to the same finding
        if "vulnerability" in expertise or "assessment" in expertise:
            # Vuln analyst: aggressive on high/critical — push for immediate fix
            matrix = {
                "critical": ("remediate_critical", 0.95,
                             "CVSS/severity mandates immediate patch — no deferral acceptable"),
                "high":     ("remediate_high",     0.88,
                             "High severity confirmed; exploit PoC increases urgency"),
                "medium":   ("investigate",        0.72,
                             "Medium severity warrants deeper investigation before patching"),
                "low":      ("accept_risk",        0.65,
                             "Low severity; risk acceptance appropriate with monitoring"),
            }
        elif "threat" in expertise or "modeling" in expertise:
            # Threat modeler: maps to MITRE, more nuanced on exploitability
            matrix = {
                "critical": ("remediate_critical", 0.92,
                             "MITRE T1190 alignment — active exploitation likely; escalate"),
                "high":     ("investigate",        0.78,
                             "Threat model shows lateral movement potential; verify first"),
                "medium":   ("defer",              0.60,
                             "Threat model: medium findings deferrable to next sprint"),
                "low":      ("accept_risk",        0.55,
                             "Low threat actor interest; accept with compensating control"),
            }
        elif "compliance" in expertise or "regulatory" in expertise:
            # Compliance expert: maps to framework requirements
            matrix = {
                "critical": ("remediate_critical", 0.97,
                             "PCI-DSS/SOC2 breach risk — compliance mandates immediate fix"),
                "high":     ("remediate_high",     0.85,
                             "Framework violation likely; remediate before next audit"),
                "medium":   ("defer",              0.68,
                             "Medium: acceptable with compensating controls documented"),
                "low":      ("accept_risk",        0.80,
                             "Low compliance impact; formal risk acceptance sufficient"),
            }
        elif "code" in expertise or "analysis" in expertise:
            # Code analyst: focuses on exploitability and PoC availability.
            # For HIGH findings, code analysts prefer to verify the full taint
            # path before declaring remediate_high — they may find the sink is
            # unreachable or already mitigated by a framework layer.
            matrix = {
                "critical": ("remediate_critical", 0.90,
                             "Code path is exploitable; PoC confirmed — patch immediately"),
                "high":     ("investigate",        0.74,
                             "Code analyst: taint path unverified — need source-to-sink trace before prescribing full remediation"),
                "medium":   ("investigate",        0.65,
                             "Code path partially constrained — needs deeper taint analysis"),
                "low":      ("false_positive",     0.55,
                             "Code review suggests low exploitability; may be false positive"),
            }
        elif "adversar" in expertise:
            # Adversary modeler: attacker-centric perspective
            matrix = {
                "critical": ("remediate_critical", 0.93,
                             "From attacker view: trivially exploitable, high ROI for threat actors"),
                "high":     ("investigate",        0.75,
                             "Attacker would attempt this; verify before public disclosure"),
                "medium":   ("defer",              0.58,
                             "Moderate attacker interest; defer to scheduled maintenance"),
                "low":      ("accept_risk",        0.62,
                             "Low attacker ROI; risk acceptance with monitoring"),
            }
        else:
            # Generic security analyst
            matrix = {
                "critical": ("remediate_critical", 0.90,
                             "Critical severity demands immediate remediation"),
                "high":     ("remediate_high",     0.80,
                             "High severity: prioritize in current sprint"),
                "medium":   ("investigate",        0.65,
                             "Medium severity: investigate exploitability before acting"),
                "low":      ("accept_risk",        0.60,
                             "Low severity: accept with documented risk"),
            }

        action, conf, reasoning = matrix[tier]
        # Scale confidence by member weight so heavier members express more certainty
        conf = round(min(conf * member.weight, 0.99), 3)
        return action, conf, reasoning

    def _query_member(
        self,
        member: CouncilMember,
        prompt: str,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
        stage: str,
    ) -> MemberAnalysis:
        """Query a single council member."""
        # Derive expertise-driven defaults so air-gapped fallbacks diverge
        default_action, default_confidence, default_reasoning = (
            self._derive_member_defaults(member, finding)
        )
        start = time.perf_counter()
        response = member.provider.analyse(
            prompt=prompt,
            context=context,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
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
            "You are the chairman of a security council. "
            "Your role is to synthesize the council's analysis into a final verdict.\n\n"
            "Council member analyses (post-peer-review):\n\n"
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
            "\nConsider the conflicting opinions and provide your authoritative "
            "decision in JSON format (recommended_action, confidence, reasoning)."
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

        If air-gap mode is CONFIGURED or ENFORCED (via FIXOPS_AIRGAP_MODE env-var
        or persisted state), the factory swaps every external provider in the
        manager (openai/anthropic/gemini/openrouter/mulerouter/deepseek) for an
        AirGapLLMProvider that routes through LocalLLMRouter. ENFORCED mode with
        no detected local backend raises RuntimeError; CONFIGURED logs critical
        and leaves the manager with an empty external set so we never silently
        degrade to api.openai.com.
        """
        # Import here to avoid circular dependency
        from core.llm_providers import (
            AnthropicMessagesProvider,
            LLMProviderManager,
        )

        self.manager = manager or LLMProviderManager()
        self.opus = AnthropicMessagesProvider(
            "claude-opus",
            model="claude-opus-4-1-20250805",
        )

        # Air-gap enforcement: replace external-API providers with AirGapLLMProvider
        # so the council cannot reach api.openai.com / api.anthropic.com / etc.
        try:
            self._enforce_air_gap_providers()
        except RuntimeError:
            # ENFORCED + no local backend → propagate. Caller MUST handle.
            raise
        except Exception as exc:  # noqa: BLE001 - resilience for non-airgap deployments
            logger.debug(
                "CouncilFactory: air-gap enforcement check skipped (%s)",
                type(exc).__name__,
            )

    def _enforce_air_gap_providers(self) -> None:
        """Swap external-API providers for AirGapLLMProvider when air-gap is active.

        Behaviour matrix:
          - DISABLED / DETECTED: no-op. External providers remain as-is.
          - CONFIGURED + local backend available: replace ALL external providers
            with AirGapLLMProvider. Escalation provider (Opus) also replaced.
          - CONFIGURED + no local backend: log CRITICAL, set external providers to
            an air-gap stub that always raises (NEVER silently call out). The
            council will surface the error rather than degrading.
          - ENFORCED + local backend available: same as CONFIGURED-with-backend.
          - ENFORCED + no local backend: raise RuntimeError — refuse to start.
        """
        from core.airgap_config import (  # local import → avoid cold-start cost
            AirGapMode,
            LocalLLMRouter,
            get_air_gap_mode,
        )
        from core.llm_providers import AirGapLLMProvider

        mode = get_air_gap_mode()
        if mode not in (AirGapMode.CONFIGURED, AirGapMode.ENFORCED):
            return  # internet-connected operation — no swap needed

        # Names that talk to external APIs and must be swapped/disabled.
        EXTERNAL_PROVIDER_NAMES = (
            "openai",
            "anthropic",
            "gemini",
            "openrouter",
            "mulerouter",
            "deepseek",
        )

        router = LocalLLMRouter()
        try:
            detected = router.detect_available_backend()
        except Exception as exc:  # noqa: BLE001 - probe must not raise
            logger.warning("Air-gap probe error: %s", exc)
            detected = None

        backend_available = bool(detected and getattr(detected, "available", False))

        if mode == AirGapMode.ENFORCED and not backend_available:
            raise RuntimeError(
                "AirGapMode.ENFORCED but no local LLM backend available — "
                "refusing to start council. Install Ollama / vLLM / llama.cpp "
                "on the air-gapped host."
            )

        if not backend_available:
            # CONFIGURED + no backend: critical-log and clear externals so the
            # council surfaces the missing-backend condition instead of silently
            # routing to api.openai.com.
            logger.critical(
                "Air-gap mode CONFIGURED but no local LLM backend detected — "
                "ALL external LLM providers DISABLED. Council will operate with "
                "deterministic fallbacks only. Install Ollama / vLLM to restore."
            )
            for pname in EXTERNAL_PROVIDER_NAMES:
                if pname in self.manager.providers:
                    self.manager.providers.pop(pname, None)
            # Also disable cloud-Opus escalation in air-gap.
            self.opus = None  # type: ignore[assignment]
            return

        # Backend available — build per-name air-gap providers preserving identity.
        replaced: List[str] = []
        for pname in EXTERNAL_PROVIDER_NAMES:
            existing = self.manager.providers.get(pname)
            if existing is None:
                continue
            try:
                # Each provider gets its OWN router so per-provider model overrides
                # don't bleed across.
                router_for_provider = LocalLLMRouter()
                self.manager.providers[pname] = AirGapLLMProvider(
                    name=existing.name,
                    local_llm_router=router_for_provider,
                    style=getattr(existing, "style", "consensus"),
                    focus=list(getattr(existing, "focus", []) or []),
                )
                replaced.append(pname)
            except RuntimeError as exc:
                # detect_available_backend() agreed at the top, but a per-provider
                # router can still race to false → drop this provider rather than
                # leaving the external version live.
                logger.error(
                    "Air-gap swap for %s failed (%s) — disabling provider.", pname, exc,
                )
                self.manager.providers.pop(pname, None)

        # Escalation provider must also route via air-gap, not api.anthropic.com.
        try:
            self.opus = AirGapLLMProvider(
                name="claude-opus-airgap",
                local_llm_router=LocalLLMRouter(),
                style="analyst",
            )
        except RuntimeError as exc:
            logger.error("Air-gap escalation provider unavailable: %s", exc)
            self.opus = None  # type: ignore[assignment]

        logger.info(
            "Air-gap mode %s enforced — swapped %d external providers (%s) for AirGapLLMProvider",
            mode.value, len(replaced), ", ".join(replaced),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _provider_has_key(self, provider_name: str) -> bool:
        """Return True if the named provider has a real API key configured.

        Checks the provider's ``api_key`` attribute (set during __init__ via
        _resolve_api_key).  Providers without keys return an empty string / None
        and will fall through to BaseLLMProvider.analyse() → confidence=0.5.
        """
        try:
            provider = self.manager.get_provider(provider_name)
            api_key = getattr(provider, "api_key", None)
            return bool(api_key)
        except Exception:
            return False

    def _available_providers_ordered(
        self, preference_order: List[str]
    ) -> List[str]:
        """Return subset of *preference_order* that have real API keys, in order."""
        return [p for p in preference_order if self._provider_has_key(p)]

    # ------------------------------------------------------------------
    # Preset: mulerouter + openrouter (env-var driven, 2-member real council)
    # ------------------------------------------------------------------

    def create_mulerouter_council(
        self,
        *,
        confidence_threshold: float = 0.75,
        max_disagreement: int = 1,
    ) -> LLMCouncilEngine:
        """Create a 2-member real council using MULEROUTER_API_KEY + OPENROUTER_API_KEY.

        This is the default preset when neither OpenAI/Anthropic/Gemini keys are
        present (the common air-gapped / free-tier deployment).

        Members:
        - Primary Analyst (MuleRouter/Qwen3-6b-Max): vulnerability + threat modeling
        - Code Analyst (OpenRouter/DeepSeek-free): code analysis + adversary modeling

        Chairman: MuleRouter (highest weight).
        """
        members = [
            CouncilMember(
                provider=self.manager.get_provider("mulerouter"),
                expertise="vulnerability_assessment",
                weight=1.0,
                name="Primary Analyst (MuleRouter/Qwen3)",
            ),
            CouncilMember(
                provider=self.manager.get_provider("openrouter"),
                expertise="code_analysis",
                weight=0.9,
                name="Code Analyst (OpenRouter/DeepSeek)",
            ),
        ]
        chairman = self.manager.get_provider("mulerouter")
        return LLMCouncilEngine(
            members=members,
            chairman=chairman,
            escalation_provider=self.opus,
            confidence_threshold=confidence_threshold,
            max_disagreement=max_disagreement,
            max_workers=2,
        )

    def create_security_council(
        self,
        *,
        confidence_threshold: float = 0.75,
        max_disagreement: int = 2,
    ) -> LLMCouncilEngine:
        """Create a security-focused council for vulnerability triage.

        Provider selection is driven by ``FIXOPS_COUNCIL_PRESET`` env-var:

        - ``mulerouter+openrouter``: 2-member real council (MuleRouter + OpenRouter).
          Use this when only MULEROUTER_API_KEY / OPENROUTER_API_KEY are set.
        - ``auto`` (default): inspect which providers have real API keys and build
          the best possible council, preferring mulerouter/openrouter over keyless
          cloud providers that would silently fall back to confidence=0.5.
        - ``full``: use all five original members regardless of key availability
          (legacy behaviour — some members may be deterministic).

        Members when preset=auto and only free-tier keys present:
        - Primary Analyst (MuleRouter): vulnerability assessment
        - Code Analyst (OpenRouter): technical depth

        Members when preset=auto and cloud keys present:
        - Vulnerability Analyst (GPT-5): CVE/vulnerability assessment
        - Threat Modeler (Claude): Attack vectors and exploitation
        - Compliance Expert (Gemini): Regulatory/compliance impact
        - Code Analyst (OpenRouter): Technical depth and implementation
        - Vulnerability Researcher (DeepSeek R1): vulnerability research

        Args:
            confidence_threshold: Escalation threshold for confidence
            max_disagreement: Max dissenters before escalation

        Returns:
            LLMCouncilEngine configured for security analysis
        """
        import os as _os

        preset = _os.environ.get("FIXOPS_COUNCIL_PRESET", "auto").lower().strip()

        # Explicit preset: mulerouter+openrouter
        if preset == "mulerouter+openrouter":
            return self.create_mulerouter_council(
                confidence_threshold=confidence_threshold,
                max_disagreement=min(max_disagreement, 1),
            )

        # Auto preset: prefer providers with real keys; fall back to mulerouter council
        if preset == "auto":
            # Priority order: free-tier keys first (always present), then cloud keys
            preferred_order = [
                "mulerouter",
                "openrouter",
                "deepseek",
                "openai",
                "anthropic",
                "gemini",
            ]
            available = self._available_providers_ordered(preferred_order)

            if not available:
                # Absolute last resort: deterministic council (legacy)
                logger.warning(
                    "CouncilFactory: no providers with API keys found — "
                    "falling back to full deterministic council. "
                    "Set MULEROUTER_API_KEY or OPENROUTER_API_KEY for real consensus."
                )
            elif set(available).issubset({"mulerouter", "openrouter", "deepseek"}):
                # Only free-tier keys — use the 2-member real council
                return self.create_mulerouter_council(
                    confidence_threshold=confidence_threshold,
                    max_disagreement=min(max_disagreement, 1),
                )
            else:
                # Cloud keys present — build best available council
                # Always include free-tier providers at the back for diversity
                all_specs = [
                    ("openai", "vulnerability_assessment", 1.0,
                     "Vulnerability Analyst (GPT-5)"),
                    ("anthropic", "threat_modeling", 0.95,
                     "Threat Modeler (Claude)"),
                    ("gemini", "compliance_mapping", 0.9,
                     "Compliance Expert (Gemini)"),
                    ("mulerouter", "code_analysis", 0.88,
                     "Code Analyst (MuleRouter)"),
                    ("openrouter", "adversary_modeling", 0.85,
                     "Adversary Modeler (OpenRouter)"),
                    ("deepseek", "vulnerability_research", 0.9,
                     "Vulnerability Researcher (DeepSeek R1)"),
                ]
                members = []
                for pname, expertise, weight, display in all_specs:
                    if self._provider_has_key(pname):
                        members.append(CouncilMember(
                            provider=self.manager.get_provider(pname),
                            expertise=expertise,
                            weight=weight,
                            name=display,
                        ))
                if members:
                    chairman = members[0].provider
                    return LLMCouncilEngine(
                        members=members,
                        chairman=chairman,
                        escalation_provider=self.opus,
                        confidence_threshold=confidence_threshold,
                        max_disagreement=max_disagreement,
                        max_workers=min(5, len(members)),
                    )

        # Preset == "full" or fallthrough: legacy hard-coded 5-member council
        # (some members may produce deterministic results if keys are missing)
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
