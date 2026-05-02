"""
Council Pipeline Adapter — Bridge between ALdeci Brain Pipeline and LLMCouncilEngine.

Provides a drop-in replacement for the legacy ConsensusEngine that integrates
the new 3-stage Karpathy LLM Council pattern into the existing pipeline flow.

Features:
  - Compatible interface with old ConsensusEngine (analyse method, result format)
  - Decision memory integration for learning from past decisions
  - Analyst feedback loop for continuous improvement
  - Opus CTO escalation for high-uncertainty cases
  - Cost guards to prevent runaway spending on escalations
  - Session history and accuracy metrics

Usage:
    from core.council_pipeline_adapter import create_consensus_engine_replacement

    council_adapter = create_consensus_engine_replacement()
    result = council_adapter.analyse(prompt=prompt, context=ctx)
    # result is compatible with old ConsensusResult format

Wire into brain_pipeline.py (line ~2945):
    OLD: result = consensus_engine.analyse(prompt=prompt, context=ctx)
    NEW: from core.council_pipeline_adapter import create_consensus_engine_replacement
         council_adapter = create_consensus_engine_replacement()
         result = council_adapter.analyse(prompt=prompt, context=ctx)
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional

from core.errors import ExternalServiceError  # noqa: F401 - re-exported for callers

logger = logging.getLogger(__name__)


# ===========================================================================
# Data Classes
# ===========================================================================


@dataclass
class ConsensusResult:
    """Drop-in replacement format for old ConsensusEngine results.

    Maintains backward compatibility with brain_pipeline.py expectations.
    """
    final_decision: str  # 'block', 'review', 'allow', 'remediate_critical', etc
    method: str  # 'council_verdict', 'council_escalation', 'deterministic'
    confidence: float  # 0.0-1.0
    reasoning: str
    council_session_id: Optional[str] = None
    providers_queried: int = 0
    providers_responded: int = 0
    consensus_pct: float = 1.0
    mitre_techniques: List[str] = field(default_factory=list)
    compliance_concerns: List[str] = field(default_factory=list)
    escalated: bool = False
    escalation_reason: Optional[str] = None
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    air_gapped: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for serialization."""
        return {
            "final_decision": self.final_decision,
            "method": self.method,
            "confidence": round(self.confidence, 3),
            "reasoning": self.reasoning,
            "council_session_id": self.council_session_id,
            "providers_queried": self.providers_queried,
            "providers_responded": self.providers_responded,
            "consensus_pct": round(self.consensus_pct, 4),
            "mitre_techniques": self.mitre_techniques[:20],
            "compliance_concerns": self.compliance_concerns[:10],
            "escalated": self.escalated,
            "escalation_reason": self.escalation_reason,
            "cost_usd": round(self.cost_usd, 6),
            "latency_ms": round(self.latency_ms, 2),
            "air_gapped": self.air_gapped,
        }


@dataclass
class EscalationRecord:
    """Track Opus CTO escalations for cost guarding."""
    timestamp: str
    finding_id: str
    council_session_id: str
    reason: str
    cost_usd: float

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ===========================================================================
# Opus CTO Escalation Handler
# ===========================================================================


class OpusCTOEscalation:
    """
    Handles escalation to Claude Opus when council cannot decide.

    Escalation triggers:
      - Council confidence < 0.7
      - Disagreement among members > max_disagreement threshold
      - Analyst requests manual review

    Cost Guard: Max 10 escalations per hour (Opus is expensive!)
    """

    def __init__(self, max_escalations_per_hour: int = 10):
        """Initialize escalation handler.

        Args:
            max_escalations_per_hour: Max Opus calls allowed per hour (cost guard)
        """
        self.max_escalations_per_hour = max_escalations_per_hour
        self.escalation_history: List[EscalationRecord] = []
        self._lock = __import__('threading').Lock()

    def can_escalate(self) -> bool:
        """Check if escalation budget remains for this hour."""
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
            cutoff_iso = cutoff.isoformat()

            recent = [
                e for e in self.escalation_history
                if e.timestamp > cutoff_iso
            ]

            remaining = self.max_escalations_per_hour - len(recent)
            if remaining <= 0:
                logger.warning(
                    "Escalation budget exhausted: %d/%d used in last hour",
                    len(recent),
                    self.max_escalations_per_hour
                )
            return remaining > 0

    def escalate_to_opus(
        self,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
        council_session_id: str,
        council_reasoning: str,
        reason: str,
    ) -> ConsensusResult:
        """Get Opus CTO's binding final verdict.

        Args:
            finding: Security finding dict
            context: Pipeline context
            council_session_id: Link to council session
            council_reasoning: What the council said
            reason: Why escalation was needed

        Returns:
            ConsensusResult with Opus's decision
        """
        if not self.can_escalate():
            logger.error("Escalation budget exceeded; using council verdict")
            # Fallback to conservative action
            return ConsensusResult(
                final_decision="review",
                method="deterministic",
                confidence=0.6,
                reasoning="Escalation budget exceeded; conservative fallback",
                council_session_id=council_session_id,
                escalated=False,
                escalation_reason="Budget exceeded"
            )

        try:
            from core.llm_providers import AnthropicMessagesProvider

            # Create Opus provider with explicit model override
            opus_provider = AnthropicMessagesProvider(
                name="opus-cto",
                model="claude-opus-4-6-20250514"  # Use latest Opus
            )

            if not opus_provider.api_key:
                logger.warning("Anthropic API key not configured; skipping Opus escalation")
                return ConsensusResult(
                    final_decision="review",
                    method="deterministic",
                    confidence=0.6,
                    reasoning="Anthropic API unavailable; conservative fallback",
                    council_session_id=council_session_id,
                    escalated=False
                )

            # Build comprehensive escalation prompt
            escalation_prompt = (
                f"OPUS CTO ESCALATION REQUEST\n"
                f"=====================================\n\n"
                f"Finding: {finding.get('title', 'Unknown')}\n"
                f"Severity: {finding.get('severity', 'medium')}\n"
                f"Risk Score: {finding.get('risk_score', 0):.2f}\n"
                f"CVE: {finding.get('cve_id', 'N/A')}\n\n"
                f"Council Reasoning (3-stage Karpathy):\n{council_reasoning}\n\n"
                f"Escalation Reason: {reason}\n\n"
                f"Context:\n"
                f"  Service: {context.get('service_name', 'unknown')}\n"
                f"  Environment: {context.get('environment', 'unknown')}\n"
                f"  Org: {context.get('org_id', 'unknown')}\n\n"
                f"Please provide final decision (remediate_critical/remediate_high/accept_risk/investigate/false_positive)\n"
                f"with confidence 0-1, reasoning, and MITRE techniques.\n"
                f"Return as JSON: {{\"action\": ..., \"confidence\": ..., \"reasoning\": ..., \"mitre_techniques\": [...]}}"
            )

            wall_start = time.perf_counter()
            response = opus_provider.analyse(
                prompt=escalation_prompt,
                context=context,
                default_action="review",
                default_confidence=0.7,
                default_reasoning="Opus escalation — conservative default",
                mitigation_hints={
                    "mitre_candidates": finding.get("mitre_techniques", []),
                    "compliance": finding.get("compliance_concerns", []),
                }
            )
            opus_latency_ms = (time.perf_counter() - wall_start) * 1000

            # Record escalation
            escalation_rec = EscalationRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                finding_id=finding.get("id", "unknown"),
                council_session_id=council_session_id,
                reason=reason,
                cost_usd=0.02,  # Rough estimate for Opus call
            )
            with self._lock:
                self.escalation_history.append(escalation_rec)

            logger.info(
                "Opus escalation completed: action=%s, confidence=%.2f, cost=$%.4f",
                response.recommended_action,
                response.confidence,
                escalation_rec.cost_usd
            )

            return ConsensusResult(
                final_decision=response.recommended_action,
                method="council_escalation",
                confidence=response.confidence,
                reasoning=response.reasoning,
                council_session_id=council_session_id,
                escalated=True,
                escalation_reason=reason,
                cost_usd=escalation_rec.cost_usd,
                latency_ms=opus_latency_ms,
                mitre_techniques=list(response.mitre_techniques),
                compliance_concerns=list(response.compliance_concerns),
            )

        except ImportError:
            logger.error("core.llm_providers not available; skipping Opus escalation")
            return ConsensusResult(
                final_decision="review",
                method="deterministic",
                confidence=0.6,
                reasoning="LLM providers unavailable; conservative fallback",
                council_session_id=council_session_id,
                escalated=False
            )
        except (ExternalServiceError, RuntimeError, ValueError, OSError) as e:
            logger.error("Opus escalation failed: %s", type(e).__name__)
            return ConsensusResult(
                final_decision="review",
                method="deterministic",
                confidence=0.6,
                reasoning=f"Escalation failed ({type(e).__name__}); conservative fallback",
                council_session_id=council_session_id,
                escalated=False
            )


# ===========================================================================
# Council Pipeline Adapter
# ===========================================================================


class CouncilPipelineAdapter:
    """
    Bridge between ALdeci Brain Pipeline and LLMCouncilEngine.

    Provides a drop-in replacement for ConsensusEngine with integrated:
      - Decision memory (learning from past decisions)
      - Analyst feedback loop (continuous improvement)
      - Opus CTO escalation (for high-uncertainty cases)
      - Cost guards (prevent runaway spending)
      - Session history (audit trail)
      - Accuracy metrics (performance tracking)
    """

    def __init__(
        self,
        council: Optional[Any] = None,
        memory_store: Optional[Any] = None,
        feedback_loop: Optional[Any] = None,
        escalation_handler: Optional[OpusCTOEscalation] = None,
    ):
        """Initialize adapter with optional lazy dependencies.

        Args:
            council: LLMCouncilEngine instance (lazy-init if None)
            memory_store: DecisionMemoryStore for learning (lazy-init if None)
            feedback_loop: DecisionFeedbackLoop (lazy-init if None)
            escalation_handler: OpusCTOEscalation handler (creates if None)
        """
        self._council = council
        self._memory_store = memory_store
        self._feedback_loop = feedback_loop
        self._escalation = escalation_handler or OpusCTOEscalation()
        self._session_history: List[Dict[str, Any]] = []
        self._lock = __import__('threading').Lock()

        logger.info("CouncilPipelineAdapter initialized")

    def _ensure_council(self) -> Any:
        """Lazy-init LLMCouncilEngine if needed."""
        if self._council is None:
            try:
                from core.llm_council import CouncilFactory, LLMCouncilEngine
                # Use factory to get a pre-configured council
                factory = CouncilFactory()
                self._council = factory.create_default_council()
                logger.info("LLMCouncilEngine initialized (lazy)")
            except ImportError as e:
                logger.error("Failed to import LLMCouncilEngine: %s", e)
                raise
        return self._council

    def _ensure_memory(self) -> Any:
        """Lazy-init DecisionMemoryStore if needed."""
        if self._memory_store is None:
            try:
                from core.decision_memory import DecisionMemoryStore
                db_path = os.environ.get(
                    "FIXOPS_DECISION_MEMORY_DB",
                    "data/decision_memory.db"
                )
                self._memory_store = DecisionMemoryStore(db_path=db_path)
                logger.info("DecisionMemoryStore initialized: %s", db_path)
            except ImportError as e:
                logger.error("Failed to import DecisionMemoryStore: %s", e)
                # Non-fatal; continue without memory
                return None
        return self._memory_store

    def _ensure_feedback(self) -> Any:
        """Lazy-init DecisionFeedbackLoop if needed."""
        if self._feedback_loop is None:
            store = self._ensure_memory()
            if store:
                try:
                    from core.decision_memory import DecisionFeedbackLoop
                    self._feedback_loop = DecisionFeedbackLoop(store)
                    logger.info("DecisionFeedbackLoop initialized")
                except ImportError as e:
                    logger.error("Failed to import DecisionFeedbackLoop: %s", e)
                    return None
        return self._feedback_loop

    def analyse(
        self,
        *,
        prompt: str,
        context: Optional[Mapping[str, Any]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Analyze findings using LLM Council with decision memory integration.

        This is the main entry point compatible with the old ConsensusEngine API.

        Args:
            prompt: Analysis prompt (for compatibility)
            context: Pipeline context dict
            findings: List of critical findings to analyze

        Returns:
            Dict compatible with old ConsensusEngine result format
        """
        if context is None:
            context = {}

        if findings is None:
            findings = context.get("findings", [])

        wall_start = time.perf_counter()
        session_id = str(uuid.uuid4())[:8]

        try:
            # Filter to critical findings
            critical = [f for f in findings if f.get("risk_score", 0) >= 0.6]
            if not critical:
                return {
                    "analyzed": 0,
                    "reason": "no critical findings",
                    "method": "skipped",
                }

            # Sort by risk and cap
            MAX_FINDINGS = int(os.environ.get("FIXOPS_MAX_LLM_FINDINGS", "50"))
            critical = sorted(
                critical,
                key=lambda f: f.get("risk_score", 0),
                reverse=True
            )[:MAX_FINDINGS]

            was_capped = len(critical) == MAX_FINDINGS

            # Build analysis context from findings
            severity_buckets: Dict[str, List[Dict[str, Any]]] = {
                "critical": [],
                "high": [],
                "medium": [],
            }
            for f in critical:
                sev = str(f.get("severity", "medium")).lower()
                bucket = severity_buckets.get(sev, severity_buckets["medium"])
                bucket.append(f)

            # Query council for verdict
            council = self._ensure_council()

            # Pass findings batch context to council
            council_context = {
                **context,
                "severity_distribution": {s: len(f) for s, f in severity_buckets.items()},
                "finding_count": len(critical),
                "avg_risk_score": sum(f.get("risk_score", 0) for f in critical) / len(critical),
            }

            # Aggregate findings into single "batch" finding for council
            batch_finding = {
                "title": f"Batch analysis: {len(critical)} findings",
                "severity": "critical" if critical else "medium",
                "findings": critical,
                "risk_score": council_context.get("avg_risk_score", 0.65),
            }

            # Get council verdict
            verdict = council.convene(batch_finding, council_context)

            # Check for escalation need
            escalation_reason = None
            if verdict.confidence < 0.7:
                escalation_reason = f"Low confidence: {verdict.confidence:.2f}"
            elif len([v for v in verdict.member_votes if v.action != verdict.action]) > 2:
                escalation_reason = "High disagreement among council members"

            if escalation_reason and self._escalation.can_escalate():
                logger.info("Escalating to Opus CTO: %s", escalation_reason)
                council_reasoning = (
                    f"Council verdict: {verdict.action} "
                    f"(confidence={verdict.confidence:.2f})\n"
                    f"Member votes: {len(verdict.member_votes)} "
                    f"(agreements: {sum(1 for v in verdict.member_votes if v.action == verdict.action)})\n"
                    f"Reasoning: {verdict.reasoning}"
                )
                result = self._escalation.escalate_to_opus(
                    batch_finding,
                    council_context,
                    session_id,
                    council_reasoning,
                    escalation_reason,
                )
            else:
                # Use council verdict as-is
                result = ConsensusResult(
                    final_decision=verdict.action,
                    method="council_verdict",
                    confidence=verdict.confidence,
                    reasoning=verdict.reasoning,
                    council_session_id=session_id,
                    providers_queried=len(verdict.member_votes),
                    providers_responded=len(verdict.member_votes),
                    consensus_pct=1.0,
                    mitre_techniques=verdict.mitre_mappings,
                    compliance_concerns=[
                        f"{f}: {v}" for f, v in verdict.compliance_impact.items()
                    ],
                    escalated=False,
                    cost_usd=verdict.cost_usd,
                    latency_ms=verdict.latency_ms,
                )

            # Record decision in memory
            store = self._ensure_memory()
            if store and findings:
                try:
                    import hashlib

                    from core.decision_memory import DecisionRecord

                    finding_content = json.dumps(critical, sort_keys=True, default=str)
                    finding_hash = hashlib.sha256(finding_content.encode()).hexdigest()

                    record = DecisionRecord(
                        finding_id=batch_finding.get("id", f"batch-{session_id}"),
                        finding_hash=finding_hash,
                        decision_type="council_verdict",
                        action=result.final_decision,
                        confidence=result.confidence,
                        reasoning=result.reasoning,
                        council_session_id=session_id,
                        mitre_techniques=result.mitre_techniques,
                        compliance_impact=result.compliance_concerns,
                        org_id=context.get("org_id", "unknown"),
                        metadata={
                            "finding_count": len(critical),
                            "severity_distribution": severity_buckets,
                            "escalated": result.escalated,
                            "method": result.method,
                        }
                    )
                    store.record(record)
                    logger.debug("Decision recorded in memory: %s", session_id)
                except (ValueError, KeyError, TypeError) as e:
                    logger.warning("Failed to record decision in memory: %s", e)

            # Record in session history
            with self._lock:
                self._session_history.append({
                    "session_id": session_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "findings_analyzed": len(critical),
                    "decision": result.final_decision,
                    "confidence": result.confidence,
                    "escalated": result.escalated,
                    "cost_usd": result.cost_usd,
                    "latency_ms": result.latency_ms,
                })

            result.latency_ms = (time.perf_counter() - wall_start) * 1000

            # Return brain_pipeline-compatible format
            return {
                "analyzed": len(critical),
                "decision": result.final_decision,
                "method": result.method,
                "confidence": result.confidence,
                "consensus_pct": result.consensus_pct,
                "capped": was_capped,
                "providers_responded": result.providers_responded,
                "escalated": result.escalated,
                "escalation_reason": result.escalation_reason,
                "cost_usd": result.cost_usd,
                "latency_ms": round(result.latency_ms, 2),
                "session_id": session_id,
                "mitre_techniques": result.mitre_techniques,
                "compliance_concerns": result.compliance_concerns,
            }

        except (ExternalServiceError, RuntimeError, ValueError, KeyError, TypeError) as e:
            logger.error("Council analysis failed: %s; using fallback", type(e).__name__)
            return {
                "analyzed": len(critical) if critical else 0,
                "decision": "review",
                "method": "fallback",
                "reason": f"Council error: {type(e).__name__}",
                "session_id": session_id,
            }

    def record_analyst_feedback(
        self,
        finding_id: str,
        analyst_id: str,
        original_action: str,
        new_action: str,
        reason: str,
        org_id: str,
    ) -> str:
        """Record analyst override for continuous learning.

        Args:
            finding_id: Finding that was overridden
            analyst_id: Email/ID of analyst
            original_action: What council recommended
            new_action: What analyst chose
            reason: Why it was overridden
            org_id: Organization ID

        Returns:
            record_id of the override
        """
        feedback_loop = self._ensure_feedback()
        if not feedback_loop:
            logger.warning("DecisionFeedbackLoop not available; skipping feedback record")
            return ""

        try:
            record_id = feedback_loop.record_override(
                finding_id=finding_id,
                original_action=original_action,
                new_action=new_action,
                analyst_id=analyst_id,
                reason=reason,
                org_id=org_id,
            )
            logger.info(
                "Analyst feedback recorded: %s -> %s (analyst=%s)",
                original_action,
                new_action,
                analyst_id
            )
            return record_id
        except (ValueError, RuntimeError, TypeError) as e:
            logger.error("Failed to record analyst feedback: %s", e)
            return ""

    def get_council_stats(self) -> Dict[str, Any]:
        """Get council performance metrics and session history.

        Returns:
            Dict with accuracy metrics, escalation rate, session count, etc.
        """
        store = self._ensure_memory()

        with self._lock:
            total_sessions = len(self._session_history)
            escalations = sum(1 for s in self._session_history if s.get("escalated"))
            total_findings = sum(s.get("findings_analyzed", 0) for s in self._session_history)
            total_cost = sum(s.get("cost_usd", 0) for s in self._session_history)
            avg_latency = (
                sum(s.get("latency_ms", 0) for s in self._session_history) / total_sessions
                if total_sessions > 0 else 0
            )

            decision_distribution = {}
            for session in self._session_history:
                decision = session.get("decision", "unknown")
                decision_distribution[decision] = decision_distribution.get(decision, 0) + 1

        stats = {
            "total_sessions": total_sessions,
            "total_findings_analyzed": total_findings,
            "escalation_count": escalations,
            "escalation_rate": escalations / total_sessions if total_sessions > 0 else 0,
            "avg_latency_ms": round(avg_latency, 2),
            "total_cost_usd": round(total_cost, 6),
            "decision_distribution": decision_distribution,
            "recent_sessions": len(self._session_history[-10:]),
        }

        # Append accuracy stats from memory if available
        if store:
            try:
                org_id = os.environ.get("FIXOPS_ORG_ID", "default")
                accuracy = store.get_accuracy_stats(org_id)
                stats.update({
                    "accuracy_stats": accuracy.to_dict(),
                    "override_rate": accuracy.override_rate,
                    "false_positive_rate": accuracy.false_positive_rate,
                })
            except (ValueError, KeyError, TypeError) as e:
                logger.warning("Failed to fetch accuracy stats: %s", e)

        return stats


# ===========================================================================
# Factory Function
# ===========================================================================


def create_consensus_engine_replacement(
    council: Optional[Any] = None,
    memory_store: Optional[Any] = None,
    feedback_loop: Optional[Any] = None,
) -> CouncilPipelineAdapter:
    """
    Create a drop-in replacement for the old ConsensusEngine.

    This is the entry point for wiring the Council into brain_pipeline.py.

    Example:
        from core.council_pipeline_adapter import create_consensus_engine_replacement

        # In brain_pipeline._step_llm_consensus():
        council_adapter = create_consensus_engine_replacement()
        result = council_adapter.analyse(prompt=prompt, context=ctx, findings=critical)

        # result is compatible with old ConsensusEngine format

    Args:
        council: Optional pre-configured LLMCouncilEngine (lazy-init if None)
        memory_store: Optional DecisionMemoryStore (lazy-init if None)
        feedback_loop: Optional DecisionFeedbackLoop (lazy-init if None)

    Returns:
        CouncilPipelineAdapter configured as drop-in ConsensusEngine replacement
    """
    return CouncilPipelineAdapter(
        council=council,
        memory_store=memory_store,
        feedback_loop=feedback_loop,
    )


# ===========================================================================
# Wiring Instructions (for brain_pipeline.py)
# ===========================================================================

"""
TO WIRE INTO brain_pipeline.py (line ~2945):

BEFORE (existing code):
    def _step_llm_consensus(self, ctx: Dict[str, Any], inp: PipelineInput) -> Dict[str, Any]:
        # ... finds critical findings ...
        result = consensus_engine.analyse(prompt=prompt, context=ctx)
        # ... processes result ...

AFTER (with Council):
    def _step_llm_consensus(self, ctx: Dict[str, Any], inp: PipelineInput) -> Dict[str, Any]:
        # ... finds critical findings ...

        # Replace the consensus engine call with council adapter
        from core.council_pipeline_adapter import create_consensus_engine_replacement
        council_adapter = create_consensus_engine_replacement()

        result = council_adapter.analyse(
            prompt=prompt,
            context=ctx,
            findings=critical  # Pass the critical findings
        )

        # result format is identical to old ConsensusEngine, so rest of code is unchanged
        ctx["llm_results"] = [result]
        return {
            "analyzed": result.get("analyzed", 0),
            "decision": result.get("decision", "review"),
            "method": result.get("method", "council"),
            "confidence": result.get("confidence", 0.5),
            "consensus_pct": result.get("consensus_pct", 0.0),
            ...
        }

ENVIRONMENT VARIABLES:
    FIXOPS_USE_COUNCIL=1              # Enable council (already used in brain_pipeline)
    FIXOPS_MAX_LLM_FINDINGS=50        # Max findings to analyze per run
    FIXOPS_DECISION_MEMORY_DB=...     # Path to decision memory SQLite database
    FIXOPS_ANTHROPIC_MODEL=...        # Override Anthropic model (for Opus escalation)
    FIXOPS_ORG_ID=...                 # Organization ID for decision records

AUDIT TRAIL:
    1. All decisions recorded in DecisionMemoryStore
    2. Analyst overrides tracked via DecisionFeedbackLoop
    3. Escalations logged with cost and reason
    4. Session history maintained for performance metrics
    5. Accuracy statistics available via get_council_stats()
"""
