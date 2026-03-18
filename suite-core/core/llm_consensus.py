"""
Multi-LLM Consensus Engine — GPT-4 + Claude + Gemini voting.

Sends the same security analysis prompt to multiple LLM providers
concurrently and merges their responses via weighted majority voting.

Consensus threshold (default 85%): the proportion of providers that
must agree on the recommended_action for the result to be considered
"consensus". Below threshold → flags as "dissent" for human review.

Usage:
    from core.llm_consensus import ConsensusEngine

    engine = ConsensusEngine(threshold=0.85)
    result = engine.analyse(
        prompt="Analyse CVE-2024-3094 ...",
        context={"service_name": "api-gateway", ...},
    )
    # result.consensus → True/False
    # result.action → "patch"
    # result.confidence → 0.92
    # result.votes → {"openai": "patch", "anthropic": "patch", "gemini": "patch"}
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Sequence

from core.llm_providers import (
    LLMProviderManager,
    LLMResponse,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Consensus result dataclass
# ---------------------------------------------------------------------------


@dataclass
class ConsensusResult:
    """Output of multi-LLM consensus voting."""

    # Consensus outcome
    consensus: bool = False                 # Did we reach threshold?
    action: str = "review"                  # Winning action
    confidence: float = 0.0                 # Averaged confidence
    agreement_ratio: float = 0.0            # 0.0-1.0 agreement on action
    threshold: float = 0.85                 # Required agreement

    # Merged analysis
    reasoning: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    compliance_concerns: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)

    # Per-provider breakdown
    votes: Dict[str, str] = field(default_factory=dict)          # provider → action
    confidences: Dict[str, float] = field(default_factory=dict)  # provider → score
    provider_responses: Dict[str, LLMResponse] = field(default_factory=dict)
    provider_errors: Dict[str, str] = field(default_factory=dict)

    # Timing
    total_ms: float = 0.0
    provider_ms: Dict[str, float] = field(default_factory=dict)

    # Dissent detail
    dissenting_providers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "consensus": self.consensus,
            "action": self.action,
            "confidence": round(self.confidence, 3),
            "agreement_ratio": round(self.agreement_ratio, 3),
            "threshold": self.threshold,
            "reasoning": self.reasoning,
            "mitre_techniques": self.mitre_techniques,
            "compliance_concerns": self.compliance_concerns,
            "attack_vectors": self.attack_vectors,
            "votes": self.votes,
            "confidences": {k: round(v, 3) for k, v in self.confidences.items()},
            "dissenting_providers": self.dissenting_providers,
            "total_ms": round(self.total_ms, 2),
            "provider_ms": {k: round(v, 2) for k, v in self.provider_ms.items()},
            "provider_count": len(self.votes),
            "errors": self.provider_errors,
        }


# ---------------------------------------------------------------------------
# Provider weights for voting
# ---------------------------------------------------------------------------

DEFAULT_PROVIDER_WEIGHTS: Dict[str, float] = {
    "openai": 1.0,
    "anthropic": 1.0,
    "gemini": 0.8,
    "sentinel": 0.6,  # Deterministic heuristic — lower weight
}


# ---------------------------------------------------------------------------
# Consensus Engine
# ---------------------------------------------------------------------------


class ConsensusEngine:
    """
    Multi-LLM consensus engine with weighted majority voting.

    Sends analysis requests to multiple providers in parallel and
    determines consensus based on configurable threshold.
    """

    def __init__(
        self,
        *,
        threshold: float = 0.85,
        providers: Sequence[str] | None = None,
        provider_weights: Dict[str, float] | None = None,
        max_workers: int = 4,
        manager: LLMProviderManager | None = None,
    ):
        self.threshold = threshold
        self.provider_names = list(providers or ["openai", "anthropic", "gemini"])
        self.weights = dict(provider_weights or DEFAULT_PROVIDER_WEIGHTS)
        self.max_workers = max_workers
        self._manager = manager or LLMProviderManager()
        self._history: List[ConsensusResult] = []

    # ------------------------------------------------------------------
    # Main consensus API
    # ------------------------------------------------------------------

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str = "review",
        default_confidence: float = 0.5,
        default_reasoning: str = "Heuristic analysis",
        mitigation_hints: Mapping[str, Any] | None = None,
    ) -> ConsensusResult:
        """
        Run the prompt through all configured providers and vote.

        Returns ConsensusResult with consensus=True if agreement ≥ threshold.
        """
        wall_start = time.perf_counter()

        # Collect responses in parallel
        responses: Dict[str, LLMResponse] = {}
        timings: Dict[str, float] = {}
        errors: Dict[str, str] = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {}
            for name in self.provider_names:
                future = pool.submit(
                    self._call_provider,
                    name,
                    prompt=prompt,
                    context=context,
                    default_action=default_action,
                    default_confidence=default_confidence,
                    default_reasoning=default_reasoning,
                    mitigation_hints=mitigation_hints,
                )
                futures[future] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    resp, duration_ms = future.result()
                    responses[name] = resp
                    timings[name] = duration_ms
                except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                    logger.warning("Provider %s failed in consensus: %s", name, exc)
                    errors[name] = str(exc)

        if not responses:
            # All providers failed → deterministic fallback
            logger.error("All consensus providers failed, using deterministic fallback")
            result = ConsensusResult(
                consensus=False,
                action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[ALL providers failed]",
                provider_errors=errors,
                total_ms=(time.perf_counter() - wall_start) * 1000,
            )
            self._history.append(result)
            return result

        # Vote: weighted majority
        result = self._vote(
            responses,
            timings=timings,
            errors=errors,
            default_action=default_action,
        )
        result.total_ms = (time.perf_counter() - wall_start) * 1000

        self._history.append(result)
        logger.info(
            "Consensus: %s (%.0f%% agreement, action=%s, %d providers, %.0fms)",
            "REACHED" if result.consensus else "DISSENT",
            result.agreement_ratio * 100,
            result.action,
            len(responses),
            result.total_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Provider invocation
    # ------------------------------------------------------------------

    def _call_provider(
        self,
        name: str,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None,
    ) -> tuple[LLMResponse, float]:
        """Call a single provider and return (response, duration_ms)."""
        start = time.perf_counter()
        provider = self._manager.get_provider(name)
        resp = provider.analyse(
            prompt=prompt,
            context=context,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
        )
        duration_ms = (time.perf_counter() - start) * 1000
        return resp, duration_ms

    # ------------------------------------------------------------------
    # Voting algorithm
    # ------------------------------------------------------------------

    def _vote(
        self,
        responses: Dict[str, LLMResponse],
        *,
        timings: Dict[str, float],
        errors: Dict[str, str],
        default_action: str,
    ) -> ConsensusResult:
        """Weighted majority voting on provider responses."""

        # Extract votes
        votes: Dict[str, str] = {}
        confidences: Dict[str, float] = {}
        for name, resp in responses.items():
            action = (resp.recommended_action or default_action).strip().lower()
            votes[name] = action
            confidences[name] = resp.confidence

        # Weighted vote tally
        weighted_counts: Dict[str, float] = {}
        total_weight = 0.0
        for name, action in votes.items():
            w = self.weights.get(name, 1.0)
            weighted_counts[action] = weighted_counts.get(action, 0.0) + w
            total_weight += w

        # Find winner
        winning_action = max(weighted_counts, key=lambda k: weighted_counts[k])
        winning_weight = weighted_counts[winning_action]
        agreement_ratio = winning_weight / total_weight if total_weight > 0 else 0.0

        consensus = agreement_ratio >= self.threshold

        # Identify dissenters
        dissenting = [name for name, action in votes.items() if action != winning_action]

        # Merge analysis from all providers
        all_mitre: List[str] = []
        all_compliance: List[str] = []
        all_attack_vectors: List[str] = []
        reasoning_parts: List[str] = []

        for name, resp in responses.items():
            if resp.mitre_techniques:
                all_mitre.extend(resp.mitre_techniques)
            if resp.compliance_concerns:
                all_compliance.extend(resp.compliance_concerns)
            if resp.attack_vectors:
                all_attack_vectors.extend(resp.attack_vectors)
            if resp.reasoning:
                reasoning_parts.append(f"[{name}] {resp.reasoning}")

        # Deduplicate
        merged_mitre = list(dict.fromkeys(all_mitre))
        merged_compliance = list(dict.fromkeys(all_compliance))
        merged_vectors = list(dict.fromkeys(all_attack_vectors))

        # Average confidence (weighted)
        avg_conf = 0.0
        if total_weight > 0:
            for name, conf in confidences.items():
                w = self.weights.get(name, 1.0)
                avg_conf += conf * w
            avg_conf /= total_weight

        # Build merged reasoning
        merged_reasoning = "\n\n".join(reasoning_parts)
        if not consensus:
            merged_reasoning = (
                f"⚠ DISSENT: Only {agreement_ratio*100:.0f}% agreement "
                f"(threshold: {self.threshold*100:.0f}%). "
                f"Dissenting: {', '.join(dissenting)}.\n\n{merged_reasoning}"
            )

        return ConsensusResult(
            consensus=consensus,
            action=winning_action,
            confidence=avg_conf,
            agreement_ratio=agreement_ratio,
            threshold=self.threshold,
            reasoning=merged_reasoning,
            mitre_techniques=merged_mitre,
            compliance_concerns=merged_compliance,
            attack_vectors=merged_vectors,
            votes=votes,
            confidences=confidences,
            provider_responses=responses,
            provider_errors=errors,
            provider_ms=timings,
            dissenting_providers=dissenting,
        )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @property
    def history(self) -> List[ConsensusResult]:
        return list(self._history)

    def stats(self) -> Dict[str, Any]:
        """Aggregate consensus statistics."""
        if not self._history:
            return {"total_analyses": 0}

        consensus_count = sum(1 for r in self._history if r.consensus)
        avg_agreement = (
            sum(r.agreement_ratio for r in self._history) / len(self._history)
        )
        avg_confidence = (
            sum(r.confidence for r in self._history) / len(self._history)
        )
        avg_ms = sum(r.total_ms for r in self._history) / len(self._history)

        # Action distribution
        action_dist: Dict[str, int] = {}
        for r in self._history:
            action_dist[r.action] = action_dist.get(r.action, 0) + 1

        return {
            "total_analyses": len(self._history),
            "consensus_reached": consensus_count,
            "dissent_count": len(self._history) - consensus_count,
            "consensus_rate": round(consensus_count / len(self._history), 3),
            "average_agreement": round(avg_agreement, 3),
            "average_confidence": round(avg_confidence, 3),
            "average_latency_ms": round(avg_ms, 2),
            "action_distribution": action_dist,
        }


__all__ = [
    "ConsensusEngine",
    "ConsensusResult",
    "DEFAULT_PROVIDER_WEIGHTS",
]
