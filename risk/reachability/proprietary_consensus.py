"""Proprietary FixOps consensus algorithm - no OSS dependencies.

This is FixOps' proprietary multi-LLM consensus algorithm that doesn't
rely on any open source consensus libraries. Built from scratch.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ProprietaryVote:
    """Proprietary vote representation."""

    provider: str
    decision: str
    confidence: float
    weight: float
    reasoning: str
    evidence: List[str] = field(default_factory=list)


@dataclass
class ProprietaryConsensusResult:
    """Proprietary consensus result."""

    final_decision: str
    consensus_confidence: float
    method: str
    votes: List[ProprietaryVote]
    agreement_score: float
    disagreement_areas: List[str] = field(default_factory=list)
    requires_review: bool = False


class ProprietaryConsensusEngine:
    """Proprietary consensus engine - custom algorithms."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize proprietary consensus engine."""
        self.config = config or {}

        # Proprietary voting methods
        self.voting_methods = {
            "weighted_majority": self._weighted_majority_vote,
            "weighted_average": self._weighted_average_vote,
            "bayesian_consensus": self._bayesian_consensus,
            "fuzzy_consensus": self._fuzzy_consensus,
        }

        # Proprietary agreement thresholds
        self.agreement_threshold = self.config.get("agreement_threshold", 0.7)
        self.confidence_threshold = self.config.get("confidence_threshold", 0.6)

    def compute_consensus(
        self,
        votes: List[ProprietaryVote],
        method: str = "weighted_majority",
    ) -> ProprietaryConsensusResult:
        """Proprietary consensus computation."""

        if not votes:
            return ProprietaryConsensusResult(
                final_decision="defer",
                consensus_confidence=0.0,
                method=method,
                votes=[],
                agreement_score=0.0,
                requires_review=True,
            )

        # Select voting method
        vote_func = self.voting_methods.get(method, self._weighted_majority_vote)

        # Compute consensus
        decision, confidence = vote_func(votes)

        # Calculate agreement score
        agreement_score = self._calculate_agreement_score(votes, decision)

        # Detect disagreements
        disagreement_areas = self._detect_disagreements(votes, decision)

        # Determine if review needed
        requires_review = (
            agreement_score < self.agreement_threshold
            or confidence < self.confidence_threshold
            or len(disagreement_areas) > 0
        )

        return ProprietaryConsensusResult(
            final_decision=decision,
            consensus_confidence=confidence,
            method=method,
            votes=votes,
            agreement_score=agreement_score,
            disagreement_areas=disagreement_areas,
            requires_review=requires_review,
        )

    def _weighted_majority_vote(
        self, votes: List[ProprietaryVote]
    ) -> Tuple[str, float]:
        """Proprietary weighted majority voting."""

        decision_votes: Dict[str, float] = {}
        total_weight = 0.0

        for vote in votes:
            decision = vote.decision
            # Weight by provider weight and confidence
            vote_weight = vote.weight * vote.confidence
            decision_votes[decision] = decision_votes.get(decision, 0.0) + vote_weight
            total_weight += vote.weight

        if not decision_votes:
            return ("defer", 0.0)

        # Find winning decision
        winning_decision = max(decision_votes.items(), key=lambda x: x[1])[0]
        winning_votes = decision_votes[winning_decision]

        # Confidence is proportion of weighted votes
        confidence = winning_votes / total_weight if total_weight > 0 else 0.0

        return (winning_decision, confidence)

    def _weighted_average_vote(self, votes: List[ProprietaryVote]) -> Tuple[str, float]:
        """Proprietary weighted average voting."""

        # Map decisions to numeric scores
        decision_scores = {
            "accept": 1.0,
            "remediate": 0.8,
            "monitor": 0.5,
            "defer": 0.3,
            "dismiss": 0.1,
        }

        weighted_sum = 0.0
        total_weight = 0.0

        for vote in votes:
            score = decision_scores.get(vote.decision, 0.5)
            weight = vote.weight * vote.confidence
            weighted_sum += score * weight
            total_weight += weight

        if total_weight == 0:
            return ("defer", 0.0)

        average_score = weighted_sum / total_weight

        # Map back to decision
        if average_score >= 0.8:
            decision = "accept"
        elif average_score >= 0.6:
            decision = "remediate"
        elif average_score >= 0.4:
            decision = "monitor"
        elif average_score >= 0.2:
            decision = "defer"
        else:
            decision = "dismiss"

        confidence = min(1.0, average_score * 1.2)  # Scale confidence

        return (decision, confidence)

    def _bayesian_consensus(self, votes: List[ProprietaryVote]) -> Tuple[str, float]:
        """Proprietary Bayesian consensus algorithm."""

        # Prior probability for each decision
        decisions = ["accept", "remediate", "monitor", "defer", "dismiss"]
        priors = {d: 0.2 for d in decisions}  # Uniform prior

        # Update with each vote (Bayesian update)
        posteriors = priors.copy()

        for vote in votes:
            decision = vote.decision
            if decision in posteriors:
                # Bayesian update: P(decision|vote) = P(vote|decision) * P(decision) / P(vote)
                likelihood = vote.confidence
                prior = posteriors[decision]

                # Normalize
                evidence = sum(
                    v.confidence * v.weight for v in votes if v.decision == decision
                )

                if evidence > 0:
                    posterior = (likelihood * prior) / evidence
                    posteriors[decision] = posterior

        # Normalize posteriors
        total = sum(posteriors.values())
        if total > 0:
            posteriors = {k: v / total for k, v in posteriors.items()}

        # Find decision with highest posterior
        winning_decision = max(posteriors.items(), key=lambda x: x[1])[0]
        confidence = posteriors[winning_decision]

        return (winning_decision, confidence)

    def _fuzzy_consensus(self, votes: List[ProprietaryVote]) -> Tuple[str, float]:
        """Proprietary fuzzy consensus algorithm."""

        # Fuzzy membership functions for decisions
        decision_memberships: Dict[str, float] = {}

        for vote in votes:
            decision = vote.decision
            membership = vote.confidence * vote.weight

            if decision not in decision_memberships:
                decision_memberships[decision] = 0.0

            decision_memberships[decision] += membership

        if not decision_memberships:
            return ("defer", 0.0)

        # Normalize memberships
        total_membership = sum(decision_memberships.values())
        if total_membership > 0:
            decision_memberships = {
                k: v / total_membership for k, v in decision_memberships.items()
            }

        # Find decision with highest membership
        winning_decision = max(decision_memberships.items(), key=lambda x: x[1])[0]
        confidence = decision_memberships[winning_decision]

        return (winning_decision, confidence)

    def _calculate_agreement_score(
        self, votes: List[ProprietaryVote], decision: str
    ) -> float:
        """Proprietary agreement score calculation."""

        if not votes:
            return 0.0

        # Count votes for winning decision
        agreeing_votes = [v for v in votes if v.decision == decision]

        # Weighted agreement
        total_weight = sum(v.weight for v in votes)
        agreeing_weight = sum(v.weight for v in agreeing_votes)

        agreement = agreeing_weight / total_weight if total_weight > 0 else 0.0

        # Boost agreement if confidences are high
        avg_confidence = (
            sum(v.confidence for v in agreeing_votes) / len(agreeing_votes)
            if agreeing_votes
            else 0.0
        )

        # Combined agreement score
        agreement_score = (agreement * 0.7) + (avg_confidence * 0.3)

        return min(1.0, max(0.0, agreement_score))

    def _detect_disagreements(
        self, votes: List[ProprietaryVote], decision: str
    ) -> List[str]:
        """Proprietary disagreement detection."""

        disagreements = []

        # Group votes by decision
        decision_groups: Dict[str, List[ProprietaryVote]] = defaultdict(list)
        for vote in votes:
            decision_groups[vote.decision].append(vote)

        # Check for significant disagreements
        for other_decision, other_votes in decision_groups.items():
            if other_decision == decision:
                continue

            other_weight = sum(v.weight for v in other_votes)
            total_weight = sum(v.weight for v in votes)

            if other_weight / total_weight > 0.3:  # 30% disagreement threshold
                disagreements.append(
                    f"{other_decision} ({len(other_votes)} votes, "
                    f"{other_weight/total_weight:.1%} weight)"
                )

        return disagreements
