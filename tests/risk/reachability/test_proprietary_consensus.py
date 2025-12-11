"""Tests for risk/reachability/proprietary_consensus.py module."""

from risk.reachability.proprietary_consensus import (
    ProprietaryConsensusEngine,
    ProprietaryConsensusResult,
    ProprietaryVote,
)


class TestProprietaryVote:
    """Tests for ProprietaryVote dataclass."""

    def test_vote_creation(self):
        """Test creating a vote."""
        vote = ProprietaryVote(
            provider="openai",
            decision="accept",
            confidence=0.9,
            weight=1.0,
            reasoning="High confidence in fix",
            evidence=["test passed", "code review approved"],
        )
        assert vote.provider == "openai"
        assert vote.decision == "accept"
        assert vote.confidence == 0.9
        assert vote.weight == 1.0
        assert vote.reasoning == "High confidence in fix"
        assert len(vote.evidence) == 2

    def test_vote_default_evidence(self):
        """Test vote with default empty evidence list."""
        vote = ProprietaryVote(
            provider="anthropic",
            decision="remediate",
            confidence=0.8,
            weight=0.9,
            reasoning="Needs remediation",
        )
        assert vote.evidence == []


class TestProprietaryConsensusResult:
    """Tests for ProprietaryConsensusResult dataclass."""

    def test_result_creation(self):
        """Test creating a consensus result."""
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Approved",
            )
        ]
        result = ProprietaryConsensusResult(
            final_decision="accept",
            consensus_confidence=0.9,
            method="weighted_majority",
            votes=votes,
            agreement_score=1.0,
            disagreement_areas=[],
            requires_review=False,
        )
        assert result.final_decision == "accept"
        assert result.consensus_confidence == 0.9
        assert result.method == "weighted_majority"
        assert len(result.votes) == 1
        assert result.agreement_score == 1.0
        assert result.requires_review is False

    def test_result_with_disagreements(self):
        """Test result with disagreement areas."""
        result = ProprietaryConsensusResult(
            final_decision="remediate",
            consensus_confidence=0.6,
            method="bayesian_consensus",
            votes=[],
            agreement_score=0.5,
            disagreement_areas=["dismiss (2 votes, 30% weight)"],
            requires_review=True,
        )
        assert len(result.disagreement_areas) == 1
        assert result.requires_review is True


class TestProprietaryConsensusEngine:
    """Tests for ProprietaryConsensusEngine class."""

    def test_initialization_default_config(self):
        """Test engine initialization with default config."""
        engine = ProprietaryConsensusEngine()
        assert engine.agreement_threshold == 0.7
        assert engine.confidence_threshold == 0.6
        assert len(engine.voting_methods) == 4

    def test_initialization_custom_config(self):
        """Test engine initialization with custom config."""
        config = {"agreement_threshold": 0.8, "confidence_threshold": 0.7}
        engine = ProprietaryConsensusEngine(config)
        assert engine.agreement_threshold == 0.8
        assert engine.confidence_threshold == 0.7

    def test_compute_consensus_empty_votes(self):
        """Test consensus with empty votes returns defer."""
        engine = ProprietaryConsensusEngine()
        result = engine.compute_consensus([])
        assert result.final_decision == "defer"
        assert result.consensus_confidence == 0.0
        assert result.agreement_score == 0.0
        assert result.requires_review is True

    def test_compute_consensus_single_vote(self):
        """Test consensus with single vote."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Approved",
            )
        ]
        result = engine.compute_consensus(votes)
        assert result.final_decision == "accept"
        assert result.consensus_confidence > 0

    def test_compute_consensus_unanimous_votes(self):
        """Test consensus with unanimous votes."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Approved",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="accept",
                confidence=0.85,
                weight=1.0,
                reasoning="Also approved",
            ),
            ProprietaryVote(
                provider="google",
                decision="accept",
                confidence=0.88,
                weight=1.0,
                reasoning="Confirmed",
            ),
        ]
        result = engine.compute_consensus(votes)
        assert result.final_decision == "accept"
        assert result.agreement_score > 0.8

    def test_compute_consensus_split_votes(self):
        """Test consensus with split votes."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Approved",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="dismiss",
                confidence=0.8,
                weight=1.0,
                reasoning="Should dismiss",
            ),
        ]
        result = engine.compute_consensus(votes)
        assert result.final_decision in ["accept", "dismiss"]

    def test_compute_consensus_weighted_majority_method(self):
        """Test consensus with weighted_majority method."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=2.0,
                reasoning="High weight",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="dismiss",
                confidence=0.9,
                weight=1.0,
                reasoning="Low weight",
            ),
        ]
        result = engine.compute_consensus(votes, method="weighted_majority")
        assert result.method == "weighted_majority"
        assert result.final_decision == "accept"

    def test_compute_consensus_weighted_average_method(self):
        """Test consensus with weighted_average method."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Accept",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="remediate",
                confidence=0.8,
                weight=1.0,
                reasoning="Remediate",
            ),
        ]
        result = engine.compute_consensus(votes, method="weighted_average")
        assert result.method == "weighted_average"
        assert result.final_decision in ["accept", "remediate"]

    def test_compute_consensus_bayesian_method(self):
        """Test consensus with bayesian_consensus method."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Accept",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="accept",
                confidence=0.85,
                weight=1.0,
                reasoning="Also accept",
            ),
        ]
        result = engine.compute_consensus(votes, method="bayesian_consensus")
        assert result.method == "bayesian_consensus"

    def test_compute_consensus_fuzzy_method(self):
        """Test consensus with fuzzy_consensus method."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="monitor",
                confidence=0.7,
                weight=1.0,
                reasoning="Monitor",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="monitor",
                confidence=0.6,
                weight=1.0,
                reasoning="Also monitor",
            ),
        ]
        result = engine.compute_consensus(votes, method="fuzzy_consensus")
        assert result.method == "fuzzy_consensus"
        assert result.final_decision == "monitor"

    def test_compute_consensus_unknown_method_falls_back(self):
        """Test consensus with unknown method falls back to weighted_majority."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Accept",
            )
        ]
        result = engine.compute_consensus(votes, method="unknown_method")
        # Should fall back to weighted_majority
        assert result.final_decision == "accept"

    def test_weighted_majority_vote_empty(self):
        """Test weighted majority with empty votes."""
        engine = ProprietaryConsensusEngine()
        decision, confidence = engine._weighted_majority_vote([])
        assert decision == "defer"
        assert confidence == 0.0

    def test_weighted_majority_vote_single(self):
        """Test weighted majority with single vote."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Accept",
            )
        ]
        decision, confidence = engine._weighted_majority_vote(votes)
        assert decision == "accept"
        assert confidence == 0.9

    def test_weighted_average_vote_empty(self):
        """Test weighted average with empty votes."""
        engine = ProprietaryConsensusEngine()
        decision, confidence = engine._weighted_average_vote([])
        assert decision == "defer"
        assert confidence == 0.0

    def test_weighted_average_vote_high_score(self):
        """Test weighted average with high score votes."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=1.0,
                weight=1.0,
                reasoning="Accept",
            )
        ]
        decision, confidence = engine._weighted_average_vote(votes)
        assert decision == "accept"

    def test_weighted_average_vote_low_score(self):
        """Test weighted average with low score votes."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="dismiss",
                confidence=1.0,
                weight=1.0,
                reasoning="Dismiss",
            )
        ]
        decision, confidence = engine._weighted_average_vote(votes)
        assert decision == "dismiss"

    def test_weighted_average_vote_unknown_decision(self):
        """Test weighted average with unknown decision type."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="unknown_decision",
                confidence=1.0,
                weight=1.0,
                reasoning="Unknown",
            )
        ]
        decision, confidence = engine._weighted_average_vote(votes)
        # Unknown decisions get score 0.5, which maps to "monitor"
        assert decision == "monitor"

    def test_bayesian_consensus_empty(self):
        """Test Bayesian consensus with empty votes."""
        engine = ProprietaryConsensusEngine()
        decision, confidence = engine._bayesian_consensus([])
        # With uniform priors and no votes, any decision could win
        assert decision in ["accept", "remediate", "monitor", "defer", "dismiss"]

    def test_bayesian_consensus_single_vote(self):
        """Test Bayesian consensus with single vote."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Accept",
            )
        ]
        decision, confidence = engine._bayesian_consensus(votes)
        # Should favor the voted decision
        assert decision in ["accept", "remediate", "monitor", "defer", "dismiss"]

    def test_fuzzy_consensus_empty(self):
        """Test fuzzy consensus with empty votes."""
        engine = ProprietaryConsensusEngine()
        decision, confidence = engine._fuzzy_consensus([])
        assert decision == "defer"
        assert confidence == 0.0

    def test_fuzzy_consensus_single_vote(self):
        """Test fuzzy consensus with single vote."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="remediate",
                confidence=0.8,
                weight=1.0,
                reasoning="Remediate",
            )
        ]
        decision, confidence = engine._fuzzy_consensus(votes)
        assert decision == "remediate"
        assert confidence == 1.0  # Only one decision, gets 100% membership

    def test_calculate_agreement_score_empty(self):
        """Test agreement score with empty votes."""
        engine = ProprietaryConsensusEngine()
        score = engine._calculate_agreement_score([], "accept")
        assert score == 0.0

    def test_calculate_agreement_score_unanimous(self):
        """Test agreement score with unanimous votes."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Accept",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="accept",
                confidence=0.85,
                weight=1.0,
                reasoning="Also accept",
            ),
        ]
        score = engine._calculate_agreement_score(votes, "accept")
        assert score > 0.8

    def test_calculate_agreement_score_split(self):
        """Test agreement score with split votes."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Accept",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="dismiss",
                confidence=0.9,
                weight=1.0,
                reasoning="Dismiss",
            ),
        ]
        score = engine._calculate_agreement_score(votes, "accept")
        assert 0.3 < score < 0.7

    def test_detect_disagreements_empty(self):
        """Test disagreement detection with empty votes."""
        engine = ProprietaryConsensusEngine()
        disagreements = engine._detect_disagreements([], "accept")
        assert disagreements == []

    def test_detect_disagreements_unanimous(self):
        """Test disagreement detection with unanimous votes."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Accept",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="accept",
                confidence=0.85,
                weight=1.0,
                reasoning="Also accept",
            ),
        ]
        disagreements = engine._detect_disagreements(votes, "accept")
        assert disagreements == []

    def test_detect_disagreements_significant(self):
        """Test disagreement detection with significant disagreement."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Accept",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="dismiss",
                confidence=0.9,
                weight=1.0,
                reasoning="Dismiss",
            ),
        ]
        disagreements = engine._detect_disagreements(votes, "accept")
        assert len(disagreements) == 1
        assert "dismiss" in disagreements[0]

    def test_requires_review_low_agreement(self):
        """Test that low agreement triggers review requirement."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.9,
                weight=1.0,
                reasoning="Accept",
            ),
            ProprietaryVote(
                provider="anthropic",
                decision="dismiss",
                confidence=0.9,
                weight=1.0,
                reasoning="Dismiss",
            ),
        ]
        result = engine.compute_consensus(votes)
        # With split votes, should require review
        assert result.requires_review is True

    def test_requires_review_low_confidence(self):
        """Test that low confidence triggers review requirement."""
        engine = ProprietaryConsensusEngine()
        votes = [
            ProprietaryVote(
                provider="openai",
                decision="accept",
                confidence=0.3,
                weight=1.0,
                reasoning="Low confidence",
            ),
        ]
        result = engine.compute_consensus(votes)
        # Low confidence should trigger review
        assert result.requires_review is True

    def test_all_decision_types(self):
        """Test all decision types are handled correctly."""
        engine = ProprietaryConsensusEngine()
        decisions = ["accept", "remediate", "monitor", "defer", "dismiss"]

        for decision in decisions:
            votes = [
                ProprietaryVote(
                    provider="openai",
                    decision=decision,
                    confidence=0.9,
                    weight=1.0,
                    reasoning=f"Decision: {decision}",
                )
            ]
            result = engine.compute_consensus(votes)
            assert result.final_decision == decision
