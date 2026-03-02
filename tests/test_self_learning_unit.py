"""Unit tests for SelfLearningEngine (V8 — 5 Feedback Loops).

Tests cover:
- FeedbackType, OutcomeStatus enums
- LearningConfig dataclass and from_env factory
- FeedbackRecord, LearningAdjustment dataclasses
- FeedbackDB: store/retrieve feedback, weights, metrics
- 5 feedback loops: DecisionOutcome, MPTEResult, FalsePositive, RemediationSuccess, PolicyViolation
- SelfLearningEngine: analyze_all, get_insights, get_status, get/set_weight
- get_learning_engine singleton

Pillar: V8 (Self-Learning) — DESIGN CONSTRAINT, tested for integrity
Agent: agent-doctor (run v6 — 2026-03-01)
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.self_learning import (
    FeedbackType,
    OutcomeStatus,
    LearningConfig,
    FeedbackRecord,
    LearningAdjustment,
    FeedbackDB,
    DecisionOutcomeLoop,
    MPTEResultLoop,
    FalsePositiveLoop,
    RemediationSuccessLoop,
    PolicyViolationLoop,
    SelfLearningEngine,
    get_learning_engine,
)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------
class TestFeedbackType:
    def test_values(self):
        assert FeedbackType.DECISION_OUTCOME == "decision_outcome"
        assert FeedbackType.MPTE_RESULT == "mpte_result"
        assert FeedbackType.FALSE_POSITIVE == "false_positive"
        assert FeedbackType.REMEDIATION_SUCCESS == "remediation_success"
        assert FeedbackType.POLICY_VIOLATION == "policy_violation"

    def test_count(self):
        assert len(FeedbackType) == 5


class TestOutcomeStatus:
    def test_values(self):
        assert OutcomeStatus.CORRECT == "correct"
        assert OutcomeStatus.INCORRECT == "incorrect"
        assert OutcomeStatus.PARTIAL == "partial"
        assert OutcomeStatus.UNKNOWN == "unknown"

    def test_count(self):
        assert len(OutcomeStatus) == 4


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------
class TestLearningConfig:
    def test_defaults(self):
        cfg = LearningConfig()
        assert cfg.enabled is True
        assert cfg.min_samples == 10
        assert cfg.decay_factor == 0.95
        assert cfg.adjustment_threshold == 0.15
        assert cfg.max_weight_change == 0.3

    def test_from_env_defaults(self):
        cfg = LearningConfig.from_env()
        assert isinstance(cfg, LearningConfig)
        assert cfg.enabled is True

    def test_from_env_custom(self):
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("FIXOPS_LEARNING_ENABLED", "false")
            mp.setenv("FIXOPS_LEARNING_MIN_SAMPLES", "20")
            mp.setenv("FIXOPS_LEARNING_DECAY_FACTOR", "0.9")
            cfg = LearningConfig.from_env()
            assert cfg.enabled is False
            assert cfg.min_samples == 20
            assert cfg.decay_factor == 0.9


# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------
class TestFeedbackRecord:
    def test_creation(self):
        rec = FeedbackRecord(
            feedback_id="test-001",
            feedback_type=FeedbackType.DECISION_OUTCOME,
            entity_id="VULN-001",
            outcome=OutcomeStatus.CORRECT,
            predicted="patch",
            actual="patch",
            confidence=0.9,
            source="brain_pipeline",
        )
        assert rec.feedback_type == FeedbackType.DECISION_OUTCOME
        assert rec.outcome == OutcomeStatus.CORRECT
        assert rec.predicted == "patch"

    def test_defaults(self):
        rec = FeedbackRecord(
            feedback_id="test-002",
            feedback_type=FeedbackType.MPTE_RESULT,
            entity_id="V-002",
            outcome=OutcomeStatus.INCORRECT,
            predicted="exploitable",
            actual="not_exploitable",
        )
        assert rec.confidence == 0.0
        assert rec.context == {}
        assert rec.recorded_at == ""
        assert rec.source == ""


class TestLearningAdjustment:
    def test_creation(self):
        adj = LearningAdjustment(
            adjustment_id="adj-001",
            feedback_type=FeedbackType.FALSE_POSITIVE,
            target="scanner:zap:rule:xss-reflected",
            metric="fp_rate",
            old_value=1.0,
            new_value=0.85,
            sample_count=50,
            confidence=0.9,
            reasoning="High FP rate detected (42%)",
        )
        assert adj.target.startswith("scanner:")
        assert adj.old_value > adj.new_value
        assert adj.applied is False


# ---------------------------------------------------------------------------
# FeedbackDB tests
# ---------------------------------------------------------------------------
class TestFeedbackDB:
    @pytest.fixture
    def db(self, tmp_path):
        db_path = str(tmp_path / "test_learning.db")
        _db = FeedbackDB(db_path)
        yield _db
        _db.close()

    def _make_record(self, fb_type=FeedbackType.DECISION_OUTCOME, entity_id="V-001"):
        import secrets
        return FeedbackRecord(
            feedback_id=f"test-{secrets.token_hex(4)}",
            feedback_type=fb_type,
            entity_id=entity_id,
            outcome=OutcomeStatus.CORRECT,
            predicted="patch",
            actual="patch",
            confidence=0.9,
            recorded_at=datetime.now(timezone.utc).isoformat(),
            source="test",
        )

    def test_init(self, db):
        assert db is not None

    def test_store_feedback(self, db):
        rec = self._make_record()
        db.store_feedback(rec)

    def test_get_feedback_empty(self, db):
        results = db.get_feedback("decision_outcome")
        assert isinstance(results, list)

    def test_store_and_retrieve(self, db):
        rec = self._make_record(FeedbackType.MPTE_RESULT, "V-002")
        db.store_feedback(rec)
        results = db.get_feedback("mpte_result")
        assert len(results) >= 1

    def test_weight_operations(self, db):
        db.set_weight("scanner:zap:accuracy", 0.85)
        val = db.get_weight("scanner:zap:accuracy")
        assert val == 0.85

    def test_weight_default(self, db):
        val = db.get_weight("nonexistent_key", default=1.0)
        assert val == 1.0

    def test_record_metric(self, db):
        db.record_metric("decision_outcome", "accuracy", 0.92)
        db.record_metric("decision_outcome", "accuracy", 0.94)

    def test_get_metrics_trend(self, db):
        db.record_metric("false_positive", "fp_rate", 0.15)
        db.record_metric("false_positive", "fp_rate", 0.12)
        trend = db.get_metrics_trend("false_positive", "fp_rate")
        assert isinstance(trend, list)

    def test_store_adjustment(self, db):
        adj = LearningAdjustment(
            adjustment_id="adj-test-1",
            feedback_type=FeedbackType.FALSE_POSITIVE,
            target="rule:xss:weight",
            metric="fp_rate",
            old_value=1.0,
            new_value=0.8,
            sample_count=30,
            confidence=0.85,
            reasoning="High FP rate",
        )
        db.store_adjustment(adj)

    def test_close_and_del(self, tmp_path):
        db_path = str(tmp_path / "test_close.db")
        db = FeedbackDB(db_path)
        db.store_feedback(self._make_record())
        db.close()
        # Should not raise on double close
        db.close()


# ---------------------------------------------------------------------------
# DecisionOutcomeLoop tests
# ---------------------------------------------------------------------------
class TestDecisionOutcomeLoop:
    @pytest.fixture
    def loop(self, tmp_path):
        db = FeedbackDB(str(tmp_path / "decision.db"))
        config = LearningConfig(min_samples=2)
        _loop = DecisionOutcomeLoop(db, config)
        yield _loop
        db.close()

    def test_record(self, loop):
        loop.record(
            decision_id="D-001",
            finding_id="V-001",
            predicted_action="patch",
            actual_outcome="patch",
        )

    def test_analyze_empty(self, loop):
        result = loop.analyze()
        assert isinstance(result, dict)

    def test_analyze_with_data(self, loop):
        for i in range(5):
            loop.record(f"D-{i}", f"V-{i}", "patch", "patch" if i < 4 else "accept")
        result = loop.analyze()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# MPTEResultLoop tests
# ---------------------------------------------------------------------------
class TestMPTEResultLoop:
    @pytest.fixture
    def loop(self, tmp_path):
        db = FeedbackDB(str(tmp_path / "mpte.db"))
        config = LearningConfig(min_samples=2)
        _loop = MPTEResultLoop(db, config)
        yield _loop
        db.close()

    def test_record(self, loop):
        loop.record(
            finding_id="V-001",
            predicted_exploitable=True,
            actual_exploitable=True,
            mpte_confidence=0.9,
        )

    def test_analyze(self, loop):
        for i in range(5):
            loop.record(f"V-{i}", True, i < 4, mpte_confidence=0.8)
        result = loop.analyze()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# FalsePositiveLoop tests
# ---------------------------------------------------------------------------
class TestFalsePositiveLoop:
    @pytest.fixture
    def loop(self, tmp_path):
        db = FeedbackDB(str(tmp_path / "fp.db"))
        config = LearningConfig(min_samples=2)
        _loop = FalsePositiveLoop(db, config)
        yield _loop
        db.close()

    def test_record(self, loop):
        loop.record(
            finding_id="V-001",
            scanner="zap",
            rule_id="xss-reflected",
            is_false_positive=True,
        )

    def test_analyze(self, loop):
        for i in range(5):
            loop.record(f"V-{i}", "zap", "xss-reflected", i < 3)
        result = loop.analyze()
        assert isinstance(result, dict)

    def test_get_suppressed_rules(self, loop):
        rules = loop.get_suppressed_rules()
        assert isinstance(rules, list)


# ---------------------------------------------------------------------------
# RemediationSuccessLoop tests
# ---------------------------------------------------------------------------
class TestRemediationSuccessLoop:
    @pytest.fixture
    def loop(self, tmp_path):
        db = FeedbackDB(str(tmp_path / "remediation.db"))
        config = LearningConfig(min_samples=2)
        _loop = RemediationSuccessLoop(db, config)
        yield _loop
        db.close()

    def test_record(self, loop):
        loop.record(
            finding_id="V-001",
            fix_type="autofix",
            fix_applied="dependency_update",
            resolved=True,
        )

    def test_analyze(self, loop):
        for i in range(5):
            loop.record(f"V-{i}", "autofix", "patch", resolved=(i < 4))
        result = loop.analyze()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# PolicyViolationLoop tests
# ---------------------------------------------------------------------------
class TestPolicyViolationLoop:
    @pytest.fixture
    def loop(self, tmp_path):
        db = FeedbackDB(str(tmp_path / "policy.db"))
        config = LearningConfig(min_samples=2)
        _loop = PolicyViolationLoop(db, config)
        yield _loop
        db.close()

    def test_record(self, loop):
        loop.record(
            policy_id="POL-001",
            rule_id="no-critical-unpatched-30d",
            violated=True,
            was_justified=False,
        )

    def test_analyze(self, loop):
        for i in range(5):
            loop.record(f"POL-{i}", f"rule-{i}", violated=(i < 2), was_justified=(i >= 2))
        result = loop.analyze()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# SelfLearningEngine tests
# ---------------------------------------------------------------------------
class TestSelfLearningEngine:
    @pytest.fixture
    def engine(self, tmp_path):
        config = LearningConfig(
            db_path=str(tmp_path / "engine.db"),
            min_samples=2,
        )
        return SelfLearningEngine(config=config)

    def test_init(self, engine):
        assert engine is not None

    def test_analyze_all_empty(self, engine):
        result = engine.analyze_all()
        assert isinstance(result, dict)

    def test_get_status(self, engine):
        status = engine.get_status()
        assert isinstance(status, dict)

    def test_get_insights(self, engine):
        insights = engine.get_insights()
        assert isinstance(insights, dict)

    def test_get_set_weight(self, engine):
        engine.set_weight("test_key", 0.75)
        val = engine.get_weight("test_key")
        assert val == 0.75

    def test_get_weight_default(self, engine):
        val = engine.get_weight("nonexistent", default=1.0)
        assert val == 1.0

    def test_decision_loop_integration(self, engine):
        engine.decision_loop.record("D1", "V1", "patch", "patch")
        engine.decision_loop.record("D2", "V2", "accept", "patch")
        result = engine.analyze_all()
        assert isinstance(result, dict)

    def test_mpte_loop_integration(self, engine):
        engine.mpte_loop.record("V1", True, True, mpte_confidence=0.9)
        engine.mpte_loop.record("V2", True, False, mpte_confidence=0.7)
        result = engine.analyze_all()
        assert isinstance(result, dict)


class TestGetLearningEngine:
    def test_returns_engine(self):
        engine = get_learning_engine()
        assert isinstance(engine, SelfLearningEngine)

    def test_singleton(self):
        e1 = get_learning_engine()
        e2 = get_learning_engine()
        assert e1 is e2
