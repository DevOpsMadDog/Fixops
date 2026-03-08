"""Coverage tests for core.self_learning — SelfLearningEngine."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.self_learning import (
    FeedbackType, OutcomeStatus, get_learning_engine,
)


class TestFeedbackType:
    def test_decision_outcome(self):
        assert FeedbackType.DECISION_OUTCOME.value == "decision_outcome"

    def test_mpte_result(self):
        assert FeedbackType.MPTE_RESULT.value == "mpte_result"

    def test_false_positive(self):
        assert FeedbackType.FALSE_POSITIVE.value == "false_positive"

    def test_remediation_success(self):
        assert FeedbackType.REMEDIATION_SUCCESS.value == "remediation_success"

    def test_policy_violation(self):
        assert FeedbackType.POLICY_VIOLATION.value == "policy_violation"


class TestOutcomeStatus:
    def test_correct(self):
        assert OutcomeStatus.CORRECT.value == "correct"

    def test_incorrect(self):
        assert OutcomeStatus.INCORRECT.value == "incorrect"

    def test_partial(self):
        assert OutcomeStatus.PARTIAL.value == "partial"

    def test_unknown(self):
        assert OutcomeStatus.UNKNOWN.value == "unknown"


class TestSelfLearningEngine:
    @pytest.fixture
    def engine(self):
        eng = get_learning_engine()
        yield eng

    def test_get_weight_default(self, engine):
        w = engine.get_weight("nonexistent-key", default=1.0)
        assert isinstance(w, (int, float))

    def test_set_and_get_weight(self, engine):
        engine.set_weight("test-rule-sl", 0.85)
        w = engine.get_weight("test-rule-sl")
        assert abs(w - 0.85) < 0.01

    def test_get_all_weights(self, engine):
        result = engine.get_all_weights()
        assert isinstance(result, dict)

    def test_get_status(self, engine):
        status = engine.get_status()
        assert isinstance(status, dict)

    def test_get_insights(self, engine):
        insights = engine.get_insights()
        assert isinstance(insights, dict)

    def test_score_with_learning(self, engine):
        finding = {
            "id": "CVE-2024-001",
            "severity": "high",
            "cvss": 8.5,
            "title": "SQL Injection",
        }
        result = engine.score_with_learning(finding)
        assert isinstance(result, dict)

    def test_compute_adjustments(self, engine):
        adjustments = engine.compute_adjustments()
        assert isinstance(adjustments, list)

    def test_analyze_all(self, engine):
        result = engine.analyze_all(days=7)
        assert isinstance(result, dict)

    def test_get_metrics_trends(self, engine):
        trends = engine.get_metrics_trends(days=7)
        assert isinstance(trends, dict)

    def test_reset_learning(self, engine):
        result = engine.reset_learning()
        assert isinstance(result, dict)
