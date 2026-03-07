"""
Tests for ALdeci Self-Healing Remediation ML — Regression Predictor.

Year 4 ML Roadmap: Predict whether auto-fix causes regression.
Tests: regression risk prediction, rollback decisions, healing actions,
       outcome recording, feature contributions, model persistence.
"""

import json
import tempfile
from pathlib import Path

import numpy as np
import pytest

from core.ml.regression_predictor import (
    CATEGORY_MAP,
    FIX_SCOPE_MAP,
    FIX_TYPE_MAP,
    LANGUAGE_MAP,
    MODEL_VERSION,
    REGRESSION_BASELINES,
    REGRESSION_FEATURE_NAMES,
    ROLLBACK_THRESHOLDS,
    SEVERITY_MAP,
    FixOutcome,
    HealingAction,
    RegressionModelMetrics,
    RegressionPrediction,
    RegressionPredictor,
    RollbackDecision,
    _generate_monitoring_config,
    _generate_rollback_plan,
    _recommended_action,
    _risk_level,
    extract_regression_features,
    get_regression_predictor,
)

# Reset singleton between tests
import core.ml.regression_predictor as rp_module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def model_dir():
    """Temp directory for model artifacts."""
    d = tempfile.mkdtemp()
    yield Path(d)


@pytest.fixture
def trained_predictor(model_dir):
    """A trained RegressionPredictor instance."""
    predictor = RegressionPredictor(model_dir=model_dir, random_seed=42)
    predictor.train(n_samples=200, n_bootstrap=5)
    return predictor


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset module-level singleton before each test."""
    rp_module._default_predictor = None
    yield
    rp_module._default_predictor = None


# ---------------------------------------------------------------------------
# Test Constants and Maps
# ---------------------------------------------------------------------------

class TestConstantsAndMaps:
    """Test that constant maps are well-formed."""

    def test_fix_type_map_has_10_entries(self):
        assert len(FIX_TYPE_MAP) == 10

    def test_severity_map_has_5_entries(self):
        assert len(SEVERITY_MAP) == 5

    def test_category_map_has_14_entries(self):
        assert len(CATEGORY_MAP) == 14

    def test_language_map_has_14_entries(self):
        assert len(LANGUAGE_MAP) == 14

    def test_fix_scope_map_has_4_entries(self):
        assert len(FIX_SCOPE_MAP) == 4

    def test_regression_baselines_match_fix_types(self):
        for fix_type in REGRESSION_BASELINES:
            assert fix_type in FIX_TYPE_MAP

    def test_regression_baselines_are_probabilities(self):
        for fix_type, prob in REGRESSION_BASELINES.items():
            assert 0.0 < prob < 1.0, f"{fix_type} baseline {prob} out of range"

    def test_feature_names_has_14_entries(self):
        assert len(REGRESSION_FEATURE_NAMES) == 14

    def test_model_version_format(self):
        parts = MODEL_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_rollback_thresholds_all_positive(self):
        for key, val in ROLLBACK_THRESHOLDS.items():
            assert val > 0, f"Threshold {key} should be positive"


# ---------------------------------------------------------------------------
# Test Feature Extraction
# ---------------------------------------------------------------------------

class TestFeatureExtraction:
    """Test feature vector extraction."""

    def test_output_shape(self):
        features = extract_regression_features({"fix_type": "code_patch"})
        assert features.shape == (14,)

    def test_output_dtype(self):
        features = extract_regression_features({})
        assert features.dtype == np.float64

    def test_all_features_normalized(self):
        features = extract_regression_features({
            "fix_type": "code_patch",
            "severity": "critical",
            "files_affected": 100,
            "lines_changed": 1000,
            "code_complexity": 200,
            "dependency_depth": 50,
            "breaking_changes": 20,
        })
        # All should be 0-1 (with some >1 clamped)
        assert np.all(features >= 0.0)
        assert np.all(features <= 1.0)

    def test_has_tests_binary(self):
        with_tests = extract_regression_features({"has_tests": True})
        without_tests = extract_regression_features({"has_tests": False})
        assert with_tests[5] == 1.0
        assert without_tests[5] == 0.0

    def test_defaults_for_missing_keys(self):
        """Empty dict should still produce valid features."""
        features = extract_regression_features({})
        assert features.shape == (14,)
        assert np.all(np.isfinite(features))

    def test_fix_scope_encoding(self):
        single = extract_regression_features({"fix_scope": "single_function"})
        system = extract_regression_features({"fix_scope": "system"})
        assert single[12] < system[12]

    def test_dependency_depth_encoding(self):
        shallow = extract_regression_features({"dependency_depth": 0})
        deep = extract_regression_features({"dependency_depth": 8})
        assert shallow[10] < deep[10]


# ---------------------------------------------------------------------------
# Test Helper Functions
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    """Test risk level, action, and plan generation helpers."""

    def test_risk_level_safe(self):
        assert _risk_level(0.05) == "SAFE"
        assert _risk_level(0.14) == "SAFE"

    def test_risk_level_caution(self):
        assert _risk_level(0.15) == "CAUTION"
        assert _risk_level(0.39) == "CAUTION"

    def test_risk_level_dangerous(self):
        assert _risk_level(0.40) == "DANGEROUS"
        assert _risk_level(0.90) == "DANGEROUS"

    def test_recommended_action_auto_apply(self):
        assert _recommended_action(0.05, True) == "auto_apply"
        assert _recommended_action(0.05, False) == "auto_apply"
        assert _recommended_action(0.20, True) == "auto_apply"

    def test_recommended_action_review(self):
        assert _recommended_action(0.20, False) == "review_and_apply"
        assert _recommended_action(0.35, True) == "review_and_apply"

    def test_recommended_action_manual(self):
        assert _recommended_action(0.55, True) == "manual_only"

    def test_recommended_action_block(self):
        assert _recommended_action(0.75, True) == "block"

    def test_rollback_plan_code_patch(self):
        plan = _generate_rollback_plan({"fix_type": "code_patch"})
        assert plan["strategy"] == "git_revert"
        assert len(plan["steps"]) > 0
        assert plan["automated"] is True

    def test_rollback_plan_dependency(self):
        plan = _generate_rollback_plan({"fix_type": "dependency_update"})
        assert plan["strategy"] == "version_pin"

    def test_rollback_plan_secret(self):
        plan = _generate_rollback_plan({"fix_type": "secret_rotation"})
        assert plan["automated"] is False

    def test_monitoring_config_high_risk(self):
        config = _generate_monitoring_config({}, 0.5)
        assert config["check_interval_seconds"] == 30
        assert config["auto_rollback_enabled"] is True

    def test_monitoring_config_low_risk(self):
        config = _generate_monitoring_config({}, 0.05)
        assert config["check_interval_seconds"] == 300
        assert config["auto_rollback_enabled"] is False

    def test_monitoring_config_canary_pct(self):
        config = _generate_monitoring_config({}, 0.3)
        assert config["canary_percentage"] == 30


# ---------------------------------------------------------------------------
# Test Model Training
# ---------------------------------------------------------------------------

class TestModelTraining:
    """Test RegressionPredictor training."""

    def test_train_returns_metrics(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        metrics = predictor.train(n_samples=100, n_bootstrap=3)
        assert isinstance(metrics, RegressionModelMetrics)

    def test_train_mae_reasonable(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        metrics = predictor.train(n_samples=200, n_bootstrap=3)
        assert metrics.mae < 0.15, f"MAE {metrics.mae} too high"

    def test_train_r2_positive(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        metrics = predictor.train(n_samples=200, n_bootstrap=3)
        assert metrics.r2 > 0.5, f"R² {metrics.r2} too low"

    def test_train_sets_trained_flag(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        assert not predictor.is_trained
        predictor.train(n_samples=50, n_bootstrap=2)
        assert predictor.is_trained

    def test_train_feature_importances(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        metrics = predictor.train(n_samples=200, n_bootstrap=3)
        assert len(metrics.feature_importances) == 14
        assert all(v >= 0 for v in metrics.feature_importances.values())

    def test_train_cv_scores(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        metrics = predictor.train(n_samples=200, n_bootstrap=3)
        assert metrics.cv_mae > 0
        assert metrics.cv_std >= 0

    def test_train_accuracy_at_thresholds(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        metrics = predictor.train(n_samples=200, n_bootstrap=3)
        assert len(metrics.accuracy_at_threshold) >= 3
        for key, acc in metrics.accuracy_at_threshold.items():
            assert 0.0 <= acc <= 1.0

    def test_train_with_outcomes(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        outcomes = [
            {
                "fix_features": {"fix_type": "code_patch", "severity": "high"},
                "regression_occurred": True,
                "regression_severity": "major",
            },
            {
                "fix_features": {"fix_type": "config_hardening", "severity": "low"},
                "regression_occurred": False,
            },
        ]
        metrics = predictor.train(n_samples=100, n_bootstrap=2, outcomes=outcomes)
        assert metrics.training_samples == 102  # 100 synthetic + 2 real

    def test_train_reproducible(self, model_dir):
        p1 = RegressionPredictor(model_dir=model_dir, random_seed=42)
        m1 = p1.train(n_samples=100, n_bootstrap=3)
        p2 = RegressionPredictor(model_dir=model_dir, random_seed=42)
        m2 = p2.train(n_samples=100, n_bootstrap=3)
        assert abs(m1.mae - m2.mae) < 1e-10


# ---------------------------------------------------------------------------
# Test Regression Risk Prediction
# ---------------------------------------------------------------------------

class TestRegressionPrediction:
    """Test regression risk predictions."""

    def test_prediction_returns_result(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
            "severity": "high",
        })
        assert isinstance(result, RegressionPrediction)

    def test_prediction_probability_range(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
        })
        assert 0.0 <= result.regression_probability <= 1.0

    def test_prediction_has_confidence_interval(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
        })
        lo, hi = result.confidence_interval
        # CI should be a valid range (bootstrap CI may not always
        # contain the primary model prediction exactly)
        assert lo < hi
        assert 0.0 <= lo <= 1.0
        assert 0.0 <= hi <= 1.0
        # CI should be reasonably close to the prediction
        assert abs(result.regression_probability - (lo + hi) / 2) < 0.15

    def test_prediction_has_risk_level(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
        })
        assert result.risk_level in ("SAFE", "CAUTION", "DANGEROUS")

    def test_prediction_has_action(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
        })
        assert result.recommended_action in (
            "auto_apply", "review_and_apply", "manual_only", "block"
        )

    def test_prediction_has_rollback_plan(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "dependency_update",
        })
        assert "strategy" in result.rollback_plan
        assert "steps" in result.rollback_plan

    def test_prediction_has_monitoring_config(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
        })
        assert "check_interval_seconds" in result.monitoring_config
        assert "metrics_to_watch" in result.monitoring_config

    def test_prediction_has_feature_contributions(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
        })
        assert len(result.feature_contributions) == 14

    def test_prediction_model_version(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({})
        assert result.model_version == MODEL_VERSION

    def test_tests_reduce_regression_risk(self, trained_predictor):
        """Fixes with test coverage should have lower regression risk."""
        no_tests = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
            "severity": "high",
            "has_tests": False,
            "lines_changed": 50,
            "files_affected": 3,
            "code_complexity": 40,
        })
        with_tests = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
            "severity": "high",
            "has_tests": True,
            "lines_changed": 50,
            "files_affected": 3,
            "code_complexity": 40,
            "test_coverage_pct": 90,
        })
        assert with_tests.regression_probability < no_tests.regression_probability

    def test_more_files_higher_risk(self, trained_predictor):
        """More files affected → higher regression risk."""
        small = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
            "files_affected": 1,
            "lines_changed": 5,
        })
        large = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
            "files_affected": 15,
            "lines_changed": 200,
            "fix_scope": "multi_file",
        })
        assert large.regression_probability > small.regression_probability

    def test_breaking_changes_increase_risk(self, trained_predictor):
        """Known breaking changes should increase regression risk."""
        no_breaking = trained_predictor.predict_regression_risk({
            "fix_type": "dependency_update",
            "breaking_changes": 0,
        })
        with_breaking = trained_predictor.predict_regression_risk({
            "fix_type": "dependency_update",
            "breaking_changes": 5,
        })
        assert with_breaking.regression_probability > no_breaking.regression_probability

    def test_prediction_raises_if_not_trained(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        with pytest.raises(RuntimeError, match="not trained"):
            predictor.predict_regression_risk({"fix_type": "code_patch"})

    def test_prediction_to_dict(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
        })
        d = result.to_dict()
        assert "regression_probability" in d
        assert "risk_level" in d
        assert "recommended_action" in d
        assert "rollback_plan" in d
        # Ensure it's JSON-serializable
        json.dumps(d)


# ---------------------------------------------------------------------------
# Test Rollback Decisions
# ---------------------------------------------------------------------------

class TestRollbackDecisions:
    """Test rollback decision analysis."""

    def test_no_regression_no_rollback(self, trained_predictor):
        decision = trained_predictor.should_rollback({
            "error_rate_delta": 0.0,
            "latency_delta_ms": 0,
            "test_failures": 0,
        })
        assert isinstance(decision, RollbackDecision)
        assert decision.should_rollback is False
        assert decision.risk_score == 0.0

    def test_crash_triggers_immediate_rollback(self, trained_predictor):
        decision = trained_predictor.should_rollback({
            "crash_count": 3,
        })
        assert decision.should_rollback is True
        assert decision.urgency == "IMMEDIATE"

    def test_high_error_rate_triggers_rollback(self, trained_predictor):
        decision = trained_predictor.should_rollback({
            "error_rate_delta": 0.10,
            "test_failures": 5,
        })
        assert decision.should_rollback is True
        assert decision.risk_score > 30

    def test_latency_spike_detected(self, trained_predictor):
        decision = trained_predictor.should_rollback({
            "latency_delta_ms": 2000,
        })
        assert "latency_delta_ms" in decision.triggered_thresholds
        assert decision.should_rollback is True

    def test_minor_degradation_no_rollback(self, trained_predictor):
        decision = trained_predictor.should_rollback({
            "error_rate_delta": 0.01,
            "latency_delta_ms": 100,
        })
        assert decision.should_rollback is False

    def test_multiple_thresholds_compound(self, trained_predictor):
        decision = trained_predictor.should_rollback({
            "error_rate_delta": 0.05,
            "latency_delta_ms": 800,
            "test_failures": 3,
            "memory_delta_mb": 200,
        })
        assert len(decision.triggered_thresholds) >= 3
        assert decision.risk_score > 50

    def test_time_affects_confidence(self, trained_predictor):
        early = trained_predictor.should_rollback({
            "error_rate_delta": 0.05,
            "time_since_deploy_minutes": 2,
        })
        late = trained_predictor.should_rollback({
            "error_rate_delta": 0.05,
            "time_since_deploy_minutes": 60,
        })
        assert late.confidence > early.confidence

    def test_rollback_recommendation_text(self, trained_predictor):
        decision = trained_predictor.should_rollback({
            "error_rate_delta": 0.0,
        })
        assert "stable" in decision.recommendation.lower() or "no regression" in decision.recommendation.lower()

    def test_rollback_to_dict(self, trained_predictor):
        decision = trained_predictor.should_rollback({
            "crash_count": 1,
            "error_rate_delta": 0.05,
        })
        d = decision.to_dict()
        assert "should_rollback" in d
        assert "urgency" in d
        json.dumps(d)


# ---------------------------------------------------------------------------
# Test Healing Actions
# ---------------------------------------------------------------------------

class TestHealingActions:
    """Test self-healing action generation."""

    def test_no_rollback_returns_alert_only(self, trained_predictor):
        decision = RollbackDecision(
            should_rollback=False, urgency="LOW", confidence=0.9,
            triggered_thresholds=[], risk_score=5.0,
            recommendation="OK", estimated_impact={}, decision_time_ms=1.0,
        )
        actions = trained_predictor.generate_healing_actions(decision)
        assert len(actions) == 1
        assert actions[0].action_type == "alert_only"

    def test_rollback_generates_rollback_action(self, trained_predictor):
        decision = RollbackDecision(
            should_rollback=True, urgency="HIGH", confidence=0.85,
            triggered_thresholds=["error_rate_delta"], risk_score=55.0,
            recommendation="Rollback", estimated_impact={}, decision_time_ms=1.0,
        )
        actions = trained_predictor.generate_healing_actions(
            decision, fix_data={"fix_type": "code_patch"}
        )
        assert any(a.action_type == "rollback" for a in actions)

    def test_crash_adds_emergency_restart(self, trained_predictor):
        decision = RollbackDecision(
            should_rollback=True, urgency="IMMEDIATE", confidence=0.95,
            triggered_thresholds=["crash_count", "error_rate_delta"],
            risk_score=90.0, recommendation="CRITICAL",
            estimated_impact={}, decision_time_ms=1.0,
        )
        actions = trained_predictor.generate_healing_actions(decision)
        assert actions[0].priority == 1
        assert "restart" in actions[0].target.lower() or "rollback" in actions[0].target.lower()

    def test_actions_are_prioritized(self, trained_predictor):
        decision = RollbackDecision(
            should_rollback=True, urgency="HIGH", confidence=0.9,
            triggered_thresholds=["error_rate_delta"], risk_score=60.0,
            recommendation="Rollback", estimated_impact={}, decision_time_ms=1.0,
        )
        actions = trained_predictor.generate_healing_actions(
            decision, fix_data={"fix_type": "code_patch"}
        )
        priorities = [a.priority for a in actions]
        assert priorities == sorted(priorities)

    def test_healing_action_to_dict(self):
        action = HealingAction(
            action_type="rollback",
            target="test",
            priority=1,
            estimated_fix_time_minutes=5,
            steps=["Step 1"],
            prerequisites=["Access"],
            risks=["Risk 1"],
        )
        d = action.to_dict()
        assert d["action_type"] == "rollback"
        json.dumps(d)


# ---------------------------------------------------------------------------
# Test Outcome Recording
# ---------------------------------------------------------------------------

class TestOutcomeRecording:
    """Test fix outcome recording for online learning."""

    def test_record_outcome(self, trained_predictor):
        outcome = FixOutcome(
            fix_id="fix-001",
            fix_type="code_patch",
            regression_occurred=True,
            regression_severity="major",
            test_failures=3,
        )
        trained_predictor.record_outcome(outcome)
        stats = trained_predictor.get_outcome_statistics()
        assert stats["total_outcomes"] == 1
        assert stats["regression_rate"] == 1.0

    def test_record_multiple_outcomes(self, trained_predictor):
        for i in range(5):
            outcome = FixOutcome(
                fix_id=f"fix-{i:03d}",
                fix_type="code_patch",
                regression_occurred=(i % 3 == 0),
            )
            trained_predictor.record_outcome(outcome)
        stats = trained_predictor.get_outcome_statistics()
        assert stats["total_outcomes"] == 5
        assert 0.0 < stats["regression_rate"] < 1.0

    def test_outcome_by_fix_type(self, trained_predictor):
        trained_predictor.record_outcome(FixOutcome(
            fix_id="fix-001", fix_type="code_patch", regression_occurred=True,
        ))
        trained_predictor.record_outcome(FixOutcome(
            fix_id="fix-002", fix_type="dependency_update", regression_occurred=False,
        ))
        stats = trained_predictor.get_outcome_statistics()
        assert "code_patch" in stats["by_fix_type"]
        assert "dependency_update" in stats["by_fix_type"]

    def test_outcome_sets_timestamp(self, trained_predictor):
        outcome = FixOutcome(
            fix_id="fix-001", fix_type="code_patch", regression_occurred=False,
        )
        assert outcome.recorded_at == ""
        trained_predictor.record_outcome(outcome)
        assert outcome.recorded_at != ""

    def test_outcome_history_limit(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        predictor._max_history = 10
        for i in range(20):
            predictor.record_outcome(FixOutcome(
                fix_id=f"fix-{i:03d}", fix_type="code_patch",
                regression_occurred=False,
            ))
        assert len(predictor._outcome_history) == 10

    def test_empty_statistics(self, trained_predictor):
        stats = trained_predictor.get_outcome_statistics()
        assert stats["total_outcomes"] == 0
        assert stats["regression_rate"] == 0.0

    def test_outcome_to_dict(self):
        outcome = FixOutcome(
            fix_id="fix-001",
            fix_type="code_patch",
            regression_occurred=True,
            regression_severity="minor",
            test_failures=1,
            error_rate_delta=0.02,
        )
        d = outcome.to_dict()
        assert d["fix_id"] == "fix-001"
        assert d["regression_occurred"] is True
        json.dumps(d)


# ---------------------------------------------------------------------------
# Test Feature Importance
# ---------------------------------------------------------------------------

class TestFeatureImportance:
    """Test feature importance extraction."""

    def test_importance_has_all_features(self, trained_predictor):
        imp = trained_predictor.get_feature_importance()
        assert len(imp) == 14
        for name in REGRESSION_FEATURE_NAMES:
            assert name in imp

    def test_importances_sum_to_one(self, trained_predictor):
        imp = trained_predictor.get_feature_importance()
        total = sum(imp.values())
        assert abs(total - 1.0) < 0.01

    def test_untrained_returns_empty(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        assert predictor.get_feature_importance() == {}


# ---------------------------------------------------------------------------
# Test Model Persistence
# ---------------------------------------------------------------------------

class TestModelPersistence:
    """Test saving and loading models."""

    def test_save_creates_files(self, trained_predictor, model_dir):
        card_path = trained_predictor.save_model()
        assert card_path.exists()
        # Model pkl should also exist
        version_tag = MODEL_VERSION.replace(".", "_")
        pkl_path = model_dir / f"regression_predictor_v{version_tag}.pkl"
        assert pkl_path.exists()

    def test_save_model_card_is_valid_json(self, trained_predictor):
        card_path = trained_predictor.save_model()
        with open(card_path) as f:
            card = json.load(f)
        assert card["model_name"] == "ALdeci Regression Predictor"
        assert card["version"] == MODEL_VERSION
        assert card["air_gap_compatible"] is True

    def test_load_restores_model(self, trained_predictor, model_dir):
        trained_predictor.save_model()

        # Create new predictor and load
        new_predictor = RegressionPredictor(model_dir=model_dir)
        assert not new_predictor.is_trained
        success = new_predictor.load_model()
        assert success
        assert new_predictor.is_trained

    def test_loaded_model_predicts_same(self, trained_predictor, model_dir):
        # Get prediction from trained model
        fix_data = {"fix_type": "code_patch", "severity": "high"}
        pred1 = trained_predictor.predict_regression_risk(fix_data)

        # Save and reload
        trained_predictor.save_model()
        new_predictor = RegressionPredictor(model_dir=model_dir)
        new_predictor.load_model()
        pred2 = new_predictor.predict_regression_risk(fix_data)

        assert abs(pred1.regression_probability - pred2.regression_probability) < 0.01

    def test_load_nonexistent_returns_false(self, model_dir):
        predictor = RegressionPredictor(model_dir=model_dir)
        assert predictor.load_model() is False


# ---------------------------------------------------------------------------
# Test Metrics Serialization
# ---------------------------------------------------------------------------

class TestMetricsSerialization:
    """Test metrics to_dict serialization."""

    def test_metrics_to_dict(self, trained_predictor):
        metrics = trained_predictor.get_metrics()
        d = metrics.to_dict()
        assert "mae" in d
        assert "rmse" in d
        assert "r2" in d
        assert "feature_importances" in d
        json.dumps(d)

    def test_metrics_values_rounded(self, trained_predictor):
        metrics = trained_predictor.get_metrics()
        d = metrics.to_dict()
        # Check decimal places
        mae_str = str(d["mae"])
        parts = mae_str.split(".")
        if len(parts) == 2:
            assert len(parts[1]) <= 4


# ---------------------------------------------------------------------------
# Test Module-Level Singleton
# ---------------------------------------------------------------------------

class TestSingleton:
    """Test get_regression_predictor singleton."""

    def test_returns_predictor(self):
        predictor = get_regression_predictor()
        assert isinstance(predictor, RegressionPredictor)

    def test_returns_same_instance(self):
        p1 = get_regression_predictor()
        p2 = get_regression_predictor()
        assert p1 is p2

    def test_custom_model_dir(self):
        d = tempfile.mkdtemp()
        predictor = get_regression_predictor(model_dir=d)
        assert predictor.model_dir == Path(d)


# ---------------------------------------------------------------------------
# Test Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Test boundary conditions and edge cases."""

    def test_extreme_values_handled(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
            "severity": "critical",
            "files_affected": 100,
            "lines_changed": 10000,
            "code_complexity": 999,
            "dependency_depth": 50,
            "breaking_changes": 100,
            "fix_scope": "system",
            "test_coverage_pct": 0,
        })
        assert 0.0 <= result.regression_probability <= 1.0

    def test_minimal_input(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({})
        assert isinstance(result, RegressionPrediction)
        assert 0.0 <= result.regression_probability <= 1.0

    def test_unknown_fix_type(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "unknown_type",
        })
        assert isinstance(result, RegressionPrediction)

    def test_unknown_language(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "language": "brainfuck",
        })
        assert isinstance(result, RegressionPrediction)

    def test_negative_values_handled(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "files_affected": -1,
            "lines_changed": -10,
            "dependency_depth": -5,
        })
        assert 0.0 <= result.regression_probability <= 1.0

    def test_rollback_all_zeros(self, trained_predictor):
        decision = trained_predictor.should_rollback({})
        assert decision.should_rollback is False
        assert decision.risk_score == 0.0
        assert len(decision.triggered_thresholds) == 0

    def test_rollback_extreme_values(self, trained_predictor):
        decision = trained_predictor.should_rollback({
            "error_rate_delta": 1.0,
            "latency_delta_ms": 10000,
            "test_failures": 100,
            "memory_delta_mb": 1000,
            "cpu_delta_pct": 100,
            "crash_count": 50,
        })
        assert decision.should_rollback is True
        assert decision.urgency == "IMMEDIATE"
        assert decision.risk_score == 100.0  # Clamped at 100

    def test_prediction_time_recorded(self, trained_predictor):
        result = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
        })
        assert result.prediction_time_ms > 0

    def test_rollback_decision_time_recorded(self, trained_predictor):
        decision = trained_predictor.should_rollback({})
        assert decision.decision_time_ms > 0

    def test_config_hardening_lower_risk_than_code_patch(self, trained_predictor):
        """Config hardening has lower base regression rate."""
        config = trained_predictor.predict_regression_risk({
            "fix_type": "config_hardening",
            "severity": "medium",
            "files_affected": 1,
            "lines_changed": 5,
        })
        code = trained_predictor.predict_regression_risk({
            "fix_type": "code_patch",
            "severity": "medium",
            "files_affected": 5,
            "lines_changed": 50,
            "code_complexity": 40,
        })
        # Config hardening with minimal changes should be lower risk
        assert config.regression_probability < code.regression_probability
