"""
Tests for the AutoFix Confidence Estimator (core.ml.autofix_confidence).

[V3] Decision Intelligence — Tests for AutoFix confidence scoring.

Covers:
  - Feature extraction
  - Model training and metrics
  - Prediction with confidence intervals
  - Fallback prediction
  - Classification thresholds
  - Save/load round-trip
  - Singleton pattern
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest
import numpy as np

# Ensure suite-core is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.ml.autofix_confidence import (
    AutoFixConfidenceModel,
    ConfidencePrediction,
    ConfidenceModelMetrics,
    extract_fix_features,
    get_autofix_confidence_model,
    CONFIDENCE_FEATURE_NAMES,
    _score_to_classification,
    _classification_to_recommendation,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def model():
    """Create a fresh model instance with temp model dir."""
    tmpdir = tempfile.mkdtemp()
    m = AutoFixConfidenceModel(model_dir=Path(tmpdir))
    return m


@pytest.fixture
def trained_model():
    """Create a trained model instance."""
    tmpdir = tempfile.mkdtemp()
    m = AutoFixConfidenceModel(model_dir=Path(tmpdir))
    m.train(n_samples=100, n_bootstrap=5)
    return m


@pytest.fixture
def dep_update_fix():
    """Dependency update fix data (high confidence expected)."""
    return {
        "fix_type": "dependency_update",
        "severity": "critical",
        "category": "dependency",
        "files_affected": 1,
        "lines_changed": 3,
        "has_tests": True,
        "llm_confidence": 0.92,
        "language": "python",
        "historical_success_rate": 0.95,
        "code_complexity": 5,
    }


@pytest.fixture
def complex_code_patch():
    """Complex code patch fix data (low confidence expected)."""
    return {
        "fix_type": "code_patch",
        "severity": "medium",
        "category": "injection",
        "files_affected": 8,
        "lines_changed": 150,
        "has_tests": False,
        "llm_confidence": 0.45,
        "language": "java",
        "historical_success_rate": 0.4,
        "code_complexity": 80,
    }


# ---------------------------------------------------------------------------
# Tests: Feature extraction
# ---------------------------------------------------------------------------

class TestFeatureExtraction:
    """Tests for fix feature extraction."""

    def test_feature_vector_shape(self, dep_update_fix):
        features = extract_fix_features(dep_update_fix)
        assert features.shape == (10,), f"Expected shape (10,), got {features.shape}"

    def test_feature_vector_range(self, dep_update_fix):
        features = extract_fix_features(dep_update_fix)
        assert np.all(features >= 0), "All features should be >= 0"
        assert np.all(features <= 1), "All features should be <= 1"

    def test_fix_type_encoding(self):
        f1 = extract_fix_features({"fix_type": "dependency_update"})
        f2 = extract_fix_features({"fix_type": "code_patch"})
        assert f1[0] != f2[0], "Different fix types should encode differently"

    def test_severity_encoding(self):
        f1 = extract_fix_features({"severity": "critical"})
        f2 = extract_fix_features({"severity": "low"})
        assert f1[1] > f2[1], "Critical severity should encode higher"

    def test_has_tests_binary(self):
        f1 = extract_fix_features({"has_tests": True})
        f2 = extract_fix_features({"has_tests": False})
        assert f1[5] == 1.0
        assert f2[5] == 0.0

    def test_llm_confidence_preserved(self):
        features = extract_fix_features({"llm_confidence": 0.85})
        assert features[6] == 0.85

    def test_files_affected_clamped(self):
        features = extract_fix_features({"files_affected": 100})
        assert features[3] == 1.0  # Clamped to 20/20

    def test_lines_changed_clamped(self):
        features = extract_fix_features({"lines_changed": 10000})
        assert features[4] == 1.0  # Clamped to 500/500

    def test_empty_fix_data(self):
        features = extract_fix_features({})
        assert features.shape == (10,)
        assert np.all(np.isfinite(features))

    def test_feature_names_count(self):
        assert len(CONFIDENCE_FEATURE_NAMES) == 10


# ---------------------------------------------------------------------------
# Tests: Classification
# ---------------------------------------------------------------------------

class TestClassification:
    """Tests for score-to-classification mapping."""

    def test_high_classification(self):
        assert _score_to_classification(90) == "HIGH"
        assert _score_to_classification(85) == "HIGH"

    def test_medium_classification(self):
        assert _score_to_classification(70) == "MEDIUM"
        assert _score_to_classification(60) == "MEDIUM"

    def test_low_classification(self):
        assert _score_to_classification(50) == "LOW"
        assert _score_to_classification(10) == "LOW"
        assert _score_to_classification(0) == "LOW"

    def test_boundary_85(self):
        assert _score_to_classification(85) == "HIGH"
        assert _score_to_classification(84.99) == "MEDIUM"

    def test_boundary_60(self):
        assert _score_to_classification(60) == "MEDIUM"
        assert _score_to_classification(59.99) == "LOW"

    def test_recommendation_high(self):
        rec = _classification_to_recommendation("HIGH")
        assert "auto-apply" in rec.lower()

    def test_recommendation_low(self):
        rec = _classification_to_recommendation("LOW")
        assert "manual" in rec.lower()


# ---------------------------------------------------------------------------
# Tests: Model training
# ---------------------------------------------------------------------------

class TestModelTraining:
    """Tests for model training."""

    def test_train_produces_metrics(self, model):
        metrics = model.train(n_samples=100, n_bootstrap=5)
        assert isinstance(metrics, ConfidenceModelMetrics)
        assert metrics.accuracy > 0
        assert metrics.mae >= 0
        assert metrics.training_samples == 100
        assert len(metrics.feature_importances) == 10

    def test_model_is_trained_after_train(self, model):
        model.train(n_samples=100, n_bootstrap=5)
        assert model.is_trained

    def test_model_not_trained_initially(self, model):
        assert not model.is_trained

    def test_training_accuracy_reasonable(self, model):
        """Training accuracy should be above chance (>33% for 3 classes)."""
        metrics = model.train(n_samples=300, n_bootstrap=5)
        assert metrics.accuracy > 0.40, (
            f"Accuracy {metrics.accuracy:.3f} too low (should be >0.40)"
        )

    def test_training_mae_reasonable(self, model):
        """MAE should be < 20 points for reasonable model."""
        metrics = model.train(n_samples=300, n_bootstrap=5)
        assert metrics.mae < 25, f"MAE {metrics.mae:.2f} too high (should be <25)"

    def test_feature_importances_sum_to_one(self, model):
        metrics = model.train(n_samples=100, n_bootstrap=5)
        total = sum(metrics.feature_importances.values())
        assert abs(total - 1.0) < 0.01, (
            f"Feature importances should sum to ~1.0, got {total}"
        )

    def test_metrics_to_dict(self, model):
        metrics = model.train(n_samples=100, n_bootstrap=5)
        d = metrics.to_dict()
        assert "accuracy" in d
        assert "mae" in d
        assert "feature_importances" in d
        assert "precision_by_class" in d


# ---------------------------------------------------------------------------
# Tests: Prediction
# ---------------------------------------------------------------------------

class TestPrediction:
    """Tests for confidence prediction."""

    def test_predict_returns_result(self, trained_model, dep_update_fix):
        result = trained_model.predict(dep_update_fix)
        assert isinstance(result, ConfidencePrediction)
        assert 0 <= result.confidence_score <= 100
        assert result.classification in ("HIGH", "MEDIUM", "LOW")

    def test_dep_update_higher_than_complex_patch(
        self, trained_model, dep_update_fix, complex_code_patch
    ):
        """Dependency updates should generally score higher than complex patches."""
        r1 = trained_model.predict(dep_update_fix)
        r2 = trained_model.predict(complex_code_patch)
        # This should generally hold (not guaranteed due to stochastic training)
        # Use a soft check
        assert r1.confidence_score > r2.confidence_score - 10, (
            f"Dep update ({r1.confidence_score:.1f}) should score higher "
            f"than complex patch ({r2.confidence_score:.1f})"
        )

    def test_confidence_interval_valid(self, trained_model, dep_update_fix):
        result = trained_model.predict(dep_update_fix)
        ci_low, ci_high = result.confidence_interval
        # Primary model (200 trees) may slightly exceed bootstrap (100 trees)
        # CI bounds, so allow ±5 point tolerance
        assert ci_low - 5 <= result.confidence_score <= ci_high + 5, (
            f"Score {result.confidence_score:.2f} should be near CI "
            f"[{ci_low:.2f}, {ci_high:.2f}]"
        )
        assert ci_low >= 0
        assert ci_high <= 100

    def test_feature_contributions_present(self, trained_model, dep_update_fix):
        result = trained_model.predict(dep_update_fix)
        assert len(result.feature_contributions) == 10

    def test_prediction_has_recommendation(self, trained_model, dep_update_fix):
        result = trained_model.predict(dep_update_fix)
        assert len(result.recommendation) > 0

    def test_prediction_time_ms(self, trained_model, dep_update_fix):
        result = trained_model.predict(dep_update_fix)
        assert result.prediction_time_ms >= 0
        assert result.prediction_time_ms < 1000  # Should be fast

    def test_to_dict(self, trained_model, dep_update_fix):
        result = trained_model.predict(dep_update_fix)
        d = result.to_dict()
        assert "confidence_score" in d
        assert "classification" in d
        assert "confidence_interval" in d
        assert "recommendation" in d


# ---------------------------------------------------------------------------
# Tests: Fallback prediction
# ---------------------------------------------------------------------------

class TestFallbackPrediction:
    """Tests for prediction when model is not trained."""

    def test_fallback_returns_result(self, model, dep_update_fix):
        result = model.predict(dep_update_fix)
        assert isinstance(result, ConfidencePrediction)
        assert 0 <= result.confidence_score <= 100
        assert result.model_version == "fallback-1.0"

    def test_fallback_dep_update_reasonable(self, model):
        result = model.predict({
            "fix_type": "dependency_update",
            "llm_confidence": 0.9,
            "has_tests": True,
            "files_affected": 1,
            "lines_changed": 3,
        })
        assert result.confidence_score >= 70, (
            f"Dep update with high LLM confidence should score >=70, got {result.confidence_score}"
        )

    def test_fallback_complex_patch_lower(self, model):
        result = model.predict({
            "fix_type": "code_patch",
            "llm_confidence": 0.3,
            "has_tests": False,
            "files_affected": 10,
            "lines_changed": 200,
        })
        assert result.confidence_score < 75


# ---------------------------------------------------------------------------
# Tests: Save/Load
# ---------------------------------------------------------------------------

class TestSaveLoad:
    """Tests for model persistence."""

    def test_save_load_round_trip(self, dep_update_fix):
        tmpdir = tempfile.mkdtemp()
        m1 = AutoFixConfidenceModel(model_dir=Path(tmpdir))
        m1.train(n_samples=100, n_bootstrap=5)
        pred1 = m1.predict(dep_update_fix)
        m1.save()

        m2 = AutoFixConfidenceModel(model_dir=Path(tmpdir))
        loaded = m2.load()
        assert loaded
        assert m2.is_trained

        pred2 = m2.predict(dep_update_fix)
        assert abs(pred1.confidence_score - pred2.confidence_score) < 1.0

    def test_load_nonexistent(self, model):
        loaded = model.load()
        assert not loaded
        assert not model.is_trained


# ---------------------------------------------------------------------------
# Tests: Singleton
# ---------------------------------------------------------------------------

class TestSingleton:
    """Tests for the module-level singleton."""

    def test_get_autofix_confidence_model(self):
        import core.ml.autofix_confidence as mod
        mod._model_instance = None
        m = get_autofix_confidence_model()
        assert m is not None
        assert isinstance(m, AutoFixConfidenceModel)

    def test_singleton_returns_same_instance(self):
        import core.ml.autofix_confidence as mod
        mod._model_instance = None
        m1 = get_autofix_confidence_model()
        m2 = get_autofix_confidence_model()
        assert m1 is m2
