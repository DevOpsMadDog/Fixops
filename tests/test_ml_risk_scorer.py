"""
Tests for ALdeci ML Risk Scoring Model.

[V3] Decision Intelligence — Validates the ML risk scoring pipeline.

Tests cover:
1. Feature extraction from vulnerability data
2. Model training on golden regression dataset
3. Prediction accuracy and confidence intervals
4. Fallback scoring when ML model unavailable
5. Model save/load round-trip
6. Golden dataset validation
7. Priority classification
8. Edge cases (missing fields, zero values, extreme values)
"""

import json
import os
import tempfile
from pathlib import Path

import numpy as np
import pytest


# Ensure suite paths are on sys.path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))


from core.ml.risk_scorer import (
    FEATURE_NAMES,
    MODEL_VERSION,
    ModelMetrics,
    PredictionResult,
    RiskScoringModel,
    extract_features,
    _encode_exposure,
    _encode_maturity,
    _score_to_priority,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def golden_path():
    """Path to golden regression dataset."""
    path = Path("data/golden_regression_cases.json")
    if not path.exists():
        pytest.skip("Golden regression dataset not found")
    return path


@pytest.fixture
def trained_model(golden_path):
    """A trained risk scoring model."""
    model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()), random_seed=42)
    model.train_from_golden_dataset(golden_path)
    return model


@pytest.fixture
def critical_vuln():
    """A critical, weaponized, internet-facing vulnerability."""
    return {
        "cvss_score": 10.0,
        "epss_score": 0.97,
        "in_kev": True,
        "asset_criticality": 1.0,
        "network_exposure": "internet",
        "exploit_available": True,
        "exploit_maturity": "weaponized",
        "reachable": True,
        "chain_cves": None,
    }


@pytest.fixture
def low_risk_vuln():
    """A low-risk, internal, no-exploit vulnerability."""
    return {
        "cvss_score": 3.0,
        "epss_score": 0.002,
        "in_kev": False,
        "asset_criticality": 0.2,
        "network_exposure": "controlled",
        "exploit_available": False,
        "exploit_maturity": "none",
        "reachable": False,
        "chain_cves": None,
    }


@pytest.fixture
def false_positive_vuln():
    """A false positive — component not present."""
    return {
        "cvss_score": 9.8,
        "epss_score": 0.04,
        "in_kev": False,
        "asset_criticality": 0.0,
        "network_exposure": "controlled",
        "exploit_available": False,
        "exploit_maturity": "none",
        "reachable": False,
    }


# ---------------------------------------------------------------------------
# Feature extraction tests
# ---------------------------------------------------------------------------

class TestFeatureExtraction:
    """Test feature extraction from vulnerability dictionaries."""

    def test_extract_features_shape(self, critical_vuln):
        features = extract_features(critical_vuln)
        assert features.shape == (len(FEATURE_NAMES),)
        assert features.dtype == np.float64

    def test_extract_critical_features(self, critical_vuln):
        features = extract_features(critical_vuln)
        assert features[0] == pytest.approx(1.0, abs=0.01)  # CVSS 10/10
        assert features[1] == pytest.approx(0.97, abs=0.01)  # EPSS
        assert features[2] == 1.0  # in_kev
        assert features[3] == pytest.approx(1.0, abs=0.01)  # criticality
        assert features[4] == pytest.approx(1.0, abs=0.01)  # internet exposure
        assert features[5] == 1.0  # exploit available
        assert features[6] == pytest.approx(1.0, abs=0.01)  # weaponized
        assert features[7] == 1.0  # reachable

    def test_extract_low_risk_features(self, low_risk_vuln):
        features = extract_features(low_risk_vuln)
        assert features[0] == pytest.approx(0.3, abs=0.01)  # CVSS 3/10
        assert features[1] == pytest.approx(0.002, abs=0.001)  # EPSS
        assert features[2] == 0.0  # not in KEV
        assert features[7] == 0.0  # not reachable

    def test_extract_missing_fields(self):
        """Missing fields should get defaults."""
        features = extract_features({})
        assert features.shape == (len(FEATURE_NAMES),)
        assert features[0] == 0.0  # default CVSS
        assert features[2] == 0.0  # default not in KEV
        assert features[7] == 1.0  # default reachable=True

    def test_extract_chain_exploit(self):
        features = extract_features({"chain_cves": ["CVE-2024-1234"]})
        assert features[8] == 1.0  # has_chain

    def test_extract_no_chain(self):
        features = extract_features({"chain_cves": None})
        assert features[8] == 0.0

    def test_all_features_bounded_0_1(self, critical_vuln):
        features = extract_features(critical_vuln)
        for i, val in enumerate(features):
            assert 0.0 <= val <= 1.0, f"Feature {FEATURE_NAMES[i]} out of bounds: {val}"


class TestEncodings:
    """Test categorical encoding functions."""

    def test_exposure_internet(self):
        assert _encode_exposure("internet") == 1.0

    def test_exposure_internal(self):
        assert _encode_exposure("internal") == 0.5

    def test_exposure_controlled(self):
        assert _encode_exposure("controlled") == 0.4

    def test_exposure_unknown(self):
        assert _encode_exposure("unknown") == 0.3

    def test_exposure_numeric(self):
        assert _encode_exposure(0.7) == 0.7

    def test_maturity_weaponized(self):
        assert _encode_maturity("weaponized") == 1.0

    def test_maturity_poc(self):
        assert _encode_maturity("proof_of_concept") == 0.6

    def test_maturity_none(self):
        assert _encode_maturity("none") == 0.0


class TestPriorityMapping:
    """Test score-to-priority classification."""

    def test_p0(self):
        assert _score_to_priority(95) == "P0"
        assert _score_to_priority(85) == "P0"

    def test_p1(self):
        assert _score_to_priority(70) == "P1"
        assert _score_to_priority(60) == "P1"

    def test_p2(self):
        assert _score_to_priority(50) == "P2"
        assert _score_to_priority(35) == "P2"

    def test_p3(self):
        assert _score_to_priority(20) == "P3"
        assert _score_to_priority(15) == "P3"

    def test_p4(self):
        assert _score_to_priority(10) == "P4"
        assert _score_to_priority(5) == "P4"

    def test_fp(self):
        assert _score_to_priority(3) == "FP"
        assert _score_to_priority(0) == "FP"


# ---------------------------------------------------------------------------
# Model training tests
# ---------------------------------------------------------------------------

class TestModelTraining:
    """Test model training and metrics."""

    def test_train_produces_metrics(self, golden_path):
        model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()))
        metrics = model.train_from_golden_dataset(golden_path)
        assert isinstance(metrics, ModelMetrics)
        assert metrics.mae >= 0
        assert metrics.rmse >= 0
        assert metrics.training_samples >= 50  # Golden dataset grows over time

    def test_model_is_trained_after_training(self, trained_model):
        assert trained_model.is_trained is True

    def test_untrained_model(self):
        model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()))
        assert model.is_trained is False

    def test_r2_positive(self, trained_model):
        """R² should be positive (model fits better than mean)."""
        assert trained_model._metrics.r2 > 0

    def test_within_range_above_80pct(self, trained_model):
        """At least 80% of golden cases should be within expected range."""
        assert trained_model._metrics.within_range_pct >= 0.80

    def test_feature_importances_sum_to_one(self, trained_model):
        importances = trained_model.get_feature_importance()
        total = sum(importances.values())
        assert total == pytest.approx(1.0, abs=0.01)

    def test_feature_importances_all_non_negative(self, trained_model):
        importances = trained_model.get_feature_importance()
        for name, val in importances.items():
            assert val >= 0, f"Feature {name} has negative importance: {val}"

    def test_cv_scores_computed(self, trained_model):
        assert len(trained_model._metrics.cv_scores) > 0

    def test_train_too_few_cases(self):
        """Should raise ValueError with < 10 cases."""
        model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"cases": [{"id": "1", "expected_risk_score_min": 0, "expected_risk_score_max": 100}]}, f)
            f.flush()
            with pytest.raises(ValueError, match="at least 10"):
                model.train_from_golden_dataset(f.name)
            os.unlink(f.name)


# ---------------------------------------------------------------------------
# Prediction tests
# ---------------------------------------------------------------------------

class TestPredictions:
    """Test model predictions."""

    def test_critical_vuln_high_score(self, trained_model, critical_vuln):
        pred = trained_model.predict(critical_vuln)
        assert isinstance(pred, PredictionResult)
        assert pred.risk_score >= 80, f"Critical vuln should score >= 80, got {pred.risk_score}"

    def test_low_risk_vuln_low_score(self, trained_model, low_risk_vuln):
        pred = trained_model.predict(low_risk_vuln)
        assert pred.risk_score < 30, f"Low risk vuln should score < 30, got {pred.risk_score}"

    def test_false_positive_very_low(self, trained_model, false_positive_vuln):
        pred = trained_model.predict(false_positive_vuln)
        assert pred.risk_score < 15, f"False positive should score < 15, got {pred.risk_score}"

    def test_prediction_has_confidence_interval(self, trained_model, critical_vuln):
        pred = trained_model.predict(critical_vuln)
        ci_low, ci_high = pred.confidence_interval
        assert ci_low <= pred.risk_score <= ci_high or pred.risk_score <= ci_high

    def test_confidence_width_reasonable(self, trained_model, critical_vuln):
        pred = trained_model.predict(critical_vuln)
        assert pred.confidence_width < 60, f"CI too wide: {pred.confidence_width}"

    def test_prediction_has_priority(self, trained_model, critical_vuln):
        pred = trained_model.predict(critical_vuln)
        assert pred.priority in ("P0", "P1", "P2", "P3", "P4", "FP")

    def test_critical_vuln_priority_p0(self, trained_model, critical_vuln):
        pred = trained_model.predict(critical_vuln)
        assert pred.priority == "P0", f"Critical vuln should be P0, got {pred.priority}"

    def test_prediction_has_feature_contributions(self, trained_model, critical_vuln):
        pred = trained_model.predict(critical_vuln)
        assert len(pred.feature_contributions) == len(FEATURE_NAMES)

    def test_prediction_time_fast(self, trained_model, critical_vuln):
        pred = trained_model.predict(critical_vuln)
        assert pred.prediction_time_ms < 100, f"Prediction too slow: {pred.prediction_time_ms}ms"

    def test_prediction_score_bounded(self, trained_model, critical_vuln):
        pred = trained_model.predict(critical_vuln)
        assert 0 <= pred.risk_score <= 100

    def test_to_dict(self, trained_model, critical_vuln):
        pred = trained_model.predict(critical_vuln)
        d = pred.to_dict()
        assert "risk_score" in d
        assert "confidence_interval" in d
        assert "priority" in d
        assert isinstance(d["confidence_interval"], list)

    def test_batch_prediction(self, trained_model, critical_vuln, low_risk_vuln):
        preds = trained_model.predict_batch([critical_vuln, low_risk_vuln])
        assert len(preds) == 2
        assert preds[0].risk_score > preds[1].risk_score


# ---------------------------------------------------------------------------
# Fallback scoring tests
# ---------------------------------------------------------------------------

class TestFallbackScoring:
    """Test fallback deterministic scoring when ML model unavailable."""

    def test_fallback_returns_result(self, critical_vuln):
        model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()))
        pred = model.predict(critical_vuln)
        assert isinstance(pred, PredictionResult)
        assert pred.model_version == "fallback-1.0"

    def test_fallback_critical_high(self, critical_vuln):
        model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()))
        pred = model.predict(critical_vuln)
        assert pred.risk_score > 50

    def test_fallback_low_risk_low(self, low_risk_vuln):
        model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()))
        pred = model.predict(low_risk_vuln)
        assert pred.risk_score < 30


# ---------------------------------------------------------------------------
# Save/Load round-trip tests
# ---------------------------------------------------------------------------

class TestSaveLoad:
    """Test model persistence."""

    def test_save_creates_files(self, trained_model):
        model_dir = Path(tempfile.mkdtemp())
        trained_model.save(model_dir)
        version_suffix = MODEL_VERSION.replace(".", "_")
        assert (model_dir / f"risk_model_v{version_suffix}.pkl").exists()
        assert (model_dir / f"scaler_v{version_suffix}.pkl").exists()
        assert (model_dir / f"model_metadata_v{version_suffix}.json").exists()

    def test_save_load_roundtrip(self, trained_model, critical_vuln):
        model_dir = Path(tempfile.mkdtemp())
        trained_model.save(model_dir)

        # Load into new model
        loaded = RiskScoringModel(model_dir=model_dir)
        assert loaded.load(model_dir) is True
        assert loaded.is_trained is True

        # Predictions should be identical
        pred1 = trained_model.predict(critical_vuln)
        pred2 = loaded.predict(critical_vuln)
        assert pred1.risk_score == pytest.approx(pred2.risk_score, abs=0.1)

    def test_load_nonexistent(self):
        model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()))
        assert model.load(Path("/nonexistent")) is False


# ---------------------------------------------------------------------------
# Golden validation tests
# ---------------------------------------------------------------------------

class TestGoldenValidation:
    """Test model validation against golden regression dataset."""

    def test_validation_returns_results(self, trained_model, golden_path):
        results = trained_model.validate_against_golden(golden_path)
        assert "total_cases" in results
        assert "passes" in results
        assert "failures" in results
        assert "pass_rate" in results

    def test_validation_pass_rate_above_80pct(self, trained_model, golden_path):
        results = trained_model.validate_against_golden(golden_path)
        assert results["pass_rate"] >= 0.80, f"Pass rate too low: {results['pass_rate']}"

    def test_all_golden_cases_validated(self, trained_model, golden_path):
        results = trained_model.validate_against_golden(golden_path)
        assert results["total_cases"] >= 50  # Golden dataset grows over time


# ---------------------------------------------------------------------------
# Model card tests
# ---------------------------------------------------------------------------

class TestModelCard:
    """Test model card generation."""

    def test_model_card_created(self, trained_model):
        model_dir = Path(tempfile.mkdtemp())
        card_path = trained_model.write_model_card(model_dir)
        assert card_path.exists()
        content = card_path.read_text()
        assert "ALdeci" in content
        assert "Risk Scoring" in content
        assert "Feature" in content
