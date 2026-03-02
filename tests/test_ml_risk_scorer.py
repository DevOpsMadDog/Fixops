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
    FeatureExplanation,
    ExplanationResult,
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
        # P0 threshold: >=82 (v2.1.0, was 85 in v1.0.0)
        assert _score_to_priority(95) == "P0"
        assert _score_to_priority(85) == "P0"
        assert _score_to_priority(82) == "P0"

    def test_p1(self):
        # P1 threshold: >=56 (v2.1.0, was 60 in v1.0.0)
        assert _score_to_priority(70) == "P1"
        assert _score_to_priority(60) == "P1"
        assert _score_to_priority(56) == "P1"
        assert _score_to_priority(81) == "P1"

    def test_p2(self):
        # P2 threshold: >=30 (v2.1.0, was 35 in v1.0.0)
        assert _score_to_priority(50) == "P2"
        assert _score_to_priority(35) == "P2"
        assert _score_to_priority(30) == "P2"
        assert _score_to_priority(55) == "P2"

    def test_p3(self):
        # P3 threshold: >=8 (v2.1.0, was 15 in v1.0.0)
        assert _score_to_priority(20) == "P3"
        assert _score_to_priority(15) == "P3"
        assert _score_to_priority(10) == "P3"
        assert _score_to_priority(8) == "P3"

    def test_p4(self):
        # P4 threshold: >=5 (unchanged)
        assert _score_to_priority(7) == "P4"
        assert _score_to_priority(5) == "P4"

    def test_fp(self):
        assert _score_to_priority(3) == "FP"
        assert _score_to_priority(0) == "FP"
        assert _score_to_priority(4.9) == "FP"


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


# ---------------------------------------------------------------------------
# SHAP-like Explanation Tests
# ---------------------------------------------------------------------------

class TestExplainPrediction:
    """Tests for SHAP-like feature explanations (explain_prediction).

    [V3] Decision Intelligence — validates why a vulnerability got its score.
    """

    def test_explanation_returns_explanation_result(self, trained_model, critical_vuln):
        """explain_prediction returns an ExplanationResult dataclass."""
        result = trained_model.explain_prediction(critical_vuln)
        assert isinstance(result, ExplanationResult)

    def test_explanation_has_all_features(self, trained_model, critical_vuln):
        """Explanation includes all 9 features."""
        result = trained_model.explain_prediction(critical_vuln)
        feature_names = [fe.name for fe in result.feature_explanations]
        for name in FEATURE_NAMES:
            assert name in feature_names, f"Missing feature: {name}"

    def test_explanation_features_are_feature_explanation(self, trained_model, critical_vuln):
        """Each feature explanation is a FeatureExplanation dataclass."""
        result = trained_model.explain_prediction(critical_vuln)
        for fe in result.feature_explanations:
            assert isinstance(fe, FeatureExplanation)
            assert hasattr(fe, "name")
            assert hasattr(fe, "value")
            assert hasattr(fe, "raw_value")
            assert hasattr(fe, "contribution")
            assert hasattr(fe, "direction")
            assert hasattr(fe, "explanation")

    def test_explanation_risk_score_matches_prediction(self, trained_model, critical_vuln):
        """Explanation risk_score should match predict() risk_score."""
        pred = trained_model.predict(critical_vuln)
        expl = trained_model.explain_prediction(critical_vuln)
        assert abs(expl.risk_score - pred.risk_score) < 0.5, (
            f"Score mismatch: explain={expl.risk_score} vs predict={pred.risk_score}"
        )

    def test_explanation_has_base_value(self, trained_model, critical_vuln):
        """Explanation includes a base_value (mean prediction)."""
        result = trained_model.explain_prediction(critical_vuln)
        assert isinstance(result.base_value, float)
        assert 0 <= result.base_value <= 100

    def test_explanation_sorted_by_contribution(self, trained_model, critical_vuln):
        """Features are sorted by absolute contribution (most impactful first)."""
        result = trained_model.explain_prediction(critical_vuln)
        contributions = [abs(fe.contribution) for fe in result.feature_explanations]
        assert contributions == sorted(contributions, reverse=True)

    def test_explanation_has_top_drivers(self, trained_model, critical_vuln):
        """Explanation includes top_drivers list."""
        result = trained_model.explain_prediction(critical_vuln)
        assert isinstance(result.top_drivers, list)
        # Critical vuln should have at least one driver
        assert len(result.top_drivers) >= 1

    def test_explanation_has_risk_narrative(self, trained_model, critical_vuln):
        """Explanation includes a human-readable risk narrative."""
        result = trained_model.explain_prediction(critical_vuln)
        assert isinstance(result.risk_narrative, str)
        assert len(result.risk_narrative) > 20

    def test_explanation_narrative_includes_score(self, trained_model, critical_vuln):
        """Risk narrative includes the score value."""
        result = trained_model.explain_prediction(critical_vuln)
        assert "/100" in result.risk_narrative

    def test_explanation_timing(self, trained_model, critical_vuln):
        """Explanation should complete in reasonable time."""
        result = trained_model.explain_prediction(critical_vuln)
        assert result.explanation_time_ms > 0
        assert result.explanation_time_ms < 5000  # Under 5 seconds

    def test_explanation_direction_values(self, trained_model, critical_vuln):
        """Direction should be one of the valid values."""
        result = trained_model.explain_prediction(critical_vuln)
        valid_directions = {"increases_risk", "decreases_risk", "neutral"}
        for fe in result.feature_explanations:
            assert fe.direction in valid_directions, (
                f"Invalid direction for {fe.name}: {fe.direction}"
            )

    def test_explanation_critical_vuln_high_score(self, trained_model, critical_vuln):
        """Critical vuln explanation should show high risk score."""
        result = trained_model.explain_prediction(critical_vuln)
        assert result.risk_score >= 70, f"Expected high score, got {result.risk_score}"

    def test_explanation_low_risk_vuln_low_score(self, trained_model, low_risk_vuln):
        """Low-risk vuln explanation should show low risk score."""
        result = trained_model.explain_prediction(low_risk_vuln)
        assert result.risk_score < 30, f"Expected low score, got {result.risk_score}"

    def test_explanation_to_dict(self, trained_model, critical_vuln):
        """ExplanationResult.to_dict() produces a serializable dict."""
        result = trained_model.explain_prediction(critical_vuln)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "risk_score" in d
        assert "base_value" in d
        assert "feature_explanations" in d
        assert "top_drivers" in d
        assert "risk_narrative" in d
        assert "explanation_time_ms" in d
        # Verify it's JSON-serializable
        json_str = json.dumps(d)
        assert len(json_str) > 100

    def test_feature_explanation_to_dict(self, trained_model, critical_vuln):
        """FeatureExplanation.to_dict() produces a serializable dict."""
        result = trained_model.explain_prediction(critical_vuln)
        fe = result.feature_explanations[0]
        d = fe.to_dict()
        assert "name" in d
        assert "value" in d
        assert "raw_value" in d
        assert "contribution" in d
        assert "direction" in d
        assert "explanation" in d

    def test_explanation_contributions_sum_approximately(self, trained_model, critical_vuln):
        """Sum of contributions should approximately equal (risk_score - base_value).

        This validates the interventional SHAP-like decomposition is roughly additive.
        Due to interaction effects in GBT, exact additivity is not expected.
        """
        result = trained_model.explain_prediction(critical_vuln)
        total_contribution = sum(fe.contribution for fe in result.feature_explanations)
        expected_delta = result.risk_score - result.base_value
        # Allow generous tolerance (GBT has interaction effects)
        assert abs(total_contribution - expected_delta) < 40, (
            f"Sum of contributions ({total_contribution:.1f}) vs "
            f"expected delta ({expected_delta:.1f}) differ too much"
        )

    def test_explanation_raw_values_correct(self, trained_model, critical_vuln):
        """Raw values in explanation should match input values."""
        result = trained_model.explain_prediction(critical_vuln)
        raw_map = {fe.name: fe.raw_value for fe in result.feature_explanations}
        assert raw_map["cvss_score"] == critical_vuln["cvss_score"]
        assert raw_map["epss_score"] == critical_vuln["epss_score"]
        assert raw_map["in_kev"] == critical_vuln["in_kev"]
        assert raw_map["asset_criticality"] == critical_vuln["asset_criticality"]

    def test_explanation_asset_criticality_is_top_driver(self, trained_model, critical_vuln):
        """For critical vuln, asset_criticality should be a top contributor.

        Feature importance shows asset_criticality at 59.4% weight.
        """
        result = trained_model.explain_prediction(critical_vuln)
        top_3_names = [fe.name for fe in result.feature_explanations[:3]]
        assert "asset_criticality" in top_3_names, (
            f"Expected asset_criticality in top 3, got: {top_3_names}"
        )


class TestExplainFallback:
    """Tests for fallback explanation when model is not trained."""

    def test_untrained_model_returns_fallback(self):
        """Untrained model should return fallback explanation."""
        model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()), random_seed=42)
        vuln = {
            "cvss_score": 7.5,
            "epss_score": 0.3,
            "in_kev": False,
            "asset_criticality": 0.5,
            "network_exposure": "internal",
        }
        result = model.explain_prediction(vuln)
        assert isinstance(result, ExplanationResult)
        assert "fallback" in result.risk_narrative.lower()

    def test_fallback_has_all_features(self):
        """Fallback explanation also includes all features."""
        model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()), random_seed=42)
        vuln = {"cvss_score": 5.0, "epss_score": 0.1}
        result = model.explain_prediction(vuln)
        feature_names = [fe.name for fe in result.feature_explanations]
        for name in FEATURE_NAMES:
            assert name in feature_names

    def test_fallback_base_value_is_50(self):
        """Fallback uses base_value=50 (midpoint)."""
        model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()), random_seed=42)
        vuln = {"cvss_score": 5.0}
        result = model.explain_prediction(vuln)
        assert result.base_value == 50.0


class TestExplainEdgeCases:
    """Edge case tests for explanation functionality."""

    def test_explanation_with_minimal_input(self, trained_model):
        """Explanation works with minimal input (all defaults)."""
        result = trained_model.explain_prediction({})
        assert isinstance(result, ExplanationResult)
        assert 0 <= result.risk_score <= 100

    def test_explanation_with_extreme_values(self, trained_model):
        """Explanation handles extreme feature values."""
        vuln = {
            "cvss_score": 10.0,
            "epss_score": 1.0,
            "in_kev": True,
            "asset_criticality": 1.0,
            "network_exposure": "internet",
            "exploit_available": True,
            "exploit_maturity": "weaponized",
            "reachable": True,
            "has_chain": True,
        }
        result = trained_model.explain_prediction(vuln)
        assert isinstance(result, ExplanationResult)
        assert result.risk_score >= 50  # All-max should be high

    def test_explanation_with_all_zeros(self, trained_model):
        """Explanation handles all-zero/false/none inputs."""
        vuln = {
            "cvss_score": 0.0,
            "epss_score": 0.0,
            "in_kev": False,
            "asset_criticality": 0.0,
            "network_exposure": "none",
            "exploit_available": False,
            "exploit_maturity": "none",
            "reachable": False,
            "has_chain": False,
        }
        result = trained_model.explain_prediction(vuln)
        assert isinstance(result, ExplanationResult)
        assert result.risk_score <= 30  # All-zero should be low

    def test_explanation_narrative_mentions_cve(self, trained_model):
        """If cve_id is provided, narrative should mention it."""
        vuln = {
            "cve_id": "CVE-2024-99999",
            "cvss_score": 8.0,
            "epss_score": 0.5,
            "asset_criticality": 0.8,
        }
        result = trained_model.explain_prediction(vuln)
        assert "CVE-2024-99999" in result.risk_narrative
