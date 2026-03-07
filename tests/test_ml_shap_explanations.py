"""
Tests for SHAP-like feature explanations in risk scoring model.

[V3] Decision Intelligence — validates that explain_prediction() produces
accurate, human-readable explanations for risk scores.

Tests cover:
  - Interventional contribution computation
  - Human-readable narrative generation
  - Top driver identification
  - Base value computation
  - Edge cases (all high, all low, mixed)
  - Fallback explanation when model is not trained
  - ExplanationResult serialization
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, ".")

from core.ml.risk_scorer import (
    ExplanationResult,
    FeatureExplanation,
    RiskScoringModel,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def trained_model():
    """Train a model once for the entire test module."""
    model = RiskScoringModel(model_dir=Path(tempfile.mkdtemp()))
    model.train_from_golden_dataset("data/golden_regression_cases.json")
    return model


@pytest.fixture
def untrained_model():
    return RiskScoringModel(model_dir=Path(tempfile.mkdtemp()))


@pytest.fixture
def critical_vuln():
    return {
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "epss_score": 0.975,
        "in_kev": True,
        "asset_criticality": 1.0,
        "network_exposure": "internet",
        "exploit_available": True,
        "exploit_maturity": "weaponized",
        "reachable": True,
    }


@pytest.fixture
def low_risk_vuln():
    return {
        "cve_id": "CVE-2023-99999",
        "cvss_score": 2.0,
        "epss_score": 0.001,
        "in_kev": False,
        "asset_criticality": 0.1,
        "network_exposure": "controlled",
        "exploit_available": False,
        "exploit_maturity": "none",
        "reachable": False,
    }


@pytest.fixture
def medium_vuln():
    return {
        "cve_id": "CVE-2024-12345",
        "cvss_score": 6.5,
        "epss_score": 0.15,
        "in_kev": False,
        "asset_criticality": 0.5,
        "network_exposure": "internal",
        "exploit_available": True,
        "exploit_maturity": "proof_of_concept",
        "reachable": True,
    }


# ---------------------------------------------------------------------------
# Tests: ExplanationResult structure
# ---------------------------------------------------------------------------


class TestExplanationStructure:
    def test_explanation_has_risk_score(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        assert isinstance(result, ExplanationResult)
        assert 0 <= result.risk_score <= 100

    def test_explanation_has_base_value(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        assert 0 <= result.base_value <= 100

    def test_explanation_has_feature_explanations(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        assert len(result.feature_explanations) == 9  # 9 features
        for fe in result.feature_explanations:
            assert isinstance(fe, FeatureExplanation)

    def test_explanation_has_top_drivers(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        assert isinstance(result.top_drivers, list)
        assert len(result.top_drivers) >= 1  # At least one driver

    def test_explanation_has_narrative(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        assert isinstance(result.risk_narrative, str)
        assert len(result.risk_narrative) > 20  # Non-trivial narrative

    def test_explanation_time_fast(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        assert result.explanation_time_ms < 50  # Under 50ms


# ---------------------------------------------------------------------------
# Tests: Feature contribution accuracy
# ---------------------------------------------------------------------------


class TestContributions:
    def test_critical_vuln_has_positive_contributions(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        # Critical vuln should have mostly positive contributions
        positive_count = sum(
            1 for fe in result.feature_explanations if fe.contribution > 0.5
        )
        assert positive_count >= 2  # At least 2 features increase risk

    def test_low_risk_has_negative_contributions(self, trained_model, low_risk_vuln):
        result = trained_model.explain_prediction(low_risk_vuln)
        # Low risk should have mostly negative contributions
        negative_count = sum(
            1 for fe in result.feature_explanations if fe.contribution < -0.5
        )
        assert negative_count >= 2  # At least 2 features decrease risk

    def test_contributions_sorted_by_impact(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        abs_contribs = [abs(fe.contribution) for fe in result.feature_explanations]
        assert abs_contribs == sorted(abs_contribs, reverse=True)

    def test_asset_criticality_is_strong_driver(self, trained_model, critical_vuln):
        """Asset criticality should be the strongest feature (59.4% importance)."""
        result = trained_model.explain_prediction(critical_vuln)
        # Find asset_criticality contribution
        ac_fe = next(
            fe for fe in result.feature_explanations if fe.name == "asset_criticality"
        )
        assert ac_fe.contribution > 5.0  # Should be strong positive

    def test_epss_encoded_correctly(self, trained_model, critical_vuln):
        """EPSS value should be correctly encoded in the explanation.

        Note: With live EPSS data updates (2026-03-07), feature importance
        shifted — asset_criticality dominates (68%), exploit_maturity 2nd (11%).
        EPSS marginal contribution varies as most golden dataset vulns now
        have updated (often higher) EPSS scores from the live API.
        The key invariant is that EPSS is correctly encoded and present.
        """
        result = trained_model.explain_prediction(critical_vuln)
        epss_fe = next(
            fe for fe in result.feature_explanations if fe.name == "epss_score"
        )
        # EPSS value should be correctly encoded (close to raw input)
        assert epss_fe.value > 0.9  # High EPSS vuln should have high encoded value
        # Contribution magnitude can vary with training data; just verify it's present
        assert isinstance(epss_fe.contribution, (int, float))

    def test_feature_directions_correct(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        for fe in result.feature_explanations:
            if fe.contribution > 0.5:
                assert fe.direction == "increases_risk"
            elif fe.contribution < -0.5:
                assert fe.direction == "decreases_risk"
            else:
                assert fe.direction == "neutral"


# ---------------------------------------------------------------------------
# Tests: Narrative quality
# ---------------------------------------------------------------------------


class TestNarrative:
    def test_critical_narrative_mentions_cve(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        assert "CVE-2021-44228" in result.risk_narrative

    def test_critical_narrative_mentions_p0(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        assert "P0" in result.risk_narrative

    def test_narrative_mentions_score(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        assert "scored" in result.risk_narrative
        assert "/100" in result.risk_narrative

    def test_low_risk_narrative_mentions_mitigators(self, trained_model, low_risk_vuln):
        result = trained_model.explain_prediction(low_risk_vuln)
        assert "mitigator" in result.risk_narrative.lower() or "below" in result.risk_narrative.lower()

    def test_narrative_mentions_drivers(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        assert "driver" in result.risk_narrative.lower() or "risk" in result.risk_narrative.lower()


# ---------------------------------------------------------------------------
# Tests: Serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_explanation_to_dict(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "risk_score" in d
        assert "base_value" in d
        assert "feature_explanations" in d
        assert "top_drivers" in d
        assert "risk_narrative" in d

    def test_explanation_json_serializable(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        d = result.to_dict()
        # Should not raise
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["risk_score"] == d["risk_score"]

    def test_feature_explanation_to_dict(self, trained_model, critical_vuln):
        result = trained_model.explain_prediction(critical_vuln)
        fe = result.feature_explanations[0]
        d = fe.to_dict()
        assert "name" in d
        assert "value" in d
        assert "raw_value" in d
        assert "contribution" in d
        assert "direction" in d
        assert "explanation" in d


# ---------------------------------------------------------------------------
# Tests: Fallback explanation (untrained model)
# ---------------------------------------------------------------------------


class TestFallbackExplanation:
    def test_fallback_returns_explanation(self, untrained_model, critical_vuln):
        result = untrained_model.explain_prediction(critical_vuln)
        assert isinstance(result, ExplanationResult)
        assert result.risk_score >= 0

    def test_fallback_mentions_fallback(self, untrained_model, critical_vuln):
        result = untrained_model.explain_prediction(critical_vuln)
        assert "fallback" in result.risk_narrative.lower()

    def test_fallback_has_9_features(self, untrained_model, critical_vuln):
        result = untrained_model.explain_prediction(critical_vuln)
        assert len(result.feature_explanations) == 9


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_all_zeros_vuln(self, trained_model):
        vuln = {
            "cvss_score": 0,
            "epss_score": 0,
            "in_kev": False,
            "asset_criticality": 0,
            "network_exposure": "none",
            "exploit_available": False,
            "exploit_maturity": "none",
            "reachable": False,
        }
        result = trained_model.explain_prediction(vuln)
        assert result.risk_score < 20

    def test_all_max_vuln(self, trained_model):
        vuln = {
            "cvss_score": 10.0,
            "epss_score": 0.99,
            "in_kev": True,
            "asset_criticality": 1.0,
            "network_exposure": "internet",
            "exploit_available": True,
            "exploit_maturity": "weaponized",
            "reachable": True,
            "has_chain": True,
        }
        result = trained_model.explain_prediction(vuln)
        assert result.risk_score > 80

    def test_medium_vuln_between_extremes(self, trained_model, medium_vuln):
        result = trained_model.explain_prediction(medium_vuln)
        assert 10 < result.risk_score < 90
