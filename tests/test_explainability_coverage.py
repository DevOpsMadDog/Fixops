"""Tests for ExplainabilityService — feature attribution and narrative generation."""
import pytest

from core.services.enterprise.explainability import (
    ExplainabilityService,
    _normalise_feature_name,
)


class TestNormaliseFeatureName:
    def test_lowercase(self):
        assert _normalise_feature_name("CVSS Score") == "cvss_score"

    def test_spaces_to_underscores(self):
        assert _normalise_feature_name("risk factor") == "risk_factor"

    def test_already_normalized(self):
        assert _normalise_feature_name("epss_score") == "epss_score"

    def test_empty_string(self):
        assert _normalise_feature_name("") == ""

    def test_mixed_case_with_spaces(self):
        assert _normalise_feature_name("Customer Impact Score") == "customer_impact_score"


class TestExplainabilityService:
    @pytest.fixture
    def svc(self):
        return ExplainabilityService()

    def test_init(self, svc):
        assert svc._baseline == {}

    def test_explain_empty_baseline(self, svc):
        result = svc.explain({"cvss": 9.8, "epss": 0.95})
        assert result["cvss"] == 9.8
        assert result["epss"] == 0.95

    def test_explain_with_baseline(self, svc):
        svc.prime_baseline([{"cvss": 5.0, "epss": 0.5}])
        result = svc.explain({"cvss": 9.8, "epss": 0.95})
        assert result["cvss"] == pytest.approx(4.8)
        assert result["epss"] == pytest.approx(0.45)

    def test_prime_baseline_multiple_examples(self, svc):
        svc.prime_baseline([
            {"cvss": 4.0, "epss": 0.2},
            {"cvss": 6.0, "epss": 0.4},
        ])
        assert svc._baseline["cvss"] == pytest.approx(5.0)
        assert svc._baseline["epss"] == pytest.approx(0.3)

    def test_prime_baseline_empty_list(self, svc):
        svc.prime_baseline([])
        assert svc._baseline == {}

    def test_prime_baseline_none(self, svc):
        svc.prime_baseline(None)
        assert svc._baseline == {}

    def test_prime_baseline_non_numeric_skipped(self, svc):
        svc.prime_baseline([{"cvss": 5.0, "name": "not-numeric"}])
        assert "cvss" in svc._baseline
        assert "name" not in svc._baseline

    def test_prime_baseline_non_mapping_skipped(self, svc):
        svc.prime_baseline(["not a dict", 42])
        assert svc._baseline == {}

    def test_explain_non_numeric_skipped(self, svc):
        result = svc.explain({"cvss": 9.8, "name": "not-numeric"})
        assert "cvss" in result
        assert "name" not in result

    def test_generate_narrative_empty(self, svc):
        result = svc.generate_narrative({}, {})
        assert "baseline" in result.lower()

    def test_generate_narrative_with_contributions(self, svc):
        features = {"cvss": 9.8, "epss": 0.95}
        contributions = {"cvss": 4.8, "epss": 0.45}
        narrative = svc.generate_narrative(features, contributions)
        assert "cvss" in narrative.lower()
        assert "increased" in narrative or "decreased" in narrative

    def test_generate_narrative_negative_contribution(self, svc):
        features = {"cvss": 2.0}
        contributions = {"cvss": -3.0}
        narrative = svc.generate_narrative(features, contributions)
        assert "decreased" in narrative

    def test_generate_narrative_top_3_only(self, svc):
        features = {f"f{i}": float(i) for i in range(10)}
        contributions = {f"f{i}": float(i) for i in range(10)}
        narrative = svc.generate_narrative(features, contributions)
        # Should only mention top 3
        parts = narrative.split(",")
        assert len(parts) <= 3

    def test_explain_rounding(self, svc):
        svc.prime_baseline([{"score": 5.0}])
        result = svc.explain({"score": 5.33333})
        assert result["score"] == pytest.approx(0.3333, abs=0.001)
