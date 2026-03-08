"""Tests for enterprise ContextualRiskScorer — severity adjustments based on business context."""
import pytest

from core.services.enterprise.risk_scorer import ContextualRiskScorer


class TestContextualRiskScorer:
    @pytest.fixture
    def scorer(self):
        return ContextualRiskScorer()

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------
    def test_normalize_none_severity(self, scorer):
        assert scorer._normalize_severity(None) == "MEDIUM"

    def test_normalize_empty_severity(self, scorer):
        assert scorer._normalize_severity("") == "MEDIUM"

    def test_normalize_valid_severities(self, scorer):
        for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            assert scorer._normalize_severity(sev) == sev

    def test_normalize_lowercase(self, scorer):
        assert scorer._normalize_severity("high") == "HIGH"

    def test_normalize_unknown(self, scorer):
        assert scorer._normalize_severity("UNKNOWN") == "MEDIUM"

    # ------------------------------------------------------------------
    # Severity index
    # ------------------------------------------------------------------
    def test_severity_index_low(self, scorer):
        assert scorer._severity_index("LOW") == 0

    def test_severity_index_medium(self, scorer):
        assert scorer._severity_index("MEDIUM") == 1

    def test_severity_index_high(self, scorer):
        assert scorer._severity_index("HIGH") == 2

    def test_severity_index_critical(self, scorer):
        assert scorer._severity_index("CRITICAL") == 3

    def test_severity_index_unknown_defaults_to_1(self, scorer):
        assert scorer._severity_index("BOGUS") == 1

    # ------------------------------------------------------------------
    # apply() basic
    # ------------------------------------------------------------------
    def test_apply_empty_findings(self, scorer):
        result = scorer.apply([], None)
        assert result == []

    def test_apply_no_business_context(self, scorer):
        findings = [{"severity": "HIGH", "id": "f1"}]
        result = scorer.apply(findings, None)
        assert len(result) == 1
        assert result[0]["fixops_severity"] == "HIGH"

    def test_apply_preserves_scanner_severity(self, scorer):
        findings = [{"severity": "LOW"}]
        result = scorer.apply(findings, {})
        assert result[0]["scanner_severity"] == "LOW"

    # ------------------------------------------------------------------
    # Customer impact adjustments
    # ------------------------------------------------------------------
    def test_high_customer_impact_promotes(self, scorer):
        findings = [{"severity": "MEDIUM"}]
        ctx = {"customer_impact": "critical"}
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "HIGH"
        assert "high_customer_impact" in result[0].get("risk_factors", [])

    def test_low_customer_impact_demotes(self, scorer):
        findings = [{"severity": "HIGH"}]
        ctx = {"customer_impact": "low"}
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "MEDIUM"

    def test_business_criticality_alias(self, scorer):
        findings = [{"severity": "MEDIUM"}]
        ctx = {"business_criticality": "high"}
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "HIGH"

    # ------------------------------------------------------------------
    # Data classification adjustments
    # ------------------------------------------------------------------
    def test_sensitive_data_promotes(self, scorer):
        findings = [{"severity": "LOW"}]
        ctx = {"data_classification": "pii"}
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "MEDIUM"

    def test_non_sensitive_data_demotes(self, scorer):
        findings = [{"severity": "MEDIUM"}]
        ctx = {"data_classification": "public"}
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "LOW"

    def test_data_classification_list(self, scorer):
        findings = [{"severity": "LOW"}]
        ctx = {"data_classification": ["pci", "financial"]}
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "MEDIUM"

    # ------------------------------------------------------------------
    # Deployment frequency adjustments
    # ------------------------------------------------------------------
    def test_rapid_deployment_promotes(self, scorer):
        findings = [{"severity": "LOW"}]
        ctx = {"deployment_frequency": "continuous"}
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "MEDIUM"

    def test_infrequent_deployment_demotes(self, scorer):
        findings = [{"severity": "HIGH"}]
        ctx = {"deployment_frequency": "quarterly"}
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "MEDIUM"

    # ------------------------------------------------------------------
    # Clamping adjustments
    # ------------------------------------------------------------------
    def test_adjustment_capped_at_plus_one(self, scorer):
        """Multiple positive factors should not escalate by more than 1."""
        findings = [{"severity": "LOW"}]
        ctx = {
            "customer_impact": "critical",
            "data_classification": "pii",
            "deployment_frequency": "continuous",
        }
        result = scorer.apply(findings, ctx)
        # Even with 3 positive factors, max adjustment is +1
        assert result[0]["fixops_severity"] == "MEDIUM"

    def test_adjustment_capped_at_minus_one(self, scorer):
        """Multiple negative factors should not demote by more than 1."""
        findings = [{"severity": "HIGH"}]
        ctx = {
            "customer_impact": "low",
            "data_classification": "public",
            "deployment_frequency": "quarterly",
        }
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "MEDIUM"

    def test_critical_cannot_go_above_critical(self, scorer):
        findings = [{"severity": "CRITICAL"}]
        ctx = {"customer_impact": "critical"}
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "CRITICAL"

    def test_low_cannot_go_below_low(self, scorer):
        findings = [{"severity": "LOW"}]
        ctx = {"customer_impact": "low"}
        result = scorer.apply(findings, ctx)
        assert result[0]["fixops_severity"] == "LOW"

    # ------------------------------------------------------------------
    # Pre-existing fixops_severity pass-through
    # ------------------------------------------------------------------
    def test_existing_fixops_severity_preserved(self, scorer):
        findings = [{"severity": "LOW", "fixops_severity": "CRITICAL"}]
        result = scorer.apply(findings, {})
        assert result[0]["fixops_severity"] == "CRITICAL"

    # ------------------------------------------------------------------
    # Multiple findings
    # ------------------------------------------------------------------
    def test_multiple_findings(self, scorer):
        findings = [
            {"severity": "LOW"},
            {"severity": "HIGH"},
            {"severity": "CRITICAL"},
        ]
        result = scorer.apply(findings, {"customer_impact": "high"})
        assert len(result) == 3
        assert result[0]["fixops_severity"] == "MEDIUM"
        assert result[1]["fixops_severity"] == "CRITICAL"
        assert result[2]["fixops_severity"] == "CRITICAL"
