"""Tests for enterprise ComplianceEngine — framework evaluation and severity mapping."""
import pytest

from core.services.enterprise.compliance_engine import ComplianceEngine, compliance_engine


class TestComplianceEngine:
    @pytest.fixture
    def engine(self):
        return ComplianceEngine()

    # ------------------------------------------------------------------
    # Framework thresholds
    # ------------------------------------------------------------------
    def test_default_thresholds(self, engine):
        assert engine.framework_thresholds["pci_dss"] == "HIGH"
        assert engine.framework_thresholds["sox"] == "HIGH"
        assert engine.framework_thresholds["hipaa"] == "HIGH"
        assert engine.framework_thresholds["nist"] == "MEDIUM"
        assert engine.framework_thresholds["gdpr"] == "MEDIUM"

    # ------------------------------------------------------------------
    # Severity normalization
    # ------------------------------------------------------------------
    def test_normalize_none_severity(self, engine):
        assert engine._normalize_severity(None) == "LOW"

    def test_normalize_empty(self, engine):
        assert engine._normalize_severity("") == "LOW"

    def test_normalize_valid(self, engine):
        for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            assert engine._normalize_severity(sev) == sev

    def test_normalize_lowercase(self, engine):
        assert engine._normalize_severity("high") == "HIGH"

    def test_normalize_unknown(self, engine):
        assert engine._normalize_severity("UNKNOWN") == "LOW"

    # ------------------------------------------------------------------
    # Max severity
    # ------------------------------------------------------------------
    def test_max_severity_same(self, engine):
        assert engine._max_severity("HIGH", "HIGH") == "HIGH"

    def test_max_severity_different(self, engine):
        assert engine._max_severity("LOW", "CRITICAL") == "CRITICAL"

    def test_max_severity_reversed(self, engine):
        assert engine._max_severity("CRITICAL", "LOW") == "CRITICAL"

    # ------------------------------------------------------------------
    # Status determination
    # ------------------------------------------------------------------
    def test_compliant(self, engine):
        assert engine._determine_status("HIGH", "LOW") == "compliant"

    def test_needs_review(self, engine):
        assert engine._determine_status("HIGH", "MEDIUM") == "needs_review"

    def test_non_compliant_at_threshold(self, engine):
        assert engine._determine_status("HIGH", "HIGH") == "non_compliant"

    def test_non_compliant_above_threshold(self, engine):
        assert engine._determine_status("HIGH", "CRITICAL") == "non_compliant"

    # ------------------------------------------------------------------
    # Full evaluation
    # ------------------------------------------------------------------
    def test_evaluate_empty_findings(self, engine):
        result = engine.evaluate(["pci_dss"], [])
        assert "pci_dss" in result
        assert result["pci_dss"]["status"] == "compliant"

    def test_evaluate_single_framework(self, engine):
        findings = [{"severity": "CRITICAL", "id": "CVE-2024-001"}]
        result = engine.evaluate(["pci_dss"], findings)
        assert result["pci_dss"]["status"] == "non_compliant"

    def test_evaluate_multiple_frameworks(self, engine):
        findings = [{"severity": "HIGH", "id": "CVE-2024-001"}]
        result = engine.evaluate(["pci_dss", "nist"], findings)
        assert "pci_dss" in result
        assert "nist" in result

    def test_evaluate_with_risk_tier(self, engine):
        findings = [{"severity": "LOW", "risk_tier": "CRITICAL"}]
        result = engine.evaluate(["pci_dss"], findings)
        assert result["pci_dss"]["status"] == "non_compliant"

    def test_evaluate_with_fixops_severity(self, engine):
        findings = [{"severity": "LOW", "fixops_severity": "HIGH"}]
        result = engine.evaluate(["pci_dss"], findings)
        assert result["pci_dss"]["status"] == "non_compliant"

    def test_evaluate_compliant_with_low_findings(self, engine):
        findings = [
            {"severity": "LOW", "id": "f1"},
            {"severity": "LOW", "id": "f2"},
        ]
        result = engine.evaluate(["pci_dss"], findings)
        assert result["pci_dss"]["status"] == "compliant"

    def test_evaluate_result_structure(self, engine):
        findings = [{"severity": "MEDIUM", "id": "f1"}]
        result = engine.evaluate(["nist"], findings)
        entry = result["nist"]
        assert "framework" in entry
        assert "status" in entry
        assert "threshold" in entry
        assert "highest_scanner_severity" in entry
        assert "highest_fixops_severity" in entry
        assert "findings" in entry

    def test_evaluate_unknown_framework(self, engine):
        """Unknown frameworks should default to HIGH threshold."""
        findings = [{"severity": "HIGH", "id": "f1"}]
        result = engine.evaluate(["custom_framework"], findings)
        assert result["custom_framework"]["status"] == "non_compliant"

    def test_singleton_instance(self):
        assert compliance_engine is not None
        assert isinstance(compliance_engine, ComplianceEngine)
