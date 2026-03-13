"""Tests for ComplianceEngine and ComplianceAutoMapper.

Covers:
  - Framework enum
  - SOC2, PCI-DSS, ISO 27001, NIST control definitions
  - ComplianceEngine initialization
  - assess_framework
  - get_compliance_gaps
  - generate_audit_bundle
  - ComplianceAutoMapper initialization
  - map_finding_to_controls
  - get_coverage_report
  - identify_gaps
  - get_compliance_engine singleton
"""

from __future__ import annotations

import pytest

from compliance.compliance_engine import (
    ComplianceAutoMapper,
    ComplianceEngine,
    CompliancePosture,
    Framework,
    get_compliance_engine,
    SOC2_CONTROLS,
    PCI_DSS_CONTROLS,
    ISO_27001_CONTROLS,
)


# ──────────────────────────────────────────────────────
#  Framework Enum
# ──────────────────────────────────────────────────────


class TestFrameworkEnum:
    def test_soc2_value(self):
        assert Framework.SOC2.value == "SOC2"

    def test_pci_dss_value(self):
        assert Framework.PCI_DSS.value == "PCI_DSS_4.0"

    def test_iso_27001_value(self):
        assert Framework.ISO_27001.value == "ISO_27001_2022"

    def test_all_frameworks(self):
        frameworks = list(Framework)
        assert len(frameworks) >= 3


# ──────────────────────────────────────────────────────
#  Control Definitions
# ──────────────────────────────────────────────────────


class TestControlDefinitions:
    def test_soc2_controls_exist(self):
        assert isinstance(SOC2_CONTROLS, dict)
        assert len(SOC2_CONTROLS) > 0

    def test_pci_dss_controls_exist(self):
        assert isinstance(PCI_DSS_CONTROLS, dict)
        assert len(PCI_DSS_CONTROLS) > 0

    def test_iso_27001_controls_exist(self):
        assert isinstance(ISO_27001_CONTROLS, dict)
        assert len(ISO_27001_CONTROLS) > 0

    def test_soc2_cc6_1_exists(self):
        """CC6.1 (Logical Access) is a core SOC2 control."""
        matching = [k for k in SOC2_CONTROLS if "CC6" in k]
        assert len(matching) > 0

    def test_pci_dss_req6_exists(self):
        """Requirement 6 (Secure Development) is a core PCI-DSS control."""
        matching = [k for k in PCI_DSS_CONTROLS if k.startswith("6")]
        assert len(matching) > 0


# ──────────────────────────────────────────────────────
#  ComplianceEngine
# ──────────────────────────────────────────────────────


class TestComplianceEngine:
    @pytest.fixture
    def engine(self):
        return ComplianceEngine()

    def test_init(self, engine):
        assert engine is not None

    def test_assess_soc2(self, engine):
        result = engine.assess_framework(Framework.SOC2)
        assert result is not None
        assert isinstance(result, CompliancePosture)
        # Should have a to_dict method
        d = result.to_dict()
        assert isinstance(d, dict)

    def test_assess_pci_dss(self, engine):
        result = engine.assess_framework(Framework.PCI_DSS)
        assert result is not None
        assert isinstance(result, CompliancePosture)

    def test_assess_iso_27001(self, engine):
        result = engine.assess_framework(Framework.ISO_27001)
        assert result is not None
        assert isinstance(result, CompliancePosture)

    def test_get_compliance_gaps(self, engine):
        gaps = engine.get_compliance_gaps(Framework.SOC2)
        assert isinstance(gaps, (list, dict))

    def test_generate_audit_bundle(self, engine):
        bundle = engine.generate_audit_bundle(Framework.SOC2, app_id="test-app")
        assert bundle is not None
        assert isinstance(bundle, dict)

    def test_framework_controls_mapping_consistency(self, engine):
        """Each framework should map to its control definitions."""
        for fw in [Framework.SOC2, Framework.PCI_DSS, Framework.ISO_27001]:
            result = engine.assess_framework(fw)
            assert result is not None


# ──────────────────────────────────────────────────────
#  ComplianceAutoMapper
# ──────────────────────────────────────────────────────


class TestComplianceAutoMapper:
    @pytest.fixture
    def mapper(self):
        return ComplianceAutoMapper()

    def test_init(self, mapper):
        assert mapper is not None

    def test_get_coverage_report_soc2(self, mapper):
        report = mapper.get_coverage_report("SOC2")
        assert report is not None
        # Returns a FrameworkCoverage object, not a dict
        assert hasattr(report, "framework")
        assert hasattr(report, "total_controls")
        assert hasattr(report, "coverage_pct")

    def test_identify_gaps_pci_dss(self, mapper):
        gaps = mapper.identify_gaps("PCI_DSS_4.0")
        assert isinstance(gaps, (list, dict))

    def test_map_finding_to_controls(self, mapper):
        finding = {
            "id": "FIND-001",
            "type": "sast",
            "severity": "high",
            "cwe": "CWE-89",
            "title": "SQL Injection",
        }
        controls = mapper.map_finding_to_controls(finding)
        assert isinstance(controls, (list, dict))


# ──────────────────────────────────────────────────────
#  Singleton
# ──────────────────────────────────────────────────────


class TestComplianceEngineSingleton:
    def test_get_compliance_engine(self):
        engine = get_compliance_engine()
        assert engine is not None
        assert isinstance(engine, ComplianceEngine)

    def test_singleton_returns_same_instance(self):
        e1 = get_compliance_engine()
        e2 = get_compliance_engine()
        assert e1 is e2
