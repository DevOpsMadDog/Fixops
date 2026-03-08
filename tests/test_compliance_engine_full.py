"""Tests for ComplianceEngine — full compliance auto-mapping."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))
sys.path.insert(0, os.path.join(ROOT, "suite-evidence-risk"))

import pytest

from compliance.compliance_engine import (
    ComplianceEngine,
    CompliancePosture,
    Control,
    ControlAssessment,
    ControlStatus,
    EvidenceType,
    Framework,
    SOC2_CONTROLS,
    PCI_DSS_CONTROLS,
    NIST_800_53_CONTROLS,
    ISO_27001_CONTROLS,
)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------
class TestFrameworkEnum:
    def test_soc2(self):
        assert Framework.SOC2 == "SOC2"

    def test_pci_dss(self):
        assert Framework.PCI_DSS == "PCI_DSS_4.0"

    def test_iso_27001(self):
        assert Framework.ISO_27001 == "ISO_27001_2022"

    def test_nist_800_53(self):
        assert Framework.NIST_800_53 == "NIST_800_53_R5"

    def test_nist_csf(self):
        assert Framework.NIST_CSF == "NIST_CSF_2.0"

    def test_owasp_asvs(self):
        assert Framework.OWASP_ASVS == "OWASP_ASVS_4.0"


class TestControlStatusEnum:
    def test_all_statuses(self):
        assert ControlStatus.SATISFIED == "satisfied"
        assert ControlStatus.PARTIALLY_SATISFIED == "partially_satisfied"
        assert ControlStatus.NOT_SATISFIED == "not_satisfied"
        assert ControlStatus.NOT_ASSESSED == "not_assessed"
        assert ControlStatus.NOT_APPLICABLE == "not_applicable"


class TestEvidenceTypeEnum:
    def test_evidence_types(self):
        assert EvidenceType.SCAN_RESULT == "scan_result"
        assert EvidenceType.POLICY_CHECK == "policy_check"
        assert EvidenceType.PENETRATION_TEST == "penetration_test"
        assert EvidenceType.CODE_REVIEW == "code_review"
        assert EvidenceType.INCIDENT_RESPONSE == "incident_response"


# ---------------------------------------------------------------------------
# Control data class tests
# ---------------------------------------------------------------------------
class TestControlDataClass:
    def test_control_to_dict(self):
        ctrl = Control(
            control_id="CC6.1",
            framework=Framework.SOC2,
            title="Logical Access Security",
            description="Access controls",
            category="CC6",
            related_cwes=["CWE-287", "CWE-306"],
            evidence_types=[EvidenceType.ACCESS_REVIEW],
        )
        d = ctrl.to_dict()
        assert d["control_id"] == "CC6.1"
        assert d["framework"] == "SOC2"
        assert "CWE-287" in d["related_cwes"]


class TestControlAssessmentDataClass:
    def test_assessment_to_dict(self):
        assessment = ControlAssessment(
            assessment_id="a-1",
            control_id="CC6.1",
            framework=Framework.SOC2,
            status=ControlStatus.SATISFIED,
            evidence_count=5,
            findings_count=2,
            score=0.85,
        )
        d = assessment.to_dict()
        assert d["status"] == "satisfied"
        assert d["evidence_count"] == 5
        assert d["score"] == 0.85


class TestCompliancePostureDataClass:
    def test_posture_to_dict(self):
        posture = CompliancePosture(
            framework=Framework.SOC2,
            total_controls=20,
            satisfied=15,
            partially_satisfied=3,
            not_satisfied=2,
            overall_score=0.82,
        )
        d = posture.to_dict()
        assert d["framework"] == "SOC2"
        assert d["total_controls"] == 20
        assert d["satisfied"] == 15
        assert "compliance_percentage" in d

    def test_compliance_percentage_calculation(self):
        posture = CompliancePosture(
            framework=Framework.PCI_DSS,
            total_controls=10,
            satisfied=8,
            partially_satisfied=2,
            not_applicable=0,
        )
        d = posture.to_dict()
        # (8 + 2*0.5) / 10 * 100 = 90.0
        assert d["compliance_percentage"] == 90.0

    def test_gaps_truncated(self):
        posture = CompliancePosture(
            framework=Framework.SOC2,
            gaps=["gap-" + str(i) for i in range(30)],
        )
        d = posture.to_dict()
        assert len(d["gaps"]) == 20  # truncated to 20


# ---------------------------------------------------------------------------
# Control registry tests
# ---------------------------------------------------------------------------
class TestControlRegistries:
    def test_soc2_controls_exist(self):
        assert len(SOC2_CONTROLS) > 0
        assert "CC6.1" in SOC2_CONTROLS
        assert "CC7.2" in SOC2_CONTROLS

    def test_pci_dss_controls_exist(self):
        assert len(PCI_DSS_CONTROLS) > 0
        assert "6.2" in PCI_DSS_CONTROLS

    def test_nist_800_53_controls_exist(self):
        assert len(NIST_800_53_CONTROLS) > 0
        assert "AC-2" in NIST_800_53_CONTROLS
        assert "RA-5" in NIST_800_53_CONTROLS

    def test_iso_27001_controls_exist(self):
        assert len(ISO_27001_CONTROLS) > 0

    def test_all_controls_have_title(self):
        for registry in [SOC2_CONTROLS, PCI_DSS_CONTROLS, NIST_800_53_CONTROLS, ISO_27001_CONTROLS]:
            for ctrl_id, ctrl_def in registry.items():
                assert "title" in ctrl_def, f"{ctrl_id} missing title"

    def test_all_controls_have_category(self):
        for registry in [SOC2_CONTROLS, PCI_DSS_CONTROLS, NIST_800_53_CONTROLS]:
            for ctrl_id, ctrl_def in registry.items():
                assert "category" in ctrl_def, f"{ctrl_id} missing category"

    def test_all_controls_have_evidence(self):
        for registry in [SOC2_CONTROLS, PCI_DSS_CONTROLS, NIST_800_53_CONTROLS]:
            for ctrl_id, ctrl_def in registry.items():
                assert "evidence" in ctrl_def, f"{ctrl_id} missing evidence"

    def test_cwe_mapped_controls(self):
        # CC6.1 should map to CWE-287
        assert "CWE-287" in SOC2_CONTROLS["CC6.1"]["cwes"]
        # PCI DSS 6.2 should map to SQL injection CWEs
        assert "CWE-89" in PCI_DSS_CONTROLS["6.2"]["cwes"]


# ---------------------------------------------------------------------------
# ComplianceEngine tests
# ---------------------------------------------------------------------------
class TestComplianceEngine:
    @pytest.fixture
    def engine(self):
        return ComplianceEngine()

    def test_init(self, engine):
        assert engine is not None

    def test_get_supported_frameworks(self, engine):
        frameworks = engine.get_supported_frameworks()
        assert len(frameworks) >= 4

    def test_get_control_details_soc2(self, engine):
        details = engine.get_control_details("CC6.1", Framework.SOC2)
        assert details is not None

    def test_get_control_details_pci(self, engine):
        details = engine.get_control_details("6.2", Framework.PCI_DSS)
        assert details is not None

    def test_get_control_details_not_found(self, engine):
        details = engine.get_control_details("NONEXISTENT", Framework.SOC2)
        assert details is None

    def test_map_findings_to_controls(self, engine):
        findings = [
            {"cwe_id": "CWE-89", "severity": "critical", "title": "SQL Injection"},
            {"cwe_id": "CWE-287", "severity": "high", "title": "Auth bypass"},
        ]
        mappings = engine.map_findings_to_controls(findings)
        assert len(mappings) > 0

    def test_map_findings_empty(self, engine):
        mappings = engine.map_findings_to_controls([])
        assert isinstance(mappings, (list, dict))

    def test_assess_framework(self, engine):
        result = engine.assess_framework(Framework.SOC2, app_id="test-app")
        assert isinstance(result, CompliancePosture)
        assert result.framework == Framework.SOC2

    def test_assess_all_frameworks(self, engine):
        result = engine.assess_all_frameworks(app_id="test-app")
        assert isinstance(result, list)
        assert len(result) >= 4

    def test_get_compliance_gaps(self, engine):
        gaps = engine.get_compliance_gaps(Framework.SOC2)
        assert isinstance(gaps, list)

    def test_get_cwe_control_mapping(self, engine):
        mapping = engine.get_cwe_control_mapping("CWE-89")
        assert isinstance(mapping, (list, dict))
        assert len(mapping) > 0

    def test_get_cwe_control_mapping_unknown(self, engine):
        mapping = engine.get_cwe_control_mapping("CWE-99999")
        assert isinstance(mapping, (list, dict))
        assert len(mapping) == 0

    def test_generate_audit_bundle(self, engine):
        bundle = engine.generate_audit_bundle(Framework.SOC2, app_id="test-app")
        assert isinstance(bundle, dict)

    def test_get_supported_frameworks_with_soc2(self, engine):
        frameworks = engine.get_supported_frameworks()
        assert len(frameworks) >= 4
        names = [f.get("name", f.get("framework", "")) for f in frameworks]
        assert any("SOC2" in n for n in names)
