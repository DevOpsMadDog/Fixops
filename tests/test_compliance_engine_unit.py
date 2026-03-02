"""
Unit tests for suite-evidence-risk/compliance/compliance_engine.py — Compliance Engine [V10/V3].

Covers:
  - Enums: Framework, ControlStatus, EvidenceType
  - Data classes: Control, ControlAssessment, CompliancePosture
  - Control definitions: SOC2, PCI_DSS, NIST_800_53, ISO_27001
  - ComplianceDB: upsert_assessment, add_evidence, save_posture,
    get_assessments, get_evidence_for_control, get_posture_trend
  - ComplianceEngine: map_findings_to_controls
  - CWE → controls reverse index
"""

import os
import sqlite3
from datetime import datetime, timezone

import pytest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-evidence-risk"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from compliance.compliance_engine import (
    Framework,
    ControlStatus,
    EvidenceType,
    Control,
    ControlAssessment,
    CompliancePosture,
    ComplianceDB,
    ComplianceEngine,
    SOC2_CONTROLS,
    PCI_DSS_CONTROLS,
    NIST_800_53_CONTROLS,
    ISO_27001_CONTROLS,
    _build_cwe_index,
    _CWE_TO_CONTROLS,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TestFrameworkEnum:
    def test_soc2_value(self):
        assert Framework.SOC2.value == "SOC2"

    def test_pci_dss_value(self):
        assert Framework.PCI_DSS.value == "PCI_DSS_4.0"

    def test_iso_value(self):
        assert Framework.ISO_27001.value == "ISO_27001_2022"

    def test_nist_800_53_value(self):
        assert Framework.NIST_800_53.value == "NIST_800_53_R5"

    def test_nist_csf_value(self):
        assert Framework.NIST_CSF.value == "NIST_CSF_2.0"

    def test_owasp_value(self):
        assert Framework.OWASP_ASVS.value == "OWASP_ASVS_4.0"


class TestControlStatusEnum:
    def test_satisfied(self):
        assert ControlStatus.SATISFIED.value == "satisfied"

    def test_not_assessed(self):
        assert ControlStatus.NOT_ASSESSED.value == "not_assessed"

    def test_all_values(self):
        statuses = [s.value for s in ControlStatus]
        assert "satisfied" in statuses
        assert "partially_satisfied" in statuses
        assert "not_satisfied" in statuses
        assert "not_assessed" in statuses
        assert "not_applicable" in statuses


class TestEvidenceTypeEnum:
    def test_scan_result(self):
        assert EvidenceType.SCAN_RESULT.value == "scan_result"

    def test_penetration_test(self):
        assert EvidenceType.PENETRATION_TEST.value == "penetration_test"

    def test_count(self):
        assert len(EvidenceType) == 10


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

class TestControlDataClass:
    def test_to_dict(self):
        ctrl = Control(
            control_id="CC6.1",
            framework=Framework.SOC2,
            title="Logical Access Security",
            description="Test control",
            category="CC6",
            related_cwes=["CWE-287"],
            evidence_types=[EvidenceType.ACCESS_REVIEW],
        )
        d = ctrl.to_dict()
        assert d["control_id"] == "CC6.1"
        assert d["framework"] == "SOC2"
        assert d["related_cwes"] == ["CWE-287"]
        assert d["evidence_types"] == ["access_review"]

    def test_defaults(self):
        ctrl = Control(
            control_id="test",
            framework=Framework.SOC2,
            title="t",
            description="d",
            category="c",
        )
        assert ctrl.sub_category == ""
        assert ctrl.related_cwes == []
        assert ctrl.automated is True


class TestControlAssessment:
    def test_to_dict(self):
        a = ControlAssessment(
            assessment_id="a1",
            control_id="CC6.1",
            framework=Framework.SOC2,
            status=ControlStatus.SATISFIED,
            evidence_count=3,
            score=0.95,
        )
        d = a.to_dict()
        assert d["assessment_id"] == "a1"
        assert d["status"] == "satisfied"
        assert d["evidence_count"] == 3
        assert d["score"] == 0.95

    def test_defaults(self):
        a = ControlAssessment(
            assessment_id="a1",
            control_id="CC6.1",
            framework=Framework.SOC2,
            status=ControlStatus.NOT_ASSESSED,
        )
        assert a.findings_count == 0
        assert a.critical_findings == 0
        assert a.assessor == "automated"


class TestCompliancePosture:
    def test_to_dict_compliance_percentage(self):
        p = CompliancePosture(
            framework=Framework.SOC2,
            total_controls=100,
            satisfied=50,
            partially_satisfied=20,
            not_satisfied=20,
            not_assessed=10,
            not_applicable=0,
            overall_score=0.6,
        )
        d = p.to_dict()
        assert d["framework"] == "SOC2"
        # compliance_pct = (50 + 20*0.5) / max(100-0, 1) * 100 = 60.0
        assert d["compliance_percentage"] == 60.0

    def test_not_applicable_excluded_from_denominator(self):
        p = CompliancePosture(
            framework=Framework.PCI_DSS,
            total_controls=20,
            satisfied=10,
            partially_satisfied=0,
            not_satisfied=0,
            not_assessed=0,
            not_applicable=10,
            overall_score=1.0,
        )
        d = p.to_dict()
        # (10 + 0) / max(20-10, 1) * 100 = 100.0
        assert d["compliance_percentage"] == 100.0

    def test_gaps_limited_to_20(self):
        p = CompliancePosture(
            framework=Framework.SOC2,
            total_controls=0,
            gaps=list(range(30)),
        )
        d = p.to_dict()
        assert len(d["gaps"]) == 20


# ---------------------------------------------------------------------------
# Control Definitions
# ---------------------------------------------------------------------------

class TestControlDefinitions:
    def test_soc2_has_controls(self):
        assert len(SOC2_CONTROLS) >= 20
        assert "CC6.1" in SOC2_CONTROLS

    def test_pci_dss_has_controls(self):
        assert len(PCI_DSS_CONTROLS) >= 20
        assert "6.2" in PCI_DSS_CONTROLS

    def test_nist_has_controls(self):
        assert len(NIST_800_53_CONTROLS) >= 20
        assert "AC-2" in NIST_800_53_CONTROLS

    def test_iso_has_controls(self):
        assert len(ISO_27001_CONTROLS) >= 15
        assert "A.8.28" in ISO_27001_CONTROLS

    def test_soc2_cc61_has_cwes(self):
        ctrl = SOC2_CONTROLS["CC6.1"]
        assert "CWE-287" in ctrl["cwes"]

    def test_pci_62_has_sqli_cwe(self):
        ctrl = PCI_DSS_CONTROLS["6.2"]
        assert "CWE-89" in ctrl["cwes"]

    def test_all_controls_have_title(self):
        for ctrl_id, ctrl in SOC2_CONTROLS.items():
            assert "title" in ctrl, f"SOC2 {ctrl_id} missing title"
        for ctrl_id, ctrl in PCI_DSS_CONTROLS.items():
            assert "title" in ctrl, f"PCI {ctrl_id} missing title"


# ---------------------------------------------------------------------------
# CWE Index
# ---------------------------------------------------------------------------

class TestCWEIndex:
    def test_build_populates_index(self):
        _build_cwe_index()
        assert len(_CWE_TO_CONTROLS) > 0

    def test_cwe_287_mapped(self):
        _build_cwe_index()
        assert "CWE-287" in _CWE_TO_CONTROLS
        # CWE-287 is in SOC2 CC6.1, PCI 8.1/8.3, NIST IA-2, ISO A.8.5
        frameworks = {fw for fw, _ in _CWE_TO_CONTROLS["CWE-287"]}
        assert Framework.SOC2 in frameworks

    def test_cwe_89_mapped_to_multiple(self):
        _build_cwe_index()
        assert "CWE-89" in _CWE_TO_CONTROLS
        assert len(_CWE_TO_CONTROLS["CWE-89"]) >= 3  # SOC2, PCI, NIST, ISO


# ---------------------------------------------------------------------------
# ComplianceDB
# ---------------------------------------------------------------------------

class TestComplianceDB:
    @pytest.fixture
    def db(self, tmp_path):
        path = str(tmp_path / "test_compliance.db")
        return ComplianceDB(db_path=path)

    def test_init_creates_tables(self, db):
        with sqlite3.connect(db.db_path) as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = {t[0] for t in tables}
            assert "assessments" in table_names
            assert "evidence_items" in table_names
            assert "posture_history" in table_names

    def test_upsert_assessment(self, db):
        a = ControlAssessment(
            assessment_id="a1",
            control_id="CC6.1",
            framework=Framework.SOC2,
            status=ControlStatus.SATISFIED,
            evidence_count=2,
            score=0.9,
            last_assessed=datetime.now(timezone.utc).isoformat(),
        )
        db.upsert_assessment(a)
        rows = db.get_assessments("SOC2")
        assert len(rows) == 1
        assert rows[0]["status"] == "satisfied"

    def test_upsert_updates_on_conflict(self, db):
        now = datetime.now(timezone.utc).isoformat()
        a1 = ControlAssessment(
            assessment_id="a1",
            control_id="CC6.1",
            framework=Framework.SOC2,
            status=ControlStatus.NOT_SATISFIED,
            score=0.2,
            last_assessed=now,
        )
        db.upsert_assessment(a1)

        a2 = ControlAssessment(
            assessment_id="a2",
            control_id="CC6.1",
            framework=Framework.SOC2,
            status=ControlStatus.SATISFIED,
            score=0.95,
            last_assessed=now,
        )
        db.upsert_assessment(a2)

        rows = db.get_assessments("SOC2")
        assert len(rows) == 1  # upsert, not duplicate
        assert rows[0]["status"] == "satisfied"

    def test_add_evidence(self, db):
        eid = db.add_evidence({
            "control_id": "CC6.1",
            "framework": "SOC2",
            "evidence_type": "scan_result",
            "source": "ZAP",
            "description": "DAST scan",
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })
        assert isinstance(eid, str)
        evidence = db.get_evidence_for_control("CC6.1", "SOC2")
        assert len(evidence) == 1
        assert evidence[0]["source"] == "ZAP"

    def test_save_and_get_posture(self, db):
        p = CompliancePosture(
            framework=Framework.SOC2,
            total_controls=20,
            satisfied=15,
            partially_satisfied=3,
            not_satisfied=2,
            overall_score=0.85,
            last_evaluated=datetime.now(timezone.utc).isoformat(),
        )
        db.save_posture(p)
        trend = db.get_posture_trend("SOC2")
        assert len(trend) == 1
        assert trend[0]["satisfied"] == 15

    def test_posture_trend_limit(self, db):
        for i in range(5):
            p = CompliancePosture(
                framework=Framework.SOC2,
                total_controls=20,
                satisfied=10 + i,
                overall_score=0.5 + i * 0.1,
                last_evaluated=f"2025-01-{i+1:02d}T00:00:00Z",
            )
            db.save_posture(p)
        trend = db.get_posture_trend("SOC2", limit=3)
        assert len(trend) == 3


# ---------------------------------------------------------------------------
# ComplianceEngine
# ---------------------------------------------------------------------------

class TestComplianceEngine:
    @pytest.fixture
    def engine(self, tmp_path):
        db = ComplianceDB(db_path=str(tmp_path / "compliance.db"))
        return ComplianceEngine(db=db)

    def test_init(self, engine):
        assert engine.db is not None
        assert len(engine._framework_controls) >= 4

    def test_map_findings_basic(self, engine):
        findings = [
            {
                "id": "f1",
                "cwe": "CWE-89",
                "severity": "critical",
                "title": "SQL Injection",
            }
        ]
        mappings = engine.map_findings_to_controls(findings)
        assert isinstance(mappings, dict)
        # CWE-89 should map to PCI 6.2, NIST SA-11/SI-10, ISO A.8.26/A.8.28
        assert "f1" in mappings
        assert len(mappings["f1"]) > 0
        # Check at least one framework mapped
        frameworks = {fw for fw, _ in mappings["f1"]}
        assert len(frameworks) >= 1

    def test_map_findings_no_cwe(self, engine):
        findings = [
            {
                "id": "f2",
                "severity": "low",
                "title": "Info disclosure",
            }
        ]
        mappings = engine.map_findings_to_controls(findings)
        assert isinstance(mappings, dict)
        assert "f2" in mappings
        assert mappings["f2"] == []  # No CWE → no mappings

    def test_map_findings_empty(self, engine):
        mappings = engine.map_findings_to_controls([])
        assert mappings == {}

    def test_map_findings_auto_collects_evidence(self, engine):
        findings = [
            {
                "id": "f3",
                "cwe": "CWE-287",
                "severity": "high",
                "title": "Auth Bypass",
                "scanner": "Burp",
            }
        ]
        engine.map_findings_to_controls(findings)
        # CWE-287 maps to SOC2 CC6.1 — evidence should be collected
        evidence = engine.db.get_evidence_for_control("CC6.1", "SOC2")
        assert len(evidence) >= 1
        assert evidence[0]["source"] == "Burp"

    def test_assess_framework(self, engine):
        findings = [
            {
                "id": "f4",
                "cwe": "CWE-89",
                "severity": "critical",
                "title": "SQLi in login",
            }
        ]
        posture = engine.assess_framework(Framework.PCI_DSS, findings=findings)
        assert isinstance(posture, CompliancePosture)
        assert posture.framework == Framework.PCI_DSS
        assert posture.total_controls == len(PCI_DSS_CONTROLS)
