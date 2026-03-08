"""Tests for core.soc2_evidence_generator — SOC2 Type II evidence generation."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.soc2_evidence_generator import (
    ControlAssessment,
    ControlStatus,
    EvidencePack,
    SOC2_CONTROLS,
    TSC,
)


# ── ControlStatus Enum ──────────────────────────────────────────────

class TestControlStatus:
    def test_values(self):
        assert ControlStatus.EFFECTIVE.value == "effective"
        assert ControlStatus.NEEDS_IMPROVEMENT.value == "needs_improvement"
        assert ControlStatus.NOT_EFFECTIVE.value == "not_effective"
        assert ControlStatus.NOT_ASSESSED.value == "not_assessed"

    def test_count(self):
        assert len(ControlStatus) == 4


# ── TSC Enum ─────────────────────────────────────────────────────────

class TestTSC:
    def test_cc_criteria(self):
        assert TSC.CC1.value == "CC1"
        assert TSC.CC6.value == "CC6"
        assert TSC.CC9.value == "CC9"

    def test_other_criteria(self):
        assert TSC.A1.value == "A1"
        assert TSC.PI1.value == "PI1"
        assert TSC.C1.value == "C1"
        assert TSC.P1.value == "P1"

    def test_count(self):
        assert len(TSC) == 13


# ── SOC2_CONTROLS ────────────────────────────────────────────────────

class TestSOC2Controls:
    def test_has_controls(self):
        assert len(SOC2_CONTROLS) >= 10

    def test_control_structure(self):
        for ctrl_id, ctrl in SOC2_CONTROLS.items():
            assert "tsc" in ctrl, f"{ctrl_id} missing tsc"
            assert "title" in ctrl, f"{ctrl_id} missing title"
            assert "checks" in ctrl, f"{ctrl_id} missing checks"
            assert isinstance(ctrl["checks"], list)

    def test_cc6_controls_exist(self):
        cc6_controls = [k for k in SOC2_CONTROLS if k.startswith("CC6")]
        assert len(cc6_controls) >= 3

    def test_cc7_controls_exist(self):
        cc7_controls = [k for k in SOC2_CONTROLS if k.startswith("CC7")]
        assert len(cc7_controls) >= 3


# ── ControlAssessment ────────────────────────────────────────────────

class TestControlAssessment:
    def test_defaults(self):
        assessment = ControlAssessment(
            control_id="CC6.1",
            title="Logical Access Security",
            tsc="CC6",
        )
        assert assessment.status == ControlStatus.NOT_ASSESSED
        assert assessment.evidence_items == []
        assert assessment.checks_passed == 0
        assert assessment.checks_total == 0
        assert assessment.findings == []
        assert assessment.tested_at == ""

    def test_effective(self):
        assessment = ControlAssessment(
            control_id="CC6.1",
            title="Logical Access Security",
            tsc="CC6",
            status=ControlStatus.EFFECTIVE,
            checks_passed=3,
            checks_total=3,
            evidence_items=[{"type": "config", "data": "rbac enabled"}],
        )
        assert assessment.status == ControlStatus.EFFECTIVE
        assert assessment.checks_passed == 3
        assert len(assessment.evidence_items) == 1

    def test_needs_improvement(self):
        assessment = ControlAssessment(
            control_id="CC7.2",
            title="Monitor for Anomalies",
            tsc="CC7",
            status=ControlStatus.NEEDS_IMPROVEMENT,
            checks_passed=2,
            checks_total=3,
            findings=["siem_alerts not configured"],
        )
        assert assessment.status == ControlStatus.NEEDS_IMPROVEMENT
        assert len(assessment.findings) == 1


# ── EvidencePack ────────────────────────────────────────────────────

class TestEvidencePack:
    def test_defaults(self):
        pack = EvidencePack()
        assert pack.framework == "SOC2"
        assert pack.version == "Type II"
        assert pack.org_id == ""
        assert pack.timeframe_days == 90
        assert pack.controls_assessed == 0
        assert pack.overall_score == 0.0
        assert pack.overall_status == "not_assessed"
        assert pack.assessments == []
        assert pack.pack_id.startswith("EP-")

    def test_custom(self):
        pack = EvidencePack(
            org_id="org-123",
            timeframe_days=180,
            controls_assessed=20,
            controls_effective=15,
            controls_needing_improvement=3,
            controls_not_effective=2,
            overall_score=75.0,
            overall_status="needs_improvement",
        )
        assert pack.org_id == "org-123"
        assert pack.timeframe_days == 180
        assert pack.controls_assessed == 20
        assert pack.overall_score == 75.0

    def test_to_dict(self):
        assessment = ControlAssessment(
            control_id="CC6.1",
            title="Logical Access Security",
            tsc="CC6",
            status=ControlStatus.EFFECTIVE,
            checks_passed=3,
            checks_total=3,
        )
        pack = EvidencePack(
            org_id="org-456",
            controls_assessed=1,
            controls_effective=1,
            overall_score=100.0,
            overall_status="effective",
            assessments=[assessment],
        )
        d = pack.to_dict()
        assert d["framework"] == "SOC2"
        assert d["version"] == "Type II"
        assert d["org_id"] == "org-456"
        assert d["overall_score"] == 100.0
        assert d["controls_summary"]["assessed"] == 1
        assert d["controls_summary"]["effective"] == 1
        assert len(d["assessments"]) == 1
        assert d["assessments"][0]["control_id"] == "CC6.1"
        assert d["assessments"][0]["status"] == "effective"
        assert "timeframe" in d
        assert d["timeframe"]["days"] == 90

    def test_pack_id_unique(self):
        pack1 = EvidencePack()
        pack2 = EvidencePack()
        assert pack1.pack_id != pack2.pack_id

    def test_generated_at_populated(self):
        pack = EvidencePack()
        assert pack.generated_at != ""
        assert "T" in pack.generated_at  # ISO format
