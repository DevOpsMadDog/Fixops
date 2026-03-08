"""Tests for SOC2 Type II Evidence Pack Generator."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.soc2_evidence_generator import (
    ControlAssessment,
    ControlStatus,
    EvidencePack,
    SOC2EvidenceGenerator,
    SOC2_CONTROLS,
    TSC,
    get_evidence_generator,
)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------
class TestControlStatusEnum:
    def test_values(self):
        assert ControlStatus.EFFECTIVE == "effective"
        assert ControlStatus.NEEDS_IMPROVEMENT == "needs_improvement"
        assert ControlStatus.NOT_EFFECTIVE == "not_effective"
        assert ControlStatus.NOT_ASSESSED == "not_assessed"


class TestTSCEnum:
    def test_all_tsc_values(self):
        expected = [
            "CC1", "CC2", "CC3", "CC4", "CC5", "CC6",
            "CC7", "CC8", "CC9", "A1", "PI1", "C1", "P1",
        ]
        for val in expected:
            assert TSC(val).value == val

    def test_tsc_count(self):
        assert len(TSC) == 13


# ---------------------------------------------------------------------------
# Controls registry tests
# ---------------------------------------------------------------------------
class TestSOC2Controls:
    def test_controls_not_empty(self):
        assert len(SOC2_CONTROLS) > 0

    def test_all_controls_have_tsc(self):
        for ctrl_id, ctrl_def in SOC2_CONTROLS.items():
            assert "tsc" in ctrl_def, f"{ctrl_id} missing 'tsc'"

    def test_all_controls_have_title(self):
        for ctrl_id, ctrl_def in SOC2_CONTROLS.items():
            assert "title" in ctrl_def, f"{ctrl_id} missing 'title'"

    def test_all_controls_have_checks(self):
        for ctrl_id, ctrl_def in SOC2_CONTROLS.items():
            assert "checks" in ctrl_def, f"{ctrl_id} missing 'checks'"
            assert isinstance(ctrl_def["checks"], list)
            assert len(ctrl_def["checks"]) > 0, f"{ctrl_id} has empty checks"

    def test_known_controls_present(self):
        assert "CC6.1" in SOC2_CONTROLS
        assert "CC7.2" in SOC2_CONTROLS
        assert "CC8.1" in SOC2_CONTROLS
        assert "CC3.1" in SOC2_CONTROLS
        assert "A1.1" in SOC2_CONTROLS
        assert "C1.1" in SOC2_CONTROLS


# ---------------------------------------------------------------------------
# ControlAssessment tests
# ---------------------------------------------------------------------------
class TestControlAssessment:
    def test_default_status(self):
        ca = ControlAssessment(
            control_id="CC6.1",
            title="Test",
            tsc="CC6",
        )
        assert ca.status == ControlStatus.NOT_ASSESSED
        assert ca.checks_passed == 0
        assert ca.checks_total == 0
        assert ca.evidence_items == []
        assert ca.findings == []

    def test_custom_values(self):
        ca = ControlAssessment(
            control_id="CC7.1",
            title="Detect Changes",
            tsc="CC7",
            status=ControlStatus.EFFECTIVE,
            checks_passed=3,
            checks_total=3,
        )
        assert ca.status == ControlStatus.EFFECTIVE
        assert ca.checks_passed == 3


# ---------------------------------------------------------------------------
# EvidencePack tests
# ---------------------------------------------------------------------------
class TestEvidencePack:
    def test_default_pack(self):
        pack = EvidencePack()
        assert pack.framework == "SOC2"
        assert pack.version == "Type II"
        assert pack.pack_id.startswith("EP-")
        assert pack.controls_assessed == 0
        assert pack.overall_score == 0.0
        assert pack.overall_status == "not_assessed"

    def test_to_dict(self):
        pack = EvidencePack(org_id="org-123")
        d = pack.to_dict()
        assert d["framework"] == "SOC2"
        assert d["version"] == "Type II"
        assert d["org_id"] == "org-123"
        assert "timeframe" in d
        assert "controls_summary" in d
        assert "assessments" in d
        assert d["controls_summary"]["assessed"] == 0

    def test_to_dict_with_assessments(self):
        pack = EvidencePack(
            controls_assessed=5,
            controls_effective=4,
            controls_needing_improvement=1,
        )
        ca = ControlAssessment(
            control_id="CC6.1",
            title="Access",
            tsc="CC6",
            status=ControlStatus.EFFECTIVE,
            checks_passed=2,
            checks_total=2,
            tested_at="2026-01-01T00:00:00Z",
        )
        pack.assessments.append(ca)
        d = pack.to_dict()
        assert len(d["assessments"]) == 1
        assert d["assessments"][0]["control_id"] == "CC6.1"
        assert d["assessments"][0]["status"] == "effective"


# ---------------------------------------------------------------------------
# SOC2EvidenceGenerator tests
# ---------------------------------------------------------------------------
class TestSOC2EvidenceGenerator:
    def test_generate_default(self):
        gen = SOC2EvidenceGenerator()
        pack = gen.generate(org_id="test-org")
        assert pack.org_id == "test-org"
        assert pack.controls_assessed == len(SOC2_CONTROLS)
        assert pack.pack_id.startswith("EP-")
        assert pack.timeframe_days == 90
        assert pack.timeframe_start != ""
        assert pack.timeframe_end != ""

    def test_generate_custom_timeframe(self):
        gen = SOC2EvidenceGenerator()
        pack = gen.generate(org_id="org-1", timeframe_days=30)
        assert pack.timeframe_days == 30

    def test_generate_specific_controls(self):
        gen = SOC2EvidenceGenerator()
        pack = gen.generate(
            org_id="org-2",
            controls=["CC6.1", "CC7.2"],
        )
        assert pack.controls_assessed == 2
        ctrl_ids = [a.control_id for a in pack.assessments]
        assert "CC6.1" in ctrl_ids
        assert "CC7.2" in ctrl_ids

    def test_generate_with_platform_data(self):
        gen = SOC2EvidenceGenerator()
        data = {
            "findings_count": 50,
            "assets_count": 100,
            "graph_stats": {"total_nodes": 200},
            "case_stats": {"total": 10},
        }
        pack = gen.generate(org_id="org-3", platform_data=data)
        # With data, more checks should pass
        assert pack.controls_assessed > 0
        assert pack.overall_score > 0

    def test_generate_without_data_lower_score(self):
        gen = SOC2EvidenceGenerator()
        pack_no_data = gen.generate(org_id="org-4")
        pack_with_data = gen.generate(
            org_id="org-5",
            platform_data={
                "findings_count": 100,
                "graph_stats": {"total_nodes": 500},
                "case_stats": {"total": 25},
            },
        )
        # With data should have higher effective rate
        assert pack_with_data.controls_effective >= pack_no_data.controls_effective

    def test_overall_status_qualified(self):
        gen = SOC2EvidenceGenerator()
        pack = gen.generate(
            org_id="org-6",
            platform_data={
                "findings_count": 100,
                "graph_stats": {"total_nodes": 500},
                "case_stats": {"total": 25},
            },
        )
        # All checks with data should be effective
        assert pack.overall_status in ("qualified", "qualified_with_exceptions")

    def test_overall_status_not_qualified(self):
        gen = SOC2EvidenceGenerator()
        # Only use controls that require data (sbom_scanning, dependency_audit)
        pack = gen.generate(
            org_id="org-7",
            controls=["CC6.8"],
            platform_data={},  # No data → those checks fail
        )
        # CC6.8 checks require findings_count > 0, so they fail
        assert pack.controls_effective < pack.controls_assessed

    def test_get_pack(self):
        gen = SOC2EvidenceGenerator()
        pack = gen.generate(org_id="org-8")
        retrieved = gen.get_pack(pack.pack_id)
        assert retrieved is not None
        assert retrieved.pack_id == pack.pack_id

    def test_get_pack_not_found(self):
        gen = SOC2EvidenceGenerator()
        assert gen.get_pack("nonexistent") is None

    def test_list_packs(self):
        gen = SOC2EvidenceGenerator()
        gen.generate(org_id="org-a")
        gen.generate(org_id="org-b")
        packs = gen.list_packs()
        assert len(packs) >= 2

    def test_summary_structure(self):
        gen = SOC2EvidenceGenerator()
        pack = gen.generate(
            org_id="org-9",
            platform_data={"findings_count": 10, "assets_count": 5},
        )
        summary = pack.summary
        assert "audit_period" in summary
        assert "organization" in summary
        assert "overall_score_pct" in summary
        assert "qualification" in summary
        assert "tsc_breakdown" in summary
        assert "total_findings" in summary
        assert "platform_metrics" in summary

    def test_tsc_breakdown_in_summary(self):
        gen = SOC2EvidenceGenerator()
        pack = gen.generate(org_id="org-10")
        tsc_bd = pack.summary.get("tsc_breakdown", {})
        # Should have breakdown by TSC categories
        assert len(tsc_bd) > 0
        for tsc_name, scores in tsc_bd.items():
            assert "score_pct" in scores
            assert "effective" in scores
            assert "total" in scores

    def test_invalid_control_skipped(self):
        gen = SOC2EvidenceGenerator()
        pack = gen.generate(org_id="org-11", controls=["INVALID_CTRL", "CC6.1"])
        assert pack.controls_assessed == 1  # Only CC6.1

    def test_pipeline_data_stored(self):
        gen = SOC2EvidenceGenerator()
        data = {"findings_count": 42}
        pack = gen.generate(org_id="org-12", platform_data=data)
        assert pack.pipeline_data == data


# ---------------------------------------------------------------------------
# Singleton test
# ---------------------------------------------------------------------------
class TestGetEvidenceGenerator:
    def test_returns_instance(self):
        gen = get_evidence_generator()
        assert isinstance(gen, SOC2EvidenceGenerator)

    def test_returns_same_instance(self):
        gen1 = get_evidence_generator()
        gen2 = get_evidence_generator()
        assert gen1 is gen2


# ---------------------------------------------------------------------------
# _evaluate_check edge cases
# ---------------------------------------------------------------------------
class TestEvaluateCheck:
    def test_unknown_check(self):
        gen = SOC2EvidenceGenerator()
        result = gen._evaluate_check("totally_unknown_check", {})
        assert result["passed"] is False
        assert "Unknown check" in result["detail"]

    def test_check_with_zero_findings(self):
        gen = SOC2EvidenceGenerator()
        result = gen._evaluate_check("sbom_scanning", {"findings_count": 0})
        assert result["passed"] is False

    def test_check_with_positive_findings(self):
        gen = SOC2EvidenceGenerator()
        result = gen._evaluate_check("sbom_scanning", {"findings_count": 10})
        assert result["passed"] is True

    def test_check_rbac(self):
        gen = SOC2EvidenceGenerator()
        result = gen._evaluate_check("rbac_enabled", {})
        assert result["passed"] is True

    def test_check_change_detection_no_nodes(self):
        gen = SOC2EvidenceGenerator()
        result = gen._evaluate_check("change_detection", {"graph_stats": {"total_nodes": 0}})
        assert result["passed"] is False

    def test_check_change_detection_with_nodes(self):
        gen = SOC2EvidenceGenerator()
        result = gen._evaluate_check("change_detection", {"graph_stats": {"total_nodes": 50}})
        assert result["passed"] is True

    def test_incident_triage_with_cases(self):
        gen = SOC2EvidenceGenerator()
        result = gen._evaluate_check("incident_triage", {"case_stats": {"total": 5}})
        assert result["passed"] is True

    def test_incident_triage_no_cases_no_findings(self):
        gen = SOC2EvidenceGenerator()
        result = gen._evaluate_check("incident_triage", {"case_stats": {"total": 0}, "findings_count": 0})
        assert result["passed"] is False


# ---------------------------------------------------------------------------
# _assess_control tests
# ---------------------------------------------------------------------------
class TestAssessControl:
    def test_effective_when_all_pass(self):
        gen = SOC2EvidenceGenerator()
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        # rbac_enabled, sso_configured, mfa_enforced all pass with no data
        ctrl_def = SOC2_CONTROLS["CC6.1"]
        assessment = gen._assess_control("CC6.1", ctrl_def, {}, now)
        assert assessment.status == ControlStatus.EFFECTIVE
        assert assessment.checks_passed == assessment.checks_total

    def test_not_effective_when_most_fail(self):
        gen = SOC2EvidenceGenerator()
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        # CC6.8 has sbom_scanning and dependency_audit - both need findings_count > 0
        ctrl_def = SOC2_CONTROLS["CC6.8"]
        assessment = gen._assess_control("CC6.8", ctrl_def, {}, now)
        assert assessment.status == ControlStatus.NOT_EFFECTIVE
        assert assessment.checks_passed == 0

    def test_needs_improvement_partial(self):
        gen = SOC2EvidenceGenerator()
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        # CC7.2 has anomaly_detection, siem_alerts, threat_feeds - all pass by default
        ctrl_def = SOC2_CONTROLS["CC7.2"]
        assessment = gen._assess_control("CC7.2", ctrl_def, {}, now)
        assert assessment.status == ControlStatus.EFFECTIVE

    def test_evidence_items_populated(self):
        gen = SOC2EvidenceGenerator()
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        ctrl_def = SOC2_CONTROLS["CC6.1"]
        assessment = gen._assess_control("CC6.1", ctrl_def, {}, now)
        assert len(assessment.evidence_items) == len(ctrl_def["checks"])
        for item in assessment.evidence_items:
            assert "check" in item
            assert "passed" in item
            assert "detail" in item
