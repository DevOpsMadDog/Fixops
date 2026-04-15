"""
Tests for the Compliance Gap Analysis & Audit Readiness engine — ALDECI.

Covers:
- SOC2_CONTROLS constant (20 controls)
- run_gap_analysis across 6 frameworks
- get_audit_readiness_score
- update_control_status / control status persistence
- create_remediation_task / list_remediation_tasks
- generate_audit_report
- get_cross_framework_coverage
- Router endpoints via FastAPI TestClient

28+ tests.
"""
from __future__ import annotations

import sys
import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.compliance_automation import (
    ComplianceAutomation,
    SUPPORTED_FRAMEWORKS,
    SOC2_CONTROLS,
    _CROSS_FRAMEWORK_MAP,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine() -> ComplianceAutomation:
    """In-memory ComplianceAutomation engine."""
    return ComplianceAutomation(db_path=":memory:")


@pytest.fixture
def seeded_engine() -> ComplianceAutomation:
    """Engine with some controls marked passing for SOC2."""
    eng = ComplianceAutomation(db_path=":memory:")
    for ctrl in SOC2_CONTROLS[:10]:
        eng.update_control_status("test-org", "SOC2", ctrl["id"], "passing",
                                  evidence_url=f"https://evidence/{ctrl['id']}")
    return eng


# ---------------------------------------------------------------------------
# SOC2 Controls constant
# ---------------------------------------------------------------------------


class TestSOC2Controls:
    def test_exactly_20_controls(self) -> None:
        assert len(SOC2_CONTROLS) == 20

    def test_required_fields_present(self) -> None:
        for ctrl in SOC2_CONTROLS:
            for field in ("id", "name", "category", "description", "test_procedure"):
                assert field in ctrl, f"Control {ctrl.get('id')} missing field '{field}'"

    def test_includes_cc6_1(self) -> None:
        ids = [c["id"] for c in SOC2_CONTROLS]
        assert "CC6.1" in ids

    def test_includes_cc9_2(self) -> None:
        ids = [c["id"] for c in SOC2_CONTROLS]
        assert "CC9.2" in ids

    def test_includes_availability_control(self) -> None:
        categories = [c["category"] for c in SOC2_CONTROLS]
        assert "A" in categories

    def test_includes_pi_control(self) -> None:
        categories = [c["category"] for c in SOC2_CONTROLS]
        assert "PI" in categories

    def test_cross_framework_map_not_empty(self) -> None:
        assert len(_CROSS_FRAMEWORK_MAP) >= 6


# ---------------------------------------------------------------------------
# Gap analysis
# ---------------------------------------------------------------------------


class TestGapAnalysis:
    def test_gap_analysis_structure(self, engine: ComplianceAutomation) -> None:
        result = engine.run_gap_analysis("org1", "SOC2")
        for key in ("framework", "org_id", "score", "total_controls",
                    "passing", "failing", "not_applicable", "in_remediation", "gaps", "assessed_at"):
            assert key in result

    def test_gap_analysis_all_failing_by_default(self, engine: ComplianceAutomation) -> None:
        result = engine.run_gap_analysis("org1", "SOC2")
        assert result["failing"] == 20
        assert result["passing"] == 0
        assert result["score"] == 0.0

    def test_gap_analysis_score_increases_after_update(self, engine: ComplianceAutomation) -> None:
        engine.update_control_status("org1", "SOC2", "CC6.1", "passing")
        result = engine.run_gap_analysis("org1", "SOC2")
        assert result["passing"] == 1
        assert result["score"] > 0.0

    def test_gap_analysis_not_applicable_counts_as_passing_for_score(self, engine: ComplianceAutomation) -> None:
        engine.update_control_status("org1", "SOC2", "PI1.1", "not_applicable")
        result = engine.run_gap_analysis("org1", "SOC2")
        assert result["not_applicable"] == 1
        assert result["score"] > 0.0

    def test_gap_analysis_gaps_sorted_by_priority(self, engine: ComplianceAutomation) -> None:
        result = engine.run_gap_analysis("org1", "SOC2")
        prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        scores = [prio_order.get(g["priority"], 99) for g in result["gaps"]]
        assert scores == sorted(scores), "Gaps not sorted by priority"

    def test_gap_analysis_invalid_framework_raises(self, engine: ComplianceAutomation) -> None:
        with pytest.raises(ValueError, match="Unsupported framework"):
            engine.run_gap_analysis("org1", "BOGUS")

    def test_gap_analysis_all_six_frameworks(self, engine: ComplianceAutomation) -> None:
        for fw in SUPPORTED_FRAMEWORKS:
            result = engine.run_gap_analysis("org1", fw)
            assert result["framework"] == fw
            assert result["total_controls"] > 0

    def test_gap_item_has_required_fields(self, engine: ComplianceAutomation) -> None:
        result = engine.run_gap_analysis("org1", "ISO27001")
        for gap in result["gaps"]:
            for field in ("control_id", "control_name", "requirement", "current_state",
                          "gap_description", "priority"):
                assert field in gap, f"Gap missing field '{field}'"

    def test_gap_in_remediation_status(self, engine: ComplianceAutomation) -> None:
        engine.update_control_status("org1", "SOC2", "CC7.1", "in_remediation")
        result = engine.run_gap_analysis("org1", "SOC2")
        assert result["in_remediation"] == 1
        in_rem_gaps = [g for g in result["gaps"] if g["current_state"] == "in_remediation"]
        assert len(in_rem_gaps) == 1


# ---------------------------------------------------------------------------
# Audit readiness scoring
# ---------------------------------------------------------------------------


class TestAuditReadiness:
    def test_readiness_structure(self, engine: ComplianceAutomation) -> None:
        result = engine.get_audit_readiness_score("org1", "SOC2")
        for key in ("framework", "org_id", "score", "ready_for_audit",
                    "blockers", "estimated_remediation_days", "total_controls",
                    "passing", "failing", "assessed_at"):
            assert key in result

    def test_not_ready_when_all_failing(self, engine: ComplianceAutomation) -> None:
        result = engine.get_audit_readiness_score("org1", "SOC2")
        assert result["ready_for_audit"] is False
        assert result["score"] == 0.0

    def test_ready_when_all_passing(self, engine: ComplianceAutomation) -> None:
        for ctrl in SOC2_CONTROLS:
            engine.update_control_status("org1", "SOC2", ctrl["id"], "passing")
        result = engine.get_audit_readiness_score("org1", "SOC2")
        assert result["ready_for_audit"] is True
        assert result["score"] == 100.0

    def test_blockers_are_critical_or_high_failing(self, engine: ComplianceAutomation) -> None:
        # CC6.1 is a critical control
        result = engine.get_audit_readiness_score("org1", "SOC2")
        assert "CC6.1" in result["blockers"]

    def test_estimated_remediation_days_positive(self, engine: ComplianceAutomation) -> None:
        result = engine.get_audit_readiness_score("org1", "SOC2")
        assert result["estimated_remediation_days"] > 0

    def test_invalid_framework_raises(self, engine: ComplianceAutomation) -> None:
        with pytest.raises(ValueError):
            engine.get_audit_readiness_score("org1", "INVALID")


# ---------------------------------------------------------------------------
# Control status management
# ---------------------------------------------------------------------------


class TestControlStatus:
    def test_update_control_status_returns_true(self, engine: ComplianceAutomation) -> None:
        result = engine.update_control_status("org1", "SOC2", "CC6.1", "passing")
        assert result is True

    def test_update_control_status_persists(self, engine: ComplianceAutomation) -> None:
        engine.update_control_status("org1", "SOC2", "CC6.1", "passing", evidence_url="https://example.com/ev1")
        gap = engine.run_gap_analysis("org1", "SOC2")
        assert gap["passing"] == 1

    def test_update_control_status_upserts(self, engine: ComplianceAutomation) -> None:
        engine.update_control_status("org1", "SOC2", "CC6.1", "failing")
        engine.update_control_status("org1", "SOC2", "CC6.1", "passing")
        gap = engine.run_gap_analysis("org1", "SOC2")
        assert gap["passing"] == 1

    def test_invalid_status_raises(self, engine: ComplianceAutomation) -> None:
        with pytest.raises(ValueError, match="Invalid status"):
            engine.update_control_status("org1", "SOC2", "CC6.1", "unknown_status")

    def test_invalid_framework_raises(self, engine: ComplianceAutomation) -> None:
        with pytest.raises(ValueError):
            engine.update_control_status("org1", "BOGUS", "CC6.1", "passing")


# ---------------------------------------------------------------------------
# Remediation tasks
# ---------------------------------------------------------------------------


class TestRemediationTasks:
    def test_create_returns_task_id(self, engine: ComplianceAutomation) -> None:
        task_id = engine.create_remediation_task(
            "org1", "CC6.1", "SOC2",
            {"title": "Fix MFA", "description": "Enable MFA on all accounts", "priority": "critical"},
        )
        assert task_id is not None
        assert len(task_id) == 36  # UUID

    def test_list_returns_created_task(self, engine: ComplianceAutomation) -> None:
        engine.create_remediation_task("org1", "CC6.1", "SOC2", {"title": "Fix MFA"})
        tasks = engine.list_remediation_tasks("org1")
        assert len(tasks) == 1
        assert tasks[0]["title"] == "Fix MFA"

    def test_list_filters_by_framework(self, engine: ComplianceAutomation) -> None:
        engine.create_remediation_task("org1", "CC6.1", "SOC2", {"title": "SOC2 task"})
        engine.create_remediation_task("org1", "REQ-8", "PCI-DSS", {"title": "PCI task"})
        soc2_tasks = engine.list_remediation_tasks("org1", framework="SOC2")
        assert len(soc2_tasks) == 1
        assert soc2_tasks[0]["framework"] == "SOC2"

    def test_list_empty_for_unknown_org(self, engine: ComplianceAutomation) -> None:
        tasks = engine.list_remediation_tasks("unknown-org")
        assert tasks == []

    def test_invalid_framework_raises(self, engine: ComplianceAutomation) -> None:
        with pytest.raises(ValueError):
            engine.create_remediation_task("org1", "CC6.1", "BOGUS", {"title": "t"})

    def test_task_fields_stored(self, engine: ComplianceAutomation) -> None:
        engine.create_remediation_task(
            "org1", "CC7.1", "SOC2",
            {"title": "Patch vuln scanner", "assignee": "security-team",
             "priority": "high", "due_date": "2026-06-01"},
        )
        tasks = engine.list_remediation_tasks("org1", framework="SOC2")
        assert tasks[0]["assignee"] == "security-team"
        assert tasks[0]["priority"] == "high"
        assert tasks[0]["due_date"] == "2026-06-01"


# ---------------------------------------------------------------------------
# Audit report generation
# ---------------------------------------------------------------------------


class TestAuditReport:
    def test_report_structure(self, engine: ComplianceAutomation) -> None:
        report = engine.generate_audit_report("org1", "SOC2")
        for key in ("report_id", "framework", "full_name", "issuer", "org_id",
                    "generated_at", "executive_summary", "gap_analysis",
                    "control_details", "evidence_summary", "remediation_tasks"):
            assert key in report

    def test_report_executive_summary_fields(self, engine: ComplianceAutomation) -> None:
        report = engine.generate_audit_report("org1", "SOC2")
        es = report["executive_summary"]
        for key in ("score", "ready_for_audit", "total_controls", "passing",
                    "failing", "open_gaps", "blockers", "estimated_remediation_days"):
            assert key in es

    def test_report_includes_remediation_tasks(self, engine: ComplianceAutomation) -> None:
        engine.create_remediation_task("org1", "CC6.1", "SOC2", {"title": "Fix MFA"})
        report = engine.generate_audit_report("org1", "SOC2")
        assert len(report["remediation_tasks"]) == 1

    def test_report_includes_evidence_summary(self, seeded_engine: ComplianceAutomation) -> None:
        report = seeded_engine.generate_audit_report("test-org", "SOC2")
        assert len(report["evidence_summary"]) > 0

    def test_report_invalid_framework_raises(self, engine: ComplianceAutomation) -> None:
        with pytest.raises(ValueError):
            engine.generate_audit_report("org1", "UNKNOWN")

    def test_report_framework_metadata(self, engine: ComplianceAutomation) -> None:
        report = engine.generate_audit_report("org1", "SOC2")
        assert report["full_name"] == "System and Organisation Controls 2"
        assert report["issuer"] == "AICPA"


# ---------------------------------------------------------------------------
# Cross-framework coverage
# ---------------------------------------------------------------------------


class TestCrossFrameworkCoverage:
    def test_coverage_structure(self, engine: ComplianceAutomation) -> None:
        result = engine.get_cross_framework_coverage("org1")
        for key in ("org_id", "coverage_groups", "total_unique_implementations",
                    "total_framework_controls_covered", "frameworks", "assessed_at"):
            assert key in result

    def test_coverage_groups_not_empty(self, engine: ComplianceAutomation) -> None:
        result = engine.get_cross_framework_coverage("org1")
        assert len(result["coverage_groups"]) >= 6

    def test_coverage_group_fields(self, engine: ComplianceAutomation) -> None:
        result = engine.get_cross_framework_coverage("org1")
        for group in result["coverage_groups"]:
            for field in ("control_tag", "description", "frameworks_covered",
                          "total_frameworks", "satisfied_in", "partial_in", "not_started_in"):
                assert field in group

    def test_coverage_satisfied_after_controls_passing(self, engine: ComplianceAutomation) -> None:
        # Mark all MFA controls passing for SOC2
        engine.update_control_status("org1", "SOC2", "CC6.1", "passing")
        engine.update_control_status("org1", "SOC2", "CC6.2", "passing")
        result = engine.get_cross_framework_coverage("org1")
        mfa_group = next(g for g in result["coverage_groups"] if g["control_tag"] == "MFA / Access Control")
        assert "SOC2" in mfa_group["satisfied_in"]

    def test_all_frameworks_listed(self, engine: ComplianceAutomation) -> None:
        result = engine.get_cross_framework_coverage("org1")
        assert set(result["frameworks"]) == set(SUPPORTED_FRAMEWORKS)


# ---------------------------------------------------------------------------
# Router endpoints
# ---------------------------------------------------------------------------


class TestComplianceGapRouter:
    @pytest.fixture
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.compliance_gap_router import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_list_frameworks(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/frameworks")
        assert resp.status_code == 200
        data = resp.json()
        assert "frameworks" in data
        assert data["count"] == 7

    def test_gap_analysis_soc2(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/gap-analysis/SOC2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "SOC2"
        assert "score" in data
        assert "gaps" in data

    def test_gap_analysis_invalid_framework(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/gap-analysis/BOGUS")
        assert resp.status_code == 422

    def test_audit_readiness_soc2(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/audit-readiness/SOC2")
        assert resp.status_code == 200
        data = resp.json()
        assert "score" in data
        assert "ready_for_audit" in data
        assert "blockers" in data

    def test_audit_readiness_invalid_framework(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/audit-readiness/INVALID")
        assert resp.status_code == 422

    def test_create_remediation_task(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance-automation/remediation-tasks",
            json={
                "control_id": "CC6.1",
                "framework": "SOC2",
                "title": "Enable MFA",
                "description": "Enforce MFA on all admin accounts",
                "priority": "critical",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "task_id" in data
        assert data["control_id"] == "CC6.1"

    def test_create_remediation_task_invalid_framework(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance-automation/remediation-tasks",
            json={"control_id": "X1", "framework": "BOGUS", "title": "t"},
        )
        assert resp.status_code == 422

    def test_list_remediation_tasks_empty(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/remediation-tasks")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_update_control_status(self, client) -> None:
        resp = client.put(
            "/api/v1/compliance-automation/controls/SOC2/CC6.1",
            json={"status": "passing", "evidence_url": "https://evidence/cc6.1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["updated"] is True
        assert data["status"] == "passing"

    def test_update_control_status_invalid_framework(self, client) -> None:
        resp = client.put(
            "/api/v1/compliance-automation/controls/BOGUS/CC6.1",
            json={"status": "passing"},
        )
        assert resp.status_code == 422

    def test_update_control_status_invalid_status(self, client) -> None:
        resp = client.put(
            "/api/v1/compliance-automation/controls/SOC2/CC6.1",
            json={"status": "invalid_status"},
        )
        assert resp.status_code == 422

    def test_generate_report(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/report/SOC2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "SOC2"
        assert "executive_summary" in data
        assert "gap_analysis" in data

    def test_generate_report_invalid_framework(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/report/NOPE")
        assert resp.status_code == 422

    def test_cross_framework_coverage(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/cross-framework")
        assert resp.status_code == 200
        data = resp.json()
        assert "coverage_groups" in data
        assert len(data["coverage_groups"]) >= 6

    def test_gap_analysis_all_frameworks_via_router(self, client) -> None:
        for fw in SUPPORTED_FRAMEWORKS:
            resp = client.get(f"/api/v1/compliance-automation/gap-analysis/{fw}")
            assert resp.status_code == 200, f"Failed for {fw}: {resp.text}"
