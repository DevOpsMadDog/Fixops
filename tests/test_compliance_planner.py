"""
Tests for CompliancePlanner — gap remediation planning module.

Covers plan generation, status transitions, assignment, effort summaries,
blocked/overdue detection, finding-to-control mapping, and stats.
"""
from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, "suite-core")

from core.compliance_planner import (
    CompliancePlanner,
    EffortLevel,
    GapRemediation,
    ImplementationStatus,
    RemediationPlan,
    RemediationPriority,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST-CSF", "CIS", "GDPR"]

SAMPLE_GAPS_BY_FRAMEWORK = {
    "SOC2": [
        {"control_id": "CC6.1", "control_name": "Access Controls", "gap_description": "No MFA enforced"},
        {"control_id": "CC6.2", "control_name": "User Authentication", "gap_description": "Weak passwords"},
        {"control_id": "CC7.1", "control_name": "System Monitoring", "gap_description": "No SIEM"},
    ],
    "PCI-DSS": [
        {"control_id": "1.1", "control_name": "Network Controls", "gap_description": "Firewall misconfigured"},
        {"control_id": "6.3", "control_name": "Vulnerability Management", "gap_description": "No scanning"},
        {"control_id": "10.2", "control_name": "Audit Logging", "gap_description": "Logs not centralised"},
    ],
    "HIPAA": [
        {"control_id": "164.308(a)(1)", "control_name": "Risk Analysis", "gap_description": "No risk analysis done"},
        {"control_id": "164.312(a)(1)", "control_name": "Access Control", "gap_description": "Shared accounts used"},
    ],
    "ISO27001": [
        {"control_id": "A.5.1", "control_name": "Security Policies", "gap_description": "No IS policy"},
        {"control_id": "A.8.1", "control_name": "Asset Management", "gap_description": "No asset inventory"},
    ],
    "NIST-CSF": [
        {"control_id": "ID.AM-1", "control_name": "Asset Inventory", "gap_description": "No discovery tool"},
        {"control_id": "PR.DS-1", "control_name": "Data at Rest", "gap_description": "Unencrypted databases"},
    ],
    "CIS": [
        {"control_id": "CIS-1", "control_name": "Asset Inventory", "gap_description": "No asset tracking"},
        {"control_id": "CIS-7", "control_name": "Vulnerability Mgmt", "gap_description": "No vuln programme"},
    ],
    "GDPR": [
        {"control_id": "Art.5", "control_name": "Lawful Processing", "gap_description": "No RoPA"},
        {"control_id": "Art.32", "control_name": "Security of Processing", "gap_description": "No encryption"},
    ],
}


@pytest.fixture
def planner(tmp_path):
    db_file = tmp_path / "test_planner.db"
    return CompliancePlanner(db_path=str(db_file))


@pytest.fixture
def soc2_plan(planner):
    return planner.generate_plan(
        framework="SOC2",
        gaps=SAMPLE_GAPS_BY_FRAMEWORK["SOC2"],
        org_id="org-test",
    )


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------

class TestEnums:
    def test_effort_levels_defined(self):
        assert set(e.value for e in EffortLevel) == {
            "minimal", "low", "medium", "high", "major"
        }

    def test_priority_levels_defined(self):
        assert set(e.value for e in RemediationPriority) == {
            "critical", "high", "medium", "low"
        }

    def test_implementation_statuses_defined(self):
        assert set(e.value for e in ImplementationStatus) == {
            "not_started", "in_progress", "implemented", "verified", "blocked"
        }


# ---------------------------------------------------------------------------
# Plan generation — one test per framework
# ---------------------------------------------------------------------------

class TestPlanGeneration:
    @pytest.mark.parametrize("framework", FRAMEWORKS)
    def test_generate_plan_for_each_framework(self, planner, framework):
        gaps = SAMPLE_GAPS_BY_FRAMEWORK[framework]
        plan = planner.generate_plan(framework=framework, gaps=gaps, org_id="org-1")
        assert isinstance(plan, RemediationPlan)
        assert plan.framework == framework
        assert plan.org_id == "org-1"
        assert plan.total_gaps == len(gaps)

    def test_generate_plan_returns_remediations(self, soc2_plan):
        assert len(soc2_plan.remediations) == 3

    def test_remediation_steps_are_non_empty(self, soc2_plan):
        for rem in soc2_plan.remediations:
            assert len(rem.remediation_steps) > 0, f"Empty steps for {rem.control_id}"

    def test_remediation_has_effort_and_priority(self, soc2_plan):
        for rem in soc2_plan.remediations:
            assert isinstance(rem.effort, EffortLevel)
            assert isinstance(rem.priority, RemediationPriority)

    def test_new_remediations_default_status_not_started(self, soc2_plan):
        for rem in soc2_plan.remediations:
            assert rem.status == ImplementationStatus.NOT_STARTED

    def test_generate_uses_template_for_known_control(self, planner):
        gaps = [{"control_id": "CC6.1", "control_name": "Access Controls", "gap_description": "No MFA"}]
        plan = planner.generate_plan("SOC2", gaps, "org-tmpl")
        rem = plan.remediations[0]
        # Template for CC6.1 should be CRITICAL
        assert rem.priority == RemediationPriority.CRITICAL

    def test_generate_uses_default_template_for_unknown_control(self, planner):
        gaps = [{"control_id": "UNKNOWN-999", "control_name": "Unknown", "gap_description": "some gap"}]
        plan = planner.generate_plan("SOC2", gaps, "org-unknown")
        rem = plan.remediations[0]
        assert len(rem.remediation_steps) >= 4

    def test_regenerate_plan_replaces_previous(self, planner):
        gaps1 = [{"control_id": "CC6.1", "control_name": "A", "gap_description": "gap1"}]
        gaps2 = [
            {"control_id": "CC6.2", "control_name": "B", "gap_description": "gap2"},
            {"control_id": "CC7.1", "control_name": "C", "gap_description": "gap3"},
        ]
        planner.generate_plan("SOC2", gaps1, "org-regen")
        plan = planner.generate_plan("SOC2", gaps2, "org-regen")
        assert plan.total_gaps == 2

    def test_plan_completion_pct_starts_at_zero(self, soc2_plan):
        assert soc2_plan.completion_pct == 0.0

    def test_plan_estimated_effort_hours_positive(self, soc2_plan):
        assert soc2_plan.estimated_total_effort_hours > 0


# ---------------------------------------------------------------------------
# get_plan / list_plans
# ---------------------------------------------------------------------------

class TestPlanRetrieval:
    def test_get_plan_returns_existing(self, planner, soc2_plan):
        fetched = planner.get_plan("SOC2", "org-test")
        assert fetched is not None
        assert fetched.framework == "SOC2"

    def test_get_plan_returns_none_for_missing(self, planner):
        result = planner.get_plan("GDPR", "org-nonexistent")
        assert result is None

    def test_list_plans_returns_all_for_org(self, planner):
        planner.generate_plan("SOC2", SAMPLE_GAPS_BY_FRAMEWORK["SOC2"], "org-multi")
        planner.generate_plan("GDPR", SAMPLE_GAPS_BY_FRAMEWORK["GDPR"], "org-multi")
        plans = planner.list_plans("org-multi")
        assert len(plans) == 2
        frameworks = {p.framework for p in plans}
        assert "SOC2" in frameworks
        assert "GDPR" in frameworks

    def test_list_plans_isolated_by_org(self, planner):
        planner.generate_plan("SOC2", SAMPLE_GAPS_BY_FRAMEWORK["SOC2"], "org-a")
        planner.generate_plan("SOC2", SAMPLE_GAPS_BY_FRAMEWORK["SOC2"], "org-b")
        plans_a = planner.list_plans("org-a")
        assert len(plans_a) == 1
        assert all(p.org_id == "org-a" for p in plans_a)


# ---------------------------------------------------------------------------
# Status updates
# ---------------------------------------------------------------------------

class TestStatusUpdates:
    @pytest.mark.parametrize("new_status", list(ImplementationStatus))
    def test_update_status_all_transitions(self, planner, soc2_plan, new_status):
        rem_id = soc2_plan.remediations[0].id
        updated = planner.update_remediation_status(rem_id, new_status, notes="test note")
        assert updated is not None
        assert updated.status == new_status

    def test_update_status_persists_notes(self, planner, soc2_plan):
        rem_id = soc2_plan.remediations[0].id
        planner.update_remediation_status(rem_id, ImplementationStatus.IN_PROGRESS, notes="working on it")
        fetched = planner.get_remediation(rem_id)
        assert fetched.notes == "working on it"

    def test_update_status_returns_none_for_missing_id(self, planner):
        result = planner.update_remediation_status("nonexistent-id", ImplementationStatus.VERIFIED)
        assert result is None

    def test_plan_completion_pct_updates_after_status_change(self, planner, soc2_plan):
        rem_id = soc2_plan.remediations[0].id
        planner.update_remediation_status(rem_id, ImplementationStatus.IMPLEMENTED)
        plan = planner.get_plan("SOC2", "org-test")
        assert plan.completion_pct > 0.0
        assert plan.remediated == 1


# ---------------------------------------------------------------------------
# Assignment
# ---------------------------------------------------------------------------

class TestAssignment:
    def test_assign_sets_assigned_to(self, planner, soc2_plan):
        rem_id = soc2_plan.remediations[0].id
        updated = planner.assign_remediation(rem_id, assigned_to="alice@example.com")
        assert updated.assigned_to == "alice@example.com"

    def test_assign_with_target_date(self, planner, soc2_plan):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        rem_id = soc2_plan.remediations[0].id
        updated = planner.assign_remediation(rem_id, assigned_to="bob@example.com", target_date=future)
        assert updated.target_date is not None
        # Compare date portion only to avoid microsecond drift
        assert updated.target_date.date() == future.date()

    def test_assign_returns_none_for_missing(self, planner):
        result = planner.assign_remediation("bad-id", assigned_to="carol@example.com")
        assert result is None


# ---------------------------------------------------------------------------
# Effort summary
# ---------------------------------------------------------------------------

class TestEffortSummary:
    def test_effort_summary_returns_dict(self, planner, soc2_plan):
        summary = planner.get_effort_summary("org-test")
        assert "total_hours" in summary
        assert "by_framework" in summary
        assert "by_priority" in summary
        assert "total_remediations" in summary

    def test_effort_summary_total_hours_positive(self, planner, soc2_plan):
        summary = planner.get_effort_summary("org-test")
        assert summary["total_hours"] > 0

    def test_effort_summary_by_framework_includes_soc2(self, planner, soc2_plan):
        summary = planner.get_effort_summary("org-test")
        assert "SOC2" in summary["by_framework"]

    def test_effort_summary_empty_org(self, planner):
        summary = planner.get_effort_summary("org-empty")
        assert summary["total_hours"] == 0.0
        assert summary["total_remediations"] == 0


# ---------------------------------------------------------------------------
# Blocked / overdue
# ---------------------------------------------------------------------------

class TestBlockedAndOverdue:
    def test_blocked_items_empty_initially(self, planner, soc2_plan):
        blocked = planner.get_blocked_items("org-test")
        assert blocked == []

    def test_blocked_items_detected(self, planner, soc2_plan):
        rem_id = soc2_plan.remediations[0].id
        planner.update_remediation_status(rem_id, ImplementationStatus.BLOCKED, notes="waiting on vendor")
        blocked = planner.get_blocked_items("org-test")
        assert len(blocked) == 1
        assert blocked[0].status == ImplementationStatus.BLOCKED

    def test_overdue_items_empty_without_target_date(self, planner, soc2_plan):
        overdue = planner.get_overdue_items("org-test")
        assert overdue == []

    def test_overdue_items_detected_past_deadline(self, planner, soc2_plan):
        past = datetime.now(timezone.utc) - timedelta(days=5)
        rem_id = soc2_plan.remediations[0].id
        planner.assign_remediation(rem_id, assigned_to="alice@example.com", target_date=past)
        overdue = planner.get_overdue_items("org-test")
        assert len(overdue) >= 1

    def test_completed_items_not_overdue(self, planner, soc2_plan):
        past = datetime.now(timezone.utc) - timedelta(days=5)
        rem_id = soc2_plan.remediations[0].id
        planner.assign_remediation(rem_id, assigned_to="dave@example.com", target_date=past)
        planner.update_remediation_status(rem_id, ImplementationStatus.VERIFIED)
        overdue = planner.get_overdue_items("org-test")
        # Verified item should not appear in overdue
        overdue_ids = [r.id for r in overdue]
        assert rem_id not in overdue_ids


# ---------------------------------------------------------------------------
# Finding-to-control mapping
# ---------------------------------------------------------------------------

class TestFindingToControlMapping:
    def test_map_findings_returns_dict(self, planner):
        findings = ["CVE-2024-1234 - authentication bypass", "unencrypted storage detected"]
        result = planner.map_findings_to_controls(findings, "SOC2")
        assert isinstance(result, dict)

    def test_map_findings_auth_matches_cc62(self, planner):
        findings = ["authentication failure detected in production", "mfa bypass vulnerability"]
        result = planner.map_findings_to_controls(findings, "SOC2")
        assert "CC6.2" in result

    def test_map_findings_no_match_returns_empty(self, planner):
        findings = ["printer paper jam on floor 3"]
        result = planner.map_findings_to_controls(findings, "SOC2")
        assert len(result) == 0

    def test_map_findings_cross_framework_isolation(self, planner):
        findings = ["unencrypted ephi storage detected"]
        soc2_result = planner.map_findings_to_controls(findings, "SOC2")
        hipaa_result = planner.map_findings_to_controls(findings, "HIPAA")
        # HIPAA controls should appear in hipaa_result, SOC2 controls in soc2_result
        hipaa_keys = set(hipaa_result.keys())
        soc2_keys = set(soc2_result.keys())
        assert hipaa_keys != soc2_keys or len(hipaa_keys) == 0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestPlannerStats:
    def test_stats_returns_expected_keys(self, planner, soc2_plan):
        stats = planner.get_planner_stats("org-test")
        assert "total_remediations" in stats
        assert "by_framework" in stats
        assert "by_status" in stats
        assert "completion_rates" in stats
        assert "overall_completion_pct" in stats

    def test_stats_total_remediations_correct(self, planner, soc2_plan):
        stats = planner.get_planner_stats("org-test")
        assert stats["total_remediations"] == 3

    def test_stats_by_framework_includes_soc2(self, planner, soc2_plan):
        stats = planner.get_planner_stats("org-test")
        assert "SOC2" in stats["by_framework"]
        assert stats["by_framework"]["SOC2"]["total"] == 3

    def test_stats_completion_rate_increases(self, planner, soc2_plan):
        rem_id = soc2_plan.remediations[0].id
        planner.update_remediation_status(rem_id, ImplementationStatus.VERIFIED)
        stats = planner.get_planner_stats("org-test")
        assert stats["completion_rates"]["SOC2"] > 0.0

    def test_stats_empty_org(self, planner):
        stats = planner.get_planner_stats("org-nobody")
        assert stats["total_remediations"] == 0
        assert stats["overall_completion_pct"] == 0.0

    def test_list_remediations_filter_by_status(self, planner, soc2_plan):
        rem_id = soc2_plan.remediations[0].id
        planner.update_remediation_status(rem_id, ImplementationStatus.IN_PROGRESS)
        results = planner.list_remediations("org-test", status_filter=ImplementationStatus.IN_PROGRESS)
        assert len(results) == 1
        assert results[0].status == ImplementationStatus.IN_PROGRESS

    def test_list_remediations_filter_by_priority(self, planner, soc2_plan):
        results = planner.list_remediations("org-test", priority_filter=RemediationPriority.CRITICAL)
        # CC6.1 is CRITICAL priority
        assert any(r.priority == RemediationPriority.CRITICAL for r in results)
