"""Tests for ComplianceScannerEngine — ALDECI.

Covers: profile CRUD, scan execution, check filtering, remediation tasks,
org isolation, stats aggregation, and framework-level scoring.
"""

from __future__ import annotations

import pytest
import tempfile
import os

from core.compliance_scanner_engine import ComplianceScannerEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_compliance.db")
    return ComplianceScannerEngine(db_path=db)


@pytest.fixture
def org_a():
    return "org-alpha"


@pytest.fixture
def org_b():
    return "org-beta"


@pytest.fixture
def profile_soc2(engine, org_a):
    return engine.create_profile(org_a, {"name": "SOC2 Profile", "frameworks": ["SOC2"]})


@pytest.fixture
def profile_multi(engine, org_a):
    return engine.create_profile(org_a, {
        "name": "Multi-Framework",
        "frameworks": ["SOC2", "ISO27001", "NIST_CSF"],
        "scan_frequency_hours": 12,
    })


@pytest.fixture
def scan_result(engine, org_a, profile_soc2):
    return engine.start_scan(org_a, profile_soc2["profile_id"])


# ------------------------------------------------------------------
# Profile CRUD
# ------------------------------------------------------------------

class TestCreateProfile:
    def test_creates_profile_with_required_fields(self, engine, org_a):
        p = engine.create_profile(org_a, {"name": "Test", "frameworks": ["SOC2"]})
        assert p["profile_id"]
        assert p["org_id"] == org_a
        assert p["name"] == "Test"
        assert "SOC2" in p["frameworks"]

    def test_defaults_to_soc2_if_empty_frameworks(self, engine, org_a):
        p = engine.create_profile(org_a, {"name": "Empty Frameworks", "frameworks": []})
        assert "SOC2" in p["frameworks"]

    def test_filters_invalid_frameworks(self, engine, org_a):
        p = engine.create_profile(org_a, {"name": "Mixed", "frameworks": ["SOC2", "INVALID_FW"]})
        assert "SOC2" in p["frameworks"]
        assert "INVALID_FW" not in p["frameworks"]

    def test_sets_enabled_true(self, engine, org_a):
        p = engine.create_profile(org_a, {"name": "P", "frameworks": ["GDPR"]})
        assert p["enabled"] is True

    def test_sets_created_at(self, engine, org_a):
        p = engine.create_profile(org_a, {"name": "P", "frameworks": ["CIS"]})
        assert p["created_at"] is not None

    def test_next_scan_set_based_on_frequency(self, engine, org_a):
        p = engine.create_profile(org_a, {"name": "P", "frameworks": ["HIPAA"], "scan_frequency_hours": 48})
        assert p["next_scan"] is not None
        assert p["scan_frequency_hours"] == 48

    def test_all_frameworks_accepted(self, engine, org_a):
        frameworks = ["SOC2", "ISO27001", "NIST_CSF", "PCI_DSS", "HIPAA", "GDPR", "CIS"]
        p = engine.create_profile(org_a, {"name": "All FW", "frameworks": frameworks})
        assert set(p["frameworks"]) == set(frameworks)


class TestListProfiles:
    def test_lists_profiles_for_org(self, engine, org_a, profile_soc2, profile_multi):
        profiles = engine.list_profiles(org_a)
        assert len(profiles) >= 2

    def test_returns_most_recent_first(self, engine, org_a, profile_soc2, profile_multi):
        profiles = engine.list_profiles(org_a)
        assert profiles[0]["profile_id"] == profile_multi["profile_id"]

    def test_deserializes_frameworks_as_list(self, engine, org_a, profile_soc2):
        profiles = engine.list_profiles(org_a)
        for p in profiles:
            assert isinstance(p["frameworks"], list)

    def test_empty_for_unknown_org(self, engine):
        assert engine.list_profiles("unknown-org") == []


class TestGetProfile:
    def test_returns_profile_by_id(self, engine, org_a, profile_soc2):
        p = engine.get_profile(org_a, profile_soc2["profile_id"])
        assert p is not None
        assert p["profile_id"] == profile_soc2["profile_id"]

    def test_returns_none_for_wrong_org(self, engine, org_a, org_b, profile_soc2):
        p = engine.get_profile(org_b, profile_soc2["profile_id"])
        assert p is None

    def test_returns_none_for_nonexistent_id(self, engine, org_a):
        assert engine.get_profile(org_a, "nonexistent-id") is None


# ------------------------------------------------------------------
# Scan Execution
# ------------------------------------------------------------------

class TestStartScan:
    def test_returns_scan_result_dict(self, engine, org_a, profile_soc2):
        result = engine.start_scan(org_a, profile_soc2["profile_id"])
        assert result["result_id"]
        assert result["org_id"] == org_a
        assert result["profile_id"] == profile_soc2["profile_id"]

    def test_status_is_completed(self, engine, org_a, profile_soc2):
        result = engine.start_scan(org_a, profile_soc2["profile_id"])
        assert result["status"] == "completed"

    def test_generates_checks(self, engine, org_a, profile_soc2):
        result = engine.start_scan(org_a, profile_soc2["profile_id"])
        assert result["total_checks"] >= 5

    def test_score_in_valid_range(self, engine, org_a, profile_soc2):
        result = engine.start_scan(org_a, profile_soc2["profile_id"])
        assert 0.0 <= result["score"] <= 100.0

    def test_score_matches_pass_ratio(self, engine, org_a, profile_soc2):
        result = engine.start_scan(org_a, profile_soc2["profile_id"])
        if result["total_checks"] > 0:
            expected = round((result["passed"] / result["total_checks"]) * 100, 2)
            assert abs(result["score"] - expected) < 0.01

    def test_totals_add_up(self, engine, org_a, profile_soc2):
        result = engine.start_scan(org_a, profile_soc2["profile_id"])
        # passed + failed + warnings + skips = total_checks
        checks = engine.list_checks(org_a, result["result_id"])
        assert len(checks) == result["total_checks"]

    def test_multi_framework_generates_more_checks(self, engine, org_a, profile_multi):
        result = engine.start_scan(org_a, profile_multi["profile_id"])
        # 3 frameworks × 5-8 checks each = at least 15 checks
        assert result["total_checks"] >= 15

    def test_updates_profile_last_scan(self, engine, org_a, profile_soc2):
        engine.start_scan(org_a, profile_soc2["profile_id"])
        profile = engine.get_profile(org_a, profile_soc2["profile_id"])
        assert profile["last_scan"] is not None

    def test_updates_profile_next_scan(self, engine, org_a, profile_soc2):
        engine.start_scan(org_a, profile_soc2["profile_id"])
        profile = engine.get_profile(org_a, profile_soc2["profile_id"])
        assert profile["next_scan"] is not None

    def test_raises_for_unknown_profile(self, engine, org_a):
        with pytest.raises(ValueError):
            engine.start_scan(org_a, "bad-profile-id")

    def test_scan_completed_timestamps_set(self, engine, org_a, profile_soc2):
        result = engine.start_scan(org_a, profile_soc2["profile_id"])
        assert result["scan_started"] is not None
        assert result["scan_completed"] is not None


# ------------------------------------------------------------------
# Scan Results
# ------------------------------------------------------------------

class TestScanResults:
    def test_get_result_by_id(self, engine, org_a, scan_result):
        r = engine.get_scan_result(org_a, scan_result["result_id"])
        assert r is not None
        assert r["result_id"] == scan_result["result_id"]

    def test_get_result_wrong_org_returns_none(self, engine, org_b, scan_result):
        r = engine.get_scan_result(org_b, scan_result["result_id"])
        assert r is None

    def test_list_results_returns_most_recent_first(self, engine, org_a, profile_soc2):
        r1 = engine.start_scan(org_a, profile_soc2["profile_id"])
        r2 = engine.start_scan(org_a, profile_soc2["profile_id"])
        results = engine.list_scan_results(org_a)
        assert results[0]["result_id"] == r2["result_id"]

    def test_list_results_filter_by_profile(self, engine, org_a, profile_soc2, profile_multi):
        engine.start_scan(org_a, profile_soc2["profile_id"])
        engine.start_scan(org_a, profile_multi["profile_id"])
        results = engine.list_scan_results(org_a, profile_id=profile_soc2["profile_id"])
        for r in results:
            assert r["profile_id"] == profile_soc2["profile_id"]

    def test_list_results_respects_limit(self, engine, org_a, profile_soc2):
        for _ in range(5):
            engine.start_scan(org_a, profile_soc2["profile_id"])
        results = engine.list_scan_results(org_a, limit=3)
        assert len(results) <= 3


# ------------------------------------------------------------------
# Compliance Checks
# ------------------------------------------------------------------

class TestListChecks:
    def test_returns_checks_for_result(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        assert len(checks) > 0

    def test_checks_scoped_to_org(self, engine, org_b, scan_result):
        checks = engine.list_checks(org_b, scan_result["result_id"])
        assert checks == []

    def test_filter_by_status_pass(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"], status="pass")
        for c in checks:
            assert c["status"] == "pass"

    def test_filter_by_status_fail(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"], status="fail")
        for c in checks:
            assert c["status"] == "fail"

    def test_filter_by_framework(self, engine, org_a, profile_multi):
        result = engine.start_scan(org_a, profile_multi["profile_id"])
        checks = engine.list_checks(org_a, result["result_id"], framework="SOC2")
        for c in checks:
            assert c["framework"] == "SOC2"

    def test_checks_have_required_fields(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        for c in checks:
            assert "check_id" in c
            assert "framework" in c
            assert "control_id" in c
            assert "control_name" in c
            assert "status" in c
            assert "severity" in c


# ------------------------------------------------------------------
# Remediation Tasks
# ------------------------------------------------------------------

class TestRemediationTasks:
    def test_create_task(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        check_id = checks[0]["check_id"]
        task = engine.create_remediation_task(org_a, check_id, {
            "title": "Fix access controls",
            "description": "Review and tighten IAM policies",
            "priority": "high",
            "assigned_to": "security-team",
            "due_date": "2026-05-01",
        })
        assert task["task_id"]
        assert task["org_id"] == org_a
        assert task["check_id"] == check_id
        assert task["status"] == "open"
        assert task["priority"] == "high"

    def test_create_task_defaults_priority_medium(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        task = engine.create_remediation_task(org_a, checks[0]["check_id"], {
            "title": "Review config",
        })
        assert task["priority"] == "medium"

    def test_list_tasks_for_org(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        engine.create_remediation_task(org_a, checks[0]["check_id"], {"title": "Task 1"})
        engine.create_remediation_task(org_a, checks[0]["check_id"], {"title": "Task 2"})
        tasks = engine.list_remediation_tasks(org_a)
        assert len(tasks) >= 2

    def test_list_tasks_filter_by_status(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        engine.create_remediation_task(org_a, checks[0]["check_id"], {"title": "Open task"})
        tasks = engine.list_remediation_tasks(org_a, status="open")
        for t in tasks:
            assert t["status"] == "open"

    def test_list_tasks_filter_by_priority(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        engine.create_remediation_task(org_a, checks[0]["check_id"], {
            "title": "Critical task", "priority": "critical"
        })
        tasks = engine.list_remediation_tasks(org_a, priority="critical")
        for t in tasks:
            assert t["priority"] == "critical"

    def test_update_task_status_to_resolved(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        task = engine.create_remediation_task(org_a, checks[0]["check_id"], {"title": "T"})
        updated = engine.update_task_status(org_a, task["task_id"], "resolved", resolved_by="admin")
        assert updated is True

    def test_update_task_status_in_progress(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        task = engine.create_remediation_task(org_a, checks[0]["check_id"], {"title": "T"})
        updated = engine.update_task_status(org_a, task["task_id"], "in_progress")
        assert updated is True

    def test_update_task_invalid_status(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        task = engine.create_remediation_task(org_a, checks[0]["check_id"], {"title": "T"})
        updated = engine.update_task_status(org_a, task["task_id"], "INVALID")
        assert updated is False

    def test_update_task_wrong_org_returns_false(self, engine, org_a, org_b, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        task = engine.create_remediation_task(org_a, checks[0]["check_id"], {"title": "T"})
        updated = engine.update_task_status(org_b, task["task_id"], "resolved")
        assert updated is False

    def test_resolved_task_has_resolved_at(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        task = engine.create_remediation_task(org_a, checks[0]["check_id"], {"title": "T"})
        engine.update_task_status(org_a, task["task_id"], "resolved")
        tasks = engine.list_remediation_tasks(org_a)
        resolved = [t for t in tasks if t["task_id"] == task["task_id"]][0]
        assert resolved["resolved_at"] is not None


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------

class TestComplianceStats:
    def test_stats_zero_for_fresh_org(self, engine):
        stats = engine.get_compliance_stats("brand-new-org")
        assert stats["total_profiles"] == 0
        assert stats["total_scans"] == 0
        assert stats["avg_score"] == 0.0
        assert stats["open_tasks"] == 0

    def test_stats_count_profiles(self, engine, org_a, profile_soc2, profile_multi):
        stats = engine.get_compliance_stats(org_a)
        assert stats["total_profiles"] >= 2
        assert stats["active_profiles"] >= 2

    def test_stats_count_scans(self, engine, org_a, profile_soc2):
        engine.start_scan(org_a, profile_soc2["profile_id"])
        engine.start_scan(org_a, profile_soc2["profile_id"])
        stats = engine.get_compliance_stats(org_a)
        assert stats["total_scans"] >= 2

    def test_stats_avg_score_in_range(self, engine, org_a, profile_soc2):
        engine.start_scan(org_a, profile_soc2["profile_id"])
        stats = engine.get_compliance_stats(org_a)
        assert 0.0 <= stats["avg_score"] <= 100.0

    def test_stats_by_framework_populated(self, engine, org_a, profile_soc2):
        engine.start_scan(org_a, profile_soc2["profile_id"])
        stats = engine.get_compliance_stats(org_a)
        assert isinstance(stats["by_framework"], dict)
        assert "SOC2" in stats["by_framework"]

    def test_stats_by_framework_multi(self, engine, org_a, profile_multi):
        engine.start_scan(org_a, profile_multi["profile_id"])
        stats = engine.get_compliance_stats(org_a)
        fw = stats["by_framework"]
        assert "SOC2" in fw
        assert "ISO27001" in fw
        assert "NIST_CSF" in fw

    def test_stats_open_tasks_counted(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        engine.create_remediation_task(org_a, checks[0]["check_id"], {"title": "Open"})
        stats = engine.get_compliance_stats(org_a)
        assert stats["open_tasks"] >= 1

    def test_stats_critical_tasks_counted(self, engine, org_a, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        engine.create_remediation_task(org_a, checks[0]["check_id"], {
            "title": "Critical", "priority": "critical"
        })
        stats = engine.get_compliance_stats(org_a)
        assert stats["critical_tasks"] >= 1


# ------------------------------------------------------------------
# Org Isolation
# ------------------------------------------------------------------

class TestOrgIsolation:
    def test_profiles_isolated_by_org(self, engine, org_a, org_b, profile_soc2):
        profiles_b = engine.list_profiles(org_b)
        ids_b = [p["profile_id"] for p in profiles_b]
        assert profile_soc2["profile_id"] not in ids_b

    def test_results_isolated_by_org(self, engine, org_a, org_b, scan_result):
        results_b = engine.list_scan_results(org_b)
        ids_b = [r["result_id"] for r in results_b]
        assert scan_result["result_id"] not in ids_b

    def test_tasks_isolated_by_org(self, engine, org_a, org_b, scan_result):
        checks = engine.list_checks(org_a, scan_result["result_id"])
        task = engine.create_remediation_task(org_a, checks[0]["check_id"], {"title": "T"})
        tasks_b = engine.list_remediation_tasks(org_b)
        ids_b = [t["task_id"] for t in tasks_b]
        assert task["task_id"] not in ids_b

    def test_stats_isolated_by_org(self, engine, org_a, org_b, scan_result):
        stats_b = engine.get_compliance_stats(org_b)
        assert stats_b["total_scans"] == 0
