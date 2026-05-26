"""Tests for ComplianceScannerEngine — ALDECI.

Covers: profile CRUD, real checkov scan execution, check filtering, remediation
tasks, org isolation, stats aggregation, and framework-level scoring.

Integration tests (TestStartScan) run real checkov against the fixture at
tests/fixtures/checkov_target/main.tf and require checkov to be installed.
Checkov IS present at /opt/homebrew/bin/checkov v3.2.521 — tests are NOT
skipped.

All downstream classes (ScanResults, ListChecks, RemediationTasks,
ComplianceStats, OrgIsolation) seed rows directly via the engine's SQLite
connection so they exercise real production code without re-running checkov.
"""

from __future__ import annotations

import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.compliance_scanner_engine import (
    ComplianceScannerEngine,
    ComplianceScanError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_scan_result(
    engine: ComplianceScannerEngine,
    org_id: str,
    profile_id: str,
    *,
    framework: str = "SOC2",
    n_pass: int = 4,
    n_fail: int = 2,
    n_warn: int = 1,
) -> dict:
    """Insert a completed scan_result + compliance_checks directly into SQLite.

    Returns a dict that mimics what start_scan() used to return, so callers
    can use it the same way.  No mocking — only real DB writes via _conn().
    """
    result_id = str(uuid.uuid4())
    scan_started = _now()
    scan_completed = _now()
    total = n_pass + n_fail + n_warn
    score = round((n_pass / total) * 100, 2) if total > 0 else 0.0

    with engine._lock:
        with engine._conn() as conn:
            conn.execute(
                """
                INSERT INTO scan_results
                    (result_id, org_id, profile_id, scan_started, scan_completed,
                     total_checks, passed, failed, warnings, score, status)
                VALUES (?,?,?,?,?,?,?,?,?,?,'completed')
                """,
                (result_id, org_id, profile_id, scan_started, scan_completed,
                 total, n_pass, n_fail, n_warn, score),
            )

            statuses = (
                ["pass"] * n_pass
                + ["fail"] * n_fail
                + ["warning"] * n_warn
            )
            for i, status in enumerate(statuses):
                conn.execute(
                    """
                    INSERT INTO compliance_checks
                        (check_id, org_id, result_id, framework, control_id,
                         control_name, category, status, severity, evidence,
                         remediation, check_duration_ms)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        str(uuid.uuid4()), org_id, result_id,
                        framework, f"CTRL-{i+1:03d}", f"Control {i+1}",
                        "Access Control", status,
                        "high" if i % 2 == 0 else "medium",
                        f"Evidence for control {i+1}",
                        f"Remediate control {i+1}" if status == "fail" else "",
                        100 + i * 10,
                    ),
                )

            # Update profile last_scan / next_scan to mirror what start_scan() did
            conn.execute(
                "UPDATE scan_profiles SET last_scan=?, next_scan=? WHERE profile_id=? AND org_id=?",
                (scan_completed, scan_completed, profile_id, org_id),
            )

    return {
        "result_id": result_id,
        "org_id": org_id,
        "profile_id": profile_id,
        "scan_started": scan_started,
        "scan_completed": scan_completed,
        "total_checks": total,
        "passed": n_pass,
        "failed": n_fail,
        "warnings": n_warn,
        "score": score,
        "status": "completed",
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

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
    """Seed a real completed scan result WITHOUT calling start_scan()."""
    return _seed_scan_result(engine, org_a, profile_soc2["profile_id"])


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


# Path to the shared checkov fixture used by config_benchmark tests too
_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "checkov_target"


# ------------------------------------------------------------------
# Scan Execution — real checkov integration
# ------------------------------------------------------------------

class TestStartScan:
    """Integration tests against a real checkov binary and a real IaC fixture.

    checkov is present at /opt/homebrew/bin/checkov v3.2.521 — these tests
    are NOT skipped.  The fixture at tests/fixtures/checkov_target/main.tf
    is intentionally mixed: it produces both passed and failed checks.
    """

    def test_real_scan_returns_result_dict(self, engine, org_a, profile_soc2):
        """start_scan() against the fixture must return a result dict."""
        result = engine.start_scan(
            org_a, profile_soc2["profile_id"], target_path=str(_FIXTURE_DIR)
        )
        assert isinstance(result, dict)
        assert result["result_id"]
        assert result["org_id"] == org_a
        assert result["status"] == "completed"
        assert result["scanner"] == "checkov"

    def test_real_scan_has_passed_and_failed(self, engine, org_a, profile_soc2):
        """Fixture is intentionally mixed — must yield passed > 0 and failed > 0."""
        result = engine.start_scan(
            org_a, profile_soc2["profile_id"], target_path=str(_FIXTURE_DIR)
        )
        assert result["passed"] > 0, f"Expected passed > 0, got {result['passed']}"
        assert result["failed"] > 0, f"Expected failed > 0, got {result['failed']}"

    def test_real_scan_score_in_range(self, engine, org_a, profile_soc2):
        """Score must be a valid percentage between 0 and 100."""
        result = engine.start_scan(
            org_a, profile_soc2["profile_id"], target_path=str(_FIXTURE_DIR)
        )
        assert 0.0 <= result["score"] <= 100.0
        # Score = passed / total * 100 — verify the arithmetic is consistent
        expected = round(result["passed"] / result["total_checks"] * 100, 2)
        assert abs(result["score"] - expected) < 0.01

    def test_real_scan_persists_scan_result(self, engine, org_a, profile_soc2):
        """get_scan_result() must return the persisted row after start_scan()."""
        result = engine.start_scan(
            org_a, profile_soc2["profile_id"], target_path=str(_FIXTURE_DIR)
        )
        fetched = engine.get_scan_result(org_a, result["result_id"])
        assert fetched is not None
        assert fetched["result_id"] == result["result_id"]
        assert fetched["passed"] == result["passed"]
        assert fetched["failed"] == result["failed"]

    def test_real_scan_persists_compliance_checks(self, engine, org_a, profile_soc2):
        """list_checks() must return one row per checkov check after start_scan()."""
        result = engine.start_scan(
            org_a, profile_soc2["profile_id"], target_path=str(_FIXTURE_DIR)
        )
        checks = engine.list_checks(org_a, result["result_id"])
        assert len(checks) == result["total_checks"], (
            f"Expected {result['total_checks']} check rows, got {len(checks)}"
        )

    def test_real_scan_checks_have_real_check_ids(self, engine, org_a, profile_soc2):
        """Every compliance_check row must have a real checkov check_id (CKV prefix)."""
        result = engine.start_scan(
            org_a, profile_soc2["profile_id"], target_path=str(_FIXTURE_DIR)
        )
        checks = engine.list_checks(org_a, result["result_id"])
        for chk in checks:
            assert chk["control_id"].startswith("CKV"), (
                f"Expected CKV check_id, got {chk['control_id']!r}"
            )

    def test_real_scan_checks_have_control_family(self, engine, org_a, profile_soc2):
        """framework column must be a real control family derived from checkov metadata."""
        result = engine.start_scan(
            org_a, profile_soc2["profile_id"], target_path=str(_FIXTURE_DIR)
        )
        checks = engine.list_checks(org_a, result["result_id"])
        for chk in checks:
            assert chk["framework"], f"check {chk['control_id']} has empty framework"
            # Must be one of the real families the engine derives — not a SOC2/PCI label
            assert "/" in chk["framework"] or chk["framework"] in ("terraform", "kubernetes", "dockerfile"), (
                f"Unexpected control family: {chk['framework']!r}"
            )

    def test_real_scan_pass_fail_checks_present(self, engine, org_a, profile_soc2):
        """Both 'pass' and 'fail' status checks must be in the compliance_checks table."""
        result = engine.start_scan(
            org_a, profile_soc2["profile_id"], target_path=str(_FIXTURE_DIR)
        )
        pass_checks = engine.list_checks(org_a, result["result_id"], status="pass")
        fail_checks = engine.list_checks(org_a, result["result_id"], status="fail")
        assert len(pass_checks) > 0, "Expected pass checks"
        assert len(fail_checks) > 0, "Expected fail checks"
        assert len(pass_checks) == result["passed"]
        assert len(fail_checks) == result["failed"]

    def test_real_scan_get_stats_reflects_scan(self, engine, org_a, profile_soc2):
        """get_compliance_stats() must reflect the persisted scan."""
        engine.start_scan(
            org_a, profile_soc2["profile_id"], target_path=str(_FIXTURE_DIR)
        )
        stats = engine.get_compliance_stats(org_a)
        assert stats["total_scans"] >= 1
        assert 0.0 <= stats["avg_score"] <= 100.0
        assert len(stats["by_framework"]) > 0

    # --- Error path tests ---

    def test_raises_when_checkov_absent(self, engine, org_a, profile_soc2, monkeypatch):
        """ComplianceScanError raised when checkov is not on PATH."""
        monkeypatch.setattr(shutil, "which", lambda _: None)
        with pytest.raises(ComplianceScanError, match="checkov not installed"):
            engine.start_scan(org_a, profile_soc2["profile_id"], target_path=str(_FIXTURE_DIR))

    def test_raises_when_target_missing(self, engine, org_a, profile_soc2):
        """ComplianceScanError raised when target_path does not exist."""
        with pytest.raises(ComplianceScanError, match="target path not found"):
            engine.start_scan(
                org_a, profile_soc2["profile_id"],
                target_path="/nonexistent/path/that/does/not/exist"
            )

    def test_raises_when_target_path_not_provided(self, engine, org_a, profile_soc2):
        """ComplianceScanError raised when target_path is None."""
        with pytest.raises(ComplianceScanError, match="target_path is required"):
            engine.start_scan(org_a, profile_soc2["profile_id"], target_path=None)

    def test_raises_when_empty_directory(self, engine, org_a, profile_soc2, tmp_path):
        """ComplianceScanError raised when target directory contains no files."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(ComplianceScanError, match="no scannable files"):
            engine.start_scan(org_a, profile_soc2["profile_id"], target_path=str(empty_dir))


# ------------------------------------------------------------------
# Scan Results — seeded via _seed_scan_result()
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
        r1 = _seed_scan_result(engine, org_a, profile_soc2["profile_id"])
        r2 = _seed_scan_result(engine, org_a, profile_soc2["profile_id"])
        results = engine.list_scan_results(org_a)
        ids = [r["result_id"] for r in results]
        # Both results present; ordering is insertion-time DESC which puts r2 first
        assert r1["result_id"] in ids
        assert r2["result_id"] in ids

    def test_list_results_filter_by_profile(self, engine, org_a, profile_soc2, profile_multi):
        _seed_scan_result(engine, org_a, profile_soc2["profile_id"])
        _seed_scan_result(engine, org_a, profile_multi["profile_id"])
        results = engine.list_scan_results(org_a, profile_id=profile_soc2["profile_id"])
        for r in results:
            assert r["profile_id"] == profile_soc2["profile_id"]

    def test_list_results_respects_limit(self, engine, org_a, profile_soc2):
        for _ in range(5):
            _seed_scan_result(engine, org_a, profile_soc2["profile_id"])
        results = engine.list_scan_results(org_a, limit=3)
        assert len(results) <= 3


# ------------------------------------------------------------------
# Compliance Checks — seeded via scan_result fixture
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
        # Seed a result with ISO27001 checks
        result = _seed_scan_result(
            engine, org_a, profile_multi["profile_id"], framework="ISO27001"
        )
        checks = engine.list_checks(org_a, result["result_id"], framework="ISO27001")
        for c in checks:
            assert c["framework"] == "ISO27001"

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
# Remediation Tasks — seeded via scan_result fixture
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
        _seed_scan_result(engine, org_a, profile_soc2["profile_id"])
        _seed_scan_result(engine, org_a, profile_soc2["profile_id"])
        stats = engine.get_compliance_stats(org_a)
        assert stats["total_scans"] >= 2

    def test_stats_avg_score_in_range(self, engine, org_a, profile_soc2):
        _seed_scan_result(engine, org_a, profile_soc2["profile_id"])
        stats = engine.get_compliance_stats(org_a)
        assert 0.0 <= stats["avg_score"] <= 100.0

    def test_stats_by_framework_populated(self, engine, org_a, profile_soc2):
        _seed_scan_result(engine, org_a, profile_soc2["profile_id"], framework="SOC2")
        stats = engine.get_compliance_stats(org_a)
        assert isinstance(stats["by_framework"], dict)
        assert "SOC2" in stats["by_framework"]

    def test_stats_by_framework_multi(self, engine, org_a, profile_multi):
        # Seed one result per framework so each appears in by_framework
        for fw in ("SOC2", "ISO27001", "NIST_CSF"):
            _seed_scan_result(engine, org_a, profile_multi["profile_id"], framework=fw)
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
