"""Tests for ConfigBenchmarkEngine — 27 tests covering all methods and org isolation."""

from __future__ import annotations

import pytest

from core.config_benchmark_engine import ConfigBenchmarkEngine

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "test_config_benchmark.db")
    return ConfigBenchmarkEngine(db_path=db)


ORG_A = "org-bench-aaa"
ORG_B = "org-bench-bbb"


def _profile(name="Test Profile", standard="CIS", target_type="linux_server", version="1.0"):
    return dict(name=name, standard=standard, target_type=target_type, version=version)


def _check(ref="CIS-1.1.1", title="Ensure test", severity="medium", category="Access Control"):
    return dict(
        check_ref=ref,
        title=title,
        description="Ensure the setting is correctly configured",
        category=category,
        severity=severity,
        expected_value="enabled",
        remediation="Enable the setting in configuration file",
    )


def _add_checks(engine, org_id, profile_id, count=5):
    """Helper: add N checks to a profile."""
    for i in range(count):
        engine.add_check(org_id, profile_id, _check(
            ref=f"CIS-1.1.{i+1}",
            title=f"Check {i+1}",
            severity=["critical", "high", "medium", "low", "info"][i % 5],
        ))


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------


class TestProfiles:
    def test_create_profile_returns_id(self, engine):
        result = engine.create_profile(ORG_A, _profile())
        assert "profile_id" in result
        assert result["org_id"] == ORG_A
        assert result["standard"] == "CIS"

    def test_create_profile_all_standards(self, engine):
        standards = ["CIS", "DISA_STIG", "NIST_800_53", "PCI_DSS_HW", "custom"]
        for std in standards:
            result = engine.create_profile(ORG_A, _profile(name=f"Profile {std}", standard=std))
            assert result["standard"] == std

    def test_create_profile_invalid_standard_defaults_custom(self, engine):
        result = engine.create_profile(ORG_A, _profile(standard="INVALID"))
        assert result["standard"] == "custom"

    def test_create_profile_all_target_types(self, engine):
        target_types = ["linux_server", "windows_server", "network_device",
                        "kubernetes", "docker", "aws", "azure"]
        for tt in target_types:
            result = engine.create_profile(ORG_A, _profile(name=f"Profile {tt}", target_type=tt))
            assert result["target_type"] == tt

    def test_list_profiles_empty(self, engine):
        result = engine.list_profiles(ORG_A)
        assert result == []

    def test_list_profiles_returns_all(self, engine):
        engine.create_profile(ORG_A, _profile(name="P1"))
        engine.create_profile(ORG_A, _profile(name="P2"))
        result = engine.list_profiles(ORG_A)
        assert len(result) == 2

    def test_list_profiles_filtered_by_standard(self, engine):
        engine.create_profile(ORG_A, _profile(name="CIS Profile", standard="CIS"))
        engine.create_profile(ORG_A, _profile(name="NIST Profile", standard="NIST_800_53"))
        cis = engine.list_profiles(ORG_A, standard="CIS")
        nist = engine.list_profiles(ORG_A, standard="NIST_800_53")
        assert len(cis) == 1
        assert len(nist) == 1
        assert cis[0]["name"] == "CIS Profile"

    def test_profile_org_isolation(self, engine):
        engine.create_profile(ORG_A, _profile(name="A Profile"))
        engine.create_profile(ORG_B, _profile(name="B Profile"))
        profiles_a = engine.list_profiles(ORG_A)
        profiles_b = engine.list_profiles(ORG_B)
        assert all(p["org_id"] == ORG_A for p in profiles_a)
        assert all(p["org_id"] == ORG_B for p in profiles_b)
        assert len(profiles_a) == 1
        assert len(profiles_b) == 1


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


class TestChecks:
    def test_add_check_returns_id(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        result = engine.add_check(ORG_A, profile["profile_id"], _check())
        assert "check_id" in result
        assert result["org_id"] == ORG_A
        assert result["profile_id"] == profile["profile_id"]

    def test_add_check_stores_fields(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        engine.add_check(ORG_A, profile["profile_id"], _check(
            ref="CIS-2.1.1", title="Ensure SSH", severity="high",
        ))
        checks = engine.list_checks(ORG_A, profile["profile_id"])
        assert len(checks) == 1
        assert checks[0]["check_ref"] == "CIS-2.1.1"
        assert checks[0]["severity"] == "high"

    def test_list_checks_filtered_by_severity(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=5)
        critical_checks = engine.list_checks(ORG_A, profile["profile_id"], severity="critical")
        assert all(c["severity"] == "critical" for c in critical_checks)

    def test_list_checks_org_isolation(self, engine):
        p_a = engine.create_profile(ORG_A, _profile())
        p_b = engine.create_profile(ORG_B, _profile())
        engine.add_check(ORG_A, p_a["profile_id"], _check(ref="CIS-A"))
        engine.add_check(ORG_B, p_b["profile_id"], _check(ref="CIS-B"))
        checks_a = engine.list_checks(ORG_A, p_a["profile_id"])
        checks_b = engine.list_checks(ORG_B, p_b["profile_id"])
        assert all(c["org_id"] == ORG_A for c in checks_a)
        assert all(c["org_id"] == ORG_B for c in checks_b)


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------


class TestAssessments:
    def test_run_assessment_no_checks_returns_error(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        result = engine.run_assessment(ORG_A, profile["profile_id"], "server-01")
        assert "error" in result

    def test_run_assessment_returns_result(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=10)
        result = engine.run_assessment(ORG_A, profile["profile_id"], "server-01")
        assert "result_id" in result
        assert result["total_checks"] == 10
        assert result["score"] >= 0.0
        assert result["score"] <= 100.0

    def test_run_assessment_status_values(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=20)
        result = engine.run_assessment(ORG_A, profile["profile_id"], "server-02")
        assert result["status"] in ("pass", "fail", "partial")

    def test_run_assessment_counts_add_up(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=15)
        result = engine.run_assessment(ORG_A, profile["profile_id"], "server-03")
        total = result["passed"] + result["failed"] + result["warnings"] + result["not_applicable"]
        assert total == 15

    def test_get_assessment_with_check_results(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=5)
        run = engine.run_assessment(ORG_A, profile["profile_id"], "server-04")
        detail = engine.get_assessment(ORG_A, run["result_id"])
        assert "check_results" in detail
        assert len(detail["check_results"]) == 5

    def test_get_assessment_not_found(self, engine):
        result = engine.get_assessment(ORG_A, "nonexistent-id")
        assert result == {}

    def test_list_assessments_all(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=5)
        engine.run_assessment(ORG_A, profile["profile_id"], "s1")
        engine.run_assessment(ORG_A, profile["profile_id"], "s2")
        results = engine.list_assessments(ORG_A)
        assert len(results) == 2

    def test_list_assessments_filtered_by_profile(self, engine):
        p1 = engine.create_profile(ORG_A, _profile(name="P1"))
        p2 = engine.create_profile(ORG_A, _profile(name="P2"))
        _add_checks(engine, ORG_A, p1["profile_id"], count=3)
        _add_checks(engine, ORG_A, p2["profile_id"], count=3)
        engine.run_assessment(ORG_A, p1["profile_id"], "s1")
        engine.run_assessment(ORG_A, p2["profile_id"], "s2")
        p1_results = engine.list_assessments(ORG_A, profile_id=p1["profile_id"])
        assert len(p1_results) == 1
        assert p1_results[0]["profile_id"] == p1["profile_id"]

    def test_get_failed_checks(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=20)
        run = engine.run_assessment(ORG_A, profile["profile_id"], "server-05")
        failures = engine.get_failed_checks(ORG_A, run["result_id"])
        assert isinstance(failures, list)
        assert all(f["status"] == "fail" for f in failures)
        # Every failure row should have check details joined
        if failures:
            assert "check_ref" in failures[0]
            assert "severity" in failures[0]
            assert "remediation" in failures[0]

    def test_assessment_org_isolation(self, engine):
        p_a = engine.create_profile(ORG_A, _profile())
        p_b = engine.create_profile(ORG_B, _profile())
        _add_checks(engine, ORG_A, p_a["profile_id"], count=3)
        _add_checks(engine, ORG_B, p_b["profile_id"], count=3)
        run_a = engine.run_assessment(ORG_A, p_a["profile_id"], "s-a")
        run_b = engine.run_assessment(ORG_B, p_b["profile_id"], "s-b")
        # ORG_A cannot see ORG_B's assessment
        assert engine.get_assessment(ORG_A, run_b["result_id"]) == {}
        assert engine.get_assessment(ORG_B, run_a["result_id"]) == {}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestBenchmarkStats:
    def test_stats_empty_org(self, engine):
        stats = engine.get_benchmark_stats("org-empty-bench")
        assert stats["total_profiles"] == 0
        assert stats["total_assessments"] == 0
        assert stats["avg_score"] == 0.0
        assert stats["critical_failures_total"] == 0

    def test_stats_reflects_data(self, engine):
        p = engine.create_profile(ORG_A, _profile(standard="CIS", target_type="linux_server"))
        _add_checks(engine, ORG_A, p["profile_id"], count=20)
        engine.run_assessment(ORG_A, p["profile_id"], "s1")
        engine.run_assessment(ORG_A, p["profile_id"], "s2")

        stats = engine.get_benchmark_stats(ORG_A)
        assert stats["total_profiles"] == 1
        assert stats["total_assessments"] == 2
        assert 0.0 <= stats["avg_score"] <= 100.0
        assert "CIS" in stats["by_standard"]
        assert "linux_server" in stats["by_target_type"]

    def test_stats_by_standard_multi(self, engine):
        p1 = engine.create_profile(ORG_A, _profile(name="CIS", standard="CIS"))
        p2 = engine.create_profile(ORG_A, _profile(name="NIST", standard="NIST_800_53"))
        _add_checks(engine, ORG_A, p1["profile_id"], count=5)
        _add_checks(engine, ORG_A, p2["profile_id"], count=5)
        engine.run_assessment(ORG_A, p1["profile_id"], "s1")
        engine.run_assessment(ORG_A, p2["profile_id"], "s2")

        stats = engine.get_benchmark_stats(ORG_A)
        assert "CIS" in stats["by_standard"]
        assert "NIST_800_53" in stats["by_standard"]

    def test_stats_org_isolation(self, engine):
        p_a = engine.create_profile(ORG_A, _profile())
        p_b = engine.create_profile(ORG_B, _profile())
        _add_checks(engine, ORG_A, p_a["profile_id"], count=5)
        _add_checks(engine, ORG_B, p_b["profile_id"], count=5)
        engine.run_assessment(ORG_A, p_a["profile_id"], "s-a")

        stats_a = engine.get_benchmark_stats(ORG_A)
        stats_b = engine.get_benchmark_stats(ORG_B)
        assert stats_a["total_assessments"] == 1
        assert stats_b["total_assessments"] == 0
