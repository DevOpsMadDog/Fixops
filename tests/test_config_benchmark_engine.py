"""Tests for ConfigBenchmarkEngine — covering all methods and org isolation.

Migration note (honest-stub pass): run_assessment() now raises NotImplementedError.
TestAssessments tests that previously expected a result dict are rewritten to
assert pytest.raises(NotImplementedError).  Tests that exercise downstream read
paths (get_assessment, list_assessments, get_failed_checks, stats) seed rows
directly via the engine's SQLite connection — the same persistence layer used
by the engine — so every assertion exercises real production code without any
mocking or faking of run_assessment().
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List

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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_assessment_result(
    engine: ConfigBenchmarkEngine,
    org_id: str,
    profile_id: str,
    target_name: str,
    check_ids: List[str],
    *,
    pass_rate: float = 0.6,
) -> dict:
    """Insert a completed assessment_result + check_results directly into SQLite.

    Returns a dict that mirrors what run_assessment() used to return.
    No mocking — only real DB writes via engine._conn().

    pass_rate controls how many check_results get status='pass' vs 'fail'.
    At least one 'fail' result is always inserted when len(check_ids) >= 1 so
    that get_failed_checks() tests have data to work with.
    """
    result_id = str(uuid.uuid4())
    now = _now()
    total = len(check_ids)

    n_pass = max(0, int(total * pass_rate))
    n_fail = total - n_pass
    # Ensure at least 1 fail so downstream assertions about failures are not vacuous
    if n_fail == 0 and total > 0:
        n_pass -= 1
        n_fail = 1

    n_warn = 0
    n_na = 0
    score = round((n_pass / total) * 100, 2) if total > 0 else 0.0

    if score >= 80:
        status = "pass"
    elif score >= 50:
        status = "partial"
    else:
        status = "fail"

    with engine._lock:
        with engine._conn() as conn:
            conn.execute(
                """
                INSERT INTO assessment_results
                    (result_id, org_id, profile_id, target_name, assessed_at,
                     passed, failed, warnings, not_applicable, score, status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (result_id, org_id, profile_id, target_name, now,
                 n_pass, n_fail, n_warn, n_na, score, status),
            )

            for i, check_id in enumerate(check_ids):
                cr_status = "pass" if i < n_pass else "fail"
                conn.execute(
                    """
                    INSERT INTO check_results
                        (cr_id, org_id, result_id, check_id, actual_value, status, notes)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        str(uuid.uuid4()), org_id, result_id, check_id,
                        "enabled" if cr_status == "pass" else "disabled",
                        cr_status,
                        f"Auto-seeded check result {i+1}",
                    ),
                )

    return {
        "result_id": result_id,
        "org_id": org_id,
        "profile_id": profile_id,
        "target_name": target_name,
        "assessed_at": now,
        "passed": n_pass,
        "failed": n_fail,
        "warnings": n_warn,
        "not_applicable": n_na,
        "total_checks": total,
        "score": score,
        "status": status,
    }


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
# Assessments — run_assessment() raises NotImplementedError; downstream read
# paths are exercised via _seed_assessment_result().
# ---------------------------------------------------------------------------


class TestAssessments:
    # --- run_assessment() raise contract ---

    def test_run_assessment_raises_not_implemented(self, engine):
        """run_assessment() must raise NotImplementedError until CONFIG_BENCHMARK_CONNECTOR_URL is set."""
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=5)
        with pytest.raises(NotImplementedError):
            engine.run_assessment(ORG_A, profile["profile_id"], "server-01")

    def test_run_assessment_raises_even_with_no_checks(self, engine):
        """No-checks case still raises NotImplementedError (env-gate fires first)."""
        profile = engine.create_profile(ORG_A, _profile())
        with pytest.raises(NotImplementedError):
            engine.run_assessment(ORG_A, profile["profile_id"], "server-no-checks")

    def test_run_assessment_raises_not_implemented_message_mentions_connector(self, engine):
        """Error message should guide callers to configure a real connector."""
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=3)
        with pytest.raises(NotImplementedError, match="CONFIG_BENCHMARK_CONNECTOR_URL"):
            engine.run_assessment(ORG_A, profile["profile_id"], "server-msg")

    # --- downstream read paths exercised via direct seeding ---

    def test_get_assessment_with_check_results(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=5)
        check_ids = [c["check_id"] for c in engine.list_checks(ORG_A, profile["profile_id"])]
        run = _seed_assessment_result(engine, ORG_A, profile["profile_id"], "server-04", check_ids)
        detail = engine.get_assessment(ORG_A, run["result_id"])
        assert "check_results" in detail
        assert len(detail["check_results"]) == 5

    def test_get_assessment_not_found(self, engine):
        result = engine.get_assessment(ORG_A, "nonexistent-id")
        assert result == {}

    def test_list_assessments_all(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=5)
        check_ids = [c["check_id"] for c in engine.list_checks(ORG_A, profile["profile_id"])]
        _seed_assessment_result(engine, ORG_A, profile["profile_id"], "s1", check_ids)
        _seed_assessment_result(engine, ORG_A, profile["profile_id"], "s2", check_ids)
        results = engine.list_assessments(ORG_A)
        assert len(results) == 2

    def test_list_assessments_filtered_by_profile(self, engine):
        p1 = engine.create_profile(ORG_A, _profile(name="P1"))
        p2 = engine.create_profile(ORG_A, _profile(name="P2"))
        _add_checks(engine, ORG_A, p1["profile_id"], count=3)
        _add_checks(engine, ORG_A, p2["profile_id"], count=3)
        ids1 = [c["check_id"] for c in engine.list_checks(ORG_A, p1["profile_id"])]
        ids2 = [c["check_id"] for c in engine.list_checks(ORG_A, p2["profile_id"])]
        _seed_assessment_result(engine, ORG_A, p1["profile_id"], "s1", ids1)
        _seed_assessment_result(engine, ORG_A, p2["profile_id"], "s2", ids2)
        p1_results = engine.list_assessments(ORG_A, profile_id=p1["profile_id"])
        assert len(p1_results) == 1
        assert p1_results[0]["profile_id"] == p1["profile_id"]

    def test_get_failed_checks(self, engine):
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=20)
        check_ids = [c["check_id"] for c in engine.list_checks(ORG_A, profile["profile_id"])]
        run = _seed_assessment_result(
            engine, ORG_A, profile["profile_id"], "server-05", check_ids, pass_rate=0.5
        )
        failures = engine.get_failed_checks(ORG_A, run["result_id"])
        assert isinstance(failures, list)
        assert all(f["status"] == "fail" for f in failures)
        if failures:
            assert "check_ref" in failures[0]
            assert "severity" in failures[0]
            assert "remediation" in failures[0]

    def test_assessment_org_isolation(self, engine):
        p_a = engine.create_profile(ORG_A, _profile())
        p_b = engine.create_profile(ORG_B, _profile())
        _add_checks(engine, ORG_A, p_a["profile_id"], count=3)
        _add_checks(engine, ORG_B, p_b["profile_id"], count=3)
        ids_a = [c["check_id"] for c in engine.list_checks(ORG_A, p_a["profile_id"])]
        ids_b = [c["check_id"] for c in engine.list_checks(ORG_B, p_b["profile_id"])]
        run_a = _seed_assessment_result(engine, ORG_A, p_a["profile_id"], "s-a", ids_a)
        run_b = _seed_assessment_result(engine, ORG_B, p_b["profile_id"], "s-b", ids_b)
        # ORG_A cannot see ORG_B's assessment
        assert engine.get_assessment(ORG_A, run_b["result_id"]) == {}
        assert engine.get_assessment(ORG_B, run_a["result_id"]) == {}

    def test_seeded_result_score_in_valid_range(self, engine):
        """Seeded results have valid score values — sanity check for helper correctness."""
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=10)
        check_ids = [c["check_id"] for c in engine.list_checks(ORG_A, profile["profile_id"])]
        run = _seed_assessment_result(engine, ORG_A, profile["profile_id"], "s-score", check_ids)
        detail = engine.get_assessment(ORG_A, run["result_id"])
        assert 0.0 <= detail["score"] <= 100.0

    def test_seeded_result_status_values(self, engine):
        """Seeded result status is one of the valid engine statuses."""
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=20)
        check_ids = [c["check_id"] for c in engine.list_checks(ORG_A, profile["profile_id"])]
        run = _seed_assessment_result(engine, ORG_A, profile["profile_id"], "s-status", check_ids)
        assert run["status"] in ("pass", "fail", "partial")

    def test_seeded_result_counts_add_up(self, engine):
        """passed + failed + warnings + not_applicable == total checks inserted."""
        profile = engine.create_profile(ORG_A, _profile())
        _add_checks(engine, ORG_A, profile["profile_id"], count=15)
        check_ids = [c["check_id"] for c in engine.list_checks(ORG_A, profile["profile_id"])]
        run = _seed_assessment_result(engine, ORG_A, profile["profile_id"], "s-counts", check_ids)
        total = run["passed"] + run["failed"] + run["warnings"] + run["not_applicable"]
        assert total == 15


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
        check_ids = [c["check_id"] for c in engine.list_checks(ORG_A, p["profile_id"])]
        _seed_assessment_result(engine, ORG_A, p["profile_id"], "s1", check_ids)
        _seed_assessment_result(engine, ORG_A, p["profile_id"], "s2", check_ids)

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
        ids1 = [c["check_id"] for c in engine.list_checks(ORG_A, p1["profile_id"])]
        ids2 = [c["check_id"] for c in engine.list_checks(ORG_A, p2["profile_id"])]
        _seed_assessment_result(engine, ORG_A, p1["profile_id"], "s1", ids1)
        _seed_assessment_result(engine, ORG_A, p2["profile_id"], "s2", ids2)

        stats = engine.get_benchmark_stats(ORG_A)
        assert "CIS" in stats["by_standard"]
        assert "NIST_800_53" in stats["by_standard"]

    def test_stats_org_isolation(self, engine):
        p_a = engine.create_profile(ORG_A, _profile())
        p_b = engine.create_profile(ORG_B, _profile())
        _add_checks(engine, ORG_A, p_a["profile_id"], count=5)
        _add_checks(engine, ORG_B, p_b["profile_id"], count=5)
        ids_a = [c["check_id"] for c in engine.list_checks(ORG_A, p_a["profile_id"])]
        _seed_assessment_result(engine, ORG_A, p_a["profile_id"], "s-a", ids_a)

        stats_a = engine.get_benchmark_stats(ORG_A)
        stats_b = engine.get_benchmark_stats(ORG_B)
        assert stats_a["total_assessments"] == 1
        assert stats_b["total_assessments"] == 0
