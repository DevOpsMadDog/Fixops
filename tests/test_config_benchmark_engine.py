"""Tests for ConfigBenchmarkEngine — covering all methods and org isolation.

Integration note: run_assessment() now runs REAL checkov against the fixture
at tests/fixtures/checkov_target/.  The integration test is decorated with
@pytest.mark.skipif(shutil.which("checkov") is None, ...) so it is skipped
only when checkov is genuinely absent.

Read-path tests (get_assessment, list_assessments, get_failed_checks, stats)
seed rows directly via the engine's SQLite connection — no mocking, no faking
of run_assessment().

Error-path tests monkeypatch shutil.which to simulate missing checkov and
cover the ConfigBenchmarkError guard.
"""

from __future__ import annotations

import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

from core.config_benchmark_engine import ConfigBenchmarkEngine, ConfigBenchmarkError

import subprocess as _sp


def _checkov_functional() -> bool:
    """True only if the checkov binary is installed AND runnable.

    The real-scan tests need a working checkov; some environments have a
    checkov that crashes on import (dependency conflict), producing no output.
    Skip (not fail) those tests there — the engine itself correctly raises an
    honest error when checkov yields nothing."""
    exe = shutil.which("checkov")
    if not exe:
        return False
    try:
        r = _sp.run([exe, "--version"], capture_output=True, text=True, timeout=20)
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


_REQUIRES_CHECKOV = pytest.mark.skipif(
    not _checkov_functional(),
    reason="checkov binary non-functional (not installed or crashes on import)",
)


# ---------------------------------------------------------------------------
# Fixture path — a real IaC directory with both pass and fail checkov results
# ---------------------------------------------------------------------------

_FIXTURE_DIR = str(
    Path(__file__).resolve().parent / "fixtures" / "checkov_target"
)

# ---------------------------------------------------------------------------
# pytest fixtures
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

    Returns a dict that mirrors what run_assessment() returns.
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
# Assessments — run_assessment() real checkov integration
# ---------------------------------------------------------------------------


@_REQUIRES_CHECKOV
class TestRunAssessmentRealCheckov:
    """Integration tests that run actual checkov against the fixture directory.

    Skipped automatically when checkov is not on PATH.
    """

    @pytest.mark.skipif(
        shutil.which("checkov") is None,
        reason="checkov not installed — skipping real integration test",
    )
    def test_run_assessment_real_checkov_produces_results(self, engine):
        """run_assessment() must produce real check results persisted in SQLite."""
        profile = engine.create_profile(ORG_A, _profile(standard="CIS", target_type="aws"))
        result = engine.run_assessment(
            ORG_A,
            profile["profile_id"],
            "test-fixture-scan",
            target_path=_FIXTURE_DIR,
        )

        # Basic shape
        assert "result_id" in result
        assert result["org_id"] == ORG_A
        assert result["scanner"] == "checkov"
        assert result["total_checks"] > 0

        # Both pass AND fail must exist (fixture is intentionally mixed)
        assert result["passed"] > 0, f"Expected passed > 0, got {result}"
        assert result["failed"] > 0, f"Expected failed > 0, got {result}"

        # Score must be computed from real counts
        expected_score = round(result["passed"] / result["total_checks"] * 100, 2)
        assert abs(result["score"] - expected_score) < 0.1

        # Score must be in valid range
        assert 0.0 <= result["score"] <= 100.0

        # Status must be a valid value
        assert result["status"] in ("pass", "partial", "fail")

    @pytest.mark.skipif(
        shutil.which("checkov") is None,
        reason="checkov not installed — skipping real integration test",
    )
    def test_run_assessment_persists_check_results_to_db(self, engine):
        """All check_results must be readable back via get_assessment()."""
        profile = engine.create_profile(ORG_A, _profile(standard="CIS", target_type="aws"))
        result = engine.run_assessment(
            ORG_A,
            profile["profile_id"],
            "test-fixture-persist",
            target_path=_FIXTURE_DIR,
        )
        result_id = result["result_id"]

        # get_assessment() must return the persisted row with check_results
        detail = engine.get_assessment(ORG_A, result_id)
        assert detail, "get_assessment() returned empty — nothing persisted"
        assert "check_results" in detail
        assert len(detail["check_results"]) == result["total_checks"], (
            f"Expected {result['total_checks']} check_results, got {len(detail['check_results'])}"
        )

        # get_failed_checks() must return only fail rows
        failures = engine.get_failed_checks(ORG_A, result_id)
        assert len(failures) == result["failed"], (
            f"Expected {result['failed']} failures, got {len(failures)}"
        )
        assert all(f["status"] == "fail" for f in failures)
        # Each failure must have check metadata (from the joined benchmark_checks row)
        if failures:
            assert "check_ref" in failures[0]
            assert "severity" in failures[0]

    @pytest.mark.skipif(
        shutil.which("checkov") is None,
        reason="checkov not installed — skipping real integration test",
    )
    def test_run_assessment_shows_in_list_assessments(self, engine):
        """list_assessments() must return the assessment after run_assessment()."""
        profile = engine.create_profile(ORG_A, _profile())
        result = engine.run_assessment(
            ORG_A,
            profile["profile_id"],
            "test-fixture-list",
            target_path=_FIXTURE_DIR,
        )
        assessments = engine.list_assessments(ORG_A)
        ids = [a["result_id"] for a in assessments]
        assert result["result_id"] in ids

    @pytest.mark.skipif(
        shutil.which("checkov") is None,
        reason="checkov not installed — skipping real integration test",
    )
    def test_run_assessment_stats_updated(self, engine):
        """get_benchmark_stats() must reflect the real assessment."""
        profile = engine.create_profile(ORG_A, _profile(standard="CIS", target_type="aws"))
        engine.run_assessment(
            ORG_A,
            profile["profile_id"],
            "test-fixture-stats",
            target_path=_FIXTURE_DIR,
        )
        stats = engine.get_benchmark_stats(ORG_A)
        assert stats["total_assessments"] >= 1
        assert 0.0 <= stats["avg_score"] <= 100.0


# ---------------------------------------------------------------------------
# Assessments — error path (guard tests — do NOT require real checkov)
# ---------------------------------------------------------------------------


class TestRunAssessmentErrors:
    def test_checkov_absent_raises_config_benchmark_error(self, engine, monkeypatch):
        """When checkov is not on PATH, raise ConfigBenchmarkError (not NotImplementedError)."""
        monkeypatch.setattr("shutil.which", lambda _name: None)
        profile = engine.create_profile(ORG_A, _profile())
        with pytest.raises(ConfigBenchmarkError, match="checkov not installed"):
            engine.run_assessment(ORG_A, profile["profile_id"], "server-01", target_path="/tmp")

    def test_missing_target_path_raises_config_benchmark_error(self, engine):
        """No target_path → ConfigBenchmarkError."""
        profile = engine.create_profile(ORG_A, _profile())
        with pytest.raises(ConfigBenchmarkError):
            engine.run_assessment(ORG_A, profile["profile_id"], "server-01", target_path=None)

    def test_nonexistent_target_path_raises_config_benchmark_error(self, engine):
        """Non-existent path → ConfigBenchmarkError."""
        profile = engine.create_profile(ORG_A, _profile())
        with pytest.raises(ConfigBenchmarkError, match="target path not found"):
            engine.run_assessment(
                ORG_A, profile["profile_id"], "server-01",
                target_path="/tmp/fixops-nonexistent/12345",
            )

    def test_empty_directory_raises_config_benchmark_error(self, engine, tmp_path):
        """Empty target directory → ConfigBenchmarkError."""
        empty_dir = tmp_path / "empty_scan_target"
        empty_dir.mkdir()
        profile = engine.create_profile(ORG_A, _profile())
        with pytest.raises(ConfigBenchmarkError, match="no scannable files"):
            engine.run_assessment(
                ORG_A, profile["profile_id"], "empty-server",
                target_path=str(empty_dir),
            )

    def test_config_benchmark_error_is_value_error_subclass(self):
        """ConfigBenchmarkError is a ValueError subclass for consistent exception hierarchy."""
        exc = ConfigBenchmarkError("test message")
        assert isinstance(exc, ValueError)
        assert "test message" in str(exc)


# ---------------------------------------------------------------------------
# Assessments — downstream read paths exercised via direct seeding
# (no dependency on real checkov; these tests stay fast)
# ---------------------------------------------------------------------------


class TestAssessmentsSeeded:
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


# ---------------------------------------------------------------------------
# Router tests
# ---------------------------------------------------------------------------


class TestConfigBenchmarkRouter:
    """Tests for the FastAPI router layer — 422 on ConfigBenchmarkError,
    201 on real run (skipped if checkov absent)."""

    @pytest.fixture()
    def client(self, tmp_path):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api import config_benchmark_router as cbr

        # Inject a fresh engine backed by a tmp DB
        fresh_engine = ConfigBenchmarkEngine(db_path=str(tmp_path / "router_test.db"))
        cbr._engine = fresh_engine

        app = FastAPI()
        app.include_router(cbr.router)
        return TestClient(app, raise_server_exceptions=False)

    def test_router_422_when_checkov_absent(self, client, monkeypatch):
        """POST /assess must return 422 when checkov is not on PATH."""
        monkeypatch.setattr("shutil.which", lambda _: None)
        # Create a profile first
        r = client.post(
            "/api/v1/config-benchmark/profiles",
            json={"name": "Test Profile", "standard": "CIS", "target_type": "linux_server"},
            headers={"X-API-Key": "test"},
        )
        assert r.status_code == 200
        profile_id = r.json()["profile_id"]

        r2 = client.post(
            f"/api/v1/config-benchmark/profiles/{profile_id}/assess",
            json={"target_name": "server-01", "target_path": "/tmp"},
            headers={"X-API-Key": "test"},
        )
        assert r2.status_code == 422
        assert "checkov" in r2.json().get("detail", "").lower()

    def test_router_422_when_target_missing(self, client):
        """POST /assess must return 422 when target_path does not exist."""
        r = client.post(
            "/api/v1/config-benchmark/profiles",
            json={"name": "Test Profile", "standard": "CIS", "target_type": "linux_server"},
            headers={"X-API-Key": "test"},
        )
        profile_id = r.json()["profile_id"]

        r2 = client.post(
            f"/api/v1/config-benchmark/profiles/{profile_id}/assess",
            json={"target_name": "server-01", "target_path": "/tmp/fixops-nonexistent/xyz999"},
            headers={"X-API-Key": "test"},
        )
        assert r2.status_code == 422

    @pytest.mark.skipif(
        shutil.which("checkov") is None,
        reason="checkov not installed — skipping real router integration test",
    )
    @_REQUIRES_CHECKOV
    def test_router_201_on_real_run(self, client):
        """POST /assess returns 200 with real data when checkov is present."""
        r = client.post(
            "/api/v1/config-benchmark/profiles",
            json={"name": "Real Profile", "standard": "CIS", "target_type": "aws"},
            headers={"X-API-Key": "test"},
        )
        assert r.status_code == 200
        profile_id = r.json()["profile_id"]

        r2 = client.post(
            f"/api/v1/config-benchmark/profiles/{profile_id}/assess",
            json={"target_name": "fixture-scan", "target_path": _FIXTURE_DIR},
            headers={"X-API-Key": "test"},
        )
        assert r2.status_code == 200
        body = r2.json()
        assert "data" in body
        data = body["data"]
        assert data["passed"] > 0
        assert data["failed"] > 0
        assert "_data_source" in body
        assert body["_data_source"]["is_simulated"] is False
        assert body["_data_source"]["source"] == "checkov"
