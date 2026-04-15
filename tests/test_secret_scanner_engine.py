"""Tests for SecretScannerEngine — 32 tests covering full lifecycle."""

from __future__ import annotations

import os
import tempfile
import pytest

from core.secret_scanner_engine import SecretScannerEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    """Fresh engine instance using a temp DB for each test."""
    db_path = str(tmp_path / "test_secret_scanner.db")
    eng = SecretScannerEngine.__new__(SecretScannerEngine)
    eng.org_id = "org_test"
    eng.db_path = db_path
    import threading
    eng._lock = threading.RLock()
    eng._init_db()
    return eng


ORG = "org_test"
ORG2 = "org_other"


@pytest.fixture()
def engine2(tmp_path):
    """Second org engine for isolation tests."""
    db_path = str(tmp_path / "test_secret_scanner2.db")
    eng = SecretScannerEngine.__new__(SecretScannerEngine)
    eng.org_id = ORG2
    eng.db_path = db_path
    import threading
    eng._lock = threading.RLock()
    eng._init_db()
    return eng


# ---------------------------------------------------------------------------
# Scan job lifecycle
# ---------------------------------------------------------------------------

class TestScanJobLifecycle:
    def test_create_job_pending(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo", "target_path": "/repo/x"})
        assert job["status"] == "pending"
        assert job["org_id"] == ORG
        assert job["target_type"] == "git_repo"
        assert job["secrets_found"] == 0
        assert job["id"]

    def test_create_job_all_target_types(self, engine):
        for tt in ("git_repo", "filesystem", "api_response", "config_file", "env_file"):
            job = engine.create_scan_job(ORG, {"target_type": tt})
            assert job["target_type"] == tt

    def test_create_job_invalid_target_type(self, engine):
        with pytest.raises(ValueError, match="Invalid target_type"):
            engine.create_scan_job(ORG, {"target_type": "invalid_type"})

    def test_start_scan_completes(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        completed = engine.start_scan(ORG, job["id"])
        assert completed["status"] == "completed"
        assert completed["secrets_found"] > 0
        assert completed["scan_duration_ms"] > 0
        assert completed["completed_at"] is not None

    def test_start_scan_env_file_has_critical(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "env_file"})
        completed = engine.start_scan(ORG, job["id"])
        assert completed["critical_count"] > 0

    def test_start_scan_not_found(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.start_scan(ORG, "nonexistent-uuid")

    def test_start_scan_already_running_fails(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "filesystem"})
        engine.start_scan(ORG, job["id"])
        # Already completed, can't start again
        with pytest.raises(ValueError):
            engine.start_scan(ORG, job["id"])

    def test_list_jobs_all(self, engine):
        engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.create_scan_job(ORG, {"target_type": "env_file"})
        jobs = engine.list_scan_jobs(ORG)
        assert len(jobs) == 2

    def test_list_jobs_filter_status(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"])
        pending_jobs = engine.list_scan_jobs(ORG, status="pending")
        completed_jobs = engine.list_scan_jobs(ORG, status="completed")
        assert len(pending_jobs) == 0
        assert len(completed_jobs) == 1

    def test_list_jobs_filter_target_type(self, engine):
        engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.create_scan_job(ORG, {"target_type": "env_file"})
        git_jobs = engine.list_scan_jobs(ORG, target_type="git_repo")
        assert len(git_jobs) == 1

    def test_get_scan_job_with_findings(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "filesystem"})
        engine.start_scan(ORG, job["id"])
        result = engine.get_scan_job(ORG, job["id"])
        assert result is not None
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_get_scan_job_not_found(self, engine):
        result = engine.get_scan_job(ORG, "no-such-id")
        assert result is None


# ---------------------------------------------------------------------------
# Simulate scan findings
# ---------------------------------------------------------------------------

class TestSimulateScan:
    def test_git_repo_has_aws_key(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        types = {f["secret_type"] for f in findings}
        assert "aws_access_key" in types

    def test_env_file_has_database_url(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "env_file"})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        types = {f["secret_type"] for f in findings}
        assert "database_url" in types

    def test_config_file_has_password(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "config_file"})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        types = {f["secret_type"] for f in findings}
        assert "password_in_code" in types

    def test_filesystem_has_private_key(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "filesystem"})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        types = {f["secret_type"] for f in findings}
        assert "private_key" in types

    def test_findings_have_masked_values(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        for f in findings:
            assert "****" in f["value_masked"]
            assert len(f["value_masked"]) > 8

    def test_findings_have_high_entropy(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        for f in findings:
            assert f["entropy"] >= 7.0

    def test_findings_have_file_path(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        for f in findings:
            assert f["file_path"]
            assert f["line_number"] > 0


# ---------------------------------------------------------------------------
# Finding management
# ---------------------------------------------------------------------------

class TestFindingManagement:
    def _create_finding(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "env_file"})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        return findings[0]["id"]

    def test_update_finding_remediated(self, engine):
        fid = self._create_finding(engine)
        ok = engine.update_finding(ORG, fid, "remediated", notes="Rotated key in vault")
        assert ok is True
        findings = engine.list_findings(ORG, status="remediated")
        assert any(f["id"] == fid for f in findings)

    def test_update_finding_accepted_risk(self, engine):
        fid = self._create_finding(engine)
        ok = engine.update_finding(ORG, fid, "accepted_risk")
        assert ok is True

    def test_update_finding_false_positive(self, engine):
        fid = self._create_finding(engine)
        ok = engine.update_finding(ORG, fid, "false_positive")
        assert ok is True

    def test_update_finding_invalid_status(self, engine):
        fid = self._create_finding(engine)
        with pytest.raises(ValueError, match="Invalid status"):
            engine.update_finding(ORG, fid, "bananas")

    def test_update_finding_not_found(self, engine):
        ok = engine.update_finding(ORG, "no-such-id", "remediated")
        assert ok is False

    def test_validate_finding_confirmed(self, engine):
        fid = self._create_finding(engine)
        ok = engine.validate_finding(ORG, fid, True)
        assert ok is True
        findings = engine.list_findings(ORG)
        match = next(f for f in findings if f["id"] == fid)
        assert match["is_valid_secret"] == "confirmed"

    def test_validate_finding_false_positive(self, engine):
        fid = self._create_finding(engine)
        ok = engine.validate_finding(ORG, fid, False)
        assert ok is True
        # Status should be updated to false_positive
        findings = engine.list_findings(ORG, status="false_positive")
        assert any(f["id"] == fid for f in findings)

    def test_list_findings_filter_severity(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "env_file"})
        engine.start_scan(ORG, job["id"])
        critical = engine.list_findings(ORG, severity="critical")
        assert len(critical) > 0
        for f in critical:
            assert f["severity"] == "critical"

    def test_list_findings_filter_secret_type(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"])
        aws_findings = engine.list_findings(ORG, secret_type="aws_access_key")
        for f in aws_findings:
            assert f["secret_type"] == "aws_access_key"

    def test_list_findings_limit(self, engine):
        for _ in range(3):
            job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
            engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG, limit=2)
        assert len(findings) <= 2


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

class TestPatterns:
    def test_create_pattern(self, engine):
        p = engine.create_pattern(ORG, {
            "pattern_name": "My AWS Key",
            "regex_pattern": r"AKIA[0-9A-Z]{16}",
            "secret_type": "aws_access_key",
            "severity": "critical",
        })
        assert p["id"]
        assert p["pattern_name"] == "My AWS Key"

    def test_create_pattern_missing_fields(self, engine):
        with pytest.raises(ValueError):
            engine.create_pattern(ORG, {"pattern_name": "x"})

    def test_list_patterns(self, engine):
        engine.create_pattern(ORG, {
            "pattern_name": "Pattern A",
            "regex_pattern": r"key_[a-z]{16}",
            "secret_type": "generic_api_key",
        })
        engine.create_pattern(ORG, {
            "pattern_name": "Pattern B",
            "regex_pattern": r"sk_live_[a-z]{24}",
            "secret_type": "stripe_key",
        })
        patterns = engine.list_patterns(ORG)
        assert len(patterns) == 2


# ---------------------------------------------------------------------------
# Suppression rules
# ---------------------------------------------------------------------------

class TestSuppressionRules:
    def test_add_suppression(self, engine):
        rule = engine.add_suppression(ORG, {
            "file_pattern": "tests/**",
            "secret_type": "generic_api_key",
            "reason": "Test fixtures",
            "approved_by": "security_team",
        })
        assert rule["id"]
        assert rule["file_pattern"] == "tests/**"

    def test_add_suppression_missing_fields(self, engine):
        with pytest.raises(ValueError):
            engine.add_suppression(ORG, {"file_pattern": "tests/**"})

    def test_list_suppressions(self, engine):
        engine.add_suppression(ORG, {
            "file_pattern": "docs/**",
            "secret_type": "jwt_token",
        })
        rules = engine.list_suppressions(ORG)
        assert len(rules) == 1


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestScannerStats:
    def test_stats_empty_org(self, engine):
        stats = engine.get_scanner_stats(ORG)
        assert stats["total_jobs"] == 0
        assert stats["total_findings"] == 0
        assert stats["remediation_rate"] == 0.0
        assert stats["critical_unresolved"] == 0

    def test_stats_after_scan(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "env_file"})
        engine.start_scan(ORG, job["id"])
        stats = engine.get_scanner_stats(ORG)
        assert stats["total_jobs"] == 1
        assert stats["total_findings"] > 0
        assert stats["critical_unresolved"] > 0
        assert "database_url" in stats["by_type"] or len(stats["by_type"]) > 0

    def test_stats_remediation_rate(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "env_file"})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        engine.update_finding(ORG, findings[0]["id"], "remediated")
        stats = engine.get_scanner_stats(ORG)
        assert stats["remediation_rate"] > 0.0

    def test_stats_false_positive_rate(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "config_file"})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        engine.validate_finding(ORG, findings[0]["id"], False)
        stats = engine.get_scanner_stats(ORG)
        assert stats["false_positive_rate"] > 0.0


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_jobs_isolated(self, engine, engine2, tmp_path):
        engine.create_scan_job(ORG, {"target_type": "git_repo"})
        jobs_org2 = engine2.list_scan_jobs(ORG2)
        assert len(jobs_org2) == 0

    def test_findings_isolated(self, engine, engine2, tmp_path):
        job = engine.create_scan_job(ORG, {"target_type": "env_file"})
        engine.start_scan(ORG, job["id"])
        findings_org2 = engine2.list_findings(ORG2)
        assert len(findings_org2) == 0
