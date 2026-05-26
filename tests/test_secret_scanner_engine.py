"""Tests for SecretScannerEngine.

Tests are split into three groups:

1. TestScanJobLifecycle — job creation, status transitions, list/get operations.
   Uses simulate=True to avoid filesystem dependency.

2. TestRealScan — plants real secrets in a temp dir and asserts the real scanner
   finds them (masked), not template values.

3. TestHonestNotConfigured — asserts that missing/absent target paths produce
   0 findings (no fabrication) rather than template results.

4. TestSimulateScan — backwards-compat tests for the simulation path
   (simulate=True), verifying the template contract is preserved for tests
   that explicitly opt in.

5. TestFindingManagement, TestPatterns, TestSuppressionRules, TestScannerStats,
   TestOrgIsolation — CRUD + stats tests, all using simulate=True.
"""

from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path

import pytest

from core.secret_scanner_engine import SecretScannerEngine, _SCAN_TEMPLATES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(tmp_path, org="org_test") -> SecretScannerEngine:
    """Fresh engine backed by a temp DB."""
    db_path = str(tmp_path / f"test_secret_scanner_{org}.db")
    eng = SecretScannerEngine.__new__(SecretScannerEngine)
    eng.org_id = org
    eng.db_path = db_path
    eng._lock = threading.RLock()
    eng._init_db()
    return eng


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    return _make_engine(tmp_path, "org_test")


@pytest.fixture()
def engine2(tmp_path):
    return _make_engine(tmp_path, "org_other")


ORG = "org_test"
ORG2 = "org_other"


@pytest.fixture()
def secret_fixture_dir(tmp_path) -> Path:
    """A temp directory with planted secret files and one clean file."""
    d = tmp_path / "repo"
    d.mkdir()

    # File 1: AWS access key (AKIAIOSFODNN7EXAMPLE is in the false-positive list;
    # use a structurally valid but non-example key)
    (d / "config.py").write_text(
        "# AWS credentials\n"
        "AWS_ACCESS_KEY_ID = 'AKIAX1234567890ABCDE'\n"
        "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n",
        encoding="utf-8",
    )

    # File 2: RSA private key header
    (d / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4ORW9I...(truncated for test)\n"
        "-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    # File 3: GitHub PAT token (ghp_ format)
    (d / "deploy.sh").write_text(
        "#!/bin/bash\n"
        "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456789\n",
        encoding="utf-8",
    )

    # File 4: clean file — no secrets
    (d / "README.md").write_text(
        "# My Project\nThis is just a README with no secrets.\n",
        encoding="utf-8",
    )

    return d


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
        completed = engine.start_scan(ORG, job["id"], simulate=True)
        assert completed["status"] == "completed"
        assert completed["secrets_found"] > 0
        assert completed["completed_at"] is not None

    def test_start_scan_env_file_has_critical(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "env_file"})
        completed = engine.start_scan(ORG, job["id"], simulate=True)
        assert completed["critical_count"] > 0

    def test_start_scan_not_found(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.start_scan(ORG, "nonexistent-uuid")

    def test_start_scan_already_completed_fails(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "filesystem"})
        engine.start_scan(ORG, job["id"], simulate=True)
        # Already completed, can't start again
        with pytest.raises(ValueError):
            engine.start_scan(ORG, job["id"], simulate=True)

    def test_list_jobs_all(self, engine):
        engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.create_scan_job(ORG, {"target_type": "env_file"})
        jobs = engine.list_scan_jobs(ORG)
        assert len(jobs) == 2

    def test_list_jobs_filter_status(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"], simulate=True)
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
        engine.start_scan(ORG, job["id"], simulate=True)
        result = engine.get_scan_job(ORG, job["id"])
        assert result is not None
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_get_scan_job_not_found(self, engine):
        result = engine.get_scan_job(ORG, "no-such-id")
        assert result is None


# ---------------------------------------------------------------------------
# Real scan — planted secrets
# ---------------------------------------------------------------------------

class TestRealScan:
    """Run the real scanner against a fixture directory with known secrets."""

    def test_real_scan_finds_secrets(self, engine, secret_fixture_dir):
        """Real scan must return at least one finding from the planted secrets."""
        job = engine.create_scan_job(
            ORG, {"target_type": "filesystem", "target_path": str(secret_fixture_dir)}
        )
        completed = engine.start_scan(ORG, job["id"])
        # Job completed successfully
        assert completed["status"] == "completed"
        findings = engine.list_findings(ORG)
        assert len(findings) >= 1, (
            "Expected at least 1 real finding from planted secrets, got 0"
        )

    def test_real_scan_finds_aws_key(self, engine, secret_fixture_dir):
        """Planted AKIA key must be found and classified as aws_access_key."""
        job = engine.create_scan_job(
            ORG, {"target_type": "filesystem", "target_path": str(secret_fixture_dir)}
        )
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        types = {f["secret_type"] for f in findings}
        assert "aws_access_key" in types, f"aws_access_key not in {types}"

    def test_real_scan_finds_private_key(self, engine, secret_fixture_dir):
        """Planted RSA private key header must be detected."""
        job = engine.create_scan_job(
            ORG, {"target_type": "filesystem", "target_path": str(secret_fixture_dir)}
        )
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        types = {f["secret_type"] for f in findings}
        assert "private_key" in types, f"private_key not in {types}"

    def test_real_scan_findings_are_masked(self, engine, secret_fixture_dir):
        """Every finding must have its secret value masked (contains ***)."""
        job = engine.create_scan_job(
            ORG, {"target_type": "filesystem", "target_path": str(secret_fixture_dir)}
        )
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        for f in findings:
            assert "***" in f["value_masked"], (
                f"Finding {f['id']} value_masked={f['value_masked']!r} is not masked"
            )

    def test_real_scan_findings_have_file_path_and_line(self, engine, secret_fixture_dir):
        """Findings from real scan must report the real file path and a valid line number."""
        job = engine.create_scan_job(
            ORG, {"target_type": "filesystem", "target_path": str(secret_fixture_dir)}
        )
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        for f in findings:
            assert f["file_path"], "file_path must not be empty"
            assert f["line_number"] >= 1, f"line_number={f['line_number']} must be >= 1"

    def test_real_scan_findings_are_not_template_values(self, engine, secret_fixture_dir):
        """Real findings must NOT be the old _SCAN_TEMPLATES fake values."""
        job = engine.create_scan_job(
            ORG, {"target_type": "filesystem", "target_path": str(secret_fixture_dir)}
        )
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        # Collect all file paths produced by templates
        template_paths = {
            p
            for paths in [
                ["src/config/settings.py", "deploy/infra.tf", ".github/workflows/ci.yml"],
                ["/etc/app/config.conf", "/home/user/.ssh/id_rsa", "/opt/app/secrets.txt"],
                [".env", ".env.production", "docker/.env"],
                ["config/database.yml", "app/settings.json", "helm/values.yaml"],
                ["response_cache/auth.json", "logs/api_debug.log", "tmp/response.json"],
            ]
            for p in paths
        }
        for f in findings:
            assert f["file_path"] not in template_paths, (
                f"file_path {f['file_path']!r} looks like a template fake path — "
                "fabricated findings leaked into real scan"
            )

    def test_clean_file_produces_no_findings(self, engine, tmp_path):
        """A directory with only clean files must produce 0 findings."""
        clean_dir = tmp_path / "clean"
        clean_dir.mkdir()
        (clean_dir / "main.py").write_text(
            "def hello():\n    print('hello world')\n", encoding="utf-8"
        )
        (clean_dir / "README.md").write_text(
            "# Clean project\nNo secrets here.\n", encoding="utf-8"
        )
        job = engine.create_scan_job(
            ORG, {"target_type": "filesystem", "target_path": str(clean_dir)}
        )
        completed = engine.start_scan(ORG, job["id"])
        assert completed["status"] == "completed"
        findings = engine.list_findings(ORG)
        assert len(findings) == 0, f"Expected 0 findings on clean dir, got {len(findings)}"


# ---------------------------------------------------------------------------
# Honest not-configured contract
# ---------------------------------------------------------------------------

class TestHonestNotConfigured:
    """Absent or missing target paths must produce 0 findings — no fabrication."""

    def test_missing_target_path_produces_zero_findings(self, engine):
        """Job with no target_path completes with 0 findings, not template values."""
        job = engine.create_scan_job(ORG, {"target_type": "git_repo", "target_path": ""})
        completed = engine.start_scan(ORG, job["id"])
        assert completed["status"] == "completed"
        assert completed["secrets_found"] == 0
        findings = engine.list_findings(ORG)
        assert len(findings) == 0

    def test_nonexistent_path_produces_zero_findings(self, engine, tmp_path):
        """Job pointing to a non-existent path completes with 0 findings."""
        nonexistent = str(tmp_path / "does_not_exist" / "repo")
        job = engine.create_scan_job(
            ORG, {"target_type": "filesystem", "target_path": nonexistent}
        )
        completed = engine.start_scan(ORG, job["id"])
        assert completed["status"] == "completed"
        assert completed["secrets_found"] == 0

    def test_zero_findings_job_is_not_template_findings(self, engine):
        """The 0-findings result from a missing path must contain no template secret types."""
        job = engine.create_scan_job(ORG, {"target_type": "env_file", "target_path": ""})
        engine.start_scan(ORG, job["id"])
        findings = engine.list_findings(ORG)
        # env_file template would inject database_url + stripe_key + jwt_token
        types = {f["secret_type"] for f in findings}
        assert "database_url" not in types or len(findings) == 0
        assert "stripe_key" not in types or len(findings) == 0


# ---------------------------------------------------------------------------
# Simulate scan findings (test-only opt-in)
# ---------------------------------------------------------------------------

class TestSimulateScan:
    """Verify the simulation path (simulate=True) still works for tests that need it."""

    def test_git_repo_has_aws_key(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"], simulate=True)
        findings = engine.list_findings(ORG)
        types = {f["secret_type"] for f in findings}
        assert "aws_access_key" in types

    def test_env_file_has_database_url(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "env_file"})
        engine.start_scan(ORG, job["id"], simulate=True)
        findings = engine.list_findings(ORG)
        types = {f["secret_type"] for f in findings}
        assert "database_url" in types

    def test_config_file_has_password(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "config_file"})
        engine.start_scan(ORG, job["id"], simulate=True)
        findings = engine.list_findings(ORG)
        types = {f["secret_type"] for f in findings}
        assert "password_in_code" in types

    def test_filesystem_has_private_key(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "filesystem"})
        engine.start_scan(ORG, job["id"], simulate=True)
        findings = engine.list_findings(ORG)
        types = {f["secret_type"] for f in findings}
        assert "private_key" in types

    def test_findings_have_masked_values(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"], simulate=True)
        findings = engine.list_findings(ORG)
        for f in findings:
            assert "****" in f["value_masked"]
            assert len(f["value_masked"]) > 8

    def test_findings_have_high_entropy(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"], simulate=True)
        findings = engine.list_findings(ORG)
        for f in findings:
            assert f["entropy"] >= 7.0

    def test_findings_have_file_path(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"], simulate=True)
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
        engine.start_scan(ORG, job["id"], simulate=True)
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
        engine.start_scan(ORG, job["id"], simulate=True)
        critical = engine.list_findings(ORG, severity="critical")
        assert len(critical) > 0
        for f in critical:
            assert f["severity"] == "critical"

    def test_list_findings_filter_secret_type(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
        engine.start_scan(ORG, job["id"], simulate=True)
        aws_findings = engine.list_findings(ORG, secret_type="aws_access_key")
        for f in aws_findings:
            assert f["secret_type"] == "aws_access_key"

    def test_list_findings_limit(self, engine):
        for _ in range(3):
            job = engine.create_scan_job(ORG, {"target_type": "git_repo"})
            engine.start_scan(ORG, job["id"], simulate=True)
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
        engine.start_scan(ORG, job["id"], simulate=True)
        stats = engine.get_scanner_stats(ORG)
        assert stats["total_jobs"] == 1
        assert stats["total_findings"] > 0
        assert stats["critical_unresolved"] > 0
        assert len(stats["by_type"]) > 0

    def test_stats_remediation_rate(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "env_file"})
        engine.start_scan(ORG, job["id"], simulate=True)
        findings = engine.list_findings(ORG)
        engine.update_finding(ORG, findings[0]["id"], "remediated")
        stats = engine.get_scanner_stats(ORG)
        assert stats["remediation_rate"] > 0.0

    def test_stats_false_positive_rate(self, engine):
        job = engine.create_scan_job(ORG, {"target_type": "config_file"})
        engine.start_scan(ORG, job["id"], simulate=True)
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
        engine.start_scan(ORG, job["id"], simulate=True)
        findings_org2 = engine2.list_findings(ORG2)
        assert len(findings_org2) == 0
