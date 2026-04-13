"""
Tests for Semgrep integration — SemgrepScanner and semgrep_router.

All subprocess calls are mocked so no semgrep binary is required.
Covers: scan methods, normalize_results, scan_and_ingest, history,
        graceful fallback, rulesets, and API router endpoints.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ── Environment setup ──────────────────────────────────────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# ── Fixtures ───────────────────────────────────────────────────────────────

SAMPLE_SEMGREP_OUTPUT: Dict[str, Any] = {
    "version": "1.45.0",
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected.exec-detected",
            "path": "app/utils.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 20},
            "extra": {
                "severity": "ERROR",
                "message": "Use of exec() is a security risk.",
                "lines": "    exec(user_input)",
                "metadata": {
                    "category": "security",
                    "cwe": ["CWE-78: OS Command Injection"],
                    "owasp": ["A03:2021 - Injection"],
                },
            },
        },
        {
            "check_id": "python.lang.security.audit.hardcoded-password.hardcoded-password-string",
            "path": "config/settings.py",
            "start": {"line": 15, "col": 1},
            "end": {"line": 15, "col": 35},
            "extra": {
                "severity": "WARNING",
                "message": "Hardcoded password detected.",
                "lines": "DB_PASSWORD = 'supersecret123'",
                "metadata": {
                    "category": "security",
                    "cwe": ["CWE-259: Use of Hard-coded Password"],
                    "owasp": ["A07:2021 - Identification and Authentication Failures"],
                },
            },
        },
        {
            "check_id": "python.lang.correctness.useless-eqeq.useless-eqeq",
            "path": "app/models.py",
            "start": {"line": 88, "col": 8},
            "end": {"line": 88, "col": 22},
            "extra": {
                "severity": "INFO",
                "message": "Useless equality check.",
                "lines": "        if x == True:",
                "metadata": {"category": "correctness"},
            },
        },
    ],
    "errors": [],
    "stats": {
        "bytes_scanned": 8192,
        "num_findings": 3,
        "total_time": 1.23,
    },
}

EMPTY_SEMGREP_OUTPUT: Dict[str, Any] = {
    "version": "1.45.0",
    "results": [],
    "errors": [],
    "stats": {"bytes_scanned": 0, "num_findings": 0, "total_time": 0.1},
}


# ── SemgrepScanner unit tests ──────────────────────────────────────────────

class TestSemgrepScannerAvailability:
    def test_is_semgrep_available_true(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        with patch("shutil.which", return_value="/usr/local/bin/semgrep"):
            assert scanner.is_semgrep_available() is True

    def test_is_semgrep_available_false(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        with patch("shutil.which", return_value=None):
            assert scanner.is_semgrep_available() is False

    def test_custom_bin_env(self, monkeypatch):
        monkeypatch.setenv("SEMGREP_BIN", "/opt/bin/semgrep")
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        assert scanner._bin == "/opt/bin/semgrep"

    def test_default_bin_name(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        assert scanner._bin == "semgrep"


class TestSemgrepScannerRunSemgrep:
    """Tests for _run_semgrep internal method."""

    def _make_scanner(self):
        from core.semgrep_integration import SemgrepScanner
        return SemgrepScanner()

    def test_returns_mock_when_not_installed(self):
        scanner = self._make_scanner()
        with patch("shutil.which", return_value=None):
            result = scanner._run_semgrep(["--config", "p/default", "/tmp"])
        assert "results" in result
        assert len(result["results"]) > 0

    def test_runs_subprocess_when_available(self):
        scanner = self._make_scanner()
        payload = json.dumps(SAMPLE_SEMGREP_OUTPUT).encode()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = payload
        mock_proc.stderr = b""
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run", return_value=mock_proc):
            result = scanner._run_semgrep(["--config", "p/default", "/app"])
        assert len(result["results"]) == 3

    def test_exit_code_1_treated_as_findings(self):
        """Semgrep exit code 1 means findings found — not an error."""
        scanner = self._make_scanner()
        payload = json.dumps(SAMPLE_SEMGREP_OUTPUT).encode()
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = payload
        mock_proc.stderr = b""
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run", return_value=mock_proc):
            result = scanner._run_semgrep(["--config", "p/default", "/app"])
        assert len(result["results"]) == 3

    def test_raises_on_bad_exit_code(self):
        scanner = self._make_scanner()
        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stdout = b""
        mock_proc.stderr = b"fatal config error"
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run", return_value=mock_proc):
            with pytest.raises(RuntimeError, match="Semgrep exited with code 2"):
                scanner._run_semgrep(["--config", "p/default", "/app"])

    def test_raises_on_invalid_json(self):
        scanner = self._make_scanner()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"not-json-output"
        mock_proc.stderr = b""
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run", return_value=mock_proc):
            with pytest.raises(RuntimeError, match="not valid JSON"):
                scanner._run_semgrep(["--config", "p/default", "/app"])

    def test_timeout_raises_runtime_error(self):
        import subprocess
        scanner = self._make_scanner()
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=5)):
            with pytest.raises(RuntimeError, match="timed out"):
                scanner._run_semgrep(["--config", "p/default", "/app"])

    def test_fallback_on_file_not_found(self):
        scanner = self._make_scanner()
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            result = scanner._run_semgrep(["--config", "p/default", "/app"])
        assert "results" in result  # mock data returned

    def test_empty_stdout_returns_empty_results(self):
        scanner = self._make_scanner()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b""
        mock_proc.stderr = b""
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run", return_value=mock_proc):
            result = scanner._run_semgrep(["--config", "p/default", "/app"])
        assert result == {"results": [], "errors": []}


class TestScanMethods:
    def _make_scanner_with_mock_run(self, output=None):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        scanner._run_semgrep = MagicMock(return_value=output or SAMPLE_SEMGREP_OUTPUT)
        return scanner

    def test_scan_directory(self):
        scanner = self._make_scanner_with_mock_run()
        result = scanner.scan_directory("/tmp/project")
        scanner._run_semgrep.assert_called_once_with(["--config", "p/default", "/tmp/project"])
        assert "results" in result

    def test_scan_directory_with_rules(self):
        scanner = self._make_scanner_with_mock_run()
        scanner.scan_directory("/tmp/project", rules="p/owasp-top-ten")
        scanner._run_semgrep.assert_called_once_with(
            ["--config", "p/owasp-top-ten", "/tmp/project"]
        )

    def test_scan_directory_rejects_empty_path(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        with pytest.raises(ValueError):
            scanner.scan_directory("")

    def test_scan_file(self):
        scanner = self._make_scanner_with_mock_run()
        scanner.scan_file("/tmp/app.py")
        scanner._run_semgrep.assert_called_once_with(["--config", "p/default", "/tmp/app.py"])

    def test_scan_file_with_rules(self):
        scanner = self._make_scanner_with_mock_run()
        scanner.scan_file("/tmp/app.py", rules="p/python")
        scanner._run_semgrep.assert_called_once_with(["--config", "p/python", "/tmp/app.py"])

    def test_scan_file_rejects_empty_path(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        with pytest.raises(ValueError):
            scanner.scan_file("")

    def test_scan_with_config(self):
        scanner = self._make_scanner_with_mock_run()
        scanner.scan_with_config("/tmp/project", "p/secrets")
        scanner._run_semgrep.assert_called_once_with(["--config", "p/secrets", "/tmp/project"])

    def test_scan_with_config_rejects_empty_path(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        with pytest.raises(ValueError):
            scanner.scan_with_config("", "p/secrets")

    def test_scan_with_config_rejects_empty_config(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        with pytest.raises(ValueError):
            scanner.scan_with_config("/tmp/project", "")


class TestGetAvailableRulesets:
    def test_returns_list(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        rulesets = scanner.get_available_rulesets()
        assert isinstance(rulesets, list)
        assert len(rulesets) > 0

    def test_includes_common_rulesets(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        rulesets = scanner.get_available_rulesets()
        assert "p/owasp-top-ten" in rulesets
        assert "p/secrets" in rulesets
        assert "p/default" in rulesets

    def test_returns_copy(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        r1 = scanner.get_available_rulesets()
        r1.append("p/fake")
        r2 = scanner.get_available_rulesets()
        assert "p/fake" not in r2


class TestNormalizeResults:
    def _make_scanner(self):
        from core.semgrep_integration import SemgrepScanner
        return SemgrepScanner()

    def test_normalize_empty_output(self):
        scanner = self._make_scanner()
        assert scanner.normalize_results({}) == []

    def test_inline_normalize_findings(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(SAMPLE_SEMGREP_OUTPUT)
        assert len(findings) == 3

    def test_inline_normalize_severity_mapping(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(SAMPLE_SEMGREP_OUTPUT)
        severities = {f["severity"] for f in findings}
        assert "high" in severities    # ERROR → high
        assert "medium" in severities  # WARNING → medium
        assert "low" in severities     # INFO → low

    def test_inline_normalize_file_path(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(SAMPLE_SEMGREP_OUTPUT)
        paths = {f["file_path"] for f in findings}
        assert "app/utils.py" in paths
        assert "config/settings.py" in paths

    def test_inline_normalize_line_number(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(SAMPLE_SEMGREP_OUTPUT)
        exec_finding = next(
            f for f in findings if "exec-detected" in f.get("rule_id", "")
        )
        assert exec_finding["line_number"] == 42

    def test_inline_normalize_rule_id(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(SAMPLE_SEMGREP_OUTPUT)
        rule_ids = {f["rule_id"] for f in findings}
        assert "python.lang.security.audit.exec-detected.exec-detected" in rule_ids

    def test_inline_normalize_empty_results(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(EMPTY_SEMGREP_OUTPUT)
        assert findings == []

    def test_normalize_results_returns_list_of_dicts(self):
        scanner = self._make_scanner()
        findings = scanner.normalize_results(SAMPLE_SEMGREP_OUTPUT)
        assert isinstance(findings, list)
        for f in findings:
            assert isinstance(f, dict)

    def test_inline_normalize_source_tool(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(SAMPLE_SEMGREP_OUTPUT)
        for f in findings:
            assert f["source_tool"] == "semgrep"


class TestScanAndIngest:
    def _make_scanner(self, mock_output=None):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        scanner._run_semgrep = MagicMock(return_value=mock_output or SAMPLE_SEMGREP_OUTPUT)
        scanner._try_ingest_to_pipeline = MagicMock()
        return scanner

    def test_scan_and_ingest_returns_summary(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest("/tmp/project", org_id="test-org")
        assert result["status"] == "completed"
        assert result["org_id"] == "test-org"
        assert result["target"] == "/tmp/project"
        assert "scan_id" in result
        assert "findings_count" in result
        assert "severity_breakdown" in result

    def test_scan_and_ingest_findings_count(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest("/tmp/project", org_id="test-org")
        assert result["findings_count"] == len(result["findings"])
        assert result["findings_count"] > 0

    def test_scan_and_ingest_severity_breakdown(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest("/tmp/project", org_id="test-org")
        breakdown = result["severity_breakdown"]
        assert isinstance(breakdown, dict)
        total = sum(breakdown.values())
        assert total == result["findings_count"]

    def test_scan_and_ingest_with_rules(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest("/tmp/project", org_id="org1", rules="p/owasp-top-ten")
        assert result["rules"] == "p/owasp-top-ten"
        scanner._run_semgrep.assert_called_once_with(
            ["--config", "p/owasp-top-ten", "/tmp/project"]
        )

    def test_scan_and_ingest_default_rules(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest("/tmp/project", org_id="org1")
        assert result["rules"] == "p/default"

    def test_scan_and_ingest_error_returns_failed_status(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        scanner._run_semgrep = MagicMock(side_effect=RuntimeError("semgrep exploded"))
        result = scanner.scan_and_ingest("/bad/path", org_id="org1")
        assert result["status"] == "failed"
        assert "error" in result
        assert result["findings_count"] == 0

    def test_scan_and_ingest_stores_in_history(self):
        from core.semgrep_integration import SemgrepScanner, _scan_history
        scanner = SemgrepScanner()
        scanner._run_semgrep = MagicMock(return_value=SAMPLE_SEMGREP_OUTPUT)
        scanner._try_ingest_to_pipeline = MagicMock()
        org_id = f"test-{uuid.uuid4().hex[:8]}"
        scanner.scan_and_ingest("/tmp/project", org_id=org_id)
        assert org_id in _scan_history
        assert len(_scan_history[org_id]) >= 1

    def test_scan_and_ingest_is_mock_flag_set(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        scanner._try_ingest_to_pipeline = MagicMock()
        with patch("shutil.which", return_value=None):
            result = scanner.scan_and_ingest("/tmp/project", org_id="org1")
        assert result["is_mock"] is True

    def test_scan_and_ingest_pipeline_ingest_called(self):
        scanner = self._make_scanner()
        scanner.scan_and_ingest("/tmp/project", org_id="test-org")
        scanner._try_ingest_to_pipeline.assert_called_once()

    def test_scan_and_ingest_has_timestamps(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest("/tmp/project", org_id="org1")
        assert "started_at" in result
        assert "completed_at" in result
        assert result["started_at"]
        assert result["completed_at"]


class TestScanHistory:
    def test_get_scan_history_empty_for_new_org(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        org_id = f"neworg-{uuid.uuid4().hex}"
        history = scanner.get_scan_history(org_id=org_id)
        assert history == []

    def test_get_scan_history_returns_summaries(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        scanner._run_semgrep = MagicMock(return_value=SAMPLE_SEMGREP_OUTPUT)
        scanner._try_ingest_to_pipeline = MagicMock()
        org_id = f"historg-{uuid.uuid4().hex[:8]}"
        scanner.scan_and_ingest("/tmp/project", org_id=org_id)
        scanner.scan_and_ingest("/tmp/other", org_id=org_id)
        history = scanner.get_scan_history(org_id=org_id)
        assert len(history) == 2

    def test_get_scan_history_most_recent_first(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        scanner._run_semgrep = MagicMock(return_value=SAMPLE_SEMGREP_OUTPUT)
        scanner._try_ingest_to_pipeline = MagicMock()
        org_id = f"orderorg-{uuid.uuid4().hex[:8]}"
        scanner.scan_and_ingest("/tmp/first", org_id=org_id)
        scanner.scan_and_ingest("/tmp/second", org_id=org_id)
        history = scanner.get_scan_history(org_id=org_id)
        assert history[0]["target"] == "/tmp/second"

    def test_get_scan_history_no_findings_in_summary(self):
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        scanner._run_semgrep = MagicMock(return_value=SAMPLE_SEMGREP_OUTPUT)
        scanner._try_ingest_to_pipeline = MagicMock()
        org_id = f"nofind-{uuid.uuid4().hex[:8]}"
        scanner.scan_and_ingest("/tmp/project", org_id=org_id)
        history = scanner.get_scan_history(org_id=org_id)
        assert "findings" not in history[0]


# ── API Router tests ───────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def semgrep_client():
    """FastAPI test client with semgrep_router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.semgrep_router import router

    app = FastAPI()
    app.include_router(router)

    import apps.api.auth_deps as auth_deps
    original = auth_deps.api_key_auth

    async def _no_auth():
        return None

    auth_deps.api_key_auth = _no_auth
    app.dependency_overrides[original] = _no_auth

    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_scanner_singleton():
    """Reset the module-level _scanner singleton between tests."""
    import apps.api.semgrep_router as semgrep_mod
    semgrep_mod._scanner = None
    yield
    semgrep_mod._scanner = None


def _make_scan_response(**kwargs) -> Dict[str, Any]:
    """Build a minimal valid ScanResponse dict."""
    base = {
        "scan_id": str(uuid.uuid4()),
        "org_id": "test",
        "target": "/tmp/project",
        "rules": "p/default",
        "started_at": "2026-01-01T00:00:00+00:00",
        "completed_at": "2026-01-01T00:00:05+00:00",
        "status": "completed",
        "is_mock": True,
        "findings_count": 2,
        "severity_breakdown": {"high": 1, "medium": 1},
        "findings": [],
    }
    base.update(kwargs)
    return base


class TestSemgrepRouterStatus:
    def test_status_available(self, semgrep_client):
        with patch("core.semgrep_integration.SemgrepScanner.is_semgrep_available", return_value=True):
            resp = semgrep_client.get("/api/v1/scan/semgrep/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is True
        assert "real scans" in body["message"]

    def test_status_not_available(self, semgrep_client):
        with patch("core.semgrep_integration.SemgrepScanner.is_semgrep_available", return_value=False):
            resp = semgrep_client.get("/api/v1/scan/semgrep/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is False
        assert "not found" in body["message"]


class TestSemgrepRouterRulesets:
    def test_rulesets_returns_list(self, semgrep_client):
        resp = semgrep_client.get("/api/v1/scan/semgrep/rulesets")
        assert resp.status_code == 200
        body = resp.json()
        assert "rulesets" in body
        assert isinstance(body["rulesets"], list)
        assert len(body["rulesets"]) > 0

    def test_rulesets_includes_owasp(self, semgrep_client):
        resp = semgrep_client.get("/api/v1/scan/semgrep/rulesets")
        assert resp.status_code == 200
        assert "p/owasp-top-ten" in resp.json()["rulesets"]


class TestSemgrepRouterScanDirectory:
    def test_scan_directory_success(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.scan_and_ingest = MagicMock(return_value=_make_scan_response())
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.post(
                "/api/v1/scan/semgrep/directory",
                json={"path": "/tmp/project", "org_id": "test"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "completed"
        assert body["findings_count"] == 2

    def test_scan_directory_missing_path(self, semgrep_client):
        resp = semgrep_client.post(
            "/api/v1/scan/semgrep/directory", json={"org_id": "test"}
        )
        assert resp.status_code == 422

    def test_scan_directory_scanner_error(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.scan_and_ingest = MagicMock(side_effect=RuntimeError("scan failed"))
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.post(
                "/api/v1/scan/semgrep/directory",
                json={"path": "/bad/path", "org_id": "test"},
            )
        assert resp.status_code == 500

    def test_scan_directory_with_rules(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.scan_and_ingest = MagicMock(
            return_value=_make_scan_response(rules="p/owasp-top-ten")
        )
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.post(
                "/api/v1/scan/semgrep/directory",
                json={"path": "/tmp/project", "rules": "p/owasp-top-ten", "org_id": "test"},
            )
        assert resp.status_code == 200
        mock_scanner.scan_and_ingest.assert_called_once_with(
            path="/tmp/project", org_id="test", rules="p/owasp-top-ten"
        )


class TestSemgrepRouterScanFile:
    def test_scan_file_success(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.scan_file = MagicMock(return_value=SAMPLE_SEMGREP_OUTPUT)
        mock_scanner.normalize_results = MagicMock(return_value=[
            {"severity": "high", "rule_id": "test"},
            {"severity": "medium", "rule_id": "test2"},
        ])
        mock_scanner.is_semgrep_available = MagicMock(return_value=False)
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.post(
                "/api/v1/scan/semgrep/file",
                json={"file_path": "/tmp/app.py", "org_id": "test"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "completed"
        assert body["target"] == "/tmp/app.py"
        assert body["findings_count"] == 2

    def test_scan_file_missing_file_path(self, semgrep_client):
        resp = semgrep_client.post(
            "/api/v1/scan/semgrep/file", json={"org_id": "test"}
        )
        assert resp.status_code == 422

    def test_scan_file_scanner_error(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.scan_file = MagicMock(side_effect=RuntimeError("scan failed"))
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.post(
                "/api/v1/scan/semgrep/file",
                json={"file_path": "/bad/file.py", "org_id": "test"},
            )
        assert resp.status_code == 500


class TestSemgrepRouterScanWithConfig:
    def test_scan_with_config_success(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.scan_with_config = MagicMock(return_value=EMPTY_SEMGREP_OUTPUT)
        mock_scanner.normalize_results = MagicMock(return_value=[])
        mock_scanner.is_semgrep_available = MagicMock(return_value=True)
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.post(
                "/api/v1/scan/semgrep/config",
                json={
                    "path": "/tmp/project",
                    "config": "p/owasp-top-ten",
                    "org_id": "test",
                },
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "completed"
        assert body["rules"] == "p/owasp-top-ten"
        assert body["findings_count"] == 0

    def test_scan_with_config_missing_fields(self, semgrep_client):
        resp = semgrep_client.post(
            "/api/v1/scan/semgrep/config",
            json={"path": "/tmp/project"},  # missing config
        )
        assert resp.status_code == 422

    def test_scan_with_config_scanner_error(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.scan_with_config = MagicMock(side_effect=RuntimeError("config error"))
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.post(
                "/api/v1/scan/semgrep/config",
                json={"path": "/tmp/project", "config": "bad-config", "org_id": "test"},
            )
        assert resp.status_code == 500


class TestSemgrepRouterHistory:
    def test_history_empty(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.get_scan_history = MagicMock(return_value=[])
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.get(
                "/api/v1/scan/semgrep/history", params={"org_id": "noorg"}
            )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_history_returns_list(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.get_scan_history = MagicMock(return_value=[
            {
                "scan_id": str(uuid.uuid4()),
                "org_id": "test",
                "target": "/tmp/project",
                "rules": "p/default",
                "started_at": "2026-01-01T00:00:00+00:00",
                "completed_at": "2026-01-01T00:00:05+00:00",
                "status": "completed",
                "is_mock": True,
                "findings_count": 3,
                "severity_breakdown": {"high": 1, "medium": 1, "low": 1},
            }
        ])
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.get(
                "/api/v1/scan/semgrep/history", params={"org_id": "test"}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["target"] == "/tmp/project"

    def test_history_default_org_id(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.get_scan_history = MagicMock(return_value=[])
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.get("/api/v1/scan/semgrep/history")
        assert resp.status_code == 200
        mock_scanner.get_scan_history.assert_called_once_with(org_id="default")

    def test_history_error_returns_500(self, semgrep_client):
        mock_scanner = MagicMock()
        mock_scanner.get_scan_history = MagicMock(side_effect=RuntimeError("db error"))
        with patch("apps.api.semgrep_router._get_scanner", return_value=mock_scanner):
            resp = semgrep_client.get("/api/v1/scan/semgrep/history")
        assert resp.status_code == 500
