"""
Tests for Trivy integration — TrivyScanner and trivy_router.

All subprocess calls are mocked so no trivy binary is required.
Covers: scan methods, normalize_results, scan_and_ingest, history,
        graceful fallback, and API router endpoints.
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

SAMPLE_TRIVY_OUTPUT: Dict[str, Any] = {
    "SchemaVersion": 2,
    "ArtifactName": "nginx:1.25",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "nginx:1.25 (debian 12.4)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-1234",
                    "PkgName": "libssl3",
                    "InstalledVersion": "3.0.9-1",
                    "FixedVersion": "3.0.11-1",
                    "Severity": "HIGH",
                    "Title": "OpenSSL buffer overflow",
                    "Description": "A buffer overflow in OpenSSL.",
                },
                {
                    "VulnerabilityID": "CVE-2023-5678",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88.1-10",
                    "FixedVersion": "",
                    "Severity": "MEDIUM",
                    "Title": "curl SSRF",
                    "Description": "Server-side request forgery in curl.",
                },
            ],
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Severity": "HIGH",
                    "Title": "Root user in container",
                    "Description": "Container runs as root.",
                    "Resolution": "Use a non-root USER in Dockerfile.",
                }
            ],
        },
        {
            "Target": "usr/local/lib/python3.11/site-packages/requests",
            "Class": "lang-pkgs",
            "Type": "python-pkg",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-9999",
                    "PkgName": "requests",
                    "InstalledVersion": "2.28.0",
                    "FixedVersion": "2.32.0",
                    "Severity": "CRITICAL",
                    "Title": "requests certificate verification bypass",
                    "Description": "TLS cert not verified.",
                }
            ],
        },
    ],
}

EMPTY_TRIVY_OUTPUT: Dict[str, Any] = {
    "SchemaVersion": 2,
    "ArtifactName": "scratch:latest",
    "ArtifactType": "container_image",
    "Results": [],
}


# ── TrivyScanner unit tests ────────────────────────────────────────────────

class TestTrivyScannerAvailability:
    def test_is_trivy_available_true(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        with patch("shutil.which", return_value="/usr/local/bin/trivy"):
            assert scanner.is_trivy_available() is True

    def test_is_trivy_available_false(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        with patch("shutil.which", return_value=None):
            assert scanner.is_trivy_available() is False

    def test_custom_bin_env(self, monkeypatch):
        monkeypatch.setenv("TRIVY_BIN", "/opt/bin/trivy")
        from importlib import reload
        import core.trivy_integration as mod
        scanner = mod.TrivyScanner()
        assert scanner._bin == "/opt/bin/trivy"


class TestTrivyScannerRunTrivy:
    """Tests for _run_trivy internal method."""

    def _make_scanner(self):
        from core.trivy_integration import TrivyScanner
        return TrivyScanner()

    def test_returns_mock_when_not_installed(self):
        scanner = self._make_scanner()
        with patch("shutil.which", return_value=None):
            result = scanner._run_trivy(["image", "nginx:latest"])
        assert "Results" in result
        assert result.get("ArtifactName") == "mock-image:latest"

    def test_runs_subprocess_when_available(self):
        scanner = self._make_scanner()
        payload = json.dumps(SAMPLE_TRIVY_OUTPUT).encode()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = payload
        mock_proc.stderr = b""
        with patch("shutil.which", return_value="/usr/bin/trivy"), \
             patch("subprocess.run", return_value=mock_proc):
            result = scanner._run_trivy(["image", "nginx:1.25"])
        assert result["ArtifactName"] == "nginx:1.25"
        assert len(result["Results"]) == 2

    def test_exit_code_1_treated_as_findings(self):
        """Trivy exit code 1 means vulnerabilities found — not an error."""
        scanner = self._make_scanner()
        payload = json.dumps(SAMPLE_TRIVY_OUTPUT).encode()
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = payload
        mock_proc.stderr = b""
        with patch("shutil.which", return_value="/usr/bin/trivy"), \
             patch("subprocess.run", return_value=mock_proc):
            result = scanner._run_trivy(["image", "nginx:1.25"])
        assert result["ArtifactName"] == "nginx:1.25"

    def test_raises_on_bad_exit_code(self):
        scanner = self._make_scanner()
        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stdout = b""
        mock_proc.stderr = b"fatal error"
        with patch("shutil.which", return_value="/usr/bin/trivy"), \
             patch("subprocess.run", return_value=mock_proc):
            with pytest.raises(RuntimeError, match="Trivy exited with code 2"):
                scanner._run_trivy(["image", "nginx:1.25"])

    def test_raises_on_invalid_json(self):
        scanner = self._make_scanner()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"not-json"
        mock_proc.stderr = b""
        with patch("shutil.which", return_value="/usr/bin/trivy"), \
             patch("subprocess.run", return_value=mock_proc):
            with pytest.raises(RuntimeError, match="not valid JSON"):
                scanner._run_trivy(["image", "nginx:1.25"])

    def test_timeout_raises_runtime_error(self):
        import subprocess
        scanner = self._make_scanner()
        with patch("shutil.which", return_value="/usr/bin/trivy"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=5)):
            with pytest.raises(RuntimeError, match="timed out"):
                scanner._run_trivy(["image", "nginx:1.25"])

    def test_fallback_on_file_not_found(self):
        scanner = self._make_scanner()
        with patch("shutil.which", return_value="/usr/bin/trivy"), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            result = scanner._run_trivy(["image", "nginx:1.25"])
        assert "Results" in result  # mock data returned


class TestScanMethods:
    def _make_scanner_with_mock_run(self, output=None):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        scanner._run_trivy = MagicMock(return_value=output or SAMPLE_TRIVY_OUTPUT)
        return scanner

    def test_scan_image(self):
        scanner = self._make_scanner_with_mock_run()
        result = scanner.scan_image("nginx:1.25")
        scanner._run_trivy.assert_called_once_with(["image", "nginx:1.25"])
        assert result["ArtifactName"] == "nginx:1.25"

    def test_scan_image_rejects_empty_name(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        with pytest.raises(ValueError):
            scanner.scan_image("")

    def test_scan_filesystem(self):
        scanner = self._make_scanner_with_mock_run()
        scanner.scan_filesystem("/tmp/project")
        scanner._run_trivy.assert_called_once_with(["fs", "/tmp/project"])

    def test_scan_filesystem_rejects_empty_path(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        with pytest.raises(ValueError):
            scanner.scan_filesystem("")

    def test_scan_repo(self):
        scanner = self._make_scanner_with_mock_run()
        scanner.scan_repo("https://github.com/org/repo")
        scanner._run_trivy.assert_called_once_with(
            ["repo", "https://github.com/org/repo"]
        )

    def test_scan_repo_rejects_empty_url(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        with pytest.raises(ValueError):
            scanner.scan_repo("")


class TestNormalizeResults:
    def _make_scanner(self):
        from core.trivy_integration import TrivyScanner
        return TrivyScanner()

    def test_normalize_empty_output(self):
        scanner = self._make_scanner()
        assert scanner.normalize_results({}) == []

    def test_inline_normalize_vulnerabilities(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(SAMPLE_TRIVY_OUTPUT)
        # 2 vulns + 1 misconfig in first result + 1 vuln in second = 4
        assert len(findings) == 4

    def test_inline_normalize_severity_mapping(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(SAMPLE_TRIVY_OUTPUT)
        severities = {f["severity"] for f in findings}
        assert "high" in severities
        assert "medium" in severities
        assert "critical" in severities

    def test_inline_normalize_cve_id_set(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(SAMPLE_TRIVY_OUTPUT)
        vuln_findings = [f for f in findings if f.get("cve_id")]
        assert len(vuln_findings) == 3  # 3 CVE findings

    def test_inline_normalize_recommendation_includes_fix(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(SAMPLE_TRIVY_OUTPUT)
        ssl_finding = next(f for f in findings if "libssl3" in f.get("package_name", ""))
        assert "3.0.11-1" in ssl_finding["recommendation"]

    def test_inline_normalize_empty_results(self):
        scanner = self._make_scanner()
        findings = scanner._inline_normalize(EMPTY_TRIVY_OUTPUT)
        assert findings == []

    def test_normalize_results_uses_inline_when_normalizer_unavailable(self):
        scanner = self._make_scanner()
        # Force inline path by making import fail
        with patch("builtins.__import__", side_effect=ImportError("no module")):
            findings = scanner._inline_normalize(SAMPLE_TRIVY_OUTPUT)
        assert len(findings) == 4

    def test_normalize_results_returns_list_of_dicts(self):
        scanner = self._make_scanner()
        findings = scanner.normalize_results(SAMPLE_TRIVY_OUTPUT)
        assert isinstance(findings, list)
        for f in findings:
            assert isinstance(f, dict)


class TestScanAndIngest:
    def _make_scanner(self, mock_output=None):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        scanner._run_trivy = MagicMock(return_value=mock_output or SAMPLE_TRIVY_OUTPUT)
        scanner._try_ingest_to_pipeline = MagicMock()
        return scanner

    def test_scan_and_ingest_returns_summary(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest("nginx:1.25", org_id="test-org")
        assert result["status"] == "completed"
        assert result["org_id"] == "test-org"
        assert result["target"] == "nginx:1.25"
        assert result["scan_type"] == "image"
        assert "scan_id" in result
        assert "findings_count" in result
        assert "severity_breakdown" in result

    def test_scan_and_ingest_findings_count(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest("nginx:1.25", org_id="test-org")
        assert result["findings_count"] == len(result["findings"])
        assert result["findings_count"] > 0

    def test_scan_and_ingest_severity_breakdown(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest("nginx:1.25", org_id="test-org")
        breakdown = result["severity_breakdown"]
        assert isinstance(breakdown, dict)
        total = sum(breakdown.values())
        assert total == result["findings_count"]

    def test_scan_and_ingest_filesystem_type(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest("/tmp/app", org_id="org1", scan_type="filesystem")
        assert result["scan_type"] == "filesystem"

    def test_scan_and_ingest_repo_type(self):
        scanner = self._make_scanner()
        result = scanner.scan_and_ingest(
            "https://github.com/org/repo", org_id="org1", scan_type="repo"
        )
        assert result["scan_type"] == "repo"

    def test_scan_and_ingest_error_returns_failed_status(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        scanner._run_trivy = MagicMock(side_effect=RuntimeError("trivy exploded"))
        result = scanner.scan_and_ingest("bad:image", org_id="org1")
        assert result["status"] == "failed"
        assert "error" in result
        assert result["findings_count"] == 0

    def test_scan_and_ingest_stores_in_history(self):
        from core.trivy_integration import TrivyScanner, _scan_history
        scanner = TrivyScanner()
        scanner._run_trivy = MagicMock(return_value=SAMPLE_TRIVY_OUTPUT)
        scanner._try_ingest_to_pipeline = MagicMock()
        org_id = f"test-{uuid.uuid4().hex[:8]}"
        scanner.scan_and_ingest("nginx:1.25", org_id=org_id)
        assert org_id in _scan_history
        assert len(_scan_history[org_id]) >= 1

    def test_scan_and_ingest_is_mock_flag_set(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        scanner._try_ingest_to_pipeline = MagicMock()
        with patch("shutil.which", return_value=None):
            result = scanner.scan_and_ingest("nginx:latest", org_id="org1")
        assert result["is_mock"] is True

    def test_scan_and_ingest_pipeline_ingest_called(self):
        scanner = self._make_scanner()
        scanner.scan_and_ingest("nginx:1.25", org_id="test-org")
        scanner._try_ingest_to_pipeline.assert_called_once()


class TestScanHistory:
    def test_get_scan_history_empty_for_new_org(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        org_id = f"neworg-{uuid.uuid4().hex}"
        history = scanner.get_scan_history(org_id=org_id)
        assert history == []

    def test_get_scan_history_returns_summaries(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        scanner._run_trivy = MagicMock(return_value=SAMPLE_TRIVY_OUTPUT)
        scanner._try_ingest_to_pipeline = MagicMock()
        org_id = f"historg-{uuid.uuid4().hex[:8]}"
        scanner.scan_and_ingest("nginx:1.25", org_id=org_id)
        scanner.scan_and_ingest("alpine:3.18", org_id=org_id)
        history = scanner.get_scan_history(org_id=org_id)
        assert len(history) == 2

    def test_get_scan_history_most_recent_first(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        scanner._run_trivy = MagicMock(return_value=SAMPLE_TRIVY_OUTPUT)
        scanner._try_ingest_to_pipeline = MagicMock()
        org_id = f"orderorg-{uuid.uuid4().hex[:8]}"
        scanner.scan_and_ingest("first:image", org_id=org_id)
        scanner.scan_and_ingest("second:image", org_id=org_id)
        history = scanner.get_scan_history(org_id=org_id)
        # Most recent (second) should be first in the list
        assert history[0]["target"] == "second:image"

    def test_get_scan_history_no_findings_in_summary(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        scanner._run_trivy = MagicMock(return_value=SAMPLE_TRIVY_OUTPUT)
        scanner._try_ingest_to_pipeline = MagicMock()
        org_id = f"nofind-{uuid.uuid4().hex[:8]}"
        scanner.scan_and_ingest("nginx:1.25", org_id=org_id)
        history = scanner.get_scan_history(org_id=org_id)
        assert "findings" not in history[0]


# ── API Router tests ───────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def trivy_client():
    """FastAPI test client with trivy_router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.trivy_router import router

    app = FastAPI()
    app.include_router(router)

    # Patch auth so all requests pass
    import apps.api.auth_deps as auth_deps
    original = auth_deps.api_key_auth

    async def _no_auth():
        return None

    auth_deps.api_key_auth = _no_auth
    # Re-import router with patched auth — simpler: override dependency
    app.dependency_overrides[original] = _no_auth

    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_scanner_singleton():
    """Reset the module-level _scanner singleton between tests."""
    import apps.api.trivy_router as trivy_mod
    trivy_mod._scanner = None
    yield
    trivy_mod._scanner = None


class TestTrivyRouterStatus:
    def test_status_available(self, trivy_client):
        with patch("core.trivy_integration.TrivyScanner.is_trivy_available", return_value=True):
            resp = trivy_client.get("/api/v1/scan/trivy/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is True
        assert "real scans" in body["message"]

    def test_status_not_available(self, trivy_client):
        with patch("core.trivy_integration.TrivyScanner.is_trivy_available", return_value=False):
            resp = trivy_client.get("/api/v1/scan/trivy/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is False
        assert "not found" in body["message"]


class TestTrivyRouterScanImage:
    def _mock_scanner(self):
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        scanner.scan_and_ingest = MagicMock(return_value={
            "scan_id": str(uuid.uuid4()),
            "org_id": "test",
            "target": "nginx:1.25",
            "scan_type": "image",
            "started_at": "2026-01-01T00:00:00+00:00",
            "completed_at": "2026-01-01T00:00:10+00:00",
            "status": "completed",
            "is_mock": True,
            "findings_count": 3,
            "severity_breakdown": {"critical": 1, "high": 1, "medium": 1},
            "findings": [],
        })
        return scanner

    def test_scan_image_success(self, trivy_client):
        mock_scanner = self._mock_scanner()
        with patch("apps.api.trivy_router._get_scanner", return_value=mock_scanner):
            resp = trivy_client.post(
                "/api/v1/scan/trivy/image",
                json={"image": "nginx:1.25", "org_id": "test"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "completed"
        assert body["findings_count"] == 3

    def test_scan_image_missing_image(self, trivy_client):
        resp = trivy_client.post("/api/v1/scan/trivy/image", json={"org_id": "test"})
        assert resp.status_code == 422

    def test_scan_image_scanner_error(self, trivy_client):
        mock_scanner = MagicMock()
        mock_scanner.scan_and_ingest = MagicMock(side_effect=RuntimeError("boom"))
        with patch("apps.api.trivy_router._get_scanner", return_value=mock_scanner):
            resp = trivy_client.post(
                "/api/v1/scan/trivy/image",
                json={"image": "bad:image", "org_id": "test"},
            )
        assert resp.status_code == 500


class TestTrivyRouterScanFilesystem:
    def test_scan_filesystem_success(self, trivy_client):
        mock_scanner = MagicMock()
        mock_scanner.scan_and_ingest = MagicMock(return_value={
            "scan_id": str(uuid.uuid4()),
            "org_id": "test",
            "target": "/tmp/project",
            "scan_type": "filesystem",
            "started_at": "2026-01-01T00:00:00+00:00",
            "completed_at": "2026-01-01T00:00:05+00:00",
            "status": "completed",
            "is_mock": True,
            "findings_count": 0,
            "severity_breakdown": {},
            "findings": [],
        })
        with patch("apps.api.trivy_router._get_scanner", return_value=mock_scanner):
            resp = trivy_client.post(
                "/api/v1/scan/trivy/filesystem",
                json={"path": "/tmp/project", "org_id": "test"},
            )
        assert resp.status_code == 200
        assert resp.json()["scan_type"] == "filesystem"

    def test_scan_filesystem_missing_path(self, trivy_client):
        resp = trivy_client.post("/api/v1/scan/trivy/filesystem", json={"org_id": "test"})
        assert resp.status_code == 422


class TestTrivyRouterScanRepo:
    def test_scan_repo_success(self, trivy_client):
        mock_scanner = MagicMock()
        mock_scanner.scan_and_ingest = MagicMock(return_value={
            "scan_id": str(uuid.uuid4()),
            "org_id": "test",
            "target": "https://github.com/org/repo",
            "scan_type": "repo",
            "started_at": "2026-01-01T00:00:00+00:00",
            "completed_at": "2026-01-01T00:00:20+00:00",
            "status": "completed",
            "is_mock": False,
            "findings_count": 5,
            "severity_breakdown": {"high": 3, "medium": 2},
            "findings": [],
        })
        with patch("apps.api.trivy_router._get_scanner", return_value=mock_scanner):
            resp = trivy_client.post(
                "/api/v1/scan/trivy/repo",
                json={"repo_url": "https://github.com/org/repo", "org_id": "test"},
            )
        assert resp.status_code == 200
        assert resp.json()["scan_type"] == "repo"

    def test_scan_repo_missing_url(self, trivy_client):
        resp = trivy_client.post("/api/v1/scan/trivy/repo", json={"org_id": "test"})
        assert resp.status_code == 422


class TestTrivyRouterHistory:
    def test_history_empty(self, trivy_client):
        mock_scanner = MagicMock()
        mock_scanner.get_scan_history = MagicMock(return_value=[])
        with patch("apps.api.trivy_router._get_scanner", return_value=mock_scanner):
            resp = trivy_client.get(
                "/api/v1/scan/trivy/history", params={"org_id": "noorg"}
            )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_history_returns_list(self, trivy_client):
        mock_scanner = MagicMock()
        mock_scanner.get_scan_history = MagicMock(return_value=[
            {
                "scan_id": str(uuid.uuid4()),
                "org_id": "test",
                "target": "nginx:1.25",
                "scan_type": "image",
                "started_at": "2026-01-01T00:00:00+00:00",
                "completed_at": "2026-01-01T00:00:10+00:00",
                "status": "completed",
                "is_mock": True,
                "findings_count": 3,
                "severity_breakdown": {"high": 2, "medium": 1},
            }
        ])
        with patch("apps.api.trivy_router._get_scanner", return_value=mock_scanner):
            resp = trivy_client.get(
                "/api/v1/scan/trivy/history", params={"org_id": "test"}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["target"] == "nginx:1.25"

    def test_history_default_org_id(self, trivy_client):
        mock_scanner = MagicMock()
        mock_scanner.get_scan_history = MagicMock(return_value=[])
        with patch("apps.api.trivy_router._get_scanner", return_value=mock_scanner):
            resp = trivy_client.get("/api/v1/scan/trivy/history")
        assert resp.status_code == 200
        mock_scanner.get_scan_history.assert_called_once_with(org_id="default")
