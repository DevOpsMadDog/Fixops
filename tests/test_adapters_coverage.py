"""Tests for core.adapters — security tool adapter data models and logic."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.adapters import (  # noqa: E402
    AdapterFinding,
    AdapterResult,
    AzureDevOpsAdapter,
    GitLabAdapter,
)


# ---------------------------------------------------------------------------
# AdapterFinding / AdapterResult data classes
# ---------------------------------------------------------------------------


class TestAdapterFinding:
    def test_defaults(self):
        f = AdapterFinding(
            tool="test",
            category="sast",
            severity="high",
            title="SQL Injection",
            description="Found SQL injection in login.py",
            rule_id="CWE-89",
        )
        assert f.tool == "test"
        assert f.severity == "high"
        assert f.confidence == 1.0
        assert f.file_path is None
        assert f.cve_id is None
        assert f.cwe_id is None
        assert isinstance(f.raw, dict)
        assert isinstance(f.detected_at, str)

    def test_to_dict(self):
        f = AdapterFinding(
            tool="snyk",
            category="sca",
            severity="critical",
            title="Prototype Pollution",
            description="lodash < 4.17.21",
            rule_id="SNYK-JS-LODASH-123",
            file_path="package.json",
            line_number=42,
            cve_id="CVE-2021-23337",
            cwe_id="CWE-1321",
            purl="pkg:npm/lodash@4.17.20",
            remediation="Upgrade lodash to >= 4.17.21",
            confidence=0.95,
        )
        d = f.to_dict()
        assert d["tool"] == "snyk"
        assert d["severity"] == "critical"
        assert d["file"] == "package.json"
        assert d["line"] == 42
        assert d["cve_id"] == "CVE-2021-23337"
        assert d["confidence"] == 0.95
        assert d["purl"] == "pkg:npm/lodash@4.17.20"
        assert "raw" in d
        assert "detected_at" in d

    def test_to_dict_keys(self):
        f = AdapterFinding(
            tool="t", category="c", severity="low",
            title="test", description="desc", rule_id="R1",
        )
        d = f.to_dict()
        expected_keys = {
            "tool", "category", "severity", "title", "description",
            "rule_id", "file", "line", "cve_id", "cwe_id", "purl",
            "resource_id", "remediation", "confidence", "raw", "detected_at",
        }
        assert set(d.keys()) == expected_keys


class TestAdapterResult:
    def test_success_result(self):
        f1 = AdapterFinding(
            tool="test", category="sast", severity="low",
            title="t1", description="d1", rule_id="R1",
        )
        r = AdapterResult(success=True, findings=[f1])
        assert r.success is True
        assert len(r.findings) == 1
        assert r.error is None

    def test_error_result(self):
        r = AdapterResult(
            success=False, findings=[], error="Connection timeout"
        )
        assert r.success is False
        assert r.error == "Connection timeout"
        assert len(r.findings) == 0

    def test_metadata(self):
        r = AdapterResult(
            success=True, findings=[], metadata={"count": 0, "project": "demo"}
        )
        assert r.metadata["count"] == 0
        assert r.metadata["project"] == "demo"


# ---------------------------------------------------------------------------
# GitLabAdapter — unit tests (no network)
# ---------------------------------------------------------------------------


class TestGitLabAdapter:
    def test_configured_with_all_fields(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        adapter = GitLabAdapter({
            "url": "https://gitlab.example.com",
            "project_id": "123",
            "token": "glpat-secret",
            "token_env": "",
        })
        assert adapter.configured is True
        assert adapter.base_url == "https://gitlab.example.com"
        assert adapter.project_id == "123"
        assert adapter.token == "glpat-secret"

    def test_not_configured_missing_token(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        adapter = GitLabAdapter({
            "url": "https://gitlab.example.com",
            "project_id": "123",
            "token_env": "",
        })
        assert adapter.configured is False

    def test_not_configured_missing_project(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        adapter = GitLabAdapter({
            "url": "https://gitlab.example.com",
            "token": "glpat-secret",
            "token_env": "",
        })
        assert adapter.configured is False

    def test_fetch_unconfigured_returns_error(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        adapter = GitLabAdapter({"token_env": ""})
        result = adapter.fetch_findings()
        assert result.success is False
        assert "not configured" in result.error

    def test_token_from_env(self, monkeypatch):
        monkeypatch.setenv("MY_GL_TOKEN", "env-token-123")
        adapter = GitLabAdapter({
            "url": "https://gitlab.example.com",
            "project_id": "456",
            "token_env": "MY_GL_TOKEN",
        })
        assert adapter.token == "env-token-123"
        assert adapter.configured is True

    def test_normalize_severity(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        adapter = GitLabAdapter({"token_env": ""})
        assert adapter._normalize_severity("critical") == "critical"
        assert adapter._normalize_severity("HIGH") == "high"
        assert adapter._normalize_severity("info") == "low"
        assert adapter._normalize_severity("unknown") == "medium"
        assert adapter._normalize_severity("garbage") == "medium"

    def test_map_scanner_to_category(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        adapter = GitLabAdapter({"token_env": ""})
        assert adapter._map_scanner_to_category("sast") == "sast"
        assert adapter._map_scanner_to_category("dependency_scanning") == "sca"
        assert adapter._map_scanner_to_category("container_scanning") == "container"
        assert adapter._map_scanner_to_category("secret_detection") == "secrets"
        assert adapter._map_scanner_to_category("DAST") == "dast"
        assert adapter._map_scanner_to_category("unknown") == "sast"

    def test_extract_cve(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        adapter = GitLabAdapter({"token_env": ""})
        ids = [
            {"type": "cwe", "value": "CWE-89"},
            {"type": "cve", "value": "CVE-2024-1234"},
        ]
        assert adapter._extract_cve(ids) == "CVE-2024-1234"
        assert adapter._extract_cve([]) is None
        assert adapter._extract_cve([{"type": "other", "value": "X"}]) is None

    def test_extract_cwe(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        adapter = GitLabAdapter({"token_env": ""})
        ids = [
            {"type": "cwe", "value": "CWE-89"},
            {"type": "cve", "value": "CVE-2024-1234"},
        ]
        assert adapter._extract_cwe(ids) == "CWE-89"
        assert adapter._extract_cwe([]) is None

    def test_trailing_slash_stripped(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        adapter = GitLabAdapter({
            "url": "https://gitlab.example.com/",
            "token_env": "",
        })
        assert adapter.base_url == "https://gitlab.example.com"

    def test_custom_timeout(self, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        adapter = GitLabAdapter({"timeout": 60.0, "token_env": ""})
        assert adapter.timeout == 60.0


# ---------------------------------------------------------------------------
# AzureDevOpsAdapter — unit tests (no network)
# ---------------------------------------------------------------------------


class TestAzureDevOpsAdapter:
    def test_configured(self, monkeypatch):
        monkeypatch.delenv("AZURE_DEVOPS_TOKEN", raising=False)
        adapter = AzureDevOpsAdapter({
            "organization": "myorg",
            "project": "myproj",
            "repository": "myrepo",
            "token": "ado-secret",
            "token_env": "",
        })
        assert adapter.configured is True

    def test_not_configured_missing_org(self, monkeypatch):
        monkeypatch.delenv("AZURE_DEVOPS_TOKEN", raising=False)
        adapter = AzureDevOpsAdapter({
            "project": "myproj",
            "token": "ado-secret",
            "token_env": "",
        })
        assert adapter.configured is False

    def test_fetch_unconfigured(self, monkeypatch):
        monkeypatch.delenv("AZURE_DEVOPS_TOKEN", raising=False)
        adapter = AzureDevOpsAdapter({"token_env": ""})
        result = adapter.fetch_findings()
        assert result.success is False
        assert "not configured" in result.error

    def test_token_from_env(self, monkeypatch):
        monkeypatch.setenv("MY_ADO_TOKEN", "env-ado-token")
        adapter = AzureDevOpsAdapter({
            "organization": "org",
            "project": "proj",
            "token_env": "MY_ADO_TOKEN",
        })
        assert adapter.token == "env-ado-token"
        assert adapter.configured is True

    def test_normalize_severity(self, monkeypatch):
        monkeypatch.delenv("AZURE_DEVOPS_TOKEN", raising=False)
        adapter = AzureDevOpsAdapter({"token_env": ""})
        assert adapter._normalize_severity("critical") == "critical"
        assert adapter._normalize_severity("note") == "low"
        assert adapter._normalize_severity("unknown") == "medium"
