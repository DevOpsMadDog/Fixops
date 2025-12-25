"""Tests for new integration adapters."""

import pytest
from unittest.mock import MagicMock, patch

from integrations.gitlab.adapter import GitLabCIAdapter
from integrations.azure_devops.adapter import AzureDevOpsAdapter
from integrations.snyk.adapter import SnykAdapter
from integrations.defectdojo.adapter import DefectDojoAdapter


@pytest.fixture
def mock_decision_engine():
    """Create mock decision engine."""
    engine = MagicMock()
    outcome = MagicMock()
    outcome.verdict = "allow"
    outcome.confidence = 0.85
    outcome.evidence.evidence_id = "test-evidence-123"
    outcome.evidence.manifest = {"url": "https://example.com/evidence"}
    outcome.compliance = {}
    outcome.top_factors = []
    outcome.marketplace_recommendations = []
    engine.evaluate.return_value = outcome
    return engine


class TestGitLabAdapter:
    """Tests for GitLab CI adapter."""

    def test_handle_merge_request_webhook(self, mock_decision_engine):
        """Test handling GitLab merge request webhook."""
        adapter = GitLabCIAdapter(mock_decision_engine)

        payload = {
            "project": {"path_with_namespace": "org/repo"},
            "object_attributes": {"iid": 42},
            "findings": [{"severity": "high", "title": "SQL Injection"}],
        }

        result = adapter.handle_webhook("merge_request", payload)

        assert result["project"] == "org/repo"
        assert result["merge_request"] == 42
        assert result["verdict"] == "allow"
        assert result["confidence"] == 0.85

    def test_extract_project_missing(self, mock_decision_engine):
        """Test error when project is missing."""
        adapter = GitLabCIAdapter(mock_decision_engine)

        with pytest.raises(ValueError, match="project details missing"):
            adapter._extract_project({})

    def test_ingest(self, mock_decision_engine):
        """Test ingest method."""
        adapter = GitLabCIAdapter(mock_decision_engine)

        payload = {
            "project": {"path": "repo"},
            "merge_request": {"iid": 1},
            "findings": [],
        }

        result = adapter.ingest(payload)
        assert "verdict" in result


class TestAzureDevOpsAdapter:
    """Tests for Azure DevOps adapter."""

    def test_handle_build_webhook(self, mock_decision_engine):
        """Test handling Azure DevOps build webhook."""
        adapter = AzureDevOpsAdapter(mock_decision_engine)

        payload = {
            "eventType": "build.complete",
            "resourceContainers": {"project": {"name": "my-project"}},
            "resource": {
                "repository": {"project": {"name": "my-project"}},
                "triggerInfo": {"pr.number": "15"},
            },
            "findings": [],
        }

        result = adapter.handle_webhook("build.complete", payload)

        assert result["project"] == "my-project"
        assert result["verdict"] == "allow"

    def test_ingest(self, mock_decision_engine):
        """Test ingest method."""
        adapter = AzureDevOpsAdapter(mock_decision_engine)

        payload = {"resource": {}, "findings": []}

        result = adapter.ingest(payload)
        assert "verdict" in result


class TestSnykAdapter:
    """Tests for Snyk adapter."""

    def test_normalize_vulnerabilities(self, mock_decision_engine):
        """Test normalizing Snyk vulnerabilities."""
        adapter = SnykAdapter(mock_decision_engine)

        payload = {
            "vulnerabilities": [
                {
                    "id": "SNYK-JS-LODASH-1234",
                    "title": "Prototype Pollution",
                    "severity": "high",
                    "packageName": "lodash",
                    "version": "4.17.10",
                    "identifiers": {"CVE": ["CVE-2019-10744"], "CWE": ["CWE-400"]},
                    "from": ["myapp", "lodash@4.17.10"],
                }
            ]
        }

        findings = list(adapter._normalize_findings(payload))

        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["cve_id"] == "CVE-2019-10744"
        assert findings[0]["package"] == "lodash"

    def test_normalize_issues_format(self, mock_decision_engine):
        """Test normalizing Snyk issues format."""
        adapter = SnykAdapter(mock_decision_engine)

        payload = {
            "issues": {
                "vulnerabilities": [
                    {"id": "SNYK-1", "title": "Vuln 1", "severity": "medium"}
                ],
                "licenses": [
                    {"id": "SNYK-L-1", "title": "License Issue", "severity": "low"}
                ],
            }
        }

        findings = list(adapter._normalize_findings(payload))
        assert len(findings) == 2

    def test_ingest(self, mock_decision_engine):
        """Test ingest method."""
        adapter = SnykAdapter(mock_decision_engine)

        payload = {"vulnerabilities": [{"id": "1", "severity": "high", "title": "Test"}]}

        result = adapter.ingest(payload)
        assert result["verdict"] == "allow"
        assert result["findings_processed"] == 1


class TestDefectDojoAdapter:
    """Tests for DefectDojo adapter."""

    def test_normalize_findings(self, mock_decision_engine):
        """Test normalizing DefectDojo findings."""
        adapter = DefectDojoAdapter(mock_decision_engine)

        payload = {
            "results": [
                {
                    "id": 123,
                    "title": "SQL Injection",
                    "description": "SQL injection vulnerability found",
                    "severity": "High",
                    "cwe": 89,
                    "file_path": "/app/login.py",
                    "line": 42,
                    "active": True,
                    "verified": True,
                }
            ]
        }

        findings = list(adapter._normalize_findings(payload))

        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["cwe_id"] == "CWE-89"
        assert findings[0]["file_path"] == "/app/login.py"
        assert findings[0]["verified"] is True

    def test_normalize_with_vulnerability_ids(self, mock_decision_engine):
        """Test normalizing with vulnerability_ids field."""
        adapter = DefectDojoAdapter(mock_decision_engine)

        payload = {
            "findings": [
                {
                    "id": 456,
                    "title": "Log4j RCE",
                    "severity": "Critical",
                    "vulnerability_ids": [
                        {"vulnerability_id": "CVE-2021-44228"},
                        {"vulnerability_id": "CWE-502"},
                    ],
                }
            ]
        }

        findings = list(adapter._normalize_findings(payload))

        assert len(findings) == 1
        assert findings[0]["cve_id"] == "CVE-2021-44228"
        assert findings[0]["cwe_id"] == "CWE-502"

    def test_ingest(self, mock_decision_engine):
        """Test ingest method."""
        adapter = DefectDojoAdapter(mock_decision_engine)

        payload = {"results": [{"id": 1, "title": "Test", "severity": "Medium"}]}

        result = adapter.ingest(payload)
        assert result["verdict"] == "allow"
        assert result["findings_processed"] == 1

    @pytest.mark.asyncio
    async def test_pull_findings_not_configured(self, mock_decision_engine):
        """Test pull when not configured."""
        adapter = DefectDojoAdapter(mock_decision_engine)

        result = await adapter.pull_findings()
        assert "error" in result

    @pytest.mark.asyncio
    async def test_push_findings_not_configured(self, mock_decision_engine):
        """Test push when not configured."""
        adapter = DefectDojoAdapter(mock_decision_engine)

        result = await adapter.push_findings([], product_id=1)
        assert "error" in result
