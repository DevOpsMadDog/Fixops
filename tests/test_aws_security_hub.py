"""
Tests for AWS Security Hub integration — AWSSecurityHubClient and aws_security_hub_router.

All boto3 calls are mocked so no AWS credentials are required.
Covers: is_configured, get_findings, get_insights, get_standards_status,
        import_findings, normalize_asff, inline fallback, history,
        and all 6 API router endpoints.
"""

from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# ── Environment setup ──────────────────────────────────────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-for-jwt-validation-32chars")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")


# ── Sample ASFF finding data ───────────────────────────────────────────────

SAMPLE_ASFF_FINDING: Dict[str, Any] = {
    "SchemaVersion": "2018-10-08",
    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/test-001",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "ProductName": "Security Hub",
    "CompanyName": "AWS",
    "Region": "us-east-1",
    "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/IAM.1",
    "AwsAccountId": "123456789012",
    "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
    "FirstObservedAt": "2026-01-01T00:00:00.000Z",
    "LastObservedAt": "2026-01-10T00:00:00.000Z",
    "CreatedAt": "2026-01-01T00:00:00.000Z",
    "UpdatedAt": "2026-01-10T00:00:00.000Z",
    "Severity": {"Label": "HIGH", "Normalized": 70},
    "Title": "IAM root user access key should not exist",
    "Description": "Root user credentials are highly privileged.",
    "Remediation": {
        "Recommendation": {
            "Text": "Delete root user access keys.",
            "Url": "https://docs.aws.amazon.com/console/securityhub/IAM.1/remediation",
        }
    },
    "Resources": [
        {
            "Type": "AwsAccount",
            "Id": "AWS::::Account:123456789012",
            "Partition": "aws",
            "Region": "us-east-1",
        }
    ],
    "Compliance": {"Status": "FAILED"},
    "WorkflowState": "NEW",
    "Workflow": {"Status": "NEW"},
    "RecordState": "ACTIVE",
}

SAMPLE_CRITICAL_FINDING: Dict[str, Any] = {
    "SchemaVersion": "2018-10-08",
    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/test-002",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "ProductName": "Security Hub",
    "CompanyName": "AWS",
    "Region": "us-east-1",
    "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.1",
    "AwsAccountId": "123456789012",
    "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
    "FirstObservedAt": "2026-01-03T00:00:00.000Z",
    "LastObservedAt": "2026-01-10T00:00:00.000Z",
    "CreatedAt": "2026-01-03T00:00:00.000Z",
    "UpdatedAt": "2026-01-10T00:00:00.000Z",
    "Severity": {"Label": "CRITICAL", "Normalized": 90},
    "Title": "S3 Block Public Access setting should be enabled",
    "Description": "S3 bucket is publicly accessible.",
    "Remediation": {
        "Recommendation": {
            "Text": "Enable S3 Block Public Access.",
            "Url": "https://docs.aws.amazon.com/console/securityhub/S3.1/remediation",
        }
    },
    "Resources": [
        {
            "Type": "AwsS3Bucket",
            "Id": "arn:aws:s3:::my-public-bucket",
            "Partition": "aws",
            "Region": "us-east-1",
        }
    ],
    "Compliance": {"Status": "FAILED"},
    "WorkflowState": "NEW",
    "Workflow": {"Status": "NEW"},
    "RecordState": "ACTIVE",
}

SAMPLE_FINDINGS = [SAMPLE_ASFF_FINDING, SAMPLE_CRITICAL_FINDING]


# ── AWSSecurityHubClient unit tests ────────────────────────────────────────


class TestAWSSecurityHubClientConfiguration:
    def test_is_configured_with_credentials(self):
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient(
            region="us-east-1",
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        assert client.is_configured() is True

    def test_is_configured_without_credentials(self):
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient(region="us-east-1", access_key="", secret_key="")
        assert client.is_configured() is False

    def test_reads_credentials_from_env(self, monkeypatch):
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAENV123")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secretenv123")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient()
        assert client.is_configured() is True
        assert client._access_key == "AKIAENV123"
        assert client._secret_key == "secretenv123"
        assert client._region == "eu-west-1"

    def test_defaults_to_us_east_1_region(self, monkeypatch):
        monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
        monkeypatch.delenv("AWS_REGION", raising=False)
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient(access_key="", secret_key="")
        assert client._region == "us-east-1"

    def test_strips_whitespace_from_credentials(self):
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient(
            access_key="  AKIA123  ",
            secret_key="  secret456  ",
        )
        assert client._access_key == "AKIA123"
        assert client._secret_key == "secret456"

    def test_missing_secret_key_means_unconfigured(self):
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient(access_key="AKIA123", secret_key="")
        assert client.is_configured() is False

    def test_missing_access_key_means_unconfigured(self):
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient(access_key="", secret_key="secret")
        assert client.is_configured() is False


class TestAWSSecurityHubClientMockFallback:
    """Mock data returned when no credentials are configured."""

    def _unconfigured(self):
        from core.aws_security_hub import AWSSecurityHubClient
        return AWSSecurityHubClient(access_key="", secret_key="")

    def test_get_findings_returns_mock_when_unconfigured(self):
        client = self._unconfigured()
        findings = client.get_findings()
        assert isinstance(findings, list)
        assert len(findings) > 0
        assert "Id" in findings[0]
        assert "Severity" in findings[0]

    def test_get_findings_mock_has_asff_schema_version(self):
        client = self._unconfigured()
        findings = client.get_findings()
        assert findings[0]["SchemaVersion"] == "2018-10-08"

    def test_get_findings_accepts_none_filters(self):
        client = self._unconfigured()
        findings = client.get_findings(filters=None)
        assert isinstance(findings, list)

    def test_get_findings_accepts_dict_filters(self):
        client = self._unconfigured()
        findings = client.get_findings(filters={"SeverityLabel": [{"Value": "HIGH"}]})
        assert isinstance(findings, list)

    def test_get_insights_returns_mock_when_unconfigured(self):
        client = self._unconfigured()
        insights = client.get_insights()
        assert isinstance(insights, list)
        assert len(insights) > 0
        assert "InsightArn" in insights[0]
        assert "Name" in insights[0]

    def test_get_standards_status_returns_mock_when_unconfigured(self):
        client = self._unconfigured()
        status = client.get_standards_status()
        assert isinstance(status, dict)
        assert "standards" in status
        assert status.get("is_mock") is True
        assert len(status["standards"]) > 0

    def test_get_standards_status_has_cis_and_pci(self):
        client = self._unconfigured()
        status = client.get_standards_status()
        names = [s["Name"] for s in status["standards"]]
        assert any("CIS" in n for n in names)
        assert any("PCI" in n for n in names)

    def test_import_findings_returns_entry_dict(self):
        client = self._unconfigured()
        client._try_ingest_to_pipeline = MagicMock()
        result = client.import_findings(org_id="test-org")
        assert isinstance(result, dict)
        assert result["status"] == "completed"
        assert result["is_mock"] is True
        assert result["findings_count"] > 0
        assert "import_id" in result
        assert "severity_breakdown" in result

    def test_import_findings_populates_findings_list(self):
        client = self._unconfigured()
        client._try_ingest_to_pipeline = MagicMock()
        result = client.import_findings(org_id="test-org")
        assert len(result["findings"]) == result["findings_count"]

    def test_import_findings_severity_breakdown_sums_to_findings_count(self):
        client = self._unconfigured()
        client._try_ingest_to_pipeline = MagicMock()
        result = client.import_findings(org_id="test-org")
        total = sum(result["severity_breakdown"].values())
        assert total == result["findings_count"]


class TestNormalizeASSF:
    """Tests for ASFF → UnifiedFinding normalization."""

    def _unconfigured(self):
        from core.aws_security_hub import AWSSecurityHubClient
        return AWSSecurityHubClient(access_key="", secret_key="")

    def test_normalize_asff_returns_list(self):
        client = self._unconfigured()
        result = client.normalize_asff(SAMPLE_FINDINGS)
        assert isinstance(result, list)
        assert len(result) == 2

    def test_normalize_asff_empty_input(self):
        client = self._unconfigured()
        result = client.normalize_asff([])
        assert result == []

    def test_normalize_asff_maps_high_severity(self):
        client = self._unconfigured()
        result = client.normalize_asff([SAMPLE_ASFF_FINDING])
        assert result[0]["severity"] == "high"

    def test_normalize_asff_maps_critical_severity(self):
        client = self._unconfigured()
        result = client.normalize_asff([SAMPLE_CRITICAL_FINDING])
        assert result[0]["severity"] == "critical"

    def test_normalize_asff_sets_source_tool(self):
        client = self._unconfigured()
        result = client.normalize_asff([SAMPLE_ASFF_FINDING])
        assert result[0]["source_tool"] == "aws_security_hub"

    def test_normalize_asff_preserves_title(self):
        client = self._unconfigured()
        result = client.normalize_asff([SAMPLE_ASFF_FINDING])
        assert "IAM root user" in result[0]["title"]

    def test_normalize_asff_includes_aws_account_id(self):
        client = self._unconfigured()
        result = client.normalize_asff([SAMPLE_ASFF_FINDING])
        assert result[0]["aws_account_id"] == "123456789012"

    def test_normalize_asff_includes_region(self):
        client = self._unconfigured()
        result = client.normalize_asff([SAMPLE_ASFF_FINDING])
        assert result[0]["aws_region"] == "us-east-1"

    def test_normalize_asff_includes_resource_type(self):
        client = self._unconfigured()
        result = client.normalize_asff([SAMPLE_ASFF_FINDING])
        assert result[0]["resource_type"] == "AwsAccount"

    def test_normalize_asff_includes_compliance_status(self):
        client = self._unconfigured()
        result = client.normalize_asff([SAMPLE_ASFF_FINDING])
        assert result[0]["compliance_status"] == "FAILED"

    def test_normalize_asff_maps_informational_to_info(self):
        client = self._unconfigured()
        info_finding = dict(SAMPLE_ASFF_FINDING)
        info_finding["Severity"] = {"Label": "INFORMATIONAL", "Normalized": 0}
        result = client.normalize_asff([info_finding])
        assert result[0]["severity"] == "info"

    def test_normalize_asff_each_finding_has_unique_id(self):
        client = self._unconfigured()
        result = client.normalize_asff(SAMPLE_FINDINGS)
        ids = [f["id"] for f in result]
        assert len(set(ids)) == len(ids)


class TestImportHistory:
    """Tests for import history tracking."""

    def test_import_history_empty_for_new_org(self):
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient(access_key="", secret_key="")
        history = client.get_import_history(org_id="brand-new-org-" + str(uuid.uuid4()))
        assert history == []

    def test_import_history_recorded_after_import(self):
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient(access_key="", secret_key="")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = "history-test-org-" + str(uuid.uuid4())
        client.import_findings(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert len(history) == 1
        assert history[0]["org_id"] == org_id

    def test_import_history_excludes_findings(self):
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient(access_key="", secret_key="")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = "no-findings-in-history-" + str(uuid.uuid4())
        client.import_findings(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert "findings" not in history[0]

    def test_import_history_most_recent_first(self):
        from core.aws_security_hub import AWSSecurityHubClient
        client = AWSSecurityHubClient(access_key="", secret_key="")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = "order-test-org-" + str(uuid.uuid4())
        client.import_findings(org_id=org_id)
        client.import_findings(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert len(history) == 2
        # Most recent first — completed_at of first entry >= second
        assert history[0]["completed_at"] >= history[1]["completed_at"]


# ── Router / API endpoint tests ────────────────────────────────────────────


@pytest.fixture
def test_client():
    """FastAPI TestClient with aws_security_hub_router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()

    # Bypass auth for tests
    from apps.api.aws_security_hub_router import router
    from apps.api.auth_deps import api_key_auth
    app.dependency_overrides[api_key_auth] = lambda: None

    app.include_router(router)
    # Reset the singleton client so each test gets a fresh one
    import apps.api.aws_security_hub_router as hub_router_mod
    hub_router_mod._client = None

    return TestClient(app)


class TestAWSSecurityHubRouterStatus:
    def test_status_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/status")
        assert resp.status_code == 200

    def test_status_unconfigured_has_configured_false(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/status")
        data = resp.json()
        assert data["configured"] is False

    def test_status_includes_region(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/status")
        data = resp.json()
        assert "region" in data
        assert data["region"] == "us-east-1"

    def test_status_message_mentions_mock_mode(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/status")
        data = resp.json()
        assert "mock" in data["message"].lower()


class TestAWSSecurityHubRouterFindings:
    def test_get_findings_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/findings")
        assert resp.status_code == 200

    def test_get_findings_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/findings")
        assert isinstance(resp.json(), list)
        assert len(resp.json()) > 0

    def test_get_findings_with_severity_filter(self, test_client):
        resp = test_client.get(
            "/api/v1/scan/aws-security-hub/findings", params={"severity": "HIGH"}
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_findings_with_workflow_status_filter(self, test_client):
        resp = test_client.get(
            "/api/v1/scan/aws-security-hub/findings",
            params={"workflow_status": "NEW"},
        )
        assert resp.status_code == 200

    def test_get_findings_mock_has_schema_version(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/findings")
        findings = resp.json()
        assert findings[0]["SchemaVersion"] == "2018-10-08"


class TestAWSSecurityHubRouterInsights:
    def test_get_insights_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/insights")
        assert resp.status_code == 200

    def test_get_insights_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/insights")
        assert isinstance(resp.json(), list)
        assert len(resp.json()) > 0

    def test_get_insights_has_insight_arn(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/insights")
        assert "InsightArn" in resp.json()[0]


class TestAWSSecurityHubRouterStandards:
    def test_get_standards_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/standards")
        assert resp.status_code == 200

    def test_get_standards_has_standards_key(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/standards")
        data = resp.json()
        assert "standards" in data

    def test_get_standards_has_is_mock_flag(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/standards")
        data = resp.json()
        assert data.get("is_mock") is True


class TestAWSSecurityHubRouterImport:
    def test_import_returns_200(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/aws-security-hub/import", json={"org_id": "test-org"}
        )
        assert resp.status_code == 200

    def test_import_returns_completed_status(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/aws-security-hub/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert data["status"] == "completed"

    def test_import_is_mock_true_when_unconfigured(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/aws-security-hub/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert data["is_mock"] is True

    def test_import_has_findings_count(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/aws-security-hub/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert data["findings_count"] > 0

    def test_import_has_severity_breakdown(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/aws-security-hub/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert "severity_breakdown" in data
        assert isinstance(data["severity_breakdown"], dict)

    def test_import_default_org_id(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/aws-security-hub/import", json={}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == "default"


class TestAWSSecurityHubRouterHistory:
    def test_history_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/history")
        assert resp.status_code == 200

    def test_history_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/aws-security-hub/history")
        assert isinstance(resp.json(), list)

    def test_history_populated_after_import(self, test_client):
        org_id = "router-history-" + str(uuid.uuid4())
        test_client.post(
            "/api/v1/scan/aws-security-hub/import", json={"org_id": org_id}
        )
        resp = test_client.get(
            "/api/v1/scan/aws-security-hub/history", params={"org_id": org_id}
        )
        data = resp.json()
        assert len(data) >= 1
        assert data[0]["org_id"] == org_id

    def test_history_entries_have_no_findings_key(self, test_client):
        org_id = "no-findings-router-" + str(uuid.uuid4())
        test_client.post(
            "/api/v1/scan/aws-security-hub/import", json={"org_id": org_id}
        )
        resp = test_client.get(
            "/api/v1/scan/aws-security-hub/history", params={"org_id": org_id}
        )
        for entry in resp.json():
            assert "findings" not in entry
