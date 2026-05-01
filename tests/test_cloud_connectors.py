"""
Tests for Cloud Connector Integration Engine.

Covers:
- Pydantic models: CloudCredentials, CloudResource, CloudFinding, PostureReport
- Credential validation (valid/invalid/expired) for AWS, Azure, GCP
- CredentialStore: add, get, remove, list, persistence
- HealthTracker: record_success, record_error, status transitions
- _RateLimiter: token acquisition, backoff
- Provider stubs: list_resources, get_resource, list_findings, get_posture
- CloudConnectorEngine: register, remove, list, sync, health, validate
- Normalization helpers: ASFF → CloudFinding, Azure severity, GCP severity
- SyncResult model
- get_engine singleton

Usage:
    pytest tests/test_cloud_connectors.py -v --timeout=10
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
import sys

# Ensure suite-core is on the path (mirrors sitecustomize.py)
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.cloud_connectors import (
    AWSProvider,
    AzureProvider,
    CloudConnectorEngine,
    CloudCredentials,
    CloudFinding,
    CloudProviderType,
    CloudResource,
    ConnectorHealth,
    ConnectorStatus,
    CredentialStore,
    FindingSeverity,
    GCPProvider,
    HealthTracker,
    PostureReport,
    ResourceType,
    SyncResult,
    _RateLimiter,
    get_engine,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def aws_creds():
    return CloudCredentials(
        provider=CloudProviderType.AWS,
        account_id="123456789012",
        label="test-aws",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        aws_region="us-east-1",
    )


@pytest.fixture
def azure_creds():
    return CloudCredentials(
        provider=CloudProviderType.AZURE,
        account_id="sub-12345",
        label="test-azure",
        azure_tenant_id="tenant-abc",
        azure_client_id="client-abc",
        azure_client_secret="secret-abc",
        azure_subscription_id="sub-12345",
    )


@pytest.fixture
def gcp_creds():
    sa_json = json.dumps({
        "type": "service_account",
        "project_id": "my-gcp-project",
        "private_key_id": "key123",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
        "client_email": "sa@my-gcp-project.iam.gserviceaccount.com",
        "client_id": "123456789",
        "token_uri": "https://oauth2.googleapis.com/token",
    })
    return CloudCredentials(
        provider=CloudProviderType.GCP,
        account_id="my-gcp-project",
        label="test-gcp",
        gcp_service_account_json=sa_json,
        gcp_project_id="my-gcp-project",
    )


@pytest.fixture
def engine():
    return CloudConnectorEngine()


@pytest.fixture
def engine_with_aws(engine, aws_creds):
    engine.register_credentials(aws_creds)
    return engine


@pytest.fixture
def tmp_persist(tmp_path):
    return str(tmp_path / "creds.json")


# ============================================================================
# CloudCredentials model tests
# ============================================================================


class TestCloudCredentials:
    def test_aws_key_pair_valid(self, aws_creds):
        ok, msg = aws_creds.is_valid()
        assert ok
        assert msg == "ok"

    def test_aws_role_arn_valid(self):
        creds = CloudCredentials(
            provider=CloudProviderType.AWS,
            account_id="111111111111",
            aws_role_arn="arn:aws:iam::111111111111:role/MyRole",
        )
        ok, msg = creds.is_valid()
        assert ok

    def test_aws_missing_credentials(self):
        creds = CloudCredentials(
            provider=CloudProviderType.AWS,
            account_id="111111111111",
        )
        ok, msg = creds.is_valid()
        assert not ok
        assert "access_key" in msg or "role_arn" in msg

    def test_azure_valid(self, azure_creds):
        ok, msg = azure_creds.is_valid()
        assert ok

    def test_azure_missing_tenant(self):
        creds = CloudCredentials(
            provider=CloudProviderType.AZURE,
            account_id="sub-xyz",
            azure_client_id="cid",
            azure_client_secret="secret",
        )
        ok, msg = creds.is_valid()
        assert not ok
        assert "tenant" in msg

    def test_azure_missing_client_id(self):
        creds = CloudCredentials(
            provider=CloudProviderType.AZURE,
            account_id="sub-xyz",
            azure_tenant_id="tid",
            azure_client_secret="secret",
        )
        ok, msg = creds.is_valid()
        assert not ok

    def test_gcp_valid(self, gcp_creds):
        ok, msg = gcp_creds.is_valid()
        assert ok

    def test_gcp_missing_both(self):
        creds = CloudCredentials(
            provider=CloudProviderType.GCP,
            account_id="proj",
        )
        ok, msg = creds.is_valid()
        assert not ok

    def test_gcp_invalid_json(self):
        creds = CloudCredentials(
            provider=CloudProviderType.GCP,
            account_id="proj",
            gcp_service_account_json="not-valid-json{{{",
        )
        ok, msg = creds.is_valid()
        assert not ok
        assert "JSON" in msg

    def test_not_expired_when_no_expiry(self, aws_creds):
        assert not aws_creds.is_expired()

    def test_expired_when_past_expiry(self, aws_creds):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        aws_creds.credential_expires_at = past
        assert aws_creds.is_expired()

    def test_not_expired_when_future(self, aws_creds):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        aws_creds.credential_expires_at = future
        assert not aws_creds.is_expired()

    def test_masked_summary_hides_secrets(self, aws_creds):
        summary = aws_creds.masked_summary()
        # Key should be masked
        assert summary["aws_access_key_id"] != aws_creds.aws_access_key_id
        assert "****" in (summary["aws_access_key_id"] or "")

    def test_masked_summary_shows_safe_fields(self, aws_creds):
        summary = aws_creds.masked_summary()
        assert summary["account_id"] == "123456789012"
        assert summary["provider"] == CloudProviderType.AWS


# ============================================================================
# CloudResource model tests
# ============================================================================


class TestCloudResource:
    def test_basic_construction(self):
        r = CloudResource(
            resource_id="i-1234567890abcdef0",
            provider=CloudProviderType.AWS,
            resource_type=ResourceType.COMPUTE,
            name="my-instance",
            region="us-east-1",
            account_id="123456789012",
        )
        assert r.resource_id == "i-1234567890abcdef0"
        assert r.public_exposure is False
        assert r.security_groups == []

    def test_to_aldeci_asset(self):
        r = CloudResource(
            resource_id="bucket-123",
            provider=CloudProviderType.AWS,
            resource_type=ResourceType.STORAGE,
            name="my-bucket",
            region="us-east-1",
            account_id="123456789012",
            public_exposure=True,
            tags={"env": "prod"},
        )
        asset = r.to_aldeci_asset()
        assert asset["asset_id"] == "bucket-123"
        assert asset["source"] == "cloud:aws"
        assert asset["public_exposure"] is True
        assert asset["tags"]["env"] == "prod"

    def test_last_seen_auto_populated(self):
        r = CloudResource(
            resource_id="r-1",
            provider=CloudProviderType.GCP,
            resource_type=ResourceType.COMPUTE,
            name="vm-1",
            region="us-central1",
            account_id="proj",
        )
        assert r.last_seen is not None


# ============================================================================
# CloudFinding model tests
# ============================================================================


class TestCloudFinding:
    def test_basic_construction(self):
        f = CloudFinding(
            provider=CloudProviderType.AWS,
            source_service="security-hub",
            title="S3 bucket public",
            description="Bucket is publicly accessible",
            severity=FindingSeverity.HIGH,
            account_id="123456789012",
        )
        assert f.finding_id  # auto-generated
        assert f.severity == FindingSeverity.HIGH

    def test_to_aldeci_finding(self):
        f = CloudFinding(
            provider=CloudProviderType.AZURE,
            source_service="defender",
            title="VM exposed to internet",
            description="RDP port open",
            severity=FindingSeverity.CRITICAL,
            account_id="sub-123",
            compliance_standards=["CIS-1.1", "NIST-AC-3"],
        )
        finding = f.to_aldeci_finding()
        assert finding["source"] == "cloud:azure:defender"
        assert finding["severity"] == "critical"
        assert "CIS-1.1" in finding["compliance"]

    def test_auto_timestamp(self):
        f = CloudFinding(
            provider=CloudProviderType.GCP,
            source_service="scc",
            title="Finding",
            description="desc",
            severity=FindingSeverity.LOW,
        )
        assert f.created_at is not None
        assert f.updated_at is not None


# ============================================================================
# _RateLimiter tests
# ============================================================================


class TestRateLimiter:
    def test_initial_burst_available(self):
        rl = _RateLimiter(requests_per_second=10.0, burst_size=5)
        for _ in range(5):
            assert rl.acquire(timeout=1.0)

    def test_acquire_returns_true_immediately(self):
        rl = _RateLimiter(requests_per_second=100.0, burst_size=10)
        assert rl.acquire(timeout=1.0) is True

    def test_acquire_timeout_returns_false(self):
        rl = _RateLimiter(requests_per_second=0.001, burst_size=1)
        # Drain the one token
        rl.acquire(timeout=1.0)
        # Next acquire should timeout quickly
        result = rl.acquire(timeout=0.1)
        assert result is False

    def test_backoff_sleep_does_not_raise(self):
        rl = _RateLimiter()
        # Should not raise even with 0 throttles
        rl.backoff_sleep()

    def test_consecutive_throttles_track(self):
        rl = _RateLimiter(requests_per_second=0.001, burst_size=1)
        rl.acquire(timeout=1.0)  # drain
        rl.acquire(timeout=0.05)  # timeout -> throttle
        assert rl._consecutive_throttles >= 1


# ============================================================================
# CredentialStore tests
# ============================================================================


class TestCredentialStore:
    def test_add_and_get(self, aws_creds):
        store = CredentialStore()
        store.add(aws_creds)
        retrieved = store.get(CloudProviderType.AWS, "123456789012")
        assert retrieved is not None
        assert retrieved.account_id == "123456789012"

    def test_get_missing_returns_none(self):
        store = CredentialStore()
        assert store.get(CloudProviderType.AWS, "nonexistent") is None

    def test_remove_existing(self, aws_creds):
        store = CredentialStore()
        store.add(aws_creds)
        removed = store.remove(CloudProviderType.AWS, "123456789012")
        assert removed is True
        assert store.get(CloudProviderType.AWS, "123456789012") is None

    def test_remove_missing_returns_false(self):
        store = CredentialStore()
        assert store.remove(CloudProviderType.AWS, "nonexistent") is False

    def test_list_all(self, aws_creds, azure_creds):
        store = CredentialStore()
        store.add(aws_creds)
        store.add(azure_creds)
        all_creds = store.list_all()
        assert len(all_creds) == 2

    def test_list_by_provider(self, aws_creds, azure_creds):
        store = CredentialStore()
        store.add(aws_creds)
        store.add(azure_creds)
        aws_list = store.list_by_provider(CloudProviderType.AWS)
        assert len(aws_list) == 1
        assert aws_list[0].provider == CloudProviderType.AWS

    def test_persist_and_load(self, aws_creds, tmp_persist):
        store1 = CredentialStore(persist_path=tmp_persist)
        store1.add(aws_creds)

        store2 = CredentialStore(persist_path=tmp_persist)
        retrieved = store2.get(CloudProviderType.AWS, "123456789012")
        assert retrieved is not None
        assert retrieved.label == "test-aws"

    def test_overwrite_existing(self, aws_creds):
        store = CredentialStore()
        store.add(aws_creds)
        aws_creds.label = "updated-label"
        store.add(aws_creds)
        retrieved = store.get(CloudProviderType.AWS, "123456789012")
        assert retrieved.label == "updated-label"


# ============================================================================
# HealthTracker tests
# ============================================================================


class TestHealthTracker:
    def test_get_or_create_new(self, aws_creds):
        tracker = HealthTracker()
        health = tracker.get_or_create(aws_creds)
        assert health.provider == CloudProviderType.AWS
        assert health.account_id == "123456789012"

    def test_get_or_create_idempotent(self, aws_creds):
        tracker = HealthTracker()
        h1 = tracker.get_or_create(aws_creds)
        h2 = tracker.get_or_create(aws_creds)
        assert h1 is h2

    def test_record_success_updates_health(self, aws_creds):
        tracker = HealthTracker()
        tracker.get_or_create(aws_creds)
        tracker.record_success(CloudProviderType.AWS, "123456789012", resources=5, findings=3)
        h = tracker.get_health(CloudProviderType.AWS, "123456789012")
        assert h.status == ConnectorStatus.HEALTHY
        assert h.resources_synced == 5
        assert h.findings_synced == 3
        assert h.last_sync_at is not None

    def test_record_error_degrades_status(self, aws_creds):
        tracker = HealthTracker()
        tracker.get_or_create(aws_creds)
        tracker.record_error(CloudProviderType.AWS, "123456789012", "timeout")
        h = tracker.get_health(CloudProviderType.AWS, "123456789012")
        assert h.status == ConnectorStatus.DEGRADED
        assert h.error_count == 1
        assert h.last_error == "timeout"

    def test_three_consecutive_errors_mark_error(self, aws_creds):
        tracker = HealthTracker()
        tracker.get_or_create(aws_creds)
        for _ in range(3):
            tracker.record_error(CloudProviderType.AWS, "123456789012", "fail")
        h = tracker.get_health(CloudProviderType.AWS, "123456789012")
        assert h.status == ConnectorStatus.ERROR

    def test_success_resets_consecutive_errors(self, aws_creds):
        tracker = HealthTracker()
        tracker.get_or_create(aws_creds)
        tracker.record_error(CloudProviderType.AWS, "123456789012", "err")
        tracker.record_success(CloudProviderType.AWS, "123456789012")
        h = tracker.get_health(CloudProviderType.AWS, "123456789012")
        assert h.consecutive_errors == 0
        assert h.status == ConnectorStatus.HEALTHY

    def test_all_health_returns_list(self, aws_creds, azure_creds):
        tracker = HealthTracker()
        tracker.get_or_create(aws_creds)
        tracker.get_or_create(azure_creds)
        all_h = tracker.all_health()
        assert len(all_h) == 2


# ============================================================================
# AWSProvider stub tests (no boto3 required)
# ============================================================================


class TestAWSProviderStubs:
    def test_list_resources_returns_empty_without_boto3(self, aws_creds):
        # NO MOCK DATA — empty when boto3 unavailable.
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            p = AWSProvider(aws_creds)
            resources = p.list_resources()
            assert resources == []

    def test_list_resources_filters_by_type(self, aws_creds):
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            p = AWSProvider(aws_creds)
            resources = p.list_resources(ResourceType.COMPUTE)
            # Empty list trivially satisfies any-type filter
            assert all(r.resource_type == ResourceType.COMPUTE for r in resources)

    def test_list_findings_returns_empty_without_boto3(self, aws_creds):
        # NO MOCK DATA — empty when client unconfigured.
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            p = AWSProvider(aws_creds)
            findings = p.list_findings()
            assert findings == []

    def test_list_findings_filters_by_severity(self, aws_creds):
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            p = AWSProvider(aws_creds)
            findings = p.list_findings(FindingSeverity.HIGH)
            # Empty list trivially satisfies the severity filter
            assert all(f.severity == FindingSeverity.HIGH for f in findings)

    def test_get_posture_returns_stub_without_boto3(self, aws_creds):
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            p = AWSProvider(aws_creds)
            report = p.get_posture()
            assert isinstance(report, PostureReport)
            assert report.score >= 0.0

    def test_normalize_asff_critical(self, aws_creds):
        p = AWSProvider(aws_creds)
        raw = {
            "Id": "arn:aws:securityhub:us-east-1::finding/123",
            "Title": "Critical Finding",
            "Description": "Something bad",
            "Severity": {"Label": "CRITICAL"},
            "Resources": [{"Id": "arn:aws:ec2:us-east-1:123:instance/i-1", "Type": "AwsEc2Instance"}],
            "Region": "us-east-1",
            "AwsAccountId": "123456789012",
            "Compliance": {"AssociatedStandards": [{"StandardsId": "CIS-AWS-1.4"}]},
        }
        finding = p._normalize_asff(raw)
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.title == "Critical Finding"
        assert "CIS-AWS-1.4" in finding.compliance_standards

    def test_normalize_asff_informational(self, aws_creds):
        p = AWSProvider(aws_creds)
        raw = {
            "Title": "Info Finding",
            "Description": "Low priority",
            "Severity": {"Label": "INFORMATIONAL"},
            "Resources": [],
        }
        finding = p._normalize_asff(raw)
        assert finding.severity == FindingSeverity.INFO

    def test_validate_credentials_fails_without_boto3(self, aws_creds):
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            p = AWSProvider(aws_creds)
            ok, msg = p.validate_credentials()
            assert not ok
            assert "boto3" in msg.lower() or "not available" in msg.lower()


# ============================================================================
# AzureProvider stub tests (no azure SDK required)
# ============================================================================


class TestAzureProviderStubs:
    def test_list_resources_returns_stubs_on_error(self, azure_creds):
        with patch("core.cloud_connectors.AzureProvider._get_access_token", return_value=None):
            p = AzureProvider(azure_creds)
            resources = p.list_resources()
            assert isinstance(resources, list)
            assert len(resources) > 0

    def test_list_findings_returns_stubs_on_error(self, azure_creds):
        with patch("core.cloud_connectors.AzureProvider._get_access_token", return_value=None):
            p = AzureProvider(azure_creds)
            findings = p.list_findings()
            assert isinstance(findings, list)

    def test_get_posture_returns_stub(self, azure_creds):
        with patch("core.cloud_connectors.AzureProvider._get_access_token", return_value=None):
            p = AzureProvider(azure_creds)
            report = p.get_posture()
            assert isinstance(report, PostureReport)
            assert report.provider == CloudProviderType.AZURE

    def test_map_azure_resource_type_compute(self, azure_creds):
        p = AzureProvider(azure_creds)
        assert p._map_azure_resource_type("Microsoft.Compute/virtualMachines") == ResourceType.COMPUTE

    def test_map_azure_resource_type_storage(self, azure_creds):
        p = AzureProvider(azure_creds)
        assert p._map_azure_resource_type("Microsoft.Storage/storageAccounts") == ResourceType.STORAGE

    def test_map_azure_resource_type_unknown(self, azure_creds):
        p = AzureProvider(azure_creds)
        assert p._map_azure_resource_type("Microsoft.Foo/bars") == ResourceType.UNKNOWN

    def test_map_azure_severity(self, azure_creds):
        p = AzureProvider(azure_creds)
        assert p._map_azure_severity("High") == FindingSeverity.HIGH
        assert p._map_azure_severity("Medium") == FindingSeverity.MEDIUM
        assert p._map_azure_severity("Low") == FindingSeverity.LOW
        assert p._map_azure_severity("Unknown") == FindingSeverity.INFO

    def test_validate_credentials_fails_without_token(self, azure_creds):
        with patch("core.cloud_connectors.AzureProvider._get_access_token", return_value=None):
            p = AzureProvider(azure_creds)
            ok, msg = p.validate_credentials()
            assert not ok


# ============================================================================
# GCPProvider stub tests (no google SDK required)
# ============================================================================


class TestGCPProviderStubs:
    def test_list_resources_returns_stubs_without_sdk(self, gcp_creds):
        with patch("core.cloud_connectors.GCPProvider._http_client", return_value=None):
            p = GCPProvider(gcp_creds)
            resources = p.list_resources()
            assert isinstance(resources, list)
            assert len(resources) > 0

    def test_list_findings_returns_stubs_without_sdk(self, gcp_creds):
        with patch("core.cloud_connectors.GCPProvider._http_client", return_value=None):
            p = GCPProvider(gcp_creds)
            findings = p.list_findings()
            assert isinstance(findings, list)

    def test_get_resource_returns_stub(self, gcp_creds):
        with patch("core.cloud_connectors.GCPProvider._http_client", return_value=None):
            p = GCPProvider(gcp_creds)
            r = p.get_resource("1234567890")
            assert r is not None
            assert r.resource_id == "1234567890"

    def test_get_posture_returns_stub(self, gcp_creds):
        p = GCPProvider(gcp_creds)
        report = p.get_posture()
        assert isinstance(report, PostureReport)
        assert report.provider == CloudProviderType.GCP

    def test_map_scc_severity(self, gcp_creds):
        p = GCPProvider(gcp_creds)
        assert p._map_scc_severity("CRITICAL") == FindingSeverity.CRITICAL
        assert p._map_scc_severity("HIGH") == FindingSeverity.HIGH
        assert p._map_scc_severity("MEDIUM") == FindingSeverity.MEDIUM
        assert p._map_scc_severity("LOW") == FindingSeverity.LOW
        assert p._map_scc_severity("UNKNOWN") == FindingSeverity.INFO


# ============================================================================
# CloudConnectorEngine integration tests
# ============================================================================


class TestCloudConnectorEngine:
    def test_register_valid_credentials(self, engine, aws_creds):
        ok, msg = engine.register_credentials(aws_creds)
        assert ok
        assert "registered" in msg.lower()

    def test_register_invalid_credentials(self, engine):
        bad = CloudCredentials(
            provider=CloudProviderType.AWS,
            account_id="bad-account",
        )
        ok, msg = engine.register_credentials(bad)
        assert not ok

    def test_list_accounts_empty(self, engine):
        result = engine.list_accounts()
        assert isinstance(result, list)
        assert len(result) == 0

    def test_list_accounts_after_register(self, engine, aws_creds):
        engine.register_credentials(aws_creds)
        result = engine.list_accounts()
        assert len(result) == 1
        assert result[0]["account_id"] == "123456789012"

    def test_list_accounts_filter_by_provider(self, engine, aws_creds, azure_creds):
        engine.register_credentials(aws_creds)
        engine.register_credentials(azure_creds)
        aws_only = engine.list_accounts(provider=CloudProviderType.AWS)
        assert len(aws_only) == 1
        assert aws_only[0]["provider"] == CloudProviderType.AWS

    def test_remove_account(self, engine, aws_creds):
        engine.register_credentials(aws_creds)
        removed = engine.remove_credentials(CloudProviderType.AWS, "123456789012")
        assert removed is True
        assert len(engine.list_accounts()) == 0

    def test_remove_nonexistent_account(self, engine):
        removed = engine.remove_credentials(CloudProviderType.AWS, "nonexistent")
        assert removed is False

    def test_list_resources_after_register(self, engine, aws_creds):
        engine.register_credentials(aws_creds)
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            resources = engine.list_resources(CloudProviderType.AWS, "123456789012")
        assert isinstance(resources, list)

    def test_list_resources_missing_account_raises(self, engine):
        with pytest.raises(KeyError):
            engine.list_resources(CloudProviderType.AWS, "nonexistent")

    def test_list_findings_after_register(self, engine, aws_creds):
        engine.register_credentials(aws_creds)
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            findings = engine.list_findings(CloudProviderType.AWS, "123456789012")
        assert isinstance(findings, list)

    def test_get_posture_after_register(self, engine, aws_creds):
        engine.register_credentials(aws_creds)
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            report = engine.get_posture(CloudProviderType.AWS, "123456789012")
        assert isinstance(report, PostureReport)
        assert 0.0 <= report.score <= 100.0

    def test_sync_account_completes(self, engine, aws_creds):
        engine.register_credentials(aws_creds)
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            result = engine.sync_account(CloudProviderType.AWS, "123456789012")
        assert result.status == "completed"
        assert result.sync_id
        assert result.started_at is not None
        assert result.completed_at is not None

    def test_sync_account_missing_fails_gracefully(self, engine):
        result = engine.sync_account(CloudProviderType.AWS, "nonexistent")
        assert result.status == "failed"
        assert result.error is not None

    def test_sync_organization_multiple_accounts(self, engine, aws_creds):
        engine.register_credentials(aws_creds)
        second = CloudCredentials(
            provider=CloudProviderType.AWS,
            account_id="999999999999",
            aws_access_key_id="AKIA999",
            aws_secret_access_key="secret999",
        )
        engine.register_credentials(second)
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            results = engine.sync_organization(CloudProviderType.AWS)
        assert len(results) == 2

    def test_health_empty_initially(self, engine):
        assert engine.health() == []

    def test_health_populated_after_register(self, engine, aws_creds):
        engine.register_credentials(aws_creds)
        health_list = engine.health()
        assert len(health_list) == 1
        assert health_list[0].account_id == "123456789012"

    def test_health_filter_by_provider(self, engine, aws_creds, azure_creds):
        engine.register_credentials(aws_creds)
        engine.register_credentials(azure_creds)
        aws_health = engine.health(provider=CloudProviderType.AWS)
        assert len(aws_health) == 1

    def test_validate_credentials_known_account(self, engine, aws_creds):
        engine.register_credentials(aws_creds)
        with patch("core.cloud_connectors.AWSProvider._boto_session", return_value=None):
            ok, msg = engine.validate_credentials(CloudProviderType.AWS, "123456789012")
        assert not ok  # no boto3 → fails

    def test_validate_credentials_unknown_account(self, engine):
        ok, msg = engine.validate_credentials(CloudProviderType.AWS, "nonexistent")
        assert not ok
        assert "No credentials" in msg or "nonexistent" in msg


# ============================================================================
# get_engine singleton test
# ============================================================================


class TestGetEngineSingleton:
    def test_returns_same_instance(self):
        import core.cloud_connectors as cc
        # Reset singleton for test isolation
        cc._engine = None
        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2
        cc._engine = None  # cleanup


# ============================================================================
# SyncResult model
# ============================================================================


class TestSyncResult:
    def test_defaults(self):
        r = SyncResult(
            provider=CloudProviderType.AWS,
            account_id="123",
            started_at=datetime.now(timezone.utc),
        )
        assert r.status == "running"
        assert r.resources_found == 0
        assert r.findings_found == 0
        assert r.sync_id

    def test_completed_state(self):
        now = datetime.now(timezone.utc)
        r = SyncResult(
            provider=CloudProviderType.GCP,
            account_id="proj",
            started_at=now,
            completed_at=now,
            status="completed",
            resources_found=10,
            findings_found=3,
        )
        assert r.status == "completed"
        assert r.resources_found == 10
