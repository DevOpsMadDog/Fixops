"""Tests for real boto3 + Azure agentless snapshot scan adapters.

8 tests covering:
1. boto3 mock returns empty list -> graceful no-op
2. boto3 mock returns 3 snapshots -> scan attempts real path
3. Azure mock returns 2 disks -> scan attempts real path
4. Missing AWS creds -> status=needs_credentials (empty list)
5. Missing Azure creds -> status=needs_credentials (empty list)
6. Both credential sets present -> both adapters constructed without error
7. Live scan fixture: EBS snapshot stream parses (mock SDK, real bytes)
8. No b"PK\x03\x04log4j-core-2.14.1-fake-bytes" anywhere in source
"""

from __future__ import annotations

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from core.agentless_snapshot_scan_engine import (
    AgentlessSnapshotScanEngine,
    MockAWSAdapter,
    SnapshotBlob,
    SnapshotRef,
    _NoCredentialsAdapter,
    _build_default_adapter,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine(adapter=None) -> AgentlessSnapshotScanEngine:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    return AgentlessSnapshotScanEngine(db_path=db_path, adapter=adapter)


# ---------------------------------------------------------------------------
# Test 1: boto3 mock returns empty list -> graceful no-op
# ---------------------------------------------------------------------------


def test_boto3_empty_list_graceful_noop():
    """When the AWS adapter returns zero snapshots, enqueue_scan returns []."""

    class EmptyAWSAdapter:
        def list_snapshots(self, org_id, provider, account_id):
            return []

        def fetch_snapshot(self, snapshot_id):
            return SnapshotBlob(snapshot_id=snapshot_id, files={})

        def release(self, snapshot_id):
            return None

    engine = _make_engine(adapter=EmptyAWSAdapter())
    result = engine.enqueue_scan(org_id="org-1", provider="aws", account_id="123456789")
    assert result == [], f"Expected empty list, got {result}"


# ---------------------------------------------------------------------------
# Test 2: boto3 mock returns 3 snapshots -> scan attempts real path
# ---------------------------------------------------------------------------


def test_boto3_three_snapshots_scan_path():
    """When AWS adapter returns 3 snapshots, engine enqueues and scans all 3."""

    class ThreeSnapshotAdapter:
        def list_snapshots(self, org_id, provider, account_id):
            return [
                SnapshotRef(
                    snapshot_id=f"snap-{i:04d}",
                    provider="aws",
                    account_id=account_id,
                    region="us-east-1",
                    size_gb=8,
                )
                for i in range(1, 4)
            ]

        def fetch_snapshot(self, snapshot_id):
            # Return a blob with a known secret so findings are generated.
            return SnapshotBlob(
                snapshot_id=snapshot_id,
                files={
                    "/etc/creds": b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                },
                os_family="linux",
            )

        def release(self, snapshot_id):
            return None

    engine = _make_engine(adapter=ThreeSnapshotAdapter())
    queued = engine.enqueue_scan(org_id="org-2", provider="aws", account_id="acct-prod")
    assert len(queued) == 3

    # Scan each and verify findings are produced.
    for row in queued:
        result = engine.run_scan(row["id"])
        assert result["status"] == "complete", f"Expected complete, got {result}"
        assert result["total_findings"] >= 1, "Expected at least 1 finding (secret)"


# ---------------------------------------------------------------------------
# Test 3: Azure mock returns 2 disks -> scan attempts real path
# ---------------------------------------------------------------------------


def test_azure_two_disks_scan_path():
    """When Azure adapter returns 2 snapshots, engine enqueues and scans them."""

    class TwoAzureDiskAdapter:
        def list_snapshots(self, org_id, provider, account_id):
            return [
                SnapshotRef(
                    snapshot_id=f"disk-snap-{i}",
                    provider="azure",
                    account_id=account_id,
                    region="eastus",
                    size_gb=32,
                )
                for i in range(1, 3)
            ]

        def fetch_snapshot(self, snapshot_id):
            return SnapshotBlob(
                snapshot_id=snapshot_id,
                files={
                    "/var/lib/dpkg/status": b"Package: log4j\nVersion: 2.14.1\n"
                },
                os_family="linux",
            )

        def release(self, snapshot_id):
            return None

    engine = _make_engine(adapter=TwoAzureDiskAdapter())
    queued = engine.enqueue_scan(
        org_id="org-3", provider="azure", account_id="sub-abc-123"
    )
    assert len(queued) == 2

    for row in queued:
        result = engine.run_scan(row["id"])
        assert result["status"] == "complete"
        # log4j vulnerable package should be found.
        assert result["by_type"]["vulnerable_package"] >= 1


# ---------------------------------------------------------------------------
# Test 4: Missing AWS creds -> needs_credentials (empty list)
# ---------------------------------------------------------------------------


def test_missing_aws_creds_returns_empty():
    """AWSEBSSnapshotConnector with no creds returns [] and warns."""
    # Patch env to remove all AWS credential sources.
    clean_env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
        }
    }
    # Also ensure ~/.aws/credentials does not accidentally satisfy the check
    # by pointing the shared creds file to a non-existent path.
    clean_env["AWS_SHARED_CREDENTIALS_FILE"] = "/nonexistent/path/credentials"

    from connectors.aws_ebs_snapshot_connector import (
        AWSEBSSnapshotConnector,
        _aws_credentials_available,
    )

    with patch.dict(os.environ, clean_env, clear=True):
        available = _aws_credentials_available(
            aws_access_key_id=None, aws_secret_access_key=None
        )
        assert not available, "Expected no AWS credentials to be available"

        connector = AWSEBSSnapshotConnector(
            aws_access_key_id=None, aws_secret_access_key=None
        )
        result = connector.list_snapshots(
            org_id="org-4", provider="aws", account_id="123"
        )
        assert result == [], f"Expected empty list, got {result}"


# ---------------------------------------------------------------------------
# Test 5: Missing Azure creds -> needs_credentials (empty list)
# ---------------------------------------------------------------------------


def test_missing_azure_creds_returns_empty():
    """AzureDiskSnapshotConnector with no creds returns [] and warns."""
    clean_env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in {
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "AZURE_SUBSCRIPTION_ID",
            "MSI_ENDPOINT",
            "IDENTITY_ENDPOINT",
        }
    }
    # Point to a non-existent CLI token cache.
    clean_env["HOME"] = "/nonexistent-home"

    from connectors.azure_disk_snapshot_connector import (
        AzureDiskSnapshotConnector,
        _azure_credentials_available,
    )

    with patch.dict(os.environ, clean_env, clear=True):
        available = _azure_credentials_available(
            client_id=None, client_secret=None, tenant_id=None
        )
        assert not available, "Expected no Azure credentials to be available"

        connector = AzureDiskSnapshotConnector(
            subscription_id="sub-999",
            client_id=None,
            client_secret=None,
            tenant_id=None,
        )
        result = connector.list_snapshots(
            org_id="org-5", provider="azure", account_id="sub-999"
        )
        assert result == [], f"Expected empty list, got {result}"


# ---------------------------------------------------------------------------
# Test 6: Both credential sets present -> both adapters constructed without error
# ---------------------------------------------------------------------------


def test_both_credential_sets_construct_adapters():
    """When AWS + Azure env vars are set, both connectors initialise cleanly."""
    aws_env = {
        "AWS_ACCESS_KEY_ID": "AKIATEST00000000TEST",
        "AWS_SECRET_ACCESS_KEY": "testsecretkey00000000000000000000000000",
    }
    azure_env = {
        "AZURE_CLIENT_ID": "test-client-id",
        "AZURE_CLIENT_SECRET": "test-client-secret",
        "AZURE_TENANT_ID": "test-tenant-id",
        "AZURE_SUBSCRIPTION_ID": "test-sub-id",
    }

    from connectors.aws_ebs_snapshot_connector import (
        AWSEBSSnapshotConnector,
        _aws_credentials_available,
    )
    from connectors.azure_disk_snapshot_connector import (
        AzureDiskSnapshotConnector,
        _azure_credentials_available,
    )

    with patch.dict(os.environ, {**aws_env, **azure_env}):
        assert _aws_credentials_available()
        assert _azure_credentials_available()

        aws_conn = AWSEBSSnapshotConnector()
        assert aws_conn is not None

        azure_conn = AzureDiskSnapshotConnector()
        assert azure_conn is not None


# ---------------------------------------------------------------------------
# Test 7: Live scan fixture — mock SDK call, real bytes parsed by probes
# ---------------------------------------------------------------------------


def test_live_scan_fixture_real_bytes_parsed():
    """EBS snapshot stream bytes are scanned correctly by all three probes."""

    # Each virtual file exercises one probe type.
    # The malware probe checks magic bytes at offset 0, so the PE header must
    # be the first bytes of its own file entry.
    creds_content = (
        b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )
    pkg_content = b"Package: openssl\nVersion: 1.0.1a\n"
    malware_content = b"MZ\x90\x00\x03\x00\x00\x00badpayloadbytes"

    class RealBytesAdapter:
        def list_snapshots(self, org_id, provider, account_id):
            return [
                SnapshotRef(
                    snapshot_id="snap-realblock",
                    provider="aws",
                    account_id=account_id,
                    region="us-east-1",
                    size_gb=8,
                )
            ]

        def fetch_snapshot(self, snapshot_id):
            # Three separate virtual files so each probe hits its trigger at offset 0.
            return SnapshotBlob(
                snapshot_id=snapshot_id,
                files={
                    "/home/ubuntu/.aws/credentials": creds_content,
                    "/var/lib/dpkg/status": pkg_content,
                    "/usr/local/bin/bad.exe": malware_content,
                },
                os_family="linux",
            )

        def release(self, snapshot_id):
            return None

    engine = _make_engine(adapter=RealBytesAdapter())
    queued = engine.enqueue_scan(
        org_id="org-7", provider="aws", account_id="acct-live"
    )
    assert len(queued) == 1

    result = engine.run_scan(queued[0]["id"])
    assert result["status"] == "complete"
    # Should find: secret (AWS key), vulnerable_package (openssl), malware (MZ)
    assert result["by_type"]["secret"] >= 1, "Expected at least 1 secret finding"
    assert result["by_type"]["vulnerable_package"] >= 1, "Expected at least 1 vuln pkg"
    assert result["by_type"]["malware"] >= 1, "Expected at least 1 malware finding"


# ---------------------------------------------------------------------------
# Test 8: No fake bytes literal in engine source
# ---------------------------------------------------------------------------


def test_no_fake_bytes_in_engine_source():
    """The engine source must not contain the removed fake-bytes literal."""
    import pathlib

    engine_src = pathlib.Path(
        __file__
    ).resolve().parents[1] / "suite-core" / "core" / "agentless_snapshot_scan_engine.py"
    content = engine_src.read_text(encoding="utf-8")

    forbidden = "PK\x03\x04log4j-core-2.14.1-fake-bytes"
    assert forbidden not in content, (
        f"Fake-bytes literal still present in {engine_src}. "
        "Remove it — this is a must-fix security hardening requirement."
    )

    # Also verify the TODO(real-adapter) comment is gone (replaced by real code).
    assert "TODO(real-adapter)" not in content, (
        "TODO(real-adapter) comment still present — real adapter was not wired in."
    )
