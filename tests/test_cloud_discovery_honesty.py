"""Tests for the cloud_discovery honesty-floor fix.

Verifies that:
1. discover_aws / discover_azure / discover_gcp raise
   CloudDiscoveryNotConfiguredError (not return fabricated assets) when no
   real credentials are present.
2. No synthetic / mock asset identifiers appear in the raised exception or
   any returned asset list.
3. The test-only FIXOPS_CLOUD_DISCOVERY_TEST_MOCK=1 escape hatch still works
   (so existing test infrastructure is not broken).
4. discover_all raises when ALL providers unconfigured, and returns partial
   real results when at least one provider is configured.
5. CloudDiscoveryNotConfiguredError is a ValueError subclass (router compat).
6. The router converts the exception to HTTP 422 with a structured body.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_discovery(tmp_path: str):
    """Return a fresh CloudDiscovery instance backed by a temp DB."""
    from core.cloud_discovery import CloudDiscovery
    return CloudDiscovery(db_path=tmp_path)


# Known fabricated identifiers that must never appear in production responses.
FABRICATED_AWS_IDS = {
    "i-0a1b2c3d4e5f60001",
    "i-0a1b2c3d4e5f60002",
    "i-0a1b2c3d4e5f60003",
    "123456789012",
    "arn:aws:s3:::prod-assets-aldeci",
}
FABRICATED_AZURE_IDS = {
    "sub-azure-0001-prod",
    "/subscriptions/sub-azure-0001-prod",
}
FABRICATED_GCP_IDS = {
    "aldeci-prod-gcp-001",
    "projects/aldeci-prod-gcp-001",
}


def _assert_no_fabricated_assets(assets, fabricated_ids: set, provider: str):
    for asset in assets:
        dump = str(asset.model_dump())
        for fid in fabricated_ids:
            assert fid not in dump, (
                f"Fabricated {provider} identifier '{fid}' found in asset: {dump}"
            )


# ---------------------------------------------------------------------------
# Exception contract
# ---------------------------------------------------------------------------

class TestCloudDiscoveryNotConfiguredError:
    def test_is_value_error_subclass(self):
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError
        err = CloudDiscoveryNotConfiguredError("aws", "no creds")
        assert isinstance(err, ValueError)
        assert isinstance(err, CloudDiscoveryNotConfiguredError)

    def test_attributes(self):
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError
        err = CloudDiscoveryNotConfiguredError("azure", "missing subscription")
        assert err.provider == "azure"
        assert err.reason == "missing subscription"
        assert "AZURE" in str(err)
        assert "missing subscription" in str(err)

    def test_all_providers(self):
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError
        for provider in ("aws", "azure", "gcp", "all"):
            err = CloudDiscoveryNotConfiguredError(provider, "test")
            assert err.provider == provider


# ---------------------------------------------------------------------------
# discover_aws — no fabrication when unconfigured
# ---------------------------------------------------------------------------

class TestDiscoverAwsHonesty:
    """When boto3 is absent OR credentials are absent, must raise — not mock."""

    def test_raises_not_configured_when_boto3_missing(self, tmp_path):
        """boto3 ImportError → CloudDiscoveryNotConfiguredError, zero assets."""
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIXOPS_CLOUD_DISCOVERY_TEST_MOCK", None)
            with patch("builtins.__import__", side_effect=_block_boto3):
                with pytest.raises(CloudDiscoveryNotConfiguredError) as exc_info:
                    disc.discover_aws("test-org")

        assert exc_info.value.provider == "aws"
        assert "boto3" in exc_info.value.reason.lower()

    def test_raises_not_configured_when_no_credentials(self, tmp_path):
        """boto3 present but session returns no credentials → not configured."""
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        mock_session = MagicMock()
        mock_session.get_credentials.return_value = None

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIXOPS_CLOUD_DISCOVERY_TEST_MOCK", None)
            os.environ.pop("AWS_ACCESS_KEY_ID", None)
            os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
            with patch("boto3.Session", return_value=mock_session):
                with pytest.raises(CloudDiscoveryNotConfiguredError) as exc_info:
                    disc.discover_aws("test-org")

        assert exc_info.value.provider == "aws"
        assert "credential" in exc_info.value.reason.lower()

    def test_no_fabricated_assets_returned(self, tmp_path):
        """discover_aws must never populate the DB with fabricated assets."""
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIXOPS_CLOUD_DISCOVERY_TEST_MOCK", None)
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = None
            with patch("boto3.Session", return_value=mock_session):
                with pytest.raises(CloudDiscoveryNotConfiguredError):
                    disc.discover_aws("test-org")

        # DB must contain zero assets for this org.
        assets = disc.get_asset_inventory("test-org", provider="aws")
        assert assets == [], f"Expected zero assets but got {len(assets)}: {assets}"

        # None of the fabricated identifiers must appear anywhere.
        _assert_no_fabricated_assets(assets, FABRICATED_AWS_IDS, "aws")


# ---------------------------------------------------------------------------
# discover_azure — no fabrication when unconfigured
# ---------------------------------------------------------------------------

class TestDiscoverAzureHonesty:
    def test_raises_when_subscription_missing(self, tmp_path):
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("AZURE_SUBSCRIPTION_ID", "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK")}
        with patch.dict(os.environ, env_clean, clear=True):
            # Azure SDK available but no subscription ID
            with patch("azure.identity.DefaultAzureCredential", MagicMock()):
                with patch("azure.mgmt.compute.ComputeManagementClient", MagicMock()):
                    with pytest.raises(CloudDiscoveryNotConfiguredError) as exc_info:
                        disc.discover_azure("test-org")

        assert exc_info.value.provider == "azure"
        assert "AZURE_SUBSCRIPTION_ID" in exc_info.value.reason

    def test_raises_when_sdk_missing(self, tmp_path):
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIXOPS_CLOUD_DISCOVERY_TEST_MOCK", None)
            with patch("builtins.__import__", side_effect=_block_azure):
                with pytest.raises(CloudDiscoveryNotConfiguredError) as exc_info:
                    disc.discover_azure("test-org")

        assert exc_info.value.provider == "azure"

    def test_no_fabricated_assets_in_db(self, tmp_path):
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("AZURE_SUBSCRIPTION_ID", "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK")}
        with patch.dict(os.environ, env_clean, clear=True):
            with patch("azure.identity.DefaultAzureCredential", MagicMock()):
                with patch("azure.mgmt.compute.ComputeManagementClient", MagicMock()):
                    with pytest.raises(CloudDiscoveryNotConfiguredError):
                        disc.discover_azure("test-org")

        assets = disc.get_asset_inventory("test-org", provider="azure")
        assert assets == []
        _assert_no_fabricated_assets(assets, FABRICATED_AZURE_IDS, "azure")


# ---------------------------------------------------------------------------
# discover_gcp — no fabrication when unconfigured
# ---------------------------------------------------------------------------

class TestDiscoverGcpHonesty:
    def test_raises_when_project_missing(self, tmp_path):
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError
        import sys

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("GCP_PROJECT_ID", "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK")}
        # Inject a fake google.cloud.compute_v1 so the SDK availability check
        # passes — but GCP_PROJECT_ID is absent so we still get the error.
        fake_compute = MagicMock()
        with patch.dict(os.environ, env_clean, clear=True):
            with patch.dict(sys.modules, {"google.cloud.compute_v1": fake_compute}):
                with pytest.raises(CloudDiscoveryNotConfiguredError) as exc_info:
                    disc.discover_gcp("test-org")

        assert exc_info.value.provider == "gcp"
        assert "GCP_PROJECT_ID" in exc_info.value.reason

    def test_raises_when_sdk_missing(self, tmp_path):
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError
        import sys

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        env_clean = {k: v for k, v in os.environ.items()
                     if k != "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK"}
        # Remove google.cloud.compute_v1 from sys.modules so the import inside
        # discover_gcp raises ImportError.
        modules_clean = {k: v for k, v in sys.modules.items()
                         if not k.startswith("google.cloud.compute_v1")}
        with patch.dict(os.environ, env_clean, clear=True):
            with patch.dict(sys.modules, modules_clean, clear=True):
                # Ensure any attempt to import google.cloud.compute_v1 fails.
                with patch("builtins.__import__", side_effect=_block_gcp):
                    with pytest.raises(CloudDiscoveryNotConfiguredError) as exc_info:
                        disc.discover_gcp("test-org")

        assert exc_info.value.provider == "gcp"

    def test_no_fabricated_assets_in_db(self, tmp_path):
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError
        import sys

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("GCP_PROJECT_ID", "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK")}
        fake_compute = MagicMock()
        with patch.dict(os.environ, env_clean, clear=True):
            with patch.dict(sys.modules, {"google.cloud.compute_v1": fake_compute}):
                with pytest.raises(CloudDiscoveryNotConfiguredError):
                    disc.discover_gcp("test-org")

        assets = disc.get_asset_inventory("test-org", provider="gcp")
        assert assets == []
        _assert_no_fabricated_assets(assets, FABRICATED_GCP_IDS, "gcp")


# ---------------------------------------------------------------------------
# discover_all — honest aggregation
# ---------------------------------------------------------------------------

class TestDiscoverAllHonesty:
    def test_raises_when_all_unconfigured(self, tmp_path):
        """All three providers unconfigured → single CloudDiscoveryNotConfiguredError."""
        import sys
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("AZURE_SUBSCRIPTION_ID", "GCP_PROJECT_ID",
                                  "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK")}
        fake_compute = MagicMock()
        with patch.dict(os.environ, env_clean, clear=True):
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = None
            with patch("boto3.Session", return_value=mock_session):
                with patch("azure.identity.DefaultAzureCredential", MagicMock()):
                    with patch("azure.mgmt.compute.ComputeManagementClient", MagicMock()):
                        with patch.dict(sys.modules, {"google.cloud.compute_v1": fake_compute}):
                            with pytest.raises(CloudDiscoveryNotConfiguredError) as exc_info:
                                disc.discover_all("test-org")

        assert exc_info.value.provider == "all"
        assert "unconfigured" in exc_info.value.reason

    def test_zero_assets_when_all_unconfigured(self, tmp_path):
        """DB must be empty after an all-unconfigured discover_all attempt."""
        import sys
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("AZURE_SUBSCRIPTION_ID", "GCP_PROJECT_ID",
                                  "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK")}
        fake_compute = MagicMock()
        with patch.dict(os.environ, env_clean, clear=True):
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = None
            with patch("boto3.Session", return_value=mock_session):
                with patch("azure.identity.DefaultAzureCredential", MagicMock()):
                    with patch("azure.mgmt.compute.ComputeManagementClient", MagicMock()):
                        with patch.dict(sys.modules, {"google.cloud.compute_v1": fake_compute}):
                            with pytest.raises(CloudDiscoveryNotConfiguredError):
                                disc.discover_all("test-org")

        all_assets = disc.get_asset_inventory("test-org")
        assert all_assets == []
        # No fabricated identifiers from any provider
        for fid_set in (FABRICATED_AWS_IDS, FABRICATED_AZURE_IDS, FABRICATED_GCP_IDS):
            _assert_no_fabricated_assets(all_assets, fid_set, "all")


# ---------------------------------------------------------------------------
# Test-mock escape hatch
# ---------------------------------------------------------------------------

class TestMockEscapeHatch:
    """FIXOPS_CLOUD_DISCOVERY_TEST_MOCK=1 must return synthetic data (test use only)."""

    def test_aws_mock_returns_assets_with_flag(self, tmp_path):
        disc = _make_discovery(str(tmp_path / "db.sqlite"))
        with patch.dict(os.environ, {"FIXOPS_CLOUD_DISCOVERY_TEST_MOCK": "1"}):
            assets = disc.discover_aws("test-org")
        assert len(assets) > 0
        providers = {a.provider for a in assets}
        assert providers == {"aws"}

    def test_azure_mock_returns_assets_with_flag(self, tmp_path):
        disc = _make_discovery(str(tmp_path / "db.sqlite"))
        with patch.dict(os.environ, {"FIXOPS_CLOUD_DISCOVERY_TEST_MOCK": "1"}):
            assets = disc.discover_azure("test-org")
        assert len(assets) > 0
        providers = {a.provider for a in assets}
        assert providers == {"azure"}

    def test_gcp_mock_returns_assets_with_flag(self, tmp_path):
        disc = _make_discovery(str(tmp_path / "db.sqlite"))
        with patch.dict(os.environ, {"FIXOPS_CLOUD_DISCOVERY_TEST_MOCK": "1"}):
            assets = disc.discover_gcp("test-org")
        assert len(assets) > 0
        providers = {a.provider for a in assets}
        assert providers == {"gcp"}

    def test_mock_not_active_without_flag(self, tmp_path):
        """Without the flag, we must NOT get fabricated assets (error instead)."""
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError

        disc = _make_discovery(str(tmp_path / "db.sqlite"))

        env_clean = {k: v for k, v in os.environ.items()
                     if k != "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK"}
        with patch.dict(os.environ, env_clean, clear=True):
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = None
            with patch("boto3.Session", return_value=mock_session):
                with pytest.raises(CloudDiscoveryNotConfiguredError):
                    disc.discover_aws("test-org")


# ---------------------------------------------------------------------------
# Router — HTTP 422 on not-configured
# ---------------------------------------------------------------------------

class TestRouterHonesty:
    """The router must return 422 (not 200 with fake assets, not 500) when
    cloud credentials are absent."""

    def _get_test_client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.cloud_discovery_router import router
        app = FastAPI()
        app.include_router(router)
        return TestClient(app, raise_server_exceptions=False)

    def test_discover_aws_returns_422_when_unconfigured(self, tmp_path):
        from core.cloud_discovery import CloudDiscoveryNotConfiguredError, _instance
        import core.cloud_discovery as cd_module

        # Patch singleton to a fresh instance
        disc = _make_discovery(str(tmp_path / "db.sqlite"))
        cd_module._instance = disc

        client = self._get_test_client()

        env_clean = {k: v for k, v in os.environ.items()
                     if k != "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK"}
        with patch.dict(os.environ, env_clean, clear=True):
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = None
            with patch("boto3.Session", return_value=mock_session):
                resp = client.post("/api/v1/cloud/discover/aws", json={"org_id": "test-org"})

        assert resp.status_code == 422, (
            f"Expected 422 but got {resp.status_code}: {resp.text}"
        )
        body = resp.json()
        detail = body.get("detail", {})
        assert detail.get("configured") is False
        assert detail.get("provider") == "aws"
        assert "reason" in detail

        # Reset singleton
        cd_module._instance = None

    def test_discover_aws_response_has_no_fabricated_assets(self, tmp_path):
        """422 body must not contain any fabricated asset identifiers."""
        import core.cloud_discovery as cd_module

        disc = _make_discovery(str(tmp_path / "db.sqlite"))
        cd_module._instance = disc

        client = self._get_test_client()

        env_clean = {k: v for k, v in os.environ.items()
                     if k != "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK"}
        with patch.dict(os.environ, env_clean, clear=True):
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = None
            with patch("boto3.Session", return_value=mock_session):
                resp = client.post("/api/v1/cloud/discover/aws", json={"org_id": "test-org"})

        response_text = resp.text
        for fid in FABRICATED_AWS_IDS:
            assert fid not in response_text, (
                f"Fabricated identifier '{fid}' found in 422 response body"
            )

        cd_module._instance = None

    def test_discover_all_returns_422_when_all_unconfigured(self, tmp_path):
        import sys
        import core.cloud_discovery as cd_module

        disc = _make_discovery(str(tmp_path / "db.sqlite"))
        cd_module._instance = disc

        client = self._get_test_client()

        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("AZURE_SUBSCRIPTION_ID", "GCP_PROJECT_ID",
                                  "FIXOPS_CLOUD_DISCOVERY_TEST_MOCK")}
        fake_compute = MagicMock()
        with patch.dict(os.environ, env_clean, clear=True):
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = None
            with patch("boto3.Session", return_value=mock_session):
                with patch("azure.identity.DefaultAzureCredential", MagicMock()):
                    with patch("azure.mgmt.compute.ComputeManagementClient", MagicMock()):
                        with patch.dict(sys.modules, {"google.cloud.compute_v1": fake_compute}):
                            resp = client.post(
                                "/api/v1/cloud/discover/all",
                                json={"org_id": "test-org"},
                            )

        assert resp.status_code == 422, (
            f"Expected 422 but got {resp.status_code}: {resp.text}"
        )
        cd_module._instance = None


# ---------------------------------------------------------------------------
# Import smoke test
# ---------------------------------------------------------------------------

def test_import_smoke():
    """Both modules must import without error."""
    from core.cloud_discovery import (  # noqa: F401
        CloudAsset,
        CloudAssetType,
        CloudDiscovery,
        CloudDiscoveryNotConfiguredError,
        get_cloud_discovery,
    )
    from apps.api.cloud_discovery_router import router  # noqa: F401
    assert router is not None


# ---------------------------------------------------------------------------
# Import-block helpers (used by patch)
# ---------------------------------------------------------------------------

_REAL_IMPORT = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__


def _block_boto3(name, *args, **kwargs):
    if name == "boto3":
        raise ImportError("boto3 blocked by test")
    return _REAL_IMPORT(name, *args, **kwargs)


def _block_azure(name, *args, **kwargs):
    if name.startswith("azure"):
        raise ImportError(f"{name} blocked by test")
    return _REAL_IMPORT(name, *args, **kwargs)


def _block_gcp(name, *args, **kwargs):
    if name.startswith("google"):
        raise ImportError(f"{name} blocked by test")
    return _REAL_IMPORT(name, *args, **kwargs)
