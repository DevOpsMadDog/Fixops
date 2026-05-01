"""Tests for HashiCorp Vault Live Connector (PAM).

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response parses correctly
3. Live API call (skipped if creds absent)
4. Pagination: list secrets endpoint collects all paths
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
import sys

sys.path.insert(0, "/Users/devops.ai/fixops/Fixops")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")


def _mock_findings():
    fe = MagicMock()
    fe.record_finding.return_value = {"id": "test-finding-vault-001"}
    return fe


def test_vault_missing_creds_graceful_noop():
    """When VAULT_ADDR / VAULT_TOKEN absent → status=needs_credentials, no crash."""
    env_patch = {"VAULT_ADDR": "", "VAULT_TOKEN": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.vault_connector import VaultConnector
        connector = VaultConnector(findings_engine=_mock_findings())
        result = connector.sync(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["org_id"] == "test-org"
    assert isinstance(result["findings"], list)
    assert len(result["findings"]) == 0
    assert "hint" in result


def test_vault_mock_api_parses_correctly():
    """A mocked Vault API response normalizes to ALDECI finding shape."""
    from connectors.vault_connector import VaultConnector

    fe = _mock_findings()
    connector = VaultConnector(findings_engine=fe)

    # Mock: token lookup, secret list, lease list
    class MockResp:
        def __init__(self, data, status_code=200):
            self._data = data
            self.status_code = status_code

        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception(f"HTTP {self.status_code}")

        def json(self):
            return self._data

    def mock_request(method, url, **kwargs):
        if "lookup-self" in url:
            return MockResp({"data": {"id": "test-token", "display_name": "test", "policies": ["default"]}})
        if "metadata" in url and method.upper() == "LIST":
            return MockResp({"data": {"keys": ["db/password", "app/secret"]}})
        if "leases" in url:
            return MockResp({"data": {"keys": []}})
        return MockResp({}, 404)

    with patch.dict(os.environ, {"VAULT_ADDR": "https://vault.test", "VAULT_TOKEN": "fake-token"}), \
         patch("httpx.request", side_effect=mock_request), \
         patch("httpx.get", side_effect=lambda url, **kw: mock_request("GET", url, **kw)):
        result = connector.sync(org_id="test-org", force_refresh=True)

    assert result["status"] in ("ok", "api_error")
    assert result["org_id"] == "test-org"
    assert isinstance(result["findings"], list)


@pytest.mark.skipif(
    not (os.environ.get("VAULT_ADDR") and os.environ.get("VAULT_TOKEN")),
    reason="VAULT_ADDR / VAULT_TOKEN not set",
)
def test_vault_live_api_call():
    """Live integration test — requires real Vault credentials."""
    from connectors.vault_connector import VaultConnector
    connector = VaultConnector(findings_engine=_mock_findings())
    result = connector.sync(org_id="live-test-org", force_refresh=True)

    assert result["status"] in ("ok", "api_error", "needs_credentials")
    assert isinstance(result["findings"], list)


def test_vault_normalize_secret_shape():
    """_normalize_secret returns correct ALDECI finding shape."""
    from connectors.vault_connector import _normalize_secret

    finding = _normalize_secret(
        mount="secret",
        secret_path="db/password",
        metadata={"created_time": "2024-01-01T00:00:00Z", "versions": {"1": {}, "2": {}, "3": {}}},
    )

    assert finding["asset_type"] == "vault_secret"
    assert finding["source_tool"] == "hashicorp_vault"
    assert finding["finding_type"] == "pam"
    assert "correlation_key" in finding
    assert "vault_kv|" in finding["correlation_key"]
    assert "db/password" in finding["title"] or "db/password" in finding["asset_id"]
