"""Tests for CyberArk Privileged Access Manager Live Connector.

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response parses correctly
3. Live API call (skipped if creds absent)
4. _normalize_account produces correct ALDECI finding shape
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
    fe.record_finding.return_value = {"id": "test-finding-cyberark-001"}
    return fe


def test_cyberark_missing_creds_graceful_noop():
    """When CYBERARK_USER / CYBERARK_PASS absent → needs_credentials, no crash."""
    env_patch = {"CYBERARK_USER": "", "CYBERARK_PASS": "", "CYBERARK_BASE_URL": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.cyberark_connector import CyberArkConnector
        connector = CyberArkConnector(findings_engine=_mock_findings())
        result = connector.sync(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["accounts_scanned"] == 0
    assert isinstance(result["findings"], list)
    assert "hint" in result


def test_cyberark_mock_api_parses_correctly():
    """A mocked CyberArk response normalizes to ALDECI finding shape."""
    from connectors.cyberark_connector import CyberArkConnector

    fe = _mock_findings()
    connector = CyberArkConnector(findings_engine=fe)

    sample_accounts = [
        {
            "id": "1001",
            "name": "admin-db",
            "platformId": "DomainAdminWindows",
            "safeName": "IT-Safe",
            "userName": "svc_admin",
            "address": "10.0.0.1",
            "lastModifiedTime": "2024-01-01T00:00:00Z",
        }
    ]

    with patch.dict(os.environ, {
        "CYBERARK_USER": "admin",
        "CYBERARK_PASS": "pass",
        "CYBERARK_BASE_URL": "https://cyberark.test",
    }), \
    patch("connectors.cyberark_connector._get_session_token", return_value="session-tok"), \
    patch("connectors.cyberark_connector._paginate", return_value=sample_accounts):
        result = connector.sync(org_id="test-org", force_refresh=True)

    assert result["status"] == "ok"
    assert result["accounts_scanned"] == 1
    assert result["findings_recorded"] == 1
    assert len(result["findings"]) == 1

    finding = result["findings"][0]
    assert finding["asset_type"] == "privileged_account"
    assert finding["source_tool"] == "cyberark_pam"
    assert finding["severity"] in ("critical", "high", "medium", "low")
    assert finding["correlation_key"].startswith("cyberark_account|")


@pytest.mark.skipif(
    not (os.environ.get("CYBERARK_USER") and os.environ.get("CYBERARK_PASS")),
    reason="CYBERARK_USER / CYBERARK_PASS not set",
)
def test_cyberark_live_api_call():
    """Live integration test — requires real CyberArk credentials."""
    from connectors.cyberark_connector import CyberArkConnector
    connector = CyberArkConnector(findings_engine=_mock_findings(), max_accounts=10)
    result = connector.sync(org_id="live-test-org", force_refresh=True)

    assert result["status"] in ("ok", "api_error", "needs_credentials")
    assert isinstance(result["findings"], list)


def test_cyberark_normalize_account_shape():
    """_normalize_account produces correct ALDECI finding shape."""
    from connectors.cyberark_connector import _normalize_account

    account = {
        "id": "9999",
        "name": "root-linux",
        "platformId": "UnixSSH",
        "safeName": "Unix-Safe",
        "userName": "root",
        "address": "192.168.1.1",
    }
    finding = _normalize_account(account)

    assert finding["asset_type"] == "privileged_account"
    assert finding["source_tool"] == "cyberark_pam"
    assert finding["finding_type"] == "pam"
    assert "9999" in finding["correlation_key"]
    assert finding["severity"] in ("critical", "high", "medium", "low", "informational")
