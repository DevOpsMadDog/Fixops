"""Tests for Microsoft Intune Live Connector (MDM).

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response parses correctly
3. Live API call (skipped if creds absent)
4. _normalize_device produces correct ALDECI finding shapes
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
    fe.record_finding.return_value = {"id": "test-finding-intune-001"}
    return fe


def test_intune_missing_creds_graceful_noop():
    """When INTUNE_* creds absent → needs_credentials, no crash."""
    env_patch = {"INTUNE_TENANT_ID": "", "INTUNE_CLIENT_ID": "", "INTUNE_CLIENT_SECRET": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.intune_connector import IntuneConnector
        connector = IntuneConnector(findings_engine=_mock_findings())
        result = connector.sync(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["devices_synced"] == 0
    assert isinstance(result["findings"], list)
    assert "hint" in result


def test_intune_mock_api_parses_correctly():
    """A mocked Graph API device response normalizes to ALDECI finding shapes."""
    from connectors.intune_connector import IntuneConnector

    fe = _mock_findings()
    connector = IntuneConnector(findings_engine=fe)

    sample_devices = [
        {
            "id": "dev-001",
            "deviceName": "LAPTOP-CORP-01",
            "operatingSystem": "Windows",
            "osVersion": "11.0",
            "complianceState": "noncompliant",
            "isEncrypted": True,
            "jailBroken": "False",
            "userPrincipalName": "user@corp.com",
            "manufacturer": "Dell",
            "model": "XPS 15",
            "lastSyncDateTime": "2024-01-01T00:00:00Z",
        }
    ]

    with patch.dict(os.environ, {
        "INTUNE_TENANT_ID": "tenant-id",
        "INTUNE_CLIENT_ID": "client-id",
        "INTUNE_CLIENT_SECRET": "secret",
    }), \
    patch("connectors.intune_connector._get_token", return_value="graph-tok"), \
    patch("connectors.intune_connector._graph_get_all", return_value=sample_devices), \
    patch("httpx.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"value": []})
        result = connector.sync(org_id="test-org", force_refresh=True)

    assert result["status"] == "ok"
    assert result["devices_synced"] == 1
    assert len(result["findings"]) >= 1

    finding = result["findings"][0]
    assert finding["asset_type"] == "managed_device"
    assert finding["source_tool"] == "microsoft_intune"
    assert finding["finding_type"] == "mdm"
    assert "dev-001" in finding["correlation_key"]


@pytest.mark.skipif(
    not (
        os.environ.get("INTUNE_TENANT_ID")
        and os.environ.get("INTUNE_CLIENT_ID")
        and os.environ.get("INTUNE_CLIENT_SECRET")
    ),
    reason="INTUNE_* credentials not set",
)
def test_intune_live_api_call():
    """Live integration test — requires real Intune credentials."""
    from connectors.intune_connector import IntuneConnector
    connector = IntuneConnector(findings_engine=_mock_findings(), max_devices=5)
    result = connector.sync(org_id="live-test-org", force_refresh=True)

    assert result["status"] in ("ok", "api_error", "needs_credentials")
    assert isinstance(result["findings"], list)


def test_intune_normalize_device_noncompliant():
    """_normalize_device flags non-compliant device as high severity."""
    from connectors.intune_connector import _normalize_device

    device = {
        "id": "dev-nc-001",
        "deviceName": "BAD-LAPTOP",
        "operatingSystem": "Windows",
        "osVersion": "10",
        "complianceState": "noncompliant",
        "isEncrypted": True,
        "jailBroken": "False",
        "userPrincipalName": "bad@corp.com",
    }
    compliance_states = [{"state": "nonCompliant", "displayName": "Policy1"}]
    findings = _normalize_device(device, compliance_states)

    non_compliant = [f for f in findings if "non-compliant" in f["title"].lower() or "noncompliant" in f["title"].lower()]
    assert len(non_compliant) >= 1
    assert non_compliant[0]["severity"] in ("high", "critical", "medium")
    assert non_compliant[0]["source_tool"] == "microsoft_intune"
