"""Tests for IntuneConnector (Microsoft Intune MDM).

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response: devices parse and generate findings correctly
3. Live API call (skipped if creds absent)
4. Pagination: @odata.nextLink followed correctly
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
    fe.record_finding.return_value = {"id": "intune-finding-001"}
    return fe


_TOKEN_RESPONSE = {
    "access_token": "fake-graph-token",
    "expires_in": 3600,
    "token_type": "Bearer",
}

_DEVICES_PAGE_1 = {
    "value": [
        {
            "id": "dev-001",
            "deviceName": "CORP-WIN-001",
            "operatingSystem": "Windows",
            "osVersion": "10.0.19045",
            "complianceState": "compliant",
            "isEncrypted": True,
            "jailBroken": "False",
            "userPrincipalName": "alice@corp.com",
            "manufacturer": "Dell",
            "model": "Latitude 5520",
            "enrolledDateTime": "2025-01-01T00:00:00Z",
            "lastSyncDateTime": "2026-04-27T08:00:00Z",
            "managementAgent": "mdm",
        },
        {
            "id": "dev-002",
            "deviceName": "CORP-MAC-002",
            "operatingSystem": "macOS",
            "osVersion": "14.4.1",
            "complianceState": "noncompliant",
            "isEncrypted": False,
            "jailBroken": "False",
            "userPrincipalName": "bob@corp.com",
            "manufacturer": "Apple",
            "model": "MacBook Pro",
            "enrolledDateTime": "2025-06-01T00:00:00Z",
            "lastSyncDateTime": "2026-04-25T08:00:00Z",
            "managementAgent": "mdm",
        },
        {
            "id": "dev-003",
            "deviceName": "CORP-IOS-003",
            "operatingSystem": "iOS",
            "osVersion": "17.4",
            "complianceState": "compliant",
            "isEncrypted": True,
            "jailBroken": "True",
            "userPrincipalName": "carol@corp.com",
            "manufacturer": "Apple",
            "model": "iPhone 15",
            "enrolledDateTime": "2025-09-01T00:00:00Z",
            "lastSyncDateTime": "2026-04-27T06:00:00Z",
            "managementAgent": "mdm",
        },
    ],
    "@odata.nextLink": None,
}

_DEVICES_PAGE_2 = {
    "value": [
        {
            "id": "dev-004",
            "deviceName": "CORP-WIN-004",
            "operatingSystem": "Windows",
            "osVersion": "11.0.22000",
            "complianceState": "compliant",
            "isEncrypted": True,
            "jailBroken": "False",
            "userPrincipalName": "dave@corp.com",
            "manufacturer": "HP",
            "model": "EliteBook",
            "enrolledDateTime": "2025-01-01T00:00:00Z",
            "lastSyncDateTime": "2026-04-27T07:00:00Z",
            "managementAgent": "mdm",
        }
    ],
}


class _MockResp:
    def __init__(self, body):
        self._body = body
        self.status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


# ---------------------------------------------------------------------------
# Test 1: missing creds → graceful no-op
# ---------------------------------------------------------------------------
def test_intune_missing_creds_graceful_noop():
    env_patch = {
        "INTUNE_TENANT_ID": "",
        "INTUNE_CLIENT_ID": "",
        "INTUNE_CLIENT_SECRET": "",
    }
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.intune_connector import IntuneConnector
        connector = IntuneConnector(findings_engine=_mock_findings())
        result = connector.sync(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["devices_synced"] == 0
    assert result["findings_recorded"] == 0
    assert "hint" in result
    assert isinstance(result["findings"], list)


# ---------------------------------------------------------------------------
# Test 2: mock API response parses correctly
# ---------------------------------------------------------------------------
def test_intune_mock_api_parses_correctly():
    from connectors.intune_connector import IntuneConnector, _normalize_device

    fe = _mock_findings()
    connector = IntuneConnector(findings_engine=fe, max_devices=100)

    def mock_post(url, data=None, timeout=None):
        return _MockResp(_TOKEN_RESPONSE)

    call_count = [0]

    def mock_get(url, headers=None, timeout=None):
        call_count[0] += 1
        if "compliancePolicyStates" in url:
            return _MockResp({"value": []})
        return _MockResp(_DEVICES_PAGE_1)

    with patch.dict(os.environ, {
        "INTUNE_TENANT_ID": "tenant-123",
        "INTUNE_CLIENT_ID": "client-abc",
        "INTUNE_CLIENT_SECRET": "secret-xyz",
    }), \
    patch("httpx.post", side_effect=mock_post), \
    patch("httpx.get", side_effect=mock_get):
        result = connector.sync(org_id="test-intune-org", force_refresh=True)

    assert result["status"] == "ok"
    assert result["mode"] == "live"
    assert result["devices_synced"] == 3

    findings = result["findings"]
    # dev-001: compliant, encrypted, not jailbroken → informational inventory
    dev1_findings = [f for f in findings if "dev-001" in f["asset_id"]]
    assert any(f["severity"] == "informational" for f in dev1_findings)

    # dev-002: noncompliant + unencrypted → high findings
    dev2_findings = [f for f in findings if "dev-002" in f["asset_id"]]
    severities = {f["severity"] for f in dev2_findings}
    assert "high" in severities

    # dev-003: jailbroken → critical
    dev3_findings = [f for f in findings if "dev-003" in f["asset_id"]]
    assert any(f["severity"] == "critical" for f in dev3_findings)
    assert any("jailbroken" in f["correlation_key"] for f in dev3_findings)

    # normalize_device shape check
    normal = _normalize_device(_DEVICES_PAGE_1["value"][0], [])
    assert len(normal) == 1
    assert normal[0]["asset_type"] == "managed_device"
    assert normal[0]["source_tool"] == "microsoft_intune"
    assert "dev-001" in normal[0]["asset_id"]


# ---------------------------------------------------------------------------
# Test 3: live API call (skipped if creds absent)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not (
        os.environ.get("INTUNE_TENANT_ID")
        and os.environ.get("INTUNE_CLIENT_ID")
        and os.environ.get("INTUNE_CLIENT_SECRET")
    ),
    reason="INTUNE_TENANT_ID / INTUNE_CLIENT_ID / INTUNE_CLIENT_SECRET not set",
)
def test_intune_live_api_call():
    from connectors.intune_connector import IntuneConnector
    connector = IntuneConnector(findings_engine=_mock_findings(), max_devices=10)
    result = connector.sync(org_id="live-intune-org", force_refresh=True)
    assert result["status"] in {"ok", "api_error"}
    assert isinstance(result["devices_synced"], int)
    assert isinstance(result["findings"], list)


# ---------------------------------------------------------------------------
# Test 4: pagination follows @odata.nextLink
# ---------------------------------------------------------------------------
def test_intune_pagination_follows_next_link():
    """_graph_get_all follows @odata.nextLink until exhausted."""
    from connectors.intune_connector import _graph_get_all

    page1 = {
        "value": [{"id": "d1"}, {"id": "d2"}],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=abc",
    }
    page2 = {
        "value": [{"id": "d3"}, {"id": "d4"}],
    }

    urls_called = []

    def mock_get(url, headers=None, timeout=None):
        urls_called.append(url)
        if "skiptoken" in url:
            return _MockResp(page2)
        return _MockResp(page1)

    with patch("httpx.get", side_effect=mock_get):
        items = _graph_get_all("fake-token", "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices")

    assert len(items) == 4
    assert items[0]["id"] == "d1"
    assert items[3]["id"] == "d4"
    assert len(urls_called) == 2
