"""Tests for WorkspaceOneConnector (VMware Workspace ONE MDM).

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response: devices parse and generate findings correctly
3. Live API call (skipped if creds absent)
4. Pagination: multiple device pages collected correctly
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
    fe.record_finding.return_value = {"id": "ws1-finding-001"}
    return fe


_DEVICES_PAGE_1 = {
    "Devices": [
        {
            "Id": {"Value": 101},
            "DeviceFriendlyName": "CORP-WIN-101",
            "Platform": "WinRT",
            "OperatingSystem": "10.0.19045.4291",
            "ComplianceStatus": "Compliant",
            "EnrollmentStatus": "Enrolled",
            "IsCompromised": False,
            "IsEncrypted": True,
            "UserName": "alice",
            "LastSeen": "2026-04-27T08:00:00",
            "Model": "Dell Latitude",
        },
        {
            "Id": {"Value": 102},
            "DeviceFriendlyName": "CORP-IOS-102",
            "Platform": "Apple",
            "OperatingSystem": "17.4",
            "ComplianceStatus": "NonCompliant",
            "EnrollmentStatus": "Enrolled",
            "IsCompromised": True,
            "IsEncrypted": True,
            "UserName": "bob",
            "LastSeen": "2026-04-26T10:00:00",
            "Model": "iPhone 15",
        },
    ],
    "Total": 3,
}

_DEVICES_PAGE_2 = {
    "Devices": [
        {
            "Id": {"Value": 103},
            "DeviceFriendlyName": "CORP-AND-103",
            "Platform": "Android",
            "OperatingSystem": "14.0",
            "ComplianceStatus": "Compliant",
            "EnrollmentStatus": "Unenrolled",
            "IsCompromised": False,
            "IsEncrypted": False,
            "UserName": "carol",
            "LastSeen": "2026-04-20T06:00:00",
            "Model": "Samsung Galaxy",
        },
    ],
    "Total": 3,
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
def test_ws1_missing_creds_graceful_noop():
    env_patch = {"WS1_API_KEY": "", "WS1_BASE_URL": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.workspace_one_connector import WorkspaceOneConnector
        connector = WorkspaceOneConnector(findings_engine=_mock_findings())
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
def test_ws1_mock_api_parses_correctly():
    from connectors.workspace_one_connector import WorkspaceOneConnector, _normalize_ws1_device

    fe = _mock_findings()
    connector = WorkspaceOneConnector(findings_engine=fe, max_devices=100)

    call_count = [0]

    def mock_get(url, params=None, headers=None, timeout=None):
        page = (params or {}).get("page", 0)
        if page == 0:
            return _MockResp(_DEVICES_PAGE_1)
        return _MockResp(_DEVICES_PAGE_2)

    with patch.dict(os.environ, {
        "WS1_BASE_URL": "https://ws1.test.com",
        "WS1_API_KEY": "fake-api-key",
    }), \
    patch("httpx.get", side_effect=mock_get):
        result = connector.sync(org_id="test-ws1-org", force_refresh=True)

    assert result["status"] == "ok"
    assert result["mode"] == "live"
    assert result["devices_synced"] == 3

    findings = result["findings"]

    # dev-101: compliant, not compromised, encrypted, enrolled → informational
    dev101 = [f for f in findings if "101" in f["asset_id"]]
    assert any(f["severity"] == "informational" for f in dev101)

    # dev-102: noncompliant + compromised → high + critical
    dev102 = [f for f in findings if "102" in f["asset_id"]]
    sevs = {f["severity"] for f in dev102}
    assert "critical" in sevs  # compromised
    assert "high" in sevs      # noncompliant

    # dev-103: unenrolled + unencrypted → medium + high
    dev103 = [f for f in findings if "103" in f["asset_id"]]
    sevs103 = {f["severity"] for f in dev103}
    assert "medium" in sevs103  # unenrolled
    assert "high" in sevs103    # unencrypted

    # Shape check
    normalized = _normalize_ws1_device(_DEVICES_PAGE_1["Devices"][0])
    assert normalized[0]["asset_type"] == "managed_device"
    assert normalized[0]["source_tool"] == "vmware_workspace_one"
    assert "101" in normalized[0]["asset_id"]
    assert normalized[0]["correlation_key"].startswith("ws1_")


# ---------------------------------------------------------------------------
# Test 3: live API call (skipped if creds absent)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not (os.environ.get("WS1_API_KEY") and os.environ.get("WS1_BASE_URL")),
    reason="WS1_API_KEY / WS1_BASE_URL not set",
)
def test_ws1_live_api_call():
    from connectors.workspace_one_connector import WorkspaceOneConnector
    connector = WorkspaceOneConnector(findings_engine=_mock_findings(), max_devices=10)
    result = connector.sync(org_id="live-ws1-org", force_refresh=True)
    assert result["status"] in {"ok", "api_error"}
    assert isinstance(result["devices_synced"], int)
    assert isinstance(result["findings"], list)


# ---------------------------------------------------------------------------
# Test 4: pagination collects across pages
# ---------------------------------------------------------------------------
def test_ws1_pagination_collects_all_devices():
    """_fetch_devices pages through all device pages."""
    from connectors.workspace_one_connector import _fetch_devices

    pages = {
        0: {"Devices": [{"Id": {"Value": 1}}, {"Id": {"Value": 2}}], "Total": 4},
        1: {"Devices": [{"Id": {"Value": 3}}, {"Id": {"Value": 4}}], "Total": 4},
        2: {"Devices": [], "Total": 4},
    }

    def mock_get(url, params=None, headers=None, timeout=None):
        page = int((params or {}).get("page", 0))
        body = pages.get(page, {"Devices": [], "Total": 4})

        class R:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return body
        return R()

    with patch.dict(os.environ, {"WS1_API_KEY": "fake-key"}), \
         patch("httpx.get", side_effect=mock_get):
        devices = _fetch_devices("https://ws1.test.com")

    assert len(devices) == 4
    ids = [d["Id"]["Value"] for d in devices]
    assert ids == [1, 2, 3, 4]
