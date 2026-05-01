"""Tests for VMware Workspace ONE Live Connector (MDM).

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response parses correctly
3. Live API call (skipped if creds absent)
4. Pagination: multiple pages collected
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
    fe.record_finding.return_value = {"id": "test-finding-ws1-001"}
    return fe


def test_ws1_missing_creds_graceful_noop():
    """When WS1_API_KEY / WS1_BASE_URL absent → needs_credentials, no crash."""
    env_patch = {"WS1_API_KEY": "", "WS1_BASE_URL": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.workspace_one_connector import WorkspaceOneConnector
        connector = WorkspaceOneConnector(findings_engine=_mock_findings())
        result = connector.sync(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["devices_synced"] == 0
    assert isinstance(result["findings"], list)
    assert "hint" in result


def test_ws1_mock_api_parses_correctly():
    """A mocked WS1 device response normalizes to ALDECI finding shapes."""
    from connectors.workspace_one_connector import WorkspaceOneConnector

    fe = _mock_findings()
    connector = WorkspaceOneConnector(findings_engine=fe)

    sample_devices = [
        {
            "Id": {"Value": 1001},
            "DeviceFriendlyName": "CORP-MAC-01",
            "OperatingSystem": "Apple Mac OS X",
            "OsVersion": "14.0",
            "ComplianceStatus": "NonCompliant",
            "IsEncrypted": True,
            "EnrollmentStatus": "Enrolled",
            "UserName": "jdoe",
            "SerialNumber": "SN12345",
        }
    ]

    with patch.dict(os.environ, {
        "WS1_API_KEY": "fake-key",
        "WS1_BASE_URL": "https://ws1.test.com",
    }), \
    patch("connectors.workspace_one_connector._fetch_devices", return_value=sample_devices):
        result = connector.sync(org_id="test-org", force_refresh=True)

    assert result["status"] == "ok"
    assert result["devices_synced"] == 1
    assert len(result["findings"]) >= 1

    finding = result["findings"][0]
    assert finding["asset_type"] == "managed_device"
    assert finding["source_tool"] == "vmware_workspace_one"
    assert finding["finding_type"] == "mdm"
    assert "correlation_key" in finding


@pytest.mark.skipif(
    not (os.environ.get("WS1_API_KEY") and os.environ.get("WS1_BASE_URL")),
    reason="WS1_API_KEY / WS1_BASE_URL not set",
)
def test_ws1_live_api_call():
    """Live integration test — requires real Workspace ONE credentials."""
    from connectors.workspace_one_connector import WorkspaceOneConnector
    connector = WorkspaceOneConnector(findings_engine=_mock_findings(), max_devices=5)
    result = connector.sync(org_id="live-test-org", force_refresh=True)

    assert result["status"] in ("ok", "api_error", "needs_credentials")
    assert isinstance(result["findings"], list)


def test_ws1_pagination_collects_all_pages():
    """_fetch_devices collects devices across multiple pages."""
    from connectors.workspace_one_connector import _fetch_devices

    page1 = {
        "Devices": [{"Id": {"Value": 1}, "DeviceFriendlyName": "DEV-1"}],
        "Total": 2,
    }
    page2 = {
        "Devices": [{"Id": {"Value": 2}, "DeviceFriendlyName": "DEV-2"}],
        "Total": 2,
    }
    page3 = {
        "Devices": [],
        "Total": 2,
    }

    responses = [page1, page2, page3]
    call_count = 0

    class MockResp:
        def __init__(self, data):
            self._data = data
            self.status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return self._data

    def mock_get(url, **kwargs):
        nonlocal call_count
        resp = MockResp(responses[min(call_count, len(responses) - 1)])
        call_count += 1
        return resp

    with patch.dict(os.environ, {"WS1_API_KEY": "key", "WS1_BASE_URL": "https://ws1.test"}), \
         patch("httpx.get", side_effect=mock_get):
        devices = _fetch_devices(base_url="https://ws1.test")

    assert len(devices) == 2
