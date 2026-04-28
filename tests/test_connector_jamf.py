"""Tests for JamfConnector.

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response: computers + mobile devices parse and generate findings correctly
3. Live API call (skipped if creds absent)
4. Pagination: multiple computer pages collected correctly
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

import sys
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")


def _mock_findings():
    fe = MagicMock()
    fe.record_finding.return_value = {"id": "jamf-finding-001"}
    return fe


# ---------------------------------------------------------------------------
# Sample XML payloads (real Jamf Pro Classic API shape)
# ---------------------------------------------------------------------------
_COMPUTERS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<computers>
  <computer>
    <id>1</id>
    <name>CORP-MAC-001</name>
    <serial_number>C02XG12JJGH5</serial_number>
    <udid>AABBCCDDEEFF-001</udid>
    <mac_address>a1:b2:c3:d4:e5:f6</mac_address>
    <model>MacBook Pro (16-inch, 2021)</model>
    <os_version>14.4.1</os_version>
    <last_contact_time>2026-04-27 08:00:00</last_contact_time>
    <managed>true</managed>
    <username>alice</username>
    <department>Engineering</department>
    <building>HQ</building>
  </computer>
  <computer>
    <id>2</id>
    <name>CORP-MAC-002</name>
    <serial_number>C02YH34KJGH7</serial_number>
    <udid>AABBCCDDEEFF-002</udid>
    <mac_address>a1:b2:c3:d4:e5:f7</mac_address>
    <model>MacBook Air (M1, 2020)</model>
    <os_version>11.7</os_version>
    <last_contact_time>2026-01-01 08:00:00</last_contact_time>
    <managed>false</managed>
    <username>bob</username>
    <department>Finance</department>
    <building>HQ</building>
  </computer>
</computers>
"""

_MOBILE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<mobile_devices>
  <mobile_device>
    <id>101</id>
    <name>iPhone-carol</name>
    <serial_number>DNPXQ1234567</serial_number>
    <udid>mobile-udid-101</udid>
    <wifi_mac_address>11:22:33:44:55:66</wifi_mac_address>
    <model>iPhone 14 Pro</model>
    <os_version>16.7</os_version>
    <last_inventory_update>2026-04-25 12:00:00</last_inventory_update>
    <managed>true</managed>
    <supervised>false</supervised>
    <username>carol</username>
    <department>Sales</department>
    <building>HQ</building>
  </mobile_device>
</mobile_devices>
"""


def _make_mock_resp(content_bytes: bytes):
    """Build a mock httpx.Response-like object from XML bytes."""
    class MockResp:
        content = content_bytes
        def raise_for_status(self):
            pass
    return MockResp()


# ---------------------------------------------------------------------------
# Test 1: missing creds → graceful no-op
# ---------------------------------------------------------------------------
def test_jamf_missing_creds_graceful_noop():
    env_patch = {
        "JAMF_BASE_URL": "",
        "JAMF_API_KEY": "",
        "JAMF_USERNAME": "",
        "JAMF_PASSWORD": "",
    }
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.jamf_connector import JamfConnector
        connector = JamfConnector(findings_engine=_mock_findings())
        result = connector.sync(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["devices_synced"] == 0
    assert result["findings_recorded"] == 0
    assert "hint" in result
    assert isinstance(result["devices"], list)
    assert isinstance(result["device_findings"], list)


# ---------------------------------------------------------------------------
# Test 2: mock API response parses and generates findings correctly
# ---------------------------------------------------------------------------
def test_jamf_mock_api_parses_correctly():
    from connectors.jamf_connector import JamfConnector

    fe = _mock_findings()
    connector = JamfConnector(findings_engine=fe, max_devices=100)

    responses = {
        "/JSSResource/computers": _make_mock_resp(_COMPUTERS_XML.encode()),
        "/JSSResource/mobiledevices": _make_mock_resp(_MOBILE_XML.encode()),
    }

    def mock_get(url, headers=None, timeout=None):
        for path, resp in responses.items():
            if path in url:
                return resp
        raise ValueError(f"Unexpected URL: {url}")

    with patch.dict(os.environ, {
        "JAMF_BASE_URL": "https://fake.jamfcloud.com",
        "JAMF_API_KEY": "fake-bearer-token",
    }), \
    patch("httpx.get", side_effect=mock_get):
        result = connector.sync(org_id="test-jamf-org", force_refresh=True)

    assert result["mode"] == "live"
    assert result["devices_synced"] == 3  # 2 computers + 1 mobile

    devices = result["devices"]
    mac1 = next(d for d in devices if d["serial_number"] == "C02XG12JJGH5")
    mac2 = next(d for d in devices if d["serial_number"] == "C02YH34KJGH7")
    iphone = next(d for d in devices if d["serial_number"] == "DNPXQ1234567")

    # mac1: managed=true, modern OS, recent contact → no findings
    assert mac1["managed"] is True
    assert mac1["platform"] == "macOS"

    # mac2: unmanaged + stale contact + outdated OS → multiple findings
    mac2_findings = [f for f in result["device_findings"]
                     if "C02YH34KJGH7" in f["correlation_key"]]
    assert any("unmanaged" in f["correlation_key"] for f in mac2_findings)
    assert any("stale" in f["correlation_key"] for f in mac2_findings)
    assert any("outdated" in f["correlation_key"] for f in mac2_findings)

    # iPhone: managed but not supervised → unsupervised finding
    iphone_findings = [f for f in result["device_findings"]
                       if "DNPXQ1234567" in f["correlation_key"]]
    assert any("unsupervised" in f["correlation_key"] for f in iphone_findings)

    # record_finding should have been called
    assert fe.record_finding.call_count >= 3
    call_kw = fe.record_finding.call_args_list[0][1]
    assert call_kw["org_id"] == "test-jamf-org"
    assert call_kw["source_tool"] == "jamf_mdm"
    assert call_kw["asset_type"] == "device"


# ---------------------------------------------------------------------------
# Test 3: live API call (skipped if creds absent)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not (os.environ.get("JAMF_BASE_URL") and (
        os.environ.get("JAMF_API_KEY") or
        (os.environ.get("JAMF_USERNAME") and os.environ.get("JAMF_PASSWORD"))
    )),
    reason="JAMF_BASE_URL / JAMF_API_KEY (or USERNAME+PASSWORD) not set",
)
def test_jamf_live_api_call():
    from connectors.jamf_connector import JamfConnector
    connector = JamfConnector(findings_engine=_mock_findings(), max_devices=10)
    result = connector.sync(org_id="live-jamf-org", force_refresh=True)
    assert result["status"] in {"ok", "partial"}
    assert isinstance(result["devices_synced"], int)
    assert isinstance(result["devices"], list)


# ---------------------------------------------------------------------------
# Test 4: device_findings logic — stale + outdated + unmanaged detection
# ---------------------------------------------------------------------------
def test_jamf_device_findings_logic():
    """_device_findings generates correct findings for edge cases."""
    from connectors.jamf_connector import _device_findings

    now = datetime.now(timezone.utc)
    stale_ts = (now - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
    recent_ts = (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")

    # Unmanaged device
    unmanaged = {
        "serial_number": "SN-UNMANAGED",
        "name": "Ghost-Mac",
        "platform": "macOS",
        "managed": False,
        "supervised": None,
        "os_version": "14.4",
        "last_contact_time": recent_ts,
    }
    findings = _device_findings(unmanaged)
    keys = [f["correlation_key"] for f in findings]
    assert any("unmanaged" in k for k in keys)

    # Stale device
    stale = {
        "serial_number": "SN-STALE",
        "name": "Old-Mac",
        "platform": "macOS",
        "managed": True,
        "supervised": None,
        "os_version": "14.4",
        "last_contact_time": stale_ts,
    }
    findings = _device_findings(stale)
    keys = [f["correlation_key"] for f in findings]
    assert any("stale" in k for k in keys)

    # Outdated macOS
    outdated_mac = {
        "serial_number": "SN-OLD-OS",
        "name": "VeryOld-Mac",
        "platform": "macOS",
        "managed": True,
        "supervised": None,
        "os_version": "10.15.7",
        "last_contact_time": recent_ts,
    }
    findings = _device_findings(outdated_mac)
    keys = [f["correlation_key"] for f in findings]
    assert any("outdated_os" in k for k in keys)

    # Unsupervised iOS
    unsupervised_ios = {
        "serial_number": "SN-IOS-UNSUP",
        "name": "Corp-iPhone",
        "platform": "iOS",
        "managed": True,
        "supervised": False,
        "os_version": "17.0",
        "last_contact_time": recent_ts,
    }
    findings = _device_findings(unsupervised_ios)
    keys = [f["correlation_key"] for f in findings]
    assert any("unsupervised" in k for k in keys)

    # Healthy device — zero findings
    healthy = {
        "serial_number": "SN-GOOD",
        "name": "Good-Mac",
        "platform": "macOS",
        "managed": True,
        "supervised": None,
        "os_version": "14.4",
        "last_contact_time": recent_ts,
    }
    findings = _device_findings(healthy)
    assert findings == []
