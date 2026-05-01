"""Test that /api/v1/mdm/devices surfaces real Intune+Jamf data.

Verifies the empty-endpoint fix (triage item #24): when the org has not
enrolled any devices, list_devices_with_mdm_fallback falls back to live
IntuneConnector and JamfConnector syncs and projects the device roster
into MDM device rows.

Stubs both connectors via dependency injection — no network calls.
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from core.mdm_engine import MDMEngine


class _StubConn:
    def __init__(self, sync_result: Dict[str, Any]) -> None:
        self._result = sync_result
        self.calls: List[str] = []

    def sync(self, org_id: str, force_refresh: bool = False, **kwargs):
        self.calls.append(org_id)
        return self._result


@pytest.fixture
def engine(tmp_path):
    return MDMEngine(db_path=str(tmp_path / "mdm.db"))


def test_no_creds_anywhere_returns_needs_credentials(engine):
    intune = _StubConn({"status": "needs_credentials", "findings": []})
    jamf = _StubConn({"status": "needs_credentials", "devices": []})
    res = engine.list_devices_with_mdm_fallback(
        "fresh-org", intune_connector=intune, jamf_connector=jamf
    )
    assert res["source"] == "needs_credentials"
    assert res["devices"] == []
    assert res["total"] == 0
    assert "INTUNE" in res["hint"] and "JAMF" in res["hint"]


def test_jamf_only_devices_projected(engine):
    intune = _StubConn({"status": "needs_credentials", "findings": []})
    jamf = _StubConn({
        "status": "ok",
        "devices_synced": 2,
        "ingested_at": "2026-05-02T00:00:00Z",
        "devices": [
            {
                "device_id": "10",
                "name": "Alice-MBP",
                "serial_number": "C02ABC123",
                "model": "MacBookPro18,3",
                "os_version": "14.4.1",
                "platform": "macOS",
                "managed": True,
                "username": "alice@corp.io",
                "last_contact_time": "2026-05-01 12:00:00",
            },
            {
                "device_id": "20",
                "name": "Bob-iPad",
                "serial_number": "DM10ABC987",
                "model": "iPad13,1",
                "os_version": "16.5",
                "platform": "iOS",
                "managed": False,        # → non_compliant projection
                "username": "bob@corp.io",
            },
        ],
    })
    res = engine.list_devices_with_mdm_fallback(
        "jamf-org", intune_connector=intune, jamf_connector=jamf
    )
    assert res["source"] == "mdm-derived"
    assert res["total"] == 2
    by_serial = {d["serial_number"]: d for d in res["devices"]}
    alice = by_serial["C02ABC123"]
    assert alice["platform"] == "macos"
    assert alice["compliance_status"] == "compliant"
    assert alice["source"] == "jamf"
    assert alice["device_id"].startswith("jamf:")

    bob = by_serial["DM10ABC987"]
    assert bob["platform"] == "ios"
    assert bob["compliance_status"] == "non_compliant"
    assert "Device unmanaged" in bob["compliance_issues"]


def test_intune_findings_projected_dedup_by_device_id(engine):
    """Multiple findings for one Intune device collapse to one row."""
    intune = _StubConn({
        "status": "ok",
        "devices_synced": 1,
        "ingested_at": "2026-05-02T00:00:00Z",
        "findings": [
            {
                "title": "Intune non-compliant device: laptop-7 (Windows 10.0.19045)",
                "severity": "high",
                "description": "Device is non-compliant.",
                "correlation_key": "intune_noncompliant|abc-123",
            },
            {
                # SAME device — should dedupe
                "title": "Intune unencrypted device: laptop-7",
                "severity": "high",
                "description": "Not encrypted.",
                "correlation_key": "intune_unencrypted|abc-123",
            },
            {
                # different device
                "title": "Intune managed device: phone-99 (iOS 17.0)",
                "severity": "informational",
                "description": "Compliant.",
                "correlation_key": "intune_device|def-456",
            },
        ],
    })
    jamf = _StubConn({"status": "needs_credentials", "devices": []})
    res = engine.list_devices_with_mdm_fallback(
        "intune-org", intune_connector=intune, jamf_connector=jamf
    )
    assert res["source"] == "mdm-derived"
    assert res["total"] == 2  # dedup
    by_id = {d["device_id"]: d for d in res["devices"]}
    assert "intune:abc-123" in by_id
    assert "intune:def-456" in by_id
    assert by_id["intune:abc-123"]["compliance_status"] == "non_compliant"
    assert by_id["intune:def-456"]["platform"] == "ios"


def test_org_enrolled_devices_take_precedence(engine):
    engine.enroll_device(
        "tier-org",
        {"device_name": "manual-1", "platform": "ios"},
    )
    intune = _StubConn({
        "status": "ok",
        "devices_synced": 1,
        "findings": [{
            "title": "Intune managed device: x", "severity": "low",
            "correlation_key": "intune_device|x",
        }],
    })
    jamf = _StubConn({"status": "needs_credentials", "devices": []})
    res = engine.list_devices_with_mdm_fallback(
        "tier-org", intune_connector=intune, jamf_connector=jamf
    )
    assert res["source"] == "org_enrolled"
    assert res["total"] == 1
    assert res["devices"][0]["device_name"] == "manual-1"
    # Connectors must NOT be called when org has rows.
    assert intune.calls == []
    assert jamf.calls == []


def test_platform_filter_applies_to_derived_rows(engine):
    intune = _StubConn({"status": "needs_credentials", "findings": []})
    jamf = _StubConn({
        "status": "ok",
        "devices_synced": 2,
        "devices": [
            {"device_id": "1", "name": "mac", "serial_number": "S1",
             "platform": "macOS", "managed": True},
            {"device_id": "2", "name": "ipad", "serial_number": "S2",
             "platform": "iOS", "managed": True},
        ],
    })
    res = engine.list_devices_with_mdm_fallback(
        "filt-org", platform="ios",
        intune_connector=intune, jamf_connector=jamf,
    )
    assert res["total"] == 1
    assert res["devices"][0]["platform"] == "ios"


def test_connector_exception_recorded_in_errors(engine):
    class _BoomIntune:
        calls: List[str] = []
        def sync(self, org_id, force_refresh=False):
            raise RuntimeError("Graph API 503")

    jamf = _StubConn({
        "status": "ok",
        "devices_synced": 1,
        "devices": [{"device_id": "10", "name": "ok-mac",
                     "serial_number": "S10", "platform": "macOS",
                     "managed": True}],
    })
    res = engine.list_devices_with_mdm_fallback(
        "mix-org", intune_connector=_BoomIntune(), jamf_connector=jamf
    )
    # Jamf still produced a row → derived
    assert res["source"] == "mdm-derived"
    assert res["total"] == 1
    assert any("Graph API 503" in e for e in (res.get("errors") or []))


def test_both_connectors_no_devices_returns_empty_with_hint(engine):
    intune = _StubConn({"status": "ok", "devices_synced": 0, "findings": []})
    jamf = _StubConn({"status": "ok", "devices_synced": 0, "devices": []})
    res = engine.list_devices_with_mdm_fallback(
        "noop-org", intune_connector=intune, jamf_connector=jamf
    )
    assert res["source"] == "mdm_no_devices"
    assert res["total"] == 0
    assert res["intune_synced"] == 0
    assert res["jamf_synced"] == 0
    assert "manually" in (res["hint"] or "").lower()
