"""Tests for MobileDeviceManagementEngine — 30+ tests."""

from __future__ import annotations

import pytest
from core.mobile_device_management_engine import MobileDeviceManagementEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "mdm_test.db")
    return MobileDeviceManagementEngine(db_path=db)


@pytest.fixture
def org():
    return "org-mdm-test"


@pytest.fixture
def org2():
    return "org-mdm-other"


# ---------------------------------------------------------------------------
# enroll_device
# ---------------------------------------------------------------------------


def test_enroll_device_basic(engine, org):
    device = engine.enroll_device(org, {"name": "iPhone 14", "platform": "ios"})
    assert device["name"] == "iPhone 14"
    assert device["platform"] == "ios"
    assert device["status"] == "enrolled"
    assert device["compliance_score"] == 100
    assert device["org_id"] == org
    assert "id" in device
    assert device["issues"] == []


def test_enroll_device_android(engine, org):
    device = engine.enroll_device(org, {"name": "Pixel 7", "platform": "android"})
    assert device["platform"] == "android"
    assert device["status"] == "enrolled"


def test_enroll_device_windows(engine, org):
    device = engine.enroll_device(org, {"name": "Surface Pro", "platform": "windows"})
    assert device["platform"] == "windows"


def test_enroll_device_macos(engine, org):
    device = engine.enroll_device(org, {"name": "MacBook Pro", "platform": "macos"})
    assert device["platform"] == "macos"


def test_enroll_device_with_optional_fields(engine, org):
    device = engine.enroll_device(org, {
        "name": "iPad",
        "platform": "ios",
        "serial_number": "SN-12345",
        "os_version": "17.0",
    })
    assert device["serial_number"] == "SN-12345"
    assert device["os_version"] == "17.0"


def test_enroll_device_invalid_platform(engine, org):
    with pytest.raises(ValueError, match="platform"):
        engine.enroll_device(org, {"name": "Device", "platform": "linux"})


def test_enroll_device_missing_name(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.enroll_device(org, {"name": "", "platform": "ios"})


def test_enroll_device_no_name_key(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.enroll_device(org, {"platform": "ios"})


# ---------------------------------------------------------------------------
# list_devices
# ---------------------------------------------------------------------------


def test_list_devices_empty(engine, org):
    assert engine.list_devices(org) == []


def test_list_devices_returns_enrolled(engine, org):
    engine.enroll_device(org, {"name": "Dev1", "platform": "ios"})
    engine.enroll_device(org, {"name": "Dev2", "platform": "android"})
    devices = engine.list_devices(org)
    assert len(devices) == 2


def test_list_devices_filter_platform(engine, org):
    engine.enroll_device(org, {"name": "iPhone", "platform": "ios"})
    engine.enroll_device(org, {"name": "Pixel", "platform": "android"})
    ios_devices = engine.list_devices(org, platform="ios")
    assert len(ios_devices) == 1
    assert ios_devices[0]["platform"] == "ios"


def test_list_devices_filter_status(engine, org):
    d1 = engine.enroll_device(org, {"name": "Dev1", "platform": "ios"})
    engine.enroll_device(org, {"name": "Dev2", "platform": "android"})
    # Update compliance to change status
    engine.update_compliance(org, d1["id"], 60)
    warning_devices = engine.list_devices(org, status="warning")
    assert len(warning_devices) == 1
    assert warning_devices[0]["id"] == d1["id"]


def test_list_devices_filter_platform_and_status(engine, org):
    d1 = engine.enroll_device(org, {"name": "iPhone", "platform": "ios"})
    engine.enroll_device(org, {"name": "Pixel", "platform": "android"})
    engine.update_compliance(org, d1["id"], 90)
    result = engine.list_devices(org, platform="ios", status="compliant")
    assert len(result) == 1


# ---------------------------------------------------------------------------
# get_device
# ---------------------------------------------------------------------------


def test_get_device(engine, org):
    enrolled = engine.enroll_device(org, {"name": "iPad", "platform": "ios"})
    fetched = engine.get_device(org, enrolled["id"])
    assert fetched["id"] == enrolled["id"]
    assert fetched["name"] == "iPad"


def test_get_device_not_found(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.get_device(org, "nonexistent-id")


# ---------------------------------------------------------------------------
# update_compliance
# ---------------------------------------------------------------------------


def test_update_compliance_compliant(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    result = engine.update_compliance(org, d["id"], 85)
    assert result["compliance_score"] == 85
    assert result["status"] == "compliant"


def test_update_compliance_warning(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    result = engine.update_compliance(org, d["id"], 65)
    assert result["compliance_score"] == 65
    assert result["status"] == "warning"


def test_update_compliance_non_compliant(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    result = engine.update_compliance(org, d["id"], 30)
    assert result["compliance_score"] == 30
    assert result["status"] == "non_compliant"


def test_update_compliance_boundary_80(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    result = engine.update_compliance(org, d["id"], 80)
    assert result["status"] == "compliant"


def test_update_compliance_boundary_50(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    result = engine.update_compliance(org, d["id"], 50)
    assert result["status"] == "warning"


def test_update_compliance_boundary_49(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    result = engine.update_compliance(org, d["id"], 49)
    assert result["status"] == "non_compliant"


def test_update_compliance_clamp_above_100(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    result = engine.update_compliance(org, d["id"], 150)
    assert result["compliance_score"] == 100


def test_update_compliance_clamp_below_0(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    result = engine.update_compliance(org, d["id"], -10)
    assert result["compliance_score"] == 0


def test_update_compliance_with_issues(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    issues = ["Outdated OS", "Missing MDM profile"]
    result = engine.update_compliance(org, d["id"], 45, issues=issues)
    assert result["issues"] == issues


# ---------------------------------------------------------------------------
# wipe_device
# ---------------------------------------------------------------------------


def test_wipe_device(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    result = engine.wipe_device(org, d["id"], "Device lost")
    assert result["status"] == "wiped"
    assert result["wipe_reason"] == "Device lost"
    assert result["wiped_at"] is not None


def test_wipe_device_not_found(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.wipe_device(org, "bad-id", "reason")


def test_wiped_device_compliance_not_updated(engine, org):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    engine.wipe_device(org, d["id"], "lost")
    # Update should not change wiped status
    engine.update_compliance(org, d["id"], 90)
    fetched = engine.get_device(org, d["id"])
    assert fetched["status"] == "wiped"


# ---------------------------------------------------------------------------
# get_compliance_summary
# ---------------------------------------------------------------------------


def test_compliance_summary_empty(engine, org):
    summary = engine.get_compliance_summary(org)
    assert summary["total"] == 0
    assert summary["by_platform"] == {}
    assert summary["by_status"] == {}
    assert summary["avg_compliance_score"] == 0.0


def test_compliance_summary_counts(engine, org):
    engine.enroll_device(org, {"name": "iPhone", "platform": "ios"})
    engine.enroll_device(org, {"name": "Pixel", "platform": "android"})
    engine.enroll_device(org, {"name": "Surface", "platform": "windows"})
    summary = engine.get_compliance_summary(org)
    assert summary["total"] == 3
    assert summary["by_platform"]["ios"] == 1
    assert summary["by_platform"]["android"] == 1
    assert summary["by_platform"]["windows"] == 1


def test_compliance_summary_avg_score(engine, org):
    d1 = engine.enroll_device(org, {"name": "D1", "platform": "ios"})
    d2 = engine.enroll_device(org, {"name": "D2", "platform": "android"})
    engine.update_compliance(org, d1["id"], 80)
    engine.update_compliance(org, d2["id"], 60)
    summary = engine.get_compliance_summary(org)
    assert summary["avg_compliance_score"] == 70.0


def test_compliance_summary_by_status(engine, org):
    d1 = engine.enroll_device(org, {"name": "D1", "platform": "ios"})
    d2 = engine.enroll_device(org, {"name": "D2", "platform": "android"})
    engine.update_compliance(org, d1["id"], 90)   # compliant
    engine.update_compliance(org, d2["id"], 30)   # non_compliant
    summary = engine.get_compliance_summary(org)
    assert summary["by_status"]["compliant"] == 1
    assert summary["by_status"]["non_compliant"] == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_list(engine, org, org2):
    engine.enroll_device(org, {"name": "OrgA Device", "platform": "ios"})
    engine.enroll_device(org2, {"name": "OrgB Device", "platform": "android"})
    assert len(engine.list_devices(org)) == 1
    assert len(engine.list_devices(org2)) == 1


def test_org_isolation_get(engine, org, org2):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    with pytest.raises(ValueError, match="not found"):
        engine.get_device(org2, d["id"])


def test_org_isolation_wipe(engine, org, org2):
    d = engine.enroll_device(org, {"name": "Dev", "platform": "ios"})
    # Wipe from wrong org must fail with not-found (correct isolation)
    with pytest.raises(ValueError, match="not found"):
        engine.wipe_device(org2, d["id"], "wrong org")
    # Original device is untouched
    fetched = engine.get_device(org, d["id"])
    assert fetched["status"] == "enrolled"


def test_org_isolation_compliance_summary(engine, org, org2):
    engine.enroll_device(org, {"name": "D1", "platform": "ios"})
    engine.enroll_device(org, {"name": "D2", "platform": "ios"})
    engine.enroll_device(org2, {"name": "D3", "platform": "android"})
    s1 = engine.get_compliance_summary(org)
    s2 = engine.get_compliance_summary(org2)
    assert s1["total"] == 2
    assert s2["total"] == 1
