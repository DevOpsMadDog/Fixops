"""Tests for MDMEngine — Mobile Device Management.

Covers: init, enroll_device, list_devices, get_device, update_compliance,
run_compliance_check, create_policy, list_policies, wipe_device,
list_wipe_requests, record_app_install, list_device_apps, get_mdm_stats,
org isolation.

30+ tests, all passing.
"""

from __future__ import annotations

import sys
import pytest
from pathlib import Path

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.mdm_engine import MDMEngine


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return MDMEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

class TestInit:
    def test_creates_db_file(self, tmp_path):
        db = tmp_path / "mdm.db"
        MDMEngine(db_path=str(db))
        assert db.exists()

    def test_tables_exist(self, engine):
        import sqlite3
        conn = sqlite3.connect(engine.db_path)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        assert "devices" in tables
        assert "mdm_policies" in tables
        assert "wipe_requests" in tables
        assert "device_apps" in tables


# ---------------------------------------------------------------------------
# Device enrollment
# ---------------------------------------------------------------------------

class TestEnrollDevice:
    def test_enroll_returns_record(self, engine):
        result = engine.enroll_device("org1", {
            "device_name": "Alice iPhone",
            "platform": "ios",
            "model": "iPhone 15",
            "serial_number": "SN12345",
            "owner_email": "alice@corp.com",
            "enrollment_type": "corporate",
            "os_version": "17.2",
        })
        assert result["device_id"]
        assert result["platform"] == "ios"
        assert result["enrollment_type"] == "corporate"
        assert result["compliance_status"] == "pending"
        assert result["compliance_issues"] == []

    def test_enroll_android(self, engine):
        result = engine.enroll_device("org1", {"platform": "android", "os_version": "14.0"})
        assert result["platform"] == "android"

    def test_enroll_byod(self, engine):
        result = engine.enroll_device("org1", {"enrollment_type": "byod", "platform": "ios"})
        assert result["enrollment_type"] == "byod"

    def test_invalid_platform_raises(self, engine):
        with pytest.raises(ValueError, match="platform"):
            engine.enroll_device("org1", {"platform": "foobar"})

    def test_invalid_enrollment_type_raises(self, engine):
        with pytest.raises(ValueError, match="enrollment_type"):
            engine.enroll_device("org1", {"enrollment_type": "unknown", "platform": "ios"})

    def test_enroll_all_platforms(self, engine):
        for platform in ("ios", "android", "windows", "macos"):
            result = engine.enroll_device("org1", {"platform": platform})
            assert result["platform"] == platform


# ---------------------------------------------------------------------------
# List / Get devices
# ---------------------------------------------------------------------------

class TestListGetDevices:
    def _enroll(self, engine, org, platform="ios", enrollment_type="corporate"):
        return engine.enroll_device(org, {"platform": platform, "enrollment_type": enrollment_type})

    def test_list_devices_empty(self, engine):
        assert engine.list_devices("org1") == []

    def test_list_devices_returns_enrolled(self, engine):
        self._enroll(engine, "org1")
        self._enroll(engine, "org1")
        results = engine.list_devices("org1")
        assert len(results) == 2

    def test_list_devices_platform_filter(self, engine):
        self._enroll(engine, "org1", platform="ios")
        self._enroll(engine, "org1", platform="android")
        ios_only = engine.list_devices("org1", platform="ios")
        assert all(d["platform"] == "ios" for d in ios_only)
        assert len(ios_only) == 1

    def test_list_devices_compliance_filter(self, engine):
        d = self._enroll(engine, "org1")
        engine.update_compliance("org1", d["device_id"], "compliant", [])
        results = engine.list_devices("org1", compliance_status="compliant")
        assert len(results) == 1

    def test_get_device_found(self, engine):
        d = self._enroll(engine, "org1")
        result = engine.get_device("org1", d["device_id"])
        assert result is not None
        assert result["device_id"] == d["device_id"]

    def test_get_device_not_found(self, engine):
        assert engine.get_device("org1", "nonexistent") is None

    def test_compliance_issues_parsed_as_list(self, engine):
        d = self._enroll(engine, "org1")
        result = engine.get_device("org1", d["device_id"])
        assert isinstance(result["compliance_issues"], list)


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

class TestCompliance:
    def test_update_compliance_valid(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        updated = engine.update_compliance("org1", d["device_id"], "compliant", [])
        assert updated is True
        result = engine.get_device("org1", d["device_id"])
        assert result["compliance_status"] == "compliant"

    def test_update_compliance_with_issues(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        engine.update_compliance("org1", d["device_id"], "non_compliant", ["OS outdated"])
        result = engine.get_device("org1", d["device_id"])
        assert result["compliance_status"] == "non_compliant"
        assert "OS outdated" in result["compliance_issues"]

    def test_update_compliance_invalid_status(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        with pytest.raises(ValueError, match="compliance_status"):
            engine.update_compliance("org1", d["device_id"], "invalid_status")

    def test_update_compliance_device_not_found(self, engine):
        result = engine.update_compliance("org1", "fake-id", "compliant")
        assert result is False

    def test_run_compliance_check_structure(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios", "os_version": "17.2"})
        result = engine.run_compliance_check("org1", d["device_id"])
        assert "passed" in result
        assert "score" in result
        assert "issues" in result
        assert "recommended_action" in result
        assert "compliance_status" in result
        assert isinstance(result["passed"], bool)
        assert 0 <= result["score"] <= 100
        assert isinstance(result["issues"], list)

    def test_run_compliance_check_outdated_os(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios", "os_version": "15.0"})
        # Create a policy requiring iOS 17.0
        engine.create_policy("org1", {
            "name": "iOS Policy",
            "platform": "ios",
            "requirements": {"min_os_version": "17.0"},
        })
        result = engine.run_compliance_check("org1", d["device_id"])
        assert result["passed"] is False
        assert any("15.0" in issue or "17.0" in issue for issue in result["issues"])

    def test_run_compliance_check_persists_result(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios", "os_version": "17.5"})
        engine.run_compliance_check("org1", d["device_id"])
        updated = engine.get_device("org1", d["device_id"])
        assert updated["last_checked"] is not None

    def test_run_compliance_check_not_found_raises(self, engine):
        with pytest.raises(ValueError):
            engine.run_compliance_check("org1", "nonexistent-device")

    def test_run_compliance_unapproved_app_fails(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios", "os_version": "17.5"})
        engine.record_app_install("org1", d["device_id"], "ShadyApp", is_approved=False)
        result = engine.run_compliance_check("org1", d["device_id"])
        assert result["passed"] is False
        assert any("unapproved" in issue.lower() for issue in result["issues"])


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

class TestPolicies:
    def test_create_policy_returns_record(self, engine):
        result = engine.create_policy("org1", {
            "name": "iOS Corporate Policy",
            "platform": "ios",
            "requirements": {
                "min_os_version": "17.0",
                "require_encryption": True,
                "require_passcode": True,
                "allowed_apps": ["Slack", "Zoom"],
            },
        })
        assert result["policy_id"]
        assert result["name"] == "iOS Corporate Policy"
        assert result["platform"] == "ios"
        assert result["min_os_version"] == "17.0"
        assert "Slack" in result["allowed_apps"]

    def test_create_policy_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name"):
            engine.create_policy("org1", {"platform": "ios"})

    def test_create_policy_invalid_platform_raises(self, engine):
        with pytest.raises(ValueError, match="platform"):
            engine.create_policy("org1", {"name": "P", "platform": "symbian"})

    def test_list_policies_empty(self, engine):
        assert engine.list_policies("org1") == []

    def test_list_policies_platform_filter(self, engine):
        engine.create_policy("org1", {"name": "iOS P", "platform": "ios"})
        engine.create_policy("org1", {"name": "Android P", "platform": "android"})
        ios_only = engine.list_policies("org1", platform="ios")
        assert len(ios_only) == 1
        assert ios_only[0]["platform"] == "ios"

    def test_list_policies_returns_booleans(self, engine):
        engine.create_policy("org1", {"name": "P", "platform": "ios", "requirements": {"require_encryption": True}})
        policies = engine.list_policies("org1")
        assert isinstance(policies[0]["require_encryption"], bool)


# ---------------------------------------------------------------------------
# Wipe
# ---------------------------------------------------------------------------

class TestWipe:
    def test_wipe_device_returns_record(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        result = engine.wipe_device("org1", d["device_id"], wiped_by="admin", wipe_type="full")
        assert result["wipe_id"]
        assert result["status"] == "pending"
        assert result["wipe_type"] == "full"

    def test_wipe_selective(self, engine):
        d = engine.enroll_device("org1", {"platform": "android"})
        result = engine.wipe_device("org1", d["device_id"], wiped_by="admin", wipe_type="selective")
        assert result["wipe_type"] == "selective"

    def test_wipe_invalid_type_raises(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        with pytest.raises(ValueError, match="wipe_type"):
            engine.wipe_device("org1", d["device_id"], wiped_by="admin", wipe_type="invalid")

    def test_wipe_marks_device_unenrolled(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        engine.wipe_device("org1", d["device_id"], wiped_by="admin", wipe_type="full")
        updated = engine.get_device("org1", d["device_id"])
        assert updated["compliance_status"] == "unenrolled"

    def test_list_wipe_requests_empty(self, engine):
        assert engine.list_wipe_requests("org1") == []

    def test_list_wipe_requests_returns_pending(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        engine.wipe_device("org1", d["device_id"], wiped_by="admin", wipe_type="full")
        requests = engine.list_wipe_requests("org1")
        assert len(requests) == 1
        assert requests[0]["status"] == "pending"


# ---------------------------------------------------------------------------
# App inventory
# ---------------------------------------------------------------------------

class TestAppInventory:
    def test_record_app_install(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        result = engine.record_app_install("org1", d["device_id"], "Slack", "4.0.1", is_approved=True)
        assert result["app_id"]
        assert result["app_name"] == "Slack"
        assert result["is_approved"] is True

    def test_record_unapproved_app(self, engine):
        d = engine.enroll_device("org1", {"platform": "android"})
        result = engine.record_app_install("org1", d["device_id"], "ShadyApp", is_approved=False)
        assert result["is_approved"] is False

    def test_list_device_apps_empty(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        assert engine.list_device_apps("org1", d["device_id"]) == []

    def test_list_device_apps_returns_installed(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        engine.record_app_install("org1", d["device_id"], "Slack", "4.0.1")
        engine.record_app_install("org1", d["device_id"], "Zoom", "5.0.0")
        apps = engine.list_device_apps("org1", d["device_id"])
        assert len(apps) == 2
        names = {a["app_name"] for a in apps}
        assert "Slack" in names
        assert "Zoom" in names

    def test_list_device_apps_is_approved_boolean(self, engine):
        d = engine.enroll_device("org1", {"platform": "ios"})
        engine.record_app_install("org1", d["device_id"], "App", is_approved=True)
        apps = engine.list_device_apps("org1", d["device_id"])
        assert isinstance(apps[0]["is_approved"], bool)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_structure(self, engine):
        result = engine.get_mdm_stats("org1")
        assert "total_devices" in result
        assert "by_platform" in result
        assert "compliant_count" in result
        assert "non_compliant_count" in result
        assert "compliant_pct" in result
        assert "pending_wipes" in result
        assert "policy_count" in result
        assert "corporate_devices" in result
        assert "byod_devices" in result

    def test_stats_empty_org(self, engine):
        result = engine.get_mdm_stats("empty-org")
        assert result["total_devices"] == 0
        assert result["compliant_pct"] == 0.0

    def test_stats_counts(self, engine):
        d1 = engine.enroll_device("org1", {"platform": "ios", "enrollment_type": "corporate"})
        d2 = engine.enroll_device("org1", {"platform": "android", "enrollment_type": "byod"})
        d3 = engine.enroll_device("org1", {"platform": "macos", "enrollment_type": "corporate"})
        engine.update_compliance("org1", d1["device_id"], "compliant")
        engine.update_compliance("org1", d2["device_id"], "non_compliant")
        # wipe d3 — marks it unenrolled; d1 and d2 keep their statuses
        engine.wipe_device("org1", d3["device_id"], "admin", "full")
        engine.create_policy("org1", {"name": "P1", "platform": "ios"})

        result = engine.get_mdm_stats("org1")
        assert result["total_devices"] == 3
        assert result["compliant_count"] == 1
        assert result["non_compliant_count"] == 1
        assert result["pending_wipes"] == 1
        assert result["policy_count"] == 1
        assert result["corporate_devices"] == 2
        assert result["byod_devices"] == 1

    def test_stats_by_platform(self, engine):
        engine.enroll_device("org1", {"platform": "ios"})
        engine.enroll_device("org1", {"platform": "ios"})
        engine.enroll_device("org1", {"platform": "android"})
        result = engine.get_mdm_stats("org1")
        assert result["by_platform"].get("ios") == 2
        assert result["by_platform"].get("android") == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_devices_isolated_by_org(self, engine):
        engine.enroll_device("org1", {"platform": "ios"})
        engine.enroll_device("org2", {"platform": "android"})
        assert len(engine.list_devices("org1")) == 1
        assert len(engine.list_devices("org2")) == 1

    def test_wipe_requests_isolated_by_org(self, engine):
        d1 = engine.enroll_device("org1", {"platform": "ios"})
        engine.wipe_device("org1", d1["device_id"], "admin", "full")
        assert len(engine.list_wipe_requests("org2")) == 0

    def test_policies_isolated_by_org(self, engine):
        engine.create_policy("org1", {"name": "P", "platform": "ios"})
        assert engine.list_policies("org2") == []

    def test_stats_isolated_by_org(self, engine):
        engine.enroll_device("org1", {"platform": "ios"})
        result = engine.get_mdm_stats("org2")
        assert result["total_devices"] == 0
