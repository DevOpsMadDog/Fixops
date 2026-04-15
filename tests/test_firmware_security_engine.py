"""Tests for FirmwareSecurityEngine.

Covers: init, register_device, list_devices, get_device, record_vulnerability,
list_vulnerabilities, create_scan, complete_scan, list_scans,
get_firmware_stats, validation errors, org isolation.

30+ tests, all passing.
"""

from __future__ import annotations

import sys
import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.firmware_security_engine import FirmwareSecurityEngine


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return FirmwareSecurityEngine(db_path=str(tmp_path / "fw_test.db"))


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

class TestInit:
    def test_creates_db_file(self, tmp_path):
        db = tmp_path / "fw.db"
        FirmwareSecurityEngine(db_path=str(db))
        assert db.exists()

    def test_tables_exist(self, engine):
        import sqlite3
        conn = sqlite3.connect(engine.db_path)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        assert "fw_devices" in tables
        assert "fw_vulnerabilities" in tables
        assert "fw_scans" in tables


# ---------------------------------------------------------------------------
# register_device
# ---------------------------------------------------------------------------

class TestRegisterDevice:
    def test_returns_record(self, engine):
        result = engine.register_device("org1", {
            "device_name": "CoreSwitch-1",
            "device_type": "switch",
            "manufacturer": "Cisco",
            "model": "Catalyst 9000",
            "firmware_version": "17.3.1",
            "risk_score": 35.0,
            "risk_level": "low",
        })
        assert result["id"]
        assert result["device_name"] == "CoreSwitch-1"
        assert result["device_type"] == "switch"
        assert result["risk_score"] == 35.0
        assert result["risk_level"] == "low"
        assert result["status"] == "active"
        assert result["org_id"] == "org1"

    def test_defaults(self, engine):
        result = engine.register_device("org1", {})
        assert result["device_type"] == "embedded"
        assert result["risk_score"] == 50.0
        assert result["risk_level"] == "medium"
        assert result["status"] == "active"

    def test_all_device_types(self, engine):
        for dt in ["router", "switch", "camera", "iot_hub", "plc", "embedded", "industrial", "medical"]:
            r = engine.register_device("org1", {"device_type": dt})
            assert r["device_type"] == dt

    def test_invalid_device_type(self, engine):
        with pytest.raises(ValueError, match="device_type"):
            engine.register_device("org1", {"device_type": "toaster"})

    def test_invalid_risk_level(self, engine):
        with pytest.raises(ValueError, match="risk_level"):
            engine.register_device("org1", {"risk_level": "extreme"})

    def test_invalid_status(self, engine):
        with pytest.raises(ValueError, match="status"):
            engine.register_device("org1", {"status": "broken"})

    def test_decommissioned_status(self, engine):
        r = engine.register_device("org1", {"status": "decommissioned"})
        assert r["status"] == "decommissioned"


# ---------------------------------------------------------------------------
# list_devices / get_device
# ---------------------------------------------------------------------------

class TestListGetDevice:
    def test_list_empty(self, engine):
        assert engine.list_devices("org1") == []

    def test_list_returns_all(self, engine):
        engine.register_device("org1", {"device_type": "router"})
        engine.register_device("org1", {"device_type": "camera"})
        assert len(engine.list_devices("org1")) == 2

    def test_filter_by_device_type(self, engine):
        engine.register_device("org1", {"device_type": "router"})
        engine.register_device("org1", {"device_type": "camera"})
        routers = engine.list_devices("org1", device_type="router")
        assert len(routers) == 1
        assert routers[0]["device_type"] == "router"

    def test_filter_by_risk_level(self, engine):
        engine.register_device("org1", {"risk_level": "critical"})
        engine.register_device("org1", {"risk_level": "low"})
        crits = engine.list_devices("org1", risk_level="critical")
        assert len(crits) == 1

    def test_org_isolation(self, engine):
        engine.register_device("org1", {"device_name": "D1"})
        engine.register_device("org2", {"device_name": "D2"})
        assert len(engine.list_devices("org1")) == 1
        assert len(engine.list_devices("org2")) == 1

    def test_get_device_found(self, engine):
        d = engine.register_device("org1", {"device_name": "PLCUnit"})
        found = engine.get_device("org1", d["id"])
        assert found["device_name"] == "PLCUnit"

    def test_get_device_not_found(self, engine):
        assert engine.get_device("org1", "nonexistent") is None

    def test_get_device_wrong_org(self, engine):
        d = engine.register_device("org1", {})
        assert engine.get_device("org2", d["id"]) is None


# ---------------------------------------------------------------------------
# record_vulnerability / list_vulnerabilities
# ---------------------------------------------------------------------------

class TestVulnerabilities:
    def _device(self, engine):
        return engine.register_device("org1", {"device_type": "router"})

    def test_record_returns_record(self, engine):
        d = self._device(engine)
        v = engine.record_vulnerability("org1", {
            "device_id": d["id"],
            "cve_id": "CVE-2024-1234",
            "title": "Buffer Overflow",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_component": "bootloader",
            "patch_available": True,
            "patch_version": "17.3.2",
        })
        assert v["id"]
        assert v["cve_id"] == "CVE-2024-1234"
        assert v["severity"] == "critical"
        assert v["cvss_score"] == 9.8
        assert v["patch_available"] == 1
        assert v["status"] == "open"

    def test_requires_device_id(self, engine):
        with pytest.raises(ValueError, match="device_id"):
            engine.record_vulnerability("org1", {"cve_id": "CVE-2024-0001"})

    def test_requires_cve_id(self, engine):
        with pytest.raises(ValueError, match="cve_id"):
            engine.record_vulnerability("org1", {"device_id": "dev1"})

    def test_invalid_severity(self, engine):
        with pytest.raises(ValueError, match="severity"):
            engine.record_vulnerability("org1", {
                "device_id": "d1", "cve_id": "CVE-X", "severity": "extreme"
            })

    def test_invalid_status(self, engine):
        with pytest.raises(ValueError, match="status"):
            engine.record_vulnerability("org1", {
                "device_id": "d1", "cve_id": "CVE-X", "status": "deleted"
            })

    def test_default_status_open(self, engine):
        d = self._device(engine)
        v = engine.record_vulnerability("org1", {"device_id": d["id"], "cve_id": "CVE-2024-X"})
        assert v["status"] == "open"

    def test_list_all(self, engine):
        d = self._device(engine)
        engine.record_vulnerability("org1", {"device_id": d["id"], "cve_id": "CVE-A", "severity": "high"})
        engine.record_vulnerability("org1", {"device_id": d["id"], "cve_id": "CVE-B", "severity": "low"})
        assert len(engine.list_vulnerabilities("org1")) == 2

    def test_filter_by_severity(self, engine):
        d = self._device(engine)
        engine.record_vulnerability("org1", {"device_id": d["id"], "cve_id": "CVE-H", "severity": "high"})
        engine.record_vulnerability("org1", {"device_id": d["id"], "cve_id": "CVE-L", "severity": "low"})
        highs = engine.list_vulnerabilities("org1", severity="high")
        assert len(highs) == 1
        assert highs[0]["severity"] == "high"

    def test_filter_by_status(self, engine):
        d = self._device(engine)
        engine.record_vulnerability("org1", {"device_id": d["id"], "cve_id": "CVE-1", "status": "open"})
        engine.record_vulnerability("org1", {"device_id": d["id"], "cve_id": "CVE-2", "status": "patched"})
        open_vulns = engine.list_vulnerabilities("org1", status="open")
        assert len(open_vulns) == 1

    def test_filter_by_device_id(self, engine):
        d1 = self._device(engine)
        d2 = engine.register_device("org1", {"device_type": "camera"})
        engine.record_vulnerability("org1", {"device_id": d1["id"], "cve_id": "CVE-D1"})
        engine.record_vulnerability("org1", {"device_id": d2["id"], "cve_id": "CVE-D2"})
        result = engine.list_vulnerabilities("org1", device_id=d1["id"])
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-D1"

    def test_org_isolation(self, engine):
        d = self._device(engine)
        engine.record_vulnerability("org1", {"device_id": d["id"], "cve_id": "CVE-O1"})
        assert engine.list_vulnerabilities("org2") == []


# ---------------------------------------------------------------------------
# create_scan / complete_scan / list_scans
# ---------------------------------------------------------------------------

class TestScans:
    def _device(self, engine):
        return engine.register_device("org1", {"device_type": "plc"})

    def test_create_scan_defaults(self, engine):
        d = self._device(engine)
        s = engine.create_scan("org1", {"device_id": d["id"]})
        assert s["id"]
        assert s["scan_type"] == "static"
        assert s["scan_status"] == "queued"
        assert s["findings_count"] == 0

    def test_create_scan_types(self, engine):
        d = self._device(engine)
        for st in ["static", "dynamic", "network", "binary"]:
            s = engine.create_scan("org1", {"device_id": d["id"], "scan_type": st})
            assert s["scan_type"] == st

    def test_invalid_scan_type(self, engine):
        with pytest.raises(ValueError, match="scan_type"):
            engine.create_scan("org1", {"scan_type": "fuzzing"})

    def test_complete_scan(self, engine):
        d = self._device(engine)
        s = engine.create_scan("org1", {"device_id": d["id"], "scan_type": "binary"})
        result = engine.complete_scan("org1", s["id"], findings_count=10, critical_count=3, high_count=4)
        assert result["scan_status"] == "completed"
        assert result["findings_count"] == 10
        assert result["critical_count"] == 3
        assert result["high_count"] == 4
        assert result["completed_at"] is not None

    def test_complete_scan_updates_device_last_scanned(self, engine):
        d = self._device(engine)
        s = engine.create_scan("org1", {"device_id": d["id"]})
        engine.complete_scan("org1", s["id"], 5, 1, 2)
        updated_device = engine.get_device("org1", d["id"])
        assert updated_device["last_scanned"] is not None

    def test_complete_scan_not_found(self, engine):
        result = engine.complete_scan("org1", "nonexistent", 0, 0, 0)
        assert result is None

    def test_complete_scan_wrong_org(self, engine):
        d = self._device(engine)
        s = engine.create_scan("org1", {"device_id": d["id"]})
        result = engine.complete_scan("org2", s["id"], 0, 0, 0)
        assert result is None

    def test_list_scans_all(self, engine):
        d = self._device(engine)
        engine.create_scan("org1", {"device_id": d["id"]})
        engine.create_scan("org1", {"device_id": d["id"], "scan_type": "dynamic"})
        assert len(engine.list_scans("org1")) == 2

    def test_list_scans_filter_by_status(self, engine):
        d = self._device(engine)
        s = engine.create_scan("org1", {"device_id": d["id"]})
        engine.complete_scan("org1", s["id"], 2, 0, 1)
        engine.create_scan("org1", {"device_id": d["id"]})
        completed = engine.list_scans("org1", scan_status="completed")
        assert len(completed) == 1
        queued = engine.list_scans("org1", scan_status="queued")
        assert len(queued) == 1

    def test_list_scans_filter_by_device(self, engine):
        d1 = self._device(engine)
        d2 = engine.register_device("org1", {"device_type": "camera"})
        engine.create_scan("org1", {"device_id": d1["id"]})
        engine.create_scan("org1", {"device_id": d2["id"]})
        result = engine.list_scans("org1", device_id=d1["id"])
        assert len(result) == 1

    def test_list_scans_org_isolation(self, engine):
        d = self._device(engine)
        engine.create_scan("org1", {"device_id": d["id"]})
        assert engine.list_scans("org2") == []


# ---------------------------------------------------------------------------
# get_firmware_stats
# ---------------------------------------------------------------------------

class TestFirmwareStats:
    def test_empty_stats(self, engine):
        stats = engine.get_firmware_stats("org1")
        assert stats["total_devices"] == 0
        assert stats["active_devices"] == 0
        assert stats["total_vulns"] == 0
        assert stats["avg_risk_score"] == 0.0
        assert stats["by_device_type"] == {}
        assert stats["by_risk_level"] == {}

    def test_populated_stats(self, engine):
        d1 = engine.register_device("org1", {
            "device_type": "router", "risk_level": "high", "risk_score": 75.0, "status": "active"
        })
        d2 = engine.register_device("org1", {
            "device_type": "camera", "risk_level": "low", "risk_score": 25.0, "status": "inactive"
        })
        engine.record_vulnerability("org1", {"device_id": d1["id"], "cve_id": "CVE-1", "severity": "critical"})
        engine.record_vulnerability("org1", {"device_id": d1["id"], "cve_id": "CVE-2", "severity": "high", "status": "patched"})

        stats = engine.get_firmware_stats("org1")
        assert stats["total_devices"] == 2
        assert stats["active_devices"] == 1
        assert stats["total_vulns"] == 2
        assert stats["critical_vulns"] == 1
        assert stats["by_device_type"]["router"] == 1
        assert stats["by_device_type"]["camera"] == 1
        assert stats["by_risk_level"]["high"] == 1
        assert stats["by_risk_level"]["low"] == 1
        assert stats["avg_risk_score"] == 50.0

    def test_unpatched_vulns(self, engine):
        d = engine.register_device("org1", {"device_type": "plc"})
        engine.record_vulnerability("org1", {
            "device_id": d["id"], "cve_id": "CVE-A",
            "patch_available": False, "status": "open"
        })
        engine.record_vulnerability("org1", {
            "device_id": d["id"], "cve_id": "CVE-B",
            "patch_available": True, "status": "open"
        })
        stats = engine.get_firmware_stats("org1")
        assert stats["unpatched_vulns"] == 1

    def test_org_isolation(self, engine):
        engine.register_device("org1", {"device_type": "switch"})
        stats2 = engine.get_firmware_stats("org2")
        assert stats2["total_devices"] == 0
