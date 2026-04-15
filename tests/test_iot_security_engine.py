"""Tests for IoTSecurityEngine.

Covers: init, register_device, list_devices, get_device, update_device_status,
record_anomaly, list_anomalies, resolve_anomaly, create_policy, list_policies,
get_iot_stats, validation errors, org isolation.

30+ tests, all passing.
"""

from __future__ import annotations

import sys
import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.iot_security_engine import IoTSecurityEngine


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return IoTSecurityEngine(db_path=str(tmp_path / "iot_test.db"))


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

class TestInit:
    def test_creates_db_file(self, tmp_path):
        db = tmp_path / "iot.db"
        IoTSecurityEngine(db_path=str(db))
        assert db.exists()

    def test_tables_exist(self, engine):
        import sqlite3
        conn = sqlite3.connect(engine.db_path)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        assert "iot_devices" in tables
        assert "iot_anomalies" in tables
        assert "iot_policies" in tables


# ---------------------------------------------------------------------------
# register_device
# ---------------------------------------------------------------------------

class TestRegisterDevice:
    def test_returns_record(self, engine):
        result = engine.register_device("org1", {
            "device_name": "TempSensor-01",
            "device_category": "sensor",
            "protocol": "mqtt",
            "ip_address": "10.0.0.1",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "firmware_version": "2.1.0",
            "risk_score": 30.0,
        })
        assert result["id"]
        assert result["device_name"] == "TempSensor-01"
        assert result["device_category"] == "sensor"
        assert result["protocol"] == "mqtt"
        assert result["risk_score"] == 30.0
        assert result["status"] == "online"
        assert result["org_id"] == "org1"

    def test_defaults(self, engine):
        result = engine.register_device("org1", {})
        assert result["device_category"] == "other"
        assert result["protocol"] == "mqtt"
        assert result["risk_score"] == 50.0
        assert result["status"] == "online"

    def test_all_categories(self, engine):
        categories = [
            "sensor", "actuator", "gateway", "camera", "wearable",
            "smart_home", "industrial", "medical", "vehicle", "other"
        ]
        for cat in categories:
            r = engine.register_device("org1", {"device_category": cat})
            assert r["device_category"] == cat

    def test_all_protocols(self, engine):
        protocols = ["mqtt", "coap", "http", "modbus", "bacnet",
                     "zigbee", "zwave", "bluetooth", "wifi", "cellular"]
        for proto in protocols:
            r = engine.register_device("org1", {"protocol": proto})
            assert r["protocol"] == proto

    def test_invalid_category(self, engine):
        with pytest.raises(ValueError, match="device_category"):
            engine.register_device("org1", {"device_category": "toaster"})

    def test_invalid_protocol(self, engine):
        with pytest.raises(ValueError, match="protocol"):
            engine.register_device("org1", {"protocol": "ftp"})


# ---------------------------------------------------------------------------
# list_devices / get_device
# ---------------------------------------------------------------------------

class TestListGetDevice:
    def test_list_empty(self, engine):
        assert engine.list_devices("org1") == []

    def test_list_returns_all(self, engine):
        engine.register_device("org1", {"device_category": "sensor"})
        engine.register_device("org1", {"device_category": "camera"})
        assert len(engine.list_devices("org1")) == 2

    def test_filter_by_category(self, engine):
        engine.register_device("org1", {"device_category": "sensor"})
        engine.register_device("org1", {"device_category": "camera"})
        sensors = engine.list_devices("org1", device_category="sensor")
        assert len(sensors) == 1
        assert sensors[0]["device_category"] == "sensor"

    def test_filter_by_status(self, engine):
        engine.register_device("org1", {"status": "online"})
        engine.register_device("org1", {"status": "offline"})
        online = engine.list_devices("org1", status="online")
        assert len(online) == 1

    def test_org_isolation(self, engine):
        engine.register_device("org1", {"device_name": "D1"})
        engine.register_device("org2", {"device_name": "D2"})
        assert len(engine.list_devices("org1")) == 1
        assert len(engine.list_devices("org2")) == 1

    def test_get_device_found(self, engine):
        d = engine.register_device("org1", {"device_name": "GatewayA"})
        found = engine.get_device("org1", d["id"])
        assert found["device_name"] == "GatewayA"

    def test_get_device_not_found(self, engine):
        assert engine.get_device("org1", "nonexistent") is None

    def test_get_device_wrong_org(self, engine):
        d = engine.register_device("org1", {})
        assert engine.get_device("org2", d["id"]) is None


# ---------------------------------------------------------------------------
# update_device_status
# ---------------------------------------------------------------------------

class TestUpdateDeviceStatus:
    def test_update_to_quarantined(self, engine):
        d = engine.register_device("org1", {"status": "online"})
        result = engine.update_device_status("org1", d["id"], "quarantined")
        assert result["status"] == "quarantined"

    def test_update_to_offline(self, engine):
        d = engine.register_device("org1", {})
        result = engine.update_device_status("org1", d["id"], "offline")
        assert result["status"] == "offline"

    def test_update_to_decommissioned(self, engine):
        d = engine.register_device("org1", {})
        result = engine.update_device_status("org1", d["id"], "decommissioned")
        assert result["status"] == "decommissioned"

    def test_invalid_status(self, engine):
        d = engine.register_device("org1", {})
        with pytest.raises(ValueError, match="status"):
            engine.update_device_status("org1", d["id"], "broken")

    def test_device_not_found(self, engine):
        result = engine.update_device_status("org1", "nonexistent", "offline")
        assert result is None

    def test_wrong_org_returns_none(self, engine):
        d = engine.register_device("org1", {})
        result = engine.update_device_status("org2", d["id"], "offline")
        assert result is None


# ---------------------------------------------------------------------------
# record_anomaly / list_anomalies / resolve_anomaly
# ---------------------------------------------------------------------------

class TestAnomalies:
    def _device(self, engine):
        return engine.register_device("org1", {"device_category": "gateway"})

    def test_record_returns_record(self, engine):
        d = self._device(engine)
        a = engine.record_anomaly("org1", {
            "device_id": d["id"],
            "anomaly_type": "port_scan",
            "severity": "high",
            "description": "Port scan detected from device",
        })
        assert a["id"]
        assert a["anomaly_type"] == "port_scan"
        assert a["severity"] == "high"
        assert a["status"] == "open"
        assert a["org_id"] == "org1"

    def test_default_status_open(self, engine):
        d = self._device(engine)
        a = engine.record_anomaly("org1", {
            "device_id": d["id"],
            "anomaly_type": "auth_failure",
            "severity": "medium",
        })
        assert a["status"] == "open"

    def test_all_anomaly_types(self, engine):
        d = self._device(engine)
        types = [
            "unusual_traffic", "port_scan", "data_exfil", "command_injection",
            "firmware_tampering", "auth_failure", "dos_attempt", "lateral_movement"
        ]
        for at in types:
            a = engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": at, "severity": "low"})
            assert a["anomaly_type"] == at

    def test_invalid_anomaly_type(self, engine):
        with pytest.raises(ValueError, match="anomaly_type"):
            engine.record_anomaly("org1", {"anomaly_type": "magic_hack", "severity": "low"})

    def test_invalid_severity(self, engine):
        with pytest.raises(ValueError, match="severity"):
            engine.record_anomaly("org1", {"anomaly_type": "port_scan", "severity": "extreme"})

    def test_list_all(self, engine):
        d = self._device(engine)
        engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "port_scan", "severity": "high"})
        engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "data_exfil", "severity": "critical"})
        assert len(engine.list_anomalies("org1")) == 2

    def test_filter_by_severity(self, engine):
        d = self._device(engine)
        engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "port_scan", "severity": "critical"})
        engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "auth_failure", "severity": "low"})
        crits = engine.list_anomalies("org1", severity="critical")
        assert len(crits) == 1

    def test_filter_by_status(self, engine):
        d = self._device(engine)
        a = engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "port_scan", "severity": "medium"})
        engine.resolve_anomaly("org1", a["id"], "resolved")
        engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "auth_failure", "severity": "low"})
        open_list = engine.list_anomalies("org1", status="open")
        assert len(open_list) == 1

    def test_filter_by_device_id(self, engine):
        d1 = self._device(engine)
        d2 = engine.register_device("org1", {"device_category": "camera"})
        engine.record_anomaly("org1", {"device_id": d1["id"], "anomaly_type": "port_scan", "severity": "low"})
        engine.record_anomaly("org1", {"device_id": d2["id"], "anomaly_type": "data_exfil", "severity": "high"})
        result = engine.list_anomalies("org1", device_id=d1["id"])
        assert len(result) == 1

    def test_org_isolation(self, engine):
        d = self._device(engine)
        engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "port_scan", "severity": "low"})
        assert engine.list_anomalies("org2") == []

    def test_resolve_anomaly(self, engine):
        d = self._device(engine)
        a = engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "port_scan", "severity": "medium"})
        result = engine.resolve_anomaly("org1", a["id"], "resolved")
        assert result["status"] == "resolved"

    def test_resolve_to_false_positive(self, engine):
        d = self._device(engine)
        a = engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "data_exfil", "severity": "high"})
        result = engine.resolve_anomaly("org1", a["id"], "false_positive")
        assert result["status"] == "false_positive"

    def test_resolve_to_investigating(self, engine):
        d = self._device(engine)
        a = engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "dos_attempt", "severity": "critical"})
        result = engine.resolve_anomaly("org1", a["id"], "investigating")
        assert result["status"] == "investigating"

    def test_resolve_invalid_status(self, engine):
        d = self._device(engine)
        a = engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "port_scan", "severity": "low"})
        with pytest.raises(ValueError, match="resolution_status"):
            engine.resolve_anomaly("org1", a["id"], "deleted")

    def test_resolve_not_found(self, engine):
        result = engine.resolve_anomaly("org1", "nonexistent", "resolved")
        assert result is None

    def test_resolve_wrong_org(self, engine):
        d = self._device(engine)
        a = engine.record_anomaly("org1", {"device_id": d["id"], "anomaly_type": "port_scan", "severity": "low"})
        result = engine.resolve_anomaly("org2", a["id"], "resolved")
        assert result is None


# ---------------------------------------------------------------------------
# create_policy / list_policies
# ---------------------------------------------------------------------------

class TestPolicies:
    def test_create_returns_record(self, engine):
        p = engine.create_policy("org1", {
            "policy_name": "Network Isolation",
            "policy_type": "network_isolation",
            "applies_to_category": "industrial",
            "enforcement": "mandatory",
            "enabled": True,
        })
        assert p["id"]
        assert p["policy_name"] == "Network Isolation"
        assert p["policy_type"] == "network_isolation"
        assert p["enforcement"] == "mandatory"
        assert p["enabled"] == 1

    def test_defaults(self, engine):
        p = engine.create_policy("org1", {})
        assert p["policy_type"] == "monitoring"
        assert p["enforcement"] == "recommended"
        assert p["applies_to_category"] == "all"
        assert p["enabled"] == 1

    def test_all_policy_types(self, engine):
        types = ["network_isolation", "traffic_filtering", "auth_enforcement",
                 "update_requirement", "monitoring"]
        for pt in types:
            p = engine.create_policy("org1", {"policy_type": pt})
            assert p["policy_type"] == pt

    def test_invalid_policy_type(self, engine):
        with pytest.raises(ValueError, match="policy_type"):
            engine.create_policy("org1", {"policy_type": "unknown"})

    def test_invalid_enforcement(self, engine):
        with pytest.raises(ValueError, match="enforcement"):
            engine.create_policy("org1", {"enforcement": "optional"})

    def test_list_all(self, engine):
        engine.create_policy("org1", {"policy_type": "monitoring"})
        engine.create_policy("org1", {"policy_type": "network_isolation"})
        assert len(engine.list_policies("org1")) == 2

    def test_filter_enabled_true(self, engine):
        engine.create_policy("org1", {"enabled": True, "policy_type": "monitoring"})
        engine.create_policy("org1", {"enabled": False, "policy_type": "traffic_filtering"})
        enabled = engine.list_policies("org1", enabled=True)
        assert len(enabled) == 1
        assert enabled[0]["enabled"] == 1

    def test_filter_enabled_false(self, engine):
        engine.create_policy("org1", {"enabled": True, "policy_type": "monitoring"})
        engine.create_policy("org1", {"enabled": False, "policy_type": "traffic_filtering"})
        disabled = engine.list_policies("org1", enabled=False)
        assert len(disabled) == 1
        assert disabled[0]["enabled"] == 0

    def test_org_isolation(self, engine):
        engine.create_policy("org1", {"policy_type": "monitoring"})
        assert engine.list_policies("org2") == []


# ---------------------------------------------------------------------------
# get_iot_stats
# ---------------------------------------------------------------------------

class TestIoTStats:
    def test_empty_stats(self, engine):
        stats = engine.get_iot_stats("org1")
        assert stats["total_devices"] == 0
        assert stats["online_devices"] == 0
        assert stats["quarantined_devices"] == 0
        assert stats["total_anomalies"] == 0
        assert stats["open_anomalies"] == 0
        assert stats["critical_anomalies"] == 0
        assert stats["by_category"] == {}
        assert stats["by_protocol"] == {}
        assert stats["avg_risk_score"] == 0.0

    def test_populated_stats(self, engine):
        d1 = engine.register_device("org1", {
            "device_category": "sensor", "protocol": "mqtt",
            "risk_score": 40.0, "status": "online"
        })
        d2 = engine.register_device("org1", {
            "device_category": "camera", "protocol": "http",
            "risk_score": 80.0, "status": "quarantined"
        })
        engine.record_anomaly("org1", {
            "device_id": d1["id"], "anomaly_type": "port_scan", "severity": "critical"
        })
        engine.record_anomaly("org1", {
            "device_id": d2["id"], "anomaly_type": "auth_failure", "severity": "low"
        })
        a3 = engine.record_anomaly("org1", {
            "device_id": d1["id"], "anomaly_type": "data_exfil", "severity": "high"
        })
        engine.resolve_anomaly("org1", a3["id"], "resolved")

        stats = engine.get_iot_stats("org1")
        assert stats["total_devices"] == 2
        assert stats["online_devices"] == 1
        assert stats["quarantined_devices"] == 1
        assert stats["total_anomalies"] == 3
        assert stats["open_anomalies"] == 2
        assert stats["critical_anomalies"] == 1
        assert stats["by_category"]["sensor"] == 1
        assert stats["by_category"]["camera"] == 1
        assert stats["by_protocol"]["mqtt"] == 1
        assert stats["by_protocol"]["http"] == 1
        assert stats["avg_risk_score"] == 60.0

    def test_org_isolation(self, engine):
        engine.register_device("org1", {"device_category": "sensor"})
        stats2 = engine.get_iot_stats("org2")
        assert stats2["total_devices"] == 0
