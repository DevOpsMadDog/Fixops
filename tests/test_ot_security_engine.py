"""Tests for OTSecurityEngine — 30+ tests."""

from __future__ import annotations

import pytest
from core.ot_security_engine import OTSecurityEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "ot_test.db")
    return OTSecurityEngine(db_path=db)


@pytest.fixture
def org():
    return "org-ot-test"


@pytest.fixture
def org2():
    return "org-ot-other"


# ---------------------------------------------------------------------------
# register_asset
# ---------------------------------------------------------------------------


def test_register_asset_plc(engine, org):
    asset = engine.register_asset(org, {"name": "PLC-001", "asset_type": "plc"})
    assert asset["name"] == "PLC-001"
    assert asset["asset_type"] == "plc"
    assert asset["status"] == "active"
    assert asset["criticality"] == "medium"
    assert asset["org_id"] == org
    assert "id" in asset


def test_register_asset_hmi(engine, org):
    asset = engine.register_asset(org, {"name": "HMI-001", "asset_type": "hmi"})
    assert asset["asset_type"] == "hmi"


def test_register_asset_scada(engine, org):
    asset = engine.register_asset(org, {"name": "SCADA-001", "asset_type": "scada"})
    assert asset["asset_type"] == "scada"


def test_register_asset_rtu(engine, org):
    asset = engine.register_asset(org, {"name": "RTU-001", "asset_type": "rtu"})
    assert asset["asset_type"] == "rtu"


def test_register_asset_sensor(engine, org):
    asset = engine.register_asset(org, {"name": "Sensor-001", "asset_type": "sensor"})
    assert asset["asset_type"] == "sensor"


def test_register_asset_historian(engine, org):
    asset = engine.register_asset(org, {"name": "Historian-001", "asset_type": "historian"})
    assert asset["asset_type"] == "historian"


def test_register_asset_critical_criticality(engine, org):
    asset = engine.register_asset(org, {
        "name": "Critical PLC",
        "asset_type": "plc",
        "criticality": "critical",
    })
    assert asset["criticality"] == "critical"


def test_register_asset_with_optional_fields(engine, org):
    asset = engine.register_asset(org, {
        "name": "PLC-002",
        "asset_type": "plc",
        "criticality": "high",
        "vendor": "Siemens",
        "firmware_version": "v2.1.0",
        "ip_address": "192.168.1.10",
        "zone": "Level 1 - Control",
    })
    assert asset["vendor"] == "Siemens"
    assert asset["firmware_version"] == "v2.1.0"
    assert asset["ip_address"] == "192.168.1.10"
    assert asset["zone"] == "Level 1 - Control"


def test_register_asset_invalid_type(engine, org):
    with pytest.raises(ValueError, match="asset_type"):
        engine.register_asset(org, {"name": "Bad", "asset_type": "router"})


def test_register_asset_invalid_criticality(engine, org):
    with pytest.raises(ValueError, match="criticality"):
        engine.register_asset(org, {
            "name": "Bad", "asset_type": "plc", "criticality": "extreme"
        })


def test_register_asset_missing_name(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.register_asset(org, {"name": "", "asset_type": "plc"})


def test_register_asset_no_name_key(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.register_asset(org, {"asset_type": "plc"})


# ---------------------------------------------------------------------------
# list_assets
# ---------------------------------------------------------------------------


def test_list_assets_empty(engine, org):
    assert engine.list_assets(org) == []


def test_list_assets_returns_all(engine, org):
    engine.register_asset(org, {"name": "PLC-1", "asset_type": "plc"})
    engine.register_asset(org, {"name": "HMI-1", "asset_type": "hmi"})
    assets = engine.list_assets(org)
    assert len(assets) == 2


def test_list_assets_filter_type(engine, org):
    engine.register_asset(org, {"name": "PLC-1", "asset_type": "plc"})
    engine.register_asset(org, {"name": "HMI-1", "asset_type": "hmi"})
    plcs = engine.list_assets(org, asset_type="plc")
    assert len(plcs) == 1
    assert plcs[0]["asset_type"] == "plc"


def test_list_assets_filter_criticality(engine, org):
    engine.register_asset(org, {"name": "A1", "asset_type": "plc", "criticality": "critical"})
    engine.register_asset(org, {"name": "A2", "asset_type": "hmi", "criticality": "low"})
    critical = engine.list_assets(org, criticality="critical")
    assert len(critical) == 1
    assert critical[0]["criticality"] == "critical"


def test_list_assets_filter_type_and_criticality(engine, org):
    engine.register_asset(org, {"name": "A1", "asset_type": "plc", "criticality": "high"})
    engine.register_asset(org, {"name": "A2", "asset_type": "plc", "criticality": "low"})
    engine.register_asset(org, {"name": "A3", "asset_type": "hmi", "criticality": "high"})
    result = engine.list_assets(org, asset_type="plc", criticality="high")
    assert len(result) == 1
    assert result[0]["name"] == "A1"


# ---------------------------------------------------------------------------
# get_asset
# ---------------------------------------------------------------------------


def test_get_asset(engine, org):
    registered = engine.register_asset(org, {"name": "PLC-1", "asset_type": "plc"})
    fetched = engine.get_asset(org, registered["id"])
    assert fetched["id"] == registered["id"]
    assert fetched["name"] == "PLC-1"


def test_get_asset_not_found(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.get_asset(org, "nonexistent-id")


# ---------------------------------------------------------------------------
# record_anomaly
# ---------------------------------------------------------------------------


def test_record_anomaly(engine, org):
    asset = engine.register_asset(org, {"name": "PLC-1", "asset_type": "plc"})
    anomaly = engine.record_anomaly(
        org, asset["id"], "unexpected_command", "high", "Unexpected Modbus command detected"
    )
    assert anomaly["asset_id"] == asset["id"]
    assert anomaly["anomaly_type"] == "unexpected_command"
    assert anomaly["severity"] == "high"
    assert anomaly["status"] == "open"
    assert anomaly["org_id"] == org
    assert "id" in anomaly
    assert anomaly["resolved_at"] is None


def test_record_anomaly_invalid_severity(engine, org):
    asset = engine.register_asset(org, {"name": "PLC-1", "asset_type": "plc"})
    with pytest.raises(ValueError, match="severity"):
        engine.record_anomaly(org, asset["id"], "type", "extreme", "desc")


def test_record_anomaly_asset_not_found(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.record_anomaly(org, "bad-asset-id", "type", "high", "desc")


def test_record_anomaly_critical_severity(engine, org):
    asset = engine.register_asset(org, {"name": "SCADA", "asset_type": "scada"})
    anomaly = engine.record_anomaly(org, asset["id"], "dos_attack", "critical", "DoS attempt")
    assert anomaly["severity"] == "critical"


# ---------------------------------------------------------------------------
# list_anomalies
# ---------------------------------------------------------------------------


def test_list_anomalies_empty(engine, org):
    assert engine.list_anomalies(org) == []


def test_list_anomalies_filter_status(engine, org):
    asset = engine.register_asset(org, {"name": "PLC-1", "asset_type": "plc"})
    a1 = engine.record_anomaly(org, asset["id"], "type1", "high", "desc1")
    engine.record_anomaly(org, asset["id"], "type2", "low", "desc2")
    engine.resolve_anomaly(org, a1["id"], "Fixed")
    open_anomalies = engine.list_anomalies(org, status="open")
    assert len(open_anomalies) == 1
    resolved = engine.list_anomalies(org, status="resolved")
    assert len(resolved) == 1


def test_list_anomalies_filter_severity(engine, org):
    asset = engine.register_asset(org, {"name": "RTU", "asset_type": "rtu"})
    engine.record_anomaly(org, asset["id"], "t1", "critical", "d1")
    engine.record_anomaly(org, asset["id"], "t2", "low", "d2")
    critical = engine.list_anomalies(org, severity="critical")
    assert len(critical) == 1
    assert critical[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# resolve_anomaly
# ---------------------------------------------------------------------------


def test_resolve_anomaly(engine, org):
    asset = engine.register_asset(org, {"name": "PLC-1", "asset_type": "plc"})
    anomaly = engine.record_anomaly(org, asset["id"], "type", "high", "desc")
    resolved = engine.resolve_anomaly(org, anomaly["id"], "Patched firmware")
    assert resolved["status"] == "resolved"
    assert resolved["resolution"] == "Patched firmware"
    assert resolved["resolved_at"] is not None


def test_resolve_anomaly_not_found(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.resolve_anomaly(org, "bad-id", "resolution")


def test_resolve_anomaly_already_resolved_remains_resolved(engine, org):
    asset = engine.register_asset(org, {"name": "PLC", "asset_type": "plc"})
    anomaly = engine.record_anomaly(org, asset["id"], "type", "medium", "desc")
    engine.resolve_anomaly(org, anomaly["id"], "Fixed once")
    result = engine.resolve_anomaly(org, anomaly["id"], "Fixed again")
    # Status stays resolved (UPDATE WHERE status != 'resolved' skips it)
    assert result["status"] == "resolved"


# ---------------------------------------------------------------------------
# get_ot_stats
# ---------------------------------------------------------------------------


def test_ot_stats_empty(engine, org):
    stats = engine.get_ot_stats(org)
    assert stats["total_assets"] == 0
    assert stats["by_type"] == {}
    assert stats["by_criticality"] == {}
    assert stats["open_anomalies"] == 0
    assert stats["critical_anomalies"] == 0


def test_ot_stats_asset_counts(engine, org):
    engine.register_asset(org, {"name": "PLC1", "asset_type": "plc", "criticality": "high"})
    engine.register_asset(org, {"name": "PLC2", "asset_type": "plc", "criticality": "critical"})
    engine.register_asset(org, {"name": "HMI1", "asset_type": "hmi", "criticality": "medium"})
    stats = engine.get_ot_stats(org)
    assert stats["total_assets"] == 3
    assert stats["by_type"]["plc"] == 2
    assert stats["by_type"]["hmi"] == 1
    assert stats["by_criticality"]["high"] == 1
    assert stats["by_criticality"]["critical"] == 1
    assert stats["by_criticality"]["medium"] == 1


def test_ot_stats_anomaly_counts(engine, org):
    asset = engine.register_asset(org, {"name": "PLC", "asset_type": "plc"})
    a1 = engine.record_anomaly(org, asset["id"], "t1", "critical", "d1")
    engine.record_anomaly(org, asset["id"], "t2", "high", "d2")
    engine.resolve_anomaly(org, a1["id"], "Fixed")
    stats = engine.get_ot_stats(org)
    assert stats["open_anomalies"] == 1
    assert stats["critical_anomalies"] == 0  # critical one was resolved


def test_ot_stats_critical_anomaly_open(engine, org):
    asset = engine.register_asset(org, {"name": "SCADA", "asset_type": "scada"})
    engine.record_anomaly(org, asset["id"], "attack", "critical", "desc")
    stats = engine.get_ot_stats(org)
    assert stats["critical_anomalies"] == 1
    assert stats["open_anomalies"] == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_assets(engine, org, org2):
    engine.register_asset(org, {"name": "OrgA PLC", "asset_type": "plc"})
    engine.register_asset(org2, {"name": "OrgB HMI", "asset_type": "hmi"})
    assert len(engine.list_assets(org)) == 1
    assert len(engine.list_assets(org2)) == 1


def test_org_isolation_get_asset(engine, org, org2):
    asset = engine.register_asset(org, {"name": "PLC", "asset_type": "plc"})
    with pytest.raises(ValueError, match="not found"):
        engine.get_asset(org2, asset["id"])


def test_org_isolation_anomalies(engine, org, org2):
    a1 = engine.register_asset(org, {"name": "PLC", "asset_type": "plc"})
    engine.record_anomaly(org, a1["id"], "type", "high", "desc")
    assert len(engine.list_anomalies(org)) == 1
    assert len(engine.list_anomalies(org2)) == 0


def test_org_isolation_stats(engine, org, org2):
    engine.register_asset(org, {"name": "PLC1", "asset_type": "plc"})
    engine.register_asset(org, {"name": "PLC2", "asset_type": "plc"})
    engine.register_asset(org2, {"name": "HMI1", "asset_type": "hmi"})
    s1 = engine.get_ot_stats(org)
    s2 = engine.get_ot_stats(org2)
    assert s1["total_assets"] == 2
    assert s2["total_assets"] == 1


def test_org_isolation_resolve_anomaly(engine, org, org2):
    asset = engine.register_asset(org, {"name": "PLC", "asset_type": "plc"})
    anomaly = engine.record_anomaly(org, asset["id"], "type", "high", "desc")
    # Resolve from wrong org must fail with not-found (correct isolation)
    with pytest.raises(ValueError, match="not found"):
        engine.resolve_anomaly(org2, anomaly["id"], "wrong org fix")
    # Original anomaly is untouched
    fetched_anomalies = engine.list_anomalies(org)
    assert fetched_anomalies[0]["status"] == "open"
