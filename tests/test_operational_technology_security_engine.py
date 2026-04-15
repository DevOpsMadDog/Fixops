"""Tests for OperationalTechnologySecurityEngine — wave 23."""

import pytest
from core.operational_technology_security_engine import OperationalTechnologySecurityEngine


@pytest.fixture
def engine(tmp_path):
    return OperationalTechnologySecurityEngine(db_path=str(tmp_path / "ot_sec.db"))


# ---------------------------------------------------------------------------
# register_asset
# ---------------------------------------------------------------------------

def test_register_asset_minimal(engine):
    asset = engine.register_asset("org1", {"asset_type": "plc", "zone": "control"})
    assert asset["asset_type"] == "plc"
    assert asset["zone"] == "control"
    assert asset["risk_score"] == 50.0
    assert asset["status"] == "operational"
    assert asset["protocol"] == "other"
    assert "id" in asset
    assert "created_at" in asset


def test_register_asset_all_types(engine):
    types = [
        "plc", "scada", "hmi", "rtu", "historian",
        "dcs", "ied", "engineering_workstation", "safety_system", "sensor",
    ]
    for atype in types:
        asset = engine.register_asset("org1", {"asset_type": atype, "zone": "control"})
        assert asset["asset_type"] == atype


def test_register_asset_all_zones(engine):
    zones = ["enterprise", "dmz", "control", "field", "safety"]
    for zone in zones:
        asset = engine.register_asset("org1", {"asset_type": "plc", "zone": zone})
        assert asset["zone"] == zone


def test_register_asset_all_protocols(engine):
    protocols = ["modbus", "dnp3", "profinet", "bacnet", "opc_ua", "iec_61850", "hart", "ethernet_ip", "s7", "other"]
    for protocol in protocols:
        asset = engine.register_asset("org1", {"asset_type": "plc", "zone": "control", "protocol": protocol})
        assert asset["protocol"] == protocol


def test_register_asset_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="asset_type"):
        engine.register_asset("org1", {"asset_type": "toaster", "zone": "control"})


def test_register_asset_invalid_zone_raises(engine):
    with pytest.raises(ValueError, match="zone"):
        engine.register_asset("org1", {"asset_type": "plc", "zone": "unknown"})


def test_register_asset_invalid_protocol_raises(engine):
    with pytest.raises(ValueError, match="protocol"):
        engine.register_asset("org1", {"asset_type": "plc", "zone": "control", "protocol": "telnet"})


def test_register_asset_all_statuses(engine):
    for status in ["operational", "maintenance", "decommissioned", "compromised"]:
        asset = engine.register_asset("org1", {"asset_type": "plc", "zone": "field", "status": status})
        assert asset["status"] == status


def test_register_asset_risk_score_default(engine):
    asset = engine.register_asset("org1", {"asset_type": "hmi", "zone": "control"})
    assert asset["risk_score"] == 50.0


# ---------------------------------------------------------------------------
# list_assets
# ---------------------------------------------------------------------------

def test_list_assets_empty(engine):
    assert engine.list_assets("org1") == []


def test_list_assets_filter_by_type(engine):
    engine.register_asset("org1", {"asset_type": "plc", "zone": "control"})
    engine.register_asset("org1", {"asset_type": "hmi", "zone": "control"})
    plcs = engine.list_assets("org1", asset_type="plc")
    assert len(plcs) == 1
    assert plcs[0]["asset_type"] == "plc"


def test_list_assets_filter_by_zone(engine):
    engine.register_asset("org1", {"asset_type": "plc", "zone": "control"})
    engine.register_asset("org1", {"asset_type": "sensor", "zone": "field"})
    field = engine.list_assets("org1", zone="field")
    assert len(field) == 1
    assert field[0]["zone"] == "field"


def test_list_assets_filter_by_status(engine):
    engine.register_asset("org1", {"asset_type": "plc", "zone": "control", "status": "operational"})
    engine.register_asset("org1", {"asset_type": "plc", "zone": "control", "status": "maintenance"})
    maint = engine.list_assets("org1", status="maintenance")
    assert len(maint) == 1


def test_list_assets_org_isolation(engine):
    engine.register_asset("org1", {"asset_type": "plc", "zone": "control"})
    assert engine.list_assets("org2") == []


# ---------------------------------------------------------------------------
# get_asset
# ---------------------------------------------------------------------------

def test_get_asset_found(engine):
    created = engine.register_asset("org1", {"asset_type": "scada", "zone": "control", "asset_name": "SCADA-1"})
    fetched = engine.get_asset("org1", created["id"])
    assert fetched is not None
    assert fetched["id"] == created["id"]
    assert fetched["asset_name"] == "SCADA-1"


def test_get_asset_not_found_returns_none(engine):
    assert engine.get_asset("org1", "nonexistent-id") is None


def test_get_asset_org_isolation(engine):
    created = engine.register_asset("org1", {"asset_type": "plc", "zone": "field"})
    assert engine.get_asset("org2", created["id"]) is None


# ---------------------------------------------------------------------------
# update_asset_status
# ---------------------------------------------------------------------------

def test_update_asset_status_changes(engine):
    asset = engine.register_asset("org1", {"asset_type": "plc", "zone": "control"})
    updated = engine.update_asset_status("org1", asset["id"], "maintenance")
    assert updated["status"] == "maintenance"


def test_update_asset_status_to_compromised(engine):
    asset = engine.register_asset("org1", {"asset_type": "plc", "zone": "control"})
    updated = engine.update_asset_status("org1", asset["id"], "compromised")
    assert updated["status"] == "compromised"


def test_update_asset_status_invalid_raises(engine):
    asset = engine.register_asset("org1", {"asset_type": "plc", "zone": "control"})
    with pytest.raises(ValueError, match="status"):
        engine.update_asset_status("org1", asset["id"], "broken")


def test_update_asset_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_asset_status("org1", "ghost-id", "maintenance")


# ---------------------------------------------------------------------------
# record_incident
# ---------------------------------------------------------------------------

def test_record_incident_basic(engine):
    incident = engine.record_incident("org1", {
        "asset_id": "asset-001",
        "incident_type": "malware",
        "severity": "critical",
        "impact_level": "major",
    })
    assert incident["incident_type"] == "malware"
    assert incident["severity"] == "critical"
    assert incident["impact_level"] == "major"
    assert incident["status"] == "detected"
    assert "id" in incident


def test_record_incident_all_types(engine):
    types = [
        "malware", "unauthorized_access", "configuration_change", "dos",
        "firmware_tampering", "network_intrusion", "physical_access",
        "data_manipulation", "safety_system_impact",
    ]
    for itype in types:
        inc = engine.record_incident("org1", {
            "asset_id": "a1", "incident_type": itype, "severity": "low", "impact_level": "none"
        })
        assert inc["incident_type"] == itype


def test_record_incident_all_severities(engine):
    for severity in ["critical", "high", "medium", "low"]:
        inc = engine.record_incident("org1", {
            "asset_id": "a1", "incident_type": "malware", "severity": severity, "impact_level": "none"
        })
        assert inc["severity"] == severity


def test_record_incident_all_impact_levels(engine):
    for impact in ["none", "minor", "moderate", "major", "catastrophic"]:
        inc = engine.record_incident("org1", {
            "asset_id": "a1", "incident_type": "dos", "severity": "low", "impact_level": impact
        })
        assert inc["impact_level"] == impact


def test_record_incident_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="incident_type"):
        engine.record_incident("org1", {
            "asset_id": "a1", "incident_type": "explosion", "severity": "critical", "impact_level": "none"
        })


def test_record_incident_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.record_incident("org1", {
            "asset_id": "a1", "incident_type": "malware", "severity": "extreme", "impact_level": "none"
        })


def test_record_incident_invalid_impact_raises(engine):
    with pytest.raises(ValueError, match="impact_level"):
        engine.record_incident("org1", {
            "asset_id": "a1", "incident_type": "malware", "severity": "low", "impact_level": "apocalyptic"
        })


def test_record_incident_default_status_detected(engine):
    inc = engine.record_incident("org1", {
        "incident_type": "dos", "severity": "medium", "impact_level": "minor"
    })
    assert inc["status"] == "detected"


# ---------------------------------------------------------------------------
# list_incidents
# ---------------------------------------------------------------------------

def test_list_incidents_empty(engine):
    assert engine.list_incidents("org1") == []


def test_list_incidents_filter_by_asset(engine):
    engine.record_incident("org1", {"asset_id": "A", "incident_type": "malware", "severity": "low", "impact_level": "none"})
    engine.record_incident("org1", {"asset_id": "B", "incident_type": "dos", "severity": "low", "impact_level": "none"})
    incidents = engine.list_incidents("org1", asset_id="A")
    assert len(incidents) == 1
    assert incidents[0]["asset_id"] == "A"


def test_list_incidents_filter_by_severity(engine):
    engine.record_incident("org1", {"incident_type": "malware", "severity": "critical", "impact_level": "major"})
    engine.record_incident("org1", {"incident_type": "dos", "severity": "low", "impact_level": "none"})
    critical = engine.list_incidents("org1", severity="critical")
    assert len(critical) == 1


def test_list_incidents_org_isolation(engine):
    engine.record_incident("org1", {"incident_type": "malware", "severity": "high", "impact_level": "minor"})
    assert engine.list_incidents("org2") == []


# ---------------------------------------------------------------------------
# update_incident_status
# ---------------------------------------------------------------------------

def test_update_incident_status_lifecycle(engine):
    inc = engine.record_incident("org1", {"incident_type": "malware", "severity": "high", "impact_level": "minor"})
    for status in ["investigating", "contained", "remediated"]:
        updated = engine.update_incident_status("org1", inc["id"], status)
        assert updated["status"] == status


def test_update_incident_status_invalid_raises(engine):
    inc = engine.record_incident("org1", {"incident_type": "malware", "severity": "high", "impact_level": "minor"})
    with pytest.raises(ValueError, match="status"):
        engine.update_incident_status("org1", inc["id"], "ignored")


def test_update_incident_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_incident_status("org1", "ghost-id", "contained")


# ---------------------------------------------------------------------------
# create_zone
# ---------------------------------------------------------------------------

def test_create_zone_basic(engine):
    zone = engine.create_zone("org1", {
        "zone_name": "Level 2 Control",
        "zone_type": "control",
        "security_level": "sl3",
        "purdue_level": 2,
        "conduit_count": 4,
    })
    assert zone["zone_type"] == "control"
    assert zone["security_level"] == "sl3"
    assert zone["purdue_level"] == 2
    assert zone["conduit_count"] == 4
    assert "id" in zone


def test_create_zone_all_types(engine):
    for ztype in ["enterprise", "dmz", "control", "field", "safety"]:
        zone = engine.create_zone("org1", {"zone_type": ztype, "security_level": "sl1", "purdue_level": 0})
        assert zone["zone_type"] == ztype


def test_create_zone_all_security_levels(engine):
    for sl in ["sl1", "sl2", "sl3", "sl4"]:
        zone = engine.create_zone("org1", {"zone_type": "control", "security_level": sl, "purdue_level": 1})
        assert zone["security_level"] == sl


def test_create_zone_purdue_level_valid_range(engine):
    for level in range(6):  # 0-5
        zone = engine.create_zone("org1", {"zone_type": "control", "security_level": "sl2", "purdue_level": level})
        assert zone["purdue_level"] == level


def test_create_zone_invalid_zone_type_raises(engine):
    with pytest.raises(ValueError, match="zone_type"):
        engine.create_zone("org1", {"zone_type": "secret", "security_level": "sl1", "purdue_level": 0})


def test_create_zone_invalid_security_level_raises(engine):
    with pytest.raises(ValueError, match="security_level"):
        engine.create_zone("org1", {"zone_type": "control", "security_level": "sl5", "purdue_level": 0})


def test_create_zone_purdue_level_out_of_range_raises(engine):
    with pytest.raises(ValueError, match="purdue_level"):
        engine.create_zone("org1", {"zone_type": "control", "security_level": "sl1", "purdue_level": 6})
    with pytest.raises(ValueError, match="purdue_level"):
        engine.create_zone("org1", {"zone_type": "control", "security_level": "sl1", "purdue_level": -1})


# ---------------------------------------------------------------------------
# list_zones
# ---------------------------------------------------------------------------

def test_list_zones_empty(engine):
    assert engine.list_zones("org1") == []


def test_list_zones_filter_by_type(engine):
    engine.create_zone("org1", {"zone_type": "control", "security_level": "sl2", "purdue_level": 2})
    engine.create_zone("org1", {"zone_type": "field", "security_level": "sl1", "purdue_level": 1})
    control = engine.list_zones("org1", zone_type="control")
    assert len(control) == 1
    assert control[0]["zone_type"] == "control"


def test_list_zones_org_isolation(engine):
    engine.create_zone("org1", {"zone_type": "safety", "security_level": "sl4", "purdue_level": 4})
    assert engine.list_zones("org2") == []


# ---------------------------------------------------------------------------
# get_ot_stats
# ---------------------------------------------------------------------------

def test_get_ot_stats_empty(engine):
    stats = engine.get_ot_stats("org1")
    assert stats["total_assets"] == 0
    assert stats["operational_assets"] == 0
    assert stats["compromised_assets"] == 0
    assert stats["total_incidents"] == 0
    assert stats["open_incidents"] == 0
    assert stats["critical_incidents"] == 0
    assert stats["total_zones"] == 0


def test_get_ot_stats_counts(engine):
    a1 = engine.register_asset("org1", {"asset_type": "plc", "zone": "control", "status": "operational"})
    a2 = engine.register_asset("org1", {"asset_type": "hmi", "zone": "field", "status": "compromised"})
    engine.register_asset("org1", {"asset_type": "sensor", "zone": "field", "status": "operational"})

    engine.record_incident("org1", {"asset_id": a1["id"], "incident_type": "malware", "severity": "critical", "impact_level": "major"})
    inc2 = engine.record_incident("org1", {"asset_id": a2["id"], "incident_type": "dos", "severity": "high", "impact_level": "minor"})
    engine.update_incident_status("org1", inc2["id"], "remediated")

    engine.create_zone("org1", {"zone_type": "control", "security_level": "sl3", "purdue_level": 2})
    engine.create_zone("org1", {"zone_type": "safety", "security_level": "sl4", "purdue_level": 4})

    stats = engine.get_ot_stats("org1")
    assert stats["total_assets"] == 3
    assert stats["operational_assets"] == 2
    assert stats["compromised_assets"] == 1
    assert stats["total_incidents"] == 2
    assert stats["open_incidents"] == 1   # only malware is still detected
    assert stats["critical_incidents"] == 1
    assert stats["total_zones"] == 2
    assert "plc" in stats["by_asset_type"]
    assert "control" in stats["by_zone"]
    assert "malware" in stats["by_incident_type"]


def test_get_ot_stats_org_isolation(engine):
    engine.register_asset("org1", {"asset_type": "plc", "zone": "control"})
    stats = engine.get_ot_stats("org2")
    assert stats["total_assets"] == 0


def test_get_ot_stats_by_asset_type_breakdown(engine):
    engine.register_asset("org1", {"asset_type": "plc", "zone": "control"})
    engine.register_asset("org1", {"asset_type": "plc", "zone": "control"})
    engine.register_asset("org1", {"asset_type": "scada", "zone": "control"})
    stats = engine.get_ot_stats("org1")
    assert stats["by_asset_type"]["plc"] == 2
    assert stats["by_asset_type"]["scada"] == 1
