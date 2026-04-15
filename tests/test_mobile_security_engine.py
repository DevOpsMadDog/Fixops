"""Tests for MobileSecurityEngine — 24 tests covering all public methods."""

import os
import pytest

from core.mobile_security_engine import MobileSecurityEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_mobile_security.db")
    return MobileSecurityEngine(db_path=db)


# ------------------------------------------------------------------
# Initialization
# ------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "mobile.db")
    MobileSecurityEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "mobile.db")
    MobileSecurityEngine(db_path=db)
    MobileSecurityEngine(db_path=db)  # second init must not raise


# ------------------------------------------------------------------
# register_device / list_devices
# ------------------------------------------------------------------

def test_register_device_returns_dict(engine):
    d = engine.register_device("org1", {
        "device_name": "iPhone 15",
        "platform": "ios",
        "os_version": "17.4",
        "enrollment_status": "enrolled",
        "compliance_status": "compliant",
        "risk_score": 10,
        "jailbroken": False,
    })
    assert d["device_id"]
    assert d["device_name"] == "iPhone 15"
    assert d["platform"] == "ios"
    assert d["enrollment_status"] == "enrolled"
    assert d["compliance_status"] == "compliant"
    assert d["risk_score"] == 10
    assert d["jailbroken"] is False
    assert d["created_at"]


def test_register_device_jailbroken_flag(engine):
    d = engine.register_device("org1", {
        "device_name": "Rooted Android",
        "platform": "android",
        "jailbroken": True,
    })
    assert d["jailbroken"] is True


def test_register_device_invalid_platform_defaults(engine):
    d = engine.register_device("org1", {"device_name": "Test", "platform": "blackberry"})
    assert d["platform"] == "android"


def test_register_device_risk_score_clamped(engine):
    d = engine.register_device("org1", {"device_name": "D", "risk_score": 200})
    assert d["risk_score"] == 100
    d2 = engine.register_device("org1", {"device_name": "D2", "risk_score": -10})
    assert d2["risk_score"] == 0


def test_list_devices_empty(engine):
    assert engine.list_devices("org_none") == []


def test_list_devices_returns_own_org(engine):
    engine.register_device("org1", {"device_name": "A", "platform": "ios"})
    engine.register_device("org2", {"device_name": "B", "platform": "android"})
    result = engine.list_devices("org1")
    assert len(result) == 1
    assert result[0]["device_name"] == "A"


def test_list_devices_filter_by_platform(engine):
    engine.register_device("org1", {"device_name": "iPhone", "platform": "ios"})
    engine.register_device("org1", {"device_name": "Pixel", "platform": "android"})
    ios_devices = engine.list_devices("org1", platform="ios")
    assert len(ios_devices) == 1
    assert ios_devices[0]["platform"] == "ios"


def test_list_devices_filter_by_compliance(engine):
    engine.register_device("org1", {"device_name": "D1", "compliance_status": "compliant"})
    engine.register_device("org1", {"device_name": "D2", "compliance_status": "non_compliant"})
    compliant = engine.list_devices("org1", compliance_status="compliant")
    assert len(compliant) == 1
    assert compliant[0]["compliance_status"] == "compliant"


def test_list_devices_filter_combined(engine):
    engine.register_device("org1", {"device_name": "D1", "platform": "ios", "compliance_status": "compliant"})
    engine.register_device("org1", {"device_name": "D2", "platform": "android", "compliance_status": "compliant"})
    result = engine.list_devices("org1", platform="ios", compliance_status="compliant")
    assert len(result) == 1


# ------------------------------------------------------------------
# update_device_compliance
# ------------------------------------------------------------------

def test_update_device_compliance(engine):
    d = engine.register_device("org1", {"device_name": "D", "compliance_status": "unknown"})
    ok = engine.update_device_compliance("org1", d["device_id"], {
        "compliance_status": "non_compliant",
        "risk_score": 75,
        "jailbroken": True,
    })
    assert ok is True
    updated = engine.list_devices("org1")[0]
    assert updated["compliance_status"] == "non_compliant"
    assert updated["risk_score"] == 75
    assert updated["jailbroken"] is True


def test_update_device_compliance_wrong_org(engine):
    d = engine.register_device("org1", {"device_name": "D"})
    ok = engine.update_device_compliance("org2", d["device_id"], {"compliance_status": "compliant"})
    assert ok is False


def test_update_device_compliance_no_valid_fields(engine):
    d = engine.register_device("org1", {"device_name": "D"})
    ok = engine.update_device_compliance("org1", d["device_id"], {"bad_field": "value"})
    assert ok is False


# ------------------------------------------------------------------
# create_threat / list_threats
# ------------------------------------------------------------------

def test_create_threat_returns_dict(engine):
    d = engine.register_device("org1", {"device_name": "D", "platform": "android"})
    t = engine.create_threat("org1", {
        "device_id": d["device_id"],
        "threat_type": "malware",
        "severity": "high",
        "description": "Suspicious app detected",
    })
    assert t["threat_id"]
    assert t["threat_type"] == "malware"
    assert t["severity"] == "high"
    assert t["status"] == "active"
    assert t["created_at"]


def test_create_threat_invalid_type_defaults(engine):
    t = engine.create_threat("org1", {"device_id": "x", "threat_type": "unknown_threat"})
    assert t["threat_type"] == "malware"


def test_list_threats_empty(engine):
    assert engine.list_threats("org_none") == []


def test_list_threats_returns_org_threats(engine):
    d = engine.register_device("org1", {"device_name": "D"})
    engine.create_threat("org1", {"device_id": d["device_id"], "threat_type": "jailbreak", "severity": "critical"})
    engine.create_threat("org2", {"device_id": "other", "threat_type": "rooted"})
    threats = engine.list_threats("org1")
    assert len(threats) == 1
    assert threats[0]["threat_type"] == "jailbreak"


def test_list_threats_filter_by_severity(engine):
    d = engine.register_device("org1", {"device_name": "D"})
    engine.create_threat("org1", {"device_id": d["device_id"], "threat_type": "malware", "severity": "critical"})
    engine.create_threat("org1", {"device_id": d["device_id"], "threat_type": "outdated_os", "severity": "low"})
    critical = engine.list_threats("org1", severity="critical")
    assert len(critical) == 1
    assert critical[0]["severity"] == "critical"


# ------------------------------------------------------------------
# create_mdm_policy / list_mdm_policies
# ------------------------------------------------------------------

def test_create_mdm_policy_returns_dict(engine):
    p = engine.create_mdm_policy("org1", {
        "name": "Strict MDM",
        "require_encryption": True,
        "require_pin": True,
        "min_os_version": "17.0",
        "allow_jailbroken": False,
        "remote_wipe_enabled": True,
    })
    assert p["policy_id"]
    assert p["name"] == "Strict MDM"
    assert p["require_encryption"] is True
    assert p["require_pin"] is True
    assert p["allow_jailbroken"] is False
    assert p["remote_wipe_enabled"] is True
    assert p["min_os_version"] == "17.0"


def test_create_mdm_policy_bool_fields_are_bool(engine):
    p = engine.create_mdm_policy("org1", {"name": "P", "require_encryption": False})
    assert isinstance(p["require_encryption"], bool)
    assert isinstance(p["allow_jailbroken"], bool)


def test_list_mdm_policies_empty(engine):
    assert engine.list_mdm_policies("org_none") == []


def test_list_mdm_policies_org_isolation(engine):
    engine.create_mdm_policy("org1", {"name": "P1"})
    engine.create_mdm_policy("org2", {"name": "P2"})
    result = engine.list_mdm_policies("org1")
    assert len(result) == 1
    assert result[0]["name"] == "P1"
    listed_p = result[0]
    assert isinstance(listed_p["require_encryption"], bool)


def test_list_mdm_policies_multiple(engine):
    engine.create_mdm_policy("org1", {"name": "A"})
    engine.create_mdm_policy("org1", {"name": "B"})
    result = engine.list_mdm_policies("org1")
    assert len(result) == 2


# ------------------------------------------------------------------
# get_mobile_stats
# ------------------------------------------------------------------

def test_get_mobile_stats_empty(engine):
    stats = engine.get_mobile_stats("org_empty")
    assert stats["total_devices"] == 0
    assert stats["enrolled"] == 0
    assert stats["compliant"] == 0
    assert stats["non_compliant"] == 0
    assert stats["jailbroken_count"] == 0
    assert stats["active_threats"] == 0
    assert stats["by_platform"] == {}


def test_get_mobile_stats_counts(engine):
    engine.register_device("org1", {"device_name": "D1", "platform": "ios",
                                     "enrollment_status": "enrolled",
                                     "compliance_status": "compliant",
                                     "jailbroken": False})
    engine.register_device("org1", {"device_name": "D2", "platform": "android",
                                     "enrollment_status": "enrolled",
                                     "compliance_status": "non_compliant",
                                     "jailbroken": True})
    engine.register_device("org1", {"device_name": "D3", "platform": "android",
                                     "enrollment_status": "pending",
                                     "compliance_status": "unknown",
                                     "jailbroken": False})

    d1 = engine.list_devices("org1")[0]
    engine.create_threat("org1", {"device_id": d1["device_id"], "threat_type": "malware", "severity": "high"})
    engine.create_threat("org1", {"device_id": d1["device_id"], "threat_type": "rooted", "severity": "critical", "status": "remediated"})

    stats = engine.get_mobile_stats("org1")
    assert stats["total_devices"] == 3
    assert stats["enrolled"] == 2
    assert stats["compliant"] == 1
    assert stats["non_compliant"] == 1
    assert stats["jailbroken_count"] == 1
    assert stats["active_threats"] == 1
    assert stats["by_platform"]["ios"] == 1
    assert stats["by_platform"]["android"] == 2


# ------------------------------------------------------------------
# Org isolation
# ------------------------------------------------------------------

def test_org_isolation_devices(engine):
    engine.register_device("org1", {"device_name": "D1"})
    engine.register_device("org2", {"device_name": "D2"})
    assert len(engine.list_devices("org1")) == 1
    assert len(engine.list_devices("org2")) == 1


def test_org_isolation_threats(engine):
    engine.create_threat("org1", {"device_id": "d1", "threat_type": "malware"})
    engine.create_threat("org2", {"device_id": "d2", "threat_type": "jailbreak"})
    assert len(engine.list_threats("org1")) == 1
    assert len(engine.list_threats("org2")) == 1


def test_org_isolation_stats(engine):
    engine.register_device("org1", {"device_name": "D1", "enrollment_status": "enrolled"})
    engine.register_device("org2", {"device_name": "D2", "enrollment_status": "enrolled"})
    stats1 = engine.get_mobile_stats("org1")
    stats2 = engine.get_mobile_stats("org2")
    assert stats1["total_devices"] == 1
    assert stats2["total_devices"] == 1
