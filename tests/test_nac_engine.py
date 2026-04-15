"""Tests for NACEngine — Network Access Control.

Covers: init, device registration, posture checks, status updates,
policy creation/application, access event logging, stats, org isolation.
"""

from __future__ import annotations

import pytest

from core.nac_engine import (
    AccessEventCreate,
    DeviceCreate,
    NACEngine,
    PolicyCreate,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return NACEngine(db_path=str(tmp_path / "test_nac.db"))


def _laptop(hostname="laptop-01", **kw) -> DeviceCreate:
    return DeviceCreate(
        hostname=hostname,
        device_type="laptop",
        owner="alice",
        ip_address="10.0.0.10",
        mac_address="aa:bb:cc:dd:ee:ff",
        os_type="Windows 11",
        **kw,
    )


def _register(engine, org_id="org1", **kw) -> dict:
    return engine.register_device(org_id, _laptop(**kw))


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "nac.db"
    NACEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_idempotent(tmp_path):
    db = str(tmp_path / "nac.db")
    NACEngine(db_path=db)
    NACEngine(db_path=db)  # should not raise


# ---------------------------------------------------------------------------
# 2. Device registration
# ---------------------------------------------------------------------------


def test_register_device_returns_record(engine):
    device = _register(engine)
    assert device["hostname"] == "laptop-01"
    assert device["device_type"] == "laptop"
    assert device["status"] == "unknown"
    assert "device_id" in device


def test_register_device_generates_uuid(engine):
    d1 = _register(engine, hostname="a")
    d2 = _register(engine, hostname="b")
    assert d1["device_id"] != d2["device_id"]


def test_register_multiple_device_types(engine):
    for dtype in ("server", "mobile", "iot", "printer"):
        d = engine.register_device(
            "org1",
            DeviceCreate(hostname=f"dev-{dtype}", device_type=dtype),
        )
        assert d["device_type"] == dtype


# ---------------------------------------------------------------------------
# 3. List / get devices
# ---------------------------------------------------------------------------


def test_list_devices_empty(engine):
    assert engine.list_devices("org1") == []


def test_list_devices_returns_all(engine):
    _register(engine, hostname="a")
    _register(engine, hostname="b")
    assert len(engine.list_devices("org1")) == 2


def test_list_devices_filter_type(engine):
    _register(engine, hostname="lap")
    engine.register_device("org1", DeviceCreate(hostname="srv", device_type="server"))
    laptops = engine.list_devices("org1", device_type="laptop")
    assert all(d["device_type"] == "laptop" for d in laptops)
    assert len(laptops) == 1


def test_list_devices_filter_status(engine):
    device = _register(engine)
    engine.update_device_status("org1", device["device_id"], "compliant", "checked", "system")
    compliant = engine.list_devices("org1", status="compliant")
    assert len(compliant) == 1


def test_get_device_returns_correct(engine):
    d = _register(engine)
    fetched = engine.get_device("org1", d["device_id"])
    assert fetched["device_id"] == d["device_id"]


def test_get_device_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.get_device("org1", "nonexistent-id")


# ---------------------------------------------------------------------------
# 4. Posture checks
# ---------------------------------------------------------------------------


def test_posture_check_structure(engine):
    d = _register(engine)
    result = engine.run_posture_check("org1", d["device_id"])
    assert "device_id" in result
    assert "passed" in result
    assert isinstance(result["passed"], bool)
    assert 0.0 <= result["score"] <= 100.0
    assert isinstance(result["checks"], list)
    assert result["recommended_action"] in ("allow", "quarantine", "block")


def test_posture_check_has_four_checks(engine):
    d = _register(engine)
    result = engine.run_posture_check("org1", d["device_id"])
    names = {c["check_name"] for c in result["checks"]}
    assert names == {"os_patch_level", "av_status", "disk_encryption", "certificate_validity"}


def test_posture_check_each_check_has_result_and_details(engine):
    d = _register(engine)
    result = engine.run_posture_check("org1", d["device_id"])
    for c in result["checks"]:
        assert c["result"] in ("pass", "fail", "warning")
        assert isinstance(c["details"], str)


def test_posture_check_laptop_with_full_data_passes(engine):
    d = _register(engine)
    result = engine.run_posture_check("org1", d["device_id"])
    assert result["passed"] is True
    assert result["recommended_action"] == "allow"


def test_posture_check_device_without_ip_mac_gets_cert_fail(engine):
    d = engine.register_device("org1", DeviceCreate(hostname="bare", device_type="laptop"))
    result = engine.run_posture_check("org1", d["device_id"])
    cert = next(c for c in result["checks"] if c["check_name"] == "certificate_validity")
    assert cert["result"] == "fail"


def test_posture_check_iot_device_av_warning(engine):
    d = engine.register_device("org1", DeviceCreate(hostname="cam01", device_type="iot",
                                                     ip_address="10.0.1.1",
                                                     mac_address="11:22:33:44:55:66"))
    result = engine.run_posture_check("org1", d["device_id"])
    av = next(c for c in result["checks"] if c["check_name"] == "av_status")
    assert av["result"] == "warning"


def test_posture_check_persisted(engine):
    d = _register(engine)
    engine.run_posture_check("org1", d["device_id"])
    # Run again — should not raise, both stored
    engine.run_posture_check("org1", d["device_id"])


# ---------------------------------------------------------------------------
# 5. Status updates
# ---------------------------------------------------------------------------


def test_update_status_compliant(engine):
    d = _register(engine)
    updated = engine.update_device_status("org1", d["device_id"], "compliant", "passed checks", "admin")
    assert updated["status"] == "compliant"


def test_update_status_quarantined(engine):
    d = _register(engine)
    updated = engine.update_device_status("org1", d["device_id"], "quarantined", "failed AV", "system")
    assert updated["status"] == "quarantined"


def test_update_status_invalid_raises(engine):
    d = _register(engine)
    with pytest.raises(ValueError, match="Invalid status"):
        engine.update_device_status("org1", d["device_id"], "hacked", "bad", "admin")


def test_update_status_wrong_org_raises(engine):
    d = _register(engine, org_id="org1")
    with pytest.raises(ValueError):
        engine.update_device_status("org2", d["device_id"], "compliant", "x", "admin")


# ---------------------------------------------------------------------------
# 6. Policy management
# ---------------------------------------------------------------------------


def test_create_policy_returns_record(engine):
    p = engine.create_policy("org1", PolicyCreate(name="Laptop Policy", device_types=["laptop"],
                                                   required_checks=["os_patch_level"],
                                                   vlan_on_pass="vlan100",
                                                   vlan_on_fail="vlan999",
                                                   action_on_fail="quarantine"))
    assert p["name"] == "Laptop Policy"
    assert p["vlan_on_pass"] == "vlan100"
    assert "policy_id" in p


def test_list_policies_empty(engine):
    assert engine.list_policies("org1") == []


def test_list_policies_returns_created(engine):
    engine.create_policy("org1", PolicyCreate(name="P1"))
    engine.create_policy("org1", PolicyCreate(name="P2"))
    policies = engine.list_policies("org1")
    assert len(policies) == 2


def test_policy_device_types_deserialized(engine):
    engine.create_policy("org1", PolicyCreate(name="P", device_types=["laptop", "mobile"]))
    p = engine.list_policies("org1")[0]
    assert isinstance(p["device_types"], list)
    assert "laptop" in p["device_types"]


# ---------------------------------------------------------------------------
# 7. Policy application
# ---------------------------------------------------------------------------


def test_apply_policy_allow_for_compliant_laptop(engine):
    d = _register(engine)
    p = engine.create_policy("org1", PolicyCreate(name="Std", device_types=["laptop"],
                                                   vlan_on_pass="vlan10",
                                                   vlan_on_fail="vlan99",
                                                   action_on_fail="quarantine"))
    result = engine.apply_policy("org1", d["device_id"], p["policy_id"])
    assert result["device_id"] == d["device_id"]
    assert result["policy_id"] == p["policy_id"]
    assert result["decision"] in ("allow", "quarantine", "block")
    assert "vlan" in result
    assert "reason" in result


def test_apply_policy_out_of_scope_device_type_allows(engine):
    d = engine.register_device("org1", DeviceCreate(hostname="srv", device_type="server"))
    p = engine.create_policy("org1", PolicyCreate(name="LaptopsOnly", device_types=["laptop"]))
    result = engine.apply_policy("org1", d["device_id"], p["policy_id"])
    assert result["decision"] == "allow"
    assert "not in policy scope" in result["reason"]


def test_apply_policy_missing_policy_raises(engine):
    d = _register(engine)
    with pytest.raises(ValueError):
        engine.apply_policy("org1", d["device_id"], "nonexistent-policy-id")


def test_apply_policy_posture_score_in_result(engine):
    d = _register(engine)
    p = engine.create_policy("org1", PolicyCreate(name="Std"))
    result = engine.apply_policy("org1", d["device_id"], p["policy_id"])
    assert "posture_score" in result
    assert isinstance(result["posture_score"], float)


# ---------------------------------------------------------------------------
# 8. Access events
# ---------------------------------------------------------------------------


def test_record_access_event(engine):
    d = _register(engine)
    ev = engine.record_access_event("org1", AccessEventCreate(
        device_id=d["device_id"], event_type="connect",
        location="HQ-Floor2", switch_port="Gi1/0/12",
    ))
    assert ev["event_type"] == "connect"
    assert ev["device_id"] == d["device_id"]
    assert "event_id" in ev


def test_record_event_with_details(engine):
    d = _register(engine)
    ev = engine.record_access_event("org1", AccessEventCreate(
        device_id=d["device_id"], event_type="quarantine",
        details={"reason": "AV failure", "severity": "high"},
    ))
    assert isinstance(ev["details"], dict)
    assert ev["details"]["severity"] == "high"


def test_record_event_wrong_device_raises(engine):
    with pytest.raises(ValueError):
        engine.record_access_event("org1", AccessEventCreate(
            device_id="bad-id", event_type="connect",
        ))


def test_list_access_events_empty(engine):
    assert engine.list_access_events("org1") == []


def test_list_access_events_returns_all(engine):
    d = _register(engine)
    for etype in ("connect", "disconnect", "quarantine"):
        engine.record_access_event("org1", AccessEventCreate(
            device_id=d["device_id"], event_type=etype,
        ))
    events = engine.list_access_events("org1")
    assert len(events) == 3


def test_list_access_events_filter_device(engine):
    d1 = _register(engine, hostname="a")
    d2 = _register(engine, hostname="b")
    engine.record_access_event("org1", AccessEventCreate(device_id=d1["device_id"], event_type="connect"))
    engine.record_access_event("org1", AccessEventCreate(device_id=d2["device_id"], event_type="connect"))
    events = engine.list_access_events("org1", device_id=d1["device_id"])
    assert len(events) == 1
    assert events[0]["device_id"] == d1["device_id"]


def test_list_access_events_limit(engine):
    d = _register(engine)
    for _ in range(10):
        engine.record_access_event("org1", AccessEventCreate(device_id=d["device_id"], event_type="connect"))
    events = engine.list_access_events("org1", limit=5)
    assert len(events) == 5


# ---------------------------------------------------------------------------
# 9. Stats
# ---------------------------------------------------------------------------


def test_get_nac_stats_empty_org(engine):
    stats = engine.get_nac_stats("org1")
    assert stats["total_devices"] == 0
    assert stats["compliant_pct"] == 0.0
    assert stats["quarantined_count"] == 0
    assert stats["events_24h"] == 0
    assert stats["policy_count"] == 0
    assert isinstance(stats["by_status"], dict)
    assert isinstance(stats["by_device_type"], dict)


def test_get_nac_stats_with_devices(engine):
    d1 = _register(engine, hostname="a")
    d2 = _register(engine, hostname="b")
    engine.update_device_status("org1", d1["device_id"], "compliant", "ok", "system")
    engine.update_device_status("org1", d2["device_id"], "quarantined", "fail", "system")

    stats = engine.get_nac_stats("org1")
    assert stats["total_devices"] == 2
    assert stats["by_status"]["compliant"] == 1
    assert stats["by_status"]["quarantined"] == 1
    assert stats["quarantined_count"] == 1
    assert stats["compliant_pct"] == 50.0


def test_get_nac_stats_policy_count(engine):
    engine.create_policy("org1", PolicyCreate(name="P1"))
    engine.create_policy("org1", PolicyCreate(name="P2"))
    stats = engine.get_nac_stats("org1")
    assert stats["policy_count"] == 2


def test_get_nac_stats_events_24h(engine):
    d = _register(engine)
    engine.record_access_event("org1", AccessEventCreate(device_id=d["device_id"], event_type="connect"))
    stats = engine.get_nac_stats("org1")
    assert stats["events_24h"] == 1


def test_get_nac_stats_by_device_type(engine):
    _register(engine, hostname="lap1")
    engine.register_device("org1", DeviceCreate(hostname="srv1", device_type="server"))
    stats = engine.get_nac_stats("org1")
    assert stats["by_device_type"]["laptop"] == 1
    assert stats["by_device_type"]["server"] == 1


# ---------------------------------------------------------------------------
# 10. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_devices(engine):
    engine.register_device("org1", DeviceCreate(hostname="org1-host"))
    engine.register_device("org2", DeviceCreate(hostname="org2-host"))
    assert len(engine.list_devices("org1")) == 1
    assert len(engine.list_devices("org2")) == 1


def test_org_isolation_get_device(engine):
    d = engine.register_device("org1", DeviceCreate(hostname="host"))
    with pytest.raises(ValueError):
        engine.get_device("org2", d["device_id"])


def test_org_isolation_events(engine):
    d1 = engine.register_device("org1", DeviceCreate(hostname="h1"))
    d2 = engine.register_device("org2", DeviceCreate(hostname="h2"))
    engine.record_access_event("org1", AccessEventCreate(device_id=d1["device_id"], event_type="connect"))
    engine.record_access_event("org2", AccessEventCreate(device_id=d2["device_id"], event_type="connect"))
    assert len(engine.list_access_events("org1")) == 1
    assert len(engine.list_access_events("org2")) == 1


def test_org_isolation_policies(engine):
    engine.create_policy("org1", PolicyCreate(name="P-org1"))
    assert engine.list_policies("org2") == []


def test_org_isolation_stats(engine):
    _register(engine, org_id="org1")
    stats = engine.get_nac_stats("org2")
    assert stats["total_devices"] == 0
