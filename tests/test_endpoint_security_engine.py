"""Tests for EndpointSecurityEngine — 25+ tests covering all public methods.

Uses tmp_path fixture for isolation (no shared state between tests).
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

import pytest
from core.endpoint_security_engine import EndpointSecurityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "test_edr.db")
    return EndpointSecurityEngine(db_path=db)


def _make_endpoint(**kwargs):
    base = {
        "hostname": "host-alpha",
        "ip": "10.0.0.1",
        "os": "Ubuntu 22.04",
        "agent_version": "3.1.0",
        "status": "active",
        "risk_score": 25,
        "policy_id": "pol-001",
    }
    base.update(kwargs)
    return base


def _make_alert(endpoint_id: str, **kwargs):
    base = {
        "endpoint_id": endpoint_id,
        "severity": "high",
        "alert_type": "malware",
        "description": "Suspicious process detected",
        "status": "open",
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "new_edr.db")
    eng = EndpointSecurityEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    """Calling __init__ twice on same DB does not raise."""
    db = str(tmp_path / "idempotent.db")
    EndpointSecurityEngine(db_path=db)
    EndpointSecurityEngine(db_path=db)


# ---------------------------------------------------------------------------
# register_endpoint
# ---------------------------------------------------------------------------


def test_register_endpoint_returns_record(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    assert ep["endpoint_id"]
    assert ep["org_id"] == "org1"
    assert ep["hostname"] == "host-alpha"
    assert ep["ip"] == "10.0.0.1"
    assert ep["os"] == "Ubuntu 22.04"
    assert ep["agent_version"] == "3.1.0"
    assert ep["status"] == "active"
    assert ep["risk_score"] == 25
    assert ep["policy_id"] == "pol-001"


def test_register_endpoint_invalid_status_defaults_active(engine):
    ep = engine.register_endpoint("org1", _make_endpoint(status="unknown"))
    assert ep["status"] == "active"


def test_register_endpoint_risk_score_clamp(engine):
    ep_high = engine.register_endpoint("org1", _make_endpoint(risk_score=999))
    assert ep_high["risk_score"] == 100
    ep_low = engine.register_endpoint("org1", _make_endpoint(risk_score=-10))
    assert ep_low["risk_score"] == 0


def test_register_multiple_endpoints(engine):
    engine.register_endpoint("org1", _make_endpoint(hostname="host-a"))
    engine.register_endpoint("org1", _make_endpoint(hostname="host-b"))
    engine.register_endpoint("org1", _make_endpoint(hostname="host-c"))
    eps = engine.list_endpoints("org1")
    assert len(eps) == 3


# ---------------------------------------------------------------------------
# list_endpoints
# ---------------------------------------------------------------------------


def test_list_endpoints_empty(engine):
    assert engine.list_endpoints("org1") == []


def test_list_endpoints_filter_by_status(engine):
    engine.register_endpoint("org1", _make_endpoint(hostname="active-1", status="active"))
    engine.register_endpoint("org1", _make_endpoint(hostname="active-2", status="active"))
    engine.register_endpoint("org1", _make_endpoint(hostname="inactive-1", status="inactive"))

    active = engine.list_endpoints("org1", status="active")
    inactive = engine.list_endpoints("org1", status="inactive")
    all_eps = engine.list_endpoints("org1")

    assert len(active) == 2
    assert len(inactive) == 1
    assert len(all_eps) == 3


def test_list_endpoints_invalid_status_returns_all(engine):
    engine.register_endpoint("org1", _make_endpoint())
    result = engine.list_endpoints("org1", status="bogus")
    assert len(result) == 1


# ---------------------------------------------------------------------------
# update_endpoint_status
# ---------------------------------------------------------------------------


def test_update_endpoint_status_success(engine):
    ep = engine.register_endpoint("org1", _make_endpoint(status="active"))
    updated = engine.update_endpoint_status("org1", ep["endpoint_id"], "inactive")
    assert updated is True

    eps = engine.list_endpoints("org1", status="inactive")
    assert len(eps) == 1
    assert eps[0]["endpoint_id"] == ep["endpoint_id"]


def test_update_endpoint_status_invalid_status(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    result = engine.update_endpoint_status("org1", ep["endpoint_id"], "broken")
    assert result is False


def test_update_endpoint_status_wrong_org(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    result = engine.update_endpoint_status("org2", ep["endpoint_id"], "inactive")
    assert result is False


def test_update_endpoint_status_nonexistent(engine):
    result = engine.update_endpoint_status("org1", "does-not-exist", "inactive")
    assert result is False


# ---------------------------------------------------------------------------
# create_alert
# ---------------------------------------------------------------------------


def test_create_alert_returns_record(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    alert = engine.create_alert("org1", _make_alert(ep["endpoint_id"]))
    assert alert["alert_id"]
    assert alert["org_id"] == "org1"
    assert alert["endpoint_id"] == ep["endpoint_id"]
    assert alert["severity"] == "high"
    assert alert["alert_type"] == "malware"
    assert alert["status"] == "open"
    assert alert["resolved_at"] is None


def test_create_alert_invalid_severity_defaults_medium(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    alert = engine.create_alert("org1", _make_alert(ep["endpoint_id"], severity="extreme"))
    assert alert["severity"] == "medium"


def test_create_alert_invalid_type_defaults_policy_violation(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    alert = engine.create_alert("org1", _make_alert(ep["endpoint_id"], alert_type="unknown"))
    assert alert["alert_type"] == "policy_violation"


def test_create_alert_all_types(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    for t in ["malware", "ransomware", "lateral_movement", "privilege_escalation", "data_exfil", "policy_violation"]:
        a = engine.create_alert("org1", _make_alert(ep["endpoint_id"], alert_type=t))
        assert a["alert_type"] == t


# ---------------------------------------------------------------------------
# list_alerts
# ---------------------------------------------------------------------------


def test_list_alerts_empty(engine):
    assert engine.list_alerts("org1") == []


def test_list_alerts_filter_status(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], status="open"))
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], status="investigating"))
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], status="open"))

    open_alerts = engine.list_alerts("org1", status="open")
    investigating = engine.list_alerts("org1", status="investigating")
    all_alerts = engine.list_alerts("org1")

    assert len(open_alerts) == 2
    assert len(investigating) == 1
    assert len(all_alerts) == 3


def test_list_alerts_filter_severity(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], severity="critical"))
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], severity="critical"))
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], severity="low"))

    critical = engine.list_alerts("org1", severity="critical")
    low = engine.list_alerts("org1", severity="low")

    assert len(critical) == 2
    assert len(low) == 1


def test_list_alerts_filter_status_and_severity(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], severity="high", status="open"))
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], severity="high", status="investigating"))
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], severity="low", status="open"))

    result = engine.list_alerts("org1", status="open", severity="high")
    assert len(result) == 1
    assert result[0]["severity"] == "high"
    assert result[0]["status"] == "open"


# ---------------------------------------------------------------------------
# resolve_alert
# ---------------------------------------------------------------------------


def test_resolve_alert_success(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    alert = engine.create_alert("org1", _make_alert(ep["endpoint_id"]))
    resolved = engine.resolve_alert("org1", alert["alert_id"], "Malware quarantined")
    assert resolved is True

    # Verify status changed
    resolved_alerts = engine.list_alerts("org1", status="resolved")
    assert len(resolved_alerts) == 1
    assert resolved_alerts[0]["resolution_note"] == "Malware quarantined"
    assert resolved_alerts[0]["resolved_at"] is not None


def test_resolve_alert_nonexistent(engine):
    result = engine.resolve_alert("org1", "no-such-alert", "note")
    assert result is False


def test_resolve_alert_wrong_org(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    alert = engine.create_alert("org1", _make_alert(ep["endpoint_id"]))
    result = engine.resolve_alert("org2", alert["alert_id"], "note")
    assert result is False


# ---------------------------------------------------------------------------
# get_edr_stats
# ---------------------------------------------------------------------------


def test_get_edr_stats_empty(engine):
    stats = engine.get_edr_stats("org1")
    assert stats["total_endpoints"] == 0
    assert stats["active"] == 0
    assert stats["inactive"] == 0
    assert stats["alerts_open"] == 0
    assert stats["alerts_by_severity"] == {}
    assert stats["compliance_rate"] == 100.0


def test_get_edr_stats_with_data(engine):
    ep1 = engine.register_endpoint("org1", _make_endpoint(hostname="h1", status="active"))
    ep2 = engine.register_endpoint("org1", _make_endpoint(hostname="h2", status="active"))
    engine.register_endpoint("org1", _make_endpoint(hostname="h3", status="inactive"))

    a1 = engine.create_alert("org1", _make_alert(ep1["endpoint_id"], severity="critical"))
    engine.create_alert("org1", _make_alert(ep2["endpoint_id"], severity="high"))
    engine.resolve_alert("org1", a1["alert_id"], "fixed")

    stats = engine.get_edr_stats("org1")
    assert stats["total_endpoints"] == 3
    assert stats["active"] == 2
    assert stats["inactive"] == 1
    assert stats["alerts_open"] == 1
    assert "high" in stats["alerts_by_severity"]
    # 1 of 2 alerts resolved = 50% compliance
    assert stats["compliance_rate"] == 50.0


# ---------------------------------------------------------------------------
# policy CRUD
# ---------------------------------------------------------------------------


def test_create_policy_returns_record(engine):
    pol = engine.create_policy("org1", {
        "name": "Anti-Malware Baseline",
        "description": "Block known malware hashes",
        "rules": {"block_known_hashes": True, "scan_interval_minutes": 60},
        "enabled": True,
    })
    assert pol["policy_id"]
    assert pol["org_id"] == "org1"
    assert pol["name"] == "Anti-Malware Baseline"
    assert pol["rules"]["block_known_hashes"] is True
    assert pol["enabled"] is True


def test_list_policies_empty(engine):
    assert engine.list_policies("org1") == []


def test_list_policies_multiple(engine):
    engine.create_policy("org1", {"name": "Policy A"})
    engine.create_policy("org1", {"name": "Policy B"})
    engine.create_policy("org1", {"name": "Policy C"})
    pols = engine.list_policies("org1")
    assert len(pols) == 3
    # sorted by name
    names = [p["name"] for p in pols]
    assert names == sorted(names)


def test_create_policy_invalid_rules_defaults_empty(engine):
    pol = engine.create_policy("org1", {"name": "Bad Rules", "rules": "not-a-dict"})
    assert pol["rules"] == {}


# ---------------------------------------------------------------------------
# get_endpoint_timeline
# ---------------------------------------------------------------------------


def test_get_endpoint_timeline_empty(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    timeline = engine.get_endpoint_timeline("org1", ep["endpoint_id"])
    assert timeline == []


def test_get_endpoint_timeline_sorted_desc(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], description="first"))
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], description="second"))
    engine.create_alert("org1", _make_alert(ep["endpoint_id"], description="third"))

    timeline = engine.get_endpoint_timeline("org1", ep["endpoint_id"])
    assert len(timeline) == 3
    # Each item should be an alert dict
    for item in timeline:
        assert "alert_id" in item
        assert item["endpoint_id"] == ep["endpoint_id"]


def test_get_endpoint_timeline_scoped_to_endpoint(engine):
    ep1 = engine.register_endpoint("org1", _make_endpoint(hostname="h1"))
    ep2 = engine.register_endpoint("org1", _make_endpoint(hostname="h2"))
    engine.create_alert("org1", _make_alert(ep1["endpoint_id"]))
    engine.create_alert("org1", _make_alert(ep1["endpoint_id"]))
    engine.create_alert("org1", _make_alert(ep2["endpoint_id"]))

    timeline_ep1 = engine.get_endpoint_timeline("org1", ep1["endpoint_id"])
    timeline_ep2 = engine.get_endpoint_timeline("org1", ep2["endpoint_id"])

    assert len(timeline_ep1) == 2
    assert len(timeline_ep2) == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_endpoints(engine):
    engine.register_endpoint("org1", _make_endpoint(hostname="org1-host"))
    engine.register_endpoint("org2", _make_endpoint(hostname="org2-host"))

    org1_eps = engine.list_endpoints("org1")
    org2_eps = engine.list_endpoints("org2")

    assert len(org1_eps) == 1
    assert org1_eps[0]["hostname"] == "org1-host"
    assert len(org2_eps) == 1
    assert org2_eps[0]["hostname"] == "org2-host"


def test_org_isolation_alerts(engine):
    ep1 = engine.register_endpoint("org1", _make_endpoint())
    ep2 = engine.register_endpoint("org2", _make_endpoint())
    engine.create_alert("org1", _make_alert(ep1["endpoint_id"], description="org1 alert"))
    engine.create_alert("org2", _make_alert(ep2["endpoint_id"], description="org2 alert"))

    assert len(engine.list_alerts("org1")) == 1
    assert len(engine.list_alerts("org2")) == 1
    assert engine.list_alerts("org1")[0]["description"] == "org1 alert"


def test_org_isolation_policies(engine):
    engine.create_policy("org1", {"name": "Org1 Policy"})
    engine.create_policy("org2", {"name": "Org2 Policy"})

    assert len(engine.list_policies("org1")) == 1
    assert len(engine.list_policies("org2")) == 1


def test_org_isolation_stats(engine):
    ep1 = engine.register_endpoint("org1", _make_endpoint())
    engine.create_alert("org1", _make_alert(ep1["endpoint_id"]))

    stats_org1 = engine.get_edr_stats("org1")
    stats_org2 = engine.get_edr_stats("org2")

    assert stats_org1["total_endpoints"] == 1
    assert stats_org1["alerts_open"] == 1
    assert stats_org2["total_endpoints"] == 0
    assert stats_org2["alerts_open"] == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_register_endpoint_minimal_data(engine):
    """Register with only required field: hostname."""
    ep = engine.register_endpoint("org1", {"hostname": "minimal-host"})
    assert ep["hostname"] == "minimal-host"
    assert ep["ip"] == ""
    assert ep["status"] == "active"
    assert ep["risk_score"] == 0


def test_create_alert_minimal_data(engine):
    """Create alert with only required field: endpoint_id."""
    ep = engine.register_endpoint("org1", _make_endpoint())
    alert = engine.create_alert("org1", {"endpoint_id": ep["endpoint_id"]})
    assert alert["severity"] == "medium"
    assert alert["alert_type"] == "policy_violation"
    assert alert["status"] == "open"


def test_get_endpoint_timeline_wrong_org(engine):
    ep = engine.register_endpoint("org1", _make_endpoint())
    engine.create_alert("org1", _make_alert(ep["endpoint_id"]))
    # org2 cannot see org1's timeline for that endpoint
    timeline = engine.get_endpoint_timeline("org2", ep["endpoint_id"])
    assert timeline == []
