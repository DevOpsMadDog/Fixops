"""Tests for UBAEngine — User Behavior Analytics.

25 tests covering init, user CRUD, event ingestion, risk analysis,
alerts lifecycle, stats, and multi-tenant org isolation.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone

import pytest

from core.uba_engine import UBAEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "test_uba.db")


@pytest.fixture()
def engine(db_path):
    return UBAEngine(db_path=db_path)


@pytest.fixture()
def org(engine):
    """Return an org_id with one registered user."""
    oid = "org-test-001"
    user = engine.register_user(oid, {
        "username": "alice",
        "department": "engineering",
        "role": "developer",
        "manager": "bob",
    })
    return oid, user["user_id"]


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_engine_init_creates_db(db_path):
    eng = UBAEngine(db_path=db_path)
    assert os.path.exists(db_path)


def test_engine_init_idempotent(db_path):
    """Creating the engine twice should not raise."""
    UBAEngine(db_path=db_path)
    UBAEngine(db_path=db_path)


# ---------------------------------------------------------------------------
# 2. User registration and listing
# ---------------------------------------------------------------------------

def test_register_user_returns_dict(engine):
    user = engine.register_user("org1", {"username": "alice", "department": "hr"})
    assert user["username"] == "alice"
    assert user["risk_score"] == 0
    assert user["status"] == "active"
    assert "user_id" in user


def test_register_user_requires_username(engine):
    with pytest.raises(ValueError, match="username"):
        engine.register_user("org1", {})


def test_register_user_default_status_active(engine):
    user = engine.register_user("org1", {"username": "bob"})
    assert user["status"] == "active"


def test_list_users_empty(engine):
    assert engine.list_users("org-empty") == []


def test_list_users_returns_registered(engine, org):
    oid, uid = org
    users = engine.list_users(oid)
    assert any(u["user_id"] == uid for u in users)


def test_list_users_filter_status(engine):
    oid = "org-status"
    engine.register_user(oid, {"username": "active1"})
    engine.register_user(oid, {"username": "term1", "status": "terminated"})
    active = engine.list_users(oid, status="active")
    assert all(u["status"] == "active" for u in active)
    terminated = engine.list_users(oid, status="terminated")
    assert all(u["status"] == "terminated" for u in terminated)


def test_list_users_filter_min_risk_score(engine):
    oid = "org-risk"
    engine.register_user(oid, {"username": "user1"})
    # All start at 0, so min_risk_score=1 returns nothing
    result = engine.list_users(oid, min_risk_score=1)
    assert result == []


# ---------------------------------------------------------------------------
# 3. Event ingestion
# ---------------------------------------------------------------------------

def test_ingest_event_returns_dict(engine, org):
    oid, uid = org
    evt = engine.ingest_event(oid, {
        "user_id": uid,
        "event_type": "login",
        "source_ip": "10.0.0.1",
        "device": "laptop-01",
    })
    assert evt["event_type"] == "login"
    assert "event_id" in evt
    assert evt["is_anomalous"] is False


def test_ingest_event_requires_user_id(engine, org):
    oid, _ = org
    with pytest.raises(ValueError, match="user_id"):
        engine.ingest_event(oid, {"event_type": "login"})


def test_ingest_event_invalid_type(engine, org):
    oid, uid = org
    with pytest.raises(ValueError, match="event_type"):
        engine.ingest_event(oid, {"user_id": uid, "event_type": "INVALID"})


def test_ingest_event_anomalous_flag(engine, org):
    oid, uid = org
    evt = engine.ingest_event(oid, {
        "user_id": uid,
        "event_type": "data_download",
        "is_anomalous": True,
        "bytes_transferred": 2_000_000_000,
    })
    assert evt["is_anomalous"] is True
    assert evt["bytes_transferred"] == 2_000_000_000


def test_list_events_filter_by_user(engine, org):
    oid, uid = org
    engine.ingest_event(oid, {"user_id": uid, "event_type": "login"})
    events = engine.list_events(oid, user_id=uid)
    assert len(events) >= 1
    assert all(e["user_id"] == uid for e in events)


def test_list_events_filter_by_anomalous(engine, org):
    oid, uid = org
    engine.ingest_event(oid, {"user_id": uid, "event_type": "login", "is_anomalous": True})
    engine.ingest_event(oid, {"user_id": uid, "event_type": "login", "is_anomalous": False})
    anomalous = engine.list_events(oid, is_anomalous=True)
    assert all(e["is_anomalous"] for e in anomalous)


# ---------------------------------------------------------------------------
# 4. Risk analysis
# ---------------------------------------------------------------------------

def test_analyze_user_returns_dict(engine, org):
    oid, uid = org
    result = engine.analyze_user(oid, uid)
    assert "risk_score" in result
    assert "indicators" in result
    assert "peer_comparison" in result


def test_analyze_user_not_found(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.analyze_user("org1", "nonexistent-uid")


def test_analyze_user_increases_risk_for_usb(engine, org):
    oid, uid = org
    for _ in range(3):
        engine.ingest_event(oid, {"user_id": uid, "event_type": "usb_use"})
    result = engine.analyze_user(oid, uid)
    assert result["indicators"]["usb_events"] == 3
    assert result["risk_score"] > 0


def test_analyze_user_peer_comparison(engine):
    oid = "org-peer"
    u1 = engine.register_user(oid, {"username": "p1", "department": "ops"})
    u2 = engine.register_user(oid, {"username": "p2", "department": "ops"})
    # Inflate u1's score
    for _ in range(3):
        engine.ingest_event(oid, {"user_id": u1["user_id"], "event_type": "privilege_use"})
    result = engine.analyze_user(oid, u1["user_id"])
    assert "delta" in result["peer_comparison"]


# ---------------------------------------------------------------------------
# 5. Alerts
# ---------------------------------------------------------------------------

def test_create_alert_returns_dict(engine, org):
    oid, uid = org
    alert = engine.create_alert(oid, uid, "anomalous_download", "high", "Large download detected")
    assert alert["alert_id"]
    assert alert["status"] == "open"
    assert alert["severity"] == "high"


def test_create_alert_invalid_severity(engine, org):
    oid, uid = org
    with pytest.raises(ValueError, match="severity"):
        engine.create_alert(oid, uid, "type", "INVALID", "desc")


def test_list_alerts_filter_status(engine, org):
    oid, uid = org
    engine.create_alert(oid, uid, "type1", "medium", "desc")
    alerts = engine.list_alerts(oid, status="open")
    assert all(a["status"] == "open" for a in alerts)


def test_update_alert_status(engine, org):
    oid, uid = org
    alert = engine.create_alert(oid, uid, "type1", "low", "desc")
    result = engine.update_alert_status(oid, alert["alert_id"], "resolved")
    assert result is True
    updated = engine.list_alerts(oid, status="resolved")
    assert any(a["alert_id"] == alert["alert_id"] for a in updated)


def test_update_alert_status_invalid(engine, org):
    oid, uid = org
    alert = engine.create_alert(oid, uid, "type1", "low", "desc")
    with pytest.raises(ValueError, match="status"):
        engine.update_alert_status(oid, alert["alert_id"], "INVALID")


# ---------------------------------------------------------------------------
# 6. Stats
# ---------------------------------------------------------------------------

def test_get_uba_stats_structure(engine, org):
    oid, uid = org
    stats = engine.get_uba_stats(oid)
    assert "total_users" in stats
    assert "high_risk_count" in stats
    assert "alerts_open" in stats
    assert "anomalous_events_today" in stats
    assert "top_risk_users" in stats
    assert isinstance(stats["top_risk_users"], list)


def test_get_uba_stats_counts(engine, org):
    oid, uid = org
    engine.create_alert(oid, uid, "type", "high", "desc")
    engine.ingest_event(oid, {"user_id": uid, "event_type": "login", "is_anomalous": True})
    stats = engine.get_uba_stats(oid)
    assert stats["total_users"] >= 1
    assert stats["alerts_open"] >= 1
    assert stats["anomalous_events_today"] >= 1


# ---------------------------------------------------------------------------
# 7. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_users(engine):
    engine.register_user("org-a", {"username": "alice"})
    engine.register_user("org-b", {"username": "bob"})
    a_users = engine.list_users("org-a")
    b_users = engine.list_users("org-b")
    assert all(u["org_id"] == "org-a" for u in a_users)
    assert all(u["org_id"] == "org-b" for u in b_users)


def test_org_isolation_events(engine):
    ua = engine.register_user("org-a", {"username": "alice"})
    engine.ingest_event("org-a", {"user_id": ua["user_id"], "event_type": "login"})
    events_b = engine.list_events("org-b")
    assert events_b == []


def test_org_isolation_alerts(engine):
    u = engine.register_user("org-a", {"username": "alice"})
    engine.create_alert("org-a", u["user_id"], "type", "low", "desc")
    assert engine.list_alerts("org-b") == []
