"""Tests for ITDREngine — ALDECI (Identity Threat Detection and Response)."""

from __future__ import annotations

import pytest

from core.itdr_engine import ITDREngine


@pytest.fixture
def engine(tmp_path):
    return ITDREngine(db_path=str(tmp_path / "itdr.db"))


# ---------------------------------------------------------------------------
# detect_threat — valid types
# ---------------------------------------------------------------------------

VALID_THREAT_TYPES = [
    "credential_stuffing",
    "account_takeover",
    "privilege_abuse",
    "lateral_movement",
    "impossible_travel",
    "mfa_bypass",
    "session_hijacking",
    "password_spray",
]


@pytest.mark.parametrize("threat_type", VALID_THREAT_TYPES)
def test_detect_threat_all_valid_types(engine, threat_type):
    t = engine.detect_threat("org1", {
        "threat_type": threat_type,
        "user_id": "user@acme.com",
        "severity": "high",
        "confidence": 85.0,
    })
    assert t["threat_type"] == threat_type
    assert t["status"] == "detected"
    assert t["org_id"] == "org1"
    assert "id" in t
    assert "detected_at" in t
    assert "updated_at" in t


def test_detect_threat_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="threat_type"):
        engine.detect_threat("org1", {
            "threat_type": "brute_force_xyz",
            "user_id": "user@acme.com",
        })


def test_detect_threat_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.detect_threat("org1", {
            "threat_type": "account_takeover",
            "user_id": "user@acme.com",
            "severity": "ultra",
        })


def test_detect_threat_missing_user_id_raises(engine):
    with pytest.raises(ValueError, match="user_id"):
        engine.detect_threat("org1", {
            "threat_type": "password_spray",
            "user_id": "",
        })


def test_detect_threat_confidence_clamped(engine):
    t = engine.detect_threat("org1", {
        "threat_type": "mfa_bypass",
        "user_id": "user1",
        "confidence": 150.0,
    })
    assert t["confidence"] == 100.0

    t2 = engine.detect_threat("org1", {
        "threat_type": "mfa_bypass",
        "user_id": "user2",
        "confidence": -10.0,
    })
    assert t2["confidence"] == 0.0


def test_detect_threat_indicators_stored(engine):
    indicators = ["192.168.1.1", "tor_exit_node", "known_bad_asn"]
    t = engine.detect_threat("org1", {
        "threat_type": "credential_stuffing",
        "user_id": "user@acme.com",
        "indicators": indicators,
    })
    assert isinstance(t["indicators"], list)
    assert t["indicators"] == indicators


# ---------------------------------------------------------------------------
# list_threats
# ---------------------------------------------------------------------------

def test_list_threats_empty(engine):
    assert engine.list_threats("org1") == []


def test_list_threats_returns_all(engine):
    for tt in ["account_takeover", "mfa_bypass"]:
        engine.detect_threat("org1", {"threat_type": tt, "user_id": "u1"})
    assert len(engine.list_threats("org1")) == 2


def test_list_threats_filter_by_type(engine):
    engine.detect_threat("org1", {"threat_type": "account_takeover", "user_id": "u1"})
    engine.detect_threat("org1", {"threat_type": "password_spray", "user_id": "u2"})
    result = engine.list_threats("org1", threat_type="account_takeover")
    assert len(result) == 1
    assert result[0]["threat_type"] == "account_takeover"


def test_list_threats_filter_by_severity(engine):
    engine.detect_threat("org1", {
        "threat_type": "session_hijacking", "user_id": "u1", "severity": "critical"
    })
    engine.detect_threat("org1", {
        "threat_type": "session_hijacking", "user_id": "u2", "severity": "low"
    })
    result = engine.list_threats("org1", severity="critical")
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_list_threats_filter_by_status(engine):
    t = engine.detect_threat("org1", {
        "threat_type": "lateral_movement", "user_id": "u1"
    })
    engine.update_threat_status("org1", t["id"], "confirmed")
    result = engine.list_threats("org1", status="confirmed")
    assert len(result) == 1


# ---------------------------------------------------------------------------
# get_threat
# ---------------------------------------------------------------------------

def test_get_threat_found(engine):
    t = engine.detect_threat("org1", {"threat_type": "impossible_travel", "user_id": "u1"})
    fetched = engine.get_threat("org1", t["id"])
    assert fetched["id"] == t["id"]


def test_get_threat_not_found(engine):
    assert engine.get_threat("org1", "nonexistent") is None


def test_get_threat_wrong_org(engine):
    t = engine.detect_threat("org1", {"threat_type": "privilege_abuse", "user_id": "u1"})
    assert engine.get_threat("org2", t["id"]) is None


# ---------------------------------------------------------------------------
# update_threat_status
# ---------------------------------------------------------------------------

VALID_THREAT_STATUSES = ["detected", "investigating", "confirmed", "false_positive", "contained"]


@pytest.mark.parametrize("new_status", VALID_THREAT_STATUSES)
def test_update_threat_status_valid(engine, new_status):
    t = engine.detect_threat("org1", {"threat_type": "password_spray", "user_id": "u1"})
    updated = engine.update_threat_status("org1", t["id"], new_status)
    assert updated["status"] == new_status


def test_update_threat_status_invalid_raises(engine):
    t = engine.detect_threat("org1", {"threat_type": "account_takeover", "user_id": "u1"})
    with pytest.raises(ValueError):
        engine.update_threat_status("org1", t["id"], "bad_status")


def test_update_threat_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_threat_status("org1", "nonexistent", "confirmed")


def test_update_threat_status_lifecycle(engine):
    t = engine.detect_threat("org1", {
        "threat_type": "credential_stuffing", "user_id": "u1"
    })
    assert t["status"] == "detected"
    u1 = engine.update_threat_status("org1", t["id"], "investigating")
    assert u1["status"] == "investigating"
    u2 = engine.update_threat_status("org1", t["id"], "confirmed")
    assert u2["status"] == "confirmed"
    u3 = engine.update_threat_status("org1", t["id"], "contained")
    assert u3["status"] == "contained"


# ---------------------------------------------------------------------------
# record_behavior
# ---------------------------------------------------------------------------

VALID_BEHAVIOR_TYPES = [
    "login_attempt",
    "failed_login",
    "mfa_challenge",
    "privilege_escalation",
    "data_access",
    "lateral_move",
    "anomalous_time",
    "new_location",
]


@pytest.mark.parametrize("behavior_type", VALID_BEHAVIOR_TYPES)
def test_record_behavior_all_types(engine, behavior_type):
    b = engine.record_behavior("org1", {
        "user_id": "user@acme.com",
        "behavior_type": behavior_type,
        "risk_score": 60,
    })
    assert b["behavior_type"] == behavior_type
    assert b["user_id"] == "user@acme.com"
    assert "id" in b
    assert "recorded_at" in b


def test_record_behavior_missing_user_id_raises(engine):
    with pytest.raises(ValueError, match="user_id"):
        engine.record_behavior("org1", {
            "user_id": "",
            "behavior_type": "login_attempt",
        })


def test_record_behavior_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="behavior_type"):
        engine.record_behavior("org1", {
            "user_id": "u1",
            "behavior_type": "bad_behavior",
        })


def test_record_behavior_risk_score_clamped(engine):
    b = engine.record_behavior("org1", {
        "user_id": "u1",
        "behavior_type": "failed_login",
        "risk_score": 200,
    })
    assert b["risk_score"] == 100

    b2 = engine.record_behavior("org1", {
        "user_id": "u2",
        "behavior_type": "failed_login",
        "risk_score": -5,
    })
    assert b2["risk_score"] == 0


def test_record_behavior_details_stored(engine):
    details = {"ip": "1.2.3.4", "country": "RU"}
    b = engine.record_behavior("org1", {
        "user_id": "u1",
        "behavior_type": "new_location",
        "details": details,
    })
    assert isinstance(b["details"], dict)
    assert b["details"] == details


def test_list_behaviors_filter_by_user(engine):
    engine.record_behavior("org1", {"user_id": "alice", "behavior_type": "login_attempt"})
    engine.record_behavior("org1", {"user_id": "bob", "behavior_type": "failed_login"})
    result = engine.list_behaviors("org1", user_id="alice")
    assert len(result) == 1
    assert result[0]["user_id"] == "alice"


def test_list_behaviors_filter_by_type(engine):
    engine.record_behavior("org1", {"user_id": "u1", "behavior_type": "data_access"})
    engine.record_behavior("org1", {"user_id": "u1", "behavior_type": "login_attempt"})
    result = engine.list_behaviors("org1", behavior_type="data_access")
    assert all(r["behavior_type"] == "data_access" for r in result)


def test_list_behaviors_limit(engine):
    for i in range(10):
        engine.record_behavior("org1", {
            "user_id": f"user{i}", "behavior_type": "login_attempt"
        })
    result = engine.list_behaviors("org1", limit=5)
    assert len(result) == 5


# ---------------------------------------------------------------------------
# create_response_action / execute_response_action
# ---------------------------------------------------------------------------

VALID_ACTION_TYPES = [
    "block_ip",
    "force_mfa",
    "disable_account",
    "revoke_session",
    "alert_security",
    "reset_password",
    "notify_user",
]


@pytest.mark.parametrize("action_type", VALID_ACTION_TYPES)
def test_create_response_action_all_types(engine, action_type):
    t = engine.detect_threat("org1", {"threat_type": "account_takeover", "user_id": "u1"})
    a = engine.create_response_action("org1", {
        "threat_id": t["id"],
        "action_type": action_type,
    })
    assert a["action_type"] == action_type
    assert a["status"] == "pending"
    assert a["threat_id"] == t["id"]


def test_create_response_action_invalid_action_type_raises(engine):
    t = engine.detect_threat("org1", {"threat_type": "mfa_bypass", "user_id": "u1"})
    with pytest.raises(ValueError, match="action_type"):
        engine.create_response_action("org1", {
            "threat_id": t["id"],
            "action_type": "invalid_action",
        })


def test_create_response_action_threat_not_found_raises(engine):
    with pytest.raises(ValueError, match="Threat not found"):
        engine.create_response_action("org1", {
            "threat_id": "nonexistent",
            "action_type": "block_ip",
        })


def test_execute_response_action_success(engine):
    t = engine.detect_threat("org1", {"threat_type": "session_hijacking", "user_id": "u1"})
    a = engine.create_response_action("org1", {
        "threat_id": t["id"], "action_type": "revoke_session"
    })
    assert a["status"] == "pending"
    executed = engine.execute_response_action("org1", a["id"])
    assert executed["status"] == "executed"
    assert executed["executed_at"] is not None


def test_execute_response_action_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.execute_response_action("org1", "nonexistent")


def test_execute_response_action_wrong_org_raises(engine):
    t = engine.detect_threat("org1", {"threat_type": "privilege_abuse", "user_id": "u1"})
    a = engine.create_response_action("org1", {
        "threat_id": t["id"], "action_type": "alert_security"
    })
    with pytest.raises(KeyError):
        engine.execute_response_action("org2", a["id"])


def test_list_response_actions_filter_by_threat(engine):
    t1 = engine.detect_threat("org1", {"threat_type": "account_takeover", "user_id": "u1"})
    t2 = engine.detect_threat("org1", {"threat_type": "mfa_bypass", "user_id": "u2"})
    engine.create_response_action("org1", {"threat_id": t1["id"], "action_type": "block_ip"})
    engine.create_response_action("org1", {"threat_id": t2["id"], "action_type": "force_mfa"})
    result = engine.list_response_actions("org1", threat_id=t1["id"])
    assert len(result) == 1
    assert result[0]["threat_id"] == t1["id"]


def test_list_response_actions_filter_by_status(engine):
    t = engine.detect_threat("org1", {"threat_type": "lateral_movement", "user_id": "u1"})
    a = engine.create_response_action("org1", {"threat_id": t["id"], "action_type": "block_ip"})
    engine.execute_response_action("org1", a["id"])
    pending = engine.list_response_actions("org1", status="pending")
    executed = engine.list_response_actions("org1", status="executed")
    assert len(pending) == 0
    assert len(executed) == 1


# ---------------------------------------------------------------------------
# get_itdr_stats
# ---------------------------------------------------------------------------

def test_get_itdr_stats_empty(engine):
    stats = engine.get_itdr_stats("org1")
    assert stats["total_threats"] == 0
    assert stats["active_threats"] == 0
    assert stats["total_behaviors"] == 0
    assert stats["pending_actions"] == 0
    assert stats["high_risk_users"] == 0
    assert stats["by_type"] == {}
    assert stats["by_severity"] == {}


def test_get_itdr_stats_counting(engine):
    t1 = engine.detect_threat("org1", {
        "threat_type": "credential_stuffing", "user_id": "u1", "severity": "critical"
    })
    t2 = engine.detect_threat("org1", {
        "threat_type": "account_takeover", "user_id": "u2", "severity": "high"
    })
    engine.update_threat_status("org1", t2["id"], "confirmed")

    engine.record_behavior("org1", {"user_id": "u1", "behavior_type": "login_attempt"})

    a = engine.create_response_action("org1", {
        "threat_id": t1["id"], "action_type": "block_ip"
    })

    stats = engine.get_itdr_stats("org1")
    assert stats["total_threats"] == 2
    # detected + confirmed = 2 active
    assert stats["active_threats"] == 2
    assert stats["total_behaviors"] == 1
    assert stats["pending_actions"] == 1
    assert stats["by_type"]["credential_stuffing"] == 1
    assert stats["by_type"]["account_takeover"] == 1
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1


def test_get_itdr_stats_high_risk_users(engine):
    # 2 behaviors with risk >= 80 from same user
    engine.record_behavior("org1", {
        "user_id": "alice", "behavior_type": "data_access", "risk_score": 90
    })
    engine.record_behavior("org1", {
        "user_id": "alice", "behavior_type": "lateral_move", "risk_score": 85
    })
    # bob is low risk
    engine.record_behavior("org1", {
        "user_id": "bob", "behavior_type": "login_attempt", "risk_score": 20
    })
    # charlie is high risk
    engine.record_behavior("org1", {
        "user_id": "charlie", "behavior_type": "privilege_escalation", "risk_score": 95
    })
    stats = engine.get_itdr_stats("org1")
    # alice and charlie are high risk, bob is not
    assert stats["high_risk_users"] == 2


def test_get_itdr_stats_active_threats_statuses(engine):
    t1 = engine.detect_threat("org1", {"threat_type": "mfa_bypass", "user_id": "u1"})
    t2 = engine.detect_threat("org1", {"threat_type": "password_spray", "user_id": "u2"})
    t3 = engine.detect_threat("org1", {"threat_type": "session_hijacking", "user_id": "u3"})
    engine.update_threat_status("org1", t1["id"], "investigating")
    engine.update_threat_status("org1", t2["id"], "false_positive")
    # t3 stays detected
    stats = engine.get_itdr_stats("org1")
    # detected(t3) + investigating(t1) = 2; false_positive doesn't count
    assert stats["active_threats"] == 2


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_threats(engine):
    engine.detect_threat("org1", {"threat_type": "account_takeover", "user_id": "u1"})
    assert engine.list_threats("org2") == []


def test_org_isolation_behaviors(engine):
    engine.record_behavior("org1", {"user_id": "u1", "behavior_type": "login_attempt"})
    assert engine.list_behaviors("org2") == []


def test_org_isolation_response_actions(engine):
    t = engine.detect_threat("org1", {"threat_type": "mfa_bypass", "user_id": "u1"})
    engine.create_response_action("org1", {"threat_id": t["id"], "action_type": "force_mfa"})
    assert engine.list_response_actions("org2") == []


def test_org_isolation_stats(engine):
    engine.detect_threat("org1", {"threat_type": "lateral_movement", "user_id": "u1"})
    stats = engine.get_itdr_stats("org2")
    assert stats["total_threats"] == 0
