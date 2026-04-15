"""Tests for ZeroTrustPolicyEngine — 30+ tests covering CRUD, evaluation,
access events, stats, compliance posture, and org isolation."""
import pytest

from core.zero_trust_policy_engine import ZeroTrustPolicyEngine


@pytest.fixture
def engine(tmp_path):
    return ZeroTrustPolicyEngine(db_path=str(tmp_path / "test.db"))


# ============================================================================
# Initialisation
# ============================================================================


def test_init_creates_db(tmp_path):
    db = tmp_path / "zt.db"
    ZeroTrustPolicyEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_is_idempotent(tmp_path):
    db = tmp_path / "zt.db"
    ZeroTrustPolicyEngine(db_path=str(db))
    ZeroTrustPolicyEngine(db_path=str(db))  # should not raise


# ============================================================================
# Policy CRUD
# ============================================================================


def test_create_policy_returns_dict(engine):
    p = engine.create_policy("org1", {"name": "Block BYOD", "policy_type": "device", "action": "deny"})
    assert p["policy_id"]
    assert p["name"] == "Block BYOD"
    assert p["policy_type"] == "device"
    assert p["action"] == "deny"
    assert p["enabled"] is True
    assert p["org_id"] == "org1"


def test_create_policy_all_types(engine):
    for pt in ("network", "identity", "device", "application"):
        p = engine.create_policy("org1", {"name": pt, "policy_type": pt, "action": "allow"})
        assert p["policy_type"] == pt


def test_create_policy_all_actions(engine):
    for action in ("allow", "deny", "mfa_required"):
        p = engine.create_policy("org1", {"name": action, "action": action, "policy_type": "network"})
        assert p["action"] == action


def test_create_policy_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="policy_type"):
        engine.create_policy("org1", {"name": "Bad", "policy_type": "invalid", "action": "deny"})


def test_create_policy_invalid_action_raises(engine):
    with pytest.raises(ValueError, match="action"):
        engine.create_policy("org1", {"name": "Bad", "policy_type": "network", "action": "quarantine"})


def test_list_policies_empty(engine):
    assert engine.list_policies("org1") == []


def test_list_policies_returns_all(engine):
    engine.create_policy("org1", {"name": "P1", "policy_type": "network", "action": "allow"})
    engine.create_policy("org1", {"name": "P2", "policy_type": "device", "action": "deny"})
    assert len(engine.list_policies("org1")) == 2


def test_list_policies_filter_by_type(engine):
    engine.create_policy("org1", {"name": "N", "policy_type": "network", "action": "allow"})
    engine.create_policy("org1", {"name": "D", "policy_type": "device", "action": "deny"})
    net = engine.list_policies("org1", policy_type="network")
    assert len(net) == 1
    assert net[0]["policy_type"] == "network"


def test_list_policies_filter_by_enabled(engine):
    engine.create_policy("org1", {"name": "On", "policy_type": "network", "action": "allow", "enabled": True})
    engine.create_policy("org1", {"name": "Off", "policy_type": "network", "action": "deny", "enabled": False})
    assert len(engine.list_policies("org1", enabled=True)) == 1
    assert len(engine.list_policies("org1", enabled=False)) == 1


def test_get_policy_returns_correct_policy(engine):
    p = engine.create_policy("org1", {"name": "X", "policy_type": "identity", "action": "mfa_required"})
    fetched = engine.get_policy("org1", p["policy_id"])
    assert fetched is not None
    assert fetched["policy_id"] == p["policy_id"]
    assert fetched["name"] == "X"


def test_get_policy_wrong_org_returns_none(engine):
    p = engine.create_policy("org1", {"name": "X", "policy_type": "network", "action": "allow"})
    assert engine.get_policy("org2", p["policy_id"]) is None


def test_get_policy_not_found_returns_none(engine):
    assert engine.get_policy("org1", "nonexistent-id") is None


def test_update_policy_name(engine):
    p = engine.create_policy("org1", {"name": "Old", "policy_type": "network", "action": "allow"})
    updated = engine.update_policy("org1", p["policy_id"], {"name": "New"})
    assert updated["name"] == "New"


def test_update_policy_enabled_false(engine):
    p = engine.create_policy("org1", {"name": "P", "policy_type": "network", "action": "allow"})
    updated = engine.update_policy("org1", p["policy_id"], {"enabled": False})
    assert updated["enabled"] is False


def test_update_policy_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.update_policy("org1", "bad-id", {"name": "X"})


def test_update_policy_wrong_org_raises(engine):
    p = engine.create_policy("org1", {"name": "P", "policy_type": "network", "action": "allow"})
    with pytest.raises(ValueError, match="not found"):
        engine.update_policy("org2", p["policy_id"], {"name": "Hacked"})


def test_delete_policy_returns_true(engine):
    p = engine.create_policy("org1", {"name": "P", "policy_type": "network", "action": "allow"})
    assert engine.delete_policy("org1", p["policy_id"]) is True
    assert engine.get_policy("org1", p["policy_id"]) is None


def test_delete_policy_not_found_returns_false(engine):
    assert engine.delete_policy("org1", "bad-id") is False


def test_delete_policy_wrong_org_returns_false(engine):
    p = engine.create_policy("org1", {"name": "P", "policy_type": "network", "action": "allow"})
    assert engine.delete_policy("org2", p["policy_id"]) is False


# ============================================================================
# Access evaluation
# ============================================================================


def test_evaluate_no_policies_returns_allow(engine):
    result = engine.evaluate_access("org1", {"user": "alice", "resource": "/api/data"})
    assert result["decision"] == "allow"
    assert result["matched_policy_id"] is None


def test_evaluate_deny_policy_matched(engine):
    engine.create_policy("org1", {
        "name": "Block Alice",
        "policy_type": "identity",
        "action": "deny",
        "priority": 1,
        "source_conditions": {"user": "alice"},
    })
    result = engine.evaluate_access("org1", {"user": "alice", "resource": "/secret"})
    assert result["decision"] == "deny"
    assert result["matched_policy_id"] is not None


def test_evaluate_mfa_required_policy(engine):
    engine.create_policy("org1", {
        "name": "MFA for Finance",
        "policy_type": "application",
        "action": "mfa_required",
        "source_conditions": {"user": "bob"},
    })
    result = engine.evaluate_access("org1", {"user": "bob", "resource": "/finance"})
    assert result["decision"] == "mfa_required"


def test_evaluate_allow_policy_matched(engine):
    engine.create_policy("org1", {
        "name": "Allow Corp",
        "policy_type": "network",
        "action": "allow",
        "source_conditions": {"source_ip": "10.0.0.1"},
    })
    result = engine.evaluate_access("org1", {"source_ip": "10.0.0.1", "resource": "/data"})
    assert result["decision"] == "allow"


def test_evaluate_policy_not_matched_defaults_allow(engine):
    engine.create_policy("org1", {
        "name": "Block Device X",
        "policy_type": "device",
        "action": "deny",
        "source_conditions": {"device": "BAD-DEVICE"},
    })
    result = engine.evaluate_access("org1", {"device": "GOOD-DEVICE", "resource": "/api"})
    assert result["decision"] == "allow"
    assert result["matched_policy_id"] is None


def test_evaluate_priority_ordering(engine):
    """Lower priority number = higher priority, first match wins."""
    engine.create_policy("org1", {
        "name": "High priority allow",
        "policy_type": "network",
        "action": "allow",
        "priority": 1,
        "source_conditions": {"user": "charlie"},
    })
    engine.create_policy("org1", {
        "name": "Low priority deny",
        "policy_type": "identity",
        "action": "deny",
        "priority": 10,
        "source_conditions": {"user": "charlie"},
    })
    result = engine.evaluate_access("org1", {"user": "charlie"})
    assert result["decision"] == "allow"


def test_evaluate_records_access_event(engine):
    engine.evaluate_access("org1", {"user": "dave", "resource": "/api/x"})
    events = engine.list_access_events("org1")
    assert len(events) == 1
    assert events[0]["user"] == "dave"


# ============================================================================
# Access event logging
# ============================================================================


def test_record_access_event_returns_event_id(engine):
    evt = engine.record_access_event("org1", {
        "user": "alice", "device": "MAC-001", "resource": "/api/data",
        "decision": "allow", "source_ip": "10.0.0.1",
    })
    assert evt["event_id"]
    assert evt["decision"] == "allow"
    assert evt["org_id"] == "org1"


def test_list_access_events_empty(engine):
    assert engine.list_access_events("org1") == []


def test_list_access_events_filter_by_decision(engine):
    engine.record_access_event("org1", {"decision": "allow", "user": "alice"})
    engine.record_access_event("org1", {"decision": "deny", "user": "bob"})
    allows = engine.list_access_events("org1", decision="allow")
    denies = engine.list_access_events("org1", decision="deny")
    assert len(allows) == 1
    assert len(denies) == 1


def test_list_access_events_org_isolation(engine):
    engine.record_access_event("org1", {"decision": "allow"})
    engine.record_access_event("org2", {"decision": "deny"})
    assert len(engine.list_access_events("org1")) == 1
    assert len(engine.list_access_events("org2")) == 1


def test_list_access_events_limit(engine):
    for i in range(10):
        engine.record_access_event("org1", {"decision": "allow", "user": f"user{i}"})
    assert len(engine.list_access_events("org1", limit=3)) == 3


# ============================================================================
# Statistics
# ============================================================================


def test_get_policy_stats_empty(engine):
    stats = engine.get_policy_stats("org1")
    assert stats["total_policies"] == 0
    assert stats["enabled_policies"] == 0
    assert stats["by_type"] == {}
    assert stats["access_events_24h"] == 0


def test_get_policy_stats_counts(engine):
    engine.create_policy("org1", {"name": "N1", "policy_type": "network", "action": "allow"})
    engine.create_policy("org1", {"name": "N2", "policy_type": "network", "action": "deny"})
    engine.create_policy("org1", {"name": "I1", "policy_type": "identity", "action": "mfa_required"})
    stats = engine.get_policy_stats("org1")
    assert stats["total_policies"] == 3
    assert stats["enabled_policies"] == 3
    assert stats["by_type"]["network"] == 2
    assert stats["by_type"]["identity"] == 1


def test_get_policy_stats_rates(engine):
    engine.record_access_event("org1", {"decision": "allow"})
    engine.record_access_event("org1", {"decision": "deny"})
    stats = engine.get_policy_stats("org1")
    assert stats["allow_rate"] >= 0.0
    assert stats["deny_rate"] >= 0.0
    assert 0.0 <= stats["mfa_rate"] <= 1.0


# ============================================================================
# Compliance posture
# ============================================================================


def test_get_compliance_posture_structure(engine):
    posture = engine.get_compliance_posture("org1")
    assert "zt_maturity_score" in posture
    assert "pillars" in posture
    assert "recommendations" in posture
    pillars = posture["pillars"]
    assert set(pillars.keys()) == {"identity", "device", "network", "application", "data"}


def test_get_compliance_posture_no_policies_score_zero(engine):
    posture = engine.get_compliance_posture("org1")
    assert posture["zt_maturity_score"] == 0
    for score in posture["pillars"].values():
        assert score == 0


def test_get_compliance_posture_score_increases_with_policies(engine):
    posture_before = engine.get_compliance_posture("org1")

    engine.create_policy("org1", {"name": "N", "policy_type": "network", "action": "allow"})
    engine.create_policy("org1", {"name": "I", "policy_type": "identity", "action": "mfa_required"})
    engine.create_policy("org1", {"name": "D", "policy_type": "device", "action": "deny"})

    posture_after = engine.get_compliance_posture("org1")
    assert posture_after["zt_maturity_score"] > posture_before["zt_maturity_score"]


def test_get_compliance_posture_recommendations_not_empty(engine):
    posture = engine.get_compliance_posture("org1")
    assert len(posture["recommendations"]) > 0


def test_get_compliance_posture_score_in_range(engine):
    engine.create_policy("org1", {"name": "P1", "policy_type": "network", "action": "allow"})
    engine.create_policy("org1", {"name": "P2", "policy_type": "identity", "action": "deny"})
    engine.create_policy("org1", {"name": "P3", "policy_type": "device", "action": "mfa_required"})
    engine.create_policy("org1", {"name": "P4", "policy_type": "application", "action": "allow"})
    posture = engine.get_compliance_posture("org1")
    assert 0 <= posture["zt_maturity_score"] <= 100


def test_get_compliance_posture_org_isolation(engine):
    engine.create_policy("org1", {"name": "P", "policy_type": "network", "action": "allow"})
    posture_org1 = engine.get_compliance_posture("org1")
    posture_org2 = engine.get_compliance_posture("org2")
    assert posture_org1["zt_maturity_score"] > posture_org2["zt_maturity_score"]


# ============================================================================
# Org isolation
# ============================================================================


def test_org_isolation_policies(engine):
    engine.create_policy("org1", {"name": "Org1 Policy", "policy_type": "network", "action": "allow"})
    engine.create_policy("org2", {"name": "Org2 Policy", "policy_type": "device", "action": "deny"})
    assert len(engine.list_policies("org1")) == 1
    assert len(engine.list_policies("org2")) == 1
    assert engine.list_policies("org1")[0]["name"] == "Org1 Policy"
    assert engine.list_policies("org2")[0]["name"] == "Org2 Policy"


def test_org_isolation_evaluate(engine):
    """Org1 policy should not affect org2 evaluation."""
    engine.create_policy("org1", {
        "name": "Deny all org1",
        "policy_type": "network",
        "action": "deny",
    })
    result = engine.evaluate_access("org2", {"user": "alice", "resource": "/data"})
    # org2 has no policies — should default allow
    assert result["decision"] == "allow"
