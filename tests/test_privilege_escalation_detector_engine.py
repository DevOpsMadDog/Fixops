"""Tests for PrivilegeEscalationDetectorEngine.

Covers:
- record_privilege_event (valid, missing fields)
- list_privilege_events (all, filtered by user, limit)
- detect_anomalous_escalation (anomaly score, risk level, indicators)
- create_detection_rule (valid, invalid regex, missing fields)
- list_detection_rules (returns rules)
- get_escalation_heatmap (top_users, top_methods, events_by_hour)
- get_detection_stats (totals, by_method, by_risk_level)
- anomaly scoring (exploit method, escalation to root, repeated attempts)
- multi-tenant isolation (org_id scoping)
- edge cases (empty org, event not found)
"""

from __future__ import annotations

import os
import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    from core.privilege_escalation_detector_engine import PrivilegeEscalationDetectorEngine
    return PrivilegeEscalationDetectorEngine(db_path=str(tmp_path / "test_ped.db"))


def _event(user="alice", from_role="user", to_role="admin", method="sudo", source_ip="10.0.0.1"):
    return {
        "user_id": user,
        "from_role": from_role,
        "to_role": to_role,
        "method": method,
        "source_ip": source_ip,
    }


ORG = "org-alpha"
ORG2 = "org-beta"


# ---------------------------------------------------------------------------
# record_privilege_event
# ---------------------------------------------------------------------------


def test_record_event_returns_id(engine):
    result = engine.record_privilege_event(ORG, _event())
    assert "id" in result
    assert result["id"]


def test_record_event_stores_org_id(engine):
    result = engine.record_privilege_event(ORG, _event())
    assert result["org_id"] == ORG


def test_record_event_stores_user_id(engine):
    result = engine.record_privilege_event(ORG, _event(user="bob"))
    assert result["user_id"] == "bob"


def test_record_event_stores_method(engine):
    result = engine.record_privilege_event(ORG, _event(method="exploit"))
    assert result["method"] == "exploit"


def test_record_event_computes_anomaly_score(engine):
    result = engine.record_privilege_event(ORG, _event())
    assert "anomaly_score" in result
    assert 0 <= result["anomaly_score"] <= 100


def test_record_event_computes_risk_level(engine):
    result = engine.record_privilege_event(ORG, _event())
    assert result["risk_level"] in ("low", "medium", "high", "critical")


def test_record_event_has_indicators(engine):
    result = engine.record_privilege_event(ORG, _event())
    assert "indicators" in result
    assert isinstance(result["indicators"], list)


def test_record_event_missing_user_id_raises(engine):
    with pytest.raises(ValueError, match="user_id is required"):
        engine.record_privilege_event(ORG, {"from_role": "user", "to_role": "admin", "method": "sudo"})


def test_record_event_missing_from_role_raises(engine):
    with pytest.raises(ValueError, match="from_role and to_role are required"):
        engine.record_privilege_event(ORG, {"user_id": "alice", "to_role": "admin"})


def test_record_event_missing_to_role_raises(engine):
    with pytest.raises(ValueError, match="from_role and to_role are required"):
        engine.record_privilege_event(ORG, {"user_id": "alice", "from_role": "user"})


# ---------------------------------------------------------------------------
# Anomaly scoring
# ---------------------------------------------------------------------------


def test_exploit_method_high_score(engine):
    result = engine.record_privilege_event(ORG, _event(method="exploit"))
    assert result["anomaly_score"] >= 60


def test_escalation_to_root_increases_score(engine):
    sudo_result = engine.record_privilege_event(ORG, _event(method="sudo", to_role="developer"))
    root_result = engine.record_privilege_event(ORG, _event(method="sudo", to_role="root", user="charlie"))
    assert root_result["anomaly_score"] >= sudo_result["anomaly_score"]


def test_exploit_to_root_is_critical(engine):
    result = engine.record_privilege_event(
        ORG, _event(user="attacker", method="exploit", from_role="guest", to_role="root")
    )
    assert result["risk_level"] in ("high", "critical")


def test_external_ip_increases_score(engine):
    internal_result = engine.record_privilege_event(
        ORG, _event(user="dave", source_ip="192.168.1.1")
    )
    external_result = engine.record_privilege_event(
        ORG, _event(user="eve", source_ip="203.0.113.5")
    )
    assert external_result["anomaly_score"] >= internal_result["anomaly_score"]


def test_repeated_escalation_increases_score(engine):
    # Record 3 events from same user to trigger frequency anomaly
    for _ in range(3):
        engine.record_privilege_event(ORG, _event(user="repeat-user"))
    result = engine.record_privilege_event(ORG, _event(user="repeat-user"))
    assert "repeated_escalation_attempts" in " ".join(result["indicators"])


def test_unprivileged_to_privileged_indicator(engine):
    result = engine.record_privilege_event(
        ORG, _event(user="frank", from_role="guest", to_role="root", method="exploit")
    )
    assert "unprivileged_to_privileged_jump" in result["indicators"]


# ---------------------------------------------------------------------------
# list_privilege_events
# ---------------------------------------------------------------------------


def test_list_events_returns_recorded(engine):
    engine.record_privilege_event(ORG, _event(user="alice"))
    engine.record_privilege_event(ORG, _event(user="bob"))
    events = engine.list_privilege_events(ORG)
    assert len(events) >= 2


def test_list_events_filter_by_user(engine):
    engine.record_privilege_event(ORG, _event(user="alice"))
    engine.record_privilege_event(ORG, _event(user="bob"))
    alice_events = engine.list_privilege_events(ORG, user_id="alice")
    assert all(e["user_id"] == "alice" for e in alice_events)


def test_list_events_limit(engine):
    for i in range(5):
        engine.record_privilege_event(ORG, _event(user=f"user-{i}"))
    events = engine.list_privilege_events(ORG, limit=3)
    assert len(events) <= 3


def test_list_events_indicators_deserialized(engine):
    engine.record_privilege_event(ORG, _event())
    events = engine.list_privilege_events(ORG)
    assert isinstance(events[0]["indicators"], list)


def test_list_events_empty_for_new_org(engine):
    events = engine.list_privilege_events("brand-new-org")
    assert events == []


# ---------------------------------------------------------------------------
# detect_anomalous_escalation
# ---------------------------------------------------------------------------


def test_detect_anomaly_returns_score(engine):
    event = engine.record_privilege_event(ORG, _event())
    result = engine.detect_anomalous_escalation(ORG, event["id"])
    assert "anomaly_score" in result
    assert 0 <= result["anomaly_score"] <= 100


def test_detect_anomaly_returns_risk_level(engine):
    event = engine.record_privilege_event(ORG, _event())
    result = engine.detect_anomalous_escalation(ORG, event["id"])
    assert result["risk_level"] in ("low", "medium", "high", "critical")


def test_detect_anomaly_returns_indicators(engine):
    event = engine.record_privilege_event(ORG, _event())
    result = engine.detect_anomalous_escalation(ORG, event["id"])
    assert "indicators" in result
    assert isinstance(result["indicators"], list)


def test_detect_anomaly_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.detect_anomalous_escalation(ORG, "nonexistent-id")


def test_detect_anomaly_wrong_org_raises(engine):
    event = engine.record_privilege_event(ORG, _event())
    with pytest.raises(ValueError, match="not found"):
        engine.detect_anomalous_escalation(ORG2, event["id"])


# ---------------------------------------------------------------------------
# create_detection_rule
# ---------------------------------------------------------------------------


def test_create_rule_returns_id(engine):
    rule = engine.create_detection_rule(ORG, {
        "name": "block-exploit", "pattern": "exploit", "severity": "critical", "action": "block"
    })
    assert "id" in rule
    assert rule["id"]


def test_create_rule_stores_name(engine):
    rule = engine.create_detection_rule(ORG, {
        "name": "sudo-alert", "pattern": "sudo", "severity": "medium", "action": "alert"
    })
    assert rule["name"] == "sudo-alert"


def test_create_rule_stores_pattern(engine):
    rule = engine.create_detection_rule(ORG, {
        "name": "test", "pattern": r"root|admin", "severity": "high", "action": "alert"
    })
    assert rule["pattern"] == r"root|admin"


def test_create_rule_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_detection_rule(ORG, {"pattern": "exploit", "severity": "high"})


def test_create_rule_missing_pattern_raises(engine):
    with pytest.raises(ValueError, match="pattern is required"):
        engine.create_detection_rule(ORG, {"name": "bad-rule", "severity": "high"})


def test_create_rule_invalid_regex_raises(engine):
    with pytest.raises(ValueError, match="Invalid regex pattern"):
        engine.create_detection_rule(ORG, {
            "name": "bad-regex", "pattern": "[unclosed", "severity": "low"
        })


def test_rule_match_increases_anomaly_score(engine):
    engine.create_detection_rule(ORG, {
        "name": "exploit-block", "pattern": "exploit", "severity": "critical", "action": "block"
    })
    result = engine.record_privilege_event(ORG, _event(method="exploit"))
    # Rule match should be in indicators
    assert any("rule_match" in ind for ind in result["indicators"])


# ---------------------------------------------------------------------------
# list_detection_rules
# ---------------------------------------------------------------------------


def test_list_rules_returns_created(engine):
    engine.create_detection_rule(ORG, {"name": "r1", "pattern": "sudo", "severity": "low"})
    engine.create_detection_rule(ORG, {"name": "r2", "pattern": "exploit", "severity": "critical"})
    rules = engine.list_detection_rules(ORG)
    assert len(rules) >= 2


def test_list_rules_empty_for_new_org(engine):
    rules = engine.list_detection_rules("fresh-org")
    assert rules == []


def test_list_rules_org_scoped(engine):
    engine.create_detection_rule(ORG, {"name": "alpha-rule", "pattern": "sudo"})
    engine.create_detection_rule(ORG2, {"name": "beta-rule", "pattern": "exploit"})
    alpha_rules = engine.list_detection_rules(ORG)
    beta_rules = engine.list_detection_rules(ORG2)
    assert all(r["name"] == "alpha-rule" for r in alpha_rules)
    assert all(r["name"] == "beta-rule" for r in beta_rules)


# ---------------------------------------------------------------------------
# get_escalation_heatmap
# ---------------------------------------------------------------------------


def test_heatmap_structure(engine):
    result = engine.get_escalation_heatmap(ORG)
    assert "total_events" in result
    assert "top_users" in result
    assert "top_methods" in result
    assert "events_by_hour" in result


def test_heatmap_counts_events(engine):
    engine.record_privilege_event(ORG, _event(user="alice"))
    engine.record_privilege_event(ORG, _event(user="alice"))
    result = engine.get_escalation_heatmap(ORG, hours=24)
    assert result["total_events"] >= 2


def test_heatmap_top_users_format(engine):
    engine.record_privilege_event(ORG, _event(user="alice"))
    result = engine.get_escalation_heatmap(ORG)
    for entry in result["top_users"]:
        assert "user_id" in entry
        assert "count" in entry


def test_heatmap_top_methods_format(engine):
    engine.record_privilege_event(ORG, _event(method="sudo"))
    result = engine.get_escalation_heatmap(ORG)
    for entry in result["top_methods"]:
        assert "method" in entry
        assert "count" in entry


def test_heatmap_empty_org(engine):
    result = engine.get_escalation_heatmap("empty-org", hours=24)
    assert result["total_events"] == 0
    assert result["top_users"] == []


# ---------------------------------------------------------------------------
# get_detection_stats
# ---------------------------------------------------------------------------


def test_stats_structure(engine):
    stats = engine.get_detection_stats(ORG)
    assert "total_events" in stats
    assert "anomalous_events" in stats
    assert "blocked_attempts" in stats
    assert "detection_rules" in stats
    assert "by_method" in stats
    assert "by_risk_level" in stats


def test_stats_counts_total_events(engine):
    engine.record_privilege_event(ORG, _event(user="alice"))
    engine.record_privilege_event(ORG, _event(user="bob"))
    stats = engine.get_detection_stats(ORG)
    assert stats["total_events"] >= 2


def test_stats_counts_rules(engine):
    engine.create_detection_rule(ORG, {"name": "r1", "pattern": "exploit"})
    stats = engine.get_detection_stats(ORG)
    assert stats["detection_rules"] >= 1


def test_stats_by_method_populated(engine):
    engine.record_privilege_event(ORG, _event(method="sudo"))
    stats = engine.get_detection_stats(ORG)
    assert "sudo" in stats["by_method"]


def test_stats_empty_org(engine):
    stats = engine.get_detection_stats("empty-org")
    assert stats["total_events"] == 0
    assert stats["anomalous_events"] == 0


# ---------------------------------------------------------------------------
# Multi-tenant isolation
# ---------------------------------------------------------------------------


def test_org_isolation_events(engine):
    engine.record_privilege_event(ORG, _event(user="alice"))
    engine.record_privilege_event(ORG2, _event(user="bob"))
    alpha_events = engine.list_privilege_events(ORG)
    beta_events = engine.list_privilege_events(ORG2)
    assert all(e["user_id"] == "alice" for e in alpha_events)
    assert all(e["user_id"] == "bob" for e in beta_events)


def test_org_isolation_stats(engine):
    engine.record_privilege_event(ORG, _event())
    stats_alpha = engine.get_detection_stats(ORG)
    stats_beta = engine.get_detection_stats(ORG2)
    assert stats_alpha["total_events"] >= 1
    assert stats_beta["total_events"] == 0
