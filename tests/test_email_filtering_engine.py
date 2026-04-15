"""Tests for EmailFilteringEngine — filter rules, email events, stats."""

from __future__ import annotations

import pytest

from core.email_filtering_engine import EmailFilteringEngine


@pytest.fixture
def engine(tmp_path):
    return EmailFilteringEngine(db_path=str(tmp_path / "test_email_filtering.db"))


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = tmp_path / "email_filtering.db"
    EmailFilteringEngine(db_path=str(db))
    assert db.exists()


def test_init_idempotent(tmp_path):
    db = tmp_path / "email_filtering.db"
    EmailFilteringEngine(db_path=str(db))
    EmailFilteringEngine(db_path=str(db))


# ---------------------------------------------------------------------------
# Filter Rules — create
# ---------------------------------------------------------------------------

def test_create_filter_rule_basic(engine):
    rule = engine.create_filter_rule("org1", {"name": "Block spam", "rule_type": "spam"})
    assert rule["id"]
    assert rule["name"] == "Block spam"
    assert rule["rule_type"] == "spam"
    assert rule["action"] == "quarantine"
    assert rule["priority"] == 50
    assert rule["status"] == "active"
    assert rule["org_id"] == "org1"


def test_create_filter_rule_all_valid_types(engine):
    valid_types = ["spam", "malware", "phishing", "dmarc", "spf", "dkim", "blacklist", "whitelist"]
    for rt in valid_types:
        rule = engine.create_filter_rule("org1", {"name": f"Rule {rt}", "rule_type": rt})
        assert rule["rule_type"] == rt


def test_create_filter_rule_all_valid_actions(engine):
    valid_actions = ["allow", "block", "quarantine", "tag"]
    for action in valid_actions:
        rule = engine.create_filter_rule("org1", {
            "name": f"Rule {action}", "rule_type": "spam", "action": action
        })
        assert rule["action"] == action


def test_create_filter_rule_priority_clamp_low(engine):
    rule = engine.create_filter_rule("org1", {"name": "r", "rule_type": "spam", "priority": -10})
    assert rule["priority"] == 1


def test_create_filter_rule_priority_clamp_high(engine):
    rule = engine.create_filter_rule("org1", {"name": "r", "rule_type": "spam", "priority": 999})
    assert rule["priority"] == 100


def test_create_filter_rule_invalid_rule_type(engine):
    with pytest.raises(ValueError, match="rule_type"):
        engine.create_filter_rule("org1", {"name": "bad", "rule_type": "invalid_type"})


def test_create_filter_rule_invalid_action(engine):
    with pytest.raises(ValueError, match="action"):
        engine.create_filter_rule("org1", {"name": "bad", "rule_type": "spam", "action": "delete"})


def test_create_filter_rule_missing_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_filter_rule("org1", {"rule_type": "spam"})


def test_create_filter_rule_missing_rule_type(engine):
    with pytest.raises(ValueError, match="rule_type"):
        engine.create_filter_rule("org1", {"name": "no type"})


# ---------------------------------------------------------------------------
# Filter Rules — list and get
# ---------------------------------------------------------------------------

def test_list_filter_rules_empty(engine):
    rules = engine.list_filter_rules("org1")
    assert rules == []


def test_list_filter_rules_filter_by_rule_type(engine):
    engine.create_filter_rule("org1", {"name": "spam rule", "rule_type": "spam"})
    engine.create_filter_rule("org1", {"name": "phishing rule", "rule_type": "phishing"})
    rules = engine.list_filter_rules("org1", rule_type="spam")
    assert len(rules) == 1
    assert rules[0]["rule_type"] == "spam"


def test_list_filter_rules_filter_by_action(engine):
    engine.create_filter_rule("org1", {"name": "block rule", "rule_type": "spam", "action": "block"})
    engine.create_filter_rule("org1", {"name": "tag rule", "rule_type": "spam", "action": "tag"})
    rules = engine.list_filter_rules("org1", action="block")
    assert len(rules) == 1
    assert rules[0]["action"] == "block"


def test_get_filter_rule_found(engine):
    created = engine.create_filter_rule("org1", {"name": "r", "rule_type": "spam"})
    fetched = engine.get_filter_rule("org1", created["id"])
    assert fetched["id"] == created["id"]
    assert fetched["name"] == "r"


def test_get_filter_rule_not_found(engine):
    result = engine.get_filter_rule("org1", "nonexistent-id")
    assert result is None


def test_get_filter_rule_org_isolation(engine):
    created = engine.create_filter_rule("org1", {"name": "r", "rule_type": "spam"})
    result = engine.get_filter_rule("org2", created["id"])
    assert result is None


# ---------------------------------------------------------------------------
# Email Events — log
# ---------------------------------------------------------------------------

def test_log_email_event_basic(engine):
    event = engine.log_email_event("org1", {
        "sender": "spam@evil.com",
        "recipient": "user@company.com",
        "filter_result": "spam",
    })
    assert event["id"]
    assert event["sender"] == "spam@evil.com"
    assert event["recipient"] == "user@company.com"
    assert event["filter_result"] == "spam"
    assert event["threat_score"] == 0
    assert event["org_id"] == "org1"


def test_log_email_event_all_filter_results(engine):
    for result in ["clean", "spam", "malware", "phishing", "quarantined", "blocked"]:
        event = engine.log_email_event("org1", {
            "sender": "s@x.com",
            "recipient": "r@y.com",
            "filter_result": result,
        })
        assert event["filter_result"] == result


def test_log_email_event_threat_score_clamped_high(engine):
    event = engine.log_email_event("org1", {
        "sender": "s@x.com",
        "recipient": "r@y.com",
        "filter_result": "malware",
        "threat_score": 200,
    })
    assert event["threat_score"] == 100


def test_log_email_event_threat_score_clamped_low(engine):
    event = engine.log_email_event("org1", {
        "sender": "s@x.com",
        "recipient": "r@y.com",
        "filter_result": "clean",
        "threat_score": -50,
    })
    assert event["threat_score"] == 0


def test_log_email_event_with_rule_id(engine):
    rule = engine.create_filter_rule("org1", {"name": "r", "rule_type": "spam"})
    event = engine.log_email_event("org1", {
        "sender": "s@x.com",
        "recipient": "r@y.com",
        "filter_result": "spam",
        "rule_id": rule["id"],
    })
    assert event["rule_id"] == rule["id"]


def test_log_email_event_invalid_filter_result(engine):
    with pytest.raises(ValueError, match="filter_result"):
        engine.log_email_event("org1", {
            "sender": "s@x.com",
            "recipient": "r@y.com",
            "filter_result": "junk",
        })


def test_log_email_event_missing_sender(engine):
    with pytest.raises(ValueError, match="sender"):
        engine.log_email_event("org1", {"recipient": "r@y.com", "filter_result": "clean"})


def test_log_email_event_missing_recipient(engine):
    with pytest.raises(ValueError, match="recipient"):
        engine.log_email_event("org1", {"sender": "s@x.com", "filter_result": "clean"})


# ---------------------------------------------------------------------------
# Email Events — list
# ---------------------------------------------------------------------------

def test_list_email_events_empty(engine):
    events = engine.list_email_events("org1")
    assert events == []


def test_list_email_events_filter_by_result(engine):
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "spam"})
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "clean"})
    events = engine.list_email_events("org1", filter_result="spam")
    assert len(events) == 1
    assert events[0]["filter_result"] == "spam"


def test_list_email_events_limit(engine):
    for i in range(10):
        engine.log_email_event("org1", {
            "sender": f"s{i}@x.com", "recipient": "r@y.com", "filter_result": "spam"
        })
    events = engine.list_email_events("org1", limit=3)
    assert len(events) == 3


def test_list_email_events_org_isolation(engine):
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "spam"})
    events = engine.list_email_events("org2")
    assert events == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_email_stats_empty(engine):
    stats = engine.get_email_stats("org1")
    assert stats["total_rules"] == 0
    assert stats["active_rules"] == 0
    assert stats["by_rule_type"] == {}
    assert stats["total_events_24h"] == 0
    assert stats["by_filter_result"] == {}
    assert stats["threat_score_avg"] == 0.0
    assert stats["blocked_count"] == 0


def test_get_email_stats_rules(engine):
    engine.create_filter_rule("org1", {"name": "spam1", "rule_type": "spam"})
    engine.create_filter_rule("org1", {"name": "spam2", "rule_type": "spam"})
    engine.create_filter_rule("org1", {"name": "phish1", "rule_type": "phishing"})
    stats = engine.get_email_stats("org1")
    assert stats["total_rules"] == 3
    assert stats["active_rules"] == 3
    assert stats["by_rule_type"]["spam"] == 2
    assert stats["by_rule_type"]["phishing"] == 1


def test_get_email_stats_blocked_count_includes_quarantined(engine):
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "blocked"})
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "quarantined"})
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "clean"})
    stats = engine.get_email_stats("org1")
    assert stats["blocked_count"] == 2


def test_get_email_stats_threat_score_avg(engine):
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "spam", "threat_score": 60})
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "malware", "threat_score": 100})
    stats = engine.get_email_stats("org1")
    assert stats["threat_score_avg"] == 80.0


def test_get_email_stats_org_isolation(engine):
    engine.create_filter_rule("org1", {"name": "spam1", "rule_type": "spam"})
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "blocked"})
    stats = engine.get_email_stats("org2")
    assert stats["total_rules"] == 0
    assert stats["blocked_count"] == 0


def test_get_email_stats_by_filter_result(engine):
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "spam"})
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "spam"})
    engine.log_email_event("org1", {"sender": "s@x.com", "recipient": "r@y.com", "filter_result": "clean"})
    stats = engine.get_email_stats("org1")
    assert stats["by_filter_result"]["spam"] == 2
    assert stats["by_filter_result"]["clean"] == 1
