"""Tests for WAFEngine — WAF rules, blocked requests, virtual patches, rate limits, stats."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from core.waf_engine import WAFEngine


@pytest.fixture
def engine(tmp_path):
    return WAFEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = tmp_path / "waf.db"
    eng = WAFEngine(db_path=str(db))
    assert db.exists()


def test_init_idempotent(tmp_path):
    db = tmp_path / "waf.db"
    WAFEngine(db_path=str(db))
    WAFEngine(db_path=str(db))  # second init should not fail


# ---------------------------------------------------------------------------
# WAF Rules — create
# ---------------------------------------------------------------------------

def test_create_rule_basic(engine):
    rule = engine.create_rule("org1", {"rule_name": "Block SQLi", "rule_type": "block", "pattern": "UNION SELECT", "target": "uri"})
    assert rule["id"]
    assert rule["rule_name"] == "Block SQLi"
    assert rule["rule_type"] == "block"
    assert rule["target"] == "uri"
    assert rule["enabled"] is True
    assert rule["org_id"] == "org1"


def test_create_rule_all_fields(engine):
    rule = engine.create_rule("org1", {
        "rule_name": "Rate limit login",
        "rule_type": "rate_limit",
        "pattern": "/api/login",
        "target": "uri",
        "action": "challenge",
        "severity": "medium",
        "enabled": False,
        "description": "Slow down brute force",
    })
    assert rule["rule_type"] == "rate_limit"
    assert rule["action"] == "challenge"
    assert rule["severity"] == "medium"
    assert rule["enabled"] is False
    assert rule["description"] == "Slow down brute force"


def test_create_rule_invalid_rule_type(engine):
    with pytest.raises(ValueError, match="rule_type"):
        engine.create_rule("org1", {"rule_name": "bad", "rule_type": "invalid"})


def test_create_rule_invalid_target(engine):
    with pytest.raises(ValueError, match="target"):
        engine.create_rule("org1", {"rule_name": "bad", "target": "cookie"})


def test_create_rule_invalid_action(engine):
    with pytest.raises(ValueError, match="action"):
        engine.create_rule("org1", {"rule_name": "bad", "action": "drop"})


def test_create_rule_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.create_rule("org1", {"rule_name": "bad", "severity": "info"})


# ---------------------------------------------------------------------------
# WAF Rules — list
# ---------------------------------------------------------------------------

def test_list_rules_empty(engine):
    rules = engine.list_rules("org1")
    assert rules == []


def test_list_rules_filter_rule_type(engine):
    engine.create_rule("org1", {"rule_name": "R1", "rule_type": "block"})
    engine.create_rule("org1", {"rule_name": "R2", "rule_type": "allow"})
    engine.create_rule("org1", {"rule_name": "R3", "rule_type": "block"})
    blocked = engine.list_rules("org1", rule_type="block")
    assert len(blocked) == 2
    allowed = engine.list_rules("org1", rule_type="allow")
    assert len(allowed) == 1


def test_list_rules_filter_enabled(engine):
    engine.create_rule("org1", {"rule_name": "R1", "enabled": True})
    engine.create_rule("org1", {"rule_name": "R2", "enabled": False})
    enabled = engine.list_rules("org1", enabled=True)
    assert len(enabled) == 1
    disabled = engine.list_rules("org1", enabled=False)
    assert len(disabled) == 1


def test_list_rules_org_isolation(engine):
    engine.create_rule("org1", {"rule_name": "A"})
    engine.create_rule("org2", {"rule_name": "B"})
    assert len(engine.list_rules("org1")) == 1
    assert len(engine.list_rules("org2")) == 1
    assert len(engine.list_rules("org3")) == 0


# ---------------------------------------------------------------------------
# WAF Rules — update
# ---------------------------------------------------------------------------

def test_update_rule(engine):
    rule = engine.create_rule("org1", {"rule_name": "Old Name", "severity": "low"})
    updated = engine.update_rule("org1", rule["id"], {"rule_name": "New Name", "severity": "critical"})
    assert updated["rule_name"] == "New Name"
    assert updated["severity"] == "critical"


def test_update_rule_not_found(engine):
    result = engine.update_rule("org1", "nonexistent-id", {"rule_name": "X"})
    assert result is None


def test_update_rule_invalid_field_ignored(engine):
    rule = engine.create_rule("org1", {"rule_name": "Test"})
    updated = engine.update_rule("org1", rule["id"], {"rule_name": "Valid", "bad_field": "ignored"})
    assert updated["rule_name"] == "Valid"


def test_update_rule_enabled_toggle(engine):
    rule = engine.create_rule("org1", {"rule_name": "Test", "enabled": True})
    updated = engine.update_rule("org1", rule["id"], {"enabled": False})
    assert updated["enabled"] is False


def test_update_rule_org_isolation(engine):
    rule = engine.create_rule("org1", {"rule_name": "Test"})
    result = engine.update_rule("org2", rule["id"], {"rule_name": "Hacked"})
    assert result is None


# ---------------------------------------------------------------------------
# WAF Rules — delete
# ---------------------------------------------------------------------------

def test_delete_rule(engine):
    rule = engine.create_rule("org1", {"rule_name": "ToDelete"})
    assert engine.delete_rule("org1", rule["id"]) is True
    assert engine.list_rules("org1") == []


def test_delete_rule_not_found(engine):
    assert engine.delete_rule("org1", "no-such-id") is False


def test_delete_rule_org_isolation(engine):
    rule = engine.create_rule("org1", {"rule_name": "Test"})
    assert engine.delete_rule("org2", rule["id"]) is False
    assert len(engine.list_rules("org1")) == 1


# ---------------------------------------------------------------------------
# Blocked Requests
# ---------------------------------------------------------------------------

def test_record_blocked_request(engine):
    req = engine.record_blocked_request("org1", {
        "rule_id": "rule-1",
        "source_ip": "1.2.3.4",
        "uri": "/api/users?id=1 UNION SELECT",
        "method": "GET",
        "user_agent": "curl/7.0",
        "attack_type": "sqli",
        "severity": "critical",
        "request_headers": {"X-Forwarded-For": "1.2.3.4"},
    })
    assert req["id"]
    assert req["attack_type"] == "sqli"
    assert req["source_ip"] == "1.2.3.4"
    assert isinstance(req["request_headers"], dict)
    assert req["request_headers"]["X-Forwarded-For"] == "1.2.3.4"


def test_record_blocked_request_invalid_attack_type(engine):
    with pytest.raises(ValueError, match="attack_type"):
        engine.record_blocked_request("org1", {"attack_type": "phishing"})


def test_record_blocked_request_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.record_blocked_request("org1", {"attack_type": "xss", "severity": "info"})


def test_list_blocked_requests_filter_attack_type(engine):
    engine.record_blocked_request("org1", {"attack_type": "sqli", "severity": "high"})
    engine.record_blocked_request("org1", {"attack_type": "xss", "severity": "medium"})
    engine.record_blocked_request("org1", {"attack_type": "sqli", "severity": "critical"})
    sqli = engine.list_blocked_requests("org1", attack_type="sqli")
    assert len(sqli) == 2
    xss = engine.list_blocked_requests("org1", attack_type="xss")
    assert len(xss) == 1


def test_list_blocked_requests_filter_severity(engine):
    engine.record_blocked_request("org1", {"attack_type": "xss", "severity": "critical"})
    engine.record_blocked_request("org1", {"attack_type": "lfi", "severity": "high"})
    critical = engine.list_blocked_requests("org1", severity="critical")
    assert len(critical) == 1


def test_list_blocked_requests_hours_filter(engine):
    # Record a request with a very old timestamp
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    engine.record_blocked_request("org1", {
        "attack_type": "xss",
        "severity": "high",
        "blocked_at": old_ts,
    })
    # Should not appear in 24h window
    results = engine.list_blocked_requests("org1", hours=24)
    assert len(results) == 0
    # Should appear in 72h window
    results = engine.list_blocked_requests("org1", hours=72)
    assert len(results) == 1


def test_list_blocked_requests_org_isolation(engine):
    engine.record_blocked_request("org1", {"attack_type": "xss", "severity": "high"})
    engine.record_blocked_request("org2", {"attack_type": "sqli", "severity": "critical"})
    assert len(engine.list_blocked_requests("org1")) == 1
    assert len(engine.list_blocked_requests("org2")) == 1


# ---------------------------------------------------------------------------
# Virtual Patches
# ---------------------------------------------------------------------------

def test_add_virtual_patch(engine):
    patch = engine.add_virtual_patch("org1", {
        "cve_id": "CVE-2024-1234",
        "title": "Apache Log4j RCE",
        "rule_pattern": ".*\\$\\{jndi:.*",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    })
    assert patch["id"]
    assert patch["cve_id"] == "CVE-2024-1234"
    assert patch["title"] == "Apache Log4j RCE"
    assert patch["active"] is True


def test_add_virtual_patch_default_expiry(engine):
    patch = engine.add_virtual_patch("org1", {
        "cve_id": "CVE-2024-9999",
        "title": "Test CVE",
    })
    # expires_at should be set (default 30 days)
    assert patch["expires_at"]
    expires = datetime.fromisoformat(patch["expires_at"])
    assert expires > datetime.now(timezone.utc)


def test_list_virtual_patches_active_only(engine):
    # Active patch
    future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    engine.add_virtual_patch("org1", {"cve_id": "CVE-A", "title": "A", "expires_at": future})
    # Expired patch
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    engine.add_virtual_patch("org1", {"cve_id": "CVE-B", "title": "B", "expires_at": past})

    active = engine.list_virtual_patches("org1", active_only=True)
    assert len(active) == 1
    assert active[0]["cve_id"] == "CVE-A"

    all_patches = engine.list_virtual_patches("org1", active_only=False)
    assert len(all_patches) == 2


def test_list_virtual_patches_org_isolation(engine):
    future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    engine.add_virtual_patch("org1", {"cve_id": "CVE-1", "title": "T1", "expires_at": future})
    engine.add_virtual_patch("org2", {"cve_id": "CVE-2", "title": "T2", "expires_at": future})
    assert len(engine.list_virtual_patches("org1")) == 1
    assert len(engine.list_virtual_patches("org2")) == 1


# ---------------------------------------------------------------------------
# Rate Limit Rules
# ---------------------------------------------------------------------------

def test_create_rate_limit_rule(engine):
    rule = engine.create_rate_limit_rule("org1", {
        "endpoint_pattern": "/api/login",
        "requests_per_minute": 10,
        "burst_size": 3,
        "action": "block",
    })
    assert rule["id"]
    assert rule["endpoint_pattern"] == "/api/login"
    assert rule["requests_per_minute"] == 10
    assert rule["burst_size"] == 3
    assert rule["action"] == "block"


def test_create_rate_limit_rule_throttle(engine):
    rule = engine.create_rate_limit_rule("org1", {
        "endpoint_pattern": "/api/search",
        "requests_per_minute": 30,
        "burst_size": 5,
        "action": "throttle",
    })
    assert rule["action"] == "throttle"


def test_create_rate_limit_rule_invalid_action(engine):
    with pytest.raises(ValueError, match="action"):
        engine.create_rate_limit_rule("org1", {"action": "drop"})


def test_list_rate_limit_rules(engine):
    engine.create_rate_limit_rule("org1", {"endpoint_pattern": "/a"})
    engine.create_rate_limit_rule("org1", {"endpoint_pattern": "/b"})
    rules = engine.list_rate_limit_rules("org1")
    assert len(rules) == 2


def test_list_rate_limit_rules_org_isolation(engine):
    engine.create_rate_limit_rule("org1", {"endpoint_pattern": "/x"})
    engine.create_rate_limit_rule("org2", {"endpoint_pattern": "/y"})
    assert len(engine.list_rate_limit_rules("org1")) == 1
    assert len(engine.list_rate_limit_rules("org2")) == 1


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_waf_stats_empty(engine):
    stats = engine.get_waf_stats("org1")
    assert "total_rules" in stats
    assert "enabled_rules" in stats
    assert "blocked_requests_24h" in stats
    assert "blocked_requests_7d" in stats
    assert "by_attack_type" in stats
    assert "top_source_ips" in stats
    assert "virtual_patches_active" in stats
    assert "false_positive_rate" in stats
    assert stats["total_rules"] == 0
    assert stats["blocked_requests_24h"] == 0


def test_get_waf_stats_counts(engine):
    engine.create_rule("org1", {"rule_name": "R1", "enabled": True})
    engine.create_rule("org1", {"rule_name": "R2", "enabled": False})
    engine.record_blocked_request("org1", {"attack_type": "sqli", "severity": "high"})
    engine.record_blocked_request("org1", {"attack_type": "xss", "severity": "medium"})

    future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    engine.add_virtual_patch("org1", {"cve_id": "CVE-1", "title": "T", "expires_at": future})

    stats = engine.get_waf_stats("org1")
    assert stats["total_rules"] == 2
    assert stats["enabled_rules"] == 1
    assert stats["blocked_requests_24h"] == 2
    assert stats["blocked_requests_7d"] == 2
    assert "sqli" in stats["by_attack_type"]
    assert "xss" in stats["by_attack_type"]
    assert stats["virtual_patches_active"] == 1


def test_get_waf_stats_org_isolation(engine):
    engine.create_rule("org1", {"rule_name": "R"})
    engine.record_blocked_request("org1", {"attack_type": "xss", "severity": "high"})
    stats = engine.get_waf_stats("org2")
    assert stats["total_rules"] == 0
    assert stats["blocked_requests_24h"] == 0


def test_get_waf_stats_top_source_ips(engine):
    for _ in range(3):
        engine.record_blocked_request("org1", {"attack_type": "sqli", "severity": "high", "source_ip": "10.0.0.1"})
    engine.record_blocked_request("org1", {"attack_type": "xss", "severity": "medium", "source_ip": "10.0.0.2"})
    stats = engine.get_waf_stats("org1")
    assert len(stats["top_source_ips"]) >= 1
    assert stats["top_source_ips"][0]["ip"] == "10.0.0.1"
    assert stats["top_source_ips"][0]["count"] == 3
