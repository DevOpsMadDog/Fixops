"""Tests for BrowserSecurityEngine — policies, events, extensions, stats."""

from __future__ import annotations

import pytest

from core.browser_security_engine import BrowserSecurityEngine


@pytest.fixture
def engine(tmp_path):
    return BrowserSecurityEngine(db_path=str(tmp_path / "browser_security.db"))


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = tmp_path / "bs.db"
    BrowserSecurityEngine(db_path=str(db))
    assert db.exists()


def test_init_idempotent(tmp_path):
    db = tmp_path / "bs.db"
    BrowserSecurityEngine(db_path=str(db))
    BrowserSecurityEngine(db_path=str(db))


# ---------------------------------------------------------------------------
# create_policy
# ---------------------------------------------------------------------------

def test_create_policy_returns_record(engine):
    policy = engine.create_policy("org1", {
        "policy_name": "Chrome Hardening",
        "browser_type": "chrome",
        "enforcement_level": "mandatory",
    })
    assert policy["id"]
    assert policy["policy_name"] == "Chrome Hardening"
    assert policy["browser_type"] == "chrome"
    assert policy["enforcement_level"] == "mandatory"
    assert policy["org_id"] == "org1"
    assert policy["status"] == "active"


def test_create_policy_default_status_active(engine):
    policy = engine.create_policy("org1", {"policy_name": "P1", "browser_type": "all"})
    assert policy["status"] == "active"


def test_create_policy_invalid_browser_type_raises(engine):
    with pytest.raises(ValueError, match="browser_type"):
        engine.create_policy("org1", {"policy_name": "X", "browser_type": "opera"})


def test_create_policy_invalid_enforcement_level_raises(engine):
    with pytest.raises(ValueError, match="enforcement_level"):
        engine.create_policy("org1", {"policy_name": "X", "enforcement_level": "strict"})


def test_create_policy_all_browser_types(engine):
    for bt in ("chrome", "firefox", "edge", "safari", "all"):
        policy = engine.create_policy("org1", {"policy_name": f"P-{bt}", "browser_type": bt})
        assert policy["browser_type"] == bt


def test_create_policy_draft_status(engine):
    policy = engine.create_policy("org1", {"policy_name": "Draft", "status": "draft"})
    assert policy["status"] == "draft"


def test_create_policy_stores_settings(engine):
    settings = {"block_third_party_cookies": True, "safe_browsing": "enhanced"}
    policy = engine.create_policy("org1", {"policy_name": "Secure", "settings": settings})
    assert policy["settings"]["block_third_party_cookies"] is True


# ---------------------------------------------------------------------------
# list_policies
# ---------------------------------------------------------------------------

def test_list_policies_empty(engine):
    assert engine.list_policies("org1") == []


def test_list_policies_org_isolation(engine):
    engine.create_policy("org1", {"policy_name": "P1", "browser_type": "chrome"})
    engine.create_policy("org2", {"policy_name": "P2", "browser_type": "firefox"})
    assert len(engine.list_policies("org1")) == 1
    assert len(engine.list_policies("org2")) == 1


def test_list_policies_filter_browser_type(engine):
    engine.create_policy("org1", {"policy_name": "Chrome Policy", "browser_type": "chrome"})
    engine.create_policy("org1", {"policy_name": "Firefox Policy", "browser_type": "firefox"})
    results = engine.list_policies("org1", browser_type="chrome")
    assert len(results) == 1
    assert results[0]["browser_type"] == "chrome"


def test_list_policies_filter_status(engine):
    engine.create_policy("org1", {"policy_name": "Active", "status": "active"})
    engine.create_policy("org1", {"policy_name": "Draft", "status": "draft"})
    results = engine.list_policies("org1", status="active")
    assert len(results) == 1
    assert results[0]["status"] == "active"


# ---------------------------------------------------------------------------
# get_policy
# ---------------------------------------------------------------------------

def test_get_policy_returns_record(engine):
    policy = engine.create_policy("org1", {"policy_name": "Test", "browser_type": "edge"})
    fetched = engine.get_policy("org1", policy["id"])
    assert fetched is not None
    assert fetched["id"] == policy["id"]
    assert fetched["browser_type"] == "edge"


def test_get_policy_not_found_returns_none(engine):
    assert engine.get_policy("org1", "nonexistent-id") is None


def test_get_policy_org_isolation(engine):
    policy = engine.create_policy("org1", {"policy_name": "Org1 Policy"})
    assert engine.get_policy("org2", policy["id"]) is None


# ---------------------------------------------------------------------------
# record_event
# ---------------------------------------------------------------------------

def test_record_event_returns_record(engine):
    event = engine.record_event("org1", {
        "event_type": "malicious_download",
        "severity": "high",
        "user_id": "user-123",
        "url": "https://evil.example.com/malware.exe",
    })
    assert event["id"]
    assert event["event_type"] == "malicious_download"
    assert event["severity"] == "high"
    assert event["org_id"] == "org1"
    assert event["blocked"] is False


def test_record_event_invalid_event_type_raises(engine):
    with pytest.raises(ValueError, match="event_type"):
        engine.record_event("org1", {"event_type": "unknown_event", "severity": "low"})


def test_record_event_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.record_event("org1", {"event_type": "cert_error", "severity": "extreme"})


def test_record_event_blocked_field(engine):
    event = engine.record_event("org1", {
        "event_type": "phishing_attempt",
        "severity": "critical",
        "blocked": True,
    })
    assert event["blocked"] is True


def test_record_event_all_event_types(engine):
    event_types = [
        "malicious_download", "phishing_attempt", "extension_install",
        "data_exfil_attempt", "cert_error", "mixed_content",
        "unsafe_navigation", "credential_leak",
    ]
    for et in event_types:
        event = engine.record_event("org1", {"event_type": et, "severity": "low"})
        assert event["event_type"] == et


# ---------------------------------------------------------------------------
# list_events
# ---------------------------------------------------------------------------

def test_list_events_empty(engine):
    assert engine.list_events("org1") == []


def test_list_events_filter_event_type(engine):
    engine.record_event("org1", {"event_type": "cert_error", "severity": "low"})
    engine.record_event("org1", {"event_type": "phishing_attempt", "severity": "high"})
    results = engine.list_events("org1", event_type="cert_error")
    assert len(results) == 1
    assert results[0]["event_type"] == "cert_error"


def test_list_events_filter_severity(engine):
    engine.record_event("org1", {"event_type": "cert_error", "severity": "low"})
    engine.record_event("org1", {"event_type": "malicious_download", "severity": "critical"})
    results = engine.list_events("org1", severity="critical")
    assert len(results) == 1
    assert results[0]["severity"] == "critical"


def test_list_events_filter_blocked(engine):
    engine.record_event("org1", {"event_type": "phishing_attempt", "severity": "high", "blocked": True})
    engine.record_event("org1", {"event_type": "cert_error", "severity": "low", "blocked": False})
    blocked = engine.list_events("org1", blocked=True)
    not_blocked = engine.list_events("org1", blocked=False)
    assert len(blocked) == 1
    assert len(not_blocked) == 1
    assert blocked[0]["blocked"] is True


def test_list_events_org_isolation(engine):
    engine.record_event("org1", {"event_type": "cert_error", "severity": "low"})
    engine.record_event("org2", {"event_type": "cert_error", "severity": "low"})
    assert len(engine.list_events("org1")) == 1
    assert len(engine.list_events("org2")) == 1


# ---------------------------------------------------------------------------
# register_extension + list_extensions
# ---------------------------------------------------------------------------

def test_register_extension_returns_record(engine):
    ext = engine.register_extension("org1", {
        "extension_id": "ext-abc123",
        "name": "Password Manager",
        "version": "3.1.0",
        "browser_type": "chrome",
        "risk_level": "low",
        "permissions": ["tabs", "storage"],
        "publisher": "TrustCo",
    })
    assert ext["id"]
    assert ext["name"] == "Password Manager"
    assert ext["risk_level"] == "low"
    assert ext["status"] == "under_review"
    assert ext["org_id"] == "org1"


def test_register_extension_default_status_under_review(engine):
    ext = engine.register_extension("org1", {
        "extension_id": "ext-xyz",
        "name": "Ad Blocker",
        "risk_level": "safe",
    })
    assert ext["status"] == "under_review"


def test_register_extension_invalid_risk_level_raises(engine):
    with pytest.raises(ValueError, match="risk_level"):
        engine.register_extension("org1", {
            "extension_id": "ext-1",
            "name": "Bad",
            "risk_level": "unknown",
        })


def test_list_extensions_filter_risk_level(engine):
    engine.register_extension("org1", {"extension_id": "e1", "name": "A", "risk_level": "critical"})
    engine.register_extension("org1", {"extension_id": "e2", "name": "B", "risk_level": "safe"})
    results = engine.list_extensions("org1", risk_level="critical")
    assert len(results) == 1
    assert results[0]["risk_level"] == "critical"


def test_list_extensions_filter_status(engine):
    engine.register_extension("org1", {"extension_id": "e1", "name": "A", "risk_level": "low", "status": "approved"})
    engine.register_extension("org1", {"extension_id": "e2", "name": "B", "risk_level": "high", "status": "blocked"})
    approved = engine.list_extensions("org1", status="approved")
    assert len(approved) == 1
    assert approved[0]["status"] == "approved"


# ---------------------------------------------------------------------------
# update_extension_status
# ---------------------------------------------------------------------------

def test_update_extension_status_valid(engine):
    ext = engine.register_extension("org1", {
        "extension_id": "e1",
        "name": "Test Ext",
        "risk_level": "medium",
    })
    updated = engine.update_extension_status("org1", ext["id"], "approved")
    assert updated is not None
    assert updated["status"] == "approved"


def test_update_extension_status_invalid_raises(engine):
    ext = engine.register_extension("org1", {
        "extension_id": "e2",
        "name": "Test Ext 2",
        "risk_level": "low",
    })
    with pytest.raises(ValueError, match="status"):
        engine.update_extension_status("org1", ext["id"], "whitelisted")


def test_update_extension_status_not_found_returns_none(engine):
    result = engine.update_extension_status("org1", "nonexistent-id", "approved")
    assert result is None


# ---------------------------------------------------------------------------
# get_browser_stats
# ---------------------------------------------------------------------------

def test_get_browser_stats_empty_org(engine):
    stats = engine.get_browser_stats("org_empty")
    assert stats["total_policies"] == 0
    assert stats["active_policies"] == 0
    assert stats["total_events"] == 0
    assert stats["blocked_events"] == 0
    assert stats["critical_events"] == 0
    assert stats["by_event_type"] == {}
    assert stats["by_risk_level"] == {}
    assert stats["extension_counts"] == {}


def test_get_browser_stats_populated_counts(engine):
    engine.create_policy("org1", {"policy_name": "P1", "status": "active"})
    engine.create_policy("org1", {"policy_name": "P2", "status": "inactive"})
    engine.record_event("org1", {"event_type": "cert_error", "severity": "critical", "blocked": True})
    engine.record_event("org1", {"event_type": "phishing_attempt", "severity": "high", "blocked": False})
    engine.register_extension("org1", {"extension_id": "e1", "name": "E1", "risk_level": "high", "status": "blocked"})

    stats = engine.get_browser_stats("org1")
    assert stats["total_policies"] == 2
    assert stats["active_policies"] == 1
    assert stats["total_events"] == 2
    assert stats["blocked_events"] == 1
    assert stats["critical_events"] == 1
    assert stats["by_event_type"]["cert_error"] == 1
    assert stats["by_event_type"]["phishing_attempt"] == 1
    assert stats["by_risk_level"]["high"] == 1
    assert stats["extension_counts"]["blocked"] == 1
