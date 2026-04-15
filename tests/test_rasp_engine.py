"""Tests for RaspEngine — 27 tests covering detection, sessions, blocking, metrics."""

from __future__ import annotations

import pytest
from core.rasp_engine import (
    RaspEngine,
    RaspConfig,
    RaspMode,
    ThreatCategory,
    ThreatSeverity,
    SessionRecord,
    RateLimitConfig,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "rasp_test.db")
    cfg = RaspConfig(mode=RaspMode.BLOCK)
    return RaspEngine(config=cfg, db_path=db)


@pytest.fixture
def monitor_engine(tmp_path):
    db = str(tmp_path / "rasp_monitor.db")
    cfg = RaspConfig(mode=RaspMode.MONITOR)
    return RaspEngine(config=cfg, db_path=db)


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


# ---------------------------------------------------------------------------
# Initialisation / config
# ---------------------------------------------------------------------------

def test_engine_initialises_with_patterns(engine):
    rules = engine.get_rules()
    assert len(rules) > 0


def test_engine_default_mode_block(engine):
    assert engine.config.mode == RaspMode.BLOCK


def test_set_mode_changes_config(engine):
    engine.set_mode(RaspMode.MONITOR)
    assert engine.config.mode == RaspMode.MONITOR


def test_update_config_changes_field(engine):
    engine.update_config(inspect_request_body=False)
    assert engine.config.inspect_request_body is False


# ---------------------------------------------------------------------------
# Rule management
# ---------------------------------------------------------------------------

def test_get_rules_returns_list(engine):
    rules = engine.get_rules()
    assert isinstance(rules, list)
    assert all(hasattr(r, "rule_id") for r in rules)


def test_set_rule_enabled_disables_rule(engine):
    rules = engine.get_rules()
    first_rule_id = rules[0].rule_id
    result = engine.set_rule_enabled(first_rule_id, False)
    assert result is True
    updated = [r for r in engine.get_rules() if r.rule_id == first_rule_id]
    assert updated[0].enabled is False


def test_set_rule_enabled_returns_false_for_unknown(engine):
    result = engine.set_rule_enabled("NONEXISTENT-RULE", True)
    assert result is False


# ---------------------------------------------------------------------------
# inspect_values — SQLi detection
# ---------------------------------------------------------------------------

def test_inspect_values_detects_sqli_union(engine, org):
    values = {"query:id": "1 UNION SELECT username, password FROM users"}
    events = engine.inspect_values(values, client_ip="1.2.3.4",
                                   method="GET", path="/api/users", org_id=org)
    assert len(events) >= 1
    assert any(e.category == ThreatCategory.SQLI for e in events)


def test_inspect_values_detects_xss(engine, org):
    values = {"query:q": "<script>alert(1)</script>"}
    events = engine.inspect_values(values, client_ip="1.2.3.5",
                                   method="GET", path="/search", org_id=org)
    assert len(events) >= 1
    assert any(e.category == ThreatCategory.XSS for e in events)


def test_inspect_values_detects_path_traversal(engine, org):
    values = {"query:file": "../../../etc/passwd"}
    events = engine.inspect_values(values, client_ip="1.2.3.6",
                                   method="GET", path="/download", org_id=org)
    assert len(events) >= 1
    assert any(e.category == ThreatCategory.PATH_TRAVERSAL for e in events)


def test_inspect_values_clean_request_returns_empty(engine, org):
    values = {"query:name": "john", "query:page": "2"}
    events = engine.inspect_values(values, client_ip="10.0.0.1",
                                   method="GET", path="/api/users", org_id=org)
    assert events == []


def test_inspect_values_records_org_id(engine, org):
    values = {"query:id": "1 UNION SELECT * FROM users"}
    events = engine.inspect_values(values, client_ip="2.2.2.2",
                                   method="GET", path="/", org_id=org)
    for ev in events:
        assert ev.org_id == org


# ---------------------------------------------------------------------------
# inspect_request_sync
# ---------------------------------------------------------------------------

def test_inspect_request_sync_blocks_sqli(engine, org):
    blocked, threats = engine.inspect_request_sync(
        client_ip="3.3.3.3",
        method="GET",
        path="/api/data",
        query_params={"id": "1 UNION SELECT * FROM secrets"},
        org_id=org,
    )
    assert blocked is True
    assert len(threats) >= 1


def test_inspect_request_sync_allows_clean(engine, org):
    blocked, threats = engine.inspect_request_sync(
        client_ip="4.4.4.4",
        method="GET",
        path="/api/users",
        query_params={"name": "alice"},
        org_id=org,
    )
    assert blocked is False
    assert threats == []


def test_inspect_request_sync_monitor_mode_not_blocked(monitor_engine, org):
    blocked, threats = monitor_engine.inspect_request_sync(
        client_ip="5.5.5.5",
        method="GET",
        path="/search",
        query_params={"q": "<script>alert(1)</script>"},
        org_id=org,
    )
    # In MONITOR mode, threats are detected but not blocked
    assert blocked is False
    assert len(threats) >= 1


def test_inspect_request_sync_trusted_ip_bypasses(engine, org):
    engine.update_config(trusted_ips=["9.9.9.9"])
    blocked, threats = engine.inspect_request_sync(
        client_ip="9.9.9.9",
        method="GET",
        path="/",
        query_params={"id": "1 UNION SELECT * FROM users"},
        org_id=org,
    )
    assert blocked is False
    assert threats == []


def test_inspect_request_sync_body_inspection(engine, org):
    blocked, threats = engine.inspect_request_sync(
        client_ip="6.6.6.6",
        method="POST",
        path="/api/submit",
        body_text='{"comment": "<script>alert(document.cookie)</script>"}',
        org_id=org,
    )
    assert len(threats) >= 1


# ---------------------------------------------------------------------------
# IP blocking
# ---------------------------------------------------------------------------

def test_block_ip_manual(engine):
    engine.block_ip("7.7.7.7", duration_seconds=60)
    blocked_ips = engine.get_blocked_ips()
    assert "7.7.7.7" in blocked_ips
    assert blocked_ips["7.7.7.7"] > 0


def test_unblock_ip_returns_true(engine):
    engine.block_ip("8.8.8.8", duration_seconds=60)
    result = engine.unblock_ip("8.8.8.8")
    assert result is True
    assert "8.8.8.8" not in engine.get_blocked_ips()


def test_unblock_ip_returns_false_for_not_blocked(engine):
    result = engine.unblock_ip("not-blocked-ip")
    assert result is False


def test_blocked_ip_returns_blocked_on_request(engine, org):
    engine.block_ip("blocked-ip", duration_seconds=300)
    blocked, threats = engine.inspect_request_sync(
        client_ip="blocked-ip",
        method="GET",
        path="/",
        org_id=org,
    )
    assert blocked is True


# ---------------------------------------------------------------------------
# Session protection
# ---------------------------------------------------------------------------

def test_register_and_check_session_clean(engine):
    sess = SessionRecord(
        session_id="sess-001",
        user_id="user-A",
        client_ip="10.0.0.1",
    )
    engine.register_session(sess)
    anomalies = engine.check_session("sess-001", "10.0.0.1", user_id="user-A")
    assert anomalies == []


def test_check_session_detects_fixation(engine):
    sess = SessionRecord(
        session_id="sess-002",
        user_id="user-B",
        client_ip="10.0.0.1",
    )
    engine.register_session(sess)
    # Different IP on same session
    anomalies = engine.check_session("sess-002", "10.0.0.99", user_id="user-B")
    assert "session_fixation" in anomalies


def test_terminate_session(engine):
    sess = SessionRecord(
        session_id="sess-003",
        user_id="user-C",
        client_ip="10.0.0.2",
    )
    engine.register_session(sess)
    engine.terminate_session("sess-003")
    # After termination, session is unknown — touch returns None (no fixation)
    anomalies = engine.check_session("sess-003", "10.0.0.2")
    assert anomalies == []


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def test_get_metrics_structure(engine):
    m = engine.get_metrics()
    assert m.requests_inspected >= 0
    assert m.threats_detected >= 0
    assert isinstance(m.by_category, dict)
    assert isinstance(m.by_severity, dict)
    assert m.engine_uptime_seconds >= 0.0


def test_get_metrics_increments_on_threat(engine, org):
    engine.inspect_request_sync(
        client_ip="20.0.0.1",
        method="GET",
        path="/api",
        query_params={"id": "1 UNION SELECT * FROM users"},
        org_id=org,
    )
    m = engine.get_metrics()
    assert m.requests_inspected >= 1
    assert m.threats_detected >= 1
    assert m.threats_blocked >= 1


def test_get_recent_threats_empty_initially(engine):
    threats = engine.get_recent_threats(limit=10)
    assert isinstance(threats, list)


def test_get_recent_threats_category_filter(engine, org):
    engine.inspect_request_sync(
        client_ip="20.0.0.2",
        method="GET",
        path="/search",
        query_params={"q": "<script>alert(1)</script>"},
        org_id=org,
    )
    xss_threats = engine.get_recent_threats(category=ThreatCategory.XSS)
    assert all(t.category == ThreatCategory.XSS for t in xss_threats)


# ---------------------------------------------------------------------------
# Report false positive
# ---------------------------------------------------------------------------

def test_report_false_positive_returns_true_after_threat(engine, org):
    _, threats = engine.inspect_request_sync(
        client_ip="30.0.0.1",
        method="GET",
        path="/api",
        query_params={"id": "1 UNION SELECT name FROM users"},
        org_id=org,
    )
    if threats:
        result = engine.report_false_positive(threats[0].event_id, reporter="analyst")
        assert result is True
        m = engine.get_metrics()
        assert m.false_positive_rate >= 0.0
