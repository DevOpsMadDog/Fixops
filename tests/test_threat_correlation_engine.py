"""
Tests for ThreatCorrelationEngine — 20 tests covering:
- DB init
- create_rule / list_rules
- ingest_event / list_events
- correlate: triggers alert when threshold met
- correlate: does NOT trigger below threshold
- Alert CRUD (create, list, filter by status)
- close_alert
- get_correlation_stats
- Org isolation

Run with: python -m pytest tests/test_threat_correlation_engine.py -v --timeout=10
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.threat_correlation_engine import ThreatCorrelationEngine


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def engine(tmp_path):
    """Fresh ThreatCorrelationEngine backed by a temp SQLite DB."""
    return ThreatCorrelationEngine(db_path=str(tmp_path / "threat_corr_test.db"))


@pytest.fixture
def org():
    return f"org-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def sample_rule_data():
    return {
        "name": "Brute Force Detection",
        "description": "Detect brute force login attempts",
        "event_types": ["login_failure"],
        "time_window_minutes": 60,
        "threshold": 3,
        "severity": "high",
        "correlation_logic": {"groupBy": "source_ip"},
        "enabled": True,
    }


@pytest.fixture
def rule(engine, org, sample_rule_data):
    return engine.create_rule(org, sample_rule_data)


# ============================================================================
# INIT
# ============================================================================


class TestInit:
    def test_engine_initializes(self, engine):
        assert engine is not None

    def test_db_file_created(self, tmp_path):
        db_path = str(tmp_path / "init_test.db")
        e = ThreatCorrelationEngine(db_path=db_path)
        assert Path(db_path).exists()

    def test_empty_org_has_no_rules(self, engine, org):
        rules = engine.list_rules(org)
        assert rules == []

    def test_empty_org_has_no_alerts(self, engine, org):
        alerts = engine.list_alerts(org)
        assert alerts == []


# ============================================================================
# CREATE / LIST RULES
# ============================================================================


class TestRules:
    def test_create_rule_returns_dict(self, engine, org, sample_rule_data):
        rule = engine.create_rule(org, sample_rule_data)
        assert isinstance(rule, dict)
        assert "rule_id" in rule

    def test_create_rule_fields(self, engine, org, sample_rule_data):
        rule = engine.create_rule(org, sample_rule_data)
        assert rule["name"] == "Brute Force Detection"
        assert rule["threshold"] == 3
        assert rule["severity"] == "high"
        assert rule["enabled"] is True
        assert rule["event_types"] == ["login_failure"]

    def test_create_rule_generates_uuid(self, engine, org, sample_rule_data):
        rule = engine.create_rule(org, sample_rule_data)
        # Valid UUID4 format
        uid = uuid.UUID(rule["rule_id"])
        assert uid.version == 4

    def test_list_rules_returns_created(self, engine, org, rule):
        rules = engine.list_rules(org)
        ids = [r["rule_id"] for r in rules]
        assert rule["rule_id"] in ids

    def test_list_rules_org_isolation(self, engine, rule, org):
        other_org = f"other-{uuid.uuid4().hex[:6]}"
        other_rules = engine.list_rules(other_org)
        ids = [r["rule_id"] for r in other_rules]
        assert rule["rule_id"] not in ids

    def test_create_multiple_rules(self, engine, org, sample_rule_data):
        for i in range(3):
            d = {**sample_rule_data, "name": f"Rule {i}"}
            engine.create_rule(org, d)
        rules = engine.list_rules(org)
        assert len(rules) == 3


# ============================================================================
# INGEST / LIST EVENTS
# ============================================================================


class TestEvents:
    def test_ingest_event_returns_dict(self, engine, org):
        evt = engine.ingest_event(org, {
            "event_type": "login_failure",
            "source_ip": "1.2.3.4",
        })
        assert isinstance(evt, dict)
        assert "event_id" in evt

    def test_ingest_event_fields(self, engine, org):
        evt = engine.ingest_event(org, {
            "event_type": "malware_detected",
            "source_ip": "10.0.0.1",
            "user_id": "user123",
            "asset_id": "asset-abc",
            "raw_data": {"hash": "abc123"},
        })
        assert evt["event_type"] == "malware_detected"
        assert evt["source_ip"] == "10.0.0.1"
        assert evt["user_id"] == "user123"

    def test_list_events_returns_ingested(self, engine, org):
        engine.ingest_event(org, {"event_type": "network_anomaly", "source_ip": "5.5.5.5"})
        events = engine.list_events(org)
        assert len(events) >= 1

    def test_list_events_filter_by_type(self, engine, org):
        engine.ingest_event(org, {"event_type": "login_failure"})
        engine.ingest_event(org, {"event_type": "malware_detected"})
        login_events = engine.list_events(org, event_type="login_failure")
        assert all(e["event_type"] == "login_failure" for e in login_events)

    def test_list_events_org_isolation(self, engine, org):
        other_org = f"other-{uuid.uuid4().hex[:6]}"
        engine.ingest_event(other_org, {"event_type": "data_exfil"})
        events = engine.list_events(org)
        assert all(e["org_id"] == org for e in events)


# ============================================================================
# CORRELATE
# ============================================================================


class TestCorrelate:
    def test_correlate_triggers_alert_when_threshold_met(self, engine, org):
        # Create rule: threshold=3, window=60m
        engine.create_rule(org, {
            "name": "Login Brute Force",
            "event_types": ["login_failure"],
            "time_window_minutes": 60,
            "threshold": 3,
            "severity": "high",
        })
        # Ingest exactly 3 events
        for _ in range(3):
            engine.ingest_event(org, {"event_type": "login_failure", "source_ip": "1.2.3.4"})

        alerts = engine.correlate(org)
        assert len(alerts) >= 1
        assert alerts[0]["severity"] == "high"

    def test_correlate_does_not_trigger_below_threshold(self, engine, org):
        engine.create_rule(org, {
            "name": "High Threshold Rule",
            "event_types": ["privilege_escalation"],
            "time_window_minutes": 60,
            "threshold": 10,
            "severity": "critical",
        })
        # Only 2 events — below threshold of 10
        for _ in range(2):
            engine.ingest_event(org, {"event_type": "privilege_escalation"})

        alerts = engine.correlate(org)
        assert len(alerts) == 0

    def test_correlate_multiple_event_types(self, engine, org):
        engine.create_rule(org, {
            "name": "Multi-Type Rule",
            "event_types": ["lateral_movement", "privilege_escalation"],
            "time_window_minutes": 60,
            "threshold": 2,
            "severity": "critical",
        })
        engine.ingest_event(org, {"event_type": "lateral_movement"})
        engine.ingest_event(org, {"event_type": "privilege_escalation"})

        alerts = engine.correlate(org)
        assert len(alerts) >= 1

    def test_correlate_skips_disabled_rules(self, engine, org):
        engine.create_rule(org, {
            "name": "Disabled Rule",
            "event_types": ["data_exfil"],
            "time_window_minutes": 60,
            "threshold": 1,
            "severity": "medium",
            "enabled": False,
        })
        engine.ingest_event(org, {"event_type": "data_exfil"})

        alerts = engine.correlate(org)
        assert len(alerts) == 0

    def test_correlate_alert_has_matched_events(self, engine, org):
        engine.create_rule(org, {
            "name": "Match Events Rule",
            "event_types": ["network_anomaly"],
            "time_window_minutes": 60,
            "threshold": 2,
            "severity": "medium",
        })
        engine.ingest_event(org, {"event_type": "network_anomaly"})
        engine.ingest_event(org, {"event_type": "network_anomaly"})

        alerts = engine.correlate(org)
        assert len(alerts) >= 1
        assert len(alerts[0]["matched_events"]) >= 2


# ============================================================================
# ALERTS
# ============================================================================


class TestAlerts:
    def test_create_alert_returns_dict(self, engine, org, rule):
        alert = engine.create_alert(org, {
            "rule_id": rule["rule_id"],
            "matched_events": ["evt-1", "evt-2"],
            "severity": "high",
        })
        assert isinstance(alert, dict)
        assert "corr_alert_id" in alert

    def test_create_alert_default_status_open(self, engine, org, rule):
        alert = engine.create_alert(org, {
            "rule_id": rule["rule_id"],
            "matched_events": [],
            "severity": "low",
        })
        assert alert["status"] == "open"

    def test_list_alerts_returns_created(self, engine, org, rule):
        engine.create_alert(org, {"rule_id": rule["rule_id"], "matched_events": [], "severity": "medium"})
        alerts = engine.list_alerts(org)
        assert len(alerts) >= 1

    def test_list_alerts_filter_by_status(self, engine, org, rule):
        a1 = engine.create_alert(org, {"rule_id": rule["rule_id"], "matched_events": [], "severity": "low"})
        engine.close_alert(org, a1["corr_alert_id"], "false positive")
        engine.create_alert(org, {"rule_id": rule["rule_id"], "matched_events": [], "severity": "medium"})

        open_alerts = engine.list_alerts(org, status="open")
        assert all(a["status"] == "open" for a in open_alerts)

    def test_close_alert_returns_true(self, engine, org, rule):
        alert = engine.create_alert(org, {
            "rule_id": rule["rule_id"],
            "matched_events": [],
            "severity": "high",
        })
        result = engine.close_alert(org, alert["corr_alert_id"], "confirmed and remediated")
        assert result is True

    def test_close_alert_sets_status_closed(self, engine, org, rule):
        alert = engine.create_alert(org, {
            "rule_id": rule["rule_id"],
            "matched_events": [],
            "severity": "high",
        })
        engine.close_alert(org, alert["corr_alert_id"], "resolved")
        closed = engine.list_alerts(org, status="closed")
        ids = [a["corr_alert_id"] for a in closed]
        assert alert["corr_alert_id"] in ids

    def test_close_nonexistent_alert_returns_false(self, engine, org):
        result = engine.close_alert(org, "nonexistent-id", "whatever")
        assert result is False

    def test_alerts_org_isolation(self, engine, org, rule):
        other_org = f"other-{uuid.uuid4().hex[:6]}"
        engine.create_alert(other_org, {"rule_id": "any", "matched_events": [], "severity": "low"})
        alerts = engine.list_alerts(org)
        assert all(a["org_id"] == org for a in alerts)


# ============================================================================
# STATS
# ============================================================================


class TestStats:
    def test_stats_returns_dict(self, engine, org):
        stats = engine.get_correlation_stats(org)
        assert isinstance(stats, dict)

    def test_stats_empty_org(self, engine):
        empty_org = f"empty-{uuid.uuid4().hex[:6]}"
        stats = engine.get_correlation_stats(empty_org)
        assert stats["total_rules"] == 0
        assert stats["total_events"] == 0
        assert stats["total_alerts"] == 0

    def test_stats_counts_rules(self, engine, org, sample_rule_data):
        engine.create_rule(org, sample_rule_data)
        engine.create_rule(org, {**sample_rule_data, "name": "Rule 2"})
        stats = engine.get_correlation_stats(org)
        assert stats["total_rules"] == 2

    def test_stats_counts_events(self, engine, org):
        engine.ingest_event(org, {"event_type": "login_failure"})
        engine.ingest_event(org, {"event_type": "malware_detected"})
        stats = engine.get_correlation_stats(org)
        assert stats["total_events"] == 2

    def test_stats_counts_alerts(self, engine, org, rule):
        engine.create_alert(org, {"rule_id": rule["rule_id"], "matched_events": [], "severity": "low"})
        stats = engine.get_correlation_stats(org)
        assert stats["total_alerts"] == 1
        assert stats["open_alerts"] == 1

    def test_stats_events_by_type(self, engine, org):
        engine.ingest_event(org, {"event_type": "login_failure"})
        engine.ingest_event(org, {"event_type": "login_failure"})
        engine.ingest_event(org, {"event_type": "data_exfil"})
        stats = engine.get_correlation_stats(org)
        assert stats["events_by_type"].get("login_failure", 0) == 2
        assert stats["events_by_type"].get("data_exfil", 0) == 1
