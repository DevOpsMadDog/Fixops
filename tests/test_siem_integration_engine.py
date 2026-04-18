"""Tests for SIEMIntegrationEngine — new source-based schema + legacy schema.

Covers: init, register_siem_source, list_siem_sources, get_siem_source,
ingest_siem_event (counter increment), list_siem_events (filters),
create_correlation_alert, list_correlation_alerts, acknowledge_alert,
get_siem_stats, org isolation, legacy API (register_siem, ingest_event,
create_alert, resolve_alert, correlate_events).

Total: 38 tests.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from core.siem_integration_engine import SIEMIntegrationEngine


@pytest.fixture()
def engine(tmp_path):
    return SIEMIntegrationEngine(db_path=str(tmp_path / "test_siem.db"))


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "siem_init.db")
    eng = SIEMIntegrationEngine(db_path=db)
    assert eng.db_path == db


def test_init_empty_stats(engine):
    stats = engine.get_siem_stats("org1")
    assert stats["total_siems"] == 0
    assert stats["total_sources"] == 0
    assert stats["total_events_24h"] == 0
    assert stats["open_alerts_count"] == 0


# ---------------------------------------------------------------------------
# 2. SIEM Source registration
# ---------------------------------------------------------------------------


def test_register_siem_source_returns_record(engine):
    result = engine.register_siem_source("org1", {
        "name": "CloudTrail Prod",
        "source_type": "cloudtrail",
    })
    assert "id" in result
    assert result["name"] == "CloudTrail Prod"
    assert result["source_type"] == "cloudtrail"
    assert result["status"] == "active"
    assert result["events_per_day"] == 0


def test_register_siem_source_all_valid_types(engine):
    valid = ["syslog", "windows_event", "cloudtrail", "azure_monitor", "gcp_logging", "custom"]
    for st in valid:
        r = engine.register_siem_source("org1", {"name": st, "source_type": st})
        assert r["source_type"] == st


def test_register_siem_source_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="source_type"):
        engine.register_siem_source("org1", {"name": "Bad", "source_type": "splunk"})


def test_register_siem_source_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_siem_source("org1", {"name": "", "source_type": "syslog"})


def test_register_siem_source_with_host_port(engine):
    result = engine.register_siem_source("org1", {
        "name": "Syslog Server",
        "source_type": "syslog",
        "host": "10.0.0.1",
        "port": 514,
    })
    assert result["host"] == "10.0.0.1"
    assert result["port"] == 514


# ---------------------------------------------------------------------------
# 3. List / Get SIEM Sources
# ---------------------------------------------------------------------------


def test_list_siem_sources_empty(engine):
    assert engine.list_siem_sources("org1") == []


def test_list_siem_sources_returns_all(engine):
    engine.register_siem_source("org1", {"name": "A", "source_type": "syslog"})
    engine.register_siem_source("org1", {"name": "B", "source_type": "cloudtrail"})
    sources = engine.list_siem_sources("org1")
    assert len(sources) == 2


def test_list_siem_sources_filter_by_source_type(engine):
    engine.register_siem_source("org1", {"name": "A", "source_type": "syslog"})
    engine.register_siem_source("org1", {"name": "B", "source_type": "cloudtrail"})
    syslog = engine.list_siem_sources("org1", source_type="syslog")
    assert len(syslog) == 1
    assert syslog[0]["source_type"] == "syslog"


def test_list_siem_sources_filter_by_status(engine):
    engine.register_siem_source("org1", {"name": "A", "source_type": "syslog"})
    active = engine.list_siem_sources("org1", status="active")
    assert len(active) == 1
    inactive = engine.list_siem_sources("org1", status="inactive")
    assert len(inactive) == 0


def test_get_siem_source_returns_correct(engine):
    src = engine.register_siem_source("org1", {"name": "Src1", "source_type": "custom"})
    fetched = engine.get_siem_source("org1", src["id"])
    assert fetched["name"] == "Src1"


def test_get_siem_source_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.get_siem_source("org1", "bad-id")


# ---------------------------------------------------------------------------
# 4. Event ingestion
# ---------------------------------------------------------------------------


def test_ingest_siem_event_returns_record(engine):
    src = engine.register_siem_source("org1", {"name": "S", "source_type": "syslog"})
    result = engine.ingest_siem_event("org1", {
        "source_id": src["id"],
        "event_type": "auth_failure",
        "severity": "high",
        "raw_data": {"user": "alice", "ip": "10.0.0.1"},
    })
    assert "id" in result
    assert result["severity"] == "high"
    assert result["event_type"] == "auth_failure"
    assert isinstance(result["raw_data"], dict)


def test_ingest_siem_event_increments_counter(engine):
    src = engine.register_siem_source("org1", {"name": "S", "source_type": "syslog"})
    engine.ingest_siem_event("org1", {
        "source_id": src["id"], "event_type": "login", "severity": "info",
        "raw_data": {},
    })
    engine.ingest_siem_event("org1", {
        "source_id": src["id"], "event_type": "login", "severity": "info",
        "raw_data": {},
    })
    updated = engine.get_siem_source("org1", src["id"])
    assert updated["events_per_day"] == 2


def test_ingest_siem_event_with_parsed_fields(engine):
    src = engine.register_siem_source("org1", {"name": "S", "source_type": "custom"})
    result = engine.ingest_siem_event("org1", {
        "source_id": src["id"],
        "event_type": "network",
        "severity": "medium",
        "raw_data": {"bytes": 1024},
        "parsed_fields": {"protocol": "TCP", "direction": "inbound"},
    })
    assert result["parsed_fields"]["protocol"] == "TCP"


def test_ingest_siem_event_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.ingest_siem_event("org1", {
            "source_id": "any", "event_type": "x", "severity": "extreme", "raw_data": {},
        })


def test_ingest_siem_event_all_valid_severities(engine):
    for sev in ["info", "low", "medium", "high", "critical"]:
        result = engine.ingest_siem_event("org1", {
            "source_id": "s1", "event_type": "test", "severity": sev, "raw_data": {},
        })
        assert result["severity"] == sev


# ---------------------------------------------------------------------------
# 5. List SIEM Events (filters)
# ---------------------------------------------------------------------------


def test_list_siem_events_empty(engine):
    assert engine.list_siem_events("org1") == []


def test_list_siem_events_filter_by_source_id(engine):
    src1 = engine.register_siem_source("org1", {"name": "S1", "source_type": "syslog"})
    src2 = engine.register_siem_source("org1", {"name": "S2", "source_type": "syslog"})
    engine.ingest_siem_event("org1", {"source_id": src1["id"], "event_type": "x", "severity": "info", "raw_data": {}})
    engine.ingest_siem_event("org1", {"source_id": src2["id"], "event_type": "x", "severity": "info", "raw_data": {}})
    events = engine.list_siem_events("org1", source_id=src1["id"])
    assert len(events) == 1
    assert events[0]["source_id"] == src1["id"]


def test_list_siem_events_filter_by_severity(engine):
    engine.ingest_siem_event("org1", {"source_id": "s1", "event_type": "x", "severity": "critical", "raw_data": {}})
    engine.ingest_siem_event("org1", {"source_id": "s1", "event_type": "x", "severity": "low", "raw_data": {}})
    crit = engine.list_siem_events("org1", severity="critical")
    assert len(crit) == 1
    assert crit[0]["severity"] == "critical"


def test_list_siem_events_filter_by_event_type(engine):
    engine.ingest_siem_event("org1", {"source_id": "s1", "event_type": "auth", "severity": "info", "raw_data": {}})
    engine.ingest_siem_event("org1", {"source_id": "s1", "event_type": "network", "severity": "info", "raw_data": {}})
    auth = engine.list_siem_events("org1", event_type="auth")
    assert len(auth) == 1


def test_list_siem_events_ordered_desc(engine):
    for i in range(3):
        engine.ingest_siem_event("org1", {"source_id": "s1", "event_type": "x", "severity": "info", "raw_data": {"i": i}})
    events = engine.list_siem_events("org1")
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)


# ---------------------------------------------------------------------------
# 6. Correlation Alerts lifecycle
# ---------------------------------------------------------------------------


def test_create_correlation_alert_returns_record(engine):
    result = engine.create_correlation_alert("org1", {
        "title": "Brute Force",
        "rule_name": "auth_failure_threshold",
        "severity": "high",
        "matched_events": ["evt1", "evt2"],
    })
    assert "id" in result
    assert result["status"] == "open"
    assert result["title"] == "Brute Force"
    assert result["matched_events"] == ["evt1", "evt2"]


def test_create_correlation_alert_missing_title_raises(engine):
    with pytest.raises(ValueError, match="title"):
        engine.create_correlation_alert("org1", {
            "title": "", "rule_name": "rule1", "severity": "high",
        })


def test_create_correlation_alert_missing_rule_name_raises(engine):
    with pytest.raises(ValueError, match="rule_name"):
        engine.create_correlation_alert("org1", {
            "title": "T", "rule_name": "", "severity": "high",
        })


def test_list_correlation_alerts_empty(engine):
    assert engine.list_correlation_alerts("org1") == []


def test_list_correlation_alerts_filter_by_status(engine):
    engine.create_correlation_alert("org1", {"title": "A", "rule_name": "r1", "severity": "high"})
    engine.create_correlation_alert("org1", {"title": "B", "rule_name": "r2", "severity": "low"})
    open_alerts = engine.list_correlation_alerts("org1", status="open")
    assert len(open_alerts) == 2
    ack_alerts = engine.list_correlation_alerts("org1", status="acknowledged")
    assert len(ack_alerts) == 0


def test_list_correlation_alerts_filter_by_severity(engine):
    engine.create_correlation_alert("org1", {"title": "A", "rule_name": "r1", "severity": "critical"})
    engine.create_correlation_alert("org1", {"title": "B", "rule_name": "r2", "severity": "low"})
    crit = engine.list_correlation_alerts("org1", severity="critical")
    assert len(crit) == 1


def test_acknowledge_alert_changes_status(engine):
    alert = engine.create_correlation_alert("org1", {
        "title": "T", "rule_name": "R", "severity": "medium",
    })
    result = engine.acknowledge_alert("org1", alert["id"], "analyst1")
    assert result["status"] == "acknowledged"
    assert result["acknowledged_by"] == "analyst1"
    assert result["acknowledged_at"] is not None


def test_acknowledge_alert_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.acknowledge_alert("org1", "bad-id", "analyst1")


# ---------------------------------------------------------------------------
# 7. Stats
# ---------------------------------------------------------------------------


def test_stats_source_counts(engine):
    engine.register_siem_source("org1", {"name": "S1", "source_type": "syslog"})
    engine.register_siem_source("org1", {"name": "S2", "source_type": "cloudtrail"})
    stats = engine.get_siem_stats("org1")
    assert stats["total_sources"] == 2
    assert stats["active_sources"] == 2


def test_stats_events_24h(engine):
    engine.ingest_siem_event("org1", {"source_id": "s1", "event_type": "x", "severity": "high", "raw_data": {}})
    engine.ingest_siem_event("org1", {"source_id": "s1", "event_type": "x", "severity": "critical", "raw_data": {}})
    stats = engine.get_siem_stats("org1")
    assert stats["total_events_24h"] == 2


def test_stats_by_severity(engine):
    engine.ingest_siem_event("org1", {"source_id": "s1", "event_type": "x", "severity": "critical", "raw_data": {}})
    engine.ingest_siem_event("org1", {"source_id": "s1", "event_type": "x", "severity": "critical", "raw_data": {}})
    stats = engine.get_siem_stats("org1")
    assert stats["by_severity"].get("critical", 0) >= 2


def test_stats_open_alerts(engine):
    engine.create_correlation_alert("org1", {"title": "A", "rule_name": "r", "severity": "high"})
    engine.create_correlation_alert("org1", {"title": "B", "rule_name": "r", "severity": "critical"})
    stats = engine.get_siem_stats("org1")
    assert stats["open_alerts_count"] == 2
    assert stats["critical_alerts"] == 1


# ---------------------------------------------------------------------------
# 8. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_sources(engine):
    engine.register_siem_source("org1", {"name": "S1", "source_type": "syslog"})
    engine.register_siem_source("org2", {"name": "S2", "source_type": "syslog"})
    assert len(engine.list_siem_sources("org1")) == 1
    assert len(engine.list_siem_sources("org2")) == 1


def test_org_isolation_events(engine):
    engine.ingest_siem_event("org1", {"source_id": "s1", "event_type": "x", "severity": "info", "raw_data": {}})
    engine.ingest_siem_event("org2", {"source_id": "s2", "event_type": "x", "severity": "info", "raw_data": {}})
    assert len(engine.list_siem_events("org1")) == 1
    assert len(engine.list_siem_events("org2")) == 1


def test_org_isolation_alerts(engine):
    engine.create_correlation_alert("org1", {"title": "A", "rule_name": "r", "severity": "high"})
    assert len(engine.list_correlation_alerts("org2")) == 0


def test_org_isolation_stats(engine):
    engine.register_siem_source("org1", {"name": "S", "source_type": "syslog"})
    stats_org2 = engine.get_siem_stats("org2")
    assert stats_org2["total_sources"] == 0


# ---------------------------------------------------------------------------
# 9. Legacy API (register_siem, ingest_event, create_alert, resolve_alert)
# ---------------------------------------------------------------------------


def test_legacy_register_siem(engine):
    result = engine.register_siem("org1", {"siem_name": "Splunk Prod", "siem_type": "splunk"})
    assert "siem_id" in result
    assert result["siem_type"] == "splunk"


def test_legacy_register_siem_hashes_token(engine):
    result = engine.register_siem("org1", {"siem_name": "QR", "api_token": "secret"})
    expected = hashlib.sha256(b"secret").hexdigest()
    assert result["api_token_hash"] == expected


def test_legacy_ingest_event(engine):
    result = engine.ingest_event("org1", {
        "siem_id": "s1", "event_type": "auth", "severity": "high",
        "raw_event": {"action": "login"},
    })
    assert "event_id" in result
    assert result["event_type"] == "auth"


def test_legacy_create_and_resolve_alert(engine):
    alert = engine.create_alert("org1", {"title": "Test", "severity": "medium"})
    assert alert["status"] == "open"
    ok = engine.resolve_alert("org1", alert["alert_id"], "analyst1")
    assert ok is True
    resolved = engine.list_alerts("org1", status="resolved")
    assert len(resolved) == 1


# ---------------------------------------------------------------------------
# parse_syslog / parse_cef / ingest_raw (new methods)
# ---------------------------------------------------------------------------


def test_parse_syslog_rfc3164(engine):
    raw = "<134>Apr 17 10:00:00 myhost sshd: Failed password for root"
    result = engine.parse_syslog(raw)
    assert result["format"] == "syslog_rfc3164"
    assert result["hostname"] == "myhost"
    assert result["app_name"] == "sshd"
    assert "Failed password" in result["message"]
    assert result["facility"] == 16
    assert result["syslog_severity"] == "info"  # priority 134 → sev 6


def test_parse_syslog_rfc5424(engine):
    raw = "<165>1 2026-04-17T10:00:00Z myhost myapp 1234 ID47 - BOM test message"
    result = engine.parse_syslog(raw)
    assert result["format"] == "syslog_rfc5424"
    assert result["hostname"] == "myhost"
    assert result["app_name"] == "myapp"
    assert result["process_id"] == "1234"


def test_parse_syslog_unknown_fallback(engine):
    raw = "some plain log line with no pri"
    result = engine.parse_syslog(raw)
    assert result["format"] == "syslog"
    assert result["message"] == raw


def test_parse_cef_full(engine):
    raw = (
        "CEF:0|ArcSight|Logger|1.0|100|Login Failed|7|"
        "src=10.0.0.1 dst=192.168.1.1 suser=admin msg=Authentication failure"
    )
    result = engine.parse_cef(raw)
    assert result["format"] == "cef"
    assert result["device_vendor"] == "ArcSight"
    assert result["device_product"] == "Logger"
    assert result["signature_id"] == "100"
    assert result["severity"] == "high"      # numeric 7 → high
    assert result["source_ip"] == "10.0.0.1"
    assert result["destination_ip"] == "192.168.1.1"
    assert result["user"] == "admin"
    assert result["message"] == "Authentication failure"


def test_parse_cef_severity_mapping_critical(engine):
    raw = "CEF:0|V|P|1|s|N|9|src=1.1.1.1"
    result = engine.parse_cef(raw)
    assert result["severity"] == "critical"


def test_parse_cef_no_prefix(engine):
    """Non-CEF string returns fallback."""
    raw = "just a plain string"
    result = engine.parse_cef(raw)
    assert result["message"] == raw


def test_ingest_raw_cef_auto_detect(engine):
    raw = (
        "CEF:0|Vendor|Product|1.0|sig1|Auth Failed|7|"
        "src=10.1.2.3 dst=192.168.0.1 suser=admin msg=Login failure"
    )
    event = engine.ingest_raw("org1", raw, fmt="auto")
    assert event["event_id"]
    assert event["severity"] == "high"
    assert event["source_ip"] == "10.1.2.3"
    assert event["destination_ip"] == "192.168.0.1"
    assert event["user"] == "admin"


def test_ingest_raw_syslog_explicit(engine):
    raw = "<134>Apr 17 10:00:00 myhost sshd: Failed password for root from 192.168.1.1"
    event = engine.ingest_raw("org1", raw, fmt="syslog")
    assert event["event_id"]
    # syslog severity 6 → info
    assert event["severity"] == "info"


def test_ingest_raw_persists_to_db(engine):
    """ingest_raw creates an event retrievable via list_events."""
    raw = "CEF:0|V|P|1|s|N|5|src=1.2.3.4"
    engine.ingest_raw("org1", raw)
    events = engine.list_events("org1")
    assert len(events) >= 1


def test_ingest_raw_empty_string(engine):
    """Empty raw string should not crash."""
    event = engine.ingest_raw("org1", "")
    assert event["event_id"]


def test_ingest_raw_cef_format_explicit(engine):
    raw = "CEF:0|Vendor|Product|1.0|s|Name|3|src=5.6.7.8"
    event = engine.ingest_raw("org1", raw, fmt="cef")
    assert event["severity"] == "low"   # cef_severity_raw=3 → low
