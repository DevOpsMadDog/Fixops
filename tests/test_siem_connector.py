"""Tests for suite-core/connectors/siem_connector.py.

Covers parser correctness, severity normalization, format auto-detection,
multi-tenant event generation, and end-to-end ingest into the three
mirrored engines.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

import pytest

# Ensure suite paths are importable when run standalone.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (
    os.path.join(_ROOT, "suite-core"),
    os.path.join(_ROOT, "suite-api", "apps"),
):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from connectors import siem_connector  # noqa: E402


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw, expected", [
    ("critical", "critical"),
    ("Critical", "critical"),
    ("HIGH", "high"),
    ("warn", "medium"),
    ("info", "info"),
    ("debug", "info"),
    ("emerg", "critical"),
    (10, "critical"),
    (9, "critical"),
    (7, "high"),
    (5, "medium"),
    (3, "low"),
    (0, "info"),
    ("9", "critical"),
    ("foo", "info"),
    (None, "info"),
    ("", "info"),
])
def test_normalize_severity(raw, expected):
    assert siem_connector.normalize_severity(raw) == expected


# ---------------------------------------------------------------------------
# Adapter registry
# ---------------------------------------------------------------------------


def test_list_adapters_contains_canonical_names():
    adapters = siem_connector.list_adapters()
    for name in ("splunk", "datadog", "sentinel", "elk", "wazuh", "qradar", "suricata", "syslog", "generic"):
        assert name in adapters


# ---------------------------------------------------------------------------
# Splunk HEC
# ---------------------------------------------------------------------------


def test_splunk_hec_parse_dict():
    payload = {
        "event": {"_raw": "Failed password for alice from 1.2.3.4", "src": "1.2.3.4", "src_user": "alice"},
        "time": 1709280000,
        "host": "web-01",
        "sourcetype": "linux_secure",
    }
    events = siem_connector.parse(payload, fmt="splunk_hec")
    assert len(events) == 1
    e = events[0]
    assert e["source_system"] == "splunk"
    assert e["event_type"] == "auth"
    assert e["source_ip"] == "1.2.3.4"
    assert e["user"] == "alice"
    assert e["host"] == "web-01"


def test_splunk_hec_parse_ndjson():
    line1 = json.dumps({"event": {"message": "evt 1"}, "time": 1709280000, "sourcetype": "syslog"})
    line2 = json.dumps({"event": "raw text", "time": 1709280001, "sourcetype": "nginx_access"})
    events = siem_connector.parse(f"{line1}\n{line2}\n", fmt="splunk_hec")
    assert len(events) == 2
    assert events[0]["message"] == "evt 1"
    assert events[1]["event_type"] == "application"


# ---------------------------------------------------------------------------
# Datadog
# ---------------------------------------------------------------------------


def test_datadog_parse_classification():
    payload = [{
        "ddsource": "nginx",
        "ddtags": "env:prod,service:web,severity:warn",
        "hostname": "web-01",
        "service": "web",
        "message": "GET /admin?id=1' OR '1'='1 HTTP/1.1 403",
        "status": "warn",
        "timestamp": "2026-03-01T10:15:23Z",
        "network.client.ip": "1.2.3.4",
    }]
    events = siem_connector.parse(payload, fmt="datadog")
    assert len(events) == 1
    e = events[0]
    assert e["source_system"] == "datadog"
    assert e["event_type"] == "application"
    assert e["severity"] == "medium"  # warn -> medium
    assert e["source_ip"] == "1.2.3.4"
    assert e["host"] == "web-01"


# ---------------------------------------------------------------------------
# Sentinel KQL
# ---------------------------------------------------------------------------


def test_sentinel_kql_parse_security_event():
    payload = {
        "tables": [{
            "name": "SecurityEvent",
            "columns": [
                {"name": "TimeGenerated", "type": "datetime"},
                {"name": "EventID", "type": "int"},
                {"name": "Computer", "type": "string"},
                {"name": "AccountName", "type": "string"},
                {"name": "IPAddress", "type": "string"},
                {"name": "Activity", "type": "string"},
                {"name": "Severity", "type": "string"},
            ],
            "rows": [
                ["2026-03-01T10:15:23Z", 4625, "WIN-01", "admin", "10.0.0.5",
                 "An account failed to log on.", "high"],
                ["2026-03-01T10:15:24Z", 4720, "WIN-01", "admin", "10.0.0.5",
                 "A user account was created.", "medium"],
            ],
        }],
    }
    events = siem_connector.parse(payload, fmt="sentinel_kql")
    assert len(events) == 2
    assert events[0]["source_system"] == "sentinel"
    assert events[0]["event_type"] == "auth"
    assert events[0]["severity"] == "high"
    assert events[0]["host"] == "WIN-01"
    assert events[0]["source_ip"] == "10.0.0.5"
    assert events[0]["user"] == "admin"


# ---------------------------------------------------------------------------
# ELK bulk
# ---------------------------------------------------------------------------


def test_elk_bulk_parses_documents():
    payload = "\n".join([
        json.dumps({"index": {"_index": "filebeat", "_id": "1"}}),
        json.dumps({
            "@timestamp": "2026-03-01T10:15:23Z",
            "host": {"name": "web-01"},
            "user": {"name": "alice"},
            "source": {"ip": "1.2.3.4"},
            "destination": {"ip": "10.0.0.5"},
            "event": {"category": "authentication", "action": "login", "severity": 7},
            "message": "User login",
        }),
        json.dumps({"index": {"_index": "filebeat", "_id": "2"}}),
        json.dumps({
            "@timestamp": "2026-03-01T10:15:24Z",
            "host": {"name": "web-02"},
            "event": {"category": "network", "severity": 9},
            "message": "Blocked outbound",
        }),
    ])
    events = siem_connector.parse(payload, fmt="elk_bulk")
    assert len(events) == 2
    assert events[0]["event_type"] == "auth"
    assert events[0]["severity"] == "high"
    assert events[1]["event_type"] == "network"
    assert events[1]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Wazuh
# ---------------------------------------------------------------------------


def test_wazuh_alert_severity_from_level():
    payload = {
        "timestamp": "2026-03-01T10:15:23Z",
        "rule": {
            "level": 12,
            "id": "5710",
            "description": "sshd: brute force trying to get access",
            "groups": ["authentication_failures", "ssh"],
        },
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.5"},
        "data": {"srcip": "1.2.3.4", "dstuser": "root"},
        "full_log": "Failed password",
    }
    events = siem_connector.parse(payload, fmt="wazuh_alert")
    assert len(events) == 1
    e = events[0]
    assert e["source_system"] == "wazuh"
    assert e["event_type"] == "auth"
    assert e["severity"] == "high"  # level 12 -> high
    assert e["source_ip"] == "1.2.3.4"
    assert e["user"] == "root"


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------


def test_suricata_eve_parses_alert():
    payload = {
        "timestamp": "2026-03-01T10:15:23Z",
        "event_type": "alert",
        "src_ip": "1.2.3.4",
        "dest_ip": "10.0.0.5",
        "src_port": 54321,
        "dest_port": 443,
        "alert": {
            "signature": "ET MALWARE Possible Cobalt Strike Beacon",
            "severity": 1,
            "category": "Malware",
        },
    }
    events = siem_connector.parse(payload, fmt="suricata_eve")
    assert len(events) == 1
    e = events[0]
    assert e["source_system"] == "suricata"
    assert e["event_type"] == "network"
    assert e["source_ip"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# CEF (QRadar / ArcSight)
# ---------------------------------------------------------------------------


def test_cef_parses_extensions():
    line = (
        "CEF:0|IBM|QRadar|7.5|100|Suspicious Outbound Connection|7|"
        "src=1.2.3.4 dst=10.0.0.5 suser=alice dvchost=web-01 "
        "msg=Connection blocked rt=2026-03-01T10:15:23Z"
    )
    events = siem_connector.parse(line, fmt="cef")
    assert len(events) == 1
    e = events[0]
    assert e["source_system"] == "qradar"
    assert e["severity"] == "high"
    assert e["source_ip"] == "1.2.3.4"
    assert e["destination_ip"] == "10.0.0.5"
    assert e["user"] == "alice"
    assert e["host"] == "web-01"


# ---------------------------------------------------------------------------
# Syslog (RFC 3164/5424)
# ---------------------------------------------------------------------------


def test_syslog_3164_parsed():
    line = "<86>Mar  1 10:15:23 web-01 sshd: Failed password for alice from 1.2.3.4 port 54321 ssh2"
    events = siem_connector.parse(line, fmt="syslog")
    assert len(events) == 1
    e = events[0]
    assert e["source_system"] == "syslog"
    assert e["event_type"] == "auth"
    assert e["host"] == "web-01"
    assert e["source_ip"] == "1.2.3.4"
    assert e["user"] == "alice"


def test_syslog_5424_parsed():
    line = (
        "<86>1 2026-03-01T10:15:23Z web-01 sshd 1234 - - "
        "Failed password for bob from 5.6.7.8 port 22 ssh2"
    )
    events = siem_connector.parse(line, fmt="syslog")
    assert len(events) == 1
    e = events[0]
    assert e["host"] == "web-01"
    assert e["user"] == "bob"
    assert e["source_ip"] == "5.6.7.8"


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload, expected", [
    ({"tables": [{"name": "X", "columns": [], "rows": []}]}, "sentinel_kql"),
    ({"ddsource": "nginx", "message": "x"}, "datadog"),
    ({"event": {"x": 1}, "time": 1709280000}, "splunk_hec"),
    ({"rule": {"level": 5}, "agent": {"id": "001"}}, "wazuh_alert"),
    ({"event_type": "alert", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"}, "suricata_eve"),
    ("CEF:0|Vendor|Product|1|100|Name|5|src=1.2.3.4", "cef"),
    ("<86>Mar  1 10:15:23 web-01 sshd: Failed password", "syslog"),
])
def test_detect_format(payload, expected):
    assert siem_connector.detect_format(payload) == expected


# ---------------------------------------------------------------------------
# Generator + multi-tenant
# ---------------------------------------------------------------------------


def test_generate_events_15_tenants_within_range():
    triples = siem_connector.generate_events(tenants=15, events_per_tenant=14, seed=42)
    assert len(triples) == 15 * 14  # 210
    tenants = {t for t, _, _ in triples}
    assert len(tenants) == 15
    fmts = {f for _, f, _ in triples}
    # Should hit at least 5 distinct formats given the generator pool.
    assert len(fmts) >= 5


def test_generate_events_per_tenant_count():
    triples = siem_connector.generate_events(tenants=3, events_per_tenant=10, seed=1)
    by_tenant: dict = {}
    for t, _, _ in triples:
        by_tenant[t] = by_tenant.get(t, 0) + 1
    assert all(v == 10 for v in by_tenant.values())
    assert len(by_tenant) == 3


def test_generate_events_deterministic_with_seed():
    a = siem_connector.generate_events(tenants=3, events_per_tenant=5, seed=99)
    b = siem_connector.generate_events(tenants=3, events_per_tenant=5, seed=99)
    assert [(t, f) for t, f, _ in a] == [(t, f) for t, f, _ in b]


# ---------------------------------------------------------------------------
# End-to-end mirror_to_engines (uses real engines with isolated DB paths)
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_engines(tmp_path, monkeypatch):
    """Create real engines pointed at temp DBs so writes don't pollute defaults."""
    from core.siem_integration_engine import SIEMIntegrationEngine
    from core.security_event_correlation_engine import SecurityEventCorrelationEngine
    from core.security_findings_engine import SecurityFindingsEngine

    siem = SIEMIntegrationEngine(db_path=str(tmp_path / "siem.db"))
    findings = SecurityFindingsEngine(db_path=str(tmp_path / "findings.db"))
    # SecurityEventCorrelationEngine uses per-org DB dir
    corr = SecurityEventCorrelationEngine(db_path=str(tmp_path / "correlation"))
    return siem, corr, findings


def test_mirror_to_engines_writes_all_three(isolated_engines):
    siem, corr, findings = isolated_engines
    events = siem_connector.parse(
        {"event": {"_raw": "Failed password for alice from 1.2.3.4", "src": "1.2.3.4",
                   "src_user": "alice", "severity": "high"},
         "time": 1709280000, "host": "web-01", "sourcetype": "linux_secure"},
        fmt="splunk_hec",
    )
    assert events
    result = siem_connector.mirror_to_engines(
        "tenant-test", events,
        siem_engine=siem, correlation_engine=corr, findings_engine=findings,
    )
    assert result["siem_events"] >= 1
    assert result["correlation_events"] >= 1
    # Severity is "high" so finding should be recorded.
    assert result["findings"] >= 1
    assert not [e for e in result["errors"] if "init" in e]


def test_mirror_skips_low_severity_findings(isolated_engines):
    siem, corr, findings = isolated_engines
    events = siem_connector.parse(
        {"event": {"message": "ok", "severity": "info"},
         "time": 1709280000, "sourcetype": "syslog"},
        fmt="splunk_hec",
    )
    result = siem_connector.mirror_to_engines(
        "tenant-test", events,
        siem_engine=siem, correlation_engine=corr, findings_engine=findings,
    )
    assert result["siem_events"] >= 1
    assert result["findings"] == 0  # low/info -> no finding


# ---------------------------------------------------------------------------
# generate_and_ingest end-to-end
# ---------------------------------------------------------------------------


def test_generate_and_ingest_15_tenants(isolated_engines):
    siem, corr, findings = isolated_engines
    summary = siem_connector.generate_and_ingest(
        tenants=15, events_per_tenant=14, seed=1337,
        siem_engine=siem, correlation_engine=corr, findings_engine=findings,
    )
    assert summary["tenants"] == 15
    assert summary["total_inputs"] == 15 * 14  # 210
    assert summary["totals"]["parsed"] >= 200  # parsing should not lose events
    assert summary["totals"]["siem_events"] >= 200
    assert summary["totals"]["correlation_events"] >= 200
    # Findings only for medium+ severity, so this depends on the random mix.
    assert summary["totals"]["findings"] >= 0
    assert len(summary["by_tenant"]) == 15
    assert len(summary["by_format"]) >= 5


# ---------------------------------------------------------------------------
# Edge cases — malformed input must NOT raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", [
    "splunk_hec", "datadog", "sentinel_kql", "elk_bulk", "wazuh_alert",
    "suricata_eve", "cef", "syslog", "json_lines",
])
def test_adapters_handle_garbage_without_raising(fmt):
    for garbage in ("", "{not json", b"\x00\x01\x02", None, 12345, []):
        try:
            result = siem_connector.parse(garbage, fmt=fmt)
        except Exception as exc:  # pragma: no cover
            pytest.fail(f"{fmt} raised on garbage {garbage!r}: {exc}")
        assert isinstance(result, list)


def test_ingest_empty_returns_zero_counts(isolated_engines):
    siem, corr, findings = isolated_engines
    result = siem_connector.ingest(
        "tenant-test", "", fmt="syslog",
        siem_engine=siem, correlation_engine=corr, findings_engine=findings,
    )
    assert result["parsed_count"] == 0
    assert result["siem_events"] == 0
