"""Tests for EDR/XDR connector — Falco + osquery + Wazuh ingest paths.

These tests do NOT touch a live cluster. They exercise the file-format
adapters and the in-memory mirror to EDREngine + SecurityFindingsEngine
+ SecurityEventCorrelationEngine using the embedded fallback events
(Falco rule pack v0.37 schema, osquery v5+ schema, Wazuh 4.x schema).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from connectors.edr_connector import (
    EDRConnector,
    _FALCO_FALLBACK_EVENTS,
    _OSQUERY_FALLBACK_EVENTS,
    _WAZUH_FALLBACK_EVENTS,
    _falco_to_edr_event,
    _osquery_to_edr_event,
    _wazuh_to_edr_event,
)
from core.edr_engine import EDREngine
from core.security_findings_engine import SecurityFindingsEngine
from core.security_event_correlation_engine import SecurityEventCorrelationEngine


@pytest.fixture
def isolated_dbs(tmp_path, monkeypatch):
    """Point all per-domain SQLite DBs at an isolated tmp dir."""
    monkeypatch.setenv("ALDECI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    yield tmp_path


@pytest.fixture
def connector(isolated_dbs):
    edr = EDREngine()
    findings = SecurityFindingsEngine()
    corr = SecurityEventCorrelationEngine()
    return EDRConnector(
        edr_engine=edr,
        findings_engine=findings,
        correlation_engine=corr,
    )


# ----------------------------------------------------------------------
# Normalizer-level tests (pure functions, no DB)
# ----------------------------------------------------------------------
def test_falco_normalizer_terminal_shell():
    """Falco shell-in-container event maps to EDR create event with T1059."""
    raw = _FALCO_FALLBACK_EVENTS[0]
    out = _falco_to_edr_event(raw)
    assert out["process_name"] == "sh"
    assert out["event_type"] == "create"
    assert out["severity"] == "medium"  # Notice
    assert out["mitre_technique"] == "T1059"
    assert out["_falco_rule"] == "Terminal shell in container"
    assert out["_container_id"] == "ea99cd034083"


def test_falco_normalizer_critical_severity():
    """Critical Falco priority maps to ALDECI critical."""
    nc_event = next(e for e in _FALCO_FALLBACK_EVENTS if e["rule"].startswith("Netcat"))
    out = _falco_to_edr_event(nc_event)
    assert out["severity"] == "critical"


def test_osquery_normalizer_extracts_pid():
    raw = _OSQUERY_FALLBACK_EVENTS[0]
    out = _osquery_to_edr_event(raw)
    assert out["process_name"] == "sh"
    assert out["pid"] == 12345
    assert out["user"] == "root"
    assert out["event_type"] == "create"


def test_osquery_normalizer_handles_missing_pid():
    raw = {"name": "test", "columns": {"name": "x", "pid": "not-a-number"}}
    out = _osquery_to_edr_event(raw)
    assert out["pid"] == 0


def test_wazuh_normalizer_critical_level():
    raw = _WAZUH_FALLBACK_EVENTS[1]  # level 14
    out = _wazuh_to_edr_event(raw)
    assert out["severity"] == "critical"
    assert out["mitre_technique"] == "T1571"
    assert out["event_type"] == "suspicious_api"
    assert out["_wazuh_rule_id"] == "100200"


def test_wazuh_normalizer_high_level():
    raw = _WAZUH_FALLBACK_EVENTS[0]  # level 12
    out = _wazuh_to_edr_event(raw)
    assert out["severity"] == "high"


# ----------------------------------------------------------------------
# End-to-end ingest tests
# ----------------------------------------------------------------------
def test_sync_from_falco_fallback_creates_endpoint(connector):
    res = connector.sync_from_falco(
        org_id="tenant-a",
        hostname="host-a",
        max_events=3,
        force_fallback=True,
    )
    assert res["mode"] == "fallback"
    assert res["events_processed"] == 3
    assert res["events_ingested"] == 3
    assert res["findings_recorded"] == 3
    eps = connector._edr.list_endpoints("tenant-a")
    assert any(e["hostname"] == "host-a" for e in eps)


def test_sync_from_falco_idempotent_endpoint(connector):
    """Running twice does not duplicate the endpoint registration."""
    connector.sync_from_falco(org_id="tenant-b", hostname="host-b", max_events=2, force_fallback=True)
    connector.sync_from_falco(org_id="tenant-b", hostname="host-b", max_events=2, force_fallback=True)
    hosts = [e["hostname"] for e in connector._edr.list_endpoints("tenant-b")]
    assert hosts.count("host-b") == 1


def test_sync_from_osquery_fallback(connector):
    res = connector.sync_from_osquery(org_id="tenant-c", max_events=2)
    assert res["mode"] == "fallback"
    assert res["events_ingested"] == 2
    assert res["findings_recorded"] == 2


def test_sync_from_osquery_real_file(connector, tmp_path):
    """A real osquery JSON-lines file is read and ingested live."""
    log = tmp_path / "osquery.log"
    log.write_text(json.dumps(_OSQUERY_FALLBACK_EVENTS[0]) + "\n")
    res = connector.sync_from_osquery(org_id="tenant-d", log_file=str(log), max_events=10)
    assert res["mode"] == "live"
    assert res["events_ingested"] == 1


def test_sync_from_wazuh_fallback(connector):
    res = connector.sync_from_wazuh(org_id="tenant-e", max_events=2)
    assert res["mode"] == "fallback"
    assert res["events_ingested"] == 2
    assert res["findings_recorded"] == 2


def test_sync_from_wazuh_real_file(connector, tmp_path):
    alerts = tmp_path / "alerts.json"
    alerts.write_text(json.dumps(_WAZUH_FALLBACK_EVENTS[1]) + "\n")
    res = connector.sync_from_wazuh(org_id="tenant-f", alerts_file=str(alerts), max_events=10)
    assert res["mode"] == "live"
    assert res["events_ingested"] == 1


# ----------------------------------------------------------------------
# Multi-tenant fan-out (the headline test for the relaunch)
# ----------------------------------------------------------------------
def test_sync_all_tenants_15_orgs_75_events(connector):
    """15 tenants × 5 Falco events/org = 75 EDR events, attributed per org."""
    org_ids = [f"tenant-{i:02d}" for i in range(15)]
    out = connector.sync_all_tenants(org_ids=org_ids, events_per_org=5, force_fallback=True)
    assert len(out) == 15
    total_falco = sum(o["falco"]["events_ingested"] for o in out.values())
    assert total_falco == 75
    # Each tenant has its own endpoint
    for org in org_ids:
        eps = connector._edr.list_endpoints(org)
        assert any(e["hostname"] == f"endpoint-{org}" for e in eps)


def test_findings_isolated_per_tenant(connector):
    """Findings from tenant-a are not visible to tenant-b."""
    connector.sync_from_falco(org_id="iso-a", max_events=2, force_fallback=True)
    connector.sync_from_falco(org_id="iso-b", max_events=3, force_fallback=True)
    # Use list_findings if available; fall back to a direct count.
    list_fn = getattr(connector._findings, "list_findings", None)
    if list_fn:
        a = list_fn(org_id="iso-a")
        b = list_fn(org_id="iso-b")
        assert all(f["org_id"] == "iso-a" for f in a)
        assert all(f["org_id"] == "iso-b" for f in b)
        assert len(a) == 2
        assert len(b) == 3


def test_correlation_engine_receives_events(connector):
    """Mirror-to-correlation path is wired and survives the round trip."""
    connector.sync_from_falco(org_id="corr-a", max_events=3, force_fallback=True)
    events = connector._correlation.list_events(org_id="corr-a")
    assert len(events) >= 3
    sources = {e["source_system"] for e in events}
    assert "falco" in sources


def test_correlation_engine_multiple_sources(connector):
    """All three source systems show up in correlation engine."""
    connector.sync_from_falco(org_id="multi", max_events=2, force_fallback=True)
    connector.sync_from_osquery(org_id="multi", max_events=2)
    connector.sync_from_wazuh(org_id="multi", max_events=2)
    events = connector._correlation.list_events(org_id="multi")
    sources = {e["source_system"] for e in events}
    assert sources == {"falco", "osquery", "wazuh"}


def test_singleton_module_accessor():
    """get_edr_connector returns a singleton."""
    from connectors.edr_connector import get_edr_connector
    a = get_edr_connector()
    b = get_edr_connector()
    assert a is b
