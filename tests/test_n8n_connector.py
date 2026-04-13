"""Tests for N8nConnector — bidirectional n8n webhook bridge.

All tests use a temp SQLite DB, no real n8n instance required.
Unreachable URLs result in 'failed' status (not exceptions).
"""
import sys
import os
import tempfile
import pytest

sys.path.insert(0, "suite-core")

from connectors.n8n_connector import N8nConnector


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def connector(tmp_path):
    """Fresh N8nConnector with isolated SQLite DB per test."""
    db = tmp_path / "n8n_test.db"
    return N8nConnector(base_url="http://localhost:15678", db_path=str(db))


# ---------------------------------------------------------------------------
# register_webhook
# ---------------------------------------------------------------------------

def test_register_webhook_creates_record(connector):
    result = connector.register_webhook("My Hook", "finding", "http://n8n.local/webhook/abc")
    assert "webhook_id" in result
    assert result["name"] == "My Hook"
    assert result["event_type"] == "finding"
    assert result["webhook_url"] == "http://n8n.local/webhook/abc"
    assert "created_at" in result


def test_register_webhook_id_is_uuid(connector):
    result = connector.register_webhook("Hook", "alert", "http://n8n.local/webhook/x")
    import uuid
    parsed = uuid.UUID(result["webhook_id"])  # raises if not UUID
    assert str(parsed) == result["webhook_id"]


def test_register_webhook_invalid_event_type_raises(connector):
    with pytest.raises(ValueError, match="Invalid event_type"):
        connector.register_webhook("Bad", "unknown_event", "http://n8n.local/webhook/x")


def test_register_multiple_event_types(connector):
    connector.register_webhook("Hook A", "finding", "http://n8n.local/a")
    connector.register_webhook("Hook B", "incident", "http://n8n.local/b")
    connector.register_webhook("Hook C", "sla_breach", "http://n8n.local/c")
    all_hooks = connector.list_webhooks()
    assert len(all_hooks) == 3
    types = {h["event_type"] for h in all_hooks}
    assert types == {"finding", "incident", "sla_breach"}


# ---------------------------------------------------------------------------
# unregister_webhook
# ---------------------------------------------------------------------------

def test_unregister_webhook_removes_record(connector):
    reg = connector.register_webhook("Hook", "finding", "http://n8n.local/webhook/x")
    removed = connector.unregister_webhook(reg["webhook_id"])
    assert removed is True
    assert connector.list_webhooks() == []


def test_unregister_nonexistent_returns_false(connector):
    result = connector.unregister_webhook("00000000-0000-0000-0000-000000000000")
    assert result is False


# ---------------------------------------------------------------------------
# list_webhooks
# ---------------------------------------------------------------------------

def test_list_webhooks_returns_list(connector):
    result = connector.list_webhooks()
    assert isinstance(result, list)


def test_list_webhooks_empty_when_none_registered(connector):
    assert connector.list_webhooks() == []


def test_list_webhooks_event_type_filter(connector):
    connector.register_webhook("F1", "finding", "http://n8n.local/f1")
    connector.register_webhook("A1", "alert", "http://n8n.local/a1")
    connector.register_webhook("F2", "finding", "http://n8n.local/f2")

    findings = connector.list_webhooks(event_type="finding")
    assert len(findings) == 2
    assert all(h["event_type"] == "finding" for h in findings)

    alerts = connector.list_webhooks(event_type="alert")
    assert len(alerts) == 1


def test_webhook_url_stored_and_retrieved(connector):
    url = "http://n8n.example.com/webhook/my-unique-path"
    reg = connector.register_webhook("URL Test", "scan_complete", url)
    hooks = connector.list_webhooks()
    match = next(h for h in hooks if h["webhook_id"] == reg["webhook_id"])
    assert match["webhook_url"] == url


# ---------------------------------------------------------------------------
# trigger_webhook
# ---------------------------------------------------------------------------

def test_trigger_webhook_no_registered_webhooks_returns_empty(connector):
    results = connector.trigger_webhook("finding", {"severity": "high"})
    assert results == []


def test_trigger_webhook_with_registered_webhook_returns_result_list(connector):
    connector.register_webhook("Hook", "finding", "http://127.0.0.1:19999/webhook/test")
    results = connector.trigger_webhook("finding", {"severity": "critical"})
    assert isinstance(results, list)
    assert len(results) == 1


def test_trigger_webhook_result_has_status_key(connector):
    connector.register_webhook("Hook", "alert", "http://127.0.0.1:19999/webhook/test")
    results = connector.trigger_webhook("alert", {})
    assert "status" in results[0]


def test_trigger_webhook_unreachable_url_returns_failed(connector):
    connector.register_webhook("Hook", "incident", "http://127.0.0.1:19999/webhook/test")
    results = connector.trigger_webhook("incident", {"test": True})
    assert results[0]["status"] == "failed"


def test_trigger_webhook_result_has_webhook_id(connector):
    reg = connector.register_webhook("Hook", "sla_breach", "http://127.0.0.1:19999/wh")
    results = connector.trigger_webhook("sla_breach", {})
    assert results[0]["webhook_id"] == reg["webhook_id"]


def test_trigger_webhook_records_event_in_history(connector):
    connector.register_webhook("Hook", "finding", "http://127.0.0.1:19999/wh")
    connector.trigger_webhook("finding", {"foo": "bar"})
    history = connector.get_event_history()
    assert len(history) == 1


# ---------------------------------------------------------------------------
# get_event_history
# ---------------------------------------------------------------------------

def test_get_event_history_returns_list(connector):
    result = connector.get_event_history()
    assert isinstance(result, list)


def test_get_event_history_limit_respected(connector):
    connector.register_webhook("Hook", "finding", "http://127.0.0.1:19999/wh")
    for _ in range(10):
        connector.trigger_webhook("finding", {})
    history = connector.get_event_history(limit=3)
    assert len(history) == 3


def test_get_event_history_event_type_filter(connector):
    connector.register_webhook("FH", "finding", "http://127.0.0.1:19999/wh")
    connector.register_webhook("AH", "alert", "http://127.0.0.1:19999/wh")
    connector.trigger_webhook("finding", {})
    connector.trigger_webhook("alert", {})
    finding_history = connector.get_event_history(event_type="finding")
    assert all(e["event_type"] == "finding" for e in finding_history)


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

def test_get_stats_returns_dict(connector):
    result = connector.get_stats()
    assert isinstance(result, dict)


def test_get_stats_has_required_keys(connector):
    stats = connector.get_stats()
    assert "total_webhooks" in stats
    assert "total_events" in stats
    assert "success_rate" in stats
    assert "events_by_type" in stats


def test_get_stats_numeric_values(connector):
    stats = connector.get_stats()
    assert isinstance(stats["total_webhooks"], int)
    assert isinstance(stats["total_events"], int)
    assert isinstance(stats["success_rate"], float)


def test_success_rate_is_float_between_0_and_1(connector):
    stats = connector.get_stats()
    assert 0.0 <= stats["success_rate"] <= 1.0


def test_events_by_type_is_dict(connector):
    stats = connector.get_stats()
    assert isinstance(stats["events_by_type"], dict)


def test_stats_reflect_registered_webhooks(connector):
    connector.register_webhook("H1", "finding", "http://n8n.local/h1")
    connector.register_webhook("H2", "alert", "http://n8n.local/h2")
    stats = connector.get_stats()
    assert stats["total_webhooks"] == 2


# ---------------------------------------------------------------------------
# test_connectivity
# ---------------------------------------------------------------------------

def test_connectivity_returns_reachable_key(connector):
    result = connector.test_connectivity()
    assert "reachable" in result


def test_connectivity_returns_latency_ms(connector):
    result = connector.test_connectivity()
    assert "latency_ms" in result
    assert isinstance(result["latency_ms"], float)


def test_connectivity_unreachable_returns_false(connector):
    result = connector.test_connectivity()
    assert result["reachable"] is False
