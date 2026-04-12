"""Tests for suite-core/core/event_emitter.py — EventEmitter, SecurityEvent, EventType.

Coverage:
- EventType enum values
- SecurityEvent model validation
- Webhook registration / unregistration
- list_webhooks
- emit() fan-out with HMAC signature verification
- Event type filtering (only matching webhooks receive events)
- Retry logic (3 attempts on failure)
- n8n template files are valid JSON

Usage:
    pytest tests/test_event_emitter.py -v --timeout=10
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on path
_suite_core = str(Path(__file__).parent.parent / "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

from core.event_emitter import (
    EventEmitter,
    EventType,
    SecurityEvent,
    Severity,
    _sign_payload,
)
from core.exceptions import ConnectorError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_emitter(tmp_path):
    """EventEmitter backed by a temporary SQLite database."""
    db_path = str(tmp_path / "test_events.db")
    return EventEmitter(db_path=db_path)


@pytest.fixture
def basic_event():
    """A minimal SecurityEvent for reuse."""
    return SecurityEvent(
        event_type=EventType.FINDING_CREATED,
        source="test-scanner",
        severity=Severity.HIGH,
        payload={"finding_id": "F-001", "title": "SQL Injection"},
    )


def _make_mock_response(status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    return resp


# ---------------------------------------------------------------------------
# EventType enum
# ---------------------------------------------------------------------------


class TestEventType:
    def test_all_values_present(self):
        values = {e.value for e in EventType}
        assert "finding.created" in values
        assert "finding.updated" in values
        assert "risk.changed" in values
        assert "compliance.gap" in values
        assert "pipeline.completed" in values
        assert "policy.violation" in values
        assert "sla.breach" in values

    def test_enum_count(self):
        assert len(EventType) == 7

    def test_from_string(self):
        et = EventType("finding.created")
        assert et == EventType.FINDING_CREATED


# ---------------------------------------------------------------------------
# SecurityEvent model
# ---------------------------------------------------------------------------


class TestSecurityEvent:
    def test_defaults(self):
        event = SecurityEvent(event_type=EventType.RISK_CHANGED, payload={})
        assert event.source == "aldeci"
        assert event.severity == Severity.INFO.value
        assert event.correlation_id is not None
        assert isinstance(event.timestamp, datetime)

    def test_custom_fields(self, basic_event):
        assert basic_event.event_type == EventType.FINDING_CREATED.value
        assert basic_event.source == "test-scanner"
        assert basic_event.severity == Severity.HIGH.value
        assert basic_event.payload["finding_id"] == "F-001"

    def test_correlation_id_is_unique(self):
        e1 = SecurityEvent(event_type=EventType.SLA_BREACH, payload={})
        e2 = SecurityEvent(event_type=EventType.SLA_BREACH, payload={})
        assert e1.correlation_id != e2.correlation_id

    def test_invalid_event_type_raises(self):
        with pytest.raises(Exception):
            SecurityEvent(event_type="not.a.real.type", payload={})

    def test_model_dump_json_roundtrip(self, basic_event):
        raw = basic_event.model_dump_json()
        data = json.loads(raw)
        assert data["event_type"] == "finding.created"
        assert data["source"] == "test-scanner"
        assert data["payload"]["finding_id"] == "F-001"

    def test_timestamp_is_utc_aware(self):
        event = SecurityEvent(event_type=EventType.POLICY_VIOLATION, payload={})
        assert event.timestamp.tzinfo is not None


# ---------------------------------------------------------------------------
# Webhook registration
# ---------------------------------------------------------------------------


class TestWebhookRegistration:
    def test_register_returns_uuid(self, tmp_emitter):
        wid = tmp_emitter.register_webhook(
            "https://n8n.example.com/webhook/abc",
            [EventType.FINDING_CREATED],
            secret="mysecret",
        )
        assert isinstance(wid, str)
        assert len(wid) == 36  # UUID4

    def test_register_multiple(self, tmp_emitter):
        w1 = tmp_emitter.register_webhook("https://a.example.com/wh", [EventType.FINDING_CREATED])
        w2 = tmp_emitter.register_webhook("https://b.example.com/wh", [EventType.SLA_BREACH])
        assert w1 != w2

    def test_register_empty_url_raises(self, tmp_emitter):
        with pytest.raises(ConnectorError):
            tmp_emitter.register_webhook("", [EventType.FINDING_CREATED])

    def test_register_empty_event_types_raises(self, tmp_emitter):
        with pytest.raises(ConnectorError):
            tmp_emitter.register_webhook("https://example.com/wh", [])

    def test_register_autogenerates_secret(self, tmp_emitter):
        # No secret provided — should not raise and should create a webhook
        wid = tmp_emitter.register_webhook(
            "https://example.com/wh",
            [EventType.COMPLIANCE_GAP],
        )
        webhooks = tmp_emitter.list_webhooks()
        wh = next((w for w in webhooks if w["id"] == wid), None)
        assert wh is not None
        assert wh["secret"]  # auto-generated


# ---------------------------------------------------------------------------
# Webhook unregistration
# ---------------------------------------------------------------------------


class TestWebhookUnregistration:
    def test_unregister_existing(self, tmp_emitter):
        wid = tmp_emitter.register_webhook("https://x.example.com/wh", [EventType.RISK_CHANGED])
        result = tmp_emitter.unregister_webhook(wid)
        assert result is True

    def test_unregister_removes_from_list(self, tmp_emitter):
        wid = tmp_emitter.register_webhook("https://x.example.com/wh", [EventType.RISK_CHANGED])
        tmp_emitter.unregister_webhook(wid)
        webhooks = tmp_emitter.list_webhooks()
        ids = [w["id"] for w in webhooks]
        assert wid not in ids

    def test_unregister_nonexistent_returns_false(self, tmp_emitter):
        result = tmp_emitter.unregister_webhook(str(uuid.uuid4()))
        assert result is False


# ---------------------------------------------------------------------------
# list_webhooks
# ---------------------------------------------------------------------------


class TestListWebhooks:
    def test_empty_initially(self, tmp_emitter):
        assert tmp_emitter.list_webhooks() == []

    def test_lists_registered_webhooks(self, tmp_emitter):
        tmp_emitter.register_webhook("https://a.example.com/wh", [EventType.FINDING_CREATED])
        tmp_emitter.register_webhook("https://b.example.com/wh", [EventType.SLA_BREACH])
        webhooks = tmp_emitter.list_webhooks()
        assert len(webhooks) == 2

    def test_webhook_fields(self, tmp_emitter):
        tmp_emitter.register_webhook(
            "https://c.example.com/wh",
            [EventType.COMPLIANCE_GAP],
            description="test desc",
        )
        webhooks = tmp_emitter.list_webhooks()
        wh = webhooks[0]
        assert "id" in wh
        assert "url" in wh
        assert "event_types" in wh
        assert "secret" in wh
        assert wh["active"] is True
        assert wh["description"] == "test desc"


# ---------------------------------------------------------------------------
# Event emission and HMAC signature
# ---------------------------------------------------------------------------


class TestEventEmission:
    def test_emit_calls_matching_webhook(self, tmp_emitter, basic_event):
        tmp_emitter.register_webhook(
            "https://n8n.example.com/wh", [EventType.FINDING_CREATED], secret="testsecret"
        )
        with patch("core.event_emitter.requests.post") as mock_post:
            mock_post.return_value = _make_mock_response(200)
            results = tmp_emitter.emit(basic_event)
        assert len(results) == 1
        assert results[0]["status"] == "success"

    def test_emit_hmac_signature_correct(self, tmp_emitter, basic_event):
        secret = "verysecret"
        tmp_emitter.register_webhook(
            "https://n8n.example.com/wh", [EventType.FINDING_CREATED], secret=secret
        )
        captured: Dict[str, Any] = {}

        def capture_post(url, data, headers, **kwargs):
            captured["body"] = data
            captured["headers"] = headers
            return _make_mock_response(200)

        with patch("core.event_emitter.requests.post", side_effect=capture_post):
            tmp_emitter.emit(basic_event)

        expected_sig = hmac.new(
            secret.encode("utf-8"), captured["body"], hashlib.sha256
        ).hexdigest()
        assert captured["headers"]["X-ALdeci-Signature"] == f"sha256={expected_sig}"

    def test_emit_correct_event_type_header(self, tmp_emitter, basic_event):
        tmp_emitter.register_webhook(
            "https://n8n.example.com/wh", [EventType.FINDING_CREATED], secret="s"
        )
        captured_headers: Dict[str, Any] = {}

        def capture(url, data, headers, **kwargs):
            captured_headers.update(headers)
            return _make_mock_response(200)

        with patch("core.event_emitter.requests.post", side_effect=capture):
            tmp_emitter.emit(basic_event)

        assert captured_headers["X-ALdeci-Event"] == "finding.created"
        assert captured_headers["User-Agent"] == "ALdeci-EventEmitter/1.0"

    def test_emit_no_matching_webhooks_returns_empty(self, tmp_emitter):
        tmp_emitter.register_webhook(
            "https://n8n.example.com/wh", [EventType.SLA_BREACH], secret="s"
        )
        event = SecurityEvent(event_type=EventType.COMPLIANCE_GAP, payload={})
        with patch("core.event_emitter.requests.post") as mock_post:
            results = tmp_emitter.emit(event)
        mock_post.assert_not_called()
        assert results == []


# ---------------------------------------------------------------------------
# Event type filtering
# ---------------------------------------------------------------------------


class TestEventTypeFiltering:
    def test_only_matching_webhook_receives_event(self, tmp_emitter):
        tmp_emitter.register_webhook(
            "https://wh1.example.com/wh", [EventType.FINDING_CREATED], secret="s1"
        )
        tmp_emitter.register_webhook(
            "https://wh2.example.com/wh", [EventType.SLA_BREACH], secret="s2"
        )
        event = SecurityEvent(event_type=EventType.FINDING_CREATED, payload={})
        calls = []

        def capture(url, **kwargs):
            calls.append(url)
            return _make_mock_response(200)

        with patch("core.event_emitter.requests.post", side_effect=capture):
            results = tmp_emitter.emit(event)

        assert len(results) == 1
        assert "wh1.example.com" in calls[0]
        assert len(calls) == 1

    def test_multiple_webhooks_same_event_type_all_receive(self, tmp_emitter):
        tmp_emitter.register_webhook("https://a.example.com/wh", [EventType.RISK_CHANGED])
        tmp_emitter.register_webhook("https://b.example.com/wh", [EventType.RISK_CHANGED])
        event = SecurityEvent(event_type=EventType.RISK_CHANGED, payload={})

        with patch("core.event_emitter.requests.post") as mock_post:
            mock_post.return_value = _make_mock_response(200)
            results = tmp_emitter.emit(event)

        assert len(results) == 2
        assert mock_post.call_count == 2

    def test_webhook_subscribed_to_multiple_types(self, tmp_emitter):
        tmp_emitter.register_webhook(
            "https://multi.example.com/wh",
            [EventType.FINDING_CREATED, EventType.FINDING_UPDATED],
        )
        for et in [EventType.FINDING_CREATED, EventType.FINDING_UPDATED]:
            event = SecurityEvent(event_type=et, payload={})
            with patch("core.event_emitter.requests.post") as mock_post:
                mock_post.return_value = _make_mock_response(200)
                results = tmp_emitter.emit(event)
            assert len(results) == 1


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------


class TestRetryLogic:
    def test_retries_three_times_on_failure(self, tmp_emitter, basic_event):
        tmp_emitter.register_webhook(
            "https://n8n.example.com/wh", [EventType.FINDING_CREATED], secret="s"
        )
        with patch("core.event_emitter.requests.post") as mock_post, \
             patch("core.event_emitter.time.sleep"):
            mock_post.return_value = _make_mock_response(500)
            results = tmp_emitter.emit(basic_event)

        assert results[0]["status"] == "failed"
        assert mock_post.call_count == 3
        assert results[0]["attempts"] == 3

    def test_succeeds_on_second_attempt(self, tmp_emitter, basic_event):
        tmp_emitter.register_webhook(
            "https://n8n.example.com/wh", [EventType.FINDING_CREATED], secret="s"
        )
        responses = [_make_mock_response(500), _make_mock_response(200)]
        with patch("core.event_emitter.requests.post", side_effect=responses), \
             patch("core.event_emitter.time.sleep"):
            results = tmp_emitter.emit(basic_event)

        assert results[0]["status"] == "success"
        assert results[0]["attempts"] == 2

    def test_timeout_error_is_retried(self, tmp_emitter, basic_event):
        import requests as _req
        tmp_emitter.register_webhook(
            "https://n8n.example.com/wh", [EventType.FINDING_CREATED], secret="s"
        )
        with patch("core.event_emitter.requests.post", side_effect=_req.Timeout), \
             patch("core.event_emitter.time.sleep"):
            results = tmp_emitter.emit(basic_event)

        assert results[0]["status"] == "failed"
        assert results[0]["error"] == "Timeout"

    def test_connection_error_is_retried(self, tmp_emitter, basic_event):
        import requests as _req
        tmp_emitter.register_webhook(
            "https://n8n.example.com/wh", [EventType.FINDING_CREATED], secret="s"
        )
        with patch("core.event_emitter.requests.post", side_effect=_req.ConnectionError), \
             patch("core.event_emitter.time.sleep"):
            results = tmp_emitter.emit(basic_event)

        assert results[0]["status"] == "failed"
        assert results[0]["error"] == "ConnectionError"


# ---------------------------------------------------------------------------
# n8n template files are valid JSON
# ---------------------------------------------------------------------------


_TEMPLATES_DIR = Path(__file__).parent.parent / "suite-integrations" / "n8n_templates"
_EXPECTED_TEMPLATES = [
    "critical_finding_slack_alert.json",
    "finding_to_jira.json",
    "compliance_gap_pagerduty.json",
]


class TestN8nTemplates:
    def test_templates_directory_exists(self):
        assert _TEMPLATES_DIR.exists(), f"Templates dir not found: {_TEMPLATES_DIR}"

    @pytest.mark.parametrize("filename", _EXPECTED_TEMPLATES)
    def test_template_is_valid_json(self, filename):
        path = _TEMPLATES_DIR / filename
        assert path.exists(), f"Template file not found: {path}"
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)  # raises if invalid
        assert isinstance(data, dict)

    @pytest.mark.parametrize("filename", _EXPECTED_TEMPLATES)
    def test_template_has_required_fields(self, filename):
        path = _TEMPLATES_DIR / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "name" in data, "Template missing 'name' field"
        assert "nodes" in data, "Template missing 'nodes' field"
        assert "connections" in data, "Template missing 'connections' field"
        assert isinstance(data["nodes"], list)
        assert len(data["nodes"]) > 0

    @pytest.mark.parametrize("filename", _EXPECTED_TEMPLATES)
    def test_template_has_webhook_trigger(self, filename):
        path = _TEMPLATES_DIR / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        node_types = [n.get("type", "") for n in data["nodes"]]
        assert any("webhook" in t.lower() for t in node_types), \
            f"No webhook trigger node found in {filename}"

    def test_slack_template_references_slack_node(self):
        path = _TEMPLATES_DIR / "critical_finding_slack_alert.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        node_types = [n.get("type", "") for n in data["nodes"]]
        assert any("slack" in t.lower() for t in node_types)

    def test_jira_template_references_jira_node(self):
        path = _TEMPLATES_DIR / "finding_to_jira.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        node_types = [n.get("type", "") for n in data["nodes"]]
        assert any("jira" in t.lower() for t in node_types)

    def test_compliance_template_has_meta(self):
        path = _TEMPLATES_DIR / "compliance_gap_pagerduty.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "meta" in data
        assert data["meta"].get("aldeci_event_type") == "compliance.gap"
