"""Tests for SlackNotifier — webhook-based Slack integration.

Covers:
- send_critical_alert sends correctly-shaped Block Kit payload
- send_incident_notification formats incident fields
- send_compliance_failure formats compliance fields
- send_test sends test blocks with correct fallback text
- Graceful no-op when webhook URL is not configured
- configure() validates URL prefix
- configure() updates webhook URL at runtime
- on_alert_created subscriber only fires for critical severity
- is_configured property reflects webhook URL presence
- Transport errors return False (no exception raised)
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# Ensure env is clean before importing the module
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

# Remove any real webhook URL from environment during tests
os.environ.pop("SLACK_WEBHOOK_URL", None)

from core.slack_notifier import (
    SlackNotifier,
    build_compliance_failure_blocks,
    build_critical_alert_blocks,
    build_incident_notification_blocks,
    build_test_blocks,
    on_alert_created,
    get_notifier,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WEBHOOK_URL = "https://hooks.slack.com/services/T000/B000/xxxx"


def _make_transport(success: bool = True):
    """Return a mock transport that records calls and returns `success`."""
    calls: List[Dict[str, Any]] = []

    def transport(url: str, payload: Dict[str, Any]) -> bool:
        calls.append({"url": url, "payload": payload})
        return success

    transport.calls = calls  # type: ignore[attr-defined]
    return transport


# ---------------------------------------------------------------------------
# Block builder tests
# ---------------------------------------------------------------------------


class TestBuildCriticalAlertBlocks:
    def test_header_contains_severity_and_title(self):
        blocks = build_critical_alert_blocks(
            {"title": "SQL Injection Detected", "severity": "critical"}
        )
        header = blocks[0]
        assert header["type"] == "header"
        assert "CRITICAL" in header["text"]["text"]
        assert "SQL Injection Detected" in header["text"]["text"]

    def test_fields_include_alert_id_and_source(self):
        blocks = build_critical_alert_blocks(
            {
                "title": "Brute Force",
                "severity": "high",
                "alert_id": "ALT-001",
                "source_engine": "auth_engine",
            }
        )
        section = next(b for b in blocks if b["type"] == "section" and "fields" in b)
        field_texts = [f["text"] for f in section["fields"]]
        assert any("ALT-001" in t for t in field_texts)
        assert any("auth_engine" in t for t in field_texts)

    def test_message_truncated_to_500_chars(self):
        long_msg = "x" * 600
        blocks = build_critical_alert_blocks(
            {"title": "T", "severity": "critical", "message": long_msg}
        )
        all_text = str(blocks)
        # Should not contain more than 500 x's in the message field
        assert "x" * 501 not in all_text

    def test_no_message_section_when_empty(self):
        blocks = build_critical_alert_blocks({"title": "T", "severity": "critical", "message": ""})
        text_sections = [b for b in blocks if b["type"] == "section" and "text" in b and "fields" not in b]
        assert len(text_sections) == 0


class TestBuildIncidentBlocks:
    def test_incident_id_and_status_present(self):
        blocks = build_incident_notification_blocks(
            {
                "title": "Ransomware Outbreak",
                "severity": "critical",
                "status": "investigating",
                "incident_id": "INC-999",
                "assignee": "alice",
            }
        )
        all_text = str(blocks)
        assert "INC-999" in all_text
        assert "Investigating" in all_text or "investigating" in all_text
        assert "alice" in all_text

    def test_description_included_when_provided(self):
        blocks = build_incident_notification_blocks(
            {"title": "T", "description": "Lateral movement detected on host."}
        )
        assert any(
            "Lateral movement" in str(b) for b in blocks
        )


class TestBuildComplianceFailureBlocks:
    def test_framework_and_control_in_output(self):
        blocks = build_compliance_failure_blocks(
            {
                "framework": "SOC2",
                "control": "CC6.1",
                "severity": "high",
                "failure_id": "CF-042",
            }
        )
        all_text = str(blocks)
        assert "SOC2" in all_text
        assert "CC6.1" in all_text
        assert "CF-042" in all_text

    def test_remediation_included_when_provided(self):
        blocks = build_compliance_failure_blocks(
            {
                "framework": "PCI-DSS",
                "control": "Req 8.3",
                "remediation": "Enable MFA on all admin accounts.",
            }
        )
        assert any("MFA" in str(b) for b in blocks)


class TestBuildTestBlocks:
    def test_default_message_in_blocks(self):
        blocks = build_test_blocks()
        assert any("ALDECI" in str(b) for b in blocks)

    def test_custom_message_in_blocks(self):
        blocks = build_test_blocks("Custom ping message")
        assert any("Custom ping message" in str(b) for b in blocks)


# ---------------------------------------------------------------------------
# SlackNotifier unit tests
# ---------------------------------------------------------------------------


class TestSlackNotifierIsConfigured:
    def test_not_configured_when_no_url(self):
        notifier = SlackNotifier(webhook_url=None)
        assert notifier.is_configured is False

    def test_configured_when_url_provided(self):
        notifier = SlackNotifier(webhook_url=_WEBHOOK_URL)
        assert notifier.is_configured is True

    def test_configure_updates_url(self):
        notifier = SlackNotifier()
        assert not notifier.is_configured
        notifier.configure(_WEBHOOK_URL)
        assert notifier.is_configured

    def test_configure_rejects_invalid_url(self):
        notifier = SlackNotifier()
        with pytest.raises(ValueError, match="hooks.slack.com"):
            notifier.configure("https://example.com/webhook")


class TestSlackNotifierSendCriticalAlert:
    def test_sends_payload_to_webhook(self):
        transport = _make_transport(success=True)
        notifier = SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)
        result = notifier.send_critical_alert(
            {"title": "Critical CVE", "severity": "critical", "alert_id": "A1"}
        )
        assert result is True
        assert len(transport.calls) == 1
        call = transport.calls[0]
        assert call["url"] == _WEBHOOK_URL
        assert "blocks" in call["payload"]
        assert "text" in call["payload"]

    def test_returns_false_when_unconfigured(self):
        notifier = SlackNotifier(webhook_url=None)
        result = notifier.send_critical_alert({"title": "T", "severity": "critical"})
        assert result is False

    def test_returns_false_on_transport_error(self):
        transport = _make_transport(success=False)
        notifier = SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)
        result = notifier.send_critical_alert({"title": "T", "severity": "critical"})
        assert result is False


class TestSlackNotifierSendIncident:
    def test_sends_incident_notification(self):
        transport = _make_transport(success=True)
        notifier = SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)
        result = notifier.send_incident_notification(
            {"title": "Data Breach", "severity": "critical", "status": "open"}
        )
        assert result is True
        payload = transport.calls[0]["payload"]
        assert any(
            "Incident" in str(b) or "Data Breach" in str(b) for b in payload["blocks"]
        )

    def test_returns_false_when_unconfigured(self):
        notifier = SlackNotifier()
        assert notifier.send_incident_notification({"title": "X"}) is False


class TestSlackNotifierSendComplianceFailure:
    def test_sends_compliance_failure(self):
        transport = _make_transport(success=True)
        notifier = SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)
        result = notifier.send_compliance_failure(
            {"framework": "HIPAA", "control": "§164.312(a)", "severity": "high"}
        )
        assert result is True
        payload = transport.calls[0]["payload"]
        assert any("HIPAA" in str(b) for b in payload["blocks"])

    def test_fallback_text_contains_framework_and_control(self):
        transport = _make_transport(success=True)
        notifier = SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)
        notifier.send_compliance_failure(
            {"framework": "ISO27001", "control": "A.9.1.1"}
        )
        text = transport.calls[0]["payload"]["text"]
        assert "ISO27001" in text
        assert "A.9.1.1" in text


class TestSlackNotifierSendTest:
    def test_sends_test_message(self):
        transport = _make_transport(success=True)
        notifier = SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)
        result = notifier.send_test("Hello Slack!")
        assert result is True
        assert transport.calls[0]["payload"]["text"] == "Hello Slack!"

    def test_returns_false_when_unconfigured(self):
        notifier = SlackNotifier()
        assert notifier.send_test() is False


# ---------------------------------------------------------------------------
# on_alert_created subscriber tests
# ---------------------------------------------------------------------------


class TestOnAlertCreated:
    def test_fires_for_critical_alerts(self):
        transport = _make_transport(success=True)
        # Patch the singleton
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)):
            result = on_alert_created({"title": "Breach", "severity": "critical"})
        assert result is True
        assert len(transport.calls) == 1

    def test_skips_non_critical_alerts(self):
        transport = _make_transport(success=True)
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)):
            result = on_alert_created({"title": "Low Risk", "severity": "low"})
        assert result is False
        assert len(transport.calls) == 0

    def test_skips_high_severity(self):
        transport = _make_transport(success=True)
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)):
            result = on_alert_created({"title": "High Alert", "severity": "high"})
        assert result is False

    def test_returns_false_when_notifier_unconfigured(self):
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=None)):
            result = on_alert_created({"title": "Critical", "severity": "critical"})
        assert result is False


# ---------------------------------------------------------------------------
# get_notifier singleton test
# ---------------------------------------------------------------------------


class TestGetNotifier:
    def test_returns_slack_notifier_instance(self):
        with patch("core.slack_notifier._notifier", None):
            notifier = get_notifier()
        assert isinstance(notifier, SlackNotifier)

    def test_singleton_returns_same_instance(self):
        instance = SlackNotifier()
        with patch("core.slack_notifier._notifier", instance):
            n1 = get_notifier()
            n2 = get_notifier()
        assert n1 is n2


# ---------------------------------------------------------------------------
# Router smoke tests
# ---------------------------------------------------------------------------


class TestSlackNotifierRouter:
    """Smoke tests for the HTTP router endpoints."""

    @pytest.fixture(autouse=True)
    def _client(self):
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from apps.api.slack_notifier_router import router
        from apps.api.auth_deps import api_key_auth

        app = FastAPI()
        app.include_router(router)
        # Bypass auth entirely for unit tests
        app.dependency_overrides[api_key_auth] = lambda: None
        self.client = TestClient(app, raise_server_exceptions=False)
        yield
        app.dependency_overrides.clear()

    def _headers(self):
        return {"X-API-Key": "test-token"}

    def test_status_unconfigured(self):
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=None)):
            resp = self.client.get("/api/v1/integrations/slack/status", headers=self._headers())
        assert resp.status_code == 200
        assert resp.json()["configured"] is False

    def test_status_configured(self):
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=_WEBHOOK_URL)):
            resp = self.client.get("/api/v1/integrations/slack/status", headers=self._headers())
        assert resp.status_code == 200
        assert resp.json()["configured"] is True

    def test_configure_valid_url(self):
        notifier = SlackNotifier(webhook_url=None)
        with patch("core.slack_notifier._notifier", notifier):
            resp = self.client.post(
                "/api/v1/integrations/slack/configure",
                json={"webhook_url": _WEBHOOK_URL},
                headers=self._headers(),
            )
        assert resp.status_code == 200
        assert resp.json()["configured"] is True

    def test_configure_invalid_url_returns_422(self):
        with patch("core.slack_notifier._notifier", SlackNotifier()):
            resp = self.client.post(
                "/api/v1/integrations/slack/configure",
                json={"webhook_url": "https://evil.com/hook"},
                headers=self._headers(),
            )
        assert resp.status_code == 422

    def test_test_endpoint_unconfigured_returns_400(self):
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=None)):
            resp = self.client.post(
                "/api/v1/integrations/slack/test",
                json={"message": "ping"},
                headers=self._headers(),
            )
        assert resp.status_code == 400

    def test_test_endpoint_configured_returns_200(self):
        transport = _make_transport(success=True)
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)):
            resp = self.client.post(
                "/api/v1/integrations/slack/test",
                json={"message": "ping"},
                headers=self._headers(),
            )
        assert resp.status_code == 200
        assert resp.json()["sent"] is True

    def test_notify_alert_sends_notification(self):
        transport = _make_transport(success=True)
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)):
            resp = self.client.post(
                "/api/v1/integrations/slack/notify/alert",
                json={"title": "Zero-day exploit", "severity": "critical"},
                headers=self._headers(),
            )
        assert resp.status_code == 200
        assert resp.json()["sent"] is True

    def test_notify_incident_sends_notification(self):
        transport = _make_transport(success=True)
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)):
            resp = self.client.post(
                "/api/v1/integrations/slack/notify/incident",
                json={"title": "Ransomware", "severity": "critical", "status": "active"},
                headers=self._headers(),
            )
        assert resp.status_code == 200

    def test_notify_compliance_sends_notification(self):
        transport = _make_transport(success=True)
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=_WEBHOOK_URL, transport=transport)):
            resp = self.client.post(
                "/api/v1/integrations/slack/notify/compliance",
                json={"framework": "SOC2", "control": "CC6.1"},
                headers=self._headers(),
            )
        assert resp.status_code == 200

    # ------------------------------------------------------------------
    # Root summary endpoint tests
    # ------------------------------------------------------------------

    def test_root_summary_configured(self):
        """GET / returns status=configured when webhook URL is set."""
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=_WEBHOOK_URL)):
            resp = self.client.get("/api/v1/integrations/slack/", headers=self._headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "configured"
        assert data["channel"] == "slack"
        assert data["summary"]["webhook_url_set"] is True

    def test_root_summary_unconfigured(self):
        """GET / returns status=unconfigured when no webhook URL is present."""
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=None)):
            resp = self.client.get("/api/v1/integrations/slack/", headers=self._headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "unconfigured"
        assert data["channel"] == "slack"
        assert data["summary"]["webhook_url_set"] is False
        assert "hint" in data

    def test_root_summary_unconfigured_hint_references_configure(self):
        """GET / hint text mentions the configure endpoint when unconfigured."""
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=None)):
            resp = self.client.get("/api/v1/integrations/slack/", headers=self._headers())
        hint = resp.json().get("hint", "")
        assert "/configure" in hint or "SLACK_WEBHOOK_URL" in hint

    def test_root_summary_no_hint_when_configured(self):
        """GET / does not include a hint key when webhook is already configured."""
        with patch("core.slack_notifier._notifier", SlackNotifier(webhook_url=_WEBHOOK_URL)):
            resp = self.client.get("/api/v1/integrations/slack/", headers=self._headers())
        assert "hint" not in resp.json()

    def test_root_summary_error_state_on_notifier_exception(self):
        """GET / returns status=error when the notifier raises."""
        class BrokenNotifier:
            @property
            def is_configured(self):
                raise RuntimeError("db gone")

        with patch("apps.api.slack_notifier_router._get_notifier", return_value=BrokenNotifier()):
            resp = self.client.get("/api/v1/integrations/slack/", headers=self._headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "error"
        assert "db gone" in data["error"]
