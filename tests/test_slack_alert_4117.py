"""Multica #4117 — smoke tests for NotificationEngine.send_slack_alert.

Two tests:
1. Webhook fires when FIXOPS_SLACK_WEBHOOK_URL is set and finding is critical.
2. No HTTP call made when env var is absent (clean no-op).
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture()
def engine():
    from core.notification_engine import NotificationEngine
    return NotificationEngine()


def _critical_finding() -> dict:
    return {
        "id": "find-001",
        "title": "SQL Injection in login endpoint",
        "severity": "critical",
        "source_tool": "SAST",
        "org_id": "org-test",
    }


# ---------------------------------------------------------------------------
# Test 1: POST is made when env var is set and webhook returns 200
# ---------------------------------------------------------------------------
def test_send_slack_alert_posts_when_configured(engine):
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock(return_value=None)

    with patch.dict(os.environ, {"FIXOPS_SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/secret"}):
        with patch("httpx.post", return_value=mock_response) as mock_post:
            result = engine.send_slack_alert(
                text="Critical finding detected",
                finding=_critical_finding(),
            )

    assert result is True
    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert "https://hooks.slack.com/services/T/B/secret" in call_kwargs[0]
    posted_payload = call_kwargs[1]["json"]
    assert "find-001" in posted_payload["text"]
    assert "critical" in posted_payload["text"].lower()


# ---------------------------------------------------------------------------
# Test 2: No HTTP call when FIXOPS_SLACK_WEBHOOK_URL is not set
# ---------------------------------------------------------------------------
def test_send_slack_alert_noop_when_unconfigured(engine):
    env = {k: v for k, v in os.environ.items() if k != "FIXOPS_SLACK_WEBHOOK_URL"}
    with patch.dict(os.environ, env, clear=True):
        with patch("httpx.post") as mock_post:
            result = engine.send_slack_alert(
                text="Should not fire",
                finding=_critical_finding(),
            )

    assert result is True
    mock_post.assert_not_called()
