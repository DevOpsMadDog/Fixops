"""SlackNotifier — lightweight webhook-based Slack notification engine for ALDECI.

Sends real-time security notifications via Slack Incoming Webhooks (no bot token
required). Formats alerts as Block Kit messages. Gracefully no-ops when
SLACK_WEBHOOK_URL is not configured.

Supported notification types:
  - Critical security alerts
  - Incident notifications
  - Compliance failures

Environment variable:
    SLACK_WEBHOOK_URL  — Slack Incoming Webhook URL
                         (https://hooks.slack.com/services/...)

Design:
  - HTTP transport is injectable for testing (no live Slack calls in tests)
  - Raises no exceptions when unconfigured — logs a warning and returns False
  - Thread-safe (stateless, no shared mutable state)
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import structlog

_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Severity emoji / color helpers
# ---------------------------------------------------------------------------

_SEVERITY_EMOJI: Dict[str, str] = {
    "critical": ":red_circle:",
    "high": ":orange_circle:",
    "medium": ":yellow_circle:",
    "low": ":white_circle:",
    "info": ":information_source:",
}

_SEVERITY_COLOR: Dict[str, str] = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFCC00",
    "low": "#36A64F",
    "info": "#439FE0",
}


def _sev_emoji(severity: str) -> str:
    return _SEVERITY_EMOJI.get(severity.lower(), ":white_circle:")


def _sev_color(severity: str) -> str:
    return _SEVERITY_COLOR.get(severity.lower(), "#888888")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# Block Kit builders
# ---------------------------------------------------------------------------


def build_critical_alert_blocks(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build Block Kit blocks for a critical security alert."""
    severity = str(alert.get("severity", "critical")).lower()
    title = alert.get("title", "Security Alert")
    message = alert.get("message", "")
    alert_id = alert.get("alert_id") or alert.get("id", "n/a")
    source = alert.get("source_engine") or alert.get("source", "ALDECI")
    org_id = alert.get("org_id", "")

    emoji = _sev_emoji(severity)
    sev_upper = severity.upper()

    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} [{sev_upper}] {title}",
                "emoji": True,
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Alert ID:*\n`{alert_id}`"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{sev_upper}"},
                {"type": "mrkdwn", "text": f"*Source:*\n{source}"},
                {"type": "mrkdwn", "text": f"*Time:*\n{_now_utc()}"},
            ],
        },
    ]
    if org_id:
        blocks[-1]["fields"].append({"type": "mrkdwn", "text": f"*Org:*\n{org_id}"})  # type: ignore[index]

    if message:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Details:*\n{message[:500]}"},
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"ALDECI Security Platform • {_now_utc()}",
                }
            ],
        }
    )
    return blocks


def build_incident_notification_blocks(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build Block Kit blocks for an incident notification."""
    severity = str(incident.get("severity", "high")).lower()
    title = incident.get("title", "Security Incident")
    incident_id = incident.get("incident_id") or incident.get("id", "n/a")
    status = incident.get("status", "open")
    assignee = incident.get("assignee", "Unassigned")
    description = incident.get("description", "")

    emoji = _sev_emoji(severity)
    sev_upper = severity.upper()

    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} Incident: {title}",
                "emoji": True,
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident ID:*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{sev_upper}"},
                {"type": "mrkdwn", "text": f"*Status:*\n{status.title()}"},
                {"type": "mrkdwn", "text": f"*Assignee:*\n{assignee}"},
            ],
        },
    ]
    if description:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Description:*\n{description[:500]}"},
            }
        )
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"ALDECI Incident Management • {_now_utc()}",
                }
            ],
        }
    )
    return blocks


def build_compliance_failure_blocks(failure: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build Block Kit blocks for a compliance failure notification."""
    framework = failure.get("framework", "Unknown Framework")
    control = failure.get("control", "Unknown Control")
    failure_id = failure.get("failure_id") or failure.get("id", "n/a")
    severity = str(failure.get("severity", "high")).lower()
    description = failure.get("description", "")
    remediation = failure.get("remediation", "")

    emoji = _sev_emoji(severity)

    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} Compliance Failure: {framework}",
                "emoji": True,
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Control:*\n{control}"},
                {"type": "mrkdwn", "text": f"*Framework:*\n{framework}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                {"type": "mrkdwn", "text": f"*Failure ID:*\n`{failure_id}`"},
            ],
        },
    ]
    if description:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Details:*\n{description[:500]}"},
            }
        )
    if remediation:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Remediation:*\n{remediation[:300]}"},
            }
        )
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"ALDECI Compliance Engine • {_now_utc()}",
                }
            ],
        }
    )
    return blocks


def build_test_blocks(message: str = "Test notification from ALDECI") -> List[Dict[str, Any]]:
    """Build Block Kit blocks for a test/ping notification."""
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":white_check_mark: ALDECI Slack Integration Test",
                "emoji": True,
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": message},
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Sent at {_now_utc()} — ALDECI Security Platform",
                }
            ],
        },
    ]


# ---------------------------------------------------------------------------
# HTTP transport (injectable for tests)
# ---------------------------------------------------------------------------

# Type alias: callable(webhook_url, payload_dict) -> bool
WebhookTransport = Callable[[str, Dict[str, Any]], bool]


def _default_transport(webhook_url: str, payload: Dict[str, Any]) -> bool:
    """Send payload to Slack webhook via httpx (sync). Returns True on success."""
    try:
        import httpx  # type: ignore[import-untyped]

        resp = httpx.post(webhook_url, json=payload, timeout=10.0)
        resp.raise_for_status()
        return True
    except Exception as exc:  # pragma: no cover
        _logger.error("slack.webhook.send_error", error=str(exc))
        return False


# ---------------------------------------------------------------------------
# SlackNotifier
# ---------------------------------------------------------------------------


class SlackNotifier:
    """Sends Slack notifications via Incoming Webhook.

    Args:
        webhook_url: Slack Incoming Webhook URL. If None, falls back to
            ``SLACK_WEBHOOK_URL`` env var. If still absent, all send
            methods return False with a warning logged.
        transport: Optional callable ``(url, payload) -> bool`` for
            testing without live HTTP calls.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        transport: Optional[WebhookTransport] = None,
    ) -> None:
        self._webhook_url: Optional[str] = (
            webhook_url or os.environ.get("SLACK_WEBHOOK_URL") or None
        )
        self._transport: WebhookTransport = transport or _default_transport

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        """True when a webhook URL is available."""
        return bool(self._webhook_url)

    def configure(self, webhook_url: str) -> None:
        """Update the webhook URL at runtime (e.g. from /configure endpoint)."""
        if not webhook_url.startswith("https://hooks.slack.com/"):
            raise ValueError(
                "Invalid Slack webhook URL. Must start with "
                "https://hooks.slack.com/"
            )
        self._webhook_url = webhook_url

    # ------------------------------------------------------------------
    # Core send primitive
    # ------------------------------------------------------------------

    def _send(self, blocks: List[Dict[str, Any]], fallback_text: str = "") -> bool:
        """Send a Block Kit payload to the configured webhook.

        Returns True on success, False when unconfigured or on error.
        """
        if not self._webhook_url:
            _logger.warning(
                "slack.notifier.unconfigured",
                hint="Set SLACK_WEBHOOK_URL environment variable",
            )
            return False

        payload: Dict[str, Any] = {
            "blocks": blocks,
            "text": fallback_text,  # fallback for notifications/screen readers
        }
        result = self._transport(self._webhook_url, payload)
        if result:
            _logger.info("slack.notification.sent", block_count=len(blocks))
        return result

    # ------------------------------------------------------------------
    # Typed notification methods
    # ------------------------------------------------------------------

    def send_critical_alert(self, alert: Dict[str, Any]) -> bool:
        """Send a critical security alert notification.

        Args:
            alert: Dict with keys: title, message, severity, alert_id,
                   source_engine, org_id (all optional except title).
        """
        blocks = build_critical_alert_blocks(alert)
        severity = alert.get("severity", "critical")
        title = alert.get("title", "Security Alert")
        return self._send(blocks, fallback_text=f"[{severity.upper()}] {title}")

    def send_incident_notification(self, incident: Dict[str, Any]) -> bool:
        """Send an incident notification.

        Args:
            incident: Dict with keys: title, severity, status, assignee,
                      incident_id, description (all optional except title).
        """
        blocks = build_incident_notification_blocks(incident)
        title = incident.get("title", "Security Incident")
        return self._send(blocks, fallback_text=f"Incident: {title}")

    def send_compliance_failure(self, failure: Dict[str, Any]) -> bool:
        """Send a compliance failure notification.

        Args:
            failure: Dict with keys: framework, control, severity, failure_id,
                     description, remediation.
        """
        blocks = build_compliance_failure_blocks(failure)
        framework = failure.get("framework", "Compliance")
        control = failure.get("control", "Unknown Control")
        return self._send(blocks, fallback_text=f"Compliance Failure: {framework} — {control}")

    def send_test(self, message: str = "Test notification from ALDECI") -> bool:
        """Send a test/ping notification to verify webhook is working."""
        blocks = build_test_blocks(message)
        return self._send(blocks, fallback_text=message)


# ---------------------------------------------------------------------------
# Module-level singleton (shared across the app process)
# ---------------------------------------------------------------------------

_notifier: Optional[SlackNotifier] = None


def get_notifier() -> SlackNotifier:
    """Return the shared SlackNotifier singleton."""
    global _notifier
    if _notifier is None:
        _notifier = SlackNotifier()
    return _notifier


# ---------------------------------------------------------------------------
# ALERT_CREATED event subscriber
# ---------------------------------------------------------------------------


def on_alert_created(alert: Dict[str, Any]) -> bool:
    """Subscriber for ALERT_CREATED events.

    Automatically fires a Slack notification for critical alerts.
    Attach this to your event bus:

        event_bus.subscribe("ALERT_CREATED", on_alert_created)

    Args:
        alert: Alert dict from AlertingNotificationEngine (or any engine).
              Must have at least "severity" key.

    Returns:
        True if notification was sent, False otherwise.
    """
    severity = str(alert.get("severity", "")).lower()
    if severity != "critical":
        return False
    notifier = get_notifier()
    return notifier.send_critical_alert(alert)
