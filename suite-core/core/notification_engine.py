"""
Phase 6: Notification Routing Engine for ALDECI.

This module provides intelligent notification routing with:
- Rule-based event filtering and routing
- Multiple notification channels (WebSocket, Email, Slack, Webhook, PagerDuty)
- Rate limiting to prevent notification floods
- SQLite-backed notification history for audit trails
- Channel adapters for easy extensibility

Compliance: SOC2 CC7.2 (System monitoring and alerting)
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.errors import ExternalServiceError  # noqa: F401 - re-exported for callers
from core.event_streaming import EventBus, StreamEvent

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================

class NotificationChannel(Enum):
    """Supported notification channels."""

    WEBSOCKET = "websocket"
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"

    def __str__(self) -> str:
        return self.value


# ============================================================================
# DATACLASSES
# ============================================================================

@dataclass
class NotificationRule:
    """
    Rule for routing events to notification channels.

    Attributes:
        rule_id: Unique rule identifier
        name: Human-readable rule name
        event_types: List of EventType strings to match
        severity_threshold: Minimum severity (info/warning/critical)
        channels: List of NotificationChannel to use
        filters: Additional event payload filters (dict)
        enabled: Whether rule is active
        org_id: Organization ID for multi-tenancy
    """

    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    event_types: List[str] = field(default_factory=list)
    severity_threshold: str = "info"
    channels: List[NotificationChannel] = field(default_factory=list)
    filters: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    org_id: str = "default"

    def matches_event(self, event: StreamEvent) -> bool:
        """Check if event matches this rule."""
        if not self.enabled:
            return False

        if event.org_id != self.org_id:
            return False

        # Check event type
        if self.event_types and str(event.event_type) not in self.event_types:
            return False

        # Check severity
        severity_order = {"info": 0, "warning": 1, "critical": 2}
        event_severity = severity_order.get(str(event.severity).lower(), 0)
        threshold_severity = severity_order.get(self.severity_threshold.lower(), 0)
        if event_severity < threshold_severity:
            return False

        # Check additional filters (simple key-value matching in payload)
        if self.filters:
            for key, value in self.filters.items():
                if key not in event.payload or event.payload[key] != value:
                    return False

        return True


@dataclass
class NotificationAction:
    """Action to take for a matched event."""

    rule_id: str
    channel: NotificationChannel
    event: StreamEvent
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class NotificationHistory:
    """Record of sent notification."""

    history_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    channel: str = ""
    event_id: str = ""
    org_id: str = "default"
    status: str = "pending"  # pending, sent, failed
    message: str = ""
    error: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sent_at: Optional[datetime] = None


# ============================================================================
# CHANNEL ADAPTERS
# ============================================================================

class WebSocketAdapter:
    """Adapter for WebSocket notifications (uses EventBus directly)."""

    def __init__(self, bus: EventBus):
        """Initialize with EventBus instance."""
        self._bus = bus
        self._logger = _logger

    async def send(self, action: NotificationAction) -> bool:
        """
        Send notification via WebSocket (no-op, already in EventBus).

        Args:
            action: NotificationAction to send

        Returns:
            True if successful
        """
        self._logger.debug(
            f"WebSocket notification for event {action.event.event_id} "
            f"already delivered via EventBus"
        )
        return True


class EmailAdapter:
    """Adapter for email notifications.

    Reads SMTP config from env vars at construction time:
        FIXOPS_SMTP_HOST, FIXOPS_SMTP_PORT, FIXOPS_SMTP_USER,
        FIXOPS_SMTP_PASS, FIXOPS_SMTP_FROM

    When FIXOPS_SMTP_HOST is not set the adapter no-ops cleanly (logs a
    debug message and returns True so the notification pipeline continues).
    """

    def __init__(
        self,
        smtp_host: str = "",
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_pass: str = "",
        smtp_from: str = "noreply@aldeci.ai",
    ):
        import os
        self._smtp_host = smtp_host or os.getenv("FIXOPS_SMTP_HOST", "")
        self._smtp_port = int(os.getenv("FIXOPS_SMTP_PORT", str(smtp_port)))
        self._smtp_user = smtp_user or os.getenv("FIXOPS_SMTP_USER", "")
        self._smtp_pass = smtp_pass or os.getenv("FIXOPS_SMTP_PASS", "")
        self._smtp_from = smtp_from or os.getenv("FIXOPS_SMTP_FROM", "noreply@aldeci.ai")
        self._logger = _logger

    async def send(self, action: NotificationAction) -> bool:
        """
        Send notification via SMTP when configured; no-op otherwise.

        Args:
            action: NotificationAction to send

        Returns:
            True if sent (or gracefully skipped when SMTP unconfigured)
        """
        if not self._smtp_host:
            self._logger.debug(
                "EmailAdapter: FIXOPS_SMTP_HOST not set — skipping email for event %s",
                action.event.event_id,
            )
            return True

        import smtplib
        from email.mime.text import MIMEText

        event_meta = getattr(action.event, "metadata", None) or {}
        recipient = event_meta.get("email") if event_meta else None
        if not recipient:
            self._logger.debug(
                "EmailAdapter: no recipient in event metadata — skipping event %s",
                action.event.event_id,
            )
            return True

        subject = f"[ALDECI] {action.event.event_type} — {action.event.event_id[:8]}"
        body = f"Event: {action.event.event_type}\nID: {action.event.event_id}\n"

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self._smtp_from
        msg["To"] = recipient

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10) as smtp:
                if self._smtp_user and self._smtp_pass:
                    smtp.starttls()
                    smtp.login(self._smtp_user, self._smtp_pass)
                smtp.sendmail(self._smtp_from, [recipient], msg.as_string())
            self._logger.info(
                "EmailAdapter: sent event %s to %s via %s:%s",
                action.event.event_id,
                recipient,
                self._smtp_host,
                self._smtp_port,
            )
            return True
        except Exception as exc:
            self._logger.error(
                "EmailAdapter: failed to send event %s — %s",
                action.event.event_id,
                exc,
            )
            return False


class SlackAdapter:
    """Adapter for Slack notifications."""

    def __init__(self, webhook_url: str):
        """
        Initialize Slack adapter.

        Args:
            webhook_url: Slack webhook URL
        """
        self._webhook_url = webhook_url
        self._logger = _logger

    async def send(self, action: NotificationAction) -> bool:
        """
        Send notification to Slack via incoming webhook.

        Args:
            action: NotificationAction to send

        Returns:
            True if successful
        """
        if not self._webhook_url or self._webhook_url.startswith("https://hooks.slack.com/services/STUB"):
            self._logger.debug(
                "SlackAdapter: webhook not configured — skipping event %s",
                action.event.event_id,
            )
            return True

        import httpx

        payload = {
            "text": (
                f":rotating_light: *ALDECI Critical Alert*\n"
                f"*Event*: {action.event.event_type}\n"
                f"*ID*: {action.event.event_id}\n"
                f"*Severity*: {action.event.severity}\n"
                f"*Org*: {action.event.org_id}"
            )
        }
        try:
            response = httpx.post(self._webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            self._logger.info(
                "SlackAdapter: sent event %s to webhook", action.event.event_id
            )
            return True
        except Exception as exc:
            self._logger.error(
                "SlackAdapter: failed to send event %s — %s",
                action.event.event_id,
                exc,
            )
            return False


class WebhookAdapter:
    """Adapter for generic webhook notifications."""

    def __init__(self, webhook_url: str):
        """
        Initialize webhook adapter.

        Args:
            webhook_url: Webhook URL
        """
        self._webhook_url = webhook_url
        self._logger = _logger

    async def send(self, action: NotificationAction) -> bool:
        """
        Send notification via webhook (stub implementation).

        Args:
            action: NotificationAction to send

        Returns:
            True if successful
        """
        action.event.to_dict()

        self._logger.info(
            f"Webhook notification (stub): Event {action.event.event_id} "
            f"to {self._webhook_url[:30]}..."
        )
        # Stub implementation - would use aiohttp to POST
        return True


class PagerDutyAdapter:
    """Adapter for PagerDuty notifications."""

    def __init__(self, api_key: str, integration_key: str):
        """
        Initialize PagerDuty adapter.

        Args:
            api_key: PagerDuty API key
            integration_key: PagerDuty integration key
        """
        self._api_key = api_key
        self._integration_key = integration_key
        self._logger = _logger

    async def send(self, action: NotificationAction) -> bool:
        """
        Send notification to PagerDuty (stub implementation).

        Args:
            action: NotificationAction to send

        Returns:
            True if successful
        """
        {
            "routing_key": self._integration_key,
            "event_action": "trigger",
            "dedup_key": action.event.event_id,
            "payload": {
                "summary": f"ALDECI: {action.event.event_type}",
                "severity": str(action.event.severity),
                "source": action.event.source,
                "custom_details": action.event.payload,
            },
        }

        self._logger.info(
            f"PagerDuty notification (stub): Event {action.event.event_id}"
        )
        # Stub implementation - would use aiohttp to POST to PagerDuty Events API v2
        return True


# ============================================================================
# NOTIFICATION ENGINE
# ============================================================================

class NotificationEngine:
    """
    Rule-based notification routing engine.

    Evaluates events against rules and distributes to configured channels.
    Includes rate limiting and notification history.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        rate_limit_per_minute: int = 10,
    ):
        """
        Initialize notification engine.

        Args:
            db_path: SQLite database path (None for in-memory)
            rate_limit_per_minute: Max notifications per channel per minute
        """
        self._db_path = db_path or ":memory:"
        self._rate_limit_per_minute = rate_limit_per_minute
        self._rules: Dict[str, NotificationRule] = {}
        self._adapters: Dict[NotificationChannel, Any] = {}
        self._channel_sent_times: Dict[str, List[datetime]] = {}  # channel → [timestamps]
        self._lock = threading.Lock()
        self._logger = _logger

        # Persistent connection — reused across all history reads/writes.
        # check_same_thread=False is safe because all DB access is serialised
        # through self._lock (see _record_history / get_history).
        self._conn: sqlite3.Connection = sqlite3.connect(
            str(self._db_path), check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")  # concurrent readers
        self._conn.execute("PRAGMA synchronous=NORMAL")  # fast, safe durability

        # Initialize database
        self._init_db()

        # Register default adapters
        self._register_default_adapters()

        # Create default rules
        self._create_default_rules()

    def _init_db(self) -> None:
        """Initialize SQLite database for notification history."""
        try:
            cursor = self._conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notification_history (
                    history_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    sent_at TEXT
                )
            """)

            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_event_id ON notification_history(event_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_org_id ON notification_history(org_id)"
            )

            self._conn.commit()
            self._logger.info(f"Notification database initialized at {self._db_path}")
        except (sqlite3.Error, OSError) as e:
            self._logger.error(f"Failed to initialize notification database: {e}")

    def _register_default_adapters(self) -> None:
        """Register default notification channel adapters."""
        import os
        self._adapters[NotificationChannel.WEBSOCKET] = WebSocketAdapter(EventBus())
        self._adapters[NotificationChannel.EMAIL] = EmailAdapter()
        self._adapters[NotificationChannel.SLACK] = SlackAdapter(
            webhook_url=os.getenv("FIXOPS_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/STUB")
        )
        self._adapters[NotificationChannel.WEBHOOK] = WebhookAdapter(
            webhook_url="https://webhook.example.com/alerts"
        )
        self._adapters[NotificationChannel.PAGERDUTY] = PagerDutyAdapter(
            api_key="stub-key",
            integration_key="stub-integration-key",
        )

    def _create_default_rules(self) -> None:
        """Create default notification rules."""
        # Rule 1: Critical system alerts to PagerDuty
        critical_rule = NotificationRule(
            rule_id="rule-critical-pagerduty",
            name="Critical System Alerts to PagerDuty",
            event_types=["system:alert"],
            severity_threshold="critical",
            channels=[NotificationChannel.PAGERDUTY],
            enabled=True,
        )
        self.add_rule(critical_rule)

        # Rule 2: Escalations to admins via WebSocket
        escalation_rule = NotificationRule(
            rule_id="rule-escalations",
            name="Escalations via WebSocket",
            event_types=["escalation:triggered"],
            severity_threshold="warning",
            channels=[NotificationChannel.WEBSOCKET],
            enabled=True,
        )
        self.add_rule(escalation_rule)

        # Rule 3: Compliance alerts via Slack
        compliance_rule = NotificationRule(
            rule_id="rule-compliance-slack",
            name="Compliance Alerts to Slack",
            event_types=["compliance:alert"],
            severity_threshold="warning",
            channels=[NotificationChannel.SLACK],
            enabled=True,
        )
        self.add_rule(compliance_rule)

    def add_rule(self, rule: NotificationRule) -> None:
        """
        Add a notification rule.

        Args:
            rule: NotificationRule to add
        """
        with self._lock:
            self._rules[rule.rule_id] = rule
            self._logger.info(f"Added notification rule: {rule.name}")

    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a notification rule.

        Args:
            rule_id: Rule ID to remove

        Returns:
            True if rule was removed
        """
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                self._logger.info(f"Removed notification rule: {rule_id}")
                return True
            return False

    def get_rule(self, rule_id: str) -> Optional[NotificationRule]:
        """Get rule by ID."""
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self, org_id: Optional[str] = None) -> List[NotificationRule]:
        """
        List all rules, optionally filtered by org.

        Args:
            org_id: Optional organization ID to filter

        Returns:
            List of matching rules
        """
        with self._lock:
            rules = list(self._rules.values())
            if org_id:
                rules = [r for r in rules if r.org_id == org_id]
            return rules

    def evaluate(self, event: StreamEvent) -> List[NotificationAction]:
        """
        Evaluate event against all rules.

        Args:
            event: StreamEvent to evaluate

        Returns:
            List of NotificationAction objects
        """
        actions = []

        with self._lock:
            for rule in self._rules.values():
                if rule.matches_event(event):
                    for channel in rule.channels:
                        action = NotificationAction(
                            rule_id=rule.rule_id,
                            channel=channel,
                            event=event,
                        )
                        actions.append(action)

        return actions

    def _is_rate_limited(self, channel: NotificationChannel) -> bool:
        """
        Check if channel is rate-limited.

        Args:
            channel: NotificationChannel to check

        Returns:
            True if channel has hit rate limit
        """
        channel_key = str(channel)
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=1)

        with self._lock:
            if channel_key not in self._channel_sent_times:
                self._channel_sent_times[channel_key] = []

            # Remove old timestamps
            self._channel_sent_times[channel_key] = [
                ts for ts in self._channel_sent_times[channel_key] if ts > cutoff
            ]

            # Check if over limit
            if len(self._channel_sent_times[channel_key]) >= self._rate_limit_per_minute:
                return True

            # Record this send
            self._channel_sent_times[channel_key].append(now)
            return False

    async def send_notification(self, action: NotificationAction) -> bool:
        """
        Send a notification action.

        Args:
            action: NotificationAction to send

        Returns:
            True if successful
        """
        # Check rate limit
        if self._is_rate_limited(action.channel):
            self._logger.warning(
                f"Rate limit exceeded for {action.channel} - dropping notification"
            )
            await self._record_history(
                action, "failed", f"Rate limited (max {self._rate_limit_per_minute}/min)"
            )
            return False

        # Get adapter
        adapter = self._adapters.get(action.channel)
        if not adapter:
            self._logger.warning(
                f"No adapter registered for channel {action.channel}"
            )
            await self._record_history(action, "failed", "No adapter found")
            return False

        # Send
        try:
            success = await adapter.send(action)
            await self._record_history(
                action, "sent" if success else "failed", "Sent successfully"
            )
            return success
        except (ExternalServiceError, OSError, RuntimeError) as e:
            self._logger.error(f"Failed to send notification: {e}")
            await self._record_history(action, "failed", str(e))
            return False

    async def _record_history(
        self,
        action: NotificationAction,
        status: str,
        message: str,
        error: Optional[str] = None,
    ) -> None:
        """
        Record notification in history database.

        Args:
            action: NotificationAction that was sent
            status: Status (pending/sent/failed)
            message: Status message
            error: Error message if failed
        """
        try:
            history = NotificationHistory(
                rule_id=action.rule_id,
                channel=str(action.channel),
                event_id=action.event.event_id,
                org_id=action.event.org_id,
                status=status,
                message=message,
                error=error,
            )

            with self._lock:
                cursor = self._conn.cursor()
                cursor.execute("""
                    INSERT INTO notification_history
                    (history_id, rule_id, channel, event_id, org_id, status, message, error, created_at, sent_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    history.history_id,
                    history.rule_id,
                    history.channel,
                    history.event_id,
                    history.org_id,
                    history.status,
                    history.message,
                    history.error,
                    history.created_at.isoformat(),
                    datetime.now(timezone.utc).isoformat() if status == "sent" else None,
                ))
                self._conn.commit()
        except (sqlite3.Error, OSError) as e:
            self._logger.error(f"Failed to record notification history: {e}")

    def get_history(
        self,
        org_id: str,
        limit: int = 100,
        event_id: Optional[str] = None,
    ) -> List[Dict]:
        """
        Get notification history.

        Args:
            org_id: Organization ID to filter
            limit: Maximum number of records
            event_id: Optional event ID to filter

        Returns:
            List of notification history records
        """
        try:
            with self._lock:
                self._conn.row_factory = sqlite3.Row
                cursor = self._conn.cursor()

                if event_id:
                    cursor.execute("""
                        SELECT * FROM notification_history
                        WHERE org_id = ? AND event_id = ?
                        ORDER BY created_at DESC
                        LIMIT ?
                    """, (org_id, event_id, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM notification_history
                        WHERE org_id = ?
                        ORDER BY created_at DESC
                        LIMIT ?
                    """, (org_id, limit))

                rows = cursor.fetchall()

            return [dict(row) for row in rows]
        except (sqlite3.Error, OSError) as e:
            self._logger.error(f"Failed to retrieve notification history: {e}")
            return []

    def send_slack_alert(self, text: str, finding: Dict[str, Any]) -> bool:
        """Post a plain-text alert to the configured Slack webhook synchronously.

        Reads FIXOPS_SLACK_WEBHOOK_URL from the environment.  No-ops cleanly
        when the env var is absent.

        Args:
            text: Human-readable alert message.
            finding: SecurityFindingsEngine record dict (id, title, severity …).

        Returns:
            True if the POST succeeded (or was skipped due to missing config).
        """
        import os
        import httpx

        webhook_url = os.getenv("FIXOPS_SLACK_WEBHOOK_URL", "")
        if not webhook_url:
            self._logger.debug(
                "send_slack_alert: FIXOPS_SLACK_WEBHOOK_URL not set — skipping finding %s",
                finding.get("id", "?"),
            )
            return True

        severity = finding.get("severity", "unknown")
        finding_id = finding.get("id", "?")
        title = finding.get("title", "Untitled")
        payload = {
            "text": (
                f":rotating_light: *ALDECI Critical Finding*\n"
                f"{text}\n"
                f"*ID*: {finding_id}\n"
                f"*Title*: {title}\n"
                f"*Severity*: {severity}"
            )
        }
        try:
            response = httpx.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            self._logger.info(
                "send_slack_alert: posted finding %s to Slack", finding_id
            )
            return True
        except Exception as exc:
            self._logger.error(
                "send_slack_alert: failed for finding %s — %s", finding_id, exc
            )
            return False
