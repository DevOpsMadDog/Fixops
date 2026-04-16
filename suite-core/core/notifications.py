"""Notification engine for ALDECI — configurable alert rules, multi-channel delivery, digest mode.

Provides:
- Channel enum: EMAIL, SLACK, IN_APP, WEBHOOK
- DigestFrequency enum: IMMEDIATE, HOURLY, DAILY, WEEKLY
- AlertRule Pydantic model
- NotificationPreference Pydantic model
- Notification Pydantic model
- NotificationEngine class (SQLite-backed)
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DB_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "..",
        "data",
        "notifications.db",
    )
)
_db_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    conditions TEXT NOT NULL,
    channels TEXT NOT NULL,
    recipients TEXT NOT NULL,
    digest_frequency TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON alert_rules(enabled);

CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    channel TEXT NOT NULL,
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    event_id TEXT,
    read INTEGER NOT NULL DEFAULT 0,
    digest_frequency TEXT NOT NULL DEFAULT 'immediate'
);
CREATE INDEX IF NOT EXISTS idx_notif_recipient ON notifications(recipient);
CREATE INDEX IF NOT EXISTS idx_notif_status ON notifications(status);
CREATE INDEX IF NOT EXISTS idx_notif_read ON notifications(read);
CREATE INDEX IF NOT EXISTS idx_notif_digest ON notifications(digest_frequency, status);

CREATE TABLE IF NOT EXISTS preferences (
    user_email TEXT PRIMARY KEY,
    channels TEXT NOT NULL,
    digest_frequency TEXT NOT NULL DEFAULT 'immediate',
    muted_sources TEXT NOT NULL DEFAULT '[]',
    quiet_hours_start INTEGER NOT NULL DEFAULT 0,
    quiet_hours_end INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Channel(str, Enum):
    EMAIL = "email"
    SLACK = "slack"
    IN_APP = "in_app"
    WEBHOOK = "webhook"


class DigestFrequency(str, Enum):
    IMMEDIATE = "immediate"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class AlertRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    enabled: bool = True
    conditions: Dict[str, Any] = Field(default_factory=dict)
    channels: List[Channel] = Field(default_factory=list)
    recipients: List[str] = Field(default_factory=list)
    digest_frequency: DigestFrequency = DigestFrequency.IMMEDIATE
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}


class NotificationPreference(BaseModel):
    user_email: str
    channels: List[Channel] = Field(default_factory=lambda: [Channel.IN_APP])
    digest_frequency: DigestFrequency = DigestFrequency.IMMEDIATE
    muted_sources: List[str] = Field(default_factory=list)
    quiet_hours_start: int = Field(default=0, ge=0, le=23)
    quiet_hours_end: int = Field(default=0, ge=0, le=23)

    model_config = {"use_enum_values": True}


class Notification(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule_name: str
    channel: Channel
    recipient: str
    subject: str
    body: str
    status: str = "pending"  # pending | sent | failed
    event_id: Optional[str] = None
    read: bool = False
    digest_frequency: DigestFrequency = DigestFrequency.IMMEDIATE

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _get_db(db_path: str = _DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def _rule_from_row(row: sqlite3.Row) -> AlertRule:
    d = dict(row)
    d["conditions"] = json.loads(d["conditions"]) if d.get("conditions") else {}
    d["channels"] = json.loads(d["channels"]) if d.get("channels") else []
    d["recipients"] = json.loads(d["recipients"]) if d.get("recipients") else []
    d["enabled"] = bool(d.get("enabled", 1))
    return AlertRule(**d)


def _notification_from_row(row: sqlite3.Row) -> Notification:
    d = dict(row)
    d["read"] = bool(d.get("read", 0))
    return Notification(**d)


# ---------------------------------------------------------------------------
# NotificationEngine
# ---------------------------------------------------------------------------


class NotificationEngine:
    """SQLite-backed notification engine with multi-channel delivery and digest support."""

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        # Initialize schema
        with self._lock:
            conn = _get_db(self._db_path)
            conn.close()

    # ------------------------------------------------------------------
    # Rule CRUD
    # ------------------------------------------------------------------

    def add_rule(self, rule: AlertRule) -> AlertRule:
        """Persist a new alert rule. Returns the rule with assigned id."""
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        rule = rule.model_copy(update={"created_at": now_dt, "updated_at": now_dt})
        channels_val = rule.channels if rule.channels else []
        channels_json = json.dumps([c if isinstance(c, str) else c.value for c in channels_val])
        freq_val = rule.digest_frequency if isinstance(rule.digest_frequency, str) else rule.digest_frequency.value
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                conn.execute(
                    "INSERT INTO alert_rules (id,name,description,enabled,conditions,channels,recipients,digest_frequency,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        rule.id,
                        rule.name,
                        rule.description,
                        1 if rule.enabled else 0,
                        json.dumps(rule.conditions),
                        channels_json,
                        json.dumps(rule.recipients),
                        freq_val,
                        now_iso,
                        now_iso,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        logger.info("Created alert rule '%s' (id=%s)", rule.name, rule.id)
        return rule

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> AlertRule:
        """Update fields on an existing rule. Raises KeyError if not found."""
        now = datetime.now(timezone.utc).isoformat()
        updates["updated_at"] = now

        set_clauses: List[str] = []
        params: List[Any] = []
        for key, val in updates.items():
            if key in ("conditions", "channels", "recipients"):
                set_clauses.append(f"{key}=?")
                params.append(json.dumps(val))
            elif key == "enabled":
                set_clauses.append(f"{key}=?")
                params.append(1 if val else 0)
            else:
                set_clauses.append(f"{key}=?")
                params.append(val)

        params.append(rule_id)
        sql = f"UPDATE alert_rules SET {', '.join(set_clauses)} WHERE id=?"  # nosec B608

        with self._lock:
            conn = _get_db(self._db_path)
            try:
                cur = conn.execute(sql, params)
                if cur.rowcount == 0:
                    raise KeyError(f"Rule {rule_id} not found")
                conn.commit()
                row = conn.execute("SELECT * FROM alert_rules WHERE id=?", (rule_id,)).fetchone()
            finally:
                conn.close()
        return _rule_from_row(row)

    def delete_rule(self, rule_id: str) -> bool:
        """Remove a rule by id. Returns True if deleted, False if not found."""
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                cur = conn.execute("DELETE FROM alert_rules WHERE id=?", (rule_id,))
                conn.commit()
                found = cur.rowcount > 0
            finally:
                conn.close()
        if found:
            logger.info("Deleted alert rule %s", rule_id)
        return found

    def list_rules(self) -> List[AlertRule]:
        """Return all alert rules ordered by name."""
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                rows = conn.execute("SELECT * FROM alert_rules ORDER BY name").fetchall()
            finally:
                conn.close()
        return [_rule_from_row(r) for r in rows]

    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Return a single rule by id, or None."""
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                row = conn.execute("SELECT * FROM alert_rules WHERE id=?", (rule_id,)).fetchone()
            finally:
                conn.close()
        return _rule_from_row(row) if row else None

    # ------------------------------------------------------------------
    # Event evaluation
    # ------------------------------------------------------------------

    def evaluate_event(self, event: Any) -> List[Notification]:
        """Match event against enabled rules and generate Notification objects.

        The event is expected to have attributes: event_type, severity, source,
        correlation_id (optional), payload (dict).
        """
        rules = self.list_rules()
        enabled = [r for r in rules if r.enabled]

        event_type = getattr(event, "event_type", None)
        if hasattr(event_type, "value"):
            event_type = event_type.value

        severity = getattr(event, "severity", None)
        if hasattr(severity, "value"):
            severity = severity.value

        source = getattr(event, "source", "")
        event_id = getattr(event, "correlation_id", None)
        payload = getattr(event, "payload", {})

        _SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        notifications: List[Notification] = []
        for rule in enabled:
            if not self._matches_rule(rule, event_type, severity, source, payload, _SEVERITY_ORDER):
                continue

            subject = f"[ALDECI] {rule.name}: {event_type or 'event'}"
            body = (
                f"Alert rule '{rule.name}' triggered.\n\n"
                f"Event type: {event_type}\n"
                f"Severity: {severity}\n"
                f"Source: {source}\n"
                f"Payload: {json.dumps(payload, default=str)}\n"
            )

            for channel in rule.channels:
                ch_val = channel if isinstance(channel, str) else channel.value
                for recipient in rule.recipients:
                    notif = Notification(
                        rule_name=rule.name,
                        channel=ch_val,
                        recipient=recipient,
                        subject=subject,
                        body=body,
                        status="pending",
                        event_id=event_id,
                        digest_frequency=rule.digest_frequency,
                    )
                    notifications.append(notif)

        # Persist all generated notifications
        for notif in notifications:
            self._persist_notification(notif)

        return notifications

    def _matches_rule(
        self,
        rule: AlertRule,
        event_type: Optional[str],
        severity: Optional[str],
        source: str,
        payload: Dict[str, Any],
        severity_order: Dict[str, int],
    ) -> bool:
        cond = rule.conditions
        if not cond:
            return True

        # severity_gte: event severity must be >= threshold
        if "severity_gte" in cond:
            threshold = cond["severity_gte"]
            ev_level = severity_order.get(str(severity).lower(), -1)
            th_level = severity_order.get(str(threshold).lower(), -1)
            if ev_level < th_level:
                return False

        # event_type match
        if "event_type" in cond:
            if event_type != cond["event_type"]:
                return False

        # finding_type match (from payload)
        if "finding_type" in cond:
            if payload.get("finding_type") != cond["finding_type"]:
                return False

        # source match
        if "source" in cond:
            if source != cond["source"]:
                return False

        return True

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def send_notification(self, notification: Notification) -> Notification:
        """Dispatch a notification via its channel. Updates status in DB."""
        channel = notification.channel if isinstance(notification.channel, str) else notification.channel.value
        try:
            if channel == Channel.EMAIL.value:
                self.send_email(notification.recipient, notification.subject, notification.body)
            elif channel == Channel.SLACK.value:
                self.send_slack(notification.recipient, notification.body)
            elif channel == Channel.IN_APP.value:
                self.send_in_app(notification.recipient, notification)
            elif channel == Channel.WEBHOOK.value:
                # Webhook dispatch would call an external URL stored in recipient
                logger.info("Webhook dispatch to %s (stub)", notification.recipient)
            else:
                logger.warning("Unknown channel: %s", channel)

            updated = self._update_notification_status(notification.id, "sent")
        except Exception as exc:
            logger.error("Failed to send notification %s via %s: %s", notification.id, channel, exc)
            updated = self._update_notification_status(notification.id, "failed")

        return updated

    def send_email(self, to: str, subject: str, body: str) -> None:
        """SMTP email delivery. Uses SMTP_HOST/SMTP_PORT/SMTP_FROM env vars."""
        smtp_host = os.environ.get("SMTP_HOST", "")
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        smtp_from = os.environ.get("SMTP_FROM", "aldeci@localhost")
        smtp_user = os.environ.get("SMTP_USER", "")
        smtp_pass = os.environ.get("SMTP_PASS", "")

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = to

        if not smtp_host:
            # Mock-safe: log instead of failing when SMTP not configured
            logger.info("Email (mock) to=%s subject=%s", to, subject)
            return

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [to], msg.as_string())
        logger.info("Email sent to %s: %s", to, subject)

    def send_slack(self, channel: str, message: str) -> None:
        """Send via SlackConnector if configured, else log."""
        slack_token = os.environ.get("SLACK_BOT_TOKEN", "")
        if not slack_token:
            logger.info("Slack (mock) channel=%s message=%s", channel, message[:80])
            return
        try:
            from core.connectors import SlackConnector
            connector = SlackConnector(bot_token=slack_token)
            connector.post_message(channel_id=channel, text=message)
        except Exception as exc:
            logger.warning("SlackConnector error: %s", exc)
            raise

    def send_in_app(self, user: str, notification: Notification) -> None:
        """Store notification for in-app retrieval (already persisted; just mark as sent)."""
        logger.info("In-app notification stored for user=%s id=%s", user, notification.id)

    # ------------------------------------------------------------------
    # Digest
    # ------------------------------------------------------------------

    def get_pending_digest(self, frequency: DigestFrequency) -> Dict[str, List[Notification]]:
        """Return pending notifications grouped by recipient for the given frequency."""
        freq_val = frequency if isinstance(frequency, str) else frequency.value
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                rows = conn.execute(
                    "SELECT * FROM notifications WHERE digest_frequency=? AND status='pending' ORDER BY recipient, timestamp",
                    (freq_val,),
                ).fetchall()
            finally:
                conn.close()

        grouped: Dict[str, List[Notification]] = {}
        for row in rows:
            notif = _notification_from_row(row)
            grouped.setdefault(notif.recipient, []).append(notif)
        return grouped

    def send_digest(self, frequency: DigestFrequency) -> int:
        """Aggregate pending notifications and send digest per recipient. Returns count sent."""
        grouped = self.get_pending_digest(frequency)
        sent_count = 0

        for recipient, notifs in grouped.items():
            if not notifs:
                continue

            subject = f"[ALDECI] Digest ({frequency if isinstance(frequency, str) else frequency.value}): {len(notifs)} alert(s)"
            body_lines = [f"You have {len(notifs)} alert(s) in this digest:\n"]
            for n in notifs:
                body_lines.append(f"- [{n.rule_name}] {n.subject}")
                body_lines.append(f"  {n.body[:200]}")
                body_lines.append("")
            body = "\n".join(body_lines)

            # Determine channel from first notification
            channel = notifs[0].channel
            digest_notif = Notification(
                rule_name="digest",
                channel=channel,
                recipient=recipient,
                subject=subject,
                body=body,
                status="pending",
                digest_frequency=frequency,
            )
            self._persist_notification(digest_notif)
            self.send_notification(digest_notif)

            # Mark source notifications as sent
            for n in notifs:
                self._update_notification_status(n.id, "sent")
            sent_count += len(notifs)

        return sent_count

    # ------------------------------------------------------------------
    # Preferences
    # ------------------------------------------------------------------

    def set_preference(self, pref: NotificationPreference) -> NotificationPreference:
        """Upsert user notification preference."""
        now = datetime.now(timezone.utc).isoformat()
        channels = pref.channels if all(isinstance(c, str) for c in pref.channels) else [c.value for c in pref.channels]
        freq = pref.digest_frequency if isinstance(pref.digest_frequency, str) else pref.digest_frequency.value

        with self._lock:
            conn = _get_db(self._db_path)
            try:
                conn.execute(
                    "INSERT INTO preferences (user_email,channels,digest_frequency,muted_sources,quiet_hours_start,quiet_hours_end,updated_at) "
                    "VALUES (?,?,?,?,?,?,?) "
                    "ON CONFLICT(user_email) DO UPDATE SET "
                    "channels=excluded.channels, digest_frequency=excluded.digest_frequency, "
                    "muted_sources=excluded.muted_sources, quiet_hours_start=excluded.quiet_hours_start, "
                    "quiet_hours_end=excluded.quiet_hours_end, updated_at=excluded.updated_at",
                    (
                        pref.user_email,
                        json.dumps(channels),
                        freq,
                        json.dumps(pref.muted_sources),
                        pref.quiet_hours_start,
                        pref.quiet_hours_end,
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        logger.info("Set preferences for %s", pref.user_email)
        return pref

    def get_preference(self, email: str) -> Optional[NotificationPreference]:
        """Return user notification preference, or None if not set."""
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                row = conn.execute("SELECT * FROM preferences WHERE user_email=?", (email,)).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        d = dict(row)
        return NotificationPreference(
            user_email=d["user_email"],
            channels=json.loads(d["channels"]),
            digest_frequency=d["digest_frequency"],
            muted_sources=json.loads(d["muted_sources"]),
            quiet_hours_start=d["quiet_hours_start"],
            quiet_hours_end=d["quiet_hours_end"],
        )

    # ------------------------------------------------------------------
    # In-app inbox
    # ------------------------------------------------------------------

    def get_unread_notifications(self, user_email: str) -> List[Notification]:
        """Return unread in-app notifications for a user."""
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                rows = conn.execute(
                    "SELECT * FROM notifications WHERE recipient=? AND channel='in_app' AND read=0 ORDER BY timestamp DESC",
                    (user_email,),
                ).fetchall()
            finally:
                conn.close()
        return [_notification_from_row(r) for r in rows]

    def mark_read(self, notification_ids: List[str]) -> int:
        """Mark notifications as read. Returns count updated."""
        if not notification_ids:
            return 0
        placeholders = ",".join("?" * len(notification_ids))
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                cur = conn.execute(
                    f"UPDATE notifications SET read=1 WHERE id IN ({placeholders})",  # nosec B608
                    notification_ids,
                )
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _persist_notification(self, notif: Notification) -> None:
        ts = notif.timestamp.isoformat() if isinstance(notif.timestamp, datetime) else notif.timestamp
        channel = notif.channel if isinstance(notif.channel, str) else notif.channel.value
        freq = notif.digest_frequency if isinstance(notif.digest_frequency, str) else notif.digest_frequency.value

        with self._lock:
            conn = _get_db(self._db_path)
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO notifications (id,timestamp,rule_name,channel,recipient,subject,body,status,event_id,read,digest_frequency) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        notif.id,
                        ts,
                        notif.rule_name,
                        channel,
                        notif.recipient,
                        notif.subject,
                        notif.body,
                        notif.status,
                        notif.event_id,
                        1 if notif.read else 0,
                        freq,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def _update_notification_status(self, notif_id: str, status: str) -> Notification:
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                conn.execute(
                    "UPDATE notifications SET status=? WHERE id=?",
                    (status, notif_id),
                )
                conn.commit()
                row = conn.execute("SELECT * FROM notifications WHERE id=?", (notif_id,)).fetchone()
            finally:
                conn.close()
        if row:
            return _notification_from_row(row)
        # Fallback: return notification with updated status
        return Notification(
            id=notif_id,
            rule_name="",
            channel=Channel.IN_APP,
            recipient="",
            subject="",
            body="",
            status=status,
        )
