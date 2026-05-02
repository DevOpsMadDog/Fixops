"""Event emitter module for ALDECI — fan-out security events to n8n webhooks.

Provides:
- EventType enum: canonical security event types
- SecurityEvent Pydantic model: structured event payload
- EventEmitter class: HMAC-signed webhook delivery with retry and SQLite persistence

Usage:
    from core.event_emitter import EventEmitter, EventType, SecurityEvent

    emitter = EventEmitter()
    wid = emitter.register_webhook("https://n8n.example.com/webhook/abc", [EventType.FINDING_CREATED], "secret123")
    emitter.emit(SecurityEvent(event_type=EventType.FINDING_CREATED, payload={"id": "F-001"}, source="scanner"))
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import requests
from pydantic import BaseModel, Field

from core.exceptions import ConnectorError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 1.0  # seconds; retry waits 1s, 2s, 4s
_DELIVERY_TIMEOUT_S = 10
_DB_PATH = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "event_emitter.db")
)
_db_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    event_types TEXT NOT NULL,
    secret TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_triggered TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_wh_active ON webhooks(active);
"""


# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    """Canonical security event types emitted by ALDECI."""

    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    RISK_CHANGED = "risk.changed"
    COMPLIANCE_GAP = "compliance.gap"
    PIPELINE_COMPLETED = "pipeline.completed"
    POLICY_VIOLATION = "policy.violation"
    SLA_BREACH = "sla.breach"


class Severity(str, Enum):
    """Event severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityEvent(BaseModel):
    """A structured security event emitted by ALDECI."""

    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    payload: Dict[str, Any] = Field(default_factory=dict)
    source: str = Field(default="aldeci", max_length=128)
    severity: Severity = Field(default=Severity.INFO)
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------


def _get_db(db_path: str = _DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["event_types"] = json.loads(d["event_types"]) if d.get("event_types") else []
    d["active"] = bool(d.get("active", 0))
    return d


# ---------------------------------------------------------------------------
# HMAC signing
# ---------------------------------------------------------------------------


def _sign_payload(secret: str, body: bytes) -> str:
    """Return hex HMAC-SHA256 signature of body using secret."""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# EventEmitter
# ---------------------------------------------------------------------------


class EventEmitter:
    """Fan-out security events to registered n8n/webhook endpoints.

    Thread-safe. SQLite-backed registration. HMAC-SHA256 signed delivery.
    Retries up to _MAX_RETRIES times with exponential backoff.
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_webhook(
        self,
        url: str,
        event_types: List[EventType],
        secret: Optional[str] = None,
        description: Optional[str] = None,
    ) -> str:
        """Register a webhook URL for a set of event types.

        Returns the webhook_id (UUID string).
        """
        if not url:
            raise ConnectorError("Webhook URL must not be empty")
        if not event_types:
            raise ConnectorError("At least one event_type must be provided")

        # SSRF protection: validate the target URL before persisting
        try:
            from core.exceptions import SSRFError
            from core.ssrf_protection import validate_url
            validate_url(url)
        except ImportError:
            pass  # ssrf_protection not available — degrade gracefully
        except SSRFError as exc:
            raise ConnectorError(f"Webhook URL rejected (SSRF): {exc}") from exc

        webhook_id = str(uuid.uuid4())
        effective_secret = secret if secret else secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc).isoformat()
        event_types_json = json.dumps([e.value if isinstance(e, EventType) else e for e in event_types])

        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    conn.execute(
                        "INSERT INTO webhooks (id, url, event_types, secret, active, created_at, failure_count, description) "
                        "VALUES (?, ?, ?, ?, 1, ?, 0, ?)",
                        (webhook_id, url, event_types_json, effective_secret, now, description),
                    )
                    conn.commit()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise ConnectorError(f"Failed to register webhook: {exc}") from exc

        logger.info("Registered webhook %s for events %s", webhook_id, event_types_json)
        return webhook_id

    def unregister_webhook(self, webhook_id: str) -> bool:
        """Deactivate a webhook registration. Returns True if found, False otherwise."""
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    cur = conn.execute(
                        "UPDATE webhooks SET active=0 WHERE id=?", (webhook_id,)
                    )
                    conn.commit()
                    found = cur.rowcount > 0
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise ConnectorError(f"Failed to unregister webhook: {exc}") from exc

        if found:
            logger.info("Unregistered webhook %s", webhook_id)
        else:
            logger.warning("Webhook %s not found for unregistration", webhook_id)
        return found

    def list_webhooks(self) -> List[Dict[str, Any]]:
        """Return all active webhook registrations."""
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    rows = conn.execute(
                        "SELECT * FROM webhooks WHERE active=1 ORDER BY created_at DESC"
                    ).fetchall()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise ConnectorError(f"Failed to list webhooks: {exc}") from exc
        return [_row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Emission
    # ------------------------------------------------------------------

    def emit(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Fan-out event to all active webhooks matching the event type.

        Returns list of delivery result dicts (one per matching webhook).
        """
        event_type_value = event.event_type if isinstance(event.event_type, str) else event.event_type.value

        # Fetch matching webhooks
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    rows = conn.execute(
                        "SELECT * FROM webhooks WHERE active=1"
                    ).fetchall()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            logger.error("Failed to query webhooks for emission: %s", exc)
            return []

        matching = [
            _row_to_dict(r)
            for r in rows
            if event_type_value in (json.loads(r["event_types"]) if isinstance(r["event_types"], str) else r["event_types"])
        ]

        results: List[Dict[str, Any]] = []
        for webhook in matching:
            result = self._deliver_with_retry(webhook, event)
            results.append(result)
            self._update_webhook_state(webhook, result)

        return results

    # ------------------------------------------------------------------
    # Internal delivery
    # ------------------------------------------------------------------

    def _deliver_with_retry(
        self, webhook: Dict[str, Any], event: SecurityEvent
    ) -> Dict[str, Any]:
        """Attempt delivery up to _MAX_RETRIES times with exponential backoff."""
        body = event.model_dump_json().encode("utf-8")
        sig = _sign_payload(webhook["secret"], body)
        headers = {
            "Content-Type": "application/json",
            "X-ALdeci-Signature": f"sha256={sig}",
            "X-ALdeci-Event": event.event_type if isinstance(event.event_type, str) else event.event_type.value,
            "X-ALdeci-Delivery-ID": event.correlation_id,
            "User-Agent": "ALdeci-EventEmitter/1.0",
        }

        last_result: Dict[str, Any] = {
            "webhook_id": webhook["id"],
            "status": "failed",
            "response_code": None,
            "error": None,
            "attempts": 0,
        }

        for attempt in range(1, _MAX_RETRIES + 1):
            last_result["attempts"] = attempt
            try:
                resp = requests.post(  # nosemgrep: dynamic-urllib-use-detected
                    webhook["url"],
                    data=body,
                    headers=headers,
                    timeout=_DELIVERY_TIMEOUT_S,
                    allow_redirects=False,
                )
                last_result["response_code"] = resp.status_code
                if 200 <= resp.status_code < 300:
                    last_result["status"] = "success"
                    last_result["error"] = None
                    logger.info(
                        "Delivered event %s to webhook %s (attempt %d)",
                        event.event_type,
                        webhook["id"],
                        attempt,
                    )
                    return last_result
                else:
                    last_result["error"] = f"HTTP {resp.status_code}"
            except requests.Timeout:
                last_result["error"] = "Timeout"
            except requests.ConnectionError:
                last_result["error"] = "ConnectionError"
            except requests.RequestException as exc:
                last_result["error"] = type(exc).__name__

            if attempt < _MAX_RETRIES:
                backoff = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning(
                    "Webhook %s delivery attempt %d failed (%s), retrying in %.1fs",
                    webhook["id"],
                    attempt,
                    last_result["error"],
                    backoff,
                )
                time.sleep(backoff)

        logger.error(
            "Webhook %s delivery failed after %d attempts: %s",
            webhook["id"],
            _MAX_RETRIES,
            last_result["error"],
        )
        return last_result

    def _update_webhook_state(
        self, webhook: Dict[str, Any], result: Dict[str, Any]
    ) -> None:
        """Update failure_count and last_triggered in SQLite after delivery."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    if result["status"] == "success":
                        conn.execute(
                            "UPDATE webhooks SET last_triggered=?, failure_count=0 WHERE id=?",
                            (now, webhook["id"]),
                        )
                    else:
                        new_count = webhook.get("failure_count", 0) + 1
                        conn.execute(
                            "UPDATE webhooks SET failure_count=?, last_triggered=? WHERE id=?",
                            (new_count, now, webhook["id"]),
                        )
                    conn.commit()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            logger.error("Failed to update webhook state: %s", exc)
