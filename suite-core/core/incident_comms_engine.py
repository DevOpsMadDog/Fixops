"""Incident Communications Engine — ALDECI.

Manages all communications during security incidents: initial notifications,
status updates, resolutions, post-mortems, stakeholder briefs, and press
releases. Supports templates, acknowledgment tracking, and delivery metrics.

Compliance: NIST CSF RS.CO-1, ISO/IEC 27001 A.16.1.6, SOC 2 CC7.4
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "incident_comms.db"
)

_VALID_COMM_TYPES = {
    "initial_notification", "status_update", "resolution",
    "post_mortem", "stakeholder_brief", "press_release",
}
_VALID_CHANNELS = {
    "email", "slack", "teams", "sms", "pagerduty", "status_page", "internal",
}
_VALID_COMM_STATUSES = {"draft", "sent", "delivered", "failed"}
_VALID_AUDIENCES = {"internal", "external", "executive", "technical", "customer", "all"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IncidentCommsEngine:
    """SQLite WAL-backed Incident Communications engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS incident_comms (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    incident_id     TEXT NOT NULL DEFAULT '',
                    comm_type       TEXT NOT NULL DEFAULT 'status_update',
                    channel         TEXT NOT NULL DEFAULT 'email',
                    subject         TEXT NOT NULL DEFAULT '',
                    body            TEXT NOT NULL DEFAULT '',
                    audience        TEXT NOT NULL DEFAULT 'internal',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    comm_status     TEXT NOT NULL DEFAULT 'draft',
                    scheduled_at    TEXT,
                    sent_at         TEXT,
                    delivered_count INTEGER NOT NULL DEFAULT 0,
                    failed_count    INTEGER NOT NULL DEFAULT 0,
                    author          TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS comm_acknowledgments (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    comm_id          TEXT NOT NULL,
                    acknowledger_id  TEXT NOT NULL DEFAULT '',
                    acknowledged_at  TEXT NOT NULL,
                    notes            TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS comm_templates (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    template_name    TEXT NOT NULL DEFAULT '',
                    comm_type        TEXT NOT NULL DEFAULT 'status_update',
                    channel          TEXT NOT NULL DEFAULT 'email',
                    subject_template TEXT NOT NULL DEFAULT '',
                    body_template    TEXT NOT NULL DEFAULT '',
                    audience         TEXT NOT NULL DEFAULT 'internal',
                    created_at       TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Communications
    # ------------------------------------------------------------------

    def create_comm(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new incident communication. subject and body are required."""
        comm_type = data.get("comm_type", "status_update")
        if comm_type not in _VALID_COMM_TYPES:
            raise ValueError(f"comm_type must be one of {_VALID_COMM_TYPES}")

        channel = data.get("channel", "email")
        if channel not in _VALID_CHANNELS:
            raise ValueError(f"channel must be one of {_VALID_CHANNELS}")

        subject = (data.get("subject") or "").strip()
        if not subject:
            raise ValueError("subject is required")

        body = (data.get("body") or "").strip()
        if not body:
            raise ValueError("body is required")

        audience = data.get("audience", "internal")
        if audience not in _VALID_AUDIENCES:
            raise ValueError(f"audience must be one of {_VALID_AUDIENCES}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")

        comm_status = data.get("comm_status", "draft")
        if comm_status not in _VALID_COMM_STATUSES:
            raise ValueError(f"comm_status must be one of {_VALID_COMM_STATUSES}")

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_id": data.get("incident_id", ""),
            "comm_type": comm_type,
            "channel": channel,
            "subject": subject,
            "body": body,
            "audience": audience,
            "severity": severity,
            "comm_status": comm_status,
            "scheduled_at": data.get("scheduled_at"),
            "sent_at": None,
            "delivered_count": 0,
            "failed_count": 0,
            "author": data.get("author", ""),
            "created_at": _now(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO incident_comms
                       (id, org_id, incident_id, comm_type, channel, subject, body,
                        audience, severity, comm_status, scheduled_at, sent_at,
                        delivered_count, failed_count, author, created_at)
                       VALUES (:id, :org_id, :incident_id, :comm_type, :channel, :subject, :body,
                               :audience, :severity, :comm_status, :scheduled_at, :sent_at,
                               :delivered_count, :failed_count, :author, :created_at)
                    """,
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("INCIDENT_CREATED", {"entity_type": "incident_comms", "org_id": org_id, "source_engine": "incident_comms"})
            except Exception:
                pass

        return record

    def list_comms(
        self,
        org_id: str,
        incident_id: Optional[str] = None,
        comm_type: Optional[str] = None,
        comm_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List communications with optional filters."""
        query = "SELECT * FROM incident_comms WHERE org_id = ?"
        params: List[Any] = [org_id]
        if incident_id:
            query += " AND incident_id = ?"
            params.append(incident_id)
        if comm_type:
            query += " AND comm_type = ?"
            params.append(comm_type)
        if comm_status:
            query += " AND comm_status = ?"
            params.append(comm_status)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_comm(self, org_id: str, comm_id: str) -> Optional[Dict[str, Any]]:
        """Return a single communication or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM incident_comms WHERE org_id = ? AND id = ?",
                (org_id, comm_id),
            ).fetchone()
        return self._row(row) if row else None

    def send_comm(
        self,
        org_id: str,
        comm_id: str,
        delivered: Optional[int] = None,
        failed: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Mark a communication as sent and update delivery counts.

        Raises KeyError if the comm does not exist for this org.
        """
        with self._lock:
            existing = self.get_comm(org_id, comm_id)
            if existing is None:
                raise KeyError(f"Communication '{comm_id}' not found")

            now = _now()
            delivered_count = int(delivered) if delivered is not None else 0
            failed_count = int(failed) if failed is not None else 0

            with self._conn() as conn:
                conn.execute(
                    """UPDATE incident_comms
                       SET comm_status = 'sent',
                           sent_at = ?,
                           delivered_count = delivered_count + ?,
                           failed_count = failed_count + ?
                       WHERE org_id = ? AND id = ?
                    """,
                    (now, delivered_count, failed_count, org_id, comm_id),
                )

        return self.get_comm(org_id, comm_id)

    # ------------------------------------------------------------------
    # Acknowledgments
    # ------------------------------------------------------------------

    def record_acknowledgment(
        self, org_id: str, comm_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record that a recipient acknowledged a communication."""
        acknowledger_id = (data.get("acknowledger_id") or "").strip()
        if not acknowledger_id:
            raise ValueError("acknowledger_id is required")

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "comm_id": comm_id,
            "acknowledger_id": acknowledger_id,
            "acknowledged_at": _now(),
            "notes": data.get("notes", ""),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO comm_acknowledgments
                       (id, org_id, comm_id, acknowledger_id, acknowledged_at, notes)
                       VALUES (:id, :org_id, :comm_id, :acknowledger_id, :acknowledged_at, :notes)
                    """,
                    record,
                )
        return record

    def list_acknowledgments(
        self, org_id: str, comm_id: str
    ) -> List[Dict[str, Any]]:
        """List all acknowledgments for a specific communication."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM comm_acknowledgments
                   WHERE org_id = ? AND comm_id = ?
                   ORDER BY acknowledged_at DESC
                """,
                (org_id, comm_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------

    def create_template(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a reusable communication template."""
        template_name = (data.get("template_name") or "").strip()
        if not template_name:
            raise ValueError("template_name is required")

        comm_type = data.get("comm_type", "status_update")
        if comm_type not in _VALID_COMM_TYPES:
            raise ValueError(f"comm_type must be one of {_VALID_COMM_TYPES}")

        channel = data.get("channel", "email")
        if channel not in _VALID_CHANNELS:
            raise ValueError(f"channel must be one of {_VALID_CHANNELS}")

        now = _now()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "template_name": template_name,
            "comm_type": comm_type,
            "channel": channel,
            "subject_template": data.get("subject_template", ""),
            "body_template": data.get("body_template", ""),
            "audience": data.get("audience", "internal"),
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO comm_templates
                       (id, org_id, template_name, comm_type, channel,
                        subject_template, body_template, audience, created_at, updated_at)
                       VALUES (:id, :org_id, :template_name, :comm_type, :channel,
                               :subject_template, :body_template, :audience, :created_at, :updated_at)
                    """,
                    record,
                )
        return record

    def list_templates(
        self,
        org_id: str,
        comm_type: Optional[str] = None,
        channel: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List templates with optional filters."""
        query = "SELECT * FROM comm_templates WHERE org_id = ?"
        params: List[Any] = [org_id]
        if comm_type:
            query += " AND comm_type = ?"
            params.append(comm_type)
        if channel:
            query += " AND channel = ?"
            params.append(channel)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_comms_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate communication statistics for the org."""
        with self._conn() as conn:
            total_comms = conn.execute(
                "SELECT COUNT(*) FROM incident_comms WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            sent_comms = conn.execute(
                "SELECT COUNT(*) FROM incident_comms WHERE org_id = ? AND comm_status = 'sent'",
                (org_id,),
            ).fetchone()[0]

            total_acknowledgments = conn.execute(
                "SELECT COUNT(*) FROM comm_acknowledgments WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            # by_channel
            by_channel_rows = conn.execute(
                "SELECT channel, COUNT(*) as cnt FROM incident_comms WHERE org_id = ? GROUP BY channel",
                (org_id,),
            ).fetchall()
            by_channel = {r["channel"]: r["cnt"] for r in by_channel_rows}

            # by_comm_type
            by_type_rows = conn.execute(
                "SELECT comm_type, COUNT(*) as cnt FROM incident_comms WHERE org_id = ? GROUP BY comm_type",
                (org_id,),
            ).fetchall()
            by_comm_type = {r["comm_type"]: r["cnt"] for r in by_type_rows}

            # failed_deliveries (sum of failed_count across all comms)
            failed_row = conn.execute(
                "SELECT SUM(failed_count) FROM incident_comms WHERE org_id = ?", (org_id,)
            ).fetchone()
            failed_deliveries = int(failed_row[0] or 0)

            # avg delivery rate = delivered / (delivered + failed) across all comms with sends
            rate_row = conn.execute(
                """SELECT SUM(delivered_count), SUM(delivered_count + failed_count)
                   FROM incident_comms WHERE org_id = ? AND comm_status IN ('sent', 'delivered')
                """,
                (org_id,),
            ).fetchone()
            total_delivered = rate_row[0] or 0
            total_attempts = rate_row[1] or 0
            avg_delivery_rate = round(total_delivered / total_attempts, 4) if total_attempts > 0 else 0.0

        return {
            "total_comms": total_comms,
            "sent_comms": sent_comms,
            "total_acknowledgments": total_acknowledgments,
            "by_channel": by_channel,
            "by_comm_type": by_comm_type,
            "failed_deliveries": failed_deliveries,
            "avg_delivery_rate": avg_delivery_rate,
        }
