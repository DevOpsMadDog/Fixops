"""Scheduled Reports Engine — ALDECI.

Manages report schedules, triggers, delivery (Slack webhook), and run history.

Capabilities:
  - Report schedules (daily/weekly/monthly/on_demand) per org
  - Multiple report types: executive_summary, vulnerability_digest, compliance_status,
    threat_intel, incident_summary, kpi_report
  - Slack webhook delivery with graceful fallback
  - Delivery log per channel/recipient
  - Report templates registry
  - Stats aggregation per org

Compliance: ISO 27001 A.16, NIST SP 800-137 (continuous monitoring), SOC 2 CC7.2
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "scheduled_reports.db"
)

# n8n webhook paths for report delivery
_N8N_EMAIL_WEBHOOK_PATH = "webhook/aldeci-report-email"
_N8N_SLACK_WEBHOOK_PATH = "webhook/aldeci-report-slack"

_VALID_REPORT_TYPES = {
    "executive_summary",
    "vulnerability_digest",
    "compliance_status",
    "threat_intel",
    "incident_summary",
    "kpi_report",
}

_VALID_FREQUENCIES = {"daily", "weekly", "monthly", "on_demand"}
_VALID_FORMATS = {"json", "pdf", "html", "csv"}
_VALID_STATUSES = {"active", "paused", "archived"}
_VALID_RUN_STATUSES = {"running", "completed", "failed", "delivered"}
_VALID_DELIVERY_CHANNELS = {"email", "slack", "webhook"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _calc_next_run(
    frequency: str,
    hour_utc: int = 8,
    day_of_week: Optional[int] = None,
    day_of_month: Optional[int] = None,
) -> Optional[str]:
    """Calculate the next scheduled run time from now."""
    now = datetime.now(timezone.utc)
    if frequency == "daily":
        t = now.replace(hour=hour_utc, minute=0, second=0, microsecond=0)
        if t <= now:
            t += timedelta(days=1)
        return t.isoformat()
    elif frequency == "weekly" and day_of_week is not None:
        days_ahead = (day_of_week - now.weekday()) % 7
        if days_ahead == 0 and now.hour >= hour_utc:
            days_ahead = 7
        t = (now + timedelta(days=days_ahead)).replace(
            hour=hour_utc, minute=0, second=0, microsecond=0
        )
        return t.isoformat()
    elif frequency == "monthly":
        dom = day_of_month or 1
        try:
            t = now.replace(
                day=min(dom, 28), hour=hour_utc, minute=0, second=0, microsecond=0
            )
        except ValueError:
            t = now.replace(day=1, hour=hour_utc, minute=0, second=0, microsecond=0)
        if t <= now:
            if t.month == 12:
                t = t.replace(year=t.year + 1, month=1)
            else:
                t = t.replace(month=t.month + 1)
        return t.isoformat()
    else:
        # on_demand or unknown
        return None


class ScheduledReportsEngine:
    """SQLite WAL-backed Scheduled Reports Engine.

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
                CREATE TABLE IF NOT EXISTS report_schedules (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL DEFAULT '',
                    report_type       TEXT NOT NULL DEFAULT 'executive_summary',
                    frequency         TEXT NOT NULL DEFAULT 'weekly',
                    hour_utc          INTEGER NOT NULL DEFAULT 8,
                    day_of_week       INTEGER,
                    day_of_month      INTEGER,
                    recipients        TEXT NOT NULL DEFAULT '[]',
                    slack_webhook_url TEXT NOT NULL DEFAULT '',
                    format            TEXT NOT NULL DEFAULT 'json',
                    enabled           INTEGER NOT NULL DEFAULT 1,
                    last_run_at       TEXT,
                    next_run_at       TEXT,
                    created_at        TEXT NOT NULL,
                    status            TEXT NOT NULL DEFAULT 'active'
                );

                CREATE INDEX IF NOT EXISTS idx_rs_org_enabled
                    ON report_schedules (org_id, enabled, next_run_at);

                CREATE INDEX IF NOT EXISTS idx_rs_org_type
                    ON report_schedules (org_id, report_type);

                CREATE TABLE IF NOT EXISTS report_runs (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    schedule_id       TEXT NOT NULL,
                    report_type       TEXT NOT NULL DEFAULT '',
                    started_at        TEXT NOT NULL,
                    completed_at      TEXT,
                    status            TEXT NOT NULL DEFAULT 'running',
                    delivery_channels TEXT NOT NULL DEFAULT '[]',
                    recipient_count   INTEGER NOT NULL DEFAULT 0,
                    content_preview   TEXT NOT NULL DEFAULT '',
                    error_message     TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_rr_org_schedule
                    ON report_runs (org_id, schedule_id, started_at DESC);

                CREATE INDEX IF NOT EXISTS idx_rr_org_status
                    ON report_runs (org_id, status);

                CREATE TABLE IF NOT EXISTS report_templates (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL DEFAULT '',
                    report_type TEXT NOT NULL DEFAULT 'executive_summary',
                    sections    TEXT NOT NULL DEFAULT '[]',
                    description TEXT NOT NULL DEFAULT '',
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rt_org_type
                    ON report_templates (org_id, report_type);

                CREATE TABLE IF NOT EXISTS delivery_log (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    run_id        TEXT NOT NULL,
                    channel       TEXT NOT NULL DEFAULT 'email',
                    recipient     TEXT NOT NULL DEFAULT '',
                    delivered_at  TEXT NOT NULL,
                    status        TEXT NOT NULL DEFAULT 'sent',
                    error_message TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_dl_org_run
                    ON delivery_log (org_id, run_id, delivered_at DESC);
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
    # Schedules
    # ------------------------------------------------------------------

    def create_schedule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new report schedule. Returns the created record."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        report_type = data.get("report_type", "executive_summary")
        if report_type not in _VALID_REPORT_TYPES:
            raise ValueError(
                f"Invalid report_type: {report_type}. Must be one of {_VALID_REPORT_TYPES}"
            )

        frequency = data.get("frequency", "weekly")
        if frequency not in _VALID_FREQUENCIES:
            raise ValueError(
                f"Invalid frequency: {frequency}. Must be one of {_VALID_FREQUENCIES}"
            )

        fmt = data.get("format", "json")
        if fmt not in _VALID_FORMATS:
            raise ValueError(f"Invalid format: {fmt}. Must be one of {_VALID_FORMATS}")

        recipients = data.get("recipients", [])
        if not isinstance(recipients, list):
            recipients = []

        hour_utc = int(data.get("hour_utc", 8))
        day_of_week = data.get("day_of_week")
        day_of_month = data.get("day_of_month")

        if day_of_week is not None:
            day_of_week = int(day_of_week)
        if day_of_month is not None:
            day_of_month = int(day_of_month)

        now = _now_iso()
        next_run = _calc_next_run(frequency, hour_utc, day_of_week, day_of_month)

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "report_type": report_type,
            "frequency": frequency,
            "hour_utc": hour_utc,
            "day_of_week": day_of_week,
            "day_of_month": day_of_month,
            "recipients": json.dumps(recipients),
            "slack_webhook_url": data.get("slack_webhook_url", ""),
            "format": fmt,
            "enabled": 1,
            "last_run_at": None,
            "next_run_at": next_run,
            "created_at": now,
            "status": "active",
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO report_schedules
                       (id, org_id, name, report_type, frequency, hour_utc,
                        day_of_week, day_of_month, recipients, slack_webhook_url,
                        format, enabled, last_run_at, next_run_at, created_at, status)
                       VALUES (:id, :org_id, :name, :report_type, :frequency, :hour_utc,
                               :day_of_week, :day_of_month, :recipients, :slack_webhook_url,
                               :format, :enabled, :last_run_at, :next_run_at, :created_at, :status)""",
                    record,
                )

        # Deserialize recipients for return
        record["recipients"] = recipients
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "scheduled_reports", "org_id": org_id, "source_engine": "scheduled_reports"})
            except Exception:
                pass

        return record

    def list_schedules(
        self,
        org_id: str,
        enabled: Optional[bool] = None,
        report_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List report schedules with optional filters."""
        sql = "SELECT * FROM report_schedules WHERE org_id = ?"
        params: list = [org_id]
        if enabled is not None:
            sql += " AND enabled = ?"
            params.append(1 if enabled else 0)
        if report_type:
            sql += " AND report_type = ?"
            params.append(report_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = [self._row(r) for r in conn.execute(sql, params).fetchall()]
        for r in rows:
            r["recipients"] = json.loads(r.get("recipients") or "[]")
        return rows

    def get_schedule(self, org_id: str, schedule_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single schedule by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM report_schedules WHERE org_id = ? AND id = ?",
                (org_id, schedule_id),
            ).fetchone()
        if not row:
            return None
        r = self._row(row)
        r["recipients"] = json.loads(r.get("recipients") or "[]")
        return r

    def update_schedule(
        self, org_id: str, schedule_id: str, updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update schedule fields. Recalculates next_run_at if frequency/timing changed."""
        existing = self.get_schedule(org_id, schedule_id)
        if not existing:
            raise ValueError(f"Schedule {schedule_id} not found for org {org_id}.")

        # Allowed update fields
        allowed = {
            "name", "report_type", "frequency", "hour_utc", "day_of_week",
            "day_of_month", "recipients", "slack_webhook_url", "format",
        }
        set_clauses = []
        params: list = []

        for key, val in updates.items():
            if key not in allowed:
                continue
            if key == "report_type" and val not in _VALID_REPORT_TYPES:
                raise ValueError(f"Invalid report_type: {val}")
            if key == "frequency" and val not in _VALID_FREQUENCIES:
                raise ValueError(f"Invalid frequency: {val}")
            if key == "format" and val not in _VALID_FORMATS:
                raise ValueError(f"Invalid format: {val}")
            if key == "recipients":
                if not isinstance(val, list):
                    val = []
                val = json.dumps(val)
            set_clauses.append(f"{key} = ?")
            params.append(val)

        # Recalculate next_run_at if scheduling fields changed
        timing_keys = {"frequency", "hour_utc", "day_of_week", "day_of_month"}
        if timing_keys & set(updates.keys()):
            frequency = updates.get("frequency", existing["frequency"])
            hour_utc = int(updates.get("hour_utc", existing["hour_utc"]))
            dow = updates.get("day_of_week", existing.get("day_of_week"))
            dom = updates.get("day_of_month", existing.get("day_of_month"))
            next_run = _calc_next_run(frequency, hour_utc, dow, dom)
            set_clauses.append("next_run_at = ?")
            params.append(next_run)

        if not set_clauses:
            return existing

        sql = f"UPDATE report_schedules SET {', '.join(set_clauses)} WHERE org_id = ? AND id = ?"  # nosec B608
        params.extend([org_id, schedule_id])

        with self._lock:
            with self._conn() as conn:
                conn.execute(sql, params)

        updated = self.get_schedule(org_id, schedule_id)
        if not updated:
            raise ValueError(f"Schedule {schedule_id} not found after update.")
        return updated

    def pause_schedule(self, org_id: str, schedule_id: str) -> Dict[str, Any]:
        """Pause a schedule (enabled=0, status='paused')."""
        if not self.get_schedule(org_id, schedule_id):
            raise ValueError(f"Schedule {schedule_id} not found for org {org_id}.")
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE report_schedules SET enabled = 0, status = 'paused' WHERE org_id = ? AND id = ?",
                    (org_id, schedule_id),
                )
        result = self.get_schedule(org_id, schedule_id)
        if not result:
            raise ValueError(f"Schedule {schedule_id} not found after pause.")
        return result

    def resume_schedule(self, org_id: str, schedule_id: str) -> Dict[str, Any]:
        """Resume a paused schedule (enabled=1, status='active', recalc next_run_at)."""
        existing = self.get_schedule(org_id, schedule_id)
        if not existing:
            raise ValueError(f"Schedule {schedule_id} not found for org {org_id}.")

        next_run = _calc_next_run(
            existing["frequency"],
            existing["hour_utc"],
            existing.get("day_of_week"),
            existing.get("day_of_month"),
        )
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE report_schedules
                       SET enabled = 1, status = 'active', next_run_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (next_run, org_id, schedule_id),
                )
        result = self.get_schedule(org_id, schedule_id)
        if not result:
            raise ValueError(f"Schedule {schedule_id} not found after resume.")
        return result

    def delete_schedule(self, org_id: str, schedule_id: str) -> bool:
        """Delete a schedule. Returns True if found and deleted."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "DELETE FROM report_schedules WHERE org_id = ? AND id = ?",
                    (org_id, schedule_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Report trigger / runs
    # ------------------------------------------------------------------

    def trigger_report(
        self,
        org_id: str,
        schedule_id: str,
        override_recipients: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Trigger an immediate report run for a schedule.

        Creates a run record, generates a content preview, attempts Slack delivery,
        logs each delivery attempt, marks run completed, and updates last_run_at.
        """
        schedule = self.get_schedule(org_id, schedule_id)
        if not schedule:
            raise ValueError(f"Schedule {schedule_id} not found for org {org_id}.")

        now = _now_iso()
        run_id = str(uuid.uuid4())

        recipients = override_recipients if override_recipients is not None else schedule["recipients"]
        if not isinstance(recipients, list):
            recipients = []

        delivery_channels: List[str] = []
        if recipients:
            delivery_channels.append("email")
        if schedule.get("slack_webhook_url"):
            delivery_channels.append("slack")

        run_record: Dict[str, Any] = {
            "id": run_id,
            "org_id": org_id,
            "schedule_id": schedule_id,
            "report_type": schedule["report_type"],
            "started_at": now,
            "completed_at": None,
            "status": "running",
            "delivery_channels": json.dumps(delivery_channels),
            "recipient_count": len(recipients),
            "content_preview": "",
            "error_message": "",
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO report_runs
                       (id, org_id, schedule_id, report_type, started_at, completed_at,
                        status, delivery_channels, recipient_count, content_preview, error_message)
                       VALUES (:id, :org_id, :schedule_id, :report_type, :started_at, :completed_at,
                               :status, :delivery_channels, :recipient_count, :content_preview, :error_message)""",
                    run_record,
                )

        # Generate content preview
        content_preview = json.dumps(
            {
                "report_type": schedule["report_type"],
                "org_id": org_id,
                "generated_at": now,
                "summary": f"Security posture report for {org_id}",
                "schedule_name": schedule["name"],
                "frequency": schedule["frequency"],
            }
        )

        # Attempt email delivery via n8n webhook
        if recipients:
            n8n_email_status, n8n_email_error = self._deliver_via_n8n(
                channel="email",
                schedule=schedule,
                org_id=org_id,
                generated_at=now,
                recipients=recipients,
                content_preview=content_preview,
            )
            for recipient in recipients:
                self._log_delivery(
                    org_id, run_id, "email", recipient,
                    status=n8n_email_status, error_message=n8n_email_error,
                )

        # Attempt Slack delivery via n8n webhook (preferred) or direct webhook fallback
        slack_url = schedule.get("slack_webhook_url", "")
        if slack_url:
            n8n_slack_status, n8n_slack_error = self._deliver_via_n8n(
                channel="slack",
                schedule=schedule,
                org_id=org_id,
                generated_at=now,
                recipients=[slack_url],
                content_preview=content_preview,
            )
            if n8n_slack_status == "failed":
                # Fall back to direct Slack webhook POST
                n8n_slack_status, n8n_slack_error = self._deliver_slack(
                    slack_url, schedule, org_id, now
                )
            self._log_delivery(
                org_id, run_id, "slack", slack_url,
                status=n8n_slack_status, error_message=n8n_slack_error,
            )

        completed_at = _now_iso()

        # Mark run completed
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE report_runs
                       SET status = 'completed', completed_at = ?, content_preview = ?
                       WHERE org_id = ? AND id = ?""",
                    (completed_at, content_preview, org_id, run_id),
                )
                # Update schedule last_run_at
                conn.execute(
                    "UPDATE report_schedules SET last_run_at = ? WHERE org_id = ? AND id = ?",
                    (completed_at, org_id, schedule_id),
                )

        run_record["status"] = "completed"
        run_record["completed_at"] = completed_at
        run_record["content_preview"] = content_preview
        run_record["delivery_channels"] = delivery_channels
        return run_record

    def _deliver_via_n8n(
        self,
        channel: str,
        schedule: Dict[str, Any],
        org_id: str,
        generated_at: str,
        recipients: List[str],
        content_preview: str,
    ) -> Tuple[str, str]:
        """POST report delivery payload to n8n webhook for email or Slack routing.

        Returns (status, error_message). Status is 'sent', 'queued', or 'failed'.
        Falls back gracefully when n8n is unavailable.
        """
        n8n_base = os.environ.get("N8N_BASE_URL", "http://localhost:5678").rstrip("/")
        webhook_path = (
            _N8N_EMAIL_WEBHOOK_PATH if channel == "email" else _N8N_SLACK_WEBHOOK_PATH
        )
        url = f"{n8n_base}/{webhook_path}"

        payload = {
            "channel": channel,
            "org_id": org_id,
            "schedule_id": schedule["id"],
            "schedule_name": schedule["name"],
            "report_type": schedule["report_type"],
            "frequency": schedule["frequency"],
            "generated_at": generated_at,
            "recipients": recipients,
            "content_preview": content_preview,
        }
        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                if resp.status in (200, 201):
                    _logger.info(
                        "n8n delivery succeeded channel=%s schedule=%s",
                        channel, schedule["id"],
                    )
                    return "sent", ""
                return "failed", f"HTTP {resp.status}"
        except Exception as exc:
            _logger.warning(
                "n8n delivery unavailable channel=%s schedule=%s error=%s",
                channel, schedule.get("id", "?"), exc,
            )
            return "failed", str(exc)

    def _deliver_slack(
        self,
        webhook_url: str,
        schedule: Dict[str, Any],
        org_id: str,
        generated_at: str,
    ) -> Tuple[str, str]:
        """Attempt Slack webhook delivery. Returns (status, error_message)."""
        payload = {
            "text": (
                f"*ALDECI Scheduled Report* — {schedule['name']}\n"
                f"Type: `{schedule['report_type']}` | Org: `{org_id}`\n"
                f"Generated: {generated_at}"
            ),
            "username": "ALDECI Reports",
            "icon_emoji": ":bar_chart:",
        }
        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
                webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                if resp.status == 200:
                    return "sent", ""
                return "failed", f"HTTP {resp.status}"
        except Exception as exc:
            _logger.warning("Slack delivery failed for schedule %s: %s", schedule["id"], exc)
            return "failed", str(exc)

    def _log_delivery(
        self,
        org_id: str,
        run_id: str,
        channel: str,
        recipient: str,
        status: str = "sent",
        error_message: str = "",
    ) -> None:
        """Insert a delivery_log entry."""
        entry = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "run_id": run_id,
            "channel": channel,
            "recipient": recipient,
            "delivered_at": _now_iso(),
            "status": status,
            "error_message": error_message,
        }
        try:
            with self._lock:
                with self._conn() as conn:
                    conn.execute(
                        """INSERT INTO delivery_log
                           (id, org_id, run_id, channel, recipient, delivered_at, status, error_message)
                           VALUES (:id, :org_id, :run_id, :channel, :recipient, :delivered_at,
                                   :status, :error_message)""",
                        entry,
                    )
        except Exception as exc:
            _logger.warning("Failed to log delivery: %s", exc)

    def list_runs(
        self,
        org_id: str,
        schedule_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List report runs with optional filters."""
        sql = "SELECT * FROM report_runs WHERE org_id = ?"
        params: list = [org_id]
        if schedule_id:
            sql += " AND schedule_id = ?"
            params.append(schedule_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = [self._row(r) for r in conn.execute(sql, params).fetchall()]
        for r in rows:
            r["delivery_channels"] = json.loads(r.get("delivery_channels") or "[]")
        return rows

    def get_run(self, org_id: str, run_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single run by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM report_runs WHERE org_id = ? AND id = ?",
                (org_id, run_id),
            ).fetchone()
        if not row:
            return None
        r = self._row(row)
        r["delivery_channels"] = json.loads(r.get("delivery_channels") or "[]")
        return r

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------

    def create_template(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a report template. Returns the created record."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        report_type = data.get("report_type", "executive_summary")
        if report_type not in _VALID_REPORT_TYPES:
            raise ValueError(f"Invalid report_type: {report_type}")

        sections = data.get("sections", [])
        if not isinstance(sections, list):
            sections = []

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "report_type": report_type,
            "sections": json.dumps(sections),
            "description": data.get("description", ""),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO report_templates
                       (id, org_id, name, report_type, sections, description, created_at)
                       VALUES (:id, :org_id, :name, :report_type, :sections, :description, :created_at)""",
                    record,
                )

        record["sections"] = sections
        return record

    def list_templates(
        self, org_id: str, report_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List templates, optionally filtered by report_type."""
        sql = "SELECT * FROM report_templates WHERE org_id = ?"
        params: list = [org_id]
        if report_type:
            sql += " AND report_type = ?"
            params.append(report_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = [self._row(r) for r in conn.execute(sql, params).fetchall()]
        for r in rows:
            r["sections"] = json.loads(r.get("sections") or "[]")
        return rows

    # ------------------------------------------------------------------
    # Default schedule seeding
    # ------------------------------------------------------------------

    def seed_default_schedules(
        self, org_id: str, overwrite: bool = False
    ) -> List[Dict[str, Any]]:
        """Create the 3 canonical ALDECI report schedules for an org if they don't exist.

        Schedules:
          1. Daily Security Posture Summary  — daily at 06:00 UTC
          2. Weekly Executive Briefing       — Monday at 08:00 UTC (day_of_week=0)
          3. Monthly Compliance Report       — 1st of month at 07:00 UTC

        Args:
            org_id: Organisation to seed schedules for.
            overwrite: If True, delete existing default schedules before re-creating.

        Returns:
            List of created schedule dicts (skips if already exists and overwrite=False).
        """
        defaults = [
            {
                "name": "Daily Security Posture Summary",
                "report_type": "executive_summary",
                "frequency": "daily",
                "hour_utc": 6,
                "day_of_week": None,
                "day_of_month": None,
                "recipients": [],
                "slack_webhook_url": "",
                "format": "json",
            },
            {
                "name": "Weekly Executive Briefing",
                "report_type": "executive_summary",
                "frequency": "weekly",
                "hour_utc": 8,
                "day_of_week": 0,  # Monday
                "day_of_month": None,
                "recipients": [],
                "slack_webhook_url": "",
                "format": "json",
            },
            {
                "name": "Monthly Compliance Report",
                "report_type": "compliance_status",
                "frequency": "monthly",
                "hour_utc": 7,
                "day_of_week": None,
                "day_of_month": 1,
                "recipients": [],
                "slack_webhook_url": "",
                "format": "json",
            },
        ]

        default_names = {d["name"] for d in defaults}

        if overwrite:
            existing = self.list_schedules(org_id)
            for sched in existing:
                if sched.get("name") in default_names:
                    self.delete_schedule(org_id, sched["id"])

        # Check which defaults already exist
        existing_names = {
            s["name"] for s in self.list_schedules(org_id)
            if s.get("name") in default_names
        }

        created: List[Dict[str, Any]] = []
        for spec in defaults:
            if spec["name"] in existing_names:
                _logger.debug(
                    "seed_default_schedules: skipping existing schedule name=%s org=%s",
                    spec["name"], org_id,
                )
                continue
            record = self.create_schedule(org_id, spec)
            created.append(record)
            _logger.info(
                "seed_default_schedules: created schedule name=%s org=%s id=%s",
                spec["name"], org_id, record["id"],
            )

        return created

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated scheduled-reports stats for org."""
        week_ago = (
            datetime.now(timezone.utc) - timedelta(days=7)
        ).isoformat()

        with self._conn() as conn:
            schedule_count = conn.execute(
                "SELECT COUNT(*) FROM report_schedules WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_schedules = conn.execute(
                "SELECT COUNT(*) FROM report_schedules WHERE org_id = ? AND enabled = 1",
                (org_id,),
            ).fetchone()[0]

            runs_this_week = conn.execute(
                "SELECT COUNT(*) FROM report_runs WHERE org_id = ? AND started_at >= ?",
                (org_id, week_ago),
            ).fetchone()[0]

            # By report type (schedules)
            by_type_rows = conn.execute(
                """SELECT report_type, COUNT(*) as cnt
                   FROM report_schedules WHERE org_id = ?
                   GROUP BY report_type""",
                (org_id,),
            ).fetchall()
            by_report_type = {r["report_type"]: r["cnt"] for r in by_type_rows}

            # Upcoming runs — next 5 by next_run_at
            upcoming_rows = conn.execute(
                """SELECT id, name, report_type, next_run_at, frequency
                   FROM report_schedules
                   WHERE org_id = ? AND enabled = 1 AND next_run_at IS NOT NULL
                   ORDER BY next_run_at ASC
                   LIMIT 5""",
                (org_id,),
            ).fetchall()
            upcoming_runs = [self._row(r) for r in upcoming_rows]

        return {
            "schedule_count": schedule_count,
            "active_schedules": active_schedules,
            "runs_this_week": runs_this_week,
            "by_report_type": by_report_type,
            "upcoming_runs": upcoming_runs,
        }
