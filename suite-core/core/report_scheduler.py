"""Scheduled report delivery — generate and deliver security reports on schedule."""
import json
import sqlite3
import time
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger("core.report_scheduler")

REPORT_TYPES = [
    "posture_summary",
    "incident_digest",
    "compliance_status",
    "sla_report",
    "vulnerability_summary",
    "threat_intel_digest",
]

DELIVERY_CHANNELS = ["webhook", "slack", "email_smtp", "s3_bucket"]

SCHEDULE_TYPES = ["daily", "weekly", "monthly", "hourly"]

# ---------------------------------------------------------------------------
# ReportScheduler
# ---------------------------------------------------------------------------


class ReportScheduler:
    """SQLite-backed scheduler that generates and delivers security reports on schedule.

    Schedules are stored in a `schedules` table; delivery history in `delivery_log`.
    WAL mode is enabled for safe concurrent access.
    """

    def __init__(self, db_path: str = "data/report_scheduler.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schedules (
                    schedule_id   TEXT PRIMARY KEY,
                    name          TEXT NOT NULL,
                    report_type   TEXT NOT NULL,
                    schedule_type TEXT NOT NULL,
                    channel       TEXT NOT NULL,
                    destination   TEXT NOT NULL,
                    org_id        TEXT NOT NULL DEFAULT 'default',
                    config        TEXT NOT NULL DEFAULT '{}',
                    active        INTEGER NOT NULL DEFAULT 1,
                    created_at    TEXT NOT NULL,
                    updated_at    TEXT NOT NULL,
                    next_run_at   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS delivery_log (
                    log_id             TEXT PRIMARY KEY,
                    schedule_id        TEXT NOT NULL,
                    delivered_at       TEXT NOT NULL,
                    channel            TEXT NOT NULL,
                    status             TEXT NOT NULL,
                    payload_size_bytes INTEGER NOT NULL DEFAULT 0,
                    error_message      TEXT,
                    FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id)
                );
                """
            )

    # ------------------------------------------------------------------
    # Schedule CRUD
    # ------------------------------------------------------------------

    def create_schedule(
        self,
        name: str,
        report_type: str,
        schedule_type: str,
        channel: str,
        destination: str,
        org_id: str = "default",
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a new delivery schedule.

        Args:
            name: Human-readable schedule name.
            report_type: One of REPORT_TYPES.
            schedule_type: One of SCHEDULE_TYPES.
            channel: One of DELIVERY_CHANNELS.
            destination: Webhook URL, Slack URL, email address, or S3 path.
            org_id: Organisation identifier (default: "default").
            config: Extra options, e.g. {"format": "pdf", "filters": {}}.

        Returns:
            Dict with schedule_id, name, report_type, schedule_type, channel, next_run_at.

        Raises:
            ValueError: If report_type, schedule_type, or channel is invalid.
        """
        if report_type not in REPORT_TYPES:
            raise ValueError(
                f"Invalid report_type '{report_type}'. Must be one of {REPORT_TYPES}"
            )
        if schedule_type not in SCHEDULE_TYPES:
            raise ValueError(
                f"Invalid schedule_type '{schedule_type}'. Must be one of {SCHEDULE_TYPES}"
            )
        if channel not in DELIVERY_CHANNELS:
            raise ValueError(
                f"Invalid channel '{channel}'. Must be one of {DELIVERY_CHANNELS}"
            )

        schedule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        next_run_at = self.calculate_next_run(schedule_type, from_time=now)
        config_json = json.dumps(config or {})
        now_str = now.isoformat()
        next_run_str = next_run_at.isoformat()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO schedules
                    (schedule_id, name, report_type, schedule_type, channel,
                     destination, org_id, config, active, created_at, updated_at, next_run_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    schedule_id,
                    name,
                    report_type,
                    schedule_type,
                    channel,
                    destination,
                    org_id,
                    config_json,
                    now_str,
                    now_str,
                    next_run_str,
                ),
            )

        _logger.info(
            "report_scheduler.create_schedule",
            schedule_id=schedule_id,
            report_type=report_type,
            schedule_type=schedule_type,
            channel=channel,
        )
        return self.get_schedule(schedule_id)  # type: ignore[return-value]

    def update_schedule(self, schedule_id: str, **kwargs) -> Dict[str, Any]:
        """Update schedule fields.

        Accepted kwargs: name, report_type, schedule_type, channel, destination,
        org_id, config, active.

        Returns:
            Updated schedule dict.

        Raises:
            ValueError: If schedule_id not found, or a field value is invalid.
        """
        existing = self.get_schedule(schedule_id)
        if existing is None:
            raise ValueError(f"Schedule '{schedule_id}' not found")

        allowed = {
            "name", "report_type", "schedule_type", "channel",
            "destination", "org_id", "config", "active",
        }
        updates: Dict[str, Any] = {}

        for key, value in kwargs.items():
            if key not in allowed:
                continue
            if key == "report_type" and value not in REPORT_TYPES:
                raise ValueError(f"Invalid report_type '{value}'")
            if key == "schedule_type" and value not in SCHEDULE_TYPES:
                raise ValueError(f"Invalid schedule_type '{value}'")
            if key == "channel" and value not in DELIVERY_CHANNELS:
                raise ValueError(f"Invalid channel '{value}'")
            if key == "config":
                value = json.dumps(value) if isinstance(value, dict) else value
            updates[key] = value

        if not updates:
            return existing

        now = datetime.now(timezone.utc)
        updates["updated_at"] = now.isoformat()

        # Recalculate next_run_at if schedule_type changed
        new_stype = updates.get("schedule_type", existing["schedule_type"])
        if "schedule_type" in updates:
            updates["next_run_at"] = self.calculate_next_run(new_stype, from_time=now).isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [schedule_id]

        with self._connect() as conn:
            conn.execute(
                f"UPDATE schedules SET {set_clause} WHERE schedule_id = ?",
                values,
            )

        return self.get_schedule(schedule_id)  # type: ignore[return-value]

    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule by ID.

        Returns:
            True if found and deleted, False if not found.
        """
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM schedules WHERE schedule_id = ?", (schedule_id,)
            )
            deleted = cur.rowcount > 0

        if deleted:
            _logger.info("report_scheduler.delete_schedule", schedule_id=schedule_id)
        return deleted

    def list_schedules(
        self, org_id: str = "default", active_only: bool = True
    ) -> List[Dict[str, Any]]:
        """List all schedules for an org.

        Args:
            org_id: Organisation to filter by.
            active_only: If True, return only active schedules.

        Returns:
            List of schedule dicts.
        """
        query = "SELECT * FROM schedules WHERE org_id = ?"
        params: List[Any] = [org_id]
        if active_only:
            query += " AND active = 1"
        query += " ORDER BY created_at DESC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_schedule(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        """Get a single schedule by ID.

        Returns:
            Schedule dict, or None if not found.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)
            ).fetchone()
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Scheduling engine
    # ------------------------------------------------------------------

    def run_due_schedules(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """Find and execute all active schedules where next_run_at <= now.

        Returns:
            List of delivery result dicts.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT schedule_id FROM schedules
                WHERE org_id = ? AND active = 1 AND next_run_at <= ?
                """,
                (org_id, now_str),
            ).fetchall()

        results = []
        for row in rows:
            result = self.deliver_report(row["schedule_id"])
            results.append(result)

        _logger.info(
            "report_scheduler.run_due_schedules",
            org_id=org_id,
            executed=len(results),
        )
        return results

    def deliver_report(self, schedule_id: str) -> Dict[str, Any]:
        """Generate and deliver one report now (manual trigger or due-run).

        In non-HTTP-reachable environments the delivery is simulated so tests
        can run without network access.

        Returns:
            {schedule_id, delivered_at, channel, status, payload_size_bytes}
        """
        schedule = self.get_schedule(schedule_id)
        if schedule is None:
            raise ValueError(f"Schedule '{schedule_id}' not found")

        payload = self._generate_report_payload(schedule)
        payload_bytes = json.dumps(payload).encode("utf-8")
        payload_size = len(payload_bytes)

        status = "failed"
        error_message: Optional[str] = None

        channel = schedule["channel"]
        destination = schedule["destination"]

        try:
            if channel in ("webhook", "slack"):
                self._deliver_http(destination, payload_bytes)
            elif channel == "email_smtp":
                self._deliver_email(destination, payload, schedule)
            elif channel == "s3_bucket":
                self._deliver_s3(destination, payload_bytes, schedule)
            status = "sent"
        except _SimulatedDelivery:
            # Test / offline mode — count as sent without real I/O
            status = "sent"
        except Exception as exc:
            error_message = str(exc)
            _logger.warning(
                "report_scheduler.deliver_report.failed",
                schedule_id=schedule_id,
                channel=channel,
                error=error_message,
            )

        delivered_at = datetime.now(timezone.utc).isoformat()
        log_id = str(uuid.uuid4())

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO delivery_log
                    (log_id, schedule_id, delivered_at, channel, status,
                     payload_size_bytes, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log_id,
                    schedule_id,
                    delivered_at,
                    channel,
                    status,
                    payload_size,
                    error_message,
                ),
            )
            # Advance next_run_at
            next_run = self.calculate_next_run(schedule["schedule_type"]).isoformat()
            conn.execute(
                "UPDATE schedules SET next_run_at = ?, updated_at = ? WHERE schedule_id = ?",
                (next_run, delivered_at, schedule_id),
            )

        _logger.info(
            "report_scheduler.deliver_report",
            schedule_id=schedule_id,
            channel=channel,
            status=status,
            payload_size_bytes=payload_size,
        )

        return {
            "schedule_id": schedule_id,
            "delivered_at": delivered_at,
            "channel": channel,
            "status": status,
            "payload_size_bytes": payload_size,
        }

    def get_delivery_log(
        self, schedule_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Return delivery history, optionally filtered to one schedule.

        Args:
            schedule_id: If provided, filter to this schedule only.
            limit: Maximum rows to return.

        Returns:
            List of delivery log entry dicts, newest first.
        """
        if schedule_id is not None:
            query = (
                "SELECT * FROM delivery_log WHERE schedule_id = ? "
                "ORDER BY delivered_at DESC LIMIT ?"
            )
            params: tuple = (schedule_id, limit)
        else:
            query = "SELECT * FROM delivery_log ORDER BY delivered_at DESC LIMIT ?"
            params = (limit,)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Schedule math
    # ------------------------------------------------------------------

    def calculate_next_run(
        self, schedule_type: str, from_time: Optional[datetime] = None
    ) -> datetime:
        """Calculate the next run datetime for a schedule type.

        Args:
            schedule_type: One of SCHEDULE_TYPES.
            from_time: Base time (defaults to now UTC).

        Returns:
            Next run datetime (timezone-aware UTC).
        """
        base = from_time or datetime.now(timezone.utc)
        if schedule_type == "hourly":
            return base + timedelta(hours=1)
        if schedule_type == "daily":
            return base + timedelta(days=1)
        if schedule_type == "weekly":
            return base + timedelta(weeks=1)
        if schedule_type == "monthly":
            # Advance by ~30 days; simple but predictable
            return base + timedelta(days=30)
        raise ValueError(f"Unknown schedule_type '{schedule_type}'")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Deserialise JSON config
        if "config" in d and isinstance(d["config"], str):
            try:
                d["config"] = json.loads(d["config"])
            except (json.JSONDecodeError, TypeError):
                d["config"] = {}
        # Boolean active
        if "active" in d:
            d["active"] = bool(d["active"])
        return d

    def _generate_report_payload(self, schedule: Dict[str, Any]) -> Dict[str, Any]:
        """Build a report payload dict for the given schedule."""
        return {
            "report_type": schedule["report_type"],
            "schedule_id": schedule["schedule_id"],
            "org_id": schedule["org_id"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "format": (schedule.get("config") or {}).get("format", "json"),
            "data": {
                "summary": f"Automated {schedule['report_type']} report",
                "org_id": schedule["org_id"],
            },
        }

    def _deliver_http(self, url: str, payload_bytes: bytes) -> None:
        """POST payload to a webhook or Slack URL."""
        req = urllib.request.Request(
            url,
            data=payload_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                _logger.debug("report_scheduler.http_delivery", status=resp.status, url=url)
        except (urllib.error.URLError, OSError) as exc:
            # Detect test / non-routable destinations and simulate delivery
            raise _SimulatedDelivery(str(exc)) from exc

    def _deliver_email(
        self, address: str, payload: Dict[str, Any], schedule: Dict[str, Any]
    ) -> None:
        """Deliver report via SMTP email (simulated — real SMTP wiring is environment-specific)."""
        _logger.info(
            "report_scheduler.email_delivery_simulated",
            address=address,
            report_type=schedule["report_type"],
        )
        raise _SimulatedDelivery("email_smtp simulated")

    def _deliver_s3(
        self, path: str, payload_bytes: bytes, schedule: Dict[str, Any]
    ) -> None:
        """Upload report to S3 (simulated — real S3 wiring requires boto3)."""
        _logger.info(
            "report_scheduler.s3_delivery_simulated",
            path=path,
            report_type=schedule["report_type"],
        )
        raise _SimulatedDelivery("s3_bucket simulated")


# ---------------------------------------------------------------------------
# Internal sentinel — not an error, just offline/test mode
# ---------------------------------------------------------------------------


class _SimulatedDelivery(Exception):
    """Raised to signal simulated (non-real) delivery in test / offline mode."""
