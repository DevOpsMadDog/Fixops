"""Data Breach Response Engine — ALDECI.

Tracks data breach cases, affected records, regulatory notifications,
and compliance reporting (GDPR 72h, HIPAA 60-day, CCPA, etc.).

Compliance: GDPR Art. 33/34, HIPAA Breach Notification Rule,
            CCPA §1798.82, NY SHIELD Act.
"""

from __future__ import annotations

import json
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "breach_response.db"
)

_VALID_BREACH_TYPES = {
    "external_attack", "insider", "lost_device",
    "vendor_breach", "accidental_disclosure",
}
_VALID_STATUSES = {"suspected", "confirmed", "contained", "reported"}
_VALID_DATA_TYPES = {"pii", "phi", "pci", "credentials", "ip"}
_VALID_NOTIFICATION_TYPES = {"regulatory", "customer", "media", "internal"}
_VALID_REPORT_STATUSES = {"draft", "submitted", "accepted"}


class BreachResponseEngine:
    """SQLite WAL-backed data breach response and regulatory tracking engine.

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
                CREATE TABLE IF NOT EXISTS breach_cases (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    title                   TEXT NOT NULL,
                    breach_type             TEXT NOT NULL,
                    discovered_at           DATETIME NOT NULL,
                    breach_date             DATETIME,
                    status                  TEXT NOT NULL DEFAULT 'suspected',
                    data_types_affected     TEXT NOT NULL DEFAULT '[]',
                    estimated_records       INTEGER NOT NULL DEFAULT 0,
                    notifiable              INTEGER NOT NULL DEFAULT 0,
                    regulatory_deadline     DATETIME,
                    created_at              DATETIME NOT NULL,
                    updated_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_breach_org
                    ON breach_cases (org_id, status);

                CREATE TABLE IF NOT EXISTS notification_log (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    case_id             TEXT NOT NULL,
                    notified_party      TEXT NOT NULL,
                    notification_type   TEXT NOT NULL,
                    sent_at             DATETIME NOT NULL,
                    content_summary     TEXT NOT NULL DEFAULT '',
                    created_at          DATETIME NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES breach_cases(id)
                );

                CREATE INDEX IF NOT EXISTS idx_notif_case
                    ON notification_log (org_id, case_id);

                CREATE TABLE IF NOT EXISTS regulatory_reports (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    case_id     TEXT NOT NULL,
                    regulator   TEXT NOT NULL,
                    report_date DATETIME NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'draft',
                    created_at  DATETIME NOT NULL,
                    updated_at  DATETIME NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES breach_cases(id)
                );

                CREATE INDEX IF NOT EXISTS idx_report_case
                    ON regulatory_reports (org_id, case_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Deserialize JSON lists
        if "data_types_affected" in d:
            try:
                d["data_types_affected"] = json.loads(d["data_types_affected"] or "[]")
            except Exception:
                d["data_types_affected"] = []
        # Booleans
        if "notifiable" in d:
            d["notifiable"] = bool(d["notifiable"])
        return d

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Breach Cases
    # ------------------------------------------------------------------

    def create_case(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new breach case. Returns the full case record."""
        case_id = str(uuid.uuid4())
        now = self._now()
        data_types = data.get("data_types_affected", [])
        if isinstance(data_types, list):
            data_types_json = json.dumps(data_types)
        else:
            data_types_json = json.dumps([data_types])

        notifiable = bool(data.get("notifiable", False))

        record = {
            "id": case_id,
            "org_id": org_id,
            "title": str(data.get("title", "")),
            "breach_type": str(data.get("breach_type", "external_attack")),
            "discovered_at": data.get("discovered_at") or now,
            "breach_date": data.get("breach_date"),
            "status": str(data.get("status", "suspected")),
            "data_types_affected": json.loads(data_types_json),
            "estimated_records": int(data.get("estimated_records_affected", 0)),
            "notifiable": notifiable,
            "regulatory_deadline": data.get("regulatory_deadline"),
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO breach_cases
                        (id, org_id, title, breach_type, discovered_at, breach_date,
                         status, data_types_affected, estimated_records, notifiable,
                         regulatory_deadline, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["id"], record["org_id"], record["title"],
                        record["breach_type"], record["discovered_at"],
                        record["breach_date"], record["status"],
                        data_types_json,
                        record["estimated_records"],
                        1 if notifiable else 0,
                        record["regulatory_deadline"],
                        record["created_at"], record["updated_at"],
                    ),
                )
        _logger.info("Created breach case %s for org %s", case_id, org_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "breach_response", "org_id": org_id, "source_engine": "breach_response"})
            except Exception:
                pass

        return record

    def list_cases(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List breach cases for an org, optionally filtered by status."""
        query = "SELECT * FROM breach_cases WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_case(self, org_id: str, case_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single breach case, enforcing org isolation."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM breach_cases WHERE id = ? AND org_id = ?",
                    (case_id, org_id),
                ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_case(
        self, org_id: str, case_id: str, data: Dict[str, Any]
    ) -> bool:
        """Update mutable breach case fields. Returns True if a row was updated."""
        allowed = {
            "title", "breach_type", "discovered_at", "breach_date",
            "status", "estimated_records_affected", "notifiable",
            "regulatory_deadline",
        }
        updates: Dict[str, Any] = {}
        for k, v in data.items():
            if k not in allowed:
                continue
            if k == "estimated_records_affected":
                updates["estimated_records"] = int(v)
            elif k == "notifiable":
                updates["notifiable"] = 1 if v else 0
            elif k == "data_types_affected":
                updates["data_types_affected"] = json.dumps(v if isinstance(v, list) else [v])
            else:
                updates[k] = v

        # Handle data_types_affected separately (not in `allowed` set above)
        if "data_types_affected" in data:
            v = data["data_types_affected"]
            updates["data_types_affected"] = json.dumps(v if isinstance(v, list) else [v])

        if not updates:
            return False

        updates["updated_at"] = self._now()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [case_id, org_id]

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    f"UPDATE breach_cases SET {set_clause} WHERE id = ? AND org_id = ?",  # nosec B608
                    values,
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    def log_notification(
        self,
        org_id: str,
        case_id: str,
        notified_party: str,
        notification_type: str,
        sent_at: str,
        content_summary: str = "",
    ) -> Dict[str, Any]:
        """Log a notification sent for a breach case."""
        notif_id = str(uuid.uuid4())
        now = self._now()
        record = {
            "id": notif_id,
            "org_id": org_id,
            "case_id": case_id,
            "notified_party": notified_party,
            "notification_type": notification_type,
            "sent_at": sent_at,
            "content_summary": content_summary,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO notification_log
                        (id, org_id, case_id, notified_party, notification_type,
                         sent_at, content_summary, created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["id"], record["org_id"], record["case_id"],
                        record["notified_party"], record["notification_type"],
                        record["sent_at"], record["content_summary"],
                        record["created_at"],
                    ),
                )
        return record

    def list_notifications(self, org_id: str, case_id: str) -> List[Dict[str, Any]]:
        """List notifications for a breach case."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM notification_log
                    WHERE org_id = ? AND case_id = ?
                    ORDER BY sent_at DESC
                    """,
                    (org_id, case_id),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Regulatory Reports
    # ------------------------------------------------------------------

    def add_regulatory_report(
        self,
        org_id: str,
        case_id: str,
        regulator: str,
        report_date: str,
        status: str = "draft",
    ) -> Dict[str, Any]:
        """Create a regulatory report entry for a breach case."""
        report_id = str(uuid.uuid4())
        now = self._now()
        record = {
            "id": report_id,
            "org_id": org_id,
            "case_id": case_id,
            "regulator": regulator,
            "report_date": report_date,
            "status": status,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO regulatory_reports
                        (id, org_id, case_id, regulator, report_date, status,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["id"], record["org_id"], record["case_id"],
                        record["regulator"], record["report_date"],
                        record["status"], record["created_at"], record["updated_at"],
                    ),
                )
        return record

    def list_reports(
        self, org_id: str, case_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List regulatory reports, optionally scoped to a specific case."""
        query = "SELECT * FROM regulatory_reports WHERE org_id = ?"
        params: List[Any] = [org_id]
        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)
        query += " ORDER BY report_date DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_breach_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate breach statistics for an org."""
        with self._lock:
            with self._conn() as conn:
                total_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM breach_cases WHERE org_id = ?",
                    (org_id,),
                ).fetchone()

                confirmed_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM breach_cases WHERE org_id = ? AND status = 'confirmed'",
                    (org_id,),
                ).fetchone()

                type_rows = conn.execute(
                    """
                    SELECT breach_type, COUNT(*) as cnt
                    FROM breach_cases WHERE org_id = ?
                    GROUP BY breach_type
                    """,
                    (org_id,),
                ).fetchall()

                notif_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM notification_log WHERE org_id = ?",
                    (org_id,),
                ).fetchone()

                reports_due_row = conn.execute(
                    """
                    SELECT COUNT(*) as cnt FROM regulatory_reports
                    WHERE org_id = ? AND status IN ('draft', 'submitted')
                    """,
                    (org_id,),
                ).fetchone()

                # avg hours from discovery to first notification per case
                avg_row = conn.execute(
                    """
                    SELECT AVG(
                        (JULIANDAY(n.sent_at) - JULIANDAY(b.discovered_at)) * 24
                    ) as avg_hours
                    FROM notification_log n
                    JOIN breach_cases b ON b.id = n.case_id
                    WHERE n.org_id = ? AND b.org_id = ?
                      AND n.notification_type = 'regulatory'
                    """,
                    (org_id, org_id),
                ).fetchone()

        return {
            "total_cases": total_row["cnt"] if total_row else 0,
            "confirmed": confirmed_row["cnt"] if confirmed_row else 0,
            "by_type": {r["breach_type"]: r["cnt"] for r in type_rows},
            "notifications_sent": notif_row["cnt"] if notif_row else 0,
            "regulatory_reports_due": reports_due_row["cnt"] if reports_due_row else 0,
            "avg_discovery_to_notify_hours": (
                round(avg_row["avg_hours"], 2)
                if avg_row and avg_row["avg_hours"] is not None
                else None
            ),
        }
