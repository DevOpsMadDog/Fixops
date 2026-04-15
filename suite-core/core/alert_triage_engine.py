"""Alert Triage Engine — ALDECI.

Centralized alert ingestion and triage workflow across all security sources
(SIEM, EDR, NDR, Cloud, WAF, IDS, Firewall). Supports bulk triage, priority
auto-assignment, escalation, and queue management.

Compliance: NIST CSF DE.AE-2, ISO/IEC 27001 A.16.1.5, SOC 2 CC7.3
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

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "alert_triage.db"
)

_VALID_SOURCE_SYSTEMS = {"siem", "edr", "ndr", "cloud", "waf", "ids", "firewall", "custom"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_TRIAGE_STATUSES = {
    "new", "triaging", "escalated", "investigating",
    "resolved", "false_positive", "duplicate",
}
_VALID_PRIORITIES = {"p1", "p2", "p3", "p4"}

_SEVERITY_TO_PRIORITY = {
    "critical": "p1",
    "high": "p2",
    "medium": "p3",
    "low": "p4",
    "info": "p4",
}

_PRIORITY_ORDER = {"p1": 1, "p2": 2, "p3": 3, "p4": 4}


class AlertTriageEngine:
    """SQLite WAL-backed Alert Triage engine.

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
                CREATE TABLE IF NOT EXISTS at_alerts (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    title             TEXT NOT NULL DEFAULT '',
                    source_system     TEXT NOT NULL DEFAULT 'siem',
                    severity          TEXT NOT NULL DEFAULT 'medium',
                    priority          TEXT NOT NULL DEFAULT 'p3',
                    raw_alert_json    TEXT NOT NULL DEFAULT '{}',
                    status            TEXT NOT NULL DEFAULT 'new',
                    assigned_to       TEXT NOT NULL DEFAULT '',
                    triage_notes      TEXT NOT NULL DEFAULT '',
                    escalation_reason TEXT NOT NULL DEFAULT '',
                    ingested_at       DATETIME,
                    triaged_at        DATETIME,
                    resolved_at       DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_at_org_status
                    ON at_alerts (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_at_org_priority
                    ON at_alerts (org_id, priority, ingested_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest_alert(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a new alert with auto-priority assignment."""
        source_system = data.get("source_system", "siem")
        if source_system not in _VALID_SOURCE_SYSTEMS:
            raise ValueError(
                f"Invalid source_system '{source_system}'. "
                f"Valid: {sorted(_VALID_SOURCE_SYSTEMS)}"
            )
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. Valid: {sorted(_VALID_SEVERITIES)}"
            )

        priority = _SEVERITY_TO_PRIORITY[severity]
        raw = data.get("raw_alert_json", data.get("raw_alert", {}))
        if isinstance(raw, dict):
            raw = json.dumps(raw)

        alert_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO at_alerts
                        (id, org_id, title, source_system, severity, priority,
                         raw_alert_json, status, assigned_to, triage_notes,
                         escalation_reason, ingested_at, triaged_at, resolved_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        alert_id,
                        org_id,
                        data.get("title", ""),
                        source_system,
                        severity,
                        priority,
                        raw,
                        "new",
                        "",
                        "",
                        "",
                        now,
                        None,
                        None,
                    ),
                )

        return self.get_alert(org_id, alert_id)  # type: ignore[return-value]

    def list_alerts(
        self,
        org_id: str,
        source_system: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List alerts with optional filters, newest first."""
        query = "SELECT * FROM at_alerts WHERE org_id = ?"
        params: List[Any] = [org_id]

        if source_system:
            query += " AND source_system = ?"
            params.append(source_system)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if priority:
            query += " AND priority = ?"
            params.append(priority)

        query += " ORDER BY ingested_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_alert(self, org_id: str, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single alert by ID (org-scoped)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM at_alerts WHERE id = ? AND org_id = ?",
                (alert_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def triage_alert(
        self, org_id: str, alert_id: str, triage_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update alert triage status and metadata."""
        triage_status = triage_data.get("triage_status") or triage_data.get("status")
        if triage_status not in _VALID_TRIAGE_STATUSES:
            raise ValueError(
                f"Invalid triage_status '{triage_status}'. "
                f"Valid: {sorted(_VALID_TRIAGE_STATUSES)}"
            )

        alert = self.get_alert(org_id, alert_id)
        if alert is None:
            raise KeyError(f"Alert '{alert_id}' not found for org '{org_id}'")

        now = self._now()
        assigned_to = triage_data.get("assigned_to", alert["assigned_to"])
        triage_notes = triage_data.get("triage_notes", alert["triage_notes"])
        escalation_reason = alert["escalation_reason"]
        triaged_at = now
        resolved_at = alert["resolved_at"]

        if triage_status == "escalated":
            escalation_reason = triage_data.get("escalation_reason", escalation_reason)
        if triage_status == "resolved":
            resolved_at = now

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE at_alerts
                    SET status = ?, assigned_to = ?, triage_notes = ?,
                        escalation_reason = ?, triaged_at = ?, resolved_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (
                        triage_status,
                        assigned_to,
                        triage_notes,
                        escalation_reason,
                        triaged_at,
                        resolved_at,
                        alert_id,
                        org_id,
                    ),
                )

        return self.get_alert(org_id, alert_id)  # type: ignore[return-value]

    def bulk_triage(
        self, org_id: str, alert_ids: List[str], action: str
    ) -> Dict[str, Any]:
        """Apply the same triage action to multiple alerts.

        action: "resolve" | "false_positive" | "escalate"
        Returns count of updated alerts.
        """
        _valid_actions = {"resolve", "false_positive", "escalate"}
        if action not in _valid_actions:
            raise ValueError(
                f"Invalid action '{action}'. Valid: {sorted(_valid_actions)}"
            )

        status_map = {
            "resolve": "resolved",
            "false_positive": "false_positive",
            "escalate": "escalated",
        }
        new_status = status_map[action]
        now = self._now()

        updated = 0
        with self._lock:
            with self._conn() as conn:
                for alert_id in alert_ids:
                    extra: tuple
                    if new_status == "resolved":
                        extra = (now,)
                        sql = (
                            "UPDATE at_alerts SET status = ?, triaged_at = ?, resolved_at = ? "
                            "WHERE id = ? AND org_id = ?"
                        )
                        params_t = (new_status, now) + extra + (alert_id, org_id)
                    else:
                        sql = (
                            "UPDATE at_alerts SET status = ?, triaged_at = ? "
                            "WHERE id = ? AND org_id = ?"
                        )
                        params_t = (new_status, now, alert_id, org_id)

                    cur = conn.execute(sql, params_t)
                    updated += cur.rowcount

        return {"updated": updated, "action": action, "alert_ids": alert_ids}

    def get_triage_queue(self, org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return new + triaging alerts ordered by priority (p1 first) then ingested_at."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM at_alerts
                WHERE org_id = ? AND status IN ('new', 'triaging')
                ORDER BY
                    CASE priority
                        WHEN 'p1' THEN 1
                        WHEN 'p2' THEN 2
                        WHEN 'p3' THEN 3
                        WHEN 'p4' THEN 4
                        ELSE 5
                    END,
                    ingested_at ASC
                LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_triage_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate triage statistics for the org."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM at_alerts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            new_alerts = conn.execute(
                "SELECT COUNT(*) FROM at_alerts WHERE org_id = ? AND status = 'new'",
                (org_id,),
            ).fetchone()[0]

            escalated = conn.execute(
                "SELECT COUNT(*) FROM at_alerts WHERE org_id = ? AND status = 'escalated'",
                (org_id,),
            ).fetchone()[0]

            fp_count = conn.execute(
                "SELECT COUNT(*) FROM at_alerts WHERE org_id = ? AND status = 'false_positive'",
                (org_id,),
            ).fetchone()[0]

            false_positive_rate = (fp_count / total * 100.0) if total else 0.0

            # avg triage time: minutes from ingested_at to triaged_at
            triage_rows = conn.execute(
                """
                SELECT ingested_at, triaged_at FROM at_alerts
                WHERE org_id = ? AND triaged_at IS NOT NULL AND ingested_at IS NOT NULL
                """,
                (org_id,),
            ).fetchall()

            avg_triage_time_minutes = 0.0
            if triage_rows:
                total_minutes = 0.0
                valid = 0
                for r in triage_rows:
                    try:
                        ingested = datetime.fromisoformat(r["ingested_at"])
                        triaged = datetime.fromisoformat(r["triaged_at"])
                        diff = (triaged - ingested).total_seconds() / 60.0
                        total_minutes += diff
                        valid += 1
                    except Exception:
                        pass
                avg_triage_time_minutes = total_minutes / valid if valid else 0.0

            # by source_system
            src_rows = conn.execute(
                """
                SELECT source_system, COUNT(*) as cnt
                FROM at_alerts WHERE org_id = ?
                GROUP BY source_system
                """,
                (org_id,),
            ).fetchall()
            by_source_system = {r["source_system"]: r["cnt"] for r in src_rows}

            # by severity
            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) as cnt
                FROM at_alerts WHERE org_id = ?
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

        return {
            "total_alerts": total,
            "new_alerts": new_alerts,
            "escalated_alerts": escalated,
            "false_positive_rate": round(false_positive_rate, 2),
            "avg_triage_time_minutes": round(avg_triage_time_minutes, 2),
            "by_source_system": by_source_system,
            "by_severity": by_severity,
        }
