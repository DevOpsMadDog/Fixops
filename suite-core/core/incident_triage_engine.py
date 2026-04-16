"""Incident Triage Engine — ALDECI.

Structured triage workflow for incoming security incidents.

Capabilities:
  - Submit incidents for triage from multiple sources
  - Score-based triage (confirmed flag + severity points)
  - Classification: true_positive, false_positive, benign, escalated
  - Escalation and resolution lifecycle
  - Stats: counts by status/severity/classification, false positive rate

Compliance: NIST SP 800-61 Rev 2, SANS Incident Response Process
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_SOURCES = {"siem", "edr", "user_report", "threat_feed", "manual"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_STATUSES = {"pending", "triaged", "escalated", "resolved"}
_VALID_CLASSIFICATIONS = {"true_positive", "false_positive", "benign", "escalated"}

_SEVERITY_SCORE = {"critical": 40, "high": 30, "medium": 20, "low": 10}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class IncidentTriageEngine:
    """SQLite WAL-backed Incident Triage engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/incident_triage.db (shared, org-scoped by column)
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "incident_triage.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    title             TEXT NOT NULL,
                    source            TEXT NOT NULL,
                    severity          TEXT NOT NULL DEFAULT 'medium',
                    raw_data          TEXT NOT NULL DEFAULT '{}',
                    status            TEXT NOT NULL DEFAULT 'pending',
                    triage_score      INTEGER NOT NULL DEFAULT 0,
                    classification    TEXT NOT NULL DEFAULT '',
                    assignee          TEXT NOT NULL DEFAULT '',
                    notes             TEXT NOT NULL DEFAULT '',
                    escalated_to      TEXT NOT NULL DEFAULT '',
                    escalation_reason TEXT NOT NULL DEFAULT '',
                    submitted_at      TEXT NOT NULL,
                    triaged_at        TEXT,
                    escalated_at      TEXT,
                    resolved_at       TEXT,
                    resolution        TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_triage_org
                    ON incidents (org_id, status, submitted_at DESC);

                CREATE INDEX IF NOT EXISTS idx_triage_severity
                    ON incidents (org_id, severity);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        r = dict(row)
        try:
            r["raw_data"] = json.loads(r["raw_data"])
        except Exception:
            r["raw_data"] = {}
        return r

    # ------------------------------------------------------------------
    # Submit
    # ------------------------------------------------------------------

    def submit_for_triage(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a new incident for triage."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        source = data.get("source", "")
        if source not in _VALID_SOURCES:
            raise ValueError(
                f"Invalid source: {source}. Must be one of {_VALID_SOURCES}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. Must be one of {_VALID_SEVERITIES}"
            )

        raw_data = data.get("raw_data", {})
        if not isinstance(raw_data, dict):
            raw_data = {}

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": title,
            "source": source,
            "severity": severity,
            "raw_data": json.dumps(raw_data),
            "status": "pending",
            "triage_score": 0,
            "classification": "",
            "assignee": "",
            "notes": "",
            "escalated_to": "",
            "escalation_reason": "",
            "submitted_at": now,
            "triaged_at": None,
            "escalated_at": None,
            "resolved_at": None,
            "resolution": "",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO incidents
                       (id, org_id, title, source, severity, raw_data, status,
                        triage_score, classification, assignee, notes,
                        escalated_to, escalation_reason,
                        submitted_at, triaged_at, escalated_at, resolved_at, resolution)
                       VALUES (:id, :org_id, :title, :source, :severity, :raw_data, :status,
                               :triage_score, :classification, :assignee, :notes,
                               :escalated_to, :escalation_reason,
                               :submitted_at, :triaged_at, :escalated_at, :resolved_at,
                               :resolution)""",
                    record,
                )
        result = dict(record)
        result["raw_data"] = raw_data
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("INCIDENT_CREATED", {"entity_type": "incident_triage", "org_id": org_id, "source_engine": "incident_triage"})
            except Exception:
                pass

        return result

    # ------------------------------------------------------------------
    # Triage
    # ------------------------------------------------------------------

    def triage_incident(
        self, org_id: str, incident_id: str, triage_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Triage an incident: score, classify, assign.

        triage_data keys:
          confirmed (bool): +40 to score if True
          severity_override (optional str): overrides severity
          assignee (optional str)
          classification (str): true_positive/false_positive/benign/escalated
          notes (optional str)

        Returns None if incident not found.
        """
        classification = triage_data.get("classification", "")
        if classification not in _VALID_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid classification: {classification}. "
                f"Must be one of {_VALID_CLASSIFICATIONS}"
            )

        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM incidents WHERE org_id = ? AND id = ?",
                    (org_id, incident_id),
                ).fetchone()
                if not row:
                    return None

                r = self._row(row)
                severity = triage_data.get("severity_override") or r["severity"]
                if severity not in _VALID_SEVERITIES:
                    severity = r["severity"]

                confirmed = bool(triage_data.get("confirmed", False))
                score = (40 if confirmed else 0) + _SEVERITY_SCORE.get(severity, 0)

                conn.execute(
                    """UPDATE incidents
                       SET status = 'triaged', triage_score = ?, classification = ?,
                           severity = ?, assignee = ?, notes = ?, triaged_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (
                        score,
                        classification,
                        severity,
                        triage_data.get("assignee", r.get("assignee", "")),
                        triage_data.get("notes", r.get("notes", "")),
                        now,
                        org_id,
                        incident_id,
                    ),
                )
                updated = conn.execute(
                    "SELECT * FROM incidents WHERE org_id = ? AND id = ?",
                    (org_id, incident_id),
                ).fetchone()

        return self._row(updated) if updated else None

    # ------------------------------------------------------------------
    # List / Get
    # ------------------------------------------------------------------

    def list_incidents(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List incidents with optional filters."""
        sql = "SELECT * FROM incidents WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if classification:
            sql += " AND classification = ?"
            params.append(classification)
        sql += " ORDER BY submitted_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_incident(self, org_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single incident by ID. Returns None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE org_id = ? AND id = ?",
                (org_id, incident_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Escalate / Resolve
    # ------------------------------------------------------------------

    def escalate_incident(
        self,
        org_id: str,
        incident_id: str,
        escalated_to: str,
        reason: str,
    ) -> Optional[Dict[str, Any]]:
        """Escalate an incident. Returns None if not found."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                affected = conn.execute(
                    """UPDATE incidents
                       SET status = 'escalated', escalated_to = ?,
                           escalation_reason = ?, escalated_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (escalated_to, reason, now, org_id, incident_id),
                ).rowcount
                if not affected:
                    return None
                row = conn.execute(
                    "SELECT * FROM incidents WHERE org_id = ? AND id = ?",
                    (org_id, incident_id),
                ).fetchone()
        return self._row(row) if row else None

    def resolve_triage(
        self, org_id: str, incident_id: str, resolution: str
    ) -> Optional[Dict[str, Any]]:
        """Resolve a triaged incident. Returns None if not found."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                affected = conn.execute(
                    """UPDATE incidents
                       SET status = 'resolved', resolved_at = ?, resolution = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, resolution, org_id, incident_id),
                ).rowcount
                if not affected:
                    return None
                row = conn.execute(
                    "SELECT * FROM incidents WHERE org_id = ? AND id = ?",
                    (org_id, incident_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_triage_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated triage stats for an org."""
        with self._conn() as conn:
            total_incidents = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM incidents "
                "WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

            severity_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM incidents "
                "WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in severity_rows}

            cls_rows = conn.execute(
                "SELECT classification, COUNT(*) as cnt FROM incidents "
                "WHERE org_id = ? AND classification != '' GROUP BY classification",
                (org_id,),
            ).fetchall()
            by_classification = {r["classification"]: r["cnt"] for r in cls_rows}

            pending_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE org_id = ? AND status = 'pending'",
                (org_id,),
            ).fetchone()[0]

            # avg_triage_score for triaged + escalated + resolved
            score_rows = conn.execute(
                "SELECT triage_score FROM incidents "
                "WHERE org_id = ? AND status IN ('triaged', 'escalated', 'resolved')",
                (org_id,),
            ).fetchall()
            if score_rows:
                avg_triage_score = round(
                    sum(r["triage_score"] for r in score_rows) / len(score_rows), 2
                )
            else:
                avg_triage_score = 0.0

            # false_positive_rate = fp / total_triaged * 100
            total_triaged = conn.execute(
                "SELECT COUNT(*) FROM incidents "
                "WHERE org_id = ? AND status IN ('triaged', 'escalated', 'resolved')",
                (org_id,),
            ).fetchone()[0]

            fp_count = conn.execute(
                "SELECT COUNT(*) FROM incidents "
                "WHERE org_id = ? AND classification = 'false_positive'",
                (org_id,),
            ).fetchone()[0]

        false_positive_rate = (
            round(fp_count / total_triaged * 100, 2) if total_triaged else 0.0
        )

        return {
            "total_incidents": total_incidents,
            "by_status": by_status,
            "by_severity": by_severity,
            "by_classification": by_classification,
            "pending_count": pending_count,
            "avg_triage_score": avg_triage_score,
            "false_positive_rate": false_positive_rate,
        }
