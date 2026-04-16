"""Risk Treatment Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Manages risk treatment plans with full lifecycle tracking:
  - Treatment creation with type/status/risk_level validation
  - Progress notes with author tracking
  - Status transitions with completed_at timestamps
  - Aggregated stats including overdue and on-time completion counts

Compliance: ISO 31000, NIST RMF, SOC2 CC3.2
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "risk_treatment_engine.db"
)

_VALID_TREATMENT_TYPES = {"mitigate", "accept", "transfer", "avoid"}
_VALID_TREATMENT_STATUSES = {"planned", "in_progress", "completed", "cancelled", "deferred"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RiskTreatmentEngine:
    """SQLite WAL-backed Risk Treatment engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/risk_treatment_engine.db
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
                CREATE TABLE IF NOT EXISTS risk_treatments (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    risk_id             TEXT NOT NULL DEFAULT '',
                    title               TEXT NOT NULL DEFAULT '',
                    description         TEXT NOT NULL DEFAULT '',
                    treatment_type      TEXT NOT NULL DEFAULT 'mitigate',
                    treatment_status    TEXT NOT NULL DEFAULT 'planned',
                    risk_level          TEXT NOT NULL DEFAULT 'medium',
                    owner               TEXT NOT NULL DEFAULT '',
                    due_date            TEXT NOT NULL DEFAULT '',
                    cost_estimate       REAL NOT NULL DEFAULT 0.0,
                    actual_cost         REAL NOT NULL DEFAULT 0.0,
                    residual_risk_level TEXT NOT NULL DEFAULT '',
                    progress_pct        INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL,
                    completed_at        TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_rt_treatments_org
                    ON risk_treatments (org_id, treatment_type, treatment_status, risk_level);

                CREATE TABLE IF NOT EXISTS treatment_notes (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    treatment_id        TEXT NOT NULL,
                    note                TEXT NOT NULL DEFAULT '',
                    author              TEXT NOT NULL DEFAULT '',
                    progress_pct_at_note INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rt_notes_org
                    ON treatment_notes (org_id, treatment_id, created_at);
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
    # Treatments
    # ------------------------------------------------------------------

    def create_treatment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new risk treatment record."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        treatment_type = data.get("treatment_type", "mitigate")
        if treatment_type not in _VALID_TREATMENT_TYPES:
            raise ValueError(
                f"Invalid treatment_type '{treatment_type}'. "
                f"Must be one of {sorted(_VALID_TREATMENT_TYPES)}"
            )

        treatment_status = data.get("treatment_status", "planned")
        if treatment_status not in _VALID_TREATMENT_STATUSES:
            raise ValueError(
                f"Invalid treatment_status '{treatment_status}'. "
                f"Must be one of {sorted(_VALID_TREATMENT_STATUSES)}"
            )

        risk_level = data.get("risk_level", "medium")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{risk_level}'. "
                f"Must be one of {sorted(_VALID_RISK_LEVELS)}"
            )

        progress_pct = int(data.get("progress_pct", 0))
        progress_pct = max(0, min(100, progress_pct))

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "risk_id": data.get("risk_id", ""),
            "title": title,
            "description": data.get("description", ""),
            "treatment_type": treatment_type,
            "treatment_status": treatment_status,
            "risk_level": risk_level,
            "owner": data.get("owner", ""),
            "due_date": data.get("due_date", ""),
            "cost_estimate": float(data.get("cost_estimate", 0.0)),
            "actual_cost": float(data.get("actual_cost", 0.0)),
            "residual_risk_level": data.get("residual_risk_level", ""),
            "progress_pct": progress_pct,
            "created_at": now,
            "updated_at": now,
            "completed_at": "",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO risk_treatments
                       (id, org_id, risk_id, title, description, treatment_type,
                        treatment_status, risk_level, owner, due_date, cost_estimate,
                        actual_cost, residual_risk_level, progress_pct,
                        created_at, updated_at, completed_at)
                       VALUES (:id, :org_id, :risk_id, :title, :description,
                               :treatment_type, :treatment_status, :risk_level,
                               :owner, :due_date, :cost_estimate, :actual_cost,
                               :residual_risk_level, :progress_pct,
                               :created_at, :updated_at, :completed_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "risk_treatment", "org_id": org_id, "source_engine": "risk_treatment"})
            except Exception:
                pass

        return record

    def list_treatments(
        self,
        org_id: str,
        treatment_type: Optional[str] = None,
        treatment_status: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List treatments with optional filters."""
        sql = "SELECT * FROM risk_treatments WHERE org_id = ?"
        params: List[Any] = [org_id]
        if treatment_type:
            sql += " AND treatment_type = ?"
            params.append(treatment_type)
        if treatment_status:
            sql += " AND treatment_status = ?"
            params.append(treatment_status)
        if risk_level:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_treatment(self, org_id: str, treatment_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single treatment by ID within the org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM risk_treatments WHERE org_id = ? AND id = ?",
                (org_id, treatment_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_treatment_status(
        self,
        org_id: str,
        treatment_id: str,
        new_status: str,
        progress_pct: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Update treatment_status (and optionally progress_pct). Sets completed_at if completed."""
        if new_status not in _VALID_TREATMENT_STATUSES:
            raise ValueError(
                f"Invalid treatment_status '{new_status}'. "
                f"Must be one of {sorted(_VALID_TREATMENT_STATUSES)}"
            )

        existing = self.get_treatment(org_id, treatment_id)
        if existing is None:
            raise KeyError(f"Treatment '{treatment_id}' not found for org '{org_id}'.")

        now = _now_iso()
        completed_at = now if new_status == "completed" else existing["completed_at"]

        if progress_pct is not None:
            progress_pct = max(0, min(100, int(progress_pct)))
        else:
            progress_pct = existing["progress_pct"]

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE risk_treatments
                       SET treatment_status = ?, progress_pct = ?,
                           completed_at = ?, updated_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (new_status, progress_pct, completed_at, now, org_id, treatment_id),
                )
        return self.get_treatment(org_id, treatment_id)

    # ------------------------------------------------------------------
    # Progress Notes
    # ------------------------------------------------------------------

    def add_progress_note(
        self,
        org_id: str,
        treatment_id: str,
        note_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add a progress note to a treatment."""
        note = (note_data.get("note") or "").strip()
        if not note:
            raise ValueError("note is required.")

        author = (note_data.get("author") or "").strip()
        if not author:
            raise ValueError("author is required.")

        progress_pct = int(note_data.get("progress_pct_at_note", 0))
        progress_pct = max(0, min(100, progress_pct))

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "treatment_id": treatment_id,
            "note": note,
            "author": author,
            "progress_pct_at_note": progress_pct,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO treatment_notes
                       (id, org_id, treatment_id, note, author,
                        progress_pct_at_note, created_at)
                       VALUES (:id, :org_id, :treatment_id, :note, :author,
                               :progress_pct_at_note, :created_at)""",
                    record,
                )
        return record

    def list_progress_notes(
        self,
        org_id: str,
        treatment_id: str,
    ) -> List[Dict[str, Any]]:
        """List progress notes for a treatment, ordered by created_at DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM treatment_notes
                   WHERE org_id = ? AND treatment_id = ?
                   ORDER BY created_at DESC""",
                (org_id, treatment_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_treatment_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated treatment statistics for an org."""
        now = _now_iso()
        with self._conn() as conn:
            total_treatments = conn.execute(
                "SELECT COUNT(*) FROM risk_treatments WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            status_rows = conn.execute(
                """SELECT treatment_status, COUNT(*) as cnt
                   FROM risk_treatments WHERE org_id = ?
                   GROUP BY treatment_status""",
                (org_id,),
            ).fetchall()
            by_status = {r["treatment_status"]: r["cnt"] for r in status_rows}

            type_rows = conn.execute(
                """SELECT treatment_type, COUNT(*) as cnt
                   FROM risk_treatments WHERE org_id = ?
                   GROUP BY treatment_type""",
                (org_id,),
            ).fetchall()
            by_type = {r["treatment_type"]: r["cnt"] for r in type_rows}

            level_rows = conn.execute(
                """SELECT risk_level, COUNT(*) as cnt
                   FROM risk_treatments WHERE org_id = ?
                   GROUP BY risk_level""",
                (org_id,),
            ).fetchall()
            by_risk_level = {r["risk_level"]: r["cnt"] for r in level_rows}

            # completed where completed_at <= due_date (both non-empty)
            completed_on_time = conn.execute(
                """SELECT COUNT(*) FROM risk_treatments
                   WHERE org_id = ?
                     AND treatment_status = 'completed'
                     AND completed_at != ''
                     AND due_date != ''
                     AND completed_at <= due_date""",
                (org_id,),
            ).fetchone()[0]

            avg_row = conn.execute(
                "SELECT AVG(progress_pct) FROM risk_treatments WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            avg_progress_pct = (
                round(avg_row[0], 2) if avg_row and avg_row[0] is not None else 0.0
            )

            # overdue: planned/in_progress with non-empty due_date < now
            overdue_count = conn.execute(
                """SELECT COUNT(*) FROM risk_treatments
                   WHERE org_id = ?
                     AND treatment_status IN ('planned', 'in_progress')
                     AND due_date != ''
                     AND due_date < ?""",
                (org_id, now),
            ).fetchone()[0]

        return {
            "total_treatments": total_treatments,
            "by_status": by_status,
            "by_type": by_type,
            "by_risk_level": by_risk_level,
            "completed_on_time": completed_on_time,
            "avg_progress_pct": avg_progress_pct,
            "overdue_count": overdue_count,
        }
