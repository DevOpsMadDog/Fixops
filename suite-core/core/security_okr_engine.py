"""Security OKR Engine — ALDECI.

Tracks Objectives and Key Results (OKRs) for security programs.

Capabilities:
  - Objective lifecycle: draft → active → completed/cancelled
  - Key result progress tracking with atomic recomputation
  - OKR update history with previous/new value recording
  - Period summary: on-track / at-risk / off-track counts
  - Team OKR view filtered by owner
  - Velocity: per-objective update history showing progress over time

Compliance: NIST CSF GV.OC, ISO 27001 A.5.1 (Policies for information security)
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_PERIODS = {
    "Q1-2026", "Q2-2026", "Q3-2026", "Q4-2026",
    "H1-2026", "H2-2026", "FY-2026",
}

_VALID_STATUSES = {
    "draft", "active", "on-track", "at-risk", "off-track", "completed", "cancelled"
}

_VALID_UNITS = {
    "percentage", "count", "days", "hours", "score", "incidents", "vulnerabilities"
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp_progress(v: float) -> float:
    return max(0.0, min(100.0, float(v)))


class SecurityOKREngine:
    """SQLite WAL-backed Security OKR engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_okr.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "security_okr.db")
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
                CREATE TABLE IF NOT EXISTS objectives (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    title       TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    owner       TEXT NOT NULL,
                    period      TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'draft',
                    progress    REAL NOT NULL DEFAULT 0.0,
                    created_at  TEXT NOT NULL,
                    due_date    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_obj_org
                    ON objectives (org_id, period, status, owner, created_at DESC);

                CREATE TABLE IF NOT EXISTS key_results (
                    id              TEXT PRIMARY KEY,
                    objective_id    TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    title           TEXT NOT NULL,
                    target_value    REAL NOT NULL DEFAULT 1.0,
                    current_value   REAL NOT NULL DEFAULT 0.0,
                    unit            TEXT NOT NULL DEFAULT 'count',
                    progress        REAL NOT NULL DEFAULT 0.0,
                    status          TEXT NOT NULL DEFAULT 'active',
                    updated_at      TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_kr_obj
                    ON key_results (objective_id, org_id, status);

                CREATE TABLE IF NOT EXISTS okr_updates (
                    id              TEXT PRIMARY KEY,
                    key_result_id   TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    previous_value  REAL NOT NULL DEFAULT 0.0,
                    new_value       REAL NOT NULL DEFAULT 0.0,
                    notes           TEXT NOT NULL DEFAULT '',
                    updated_by      TEXT NOT NULL DEFAULT '',
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_upd_kr
                    ON okr_updates (key_result_id, org_id, updated_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Objectives
    # ------------------------------------------------------------------

    def create_objective(
        self,
        org_id: str,
        title: str,
        description: str = "",
        owner: str = "",
        period: str = "Q1-2026",
        due_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new objective with status=draft."""
        title = (title or "").strip()
        if not title:
            raise ValueError("title is required.")
        if period not in _VALID_PERIODS:
            raise ValueError(
                f"Invalid period: {period!r}. "
                f"Must be one of {sorted(_VALID_PERIODS)}"
            )
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": title,
            "description": description or "",
            "owner": owner or "",
            "period": period,
            "status": "draft",
            "progress": 0.0,
            "created_at": now,
            "due_date": due_date,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO objectives
                       (id, org_id, title, description, owner, period,
                        status, progress, created_at, due_date)
                       VALUES (:id, :org_id, :title, :description, :owner, :period,
                               :status, :progress, :created_at, :due_date)""",
                    record,
                )
        return record

    def list_objectives(
        self,
        org_id: str,
        period: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List objectives with optional filters."""
        sql = "SELECT * FROM objectives WHERE org_id = ?"
        params: list = [org_id]
        if period is not None:
            sql += " AND period = ?"
            params.append(period)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_objective(self, objective_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return objective with nested key_results list."""
        with self._conn() as conn:
            obj_row = conn.execute(
                "SELECT * FROM objectives WHERE id = ? AND org_id = ?",
                (objective_id, org_id),
            ).fetchone()
            if not obj_row:
                return None
            result = self._row(obj_row)
            kr_rows = conn.execute(
                "SELECT * FROM key_results WHERE objective_id = ? AND org_id = ? "
                "ORDER BY created_at ASC",
                (objective_id, org_id),
            ).fetchall()
        result["key_results"] = [self._row(r) for r in kr_rows]
        return result

    def close_objective(
        self, objective_id: str, org_id: str, final_status: str
    ) -> Dict[str, Any]:
        """Set objective status to final_status (progress stays as-is)."""
        if final_status not in _VALID_STATUSES:
            raise ValueError(
                f"Invalid final_status: {final_status!r}. "
                f"Must be one of {sorted(_VALID_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE objectives SET status = ? WHERE id = ? AND org_id = ?",
                    (final_status, objective_id, org_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Objective not found: {objective_id}")
                row = conn.execute(
                    "SELECT * FROM objectives WHERE id = ? AND org_id = ?",
                    (objective_id, org_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Key Results
    # ------------------------------------------------------------------

    def add_key_result(
        self,
        objective_id: str,
        org_id: str,
        title: str,
        target_value: float,
        unit: str = "count",
    ) -> Dict[str, Any]:
        """Add a key result to an objective. current_value=0, progress=0."""
        title = (title or "").strip()
        if not title:
            raise ValueError("title is required.")
        if unit not in _VALID_UNITS:
            raise ValueError(
                f"Invalid unit: {unit!r}. "
                f"Must be one of {sorted(_VALID_UNITS)}"
            )
        target_value = float(target_value)
        if target_value <= 0:
            raise ValueError("target_value must be > 0.")
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "objective_id": objective_id,
            "org_id": org_id,
            "title": title,
            "target_value": target_value,
            "current_value": 0.0,
            "unit": unit,
            "progress": 0.0,
            "status": "active",
            "updated_at": now,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO key_results
                       (id, objective_id, org_id, title, target_value, current_value,
                        unit, progress, status, updated_at, created_at)
                       VALUES (:id, :objective_id, :org_id, :title, :target_value,
                               :current_value, :unit, :progress, :status,
                               :updated_at, :created_at)""",
                    record,
                )
        return record

    def update_key_result(
        self,
        key_result_id: str,
        objective_id: str,
        org_id: str,
        new_value: float,
        notes: str = "",
        updated_by: str = "",
    ) -> Dict[str, Any]:
        """Update key result value; recompute progress and parent objective progress."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                kr_row = conn.execute(
                    "SELECT * FROM key_results WHERE id = ? AND objective_id = ? AND org_id = ?",
                    (key_result_id, objective_id, org_id),
                ).fetchone()
                if not kr_row:
                    raise KeyError(f"Key result not found: {key_result_id}")

                previous_value = kr_row["current_value"]
                target_value = kr_row["target_value"]
                new_progress = _clamp_progress((new_value / target_value) * 100.0) if target_value > 0 else 0.0

                # Record the update
                update_record = {
                    "id": str(uuid.uuid4()),
                    "key_result_id": key_result_id,
                    "org_id": org_id,
                    "previous_value": previous_value,
                    "new_value": float(new_value),
                    "notes": notes or "",
                    "updated_by": updated_by or "",
                    "updated_at": now,
                }
                conn.execute(
                    """INSERT INTO okr_updates
                       (id, key_result_id, org_id, previous_value, new_value,
                        notes, updated_by, updated_at)
                       VALUES (:id, :key_result_id, :org_id, :previous_value, :new_value,
                               :notes, :updated_by, :updated_at)""",
                    update_record,
                )

                # Update the key result
                conn.execute(
                    """UPDATE key_results
                       SET current_value = ?, progress = ?, updated_at = ?
                       WHERE id = ? AND org_id = ?""",
                    (float(new_value), new_progress, now, key_result_id, org_id),
                )

                # Recompute objective progress = avg of all key result progress values
                avg_row = conn.execute(
                    "SELECT AVG(progress) AS avg_p FROM key_results "
                    "WHERE objective_id = ? AND org_id = ?",
                    (objective_id, org_id),
                ).fetchone()
                obj_progress = _clamp_progress(avg_row["avg_p"] or 0.0)
                conn.execute(
                    "UPDATE objectives SET progress = ? WHERE id = ? AND org_id = ?",
                    (obj_progress, objective_id, org_id),
                )

                updated_kr = conn.execute(
                    "SELECT * FROM key_results WHERE id = ? AND org_id = ?",
                    (key_result_id, org_id),
                ).fetchone()
        return self._row(updated_kr)

    # ------------------------------------------------------------------
    # Summaries & Queries
    # ------------------------------------------------------------------

    def get_period_summary(self, org_id: str, period: str) -> Dict[str, Any]:
        """Summary for a period: avg_progress, on_track / at_risk / off_track counts."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT progress FROM objectives WHERE org_id = ? AND period = ?",
                (org_id, period),
            ).fetchall()

        if not rows:
            return {
                "org_id": org_id,
                "period": period,
                "total_objectives": 0,
                "avg_progress": 0.0,
                "on_track_count": 0,
                "at_risk_count": 0,
                "off_track_count": 0,
            }

        progresses = [r["progress"] for r in rows]
        on_track = sum(1 for p in progresses if p >= 70)
        at_risk = sum(1 for p in progresses if 30 <= p < 70)
        off_track = sum(1 for p in progresses if p < 30)
        avg_p = sum(progresses) / len(progresses)

        return {
            "org_id": org_id,
            "period": period,
            "total_objectives": len(progresses),
            "avg_progress": round(avg_p, 2),
            "on_track_count": on_track,
            "at_risk_count": at_risk,
            "off_track_count": off_track,
        }

    def get_team_okrs(self, org_id: str, owner: str) -> List[Dict[str, Any]]:
        """Return objectives filtered by owner."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM objectives WHERE org_id = ? AND owner = ? "
                "ORDER BY created_at DESC",
                (org_id, owner),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_okr_velocity(self, org_id: str) -> List[Dict[str, Any]]:
        """Per-objective list of updates showing progress over time."""
        with self._conn() as conn:
            obj_rows = conn.execute(
                "SELECT id, title FROM objectives WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()

            velocity = []
            for obj_row in obj_rows:
                obj_id = obj_row["id"]
                kr_rows = conn.execute(
                    "SELECT id FROM key_results WHERE objective_id = ? AND org_id = ?",
                    (obj_id, org_id),
                ).fetchall()
                kr_ids = [r["id"] for r in kr_rows]

                updates = []
                if kr_ids:
                    placeholders = ",".join("?" * len(kr_ids))
                    upd_rows = conn.execute(
                        f"SELECT * FROM okr_updates WHERE org_id = ? "  # nosec B608
                        f"AND key_result_id IN ({placeholders}) "
                        f"ORDER BY updated_at ASC",
                        [org_id] + kr_ids,
                    ).fetchall()
                    updates = [self._row(r) for r in upd_rows]

                velocity.append({
                    "objective_id": obj_id,
                    "objective_title": obj_row["title"],
                    "updates": updates,
                })

        return velocity
