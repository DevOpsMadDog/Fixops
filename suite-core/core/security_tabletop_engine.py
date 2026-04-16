"""Security Tabletop Engine — ALDECI.

Manages security tabletop exercises, participants, and findings.

Capabilities:
  - Exercise registry with scenario types and lifecycle tracking
  - Participant management with attendance and performance scoring
  - Finding tracking with severity and remediation status
  - Stats: totals, completed, open findings, avg score, by scenario/status

Compliance: NIST SP 800-84, CISA Tabletop Exercise Packages (CTEPs)
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

_VALID_SCENARIO_TYPES = {
    "ransomware",
    "data_breach",
    "supply_chain",
    "insider_threat",
    "nation_state",
    "ddos",
    "phishing",
    "physical",
}
_VALID_EXERCISE_STATUSES = {"planned", "in_progress", "completed", "cancelled"}
_VALID_FINDING_TYPES = {"gap", "strength", "improvement", "critical_failure"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_FINDING_STATUSES = {"open", "in_review", "remediated"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityTabletopEngine:
    """SQLite WAL-backed Security Tabletop engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_tabletop.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "security_tabletop.db")
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
                CREATE TABLE IF NOT EXISTS tabletop_exercises (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    title             TEXT NOT NULL,
                    scenario_type     TEXT NOT NULL,
                    status            TEXT NOT NULL DEFAULT 'planned',
                    scheduled_at      TEXT,
                    completed_at      TEXT,
                    facilitator       TEXT NOT NULL DEFAULT '',
                    participant_count INTEGER NOT NULL DEFAULT 0,
                    overall_score     REAL NOT NULL DEFAULT 0.0,
                    findings_count    INTEGER NOT NULL DEFAULT 0,
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tabletop_exercises_org
                    ON tabletop_exercises (org_id, status, scenario_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS tabletop_participants (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    exercise_id       TEXT NOT NULL,
                    name              TEXT NOT NULL,
                    role              TEXT NOT NULL DEFAULT '',
                    department        TEXT NOT NULL DEFAULT '',
                    attended          INTEGER NOT NULL DEFAULT 1,
                    performance_score REAL NOT NULL DEFAULT 0.0,
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tabletop_participants_org
                    ON tabletop_participants (org_id, exercise_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS tabletop_findings (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    exercise_id  TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    title        TEXT NOT NULL,
                    description  TEXT NOT NULL DEFAULT '',
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    status       TEXT NOT NULL DEFAULT 'open',
                    assigned_to  TEXT NOT NULL DEFAULT '',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tabletop_findings_org
                    ON tabletop_findings (org_id, exercise_id, severity, status, created_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Exercises
    # ------------------------------------------------------------------

    def create_exercise(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new tabletop exercise."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        scenario_type = data.get("scenario_type", "ransomware")
        if scenario_type not in _VALID_SCENARIO_TYPES:
            raise ValueError(
                f"Invalid scenario_type: {scenario_type}. "
                f"Must be one of {sorted(_VALID_SCENARIO_TYPES)}"
            )

        status = data.get("status", "planned")
        if status not in _VALID_EXERCISE_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. "
                f"Must be one of {sorted(_VALID_EXERCISE_STATUSES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": title,
            "scenario_type": scenario_type,
            "status": status,
            "scheduled_at": data.get("scheduled_at"),
            "completed_at": None,
            "facilitator": data.get("facilitator", ""),
            "participant_count": int(data.get("participant_count", 0)),
            "overall_score": 0.0,
            "findings_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tabletop_exercises
                       (id, org_id, title, scenario_type, status, scheduled_at, completed_at,
                        facilitator, participant_count, overall_score, findings_count, created_at)
                       VALUES (:id, :org_id, :title, :scenario_type, :status, :scheduled_at, :completed_at,
                               :facilitator, :participant_count, :overall_score, :findings_count, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_tabletop", "org_id": org_id, "source_engine": "security_tabletop"})
            except Exception:
                pass

        return record

    def list_exercises(
        self,
        org_id: str,
        status: Optional[str] = None,
        scenario_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List exercises with optional filters."""
        sql = "SELECT * FROM tabletop_exercises WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if scenario_type:
            sql += " AND scenario_type = ?"
            params.append(scenario_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_exercise(self, org_id: str, exercise_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single exercise by ID with org isolation."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM tabletop_exercises WHERE org_id = ? AND id = ?",
                (org_id, exercise_id),
            ).fetchone()
        return dict(row) if row else None

    def complete_exercise(
        self, org_id: str, exercise_id: str, overall_score: float
    ) -> Dict[str, Any]:
        """Mark an exercise as completed with a score (clamped 0-100)."""
        clamped_score = max(0.0, min(100.0, float(overall_score)))
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE tabletop_exercises SET status = 'completed', overall_score = ?, completed_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (clamped_score, now, org_id, exercise_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Exercise {exercise_id} not found in org {org_id}")
                row = conn.execute(
                    "SELECT * FROM tabletop_exercises WHERE org_id = ? AND id = ?",
                    (org_id, exercise_id),
                ).fetchone()
        return dict(row)

    # ------------------------------------------------------------------
    # Participants
    # ------------------------------------------------------------------

    def add_participant(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a participant to an exercise."""
        exercise_id = (data.get("exercise_id") or "").strip()
        if not exercise_id:
            raise ValueError("exercise_id is required.")

        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        performance_score = max(0.0, min(100.0, float(data.get("performance_score", 0.0))))
        attended = bool(data.get("attended", True))

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "exercise_id": exercise_id,
            "name": name,
            "role": data.get("role", ""),
            "department": data.get("department", ""),
            "attended": 1 if attended else 0,
            "performance_score": performance_score,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tabletop_participants
                       (id, org_id, exercise_id, name, role, department, attended, performance_score, created_at)
                       VALUES (:id, :org_id, :exercise_id, :name, :role, :department, :attended, :performance_score, :created_at)""",
                    record,
                )
        record["attended"] = attended
        return record

    def list_participants(self, org_id: str, exercise_id: str) -> List[Dict[str, Any]]:
        """List participants for a specific exercise."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM tabletop_participants WHERE org_id = ? AND exercise_id = ? ORDER BY created_at DESC",
                (org_id, exercise_id),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def record_finding(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a finding from a tabletop exercise."""
        exercise_id = (data.get("exercise_id") or "").strip()
        if not exercise_id:
            raise ValueError("exercise_id is required.")

        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        finding_type = data.get("finding_type", "gap")
        if finding_type not in _VALID_FINDING_TYPES:
            raise ValueError(
                f"Invalid finding_type: {finding_type}. "
                f"Must be one of {sorted(_VALID_FINDING_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        status = data.get("status", "open")
        if status not in _VALID_FINDING_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. "
                f"Must be one of {sorted(_VALID_FINDING_STATUSES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "exercise_id": exercise_id,
            "finding_type": finding_type,
            "title": title,
            "description": data.get("description", ""),
            "severity": severity,
            "status": status,
            "assigned_to": data.get("assigned_to", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tabletop_findings
                       (id, org_id, exercise_id, finding_type, title, description,
                        severity, status, assigned_to, created_at)
                       VALUES (:id, :org_id, :exercise_id, :finding_type, :title, :description,
                               :severity, :status, :assigned_to, :created_at)""",
                    record,
                )
        return record

    def list_findings(
        self,
        org_id: str,
        exercise_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        sql = "SELECT * FROM tabletop_findings WHERE org_id = ?"
        params: list = [org_id]
        if exercise_id:
            sql += " AND exercise_id = ?"
            params.append(exercise_id)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_tabletop_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated tabletop exercise statistics."""
        with self._conn() as conn:
            total_exercises = conn.execute(
                "SELECT COUNT(*) FROM tabletop_exercises WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            completed_exercises = conn.execute(
                "SELECT COUNT(*) FROM tabletop_exercises WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()[0]

            avg_score_row = conn.execute(
                "SELECT AVG(overall_score) FROM tabletop_exercises WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()[0]
            avg_score = round(float(avg_score_row), 2) if avg_score_row is not None else 0.0

            total_findings = conn.execute(
                "SELECT COUNT(*) FROM tabletop_findings WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            open_findings = conn.execute(
                "SELECT COUNT(*) FROM tabletop_findings WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            critical_findings = conn.execute(
                "SELECT COUNT(*) FROM tabletop_findings WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            by_scenario_rows = conn.execute(
                "SELECT scenario_type, COUNT(*) as cnt FROM tabletop_exercises WHERE org_id = ? GROUP BY scenario_type",
                (org_id,),
            ).fetchall()

            by_status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM tabletop_exercises WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()

        return {
            "total_exercises": total_exercises,
            "completed_exercises": completed_exercises,
            "avg_score": avg_score,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "by_scenario": {r["scenario_type"]: r["cnt"] for r in by_scenario_rows},
            "by_status": {r["status"]: r["cnt"] for r in by_status_rows},
        }
