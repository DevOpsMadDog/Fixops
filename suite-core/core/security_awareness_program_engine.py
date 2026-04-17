"""Security Awareness Program Engine — ALDECI.

Manages security awareness training programs, enrollments, completions,
and event tracking.

Capabilities:
  - Create and manage awareness programs with pass thresholds
  - Enroll users (dedup via INSERT OR IGNORE)
  - Record completions with score-based pass/fail and rolling pass_rate
  - Track awareness events (phishing simulations, incidents, etc.)
  - Department-level compliance reporting
  - Overdue enrollment detection (30-day window)
  - Multi-tenant org_id isolation

Compliance: NIST SP 800-50, ISO 27001 A.6.3
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
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

_VALID_PROGRAM_TYPES = {
    "phishing", "social_engineering", "data_handling", "password_security",
    "incident_reporting", "compliance", "general", "role_based",
}

_VALID_FREQUENCIES = {"one_time", "monthly", "quarterly", "annual"}

_VALID_EVENT_TYPES = {
    "phishing_simulation", "security_incident", "policy_violation",
    "near_miss", "positive_behavior",
}

_VALID_TARGET_AUDIENCES = {
    "all_staff", "developers", "managers", "executives", "it_staff", "finance",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


class SecurityAwarenessProgramEngine:
    """SQLite WAL-backed Security Awareness Program engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_awareness_program.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "security_awareness_program.db")
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
                CREATE TABLE IF NOT EXISTS awareness_programs (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    program_name    TEXT NOT NULL,
                    program_type    TEXT NOT NULL,
                    target_audience TEXT NOT NULL DEFAULT 'all_staff',
                    duration_mins   INTEGER NOT NULL DEFAULT 30,
                    frequency       TEXT NOT NULL DEFAULT 'annual',
                    passing_score   INTEGER NOT NULL DEFAULT 70,
                    enrolled_count  INTEGER NOT NULL DEFAULT 0,
                    completed_count INTEGER NOT NULL DEFAULT 0,
                    pass_rate       REAL NOT NULL DEFAULT 0.0,
                    status          TEXT NOT NULL DEFAULT 'active',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ap_org
                    ON awareness_programs (org_id, program_type);

                CREATE TABLE IF NOT EXISTS program_enrollments (
                    id           TEXT PRIMARY KEY,
                    program_id   TEXT NOT NULL,
                    org_id       TEXT NOT NULL,
                    user_id      TEXT NOT NULL,
                    user_name    TEXT NOT NULL DEFAULT '',
                    department   TEXT NOT NULL DEFAULT '',
                    enrolled_at  TEXT NOT NULL,
                    completed_at TEXT,
                    score        INTEGER NOT NULL DEFAULT 0,
                    passed       INTEGER NOT NULL DEFAULT 0,
                    attempts     INTEGER NOT NULL DEFAULT 0,
                    created_at   TEXT NOT NULL,
                    UNIQUE(program_id, org_id, user_id)
                );

                CREATE INDEX IF NOT EXISTS idx_pe_program
                    ON program_enrollments (program_id, org_id);

                CREATE INDEX IF NOT EXISTS idx_pe_org_dept
                    ON program_enrollments (org_id, department);

                CREATE TABLE IF NOT EXISTS awareness_events (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    event_type      TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    affected_users  INTEGER NOT NULL DEFAULT 0,
                    department      TEXT NOT NULL DEFAULT '',
                    event_date      TEXT NOT NULL,
                    response_action TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ae_org
                    ON awareness_events (org_id, event_type);
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
    # Programs
    # ------------------------------------------------------------------

    def create_program(
        self,
        org_id: str,
        program_name: str,
        program_type: str,
        target_audience: str,
        duration_mins: int,
        frequency: str,
        passing_score: int,
    ) -> Dict[str, Any]:
        """Create a new awareness program."""
        if program_type not in _VALID_PROGRAM_TYPES:
            raise ValueError(
                f"Invalid program_type: {program_type!r}. "
                f"Must be one of {sorted(_VALID_PROGRAM_TYPES)}"
            )
        if frequency not in _VALID_FREQUENCIES:
            raise ValueError(
                f"Invalid frequency: {frequency!r}. "
                f"Must be one of {sorted(_VALID_FREQUENCIES)}"
            )
        if target_audience not in _VALID_TARGET_AUDIENCES:
            raise ValueError(
                f"Invalid target_audience: {target_audience!r}. "
                f"Must be one of {sorted(_VALID_TARGET_AUDIENCES)}"
            )
        now = _now()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "program_name": program_name,
            "program_type": program_type,
            "target_audience": target_audience,
            "duration_mins": int(duration_mins),
            "frequency": frequency,
            "passing_score": int(passing_score),
            "enrolled_count": 0,
            "completed_count": 0,
            "pass_rate": 0.0,
            "status": "active",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO awareness_programs
                       (id, org_id, program_name, program_type, target_audience,
                        duration_mins, frequency, passing_score, enrolled_count,
                        completed_count, pass_rate, status, created_at)
                       VALUES (:id, :org_id, :program_name, :program_type, :target_audience,
                               :duration_mins, :frequency, :passing_score, :enrolled_count,
                               :completed_count, :pass_rate, :status, :created_at)""",
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Enrollments
    # ------------------------------------------------------------------

    def enroll_user(
        self,
        program_id: str,
        org_id: str,
        user_id: str,
        user_name: str,
        department: str,
    ) -> Dict[str, Any]:
        """Enroll a user in a program. Dedup via INSERT OR IGNORE on (program_id, org_id, user_id).
        enrolled_count is only incremented when a new row is actually inserted.
        """
        now = _now()
        enrollment_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                cursor = conn.execute(
                    """INSERT OR IGNORE INTO program_enrollments
                       (id, program_id, org_id, user_id, user_name, department,
                        enrolled_at, completed_at, score, passed, attempts, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, 0, 0, ?)""",
                    (enrollment_id, program_id, org_id, user_id, user_name, department, now, now),
                )
                newly_inserted = cursor.rowcount > 0
                if newly_inserted:
                    conn.execute(
                        "UPDATE awareness_programs SET enrolled_count=enrolled_count+1 WHERE id=? AND org_id=?",
                        (program_id, org_id),
                    )
                # Return the actual row (existing or new)
                row = conn.execute(
                    "SELECT * FROM program_enrollments WHERE program_id=? AND org_id=? AND user_id=?",
                    (program_id, org_id, user_id),
                ).fetchone()
        result = self._row(row)
        result["newly_enrolled"] = newly_inserted
        return result

    def record_completion(
        self,
        enrollment_id: str,
        org_id: str,
        score: int,
    ) -> Dict[str, Any]:
        """Record completion of an enrollment. Recomputes program completed_count and pass_rate."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM program_enrollments WHERE id=? AND org_id=?",
                    (enrollment_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Enrollment {enrollment_id!r} not found.")

                enrollment = self._row(row)
                program_id = enrollment["program_id"]

                # Get passing_score from program
                pb_row = conn.execute(
                    "SELECT passing_score FROM awareness_programs WHERE id=? AND org_id=?",
                    (program_id, org_id),
                ).fetchone()
                passing_score = pb_row["passing_score"] if pb_row else 70

                passed = 1 if score >= passing_score else 0

                conn.execute(
                    """UPDATE program_enrollments
                       SET completed_at=?, score=?, passed=?, attempts=attempts+1
                       WHERE id=? AND org_id=?""",
                    (now, int(score), passed, enrollment_id, org_id),
                )

                # Recompute program stats
                stats_row = conn.execute(
                    """SELECT
                           COUNT(completed_at) as completed_count,
                           COALESCE(SUM(passed), 0) as pass_count
                       FROM program_enrollments
                       WHERE program_id=? AND org_id=? AND completed_at IS NOT NULL""",
                    (program_id, org_id),
                ).fetchone()
                completed_count = stats_row["completed_count"]
                pass_count = stats_row["pass_count"]
                pass_rate = (pass_count / completed_count * 100.0) if completed_count > 0 else 0.0

                conn.execute(
                    "UPDATE awareness_programs SET completed_count=?, pass_rate=? WHERE id=? AND org_id=?",
                    (completed_count, pass_rate, program_id, org_id),
                )

                updated = conn.execute(
                    "SELECT * FROM program_enrollments WHERE id=? AND org_id=?",
                    (enrollment_id, org_id),
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def record_event(
        self,
        org_id: str,
        event_type: str,
        description: str,
        affected_users: int,
        department: str,
        event_date: str,
        response_action: str,
    ) -> Dict[str, Any]:
        """Record an awareness event."""
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type: {event_type!r}. "
                f"Must be one of {sorted(_VALID_EVENT_TYPES)}"
            )
        now = _now()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "event_type": event_type,
            "description": description,
            "affected_users": int(affected_users),
            "department": department,
            "event_date": event_date,
            "response_action": response_action,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO awareness_events
                       (id, org_id, event_type, description, affected_users,
                        department, event_date, response_action, created_at)
                       VALUES (:id, :org_id, :event_type, :description, :affected_users,
                               :department, :event_date, :response_action, :created_at)""",
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_program_stats(
        self, program_id: str, org_id: str
    ) -> Dict[str, Any]:
        """Return program details with completion_rate, pass_rate, dept_breakdown, low_score_users."""
        with self._conn() as conn:
            pb_row = conn.execute(
                "SELECT * FROM awareness_programs WHERE id=? AND org_id=?",
                (program_id, org_id),
            ).fetchone()
            if not pb_row:
                raise KeyError(f"Program {program_id!r} not found.")

            program = self._row(pb_row)
            enrolled = program["enrolled_count"]
            completed = program["completed_count"]
            completion_rate = (completed / enrolled * 100.0) if enrolled > 0 else 0.0

            # Dept breakdown
            dept_rows = conn.execute(
                """SELECT department,
                          COUNT(*) as enrolled,
                          COUNT(completed_at) as completed,
                          COALESCE(SUM(passed), 0) as passed
                   FROM program_enrollments
                   WHERE program_id=? AND org_id=?
                   GROUP BY department""",
                (program_id, org_id),
            ).fetchall()
            dept_breakdown: Dict[str, Any] = {}
            for dr in dept_rows:
                dept_breakdown[dr["department"]] = {
                    "enrolled": dr["enrolled"],
                    "completed": dr["completed"],
                    "passed": dr["passed"],
                }

            # Low score users: completed but score < passing_score
            passing_score = program["passing_score"]
            low_rows = conn.execute(
                """SELECT * FROM program_enrollments
                   WHERE program_id=? AND org_id=? AND completed_at IS NOT NULL
                     AND score < ?
                   ORDER BY score ASC
                   LIMIT 10""",
                (program_id, org_id, passing_score),
            ).fetchall()

        program["completion_rate"] = completion_rate
        program["dept_breakdown"] = dept_breakdown
        program["low_score_users"] = [self._row(r) for r in low_rows]
        return program

    def get_department_compliance(self, org_id: str) -> List[Dict[str, Any]]:
        """Return per-department compliance: enrolled, completed, passed, compliance_rate."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT department,
                          COUNT(*) as enrolled_count,
                          COUNT(completed_at) as completed_count,
                          COALESCE(SUM(passed), 0) as pass_count
                   FROM program_enrollments
                   WHERE org_id=?
                   GROUP BY department
                   ORDER BY department ASC""",
                (org_id,),
            ).fetchall()

        results = []
        for r in rows:
            enrolled = r["enrolled_count"]
            passed = r["pass_count"]
            compliance_rate = (passed / enrolled * 100.0) if enrolled > 0 else 0.0
            results.append({
                "department": r["department"],
                "enrolled_count": enrolled,
                "completed_count": r["completed_count"],
                "pass_count": passed,
                "compliance_rate": compliance_rate,
            })
        return results

    def get_overdue_enrollments(self, org_id: str) -> List[Dict[str, Any]]:
        """Return enrollments where completed_at IS NULL and enrolled_at < 30 days ago."""
        cutoff = (_now_dt() - timedelta(days=30)).isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM program_enrollments
                   WHERE org_id=? AND completed_at IS NULL AND enrolled_at < ?
                   ORDER BY enrolled_at ASC""",
                (org_id, cutoff),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_program_summary(self, org_id: str) -> Dict[str, Any]:
        """Return org-level program summary."""
        with self._conn() as conn:
            total_programs = conn.execute(
                "SELECT COUNT(*) as cnt FROM awareness_programs WHERE org_id=?",
                (org_id,),
            ).fetchone()["cnt"]

            totals_row = conn.execute(
                """SELECT COALESCE(SUM(enrolled_count), 0) as total_enrolled,
                          COALESCE(SUM(completed_count), 0) as total_completed
                   FROM awareness_programs WHERE org_id=?""",
                (org_id,),
            ).fetchone()
            total_enrolled = totals_row["total_enrolled"]
            total_completed = totals_row["total_completed"]

            # Overall pass_rate from enrollments
            pass_row = conn.execute(
                """SELECT COUNT(completed_at) as completed_cnt,
                          COALESCE(SUM(passed), 0) as pass_cnt
                   FROM program_enrollments WHERE org_id=? AND completed_at IS NOT NULL""",
                (org_id,),
            ).fetchone()
            completed_cnt = pass_row["completed_cnt"]
            pass_cnt = pass_row["pass_cnt"]
            overall_pass_rate = (pass_cnt / completed_cnt * 100.0) if completed_cnt > 0 else 0.0

            type_rows = conn.execute(
                """SELECT program_type, COUNT(*) as cnt
                   FROM awareness_programs WHERE org_id=?
                   GROUP BY program_type""",
                (org_id,),
            ).fetchall()
            by_type = {r["program_type"]: r["cnt"] for r in type_rows}

        return {
            "total_programs": total_programs,
            "total_enrolled": total_enrolled,
            "total_completed": total_completed,
            "overall_pass_rate": overall_pass_rate,
            "by_type": by_type,
        }
