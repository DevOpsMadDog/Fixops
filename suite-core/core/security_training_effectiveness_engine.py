"""Security Training Effectiveness Engine — ALDECI.

Measures security training outcomes and tracks knowledge retention across
training programs, completions, and long-term assessment scores.

Capabilities:
  - Create and manage training programs with passing scores
  - Track enrollments and completions with pre/post score improvement
  - Record knowledge retention assessments over time
  - Department-level compliance reporting
  - Multi-tenant org_id isolation

Compliance: NIST SP 800-50, ISO 27001 A.6.3, CIS Control 14
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

_VALID_TRAINING_TYPES = {
    "awareness",
    "phishing",
    "compliance",
    "technical",
    "leadership",
    "onboarding",
    "refresher",
}

_VALID_DELIVERY_METHODS = {
    "online",
    "instructor-led",
    "hybrid",
    "self-paced",
    "simulation",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


class SecurityTrainingEffectivenessEngine:
    """SQLite WAL-backed Security Training Effectiveness engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_training_effectiveness.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(
                Path(_DEFAULT_DB_DIR) / "security_training_effectiveness.db"
            )
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
                CREATE TABLE IF NOT EXISTS training_programs (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    program_name      TEXT NOT NULL,
                    training_type     TEXT NOT NULL DEFAULT 'awareness',
                    target_audience   TEXT NOT NULL DEFAULT 'all',
                    delivery_method   TEXT NOT NULL DEFAULT 'online',
                    duration_mins     INTEGER NOT NULL DEFAULT 60,
                    passing_score     REAL NOT NULL DEFAULT 70.0,
                    enrollment_count  INTEGER NOT NULL DEFAULT 0,
                    completion_count  INTEGER NOT NULL DEFAULT 0,
                    avg_score         REAL NOT NULL DEFAULT 0.0,
                    completion_rate   REAL NOT NULL DEFAULT 0.0,
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tp_org
                    ON training_programs (org_id, training_type);

                CREATE TABLE IF NOT EXISTS training_completions (
                    id               TEXT PRIMARY KEY,
                    program_id       TEXT NOT NULL,
                    org_id           TEXT NOT NULL,
                    employee_id      TEXT NOT NULL,
                    department       TEXT NOT NULL DEFAULT '',
                    pre_score        REAL NOT NULL DEFAULT 0.0,
                    post_score       REAL NOT NULL DEFAULT 0.0,
                    score_improvement REAL NOT NULL DEFAULT 0.0,
                    passed           INTEGER NOT NULL DEFAULT 0,
                    completed_at     TEXT,
                    time_spent_mins  INTEGER NOT NULL DEFAULT 0,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tc_prog_org
                    ON training_completions (program_id, org_id);

                CREATE INDEX IF NOT EXISTS idx_tc_emp
                    ON training_completions (org_id, employee_id);

                CREATE TABLE IF NOT EXISTS knowledge_retention (
                    id                  TEXT PRIMARY KEY,
                    program_id          TEXT NOT NULL,
                    org_id              TEXT NOT NULL,
                    employee_id         TEXT NOT NULL,
                    assessment_date     TEXT NOT NULL,
                    retention_score     REAL NOT NULL DEFAULT 0.0,
                    days_since_training INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_kr_prog_org
                    ON knowledge_retention (program_id, org_id);
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
        training_type: str = "awareness",
        target_audience: str = "all",
        delivery_method: str = "online",
        duration_mins: int = 60,
        passing_score: float = 70.0,
    ) -> Dict[str, Any]:
        """Create a new training program."""
        if training_type not in _VALID_TRAINING_TYPES:
            raise ValueError(
                f"training_type must be one of {sorted(_VALID_TRAINING_TYPES)}"
            )
        if delivery_method not in _VALID_DELIVERY_METHODS:
            raise ValueError(
                f"delivery_method must be one of {sorted(_VALID_DELIVERY_METHODS)}"
            )
        passing_score = _clamp(passing_score)
        row_id = str(uuid.uuid4())
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO training_programs
                        (id, org_id, program_name, training_type, target_audience,
                         delivery_method, duration_mins, passing_score,
                         enrollment_count, completion_count, avg_score,
                         completion_rate, created_at)
                    VALUES (?,?,?,?,?,?,?,?,0,0,0.0,0.0,?)
                    """,
                    (
                        row_id, org_id, program_name, training_type,
                        target_audience, delivery_method, duration_mins,
                        passing_score, now,
                    ),
                )
            return self._get_program(row_id, org_id)

    def _get_program(self, program_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM training_programs WHERE id=? AND org_id=?",
                (program_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def list_programs(
        self, org_id: str, training_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List programs, optionally filtered by training_type."""
        with self._conn() as conn:
            if training_type:
                rows = conn.execute(
                    "SELECT * FROM training_programs WHERE org_id=? AND training_type=? ORDER BY created_at DESC",
                    (org_id, training_type),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM training_programs WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Enrollment & completion
    # ------------------------------------------------------------------

    def enroll(
        self,
        program_id: str,
        org_id: str,
        employee_id: str,
        department: str = "",
    ) -> Dict[str, Any]:
        """Enroll an employee in a training program."""
        with self._lock:
            program = self._get_program(program_id, org_id)
            if not program:
                raise KeyError(f"Program {program_id} not found")
            completion_id = str(uuid.uuid4())
            now = _now()
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO training_completions
                        (id, program_id, org_id, employee_id, department,
                         pre_score, post_score, score_improvement, passed,
                         completed_at, time_spent_mins, created_at)
                    VALUES (?,?,?,?,?,0.0,0.0,0.0,0,NULL,0,?)
                    """,
                    (completion_id, program_id, org_id, employee_id, department, now),
                )
                conn.execute(
                    "UPDATE training_programs SET enrollment_count = enrollment_count + 1 WHERE id=? AND org_id=?",
                    (program_id, org_id),
                )
            if _get_tg_bus:
                try:
                    bus = _get_tg_bus()
                    if bus and getattr(bus, "enabled", False):
                        bus.emit("TRAINING_COMPLETED", {"entity_type": "security_training_effectiveness_engine", "org_id": org_id, "source_engine": "security_training_effectiveness_engine"})
                except Exception:
                    pass
            return {"id": completion_id, "program_id": program_id, "employee_id": employee_id, "status": "enrolled"}

    def record_completion(
        self,
        program_id: str,
        org_id: str,
        employee_id: str,
        pre_score: float,
        post_score: float,
        time_spent_mins: int = 0,
    ) -> Dict[str, Any]:
        """Record a training completion with pre/post scores."""
        pre_score = _clamp(pre_score)
        post_score = _clamp(post_score)
        score_improvement = post_score - pre_score
        now = _now()

        with self._lock:
            program = self._get_program(program_id, org_id)
            if not program:
                raise KeyError(f"Program {program_id} not found")
            passing_score = program["passing_score"]
            passed = 1 if post_score >= passing_score else 0

            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE training_completions
                    SET pre_score=?, post_score=?, score_improvement=?,
                        passed=?, completed_at=?, time_spent_mins=?
                    WHERE program_id=? AND org_id=? AND employee_id=?
                      AND completed_at IS NULL
                    """,
                    (
                        pre_score, post_score, score_improvement,
                        passed, now, time_spent_mins,
                        program_id, org_id, employee_id,
                    ),
                )
                # Recompute program-level stats
                agg = conn.execute(
                    """
                    SELECT COUNT(*) AS cnt,
                           AVG(post_score) AS avg_ps
                    FROM training_completions
                    WHERE program_id=? AND org_id=? AND completed_at IS NOT NULL
                    """,
                    (program_id, org_id),
                ).fetchone()
                completion_count = agg["cnt"] or 0
                avg_score = agg["avg_ps"] or 0.0
                enrollment_count = program["enrollment_count"]
                completion_rate = (
                    completion_count / enrollment_count * 100
                    if enrollment_count > 0
                    else 0.0
                )
                conn.execute(
                    """
                    UPDATE training_programs
                    SET completion_count=?, avg_score=?, completion_rate=?
                    WHERE id=? AND org_id=?
                    """,
                    (completion_count, avg_score, completion_rate, program_id, org_id),
                )
            return self._get_program(program_id, org_id)

    # ------------------------------------------------------------------
    # Knowledge retention
    # ------------------------------------------------------------------

    def record_retention(
        self,
        program_id: str,
        org_id: str,
        employee_id: str,
        retention_score: float,
        days_since_training: int = 0,
    ) -> Dict[str, Any]:
        """Record a knowledge retention assessment."""
        retention_score = _clamp(retention_score)
        row_id = str(uuid.uuid4())
        now = _now()
        assessment_date = now[:10]
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO knowledge_retention
                        (id, program_id, org_id, employee_id, assessment_date,
                         retention_score, days_since_training, created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        row_id, program_id, org_id, employee_id,
                        assessment_date, retention_score, days_since_training, now,
                    ),
                )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("TRAINING_COMPLETED", {"entity_type": "security_training_effectiveness_engine", "org_id": org_id, "source_engine": "security_training_effectiveness_engine"})
            except Exception:
                pass
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("TRAINING_COMPLETED", {"entity_type": "security_training_effectiveness_engine", "org_id": org_id, "source_engine": "security_training_effectiveness_engine"})
            except Exception:
                pass
        return {
            "id": row_id,
            "program_id": program_id,
            "employee_id": employee_id,
            "retention_score": retention_score,
            "days_since_training": days_since_training,
        }

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_effectiveness(
        self, program_id: str, org_id: str
    ) -> Dict[str, Any]:
        """Return full effectiveness report for a program."""
        program = self._get_program(program_id, org_id)
        if not program:
            raise KeyError(f"Program {program_id} not found")

        with self._conn() as conn:
            # Completion stats
            stats = conn.execute(
                """
                SELECT AVG(pre_score) AS avg_pre,
                       AVG(post_score) AS avg_post,
                       AVG(score_improvement) AS avg_imp,
                       COUNT(*) AS total,
                       SUM(passed) AS total_passed
                FROM training_completions
                WHERE program_id=? AND org_id=? AND completed_at IS NOT NULL
                """,
                (program_id, org_id),
            ).fetchone()

            total = stats["total"] or 0
            total_passed = stats["total_passed"] or 0
            pass_rate = (total_passed / total * 100) if total > 0 else 0.0

            # By department
            dept_rows = conn.execute(
                """
                SELECT department, AVG(post_score) AS avg_score, COUNT(*) AS cnt
                FROM training_completions
                WHERE program_id=? AND org_id=? AND completed_at IS NOT NULL
                GROUP BY department
                """,
                (program_id, org_id),
            ).fetchall()
            by_department = {
                r["department"]: {"avg_score": r["avg_score"], "count": r["cnt"]}
                for r in dept_rows
            }

            # Retention trend by bucket
            ret_rows = conn.execute(
                """
                SELECT CASE
                         WHEN days_since_training <= 7  THEN '7'
                         WHEN days_since_training <= 30 THEN '30'
                         WHEN days_since_training <= 60 THEN '60'
                         ELSE '90'
                       END AS bucket,
                       AVG(retention_score) AS avg_retention
                FROM knowledge_retention
                WHERE program_id=? AND org_id=?
                GROUP BY bucket
                ORDER BY bucket
                """,
                (program_id, org_id),
            ).fetchall()
            retention_trend = {r["bucket"]: r["avg_retention"] for r in ret_rows}

        return {
            **program,
            "avg_pre_score": stats["avg_pre"] or 0.0,
            "avg_post_score": stats["avg_post"] or 0.0,
            "avg_improvement": stats["avg_imp"] or 0.0,
            "pass_rate": pass_rate,
            "by_department": by_department,
            "retention_trend": retention_trend,
        }

    def get_department_compliance(self, org_id: str) -> List[Dict[str, Any]]:
        """Completion rate, avg score, passed count by department."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT tc.department,
                       COUNT(*) AS total,
                       SUM(CASE WHEN tc.completed_at IS NOT NULL THEN 1 ELSE 0 END) AS completed,
                       AVG(CASE WHEN tc.completed_at IS NOT NULL THEN tc.post_score END) AS avg_score,
                       SUM(tc.passed) AS passed_count
                FROM training_completions tc
                WHERE tc.org_id=?
                GROUP BY tc.department
                ORDER BY tc.department
                """,
                (org_id,),
            ).fetchall()
        result = []
        for r in rows:
            total = r["total"] or 0
            completed = r["completed"] or 0
            result.append({
                "department": r["department"],
                "completion_rate": (completed / total * 100) if total > 0 else 0.0,
                "avg_score": r["avg_score"] or 0.0,
                "passed_count": r["passed_count"] or 0,
                "total_enrolled": total,
                "total_completed": completed,
            })
        return result

    def get_summary(self, org_id: str) -> Dict[str, Any]:
        """Aggregate summary across all programs for an org."""
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS total_programs,
                       SUM(enrollment_count) AS total_enrollments,
                       SUM(completion_count) AS total_completions,
                       AVG(completion_rate) AS overall_completion_rate,
                       AVG(avg_score) AS overall_avg_score
                FROM training_programs
                WHERE org_id=?
                """,
                (org_id,),
            ).fetchone()

            # Count programs where avg_score < passing_score OR completion_rate < 50
            low_count = conn.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM training_programs
                WHERE org_id=?
                  AND (avg_score < passing_score OR completion_rate < 50)
                """,
                (org_id,),
            ).fetchone()["cnt"]

        return {
            "total_programs": row["total_programs"] or 0,
            "total_enrollments": row["total_enrollments"] or 0,
            "total_completions": row["total_completions"] or 0,
            "overall_completion_rate": row["overall_completion_rate"] or 0.0,
            "overall_avg_score": row["overall_avg_score"] or 0.0,
            "low_performing_programs": low_count or 0,
        }
