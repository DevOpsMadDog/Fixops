"""
Security Awareness Score Tracker — ALDECI.

Tracks employee security training completions, phishing simulation results,
and computes composite awareness scores with risk tiering.

Multi-tenant via org_id.  Thread-safe via RLock.  SQLite WAL for concurrency.
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "awareness_score_engine.db"
)

_VALID_RISK_LEVELS = {"high_risk", "elevated", "standard"}
_VALID_TRAINING_TYPES = {
    "phishing_sim", "security_basics", "data_handling",
    "incident_response", "compliance", "role_specific",
}
_VALID_RISK_TIERS = {"champion", "proficient", "developing", "at_risk"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _this_month_start() -> str:
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()


class AwarenessScoreEngine:
    """SQLite WAL-backed Security Awareness Score engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: employee_profiles, training_completions, phishing_tests, awareness_scores.
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
                CREATE TABLE IF NOT EXISTS employee_profiles (
                    profile_id              TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    employee_id             TEXT NOT NULL,
                    name                    TEXT NOT NULL DEFAULT '',
                    department              TEXT NOT NULL DEFAULT '',
                    role                    TEXT NOT NULL DEFAULT '',
                    risk_level              TEXT NOT NULL DEFAULT 'standard',
                    last_training_at        DATETIME,
                    phishing_click_rate     REAL NOT NULL DEFAULT 0.0,
                    training_completion_pct REAL NOT NULL DEFAULT 0.0,
                    created_at              DATETIME NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_ep_org_emp
                    ON employee_profiles (org_id, employee_id);

                CREATE INDEX IF NOT EXISTS idx_ep_org
                    ON employee_profiles (org_id, department, risk_level);

                CREATE TABLE IF NOT EXISTS training_completions (
                    completion_id   TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    employee_id     TEXT NOT NULL,
                    training_name   TEXT NOT NULL,
                    training_type   TEXT NOT NULL DEFAULT 'security_basics',
                    completed_at    DATETIME NOT NULL,
                    score           REAL NOT NULL DEFAULT 0.0,
                    passed          INTEGER NOT NULL DEFAULT 1,
                    expires_at      DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_tc_org_emp
                    ON training_completions (org_id, employee_id, completed_at);

                CREATE TABLE IF NOT EXISTS phishing_tests (
                    test_id         TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    employee_id     TEXT NOT NULL,
                    campaign_name   TEXT NOT NULL DEFAULT '',
                    sent_at         DATETIME NOT NULL,
                    clicked         INTEGER NOT NULL DEFAULT 0,
                    reported        INTEGER NOT NULL DEFAULT 0,
                    clicked_at      DATETIME,
                    reported_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_pt_org_emp
                    ON phishing_tests (org_id, employee_id, sent_at);

                CREATE TABLE IF NOT EXISTS awareness_scores (
                    score_id                    TEXT PRIMARY KEY,
                    org_id                      TEXT NOT NULL,
                    employee_id                 TEXT NOT NULL,
                    calculated_at               DATETIME NOT NULL,
                    training_score              REAL NOT NULL DEFAULT 0.0,
                    phishing_resistance_score   REAL NOT NULL DEFAULT 0.0,
                    overall_score               REAL NOT NULL DEFAULT 0.0,
                    risk_tier                   TEXT NOT NULL DEFAULT 'at_risk'
                );

                CREATE INDEX IF NOT EXISTS idx_as_org_emp
                    ON awareness_scores (org_id, employee_id, calculated_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Employees
    # ------------------------------------------------------------------

    def register_employee(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register or upsert an employee profile."""
        risk_level = data.get("risk_level", "standard")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(f"Invalid risk_level '{risk_level}'. Valid: {_VALID_RISK_LEVELS}")

        record = {
            "profile_id": str(uuid.uuid4()),
            "org_id": org_id,
            "employee_id": data["employee_id"],
            "name": data.get("name", ""),
            "department": data.get("department", ""),
            "role": data.get("role", ""),
            "risk_level": risk_level,
            "last_training_at": data.get("last_training_at"),
            "phishing_click_rate": float(data.get("phishing_click_rate", 0.0)),
            "training_completion_pct": float(data.get("training_completion_pct", 0.0)),
            "created_at": _now(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO employee_profiles
                       (profile_id, org_id, employee_id, name, department, role,
                        risk_level, last_training_at, phishing_click_rate,
                        training_completion_pct, created_at)
                       VALUES (:profile_id, :org_id, :employee_id, :name, :department, :role,
                               :risk_level, :last_training_at, :phishing_click_rate,
                               :training_completion_pct, :created_at)
                       ON CONFLICT(org_id, employee_id) DO UPDATE SET
                           name = excluded.name,
                           department = excluded.department,
                           role = excluded.role,
                           risk_level = excluded.risk_level""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "awareness_score", "org_id": org_id, "source_engine": "awareness_score"})
            except Exception:
                pass

        return record

    def list_employees(
        self,
        org_id: str,
        department: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List employee profiles for an org."""
        query = "SELECT * FROM employee_profiles WHERE org_id = ?"
        params: List[Any] = [org_id]
        if department:
            query += " AND department = ?"
            params.append(department)
        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level)
        query += " ORDER BY name"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def record_training(self, org_id: str, employee_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a training completion for an employee."""
        training_type = data.get("training_type", "security_basics")
        if training_type not in _VALID_TRAINING_TYPES:
            raise ValueError(f"Invalid training_type '{training_type}'")

        completed_at = data.get("completed_at", _now())
        score = float(data.get("score", 0.0))
        passed = int(data.get("passed", score >= 70.0))

        # expires_at: default 1 year from completion
        expires_at = data.get("expires_at")
        if not expires_at:
            try:
                dt = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
                expires_at = (dt + timedelta(days=365)).isoformat()
            except Exception:
                expires_at = None

        record = {
            "completion_id": str(uuid.uuid4()),
            "org_id": org_id,
            "employee_id": employee_id,
            "training_name": data["training_name"],
            "training_type": training_type,
            "completed_at": completed_at,
            "score": score,
            "passed": passed,
            "expires_at": expires_at,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO training_completions
                       (completion_id, org_id, employee_id, training_name, training_type,
                        completed_at, score, passed, expires_at)
                       VALUES (:completion_id, :org_id, :employee_id, :training_name, :training_type,
                               :completed_at, :score, :passed, :expires_at)""",
                    record,
                )
                # Update last_training_at on profile
                conn.execute(
                    """UPDATE employee_profiles SET last_training_at = ?
                       WHERE org_id = ? AND employee_id = ?""",
                    (completed_at, org_id, employee_id),
                )
        return record

    # ------------------------------------------------------------------
    # Phishing Tests
    # ------------------------------------------------------------------

    def record_phishing_test(self, org_id: str, employee_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a phishing simulation result."""
        clicked = int(data.get("clicked", 0))
        reported = int(data.get("reported", 0))

        record = {
            "test_id": str(uuid.uuid4()),
            "org_id": org_id,
            "employee_id": employee_id,
            "campaign_name": data.get("campaign_name", ""),
            "sent_at": data.get("sent_at", _now()),
            "clicked": clicked,
            "reported": reported,
            "clicked_at": data.get("clicked_at"),
            "reported_at": data.get("reported_at"),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO phishing_tests
                       (test_id, org_id, employee_id, campaign_name,
                        sent_at, clicked, reported, clicked_at, reported_at)
                       VALUES (:test_id, :org_id, :employee_id, :campaign_name,
                               :sent_at, :clicked, :reported, :clicked_at, :reported_at)""",
                    record,
                )
                # Recalculate click rate on profile
                click_row = conn.execute(
                    """SELECT
                         COUNT(*) as total,
                         SUM(clicked) as total_clicked
                       FROM phishing_tests WHERE org_id = ? AND employee_id = ?""",
                    (org_id, employee_id),
                ).fetchone()
                if click_row and click_row["total"] > 0:
                    click_rate = (click_row["total_clicked"] or 0) / click_row["total"]
                    conn.execute(
                        """UPDATE employee_profiles SET phishing_click_rate = ?
                           WHERE org_id = ? AND employee_id = ?""",
                        (click_rate, org_id, employee_id),
                    )
        return record

    # ------------------------------------------------------------------
    # Score Calculation
    # ------------------------------------------------------------------

    def calculate_score(self, org_id: str, employee_id: str) -> Dict[str, Any]:
        """Compute composite awareness score for an employee.

        training_score = completion_pct × 70 + avg_score × 30
        phishing_resistance = 100 − click_rate × 100
        overall = training × 0.6 + phishing × 0.4
        risk_tier: champion≥85, proficient≥70, developing≥50, at_risk<50
        """
        with self._lock:
            with self._conn() as conn:
                profile = conn.execute(
                    "SELECT * FROM employee_profiles WHERE org_id = ? AND employee_id = ?",
                    (org_id, employee_id),
                ).fetchone()
                if not profile:
                    raise ValueError(f"Employee '{employee_id}' not found for org '{org_id}'")

                # Training stats
                train_row = conn.execute(
                    """SELECT
                         COUNT(*) as total,
                         SUM(passed) as passed_count,
                         AVG(score) as avg_score
                       FROM training_completions WHERE org_id = ? AND employee_id = ?""",
                    (org_id, employee_id),
                ).fetchone()

                # Phishing stats
                phish_row = conn.execute(
                    """SELECT
                         COUNT(*) as total,
                         SUM(clicked) as total_clicked
                       FROM phishing_tests WHERE org_id = ? AND employee_id = ?""",
                    (org_id, employee_id),
                ).fetchone()

        # Compute training score
        total_trainings = train_row["total"] if train_row else 0
        if total_trainings > 0:
            completion_pct = (train_row["passed_count"] or 0) / total_trainings
            avg_score = float(train_row["avg_score"] or 0.0)
        else:
            completion_pct = 0.0
            avg_score = 0.0

        training_score = (completion_pct * 70.0) + (avg_score / 100.0 * 30.0)
        training_score = min(100.0, max(0.0, training_score))

        # Compute phishing resistance
        total_phishing = phish_row["total"] if phish_row else 0
        if total_phishing > 0:
            click_rate = (phish_row["total_clicked"] or 0) / total_phishing
        else:
            click_rate = 0.0
        phishing_resistance_score = max(0.0, 100.0 - click_rate * 100.0)

        # Overall score
        overall_score = (training_score * 0.6) + (phishing_resistance_score * 0.4)
        overall_score = min(100.0, max(0.0, overall_score))

        # Risk tier
        if overall_score >= 85.0:
            risk_tier = "champion"
        elif overall_score >= 70.0:
            risk_tier = "proficient"
        elif overall_score >= 50.0:
            risk_tier = "developing"
        else:
            risk_tier = "at_risk"

        now_str = _now()
        score_record = {
            "score_id": str(uuid.uuid4()),
            "org_id": org_id,
            "employee_id": employee_id,
            "calculated_at": now_str,
            "training_score": round(training_score, 2),
            "phishing_resistance_score": round(phishing_resistance_score, 2),
            "overall_score": round(overall_score, 2),
            "risk_tier": risk_tier,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO awareness_scores
                       (score_id, org_id, employee_id, calculated_at,
                        training_score, phishing_resistance_score, overall_score, risk_tier)
                       VALUES (:score_id, :org_id, :employee_id, :calculated_at,
                               :training_score, :phishing_resistance_score, :overall_score, :risk_tier)""",
                    score_record,
                )
        return score_record

    def list_scores(
        self,
        org_id: str,
        risk_tier: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List the latest score per employee for an org."""
        query = """
            SELECT s.*
            FROM awareness_scores s
            INNER JOIN (
                SELECT employee_id, MAX(calculated_at) as latest
                FROM awareness_scores WHERE org_id = ?
                GROUP BY employee_id
            ) latest ON s.employee_id = latest.employee_id
                     AND s.calculated_at = latest.latest
                     AND s.org_id = ?
        """
        params: List[Any] = [org_id, org_id]
        if risk_tier:
            query += " WHERE s.risk_tier = ?"
            params.append(risk_tier)
        query += " ORDER BY s.overall_score DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Summaries
    # ------------------------------------------------------------------

    def get_department_summary(self, org_id: str) -> Dict[str, Any]:
        """Return awareness stats grouped by department."""
        with self._lock:
            with self._conn() as conn:
                dept_rows = conn.execute(
                    """SELECT ep.department,
                              COUNT(DISTINCT ep.employee_id) as employee_count
                       FROM employee_profiles ep
                       WHERE ep.org_id = ?
                       GROUP BY ep.department""",
                    (org_id,),
                ).fetchall()

                score_rows = conn.execute(
                    """SELECT ep.department,
                              AVG(s.overall_score) as avg_score,
                              COUNT(CASE WHEN s.risk_tier = 'at_risk' THEN 1 END) as at_risk_count,
                              COUNT(CASE WHEN s.risk_tier = 'champion' THEN 1 END) as champion_count
                       FROM employee_profiles ep
                       JOIN (
                           SELECT employee_id, risk_tier, overall_score,
                                  MAX(calculated_at) as latest
                           FROM awareness_scores WHERE org_id = ?
                           GROUP BY employee_id
                       ) s ON ep.employee_id = s.employee_id
                       WHERE ep.org_id = ?
                       GROUP BY ep.department""",
                    (org_id, org_id),
                ).fetchall()

        score_map: Dict[str, Any] = {}
        for r in score_rows:
            score_map[r["department"]] = {
                "avg_score": round(float(r["avg_score"] or 0.0), 2),
                "at_risk_count": r["at_risk_count"] or 0,
                "champion_count": r["champion_count"] or 0,
            }

        by_department: Dict[str, Any] = {}
        for r in dept_rows:
            dept = r["department"] or "Unknown"
            sm = score_map.get(dept, {"avg_score": 0.0, "at_risk_count": 0, "champion_count": 0})
            by_department[dept] = {
                "employee_count": r["employee_count"],
                "avg_score": sm["avg_score"],
                "at_risk_count": sm["at_risk_count"],
                "champion_count": sm["champion_count"],
            }

        return {"by_department": by_department}

    def get_awareness_stats(self, org_id: str) -> Dict[str, Any]:
        """Return high-level awareness stats for an org."""
        with self._lock:
            with self._conn() as conn:
                emp_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM employee_profiles WHERE org_id = ?",
                    (org_id,),
                ).fetchone()

                score_row = conn.execute(
                    """SELECT
                         AVG(s.overall_score) as avg_score,
                         COUNT(CASE WHEN s.risk_tier = 'at_risk' THEN 1 END) as at_risk_count,
                         COUNT(CASE WHEN s.risk_tier = 'champion' THEN 1 END) as champions_count
                       FROM (
                           SELECT employee_id, risk_tier, overall_score,
                                  MAX(calculated_at) as latest
                           FROM awareness_scores WHERE org_id = ?
                           GROUP BY employee_id
                       ) s""",
                    (org_id,),
                ).fetchone()

                train_row = conn.execute(
                    """SELECT COUNT(*) as cnt FROM training_completions
                       WHERE org_id = ? AND completed_at >= ?""",
                    (org_id, _this_month_start()),
                ).fetchone()

                phish_row = conn.execute(
                    """SELECT
                         COUNT(*) as total,
                         AVG(CAST(clicked AS REAL)) as avg_click_rate
                       FROM phishing_tests WHERE org_id = ?""",
                    (org_id,),
                ).fetchone()

                # Top risk department
                top_dept_row = conn.execute(
                    """SELECT ep.department,
                              AVG(s.overall_score) as avg_score
                       FROM employee_profiles ep
                       JOIN (
                           SELECT employee_id, overall_score, MAX(calculated_at)
                           FROM awareness_scores WHERE org_id = ?
                           GROUP BY employee_id
                       ) s ON ep.employee_id = s.employee_id
                       WHERE ep.org_id = ?
                       GROUP BY ep.department
                       ORDER BY avg_score ASC
                       LIMIT 1""",
                    (org_id, org_id),
                ).fetchone()

        return {
            "total_employees": emp_row["cnt"] if emp_row else 0,
            "avg_overall_score": round(float(score_row["avg_score"] or 0.0), 2) if score_row else 0.0,
            "at_risk_count": score_row["at_risk_count"] or 0 if score_row else 0,
            "champions_count": score_row["champions_count"] or 0 if score_row else 0,
            "training_completions_this_month": train_row["cnt"] if train_row else 0,
            "phishing_click_rate_avg": round(float(phish_row["avg_click_rate"] or 0.0), 4) if phish_row else 0.0,
            "top_risk_department": top_dept_row["department"] if top_dept_row else None,
        }


# Module-level singleton
_engine: Optional[AwarenessScoreEngine] = None


def get_engine() -> AwarenessScoreEngine:
    global _engine
    if _engine is None:
        _engine = AwarenessScoreEngine()
    return _engine
