"""Control Testing Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Tracks security control effectiveness through scheduled and ad-hoc testing.
  - Define security controls mapped to compliance frameworks
  - Run tests with pass/fail/partial results and effectiveness scoring
  - Rolling average effectiveness from last 5 tests
  - Auto-computes control status based on score thresholds
  - Schedule management for recurring control tests

Compliance: NIST SP 800-53 CA-2, ISO 27001 A.18.2, SOC2 CC4.1
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "control_testing_engine.db"
)

_VALID_CONTROL_TYPES = {"preventive", "detective", "corrective", "compensating", "deterrent"}
_VALID_FRAMEWORKS = {"NIST", "ISO27001", "SOC2", "PCI-DSS", "CIS", "HIPAA", "custom"}
_VALID_TEST_METHODS = {"automated", "manual", "interview", "observation", "inspection"}
_VALID_RESULTS = {"pass", "fail", "partial", "not-applicable"}
_VALID_STATUSES = {"effective", "partially-effective", "ineffective", "failing", "untested"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _future_iso(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _score_to_status(score: float) -> str:
    if score >= 80:
        return "effective"
    if score >= 60:
        return "partially-effective"
    if score >= 40:
        return "ineffective"
    return "failing"


class ControlTestingEngine:
    """SQLite WAL-backed Control Testing engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/control_testing_engine.db
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
                CREATE TABLE IF NOT EXISTS security_controls (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    control_name        TEXT NOT NULL DEFAULT '',
                    control_type        TEXT NOT NULL DEFAULT 'preventive',
                    framework           TEXT NOT NULL DEFAULT 'NIST',
                    description         TEXT NOT NULL DEFAULT '',
                    owner               TEXT NOT NULL DEFAULT '',
                    test_frequency_days INTEGER NOT NULL DEFAULT 90,
                    last_tested         TEXT,
                    effectiveness_score REAL NOT NULL DEFAULT 0.0,
                    status              TEXT NOT NULL DEFAULT 'untested',
                    created_at          TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_ct_controls_org
                    ON security_controls (org_id, framework, status);

                CREATE TABLE IF NOT EXISTS control_tests (
                    id             TEXT PRIMARY KEY,
                    control_id     TEXT NOT NULL,
                    org_id         TEXT NOT NULL,
                    test_name      TEXT NOT NULL DEFAULT '',
                    test_method    TEXT NOT NULL DEFAULT 'manual',
                    tester         TEXT NOT NULL DEFAULT '',
                    result         TEXT NOT NULL DEFAULT 'fail',
                    score          REAL NOT NULL DEFAULT 0.0,
                    findings       TEXT NOT NULL DEFAULT '',
                    evidence       TEXT NOT NULL DEFAULT '',
                    tested_at      TEXT NOT NULL DEFAULT '',
                    next_test_date TEXT NOT NULL DEFAULT '',
                    created_at     TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_ct_tests_control
                    ON control_tests (control_id, org_id, tested_at DESC);

                CREATE TABLE IF NOT EXISTS test_schedules (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    control_id     TEXT NOT NULL,
                    schedule_name  TEXT NOT NULL DEFAULT '',
                    frequency_days INTEGER NOT NULL DEFAULT 90,
                    next_run       TEXT NOT NULL DEFAULT '',
                    enabled        INTEGER NOT NULL DEFAULT 1,
                    last_run       TEXT,
                    created_at     TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_ct_schedules_org
                    ON test_schedules (org_id, control_id);
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
    # Controls
    # ------------------------------------------------------------------

    def create_control(
        self,
        org_id: str,
        control_name: str,
        control_type: str,
        framework: str,
        description: str,
        owner: str,
        test_frequency_days: int,
    ) -> Dict[str, Any]:
        """Create a new security control."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "control_name": control_name,
            "control_type": control_type,
            "framework": framework,
            "description": description,
            "owner": owner,
            "test_frequency_days": int(test_frequency_days),
            "last_tested": None,
            "effectiveness_score": 0.0,
            "status": "untested",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO security_controls
                       (id, org_id, control_name, control_type, framework, description,
                        owner, test_frequency_days, last_tested, effectiveness_score,
                        status, created_at)
                       VALUES (:id, :org_id, :control_name, :control_type, :framework,
                               :description, :owner, :test_frequency_days, :last_tested,
                               :effectiveness_score, :status, :created_at)""",
                    record,
                )
        return record

    def run_test(
        self,
        control_id: str,
        org_id: str,
        test_name: str,
        test_method: str,
        tester: str,
        result: str,
        score: float,
        findings: str,
        evidence: str,
    ) -> Optional[Dict[str, Any]]:
        """Run a test against a control; update rolling avg effectiveness (last 5)."""
        score = max(0.0, min(100.0, float(score)))
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                control_row = conn.execute(
                    "SELECT * FROM security_controls WHERE id = ? AND org_id = ?",
                    (control_id, org_id),
                ).fetchone()
                if not control_row:
                    return None

                freq_days = control_row["test_frequency_days"]
                next_test_date = _future_iso(freq_days)

                test_record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "control_id": control_id,
                    "org_id": org_id,
                    "test_name": test_name,
                    "test_method": test_method,
                    "tester": tester,
                    "result": result,
                    "score": score,
                    "findings": findings,
                    "evidence": evidence,
                    "tested_at": now,
                    "next_test_date": next_test_date,
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO control_tests
                       (id, control_id, org_id, test_name, test_method, tester, result,
                        score, findings, evidence, tested_at, next_test_date, created_at)
                       VALUES (:id, :control_id, :org_id, :test_name, :test_method,
                               :tester, :result, :score, :findings, :evidence,
                               :tested_at, :next_test_date, :created_at)""",
                    test_record,
                )

                # Rolling average of last 5 scores
                recent_rows = conn.execute(
                    """SELECT score FROM control_tests
                       WHERE control_id = ? AND org_id = ?
                       ORDER BY tested_at DESC LIMIT 5""",
                    (control_id, org_id),
                ).fetchall()
                scores = [r["score"] for r in recent_rows]
                avg_score = sum(scores) / len(scores) if scores else score
                new_status = _score_to_status(avg_score)

                conn.execute(
                    """UPDATE security_controls
                       SET last_tested = ?, effectiveness_score = ?, status = ?
                       WHERE id = ? AND org_id = ?""",
                    (now, avg_score, new_status, control_id, org_id),
                )

        return test_record

    # ------------------------------------------------------------------
    # Schedules
    # ------------------------------------------------------------------

    def create_schedule(
        self,
        org_id: str,
        control_id: str,
        schedule_name: str,
        frequency_days: int,
    ) -> Dict[str, Any]:
        """Create a test schedule for a control."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "control_id": control_id,
            "schedule_name": schedule_name,
            "frequency_days": int(frequency_days),
            "next_run": _future_iso(frequency_days),
            "enabled": 1,
            "last_run": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO test_schedules
                       (id, org_id, control_id, schedule_name, frequency_days,
                        next_run, enabled, last_run, created_at)
                       VALUES (:id, :org_id, :control_id, :schedule_name, :frequency_days,
                               :next_run, :enabled, :last_run, :created_at)""",
                    record,
                )
        return record

    def update_schedule_run(self, schedule_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Mark a schedule as run; advance next_run."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM test_schedules WHERE id = ? AND org_id = ?",
                    (schedule_id, org_id),
                ).fetchone()
                if not row:
                    return None
                freq = row["frequency_days"]
                next_run = _future_iso(freq)
                conn.execute(
                    "UPDATE test_schedules SET last_run = ?, next_run = ? WHERE id = ?",
                    (now, next_run, schedule_id),
                )
                updated = conn.execute(
                    "SELECT * FROM test_schedules WHERE id = ?", (schedule_id,)
                ).fetchone()
                return self._row(updated)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_control(self, control_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a control with its 10 most recent tests."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM security_controls WHERE id = ? AND org_id = ?",
                (control_id, org_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            test_rows = conn.execute(
                """SELECT * FROM control_tests
                   WHERE control_id = ? AND org_id = ?
                   ORDER BY tested_at DESC LIMIT 10""",
                (control_id, org_id),
            ).fetchall()
            result["recent_tests"] = [self._row(t) for t in test_rows]
        return result

    def list_controls(
        self,
        org_id: str,
        framework: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List controls with optional filters."""
        sql = "SELECT * FROM security_controls WHERE org_id = ?"
        params: List[Any] = [org_id]
        if framework:
            sql += " AND framework = ?"
            params.append(framework)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY effectiveness_score ASC, created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_due_tests(self, org_id: str) -> List[Dict[str, Any]]:
        """Return controls where last_tested is NULL or overdue by frequency."""
        _now_iso()
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM security_controls WHERE org_id = ?",
                (org_id,),
            ).fetchall()

        due = []
        for row in rows:
            d = self._row(row)
            if d["last_tested"] is None:
                due.append(d)
            else:
                # Compare using ISO strings — works for UTC
                try:
                    last = datetime.fromisoformat(d["last_tested"])
                    delta = datetime.now(timezone.utc) - last.replace(tzinfo=timezone.utc) if last.tzinfo is None else datetime.now(timezone.utc) - last
                    if delta.days >= d["test_frequency_days"]:
                        due.append(d)
                except (ValueError, TypeError):
                    due.append(d)
        return due

    def get_control_effectiveness_summary(self, org_id: str) -> Dict[str, Any]:
        """Summary: avg score, status counts, never-tested controls, framework breakdown."""
        with self._conn() as conn:
            avg_row = conn.execute(
                "SELECT AVG(effectiveness_score) AS avg_score FROM security_controls WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            avg_score = round(avg_row["avg_score"] or 0.0, 2)

            status_rows = conn.execute(
                """SELECT status, COUNT(*) AS cnt
                   FROM security_controls WHERE org_id = ?
                   GROUP BY status""",
                (org_id,),
            ).fetchall()
            by_status: Dict[str, int] = {r["status"]: r["cnt"] for r in status_rows}

            never_tested = conn.execute(
                "SELECT COUNT(*) AS cnt FROM security_controls WHERE org_id = ? AND last_tested IS NULL",
                (org_id,),
            ).fetchone()["cnt"]

            framework_rows = conn.execute(
                """SELECT framework, COUNT(*) AS cnt, AVG(effectiveness_score) AS avg_score
                   FROM security_controls WHERE org_id = ?
                   GROUP BY framework""",
                (org_id,),
            ).fetchall()
            framework_breakdown = [
                {
                    "framework": r["framework"],
                    "control_count": r["cnt"],
                    "avg_effectiveness": round(r["avg_score"] or 0.0, 2),
                }
                for r in framework_rows
            ]

        return {
            "avg_effectiveness_score": avg_score,
            "by_status": by_status,
            "controls_never_tested": never_tested,
            "framework_breakdown": framework_breakdown,
        }

    def get_failing_controls(self, org_id: str) -> List[Dict[str, Any]]:
        """Return controls with status in (ineffective, failing)."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM security_controls
                   WHERE org_id = ? AND status IN ('ineffective', 'failing')
                   ORDER BY effectiveness_score ASC""",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]
