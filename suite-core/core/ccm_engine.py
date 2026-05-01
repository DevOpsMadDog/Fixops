"""
⚠️  SIMULATED DATA — NOT FOR PRODUCTION OR DEMO USE  ⚠️

This engine generates randomized control test outcomes for development/testing.
DO NOT use the output in customer-facing screens or pitches.

Real implementation tracking:
- Control test outcomes (line 287) use random.random() with 80/15/5 probability
  roll — not from real control evidence or policy evaluation.
- Real implementation requires: OPA/Conftest policy-as-code evaluation, real
  audit log ingestion, and automated evidence collection from security tools.
  Configure via /api/v1/connectors/ccm/configure

Until real integrations are wired, these endpoints return a structured
warning header so callers can detect simulation mode.

Continuous Control Monitoring Engine — ALDECI.

Tracks security controls, automated/manual tests, failures, and remediation
across SOC2, ISO27001, NIST, PCI, HIPAA, and CIS frameworks.

Multi-tenant via org_id.  Thread-safe via RLock.  SQLite WAL for concurrency.
"""
from __future__ import annotations

import json
import logging
import random
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
_logger.warning(
    "⚠️  %s loaded in SIMULATION mode — control outcomes are randomized (80/15/5 roll); do not present in demos. "
    "Configure real connectors via /api/v1/connectors/ccm/configure",
    __name__,
)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "ccm_engine.db"
)

_VALID_FRAMEWORKS = {"SOC2", "ISO27001", "NIST", "PCI", "HIPAA", "CIS"}
_VALID_CONTROL_TYPES = {"preventive", "detective", "corrective"}
_VALID_FREQUENCIES = {"continuous", "daily", "weekly", "monthly", "quarterly"}
_VALID_TEST_TYPES = {"automated", "manual", "self_assessment"}
_VALID_STATUSES = {"not_tested", "passing", "failing", "degraded", "not_applicable"}
_VALID_FAILURE_TYPES = {"gap", "regression", "exception", "design_deficiency"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# Frequency → next run delta
_FREQUENCY_DELTA: Dict[str, timedelta] = {
    "continuous": timedelta(hours=1),
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "monthly": timedelta(days=30),
    "quarterly": timedelta(days=90),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CCMEngine:
    """SQLite WAL-backed Continuous Control Monitoring engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: controls, control_tests, control_failures, control_history.
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
                CREATE TABLE IF NOT EXISTS controls (
                    control_id      TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    control_name    TEXT NOT NULL,
                    framework       TEXT NOT NULL DEFAULT 'NIST',
                    control_ref     TEXT NOT NULL DEFAULT '',
                    category        TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    control_type    TEXT NOT NULL DEFAULT 'detective',
                    frequency       TEXT NOT NULL DEFAULT 'monthly',
                    owner           TEXT NOT NULL DEFAULT '',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ctrl_org
                    ON controls (org_id, framework, enabled);

                CREATE TABLE IF NOT EXISTS control_tests (
                    test_id         TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    control_id      TEXT NOT NULL
                        REFERENCES controls(control_id) ON DELETE CASCADE,
                    test_name       TEXT NOT NULL,
                    test_type       TEXT NOT NULL DEFAULT 'automated',
                    expected_result TEXT NOT NULL DEFAULT '',
                    last_run        DATETIME,
                    next_run        DATETIME,
                    status          TEXT NOT NULL DEFAULT 'not_tested',
                    evidence        TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ct_org
                    ON control_tests (org_id, control_id, status);

                CREATE TABLE IF NOT EXISTS control_failures (
                    failure_id          TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    control_id          TEXT NOT NULL
                        REFERENCES controls(control_id) ON DELETE CASCADE,
                    test_id             TEXT,
                    failure_type        TEXT NOT NULL DEFAULT 'gap',
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    description         TEXT NOT NULL DEFAULT '',
                    detected_at         DATETIME NOT NULL,
                    remediated_at       DATETIME,
                    remediation_notes   TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_cf_org
                    ON control_failures (org_id, control_id, remediated_at);

                CREATE TABLE IF NOT EXISTS control_history (
                    history_id          TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    control_id          TEXT NOT NULL
                        REFERENCES controls(control_id) ON DELETE CASCADE,
                    recorded_at         DATETIME NOT NULL,
                    status              TEXT NOT NULL DEFAULT '',
                    evidence_snapshot   TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_ch_org
                    ON control_history (org_id, control_id, recorded_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def register_control(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new security control."""
        framework = data.get("framework", "NIST")
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(f"Invalid framework '{framework}'. Valid: {_VALID_FRAMEWORKS}")
        control_type = data.get("control_type", "detective")
        if control_type not in _VALID_CONTROL_TYPES:
            raise ValueError(f"Invalid control_type '{control_type}'")
        frequency = data.get("frequency", "monthly")
        if frequency not in _VALID_FREQUENCIES:
            raise ValueError(f"Invalid frequency '{frequency}'")

        record = {
            "control_id": str(uuid.uuid4()),
            "org_id": org_id,
            "control_name": data["control_name"],
            "framework": framework,
            "control_ref": data.get("control_ref", ""),
            "category": data.get("category", ""),
            "description": data.get("description", ""),
            "control_type": control_type,
            "frequency": frequency,
            "owner": data.get("owner", ""),
            "enabled": int(data.get("enabled", True)),
            "created_at": _now(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO controls
                       (control_id, org_id, control_name, framework, control_ref,
                        category, description, control_type, frequency, owner, enabled, created_at)
                       VALUES (:control_id, :org_id, :control_name, :framework, :control_ref,
                               :category, :description, :control_type, :frequency, :owner, :enabled, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "ccm", "org_id": org_id, "source_engine": "ccm"})
            except Exception:
                pass

        return record

    def list_controls(
        self,
        org_id: str,
        framework: Optional[str] = None,
        control_type: Optional[str] = None,
        enabled_only: bool = True,
    ) -> List[Dict[str, Any]]:
        """List controls for an org with optional filters."""
        query = "SELECT * FROM controls WHERE org_id = ?"
        params: List[Any] = [org_id]
        if framework:
            query += " AND framework = ?"
            params.append(framework)
        if control_type:
            query += " AND control_type = ?"
            params.append(control_type)
        if enabled_only:
            query += " AND enabled = 1"
        query += " ORDER BY framework, control_ref"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def add_test(self, org_id: str, control_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a test definition to a control."""
        # Verify control belongs to org
        with self._lock:
            with self._conn() as conn:
                ctrl = conn.execute(
                    "SELECT * FROM controls WHERE control_id = ? AND org_id = ?",
                    (control_id, org_id),
                ).fetchone()
        if not ctrl:
            raise ValueError(f"Control '{control_id}' not found for org '{org_id}'")

        test_type = data.get("test_type", "automated")
        if test_type not in _VALID_TEST_TYPES:
            raise ValueError(f"Invalid test_type '{test_type}'")

        record = {
            "test_id": str(uuid.uuid4()),
            "org_id": org_id,
            "control_id": control_id,
            "test_name": data["test_name"],
            "test_type": test_type,
            "expected_result": data.get("expected_result", ""),
            "last_run": None,
            "next_run": None,
            "status": "not_tested",
            "evidence": data.get("evidence", ""),
            "created_at": _now(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO control_tests
                       (test_id, org_id, control_id, test_name, test_type,
                        expected_result, last_run, next_run, status, evidence, created_at)
                       VALUES (:test_id, :org_id, :control_id, :test_name, :test_type,
                               :expected_result, :last_run, :next_run, :status, :evidence, :created_at)""",
                    record,
                )
        return record

    def run_test(self, org_id: str, test_id: str) -> Dict[str, Any]:
        """Simulate running a control test.

        Outcome probabilities: 80% passing, 15% failing, 5% degraded.
        Updates last_run, next_run, status, records history snapshot.
        """
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    """SELECT ct.*, c.frequency FROM control_tests ct
                       JOIN controls c ON ct.control_id = c.control_id
                       WHERE ct.test_id = ? AND ct.org_id = ?""",
                    (test_id, org_id),
                ).fetchone()
        if not row:
            raise ValueError(f"Test '{test_id}' not found for org '{org_id}'")

        # Simulate outcome
        rand = random.random()
        if rand < 0.80:
            new_status = "passing"
        elif rand < 0.95:
            new_status = "failing"
        else:
            new_status = "degraded"

        now_dt = datetime.now(timezone.utc)
        now_str = now_dt.isoformat()
        frequency = row["frequency"]
        delta = _FREQUENCY_DELTA.get(frequency, timedelta(days=30))
        next_run_str = (now_dt + delta).isoformat()

        evidence_snapshot = json.dumps({
            "test_name": row["test_name"],
            "status": new_status,
            "run_at": now_str,
            "expected_result": row["expected_result"],
        })

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE control_tests
                       SET status = ?, last_run = ?, next_run = ?
                       WHERE test_id = ? AND org_id = ?""",
                    (new_status, now_str, next_run_str, test_id, org_id),
                )
                # Record history
                conn.execute(
                    """INSERT INTO control_history
                       (history_id, org_id, control_id, recorded_at, status, evidence_snapshot)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (str(uuid.uuid4()), org_id, row["control_id"],
                     now_str, new_status, evidence_snapshot),
                )

        return {
            "test_id": test_id,
            "org_id": org_id,
            "control_id": row["control_id"],
            "status": new_status,
            "last_run": now_str,
            "next_run": next_run_str,
            "evidence_snapshot": evidence_snapshot,
        }

    def list_tests(
        self,
        org_id: str,
        control_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List tests for an org with optional filters."""
        query = "SELECT * FROM control_tests WHERE org_id = ?"
        params: List[Any] = [org_id]
        if control_id:
            query += " AND control_id = ?"
            params.append(control_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Failures
    # ------------------------------------------------------------------

    def log_failure(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log a control failure."""
        failure_type = data.get("failure_type", "gap")
        if failure_type not in _VALID_FAILURE_TYPES:
            raise ValueError(f"Invalid failure_type '{failure_type}'")
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'")

        record = {
            "failure_id": str(uuid.uuid4()),
            "org_id": org_id,
            "control_id": data["control_id"],
            "test_id": data.get("test_id"),
            "failure_type": failure_type,
            "severity": severity,
            "description": data.get("description", ""),
            "detected_at": data.get("detected_at", _now()),
            "remediated_at": None,
            "remediation_notes": "",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO control_failures
                       (failure_id, org_id, control_id, test_id, failure_type, severity,
                        description, detected_at, remediated_at, remediation_notes)
                       VALUES (:failure_id, :org_id, :control_id, :test_id, :failure_type,
                               :severity, :description, :detected_at, :remediated_at, :remediation_notes)""",
                    record,
                )
        return record

    def remediate_failure(self, org_id: str, failure_id: str, notes: str) -> bool:
        """Mark a failure as remediated."""
        with self._lock:
            with self._conn() as conn:
                result = conn.execute(
                    """UPDATE control_failures
                       SET remediated_at = ?, remediation_notes = ?
                       WHERE failure_id = ? AND org_id = ? AND remediated_at IS NULL""",
                    (_now(), notes, failure_id, org_id),
                )
        return result.rowcount > 0

    def list_failures(
        self,
        org_id: str,
        remediated: bool = False,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List failures for an org."""
        query = "SELECT * FROM control_failures WHERE org_id = ?"
        params: List[Any] = [org_id]
        if remediated:
            query += " AND remediated_at IS NOT NULL"
        else:
            query += " AND remediated_at IS NULL"
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY detected_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Coverage & Stats
    # ------------------------------------------------------------------

    def get_control_coverage(self, org_id: str) -> Dict[str, Any]:
        """Compute control coverage across frameworks."""
        with self._lock:
            with self._conn() as conn:
                # Total enabled controls
                total_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM controls WHERE org_id = ? AND enabled = 1",
                    (org_id,),
                ).fetchone()
                total_controls = total_row["cnt"] if total_row else 0

                # Per-framework breakdown via tests
                framework_rows = conn.execute(
                    """SELECT c.framework,
                              COUNT(DISTINCT c.control_id) as total,
                              COUNT(DISTINCT CASE WHEN ct.status = 'passing' THEN ct.control_id END) as passing,
                              COUNT(DISTINCT CASE WHEN ct.status = 'failing' THEN ct.control_id END) as failing
                       FROM controls c
                       LEFT JOIN control_tests ct ON c.control_id = ct.control_id AND ct.org_id = c.org_id
                       WHERE c.org_id = ? AND c.enabled = 1
                       GROUP BY c.framework""",
                    (org_id,),
                ).fetchall()

                # Overall pass rate from tests
                pass_row = conn.execute(
                    """SELECT
                         COUNT(*) as total_tests,
                         SUM(CASE WHEN status = 'passing' THEN 1 ELSE 0 END) as passing_tests
                       FROM control_tests WHERE org_id = ?""",
                    (org_id,),
                ).fetchone()

                # Untested controls (no tests or all tests not_tested)
                untested_row = conn.execute(
                    """SELECT COUNT(DISTINCT c.control_id) as cnt
                       FROM controls c
                       WHERE c.org_id = ? AND c.enabled = 1
                         AND NOT EXISTS (
                             SELECT 1 FROM control_tests ct
                             WHERE ct.control_id = c.control_id
                               AND ct.org_id = c.org_id
                               AND ct.status != 'not_tested'
                         )""",
                    (org_id,),
                ).fetchone()

                # Critical failures (open)
                crit_row = conn.execute(
                    """SELECT COUNT(*) as cnt FROM control_failures
                       WHERE org_id = ? AND severity = 'critical' AND remediated_at IS NULL""",
                    (org_id,),
                ).fetchone()

        by_framework: Dict[str, Any] = {}
        for r in framework_rows:
            by_framework[r["framework"]] = {
                "total": r["total"],
                "passing": r["passing"],
                "failing": r["failing"],
            }

        total_tests = pass_row["total_tests"] if pass_row else 0
        passing_tests = pass_row["passing_tests"] if pass_row else 0
        overall_pass_rate = (passing_tests / total_tests * 100.0) if total_tests > 0 else 0.0

        return {
            "total_controls": total_controls,
            "by_framework": by_framework,
            "overall_pass_rate": round(overall_pass_rate, 2),
            "untested_controls": untested_row["cnt"] if untested_row else 0,
            "critical_failures": crit_row["cnt"] if crit_row else 0,
        }

    def get_ccm_stats(self, org_id: str) -> Dict[str, Any]:
        """Return high-level CCM statistics for an org."""
        with self._lock:
            with self._conn() as conn:
                ctrl_row = conn.execute(
                    """SELECT
                         COUNT(*) as total_controls,
                         SUM(enabled) as enabled_controls
                       FROM controls WHERE org_id = ?""",
                    (org_id,),
                ).fetchone()

                test_row = conn.execute(
                    """SELECT
                         COUNT(*) as total_tests,
                         SUM(CASE WHEN status = 'passing' THEN 1 ELSE 0 END) as passing_tests,
                         SUM(CASE WHEN status = 'failing' THEN 1 ELSE 0 END) as failing_tests
                       FROM control_tests WHERE org_id = ?""",
                    (org_id,),
                ).fetchone()

                fail_row = conn.execute(
                    """SELECT
                         COUNT(*) as open_failures,
                         SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_failures
                       FROM control_failures
                       WHERE org_id = ? AND remediated_at IS NULL""",
                    (org_id,),
                ).fetchone()

        total_tests = test_row["total_tests"] if test_row else 0
        passing_tests = test_row["passing_tests"] if test_row else 0
        coverage_pct = (passing_tests / total_tests * 100.0) if total_tests > 0 else 0.0

        return {
            "total_controls": ctrl_row["total_controls"] if ctrl_row else 0,
            "enabled_controls": ctrl_row["enabled_controls"] if ctrl_row else 0,
            "total_tests": total_tests,
            "passing_tests": passing_tests,
            "failing_tests": test_row["failing_tests"] if test_row else 0,
            "open_failures": fail_row["open_failures"] if fail_row else 0,
            "critical_failures": fail_row["critical_failures"] if fail_row else 0,
            "coverage_pct": round(coverage_pct, 2),
        }


# Module-level singleton
_engine: Optional[CCMEngine] = None


def get_engine() -> CCMEngine:
    global _engine
    if _engine is None:
        _engine = CCMEngine()
    return _engine
