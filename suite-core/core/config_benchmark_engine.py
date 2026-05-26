"""
Security Configuration Benchmark Engine — ALDECI.

STATUS: STUB — profile and check CRUD are production-ready (SQLite WAL).
The core run_assessment() method is NOT production-ready: it generates
seeded-random pass/fail outcomes instead of real CIS-CAT / OpenSCAP output.
Customers must NOT be shown assessment results.

To make real: integrate CIS-CAT Pro, OpenSCAP, Lynis, or cloud-native
benchmark tools via /api/v1/connectors/config-benchmark/configure. Set
CONFIG_BENCHMARK_CONNECTOR_URL env var to enable. Until wired,
run_assessment() raises NotImplementedError.

Manages CIS/DISA-STIG/NIST 800-53/PCI-DSS benchmark profiles and checks,
runs mock assessments, and tracks compliance scores.

Thread-safe via RLock. Multi-tenant via org_id.
"""

from __future__ import annotations

import logging
import random
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
_logger.warning(
    "⚠️  %s: run_assessment() is STUB — results are seeded-random. "
    "Set CONFIG_BENCHMARK_CONNECTOR_URL to enable real CIS-CAT/OpenSCAP scanning. "
    "Profile and check CRUD are production-ready.",
    __name__,
)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "config_benchmark.db"
)

_VALID_STANDARDS = {"CIS", "DISA_STIG", "NIST_800_53", "PCI_DSS_HW", "custom"}
_VALID_TARGET_TYPES = {
    "linux_server", "windows_server", "network_device",
    "kubernetes", "docker", "aws", "azure",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_STATUSES = {"pass", "fail", "warning", "not_applicable"}

# Mock assessment: ~65% pass rate base
_BASE_PASS_RATE = 0.65


class ConfigBenchmarkEngine:
    """SQLite WAL-backed security configuration benchmark engine.

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
                CREATE TABLE IF NOT EXISTS benchmark_profiles (
                    profile_id  TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    standard    TEXT NOT NULL DEFAULT 'CIS',
                    target_type TEXT NOT NULL DEFAULT 'linux_server',
                    version     TEXT NOT NULL DEFAULT '1.0',
                    created_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_profile_org
                    ON benchmark_profiles (org_id, standard);

                CREATE TABLE IF NOT EXISTS benchmark_checks (
                    check_id       TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    profile_id     TEXT NOT NULL,
                    check_ref      TEXT NOT NULL,
                    title          TEXT NOT NULL,
                    description    TEXT NOT NULL DEFAULT '',
                    category       TEXT NOT NULL DEFAULT '',
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    expected_value TEXT NOT NULL DEFAULT '',
                    remediation    TEXT NOT NULL DEFAULT '',
                    created_at     DATETIME NOT NULL,
                    FOREIGN KEY (profile_id) REFERENCES benchmark_profiles(profile_id)
                );

                CREATE INDEX IF NOT EXISTS idx_check_org_profile
                    ON benchmark_checks (org_id, profile_id, severity);

                CREATE TABLE IF NOT EXISTS assessment_results (
                    result_id      TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    profile_id     TEXT NOT NULL,
                    target_name    TEXT NOT NULL,
                    assessed_at    DATETIME NOT NULL,
                    passed         INTEGER NOT NULL DEFAULT 0,
                    failed         INTEGER NOT NULL DEFAULT 0,
                    warnings       INTEGER NOT NULL DEFAULT 0,
                    not_applicable INTEGER NOT NULL DEFAULT 0,
                    score          REAL NOT NULL DEFAULT 0.0,
                    status         TEXT NOT NULL DEFAULT 'fail',
                    FOREIGN KEY (profile_id) REFERENCES benchmark_profiles(profile_id)
                );

                CREATE INDEX IF NOT EXISTS idx_result_org
                    ON assessment_results (org_id, profile_id, assessed_at DESC);

                CREATE TABLE IF NOT EXISTS check_results (
                    cr_id        TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    result_id    TEXT NOT NULL,
                    check_id     TEXT NOT NULL,
                    actual_value TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT 'fail',
                    notes        TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (result_id) REFERENCES assessment_results(result_id),
                    FOREIGN KEY (check_id) REFERENCES benchmark_checks(check_id)
                );

                CREATE INDEX IF NOT EXISTS idx_cr_result
                    ON check_results (org_id, result_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Profiles
    # ------------------------------------------------------------------

    def create_profile(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new benchmark profile."""
        profile_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        standard = str(data.get("standard", "CIS"))
        if standard not in _VALID_STANDARDS:
            standard = "custom"
        target_type = str(data.get("target_type", "linux_server"))
        if target_type not in _VALID_TARGET_TYPES:
            target_type = "linux_server"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO benchmark_profiles
                        (profile_id, org_id, name, standard, target_type, version, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        profile_id,
                        org_id,
                        str(data.get("name", "Unnamed Profile")),
                        standard,
                        target_type,
                        str(data.get("version", "1.0")),
                        now,
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "config_benchmark", "org_id": org_id, "source_engine": "config_benchmark"})
            except Exception:
                pass

        return {
            "profile_id": profile_id,
            "org_id": org_id,
            "name": data.get("name", "Unnamed Profile"),
            "standard": standard,
            "target_type": target_type,
            "version": data.get("version", "1.0"),
            "created_at": now,
        }

    def list_profiles(self, org_id: str, standard: Optional[str] = None) -> List[Dict[str, Any]]:
        """List profiles for an org, optionally filtered by standard."""
        if standard:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM benchmark_profiles WHERE org_id=? AND standard=? ORDER BY created_at DESC",
                    (org_id, standard),
                ).fetchall()
        else:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM benchmark_profiles WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def add_check(self, org_id: str, profile_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a benchmark check to a profile."""
        check_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        severity = str(data.get("severity", "medium")).lower()
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO benchmark_checks
                        (check_id, org_id, profile_id, check_ref, title, description,
                         category, severity, expected_value, remediation, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        check_id,
                        org_id,
                        profile_id,
                        str(data.get("check_ref", f"CHECK-{check_id[:8].upper()}")),
                        str(data.get("title", "Unnamed Check")),
                        str(data.get("description", "")),
                        str(data.get("category", "")),
                        severity,
                        str(data.get("expected_value", "")),
                        str(data.get("remediation", "")),
                        now,
                    ),
                )
        return {
            "check_id": check_id,
            "org_id": org_id,
            "profile_id": profile_id,
            **{k: data.get(k, "") for k in ("check_ref", "title", "description", "category", "expected_value", "remediation")},
            "severity": severity,
            "created_at": now,
        }

    def list_checks(
        self, org_id: str, profile_id: str, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List checks for a profile, optionally filtered by severity."""
        if severity:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM benchmark_checks WHERE org_id=? AND profile_id=? AND severity=? ORDER BY check_ref",
                    (org_id, profile_id, severity),
                ).fetchall()
        else:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM benchmark_checks WHERE org_id=? AND profile_id=? ORDER BY check_ref",
                    (org_id, profile_id),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------

    def run_assessment(self, org_id: str, profile_id: str, target_name: str) -> Dict[str, Any]:
        """Run a real benchmark assessment via CIS-CAT Pro / OpenSCAP.

        Requires a benchmark connector configured via
        /api/v1/connectors/config-benchmark/configure. Raises NotImplementedError
        until CONFIG_BENCHMARK_CONNECTOR_URL env var is set, to prevent
        seeded-random pass/fail outcomes from reaching customers.

        Profile CRUD, check definitions, get_assessment(), list_assessments(),
        get_failed_checks(), and get_benchmark_stats() are production-ready.
        """
        import os
        if not os.environ.get("CONFIG_BENCHMARK_CONNECTOR_URL"):
            raise NotImplementedError(
                "run_assessment() requires a real benchmark scanner (CIS-CAT Pro, "
                "OpenSCAP, Lynis, or cloud-native benchmark APIs). "
                "Configure via /api/v1/connectors/config-benchmark/configure and set "
                "CONFIG_BENCHMARK_CONNECTOR_URL env var. "
                "Profile and check CRUD work now — add checks, then run via real scanner."
            )
        raise NotImplementedError(
            "run_assessment() benchmark connector integration not yet implemented."
        )

    def get_assessment(self, org_id: str, result_id: str) -> Dict[str, Any]:
        """Return assessment with embedded check_results."""
        with self._conn() as conn:
            result_row = conn.execute(
                "SELECT * FROM assessment_results WHERE result_id=? AND org_id=?",
                (result_id, org_id),
            ).fetchone()
            if not result_row:
                return {}
            cr_rows = conn.execute(
                "SELECT * FROM check_results WHERE result_id=? AND org_id=? ORDER BY status",
                (result_id, org_id),
            ).fetchall()

        result = self._row_to_dict(result_row)
        result["check_results"] = [self._row_to_dict(r) for r in cr_rows]
        return result

    def list_assessments(self, org_id: str, profile_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List assessments, optionally filtered by profile."""
        if profile_id:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM assessment_results WHERE org_id=? AND profile_id=? ORDER BY assessed_at DESC",
                    (org_id, profile_id),
                ).fetchall()
        else:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM assessment_results WHERE org_id=? ORDER BY assessed_at DESC",
                    (org_id,),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_failed_checks(self, org_id: str, result_id: str) -> List[Dict[str, Any]]:
        """Return failed check_results with check details joined."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT cr.*, bc.check_ref, bc.title, bc.severity,
                       bc.remediation, bc.category
                FROM check_results cr
                JOIN benchmark_checks bc ON cr.check_id = bc.check_id
                WHERE cr.result_id=? AND cr.org_id=? AND cr.status='fail'
                ORDER BY bc.severity
                """,
                (result_id, org_id),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_benchmark_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate benchmark statistics for an org."""
        with self._conn() as conn:
            profile_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM benchmark_profiles WHERE org_id=?",
                (org_id,),
            ).fetchone()["cnt"]

            assessment_row = conn.execute(
                "SELECT COUNT(*) as cnt, AVG(score) as avg_score FROM assessment_results WHERE org_id=?",
                (org_id,),
            ).fetchone()

            by_standard_rows = conn.execute(
                """
                SELECT bp.standard, COUNT(ar.result_id) as cnt, AVG(ar.score) as avg_score
                FROM benchmark_profiles bp
                LEFT JOIN assessment_results ar ON bp.profile_id = ar.profile_id AND ar.org_id = bp.org_id
                WHERE bp.org_id=?
                GROUP BY bp.standard
                """,
                (org_id,),
            ).fetchall()

            by_target_rows = conn.execute(
                """
                SELECT bp.target_type, COUNT(ar.result_id) as cnt, AVG(ar.score) as avg_score
                FROM benchmark_profiles bp
                LEFT JOIN assessment_results ar ON bp.profile_id = ar.profile_id AND ar.org_id = bp.org_id
                WHERE bp.org_id=?
                GROUP BY bp.target_type
                """,
                (org_id,),
            ).fetchall()

            critical_failures = conn.execute(
                """
                SELECT COUNT(*) as cnt
                FROM check_results cr
                JOIN benchmark_checks bc ON cr.check_id = bc.check_id
                JOIN assessment_results ar ON cr.result_id = ar.result_id
                WHERE ar.org_id=? AND cr.status='fail' AND bc.severity='critical'
                """,
                (org_id,),
            ).fetchone()["cnt"]

        by_standard = {
            r["standard"]: {"assessments": r["cnt"], "avg_score": round(r["avg_score"] or 0.0, 2)}
            for r in by_standard_rows
        }
        by_target_type = {
            r["target_type"]: {"assessments": r["cnt"], "avg_score": round(r["avg_score"] or 0.0, 2)}
            for r in by_target_rows
        }

        return {
            "org_id": org_id,
            "total_profiles": profile_count,
            "total_assessments": assessment_row["cnt"] or 0,
            "avg_score": round(assessment_row["avg_score"] or 0.0, 2),
            "by_standard": by_standard,
            "by_target_type": by_target_type,
            "critical_failures_total": critical_failures or 0,
        }
