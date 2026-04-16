"""Endpoint Compliance Engine — ALDECI.

CIS benchmark compliance for endpoints (Windows / Linux / macOS / mobile).

Capabilities:
  - Endpoint registry with OS type and department tracking
  - Compliance check recording per CIS benchmark / DISA STIG
  - Bulk check ingestion for scanner integration
  - Compliance exception workflow
  - Baseline management (target score per OS + benchmark)
  - Stats aggregation and per-department compliance rates

Compliance: CIS Benchmarks L1/L2 (Windows, Ubuntu, RHEL, macOS), DISA STIG
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

_VALID_OS_TYPES = {"windows", "linux", "macos", "android", "ios"}
_VALID_COMPLIANCE_LEVELS = {"compliant", "partial", "non_compliant"}
_VALID_BENCHMARKS = {
    "cis_windows_l1", "cis_windows_l2", "cis_ubuntu", "cis_rhel",
    "cis_macos", "stig_win", "disa_stig",
}
_VALID_CATEGORIES = {
    "account_policy", "local_policy", "event_log", "registry",
    "service", "network", "firewall", "application",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_CHECK_STATUSES = {"passed", "failed", "not_applicable", "error"}

# Weight map for score computation (higher weight = more impact on score)
_SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path_for_org(org_id: str) -> str:
    base = Path(__file__).resolve().parents[2] / ".fixops_data"
    return str(base / f"{org_id}_endpoint_compliance.db")


class EndpointComplianceEngine:
    """SQLite WAL-backed endpoint compliance engine.

    Thread-safe via RLock. Multi-tenant via org_id — each org gets its own DB.
    """

    def __init__(self, db_path: str) -> None:
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
                CREATE TABLE IF NOT EXISTS endpoints (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    hostname            TEXT NOT NULL,
                    os_type             TEXT NOT NULL DEFAULT 'linux',
                    os_version          TEXT NOT NULL DEFAULT '',
                    department          TEXT NOT NULL DEFAULT '',
                    owner_id            TEXT NOT NULL DEFAULT '',
                    last_scan           DATETIME,
                    compliance_score    REAL NOT NULL DEFAULT 0.0,
                    compliance_level    TEXT NOT NULL DEFAULT 'non_compliant',
                    critical_failures   INTEGER NOT NULL DEFAULT 0,
                    high_failures       INTEGER NOT NULL DEFAULT 0,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ep_org_level
                    ON endpoints (org_id, compliance_level);

                CREATE INDEX IF NOT EXISTS idx_ep_org_dept
                    ON endpoints (org_id, department);

                CREATE TABLE IF NOT EXISTS compliance_checks (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    endpoint_id         TEXT NOT NULL,
                    benchmark           TEXT NOT NULL DEFAULT 'cis_windows_l1',
                    check_id            TEXT NOT NULL,
                    check_name          TEXT NOT NULL DEFAULT '',
                    category            TEXT NOT NULL DEFAULT 'local_policy',
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    status              TEXT NOT NULL DEFAULT 'failed',
                    actual_value        TEXT NOT NULL DEFAULT '',
                    expected_value      TEXT NOT NULL DEFAULT '',
                    remediation         TEXT NOT NULL DEFAULT '',
                    scanned_at          DATETIME NOT NULL,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cc_org_endpoint
                    ON compliance_checks (org_id, endpoint_id, scanned_at DESC);

                CREATE INDEX IF NOT EXISTS idx_cc_org_status
                    ON compliance_checks (org_id, status, severity);

                CREATE TABLE IF NOT EXISTS compliance_exceptions (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    endpoint_id         TEXT NOT NULL,
                    check_id            TEXT NOT NULL,
                    reason              TEXT NOT NULL DEFAULT '',
                    approved_by         TEXT NOT NULL DEFAULT '',
                    expires_at          TEXT NOT NULL DEFAULT '',
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ce_org_endpoint
                    ON compliance_exceptions (org_id, endpoint_id);

                CREATE TABLE IF NOT EXISTS compliance_baselines (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    baseline_name       TEXT NOT NULL,
                    os_type             TEXT NOT NULL DEFAULT 'linux',
                    benchmark           TEXT NOT NULL,
                    required_checks     TEXT NOT NULL DEFAULT '[]',
                    target_score        REAL NOT NULL DEFAULT 80.0,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cb_org_os
                    ON compliance_baselines (org_id, os_type);
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
    # Helpers
    # ------------------------------------------------------------------

    def _recompute_endpoint_score(self, org_id: str, endpoint_id: str) -> None:
        """Recompute weighted compliance score and update the endpoint record."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT severity, status, COUNT(*) as cnt
                   FROM compliance_checks
                   WHERE org_id = ? AND endpoint_id = ?
                     AND status IN ('passed', 'failed')
                   GROUP BY severity, status""",
                (org_id, endpoint_id),
            ).fetchall()

        total_weight = 0
        passed_weight = 0
        crit_fail = 0
        high_fail = 0

        for r in rows:
            w = _SEVERITY_WEIGHTS.get(r["severity"], 1)
            weight = w * r["cnt"]
            total_weight += weight
            if r["status"] == "passed":
                passed_weight += weight
            else:
                if r["severity"] == "critical":
                    crit_fail += r["cnt"]
                elif r["severity"] == "high":
                    high_fail += r["cnt"]

        score = round((passed_weight / total_weight) * 100.0, 2) if total_weight > 0 else 0.0

        if score >= 90.0:
            level = "compliant"
        elif score >= 60.0:
            level = "partial"
        else:
            level = "non_compliant"

        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE endpoints
                       SET compliance_score = ?, compliance_level = ?,
                           critical_failures = ?, high_failures = ?,
                           last_scan = ?
                       WHERE org_id = ? AND id = ?""",
                    (score, level, crit_fail, high_fail, now, org_id, endpoint_id),
                )

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    def register_endpoint(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new endpoint."""
        hostname = (data.get("hostname") or "").strip()
        if not hostname:
            raise ValueError("hostname is required.")

        os_type = data.get("os_type", "linux")
        if os_type not in _VALID_OS_TYPES:
            raise ValueError(f"Invalid os_type: {os_type}. Must be one of {_VALID_OS_TYPES}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "hostname": hostname,
            "os_type": os_type,
            "os_version": data.get("os_version", ""),
            "department": data.get("department", ""),
            "owner_id": data.get("owner_id", ""),
            "last_scan": None,
            "compliance_score": 0.0,
            "compliance_level": "non_compliant",
            "critical_failures": 0,
            "high_failures": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO endpoints
                       (id, org_id, hostname, os_type, os_version, department,
                        owner_id, last_scan, compliance_score, compliance_level,
                        critical_failures, high_failures, created_at)
                       VALUES (:id, :org_id, :hostname, :os_type, :os_version, :department,
                               :owner_id, :last_scan, :compliance_score, :compliance_level,
                               :critical_failures, :high_failures, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "endpoint_compliance", "org_id": org_id, "source_engine": "endpoint_compliance"})
            except Exception:
                pass

        return record

    def list_endpoints(
        self,
        org_id: str,
        compliance_level: Optional[str] = None,
        os_type: Optional[str] = None,
        department: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List endpoints with optional filters."""
        sql = "SELECT * FROM endpoints WHERE org_id = ?"
        params: list = [org_id]
        if compliance_level:
            sql += " AND compliance_level = ?"
            params.append(compliance_level)
        if os_type:
            sql += " AND os_type = ?"
            params.append(os_type)
        if department:
            sql += " AND department = ?"
            params.append(department)
        sql += " ORDER BY compliance_score ASC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_endpoint(self, org_id: str, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Return endpoint with a check summary."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM endpoints WHERE org_id = ? AND id = ?",
                (org_id, endpoint_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)

            # Summary by benchmark + status
            sum_rows = conn.execute(
                """SELECT benchmark, status, COUNT(*) as cnt
                   FROM compliance_checks
                   WHERE org_id = ? AND endpoint_id = ?
                   GROUP BY benchmark, status""",
                (org_id, endpoint_id),
            ).fetchall()
            summary: Dict[str, Any] = {}
            for sr in sum_rows:
                key = f"{sr['benchmark']}_{sr['status']}"
                summary[key] = sr["cnt"]
            result["check_summary"] = summary
        return result

    # ------------------------------------------------------------------
    # Compliance checks
    # ------------------------------------------------------------------

    def record_check(
        self, org_id: str, endpoint_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a single compliance check and recompute endpoint score."""
        check_id = (data.get("check_id") or "").strip()
        if not check_id:
            raise ValueError("check_id is required.")

        status = data.get("status", "failed")
        if status not in _VALID_CHECK_STATUSES:
            raise ValueError(f"Invalid status: {status}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        benchmark = data.get("benchmark", "cis_windows_l1")
        if benchmark not in _VALID_BENCHMARKS:
            raise ValueError(f"Invalid benchmark: {benchmark}")

        category = data.get("category", "local_policy")
        if category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid category: {category}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "endpoint_id": endpoint_id,
            "benchmark": benchmark,
            "check_id": check_id,
            "check_name": data.get("check_name", ""),
            "category": category,
            "severity": severity,
            "status": status,
            "actual_value": data.get("actual_value", ""),
            "expected_value": data.get("expected_value", ""),
            "remediation": data.get("remediation", ""),
            "scanned_at": data.get("scanned_at", now),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO compliance_checks
                       (id, org_id, endpoint_id, benchmark, check_id, check_name,
                        category, severity, status, actual_value, expected_value,
                        remediation, scanned_at, created_at)
                       VALUES (:id, :org_id, :endpoint_id, :benchmark, :check_id, :check_name,
                               :category, :severity, :status, :actual_value, :expected_value,
                               :remediation, :scanned_at, :created_at)""",
                    record,
                )
        self._recompute_endpoint_score(org_id, endpoint_id)
        return record

    def bulk_record_checks(
        self, org_id: str, endpoint_id: str, checks_list: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Batch-record compliance checks. Returns list of created records."""
        results = []
        now = _now_iso()
        records_to_insert = []

        for data in checks_list:
            check_id = (data.get("check_id") or "").strip()
            if not check_id:
                continue
            status = data.get("status", "failed")
            if status not in _VALID_CHECK_STATUSES:
                status = "failed"
            severity = data.get("severity", "medium")
            if severity not in _VALID_SEVERITIES:
                severity = "medium"
            benchmark = data.get("benchmark", "cis_windows_l1")
            if benchmark not in _VALID_BENCHMARKS:
                benchmark = "cis_windows_l1"
            category = data.get("category", "local_policy")
            if category not in _VALID_CATEGORIES:
                category = "local_policy"

            record = {
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "endpoint_id": endpoint_id,
                "benchmark": benchmark,
                "check_id": check_id,
                "check_name": data.get("check_name", ""),
                "category": category,
                "severity": severity,
                "status": status,
                "actual_value": data.get("actual_value", ""),
                "expected_value": data.get("expected_value", ""),
                "remediation": data.get("remediation", ""),
                "scanned_at": data.get("scanned_at", now),
                "created_at": now,
            }
            records_to_insert.append(record)
            results.append(record)

        if records_to_insert:
            with self._lock:
                with self._conn() as conn:
                    conn.executemany(
                        """INSERT INTO compliance_checks
                           (id, org_id, endpoint_id, benchmark, check_id, check_name,
                            category, severity, status, actual_value, expected_value,
                            remediation, scanned_at, created_at)
                           VALUES (:id, :org_id, :endpoint_id, :benchmark, :check_id, :check_name,
                                   :category, :severity, :status, :actual_value, :expected_value,
                                   :remediation, :scanned_at, :created_at)""",
                        records_to_insert,
                    )
            self._recompute_endpoint_score(org_id, endpoint_id)

        return results

    def list_checks(
        self,
        org_id: str,
        endpoint_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        benchmark: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List compliance checks with optional filters."""
        sql = "SELECT * FROM compliance_checks WHERE org_id = ?"
        params: list = [org_id]
        if endpoint_id:
            sql += " AND endpoint_id = ?"
            params.append(endpoint_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if benchmark:
            sql += " AND benchmark = ?"
            params.append(benchmark)
        sql += " ORDER BY scanned_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Exceptions
    # ------------------------------------------------------------------

    def add_exception(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a compliance exception for an endpoint check."""
        endpoint_id = (data.get("endpoint_id") or "").strip()
        check_id = (data.get("check_id") or "").strip()
        if not endpoint_id or not check_id:
            raise ValueError("endpoint_id and check_id are required.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "endpoint_id": endpoint_id,
            "check_id": check_id,
            "reason": data.get("reason", ""),
            "approved_by": data.get("approved_by", ""),
            "expires_at": data.get("expires_at", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO compliance_exceptions
                       (id, org_id, endpoint_id, check_id, reason, approved_by,
                        expires_at, created_at)
                       VALUES (:id, :org_id, :endpoint_id, :check_id, :reason, :approved_by,
                               :expires_at, :created_at)""",
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Baselines
    # ------------------------------------------------------------------

    def create_baseline(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a compliance baseline definition."""
        name = (data.get("baseline_name") or "").strip()
        if not name:
            raise ValueError("baseline_name is required.")

        os_type = data.get("os_type", "linux")
        if os_type not in _VALID_OS_TYPES:
            raise ValueError(f"Invalid os_type: {os_type}")

        benchmark = data.get("benchmark", "cis_ubuntu")
        if benchmark not in _VALID_BENCHMARKS:
            raise ValueError(f"Invalid benchmark: {benchmark}")

        required_checks = data.get("required_checks", [])
        if not isinstance(required_checks, list):
            required_checks = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "baseline_name": name,
            "os_type": os_type,
            "benchmark": benchmark,
            "required_checks": json.dumps(required_checks),
            "target_score": float(data.get("target_score", 80.0)),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO compliance_baselines
                       (id, org_id, baseline_name, os_type, benchmark,
                        required_checks, target_score, created_at)
                       VALUES (:id, :org_id, :baseline_name, :os_type, :benchmark,
                               :required_checks, :target_score, :created_at)""",
                    record,
                )
        record["required_checks"] = required_checks
        return record

    def list_baselines(self, org_id: str) -> List[Dict[str, Any]]:
        """List all compliance baselines for org."""
        with self._conn() as conn:
            rows = [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM compliance_baselines WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            ]
        for r in rows:
            try:
                r["required_checks"] = json.loads(r["required_checks"])
            except Exception:
                r["required_checks"] = []
        return rows

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_endpoint_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated endpoint compliance statistics."""
        with self._conn() as conn:
            total_endpoints = conn.execute(
                "SELECT COUNT(*) FROM endpoints WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            level_rows = conn.execute(
                """SELECT compliance_level, COUNT(*) as cnt
                   FROM endpoints WHERE org_id = ? GROUP BY compliance_level""",
                (org_id,),
            ).fetchall()
            by_compliance_level = {r["compliance_level"]: r["cnt"] for r in level_rows}

            os_rows = conn.execute(
                """SELECT os_type, COUNT(*) as cnt
                   FROM endpoints WHERE org_id = ? GROUP BY os_type""",
                (org_id,),
            ).fetchall()
            by_os_type = {r["os_type"]: r["cnt"] for r in os_rows}

            avg_score_row = conn.execute(
                "SELECT AVG(compliance_score) FROM endpoints WHERE org_id = ?", (org_id,)
            ).fetchone()
            avg_compliance_score = round(avg_score_row[0] or 0.0, 2)

            # Endpoints below their baseline target score (use 80 as default)
            endpoints_below_target = conn.execute(
                "SELECT COUNT(*) FROM endpoints WHERE org_id = ? AND compliance_score < 80.0",
                (org_id,),
            ).fetchone()[0]

            critical_failures_total = conn.execute(
                "SELECT COALESCE(SUM(critical_failures), 0) FROM endpoints WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            compliant_count = by_compliance_level.get("compliant", 0)
            compliant_rate = (
                round((compliant_count / total_endpoints) * 100.0, 2)
                if total_endpoints > 0
                else 0.0
            )

        return {
            "total_endpoints": total_endpoints,
            "by_compliance_level": by_compliance_level,
            "by_os_type": by_os_type,
            "avg_compliance_score": avg_compliance_score,
            "endpoints_below_target": endpoints_below_target,
            "critical_failures_total": critical_failures_total,
            "compliant_rate": compliant_rate,
        }

    def get_department_compliance(self, org_id: str) -> List[Dict[str, Any]]:
        """Return per-department compliance rates."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT
                     department,
                     COUNT(*) as total,
                     AVG(compliance_score) as avg_score,
                     SUM(CASE WHEN compliance_level = 'compliant' THEN 1 ELSE 0 END) as compliant,
                     SUM(CASE WHEN compliance_level = 'partial' THEN 1 ELSE 0 END) as partial,
                     SUM(CASE WHEN compliance_level = 'non_compliant' THEN 1 ELSE 0 END) as non_compliant,
                     COALESCE(SUM(critical_failures), 0) as critical_failures
                   FROM endpoints
                   WHERE org_id = ?
                   GROUP BY department
                   ORDER BY avg_score ASC""",
                (org_id,),
            ).fetchall()

        result = []
        for r in rows:
            total = r["total"] or 0
            compliant = r["compliant"] or 0
            result.append({
                "department": r["department"] or "unassigned",
                "total_endpoints": total,
                "avg_compliance_score": round(r["avg_score"] or 0.0, 2),
                "compliant": compliant,
                "partial": r["partial"] or 0,
                "non_compliant": r["non_compliant"] or 0,
                "compliant_rate": round((compliant / total) * 100.0, 2) if total > 0 else 0.0,
                "critical_failures": r["critical_failures"] or 0,
            })
        return result


# ---------------------------------------------------------------------------
# Per-org singleton cache
# ---------------------------------------------------------------------------
_instances: Dict[str, EndpointComplianceEngine] = {}
_instances_lock = threading.Lock()


def get_engine(org_id: str) -> EndpointComplianceEngine:
    """Return (or create) an EndpointComplianceEngine instance for org_id."""
    with _instances_lock:
        if org_id not in _instances:
            _instances[org_id] = EndpointComplianceEngine(db_path=_db_path_for_org(org_id))
        return _instances[org_id]
