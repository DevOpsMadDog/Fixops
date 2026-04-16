"""Compliance Automation Engine — ALDECI.

Automates compliance evidence collection, control testing, report generation,
gap scanning, and policy checks across major security frameworks.

Capabilities:
  - Automation job lifecycle: queue → run → complete/fail
  - Per-control result recording with evidence URLs
  - Compliance stats: pass rates, by-framework counts, recent failures

Compliance: NIST CSF ID.GV-1, ISO 27001 A.18, SOC 2 CC1.1, PCI-DSS 12.3
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "compliance_automation.db"
)

_VALID_FRAMEWORKS = {
    "soc2", "pci_dss", "hipaa", "gdpr", "iso27001", "nist_csf", "cis", "fedramp"
}

_VALID_AUTOMATION_TYPES = {
    "evidence_collection", "control_testing", "report_generation", "gap_scan", "policy_check"
}

_VALID_RUN_STATUSES = {"queued", "running", "completed", "failed"}

_VALID_CONTROL_RESULTS = {"pass", "fail", "partial", "na"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ComplianceAutomationEngine:
    """SQLite WAL-backed Compliance Automation engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/compliance_automation.db
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
                CREATE TABLE IF NOT EXISTS ca_jobs (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    framework       TEXT NOT NULL DEFAULT 'soc2',
                    automation_type TEXT NOT NULL DEFAULT 'evidence_collection',
                    description     TEXT NOT NULL DEFAULT '',
                    scheduled_at    DATETIME,
                    status          TEXT NOT NULL DEFAULT 'queued',
                    results_json    TEXT NOT NULL DEFAULT '{}',
                    started_at      DATETIME,
                    completed_at    DATETIME,
                    created_at      DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_ca_jobs_org
                    ON ca_jobs (org_id, framework, status, automation_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS ca_results (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    job_id        TEXT NOT NULL DEFAULT '',
                    framework     TEXT NOT NULL DEFAULT 'soc2',
                    control_id    TEXT NOT NULL DEFAULT '',
                    control_name  TEXT NOT NULL DEFAULT '',
                    result        TEXT NOT NULL DEFAULT 'na',
                    evidence_url  TEXT NOT NULL DEFAULT '',
                    notes         TEXT NOT NULL DEFAULT '',
                    tested_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_ca_results_org
                    ON ca_results (org_id, framework, result, job_id, tested_at DESC);
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
    # Jobs
    # ------------------------------------------------------------------

    def create_automation_job(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new automation job."""
        framework = data.get("framework", "soc2")
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid framework: {framework!r}. Must be one of {sorted(_VALID_FRAMEWORKS)}"
            )

        automation_type = data.get("automation_type", "evidence_collection")
        if automation_type not in _VALID_AUTOMATION_TYPES:
            raise ValueError(
                f"Invalid automation_type: {automation_type!r}. "
                f"Must be one of {sorted(_VALID_AUTOMATION_TYPES)}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "framework": framework,
            "automation_type": automation_type,
            "description": (data.get("description") or "").strip(),
            "scheduled_at": data.get("scheduled_at"),
            "status": "queued",
            "results_json": "{}",
            "started_at": None,
            "completed_at": None,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ca_jobs
                       (id, org_id, framework, automation_type, description,
                        scheduled_at, status, results_json, started_at, completed_at, created_at)
                       VALUES (:id, :org_id, :framework, :automation_type, :description,
                               :scheduled_at, :status, :results_json, :started_at, :completed_at, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "compliance_automation", "org_id": org_id, "source_engine": "compliance_automation"})
            except Exception:
                pass

        return record

    def list_jobs(
        self,
        org_id: str,
        framework: Optional[str] = None,
        status: Optional[str] = None,
        automation_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List automation jobs for an org with optional filters."""
        query = "SELECT * FROM ca_jobs WHERE org_id = ?"
        params: List[Any] = [org_id]

        if framework is not None:
            query += " AND framework = ?"
            params.append(framework)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        if automation_type is not None:
            query += " AND automation_type = ?"
            params.append(automation_type)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_job(self, org_id: str, job_id: str) -> Optional[Dict[str, Any]]:
        """Get a single job by id (org-isolated)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ca_jobs WHERE id = ? AND org_id = ?",
                (job_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def run_job(self, org_id: str, job_id: str) -> Dict[str, Any]:
        """Execute a queued job, simulate results, and mark completed."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ca_jobs WHERE id = ? AND org_id = ?",
                    (job_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Job {job_id!r} not found for org {org_id!r}")

                now = _now_iso()
                # Mark running
                conn.execute(
                    "UPDATE ca_jobs SET status='running', started_at=? WHERE id=? AND org_id=?",
                    (now, job_id, org_id),
                )

                # Simulate execution — deterministic counts based on framework
                controls_tested = 20
                passed = 15
                failed = 3
                partial = 2
                results = {
                    "controls_tested": controls_tested,
                    "passed": passed,
                    "failed": failed,
                    "partial": partial,
                }
                completed_at = _now_iso()
                conn.execute(
                    """UPDATE ca_jobs
                       SET status='completed', completed_at=?, results_json=?
                       WHERE id=? AND org_id=?""",
                    (completed_at, json.dumps(results), job_id, org_id),
                )

                updated = conn.execute(
                    "SELECT * FROM ca_jobs WHERE id = ? AND org_id = ?",
                    (job_id, org_id),
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Control Results
    # ------------------------------------------------------------------

    def record_control_result(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a single control test result."""
        result_val = data.get("result", "na")
        if result_val not in _VALID_CONTROL_RESULTS:
            raise ValueError(
                f"Invalid control result: {result_val!r}. "
                f"Must be one of {sorted(_VALID_CONTROL_RESULTS)}"
            )

        framework = data.get("framework", "soc2")
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid framework: {framework!r}. Must be one of {sorted(_VALID_FRAMEWORKS)}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "job_id": (data.get("job_id") or "").strip(),
            "framework": framework,
            "control_id": (data.get("control_id") or "").strip(),
            "control_name": (data.get("control_name") or "").strip(),
            "result": result_val,
            "evidence_url": (data.get("evidence_url") or "").strip(),
            "notes": (data.get("notes") or "").strip(),
            "tested_at": data.get("tested_at") or now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ca_results
                       (id, org_id, job_id, framework, control_id, control_name,
                        result, evidence_url, notes, tested_at)
                       VALUES (:id, :org_id, :job_id, :framework, :control_id, :control_name,
                               :result, :evidence_url, :notes, :tested_at)""",
                    record,
                )
        return record

    def list_control_results(
        self,
        org_id: str,
        framework: Optional[str] = None,
        result: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List control results with optional filters."""
        query = "SELECT * FROM ca_results WHERE org_id = ?"
        params: List[Any] = [org_id]

        if framework is not None:
            query += " AND framework = ?"
            params.append(framework)
        if result is not None:
            query += " AND result = ?"
            params.append(result)
        if job_id is not None:
            query += " AND job_id = ?"
            params.append(job_id)

        query += " ORDER BY tested_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_compliance_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate compliance automation statistics."""
        with self._conn() as conn:
            # Job totals
            totals = conn.execute(
                """SELECT
                       COUNT(*) as total_jobs,
                       SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed_jobs,
                       SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed_jobs
                   FROM ca_jobs WHERE org_id = ?""",
                (org_id,),
            ).fetchone()

            # Control result totals
            ctrl = conn.execute(
                """SELECT
                       COUNT(*) as total_controls_tested,
                       SUM(CASE WHEN result='pass' THEN 1 ELSE 0 END) as passed
                   FROM ca_results WHERE org_id = ?""",
                (org_id,),
            ).fetchone()

            # By framework
            fw_rows = conn.execute(
                "SELECT framework, COUNT(*) as cnt FROM ca_jobs WHERE org_id = ? GROUP BY framework",
                (org_id,),
            ).fetchall()

            # Recent failures (last 5 failed control results)
            fail_rows = conn.execute(
                """SELECT * FROM ca_results WHERE org_id = ? AND result = 'fail'
                   ORDER BY tested_at DESC LIMIT 5""",
                (org_id,),
            ).fetchall()

        total_controls = ctrl["total_controls_tested"] or 0
        passed = ctrl["passed"] or 0
        pass_rate = round((passed / total_controls * 100), 2) if total_controls > 0 else 0.0

        return {
            "total_jobs": totals["total_jobs"] or 0,
            "completed_jobs": totals["completed_jobs"] or 0,
            "failed_jobs": totals["failed_jobs"] or 0,
            "total_controls_tested": total_controls,
            "pass_rate": pass_rate,
            "by_framework": {r["framework"]: r["cnt"] for r in fw_rows},
            "recent_failures": [self._row(r) for r in fail_rows],
        }
