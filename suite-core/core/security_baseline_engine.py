"""Security Baseline Engine — ALDECI.

Security configuration baseline management and drift detection.
Supports CIS, NIST, STIG, ISO27001, PCI-DSS, and custom frameworks
with automated compliance assessment and trend tracking.

Compliance: CIS Controls v8, NIST SP 800-53 CM-6, ISO/IEC 27001 A.18.2.2
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_baseline.db"
)

_VALID_TARGET_TYPES = {
    "server", "workstation", "network_device", "cloud_instance",
    "container", "database", "application",
}
_VALID_FRAMEWORKS = {"CIS", "NIST", "STIG", "ISO27001", "PCI-DSS", "custom"}
_VALID_STATUSES = {"draft", "active", "deprecated"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_CONTROL_STATUSES = {"pass", "fail", "skip"}


class SecurityBaselineEngine:
    """SQLite WAL-backed Security Baseline engine.

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
                CREATE TABLE IF NOT EXISTS baselines (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    baseline_name   TEXT NOT NULL,
                    target_type     TEXT NOT NULL DEFAULT 'server',
                    framework       TEXT NOT NULL DEFAULT 'CIS',
                    version         TEXT NOT NULL DEFAULT '1.0',
                    control_count   INTEGER NOT NULL DEFAULT 0,
                    created_by      TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'draft',
                    published_at    TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bl_org_status
                    ON baselines (org_id, status);

                CREATE TABLE IF NOT EXISTS baseline_controls (
                    id              TEXT PRIMARY KEY,
                    baseline_id     TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    control_id      TEXT NOT NULL,
                    control_name    TEXT NOT NULL DEFAULT '',
                    category        TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    expected_value  TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    automated_check INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bc_baseline_org
                    ON baseline_controls (baseline_id, org_id);

                CREATE TABLE IF NOT EXISTS baseline_assessments (
                    id              TEXT PRIMARY KEY,
                    baseline_id     TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    target_name     TEXT NOT NULL DEFAULT '',
                    assessed_at     TEXT NOT NULL,
                    pass_count      INTEGER NOT NULL DEFAULT 0,
                    fail_count      INTEGER NOT NULL DEFAULT 0,
                    skip_count      INTEGER NOT NULL DEFAULT 0,
                    compliance_pct  REAL NOT NULL DEFAULT 0.0,
                    assessed_by     TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ba_baseline_org
                    ON baseline_assessments (baseline_id, org_id, assessed_at);

                CREATE TABLE IF NOT EXISTS assessment_results (
                    id              TEXT PRIMARY KEY,
                    assessment_id   TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    control_id      TEXT NOT NULL,
                    control_name    TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'skip',
                    actual_value    TEXT NOT NULL DEFAULT '',
                    deviation       TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ar_assessment_org
                    ON assessment_results (assessment_id, org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_baseline(
        self,
        org_id: str,
        baseline_name: str,
        target_type: str,
        framework: str,
        version: str,
        created_by: str,
    ) -> Dict[str, Any]:
        """Create a new security baseline in draft status."""
        if target_type not in _VALID_TARGET_TYPES:
            raise ValueError(
                f"Invalid target_type '{target_type}'. Valid: {sorted(_VALID_TARGET_TYPES)}"
            )
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid framework '{framework}'. Valid: {sorted(_VALID_FRAMEWORKS)}"
            )

        baseline_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO baselines
                        (id, org_id, baseline_name, target_type, framework, version,
                         control_count, created_by, status, published_at, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (baseline_id, org_id, baseline_name, target_type, framework, version,
                     0, created_by, "draft", None, now),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM baselines WHERE id = ?", (baseline_id,)
            ).fetchone()
        return self._row(row)

    def add_control(
        self,
        baseline_id: str,
        org_id: str,
        control_id: str,
        control_name: str,
        category: str,
        description: str,
        expected_value: str,
        severity: str,
        automated_check: bool = False,
    ) -> Dict[str, Any]:
        """Add a control to a baseline and increment the control_count."""
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. Valid: {sorted(_VALID_SEVERITIES)}"
            )

        # Verify baseline belongs to org
        with self._conn() as conn:
            bl_row = conn.execute(
                "SELECT id FROM baselines WHERE id = ? AND org_id = ?",
                (baseline_id, org_id),
            ).fetchone()
        if bl_row is None:
            raise KeyError(f"Baseline '{baseline_id}' not found for org '{org_id}'")

        ctrl_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO baseline_controls
                        (id, baseline_id, org_id, control_id, control_name, category,
                         description, expected_value, severity, automated_check, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (ctrl_id, baseline_id, org_id, control_id, control_name, category,
                     description, expected_value, severity, 1 if automated_check else 0, now),
                )
                conn.execute(
                    "UPDATE baselines SET control_count = control_count + 1 WHERE id = ? AND org_id = ?",
                    (baseline_id, org_id),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM baseline_controls WHERE id = ?", (ctrl_id,)
            ).fetchone()
        return self._row(row)

    def publish_baseline(self, baseline_id: str, org_id: str) -> Dict[str, Any]:
        """Publish a baseline (status=active, published_at=now)."""
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM baselines WHERE id = ? AND org_id = ?",
                    (baseline_id, org_id),
                ).fetchone()
                if row is None:
                    raise KeyError(f"Baseline '{baseline_id}' not found for org '{org_id}'")

                conn.execute(
                    "UPDATE baselines SET status = 'active', published_at = ? WHERE id = ? AND org_id = ?",
                    (now, baseline_id, org_id),
                )

        with self._conn() as conn:
            updated = conn.execute(
                "SELECT * FROM baselines WHERE id = ?", (baseline_id,)
            ).fetchone()
        record = self._row(updated)
        self._emit_event(
            "baseline.published",
            {"baseline_id": baseline_id, "org_id": org_id, "published_at": now},
        )
        return record

    def run_assessment(
        self,
        baseline_id: str,
        org_id: str,
        target_name: str,
        results_list: List[Dict[str, Any]],
        assessed_by: str,
    ) -> Dict[str, Any]:
        """Run a baseline assessment against a target.

        results_list items: {control_id, control_name, status (pass/fail/skip),
                             actual_value, deviation, severity}

        compliance_pct = pass_count / (pass_count + fail_count) * 100 if (pass+fail) > 0 else 0.
        """
        # Verify baseline belongs to org
        with self._conn() as conn:
            bl_row = conn.execute(
                "SELECT id FROM baselines WHERE id = ? AND org_id = ?",
                (baseline_id, org_id),
            ).fetchone()
        if bl_row is None:
            raise KeyError(f"Baseline '{baseline_id}' not found for org '{org_id}'")

        assessment_id = str(uuid.uuid4())
        now = self._now()

        pass_count = 0
        fail_count = 0
        skip_count = 0

        for r in results_list:
            s = r.get("status", "skip")
            if s == "pass":
                pass_count += 1
            elif s == "fail":
                fail_count += 1
            else:
                skip_count += 1

        denominator = pass_count + fail_count
        compliance_pct = (pass_count / denominator * 100.0) if denominator > 0 else 0.0

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO baseline_assessments
                        (id, baseline_id, org_id, target_name, assessed_at,
                         pass_count, fail_count, skip_count, compliance_pct,
                         assessed_by, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (assessment_id, baseline_id, org_id, target_name, now,
                     pass_count, fail_count, skip_count, compliance_pct,
                     assessed_by, now),
                )

                for r in results_list:
                    result_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO assessment_results
                            (id, assessment_id, org_id, control_id, control_name,
                             status, actual_value, deviation, severity, created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            result_id, assessment_id, org_id,
                            r.get("control_id", ""),
                            r.get("control_name", ""),
                            r.get("status", "skip"),
                            r.get("actual_value", ""),
                            r.get("deviation", ""),
                            r.get("severity", "medium"),
                            now,
                        ),
                    )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM baseline_assessments WHERE id = ?", (assessment_id,)
            ).fetchone()
        record = self._row(row)
        self._emit_event(
            "baseline.assessed",
            {
                "assessment_id": assessment_id,
                "baseline_id": baseline_id,
                "org_id": org_id,
                "target_name": target_name,
                "compliance_pct": compliance_pct,
                "pass": pass_count,
                "fail": fail_count,
                "skip": skip_count,
            },
        )
        return record

    def get_baseline_detail(self, baseline_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return baseline + controls + last 5 assessments."""
        with self._conn() as conn:
            bl_row = conn.execute(
                "SELECT * FROM baselines WHERE id = ? AND org_id = ?",
                (baseline_id, org_id),
            ).fetchone()
            if bl_row is None:
                return None

            controls = conn.execute(
                "SELECT * FROM baseline_controls WHERE baseline_id = ? AND org_id = ? ORDER BY created_at ASC",
                (baseline_id, org_id),
            ).fetchall()

            assessments = conn.execute(
                """
                SELECT * FROM baseline_assessments
                WHERE baseline_id = ? AND org_id = ?
                ORDER BY assessed_at DESC
                LIMIT 5
                """,
                (baseline_id, org_id),
            ).fetchall()

        result = self._row(bl_row)
        result["controls"] = [self._row(c) for c in controls]
        result["recent_assessments"] = [self._row(a) for a in assessments]
        return result

    def get_drift_report(self, baseline_id: str, org_id: str) -> Dict[str, Any]:
        """Compare the last 2 assessments and report control drift.

        Returns {improved: [], degraded: [], new_failures: []}
        improved: controls that changed fail → pass
        degraded: controls that changed pass → fail
        new_failures: controls that are fail in latest but not in previous
        """
        with self._conn() as conn:
            # Get last 2 assessments ordered by assessed_at DESC
            assessments = conn.execute(
                """
                SELECT id, assessed_at FROM baseline_assessments
                WHERE baseline_id = ? AND org_id = ?
                ORDER BY assessed_at DESC
                LIMIT 2
                """,
                (baseline_id, org_id),
            ).fetchall()

        if len(assessments) < 2:
            return {"improved": [], "degraded": [], "new_failures": [], "insufficient_data": True}

        latest_id = assessments[0]["id"]
        previous_id = assessments[1]["id"]

        with self._conn() as conn:
            latest_rows = conn.execute(
                "SELECT control_id, control_name, status FROM assessment_results WHERE assessment_id = ? AND org_id = ?",
                (latest_id, org_id),
            ).fetchall()
            previous_rows = conn.execute(
                "SELECT control_id, control_name, status FROM assessment_results WHERE assessment_id = ? AND org_id = ?",
                (previous_id, org_id),
            ).fetchall()

        latest_map: Dict[str, Dict[str, Any]] = {r["control_id"]: self._row(r) for r in latest_rows}
        previous_map: Dict[str, Dict[str, Any]] = {r["control_id"]: self._row(r) for r in previous_rows}

        improved: List[Dict[str, Any]] = []
        degraded: List[Dict[str, Any]] = []
        new_failures: List[Dict[str, Any]] = []

        for ctrl_id, latest in latest_map.items():
            if ctrl_id in previous_map:
                prev_status = previous_map[ctrl_id]["status"]
                curr_status = latest["status"]
                if prev_status == "fail" and curr_status == "pass":
                    improved.append(latest)
                elif prev_status == "pass" and curr_status == "fail":
                    degraded.append(latest)
            else:
                # New control in latest assessment — if failing, it's a new failure
                if latest["status"] == "fail":
                    new_failures.append(latest)

        return {
            "improved": improved,
            "degraded": degraded,
            "new_failures": new_failures,
            "latest_assessment_id": latest_id,
            "previous_assessment_id": previous_id,
        }

    def get_compliance_trend(self, baseline_id: str, org_id: str) -> List[Dict[str, Any]]:
        """Return all assessments ordered by date with compliance_pct."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT id, assessed_at, target_name, pass_count, fail_count,
                       skip_count, compliance_pct, assessed_by
                FROM baseline_assessments
                WHERE baseline_id = ? AND org_id = ?
                ORDER BY assessed_at ASC
                """,
                (baseline_id, org_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    def list_baselines(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List baselines for an org, optionally filtered by status."""
        if status is not None and status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Valid: {sorted(_VALID_STATUSES)}")

        query = "SELECT * FROM baselines WHERE org_id = ?"
        params: List[Any] = [org_id]

        if status is not None:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
            if emit is None:
                return
            result = emit(event_type, payload)
            try:
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            _logger.debug("baseline trustgraph emit failed: %s", event_type)
