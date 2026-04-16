"""Cloud Compliance Engine — ALDECI.

Multi-cloud compliance posture across AWS / Azure / GCP.

Capabilities:
  - Assessment lifecycle per framework (CIS AWS/Azure/GCP, NIST 800-53, SOC 2,
    PCI-DSS, HIPAA, ISO 27001)
  - Control result recording with automatic score computation
  - Drift detection between consecutive assessments
  - Remediation plan management
  - Stats aggregation per org

Compliance: CIS Benchmarks v1.5/1.3, NIST SP 800-53, PCI-DSS v4, HIPAA, ISO 27001
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

_VALID_PROVIDERS = {"aws", "azure", "gcp", "multi"}
_VALID_FRAMEWORKS = {
    "cis_aws_v1.5", "cis_azure_v1.5", "cis_gcp_v1.3",
    "nist_800_53", "soc2", "pci_dss", "hipaa", "iso27001",
}
_VALID_ASSESSMENT_STATUSES = {"running", "completed", "failed"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_CONTROL_STATUSES = {"passed", "failed", "not_applicable", "manual_check"}
_VALID_PRIORITIES = {"p1", "p2", "p3", "p4"}
_VALID_EFFORTS = {"low", "medium", "high"}
_VALID_REMEDIATION_STATUSES = {"planned", "in_progress", "completed", "deferred"}
_VALID_DRIFT_DIRECTIONS = {"improving", "declining", "stable"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path_for_org(org_id: str) -> str:
    base = Path(__file__).resolve().parents[2] / ".fixops_data"
    return str(base / f"{org_id}_cloud_compliance.db")


class CloudComplianceEngine:
    """SQLite WAL-backed cloud compliance engine.

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
                CREATE TABLE IF NOT EXISTS compliance_assessments (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    cloud_provider      TEXT NOT NULL DEFAULT 'aws',
                    framework           TEXT NOT NULL,
                    scope               TEXT NOT NULL DEFAULT '{}',
                    status              TEXT NOT NULL DEFAULT 'running',
                    total_controls      INTEGER NOT NULL DEFAULT 0,
                    passed              INTEGER NOT NULL DEFAULT 0,
                    failed              INTEGER NOT NULL DEFAULT 0,
                    not_applicable      INTEGER NOT NULL DEFAULT 0,
                    score               REAL NOT NULL DEFAULT 0.0,
                    assessed_at         DATETIME,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ca_org_framework
                    ON compliance_assessments (org_id, framework, created_at DESC);

                CREATE TABLE IF NOT EXISTS control_results (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    assessment_id       TEXT NOT NULL,
                    control_id          TEXT NOT NULL,
                    control_name        TEXT NOT NULL DEFAULT '',
                    section             TEXT NOT NULL DEFAULT '',
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    status              TEXT NOT NULL DEFAULT 'manual_check',
                    evidence            TEXT NOT NULL DEFAULT '',
                    resource_id         TEXT NOT NULL DEFAULT '',
                    resource_type       TEXT NOT NULL DEFAULT '',
                    resource_name       TEXT NOT NULL DEFAULT '',
                    region              TEXT NOT NULL DEFAULT '',
                    remediation         TEXT NOT NULL DEFAULT '',
                    auto_remediated     INTEGER NOT NULL DEFAULT 0,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cr_org_assessment
                    ON control_results (org_id, assessment_id, severity);

                CREATE INDEX IF NOT EXISTS idx_cr_org_status
                    ON control_results (org_id, status);

                CREATE TABLE IF NOT EXISTS remediation_plans (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    assessment_id       TEXT NOT NULL,
                    control_id          TEXT NOT NULL,
                    priority            TEXT NOT NULL DEFAULT 'p3',
                    assigned_team       TEXT NOT NULL DEFAULT '',
                    estimated_effort    TEXT NOT NULL DEFAULT 'medium',
                    target_date         TEXT NOT NULL DEFAULT '',
                    status              TEXT NOT NULL DEFAULT 'planned',
                    notes               TEXT NOT NULL DEFAULT '',
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rp_org_status
                    ON remediation_plans (org_id, status, priority);

                CREATE TABLE IF NOT EXISTS compliance_drift (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    framework           TEXT NOT NULL,
                    previous_score      REAL NOT NULL DEFAULT 0.0,
                    current_score       REAL NOT NULL DEFAULT 0.0,
                    change_pct          REAL NOT NULL DEFAULT 0.0,
                    drift_direction     TEXT NOT NULL DEFAULT 'stable',
                    period_days         INTEGER NOT NULL DEFAULT 0,
                    key_changes         TEXT NOT NULL DEFAULT '[]',
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cd_org_framework
                    ON compliance_drift (org_id, framework, created_at DESC);
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
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new compliance assessment."""
        framework = data.get("framework", "")
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(f"Invalid framework: {framework}. Must be one of {_VALID_FRAMEWORKS}")

        provider = data.get("cloud_provider", "aws")
        if provider not in _VALID_PROVIDERS:
            raise ValueError(f"Invalid cloud_provider: {provider}")

        scope = data.get("scope", {})
        if not isinstance(scope, dict):
            scope = {}

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "cloud_provider": provider,
            "framework": framework,
            "scope": json.dumps(scope),
            "status": "running",
            "total_controls": int(data.get("total_controls", 0)),
            "passed": 0,
            "failed": 0,
            "not_applicable": 0,
            "score": 0.0,
            "assessed_at": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO compliance_assessments
                       (id, org_id, cloud_provider, framework, scope, status,
                        total_controls, passed, failed, not_applicable, score,
                        assessed_at, created_at)
                       VALUES (:id, :org_id, :cloud_provider, :framework, :scope, :status,
                               :total_controls, :passed, :failed, :not_applicable, :score,
                               :assessed_at, :created_at)""",
                    record,
                )
        record["scope"] = scope
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_compliance", "org_id": org_id, "source_engine": "cloud_compliance"})
            except Exception:
                pass

        return record

    def list_assessments(
        self,
        org_id: str,
        framework: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assessments, optionally filtered."""
        sql = "SELECT * FROM compliance_assessments WHERE org_id = ?"
        params: list = [org_id]
        if framework:
            sql += " AND framework = ?"
            params.append(framework)
        if provider:
            sql += " AND cloud_provider = ?"
            params.append(provider)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = [self._row(r) for r in conn.execute(sql, params).fetchall()]
        for r in rows:
            try:
                r["scope"] = json.loads(r["scope"])
            except Exception:
                r["scope"] = {}
        return rows

    def get_assessment(self, org_id: str, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Return assessment with a control summary."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM compliance_assessments WHERE org_id = ? AND id = ?",
                (org_id, assessment_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            try:
                result["scope"] = json.loads(result["scope"])
            except Exception:
                result["scope"] = {}

            # Control summary by severity
            sev_rows = conn.execute(
                """SELECT severity, status, COUNT(*) as cnt
                   FROM control_results
                   WHERE org_id = ? AND assessment_id = ?
                   GROUP BY severity, status""",
                (org_id, assessment_id),
            ).fetchall()
            summary: Dict[str, Any] = {}
            for sr in sev_rows:
                key = f"{sr['severity']}_{sr['status']}"
                summary[key] = sr["cnt"]
            result["control_summary"] = summary
        return result

    def add_control_result(
        self, org_id: str, assessment_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a control result and update the assessment score."""
        control_id = (data.get("control_id") or "").strip()
        if not control_id:
            raise ValueError("control_id is required.")

        status = data.get("status", "manual_check")
        if status not in _VALID_CONTROL_STATUSES:
            raise ValueError(f"Invalid status: {status}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "assessment_id": assessment_id,
            "control_id": control_id,
            "control_name": data.get("control_name", ""),
            "section": data.get("section", ""),
            "severity": severity,
            "status": status,
            "evidence": data.get("evidence", ""),
            "resource_id": data.get("resource_id", ""),
            "resource_type": data.get("resource_type", ""),
            "resource_name": data.get("resource_name", ""),
            "region": data.get("region", ""),
            "remediation": data.get("remediation", ""),
            "auto_remediated": 1 if data.get("auto_remediated") else 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO control_results
                       (id, org_id, assessment_id, control_id, control_name, section,
                        severity, status, evidence, resource_id, resource_type,
                        resource_name, region, remediation, auto_remediated, created_at)
                       VALUES (:id, :org_id, :assessment_id, :control_id, :control_name, :section,
                               :severity, :status, :evidence, :resource_id, :resource_type,
                               :resource_name, :region, :remediation, :auto_remediated, :created_at)""",
                    record,
                )
            self._recompute_assessment_score(org_id, assessment_id)
        return record

    def _recompute_assessment_score(self, org_id: str, assessment_id: str) -> None:
        """Recompute and persist assessment score from current control results."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT
                     SUM(CASE WHEN status='passed' THEN 1 ELSE 0 END) as passed,
                     SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed,
                     SUM(CASE WHEN status='not_applicable' THEN 1 ELSE 0 END) as na
                   FROM control_results
                   WHERE org_id = ? AND assessment_id = ?""",
                (org_id, assessment_id),
            ).fetchone()
            passed = row["passed"] or 0
            failed = row["failed"] or 0
            na = row["na"] or 0
            total = passed + failed + na
            score = round((passed / total) * 100.0, 2) if total > 0 else 0.0
            conn.execute(
                """UPDATE compliance_assessments
                   SET passed = ?, failed = ?, not_applicable = ?,
                       total_controls = ?, score = ?
                   WHERE org_id = ? AND id = ?""",
                (passed, failed, na, total, score, org_id, assessment_id),
            )

    def complete_assessment(
        self, org_id: str, assessment_id: str
    ) -> Optional[Dict[str, Any]]:
        """Mark assessment completed, compute final score, detect drift."""
        with self._lock:
            self._recompute_assessment_score(org_id, assessment_id)
            now = _now_iso()
            with self._conn() as conn:
                conn.execute(
                    """UPDATE compliance_assessments
                       SET status = 'completed', assessed_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, org_id, assessment_id),
                )
                row = conn.execute(
                    "SELECT * FROM compliance_assessments WHERE org_id = ? AND id = ?",
                    (org_id, assessment_id),
                ).fetchone()
                if not row:
                    return None
                assessment = self._row(row)

            # Drift detection — find previous completed assessment for same framework
            with self._conn() as conn:
                prev_row = conn.execute(
                    """SELECT score, assessed_at FROM compliance_assessments
                       WHERE org_id = ? AND framework = ? AND status = 'completed'
                         AND id != ?
                       ORDER BY assessed_at DESC LIMIT 1""",
                    (org_id, assessment["framework"], assessment_id),
                ).fetchone()

            if prev_row:
                prev_score = prev_row["score"]
                curr_score = assessment["score"]
                change_pct = round(curr_score - prev_score, 2)
                if change_pct > 0.5:
                    direction = "improving"
                elif change_pct < -0.5:
                    direction = "declining"
                else:
                    direction = "stable"

                # Compute period days
                try:
                    prev_dt = datetime.fromisoformat(prev_row["assessed_at"].replace("Z", "+00:00"))
                    curr_dt = datetime.fromisoformat(now.replace("Z", "+00:00"))
                    period_days = (curr_dt - prev_dt).days
                except Exception:
                    period_days = 0

                drift_record = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "framework": assessment["framework"],
                    "previous_score": prev_score,
                    "current_score": curr_score,
                    "change_pct": change_pct,
                    "drift_direction": direction,
                    "period_days": period_days,
                    "key_changes": json.dumps([]),
                    "created_at": now,
                }
                with self._lock:
                    with self._conn() as conn:
                        conn.execute(
                            """INSERT INTO compliance_drift
                               (id, org_id, framework, previous_score, current_score,
                                change_pct, drift_direction, period_days, key_changes, created_at)
                               VALUES (:id, :org_id, :framework, :previous_score, :current_score,
                                       :change_pct, :drift_direction, :period_days,
                                       :key_changes, :created_at)""",
                            drift_record,
                        )

        try:
            assessment["scope"] = json.loads(assessment["scope"])
        except Exception:
            assessment["scope"] = {}
        return assessment

    # ------------------------------------------------------------------
    # Control results
    # ------------------------------------------------------------------

    def list_control_results(
        self,
        org_id: str,
        assessment_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List control results with optional filters."""
        sql = "SELECT * FROM control_results WHERE org_id = ?"
        params: list = [org_id]
        if assessment_id:
            sql += " AND assessment_id = ?"
            params.append(assessment_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Remediation plans
    # ------------------------------------------------------------------

    def create_remediation_plan(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a remediation plan."""
        assessment_id = (data.get("assessment_id") or "").strip()
        control_id = (data.get("control_id") or "").strip()
        if not assessment_id or not control_id:
            raise ValueError("assessment_id and control_id are required.")

        priority = data.get("priority", "p3")
        if priority not in _VALID_PRIORITIES:
            raise ValueError(f"Invalid priority: {priority}")

        effort = data.get("estimated_effort", "medium")
        if effort not in _VALID_EFFORTS:
            raise ValueError(f"Invalid estimated_effort: {effort}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "assessment_id": assessment_id,
            "control_id": control_id,
            "priority": priority,
            "assigned_team": data.get("assigned_team", ""),
            "estimated_effort": effort,
            "target_date": data.get("target_date", ""),
            "status": "planned",
            "notes": data.get("notes", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO remediation_plans
                       (id, org_id, assessment_id, control_id, priority, assigned_team,
                        estimated_effort, target_date, status, notes, created_at)
                       VALUES (:id, :org_id, :assessment_id, :control_id, :priority, :assigned_team,
                               :estimated_effort, :target_date, :status, :notes, :created_at)""",
                    record,
                )
        return record

    def update_remediation_plan(
        self, org_id: str, plan_id: str, status: str
    ) -> bool:
        """Update remediation plan status. Returns True if found."""
        if status not in _VALID_REMEDIATION_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE remediation_plans SET status = ? WHERE org_id = ? AND id = ?",
                    (status, org_id, plan_id),
                )
                return cur.rowcount > 0

    def list_remediation_plans(
        self,
        org_id: str,
        assessment_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List remediation plans with optional filters."""
        sql = "SELECT * FROM remediation_plans WHERE org_id = ?"
        params: list = [org_id]
        if assessment_id:
            sql += " AND assessment_id = ?"
            params.append(assessment_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY priority ASC, created_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Drift
    # ------------------------------------------------------------------

    def list_drift_history(
        self,
        org_id: str,
        framework: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Return compliance drift history, newest first."""
        sql = "SELECT * FROM compliance_drift WHERE org_id = ?"
        params: list = [org_id]
        if framework:
            sql += " AND framework = ?"
            params.append(framework)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = [self._row(r) for r in conn.execute(sql, params).fetchall()]
        for r in rows:
            try:
                r["key_changes"] = json.loads(r["key_changes"])
            except Exception:
                r["key_changes"] = []
        return rows

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_compliance_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated compliance statistics for org."""
        with self._conn() as conn:
            assessments_run = conn.execute(
                "SELECT COUNT(*) FROM compliance_assessments WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            total_controls = conn.execute(
                "SELECT COALESCE(SUM(total_controls), 0) FROM compliance_assessments WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            # avg score by framework
            fw_rows = conn.execute(
                """SELECT framework, AVG(score) as avg_score
                   FROM compliance_assessments WHERE org_id = ? AND status = 'completed'
                   GROUP BY framework""",
                (org_id,),
            ).fetchall()
            avg_score_by_framework = {r["framework"]: round(r["avg_score"], 2) for r in fw_rows}

            frameworks_assessed = len(avg_score_by_framework)

            # Pass rate
            pass_row = conn.execute(
                """SELECT
                     COALESCE(SUM(passed), 0) as total_passed,
                     COALESCE(SUM(passed) + SUM(failed), 0) as total_scored
                   FROM compliance_assessments WHERE org_id = ?""",
                (org_id,),
            ).fetchone()
            total_passed = pass_row["total_passed"] or 0
            total_scored = pass_row["total_scored"] or 0
            pass_rate = round((total_passed / total_scored) * 100.0, 2) if total_scored > 0 else 0.0

            # Critical failures
            critical_failures = conn.execute(
                """SELECT COUNT(*) FROM control_results
                   WHERE org_id = ? AND severity = 'critical' AND status = 'failed'""",
                (org_id,),
            ).fetchone()[0]

            remediation_plans_active = conn.execute(
                """SELECT COUNT(*) FROM remediation_plans
                   WHERE org_id = ? AND status IN ('planned', 'in_progress')""",
                (org_id,),
            ).fetchone()[0]

        return {
            "assessments_run": assessments_run,
            "avg_score_by_framework": avg_score_by_framework,
            "frameworks_assessed": frameworks_assessed,
            "total_controls": total_controls,
            "pass_rate": pass_rate,
            "critical_failures": critical_failures,
            "remediation_plans_active": remediation_plans_active,
        }


# ---------------------------------------------------------------------------
# Per-org singleton cache
# ---------------------------------------------------------------------------
_instances: Dict[str, CloudComplianceEngine] = {}
_instances_lock = threading.Lock()


def get_engine(org_id: str) -> CloudComplianceEngine:
    """Return (or create) a CloudComplianceEngine instance for org_id."""
    with _instances_lock:
        if org_id not in _instances:
            _instances[org_id] = CloudComplianceEngine(db_path=_db_path_for_org(org_id))
        return _instances[org_id]
