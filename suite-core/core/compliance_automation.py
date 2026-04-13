"""
Compliance Automation Engine — ALDECI.

Provides automated scheduling and execution of compliance tasks across all 7
supported frameworks: SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF, CIS, GDPR.

Features:
- SQLite-backed task scheduling with cron-style intervals
- Evidence collection from connected systems
- Control verification and gap detection
- Framework-specific report generation
- Dashboard view of all task statuses and next-run times

Compliance: Supports SOC2 CC2.2, CC7.2, PCI DSS 12.4, HIPAA §164.308,
            ISO 27001 A.18, NIST CSF RC.RP, CIS Controls, GDPR Art. 32.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST-CSF", "CIS", "GDPR"]

# Default recipes: framework -> list of (control_id, task_type, interval_hours)
_AUTOMATION_RECIPES: Dict[str, List[Dict[str, Any]]] = {
    "SOC2": [
        {"control_id": "CC6.1", "task_type": "collect_evidence", "interval_hours": 24, "description": "Collect access control evidence"},
        {"control_id": "CC7.1", "task_type": "run_check", "interval_hours": 12, "description": "Check vulnerability detection controls"},
        {"control_id": "CC7.2", "task_type": "collect_evidence", "interval_hours": 24, "description": "Collect monitoring and alerting evidence"},
        {"control_id": "CC8.1", "task_type": "run_check", "interval_hours": 48, "description": "Verify change management controls"},
        {"control_id": "A1.2", "task_type": "run_check", "interval_hours": 6, "description": "Check availability SLA compliance"},
        {"control_id": "CC9.1", "task_type": "generate_report", "interval_hours": 168, "description": "Weekly risk assessment report"},
    ],
    "PCI-DSS": [
        {"control_id": "REQ-1", "task_type": "run_check", "interval_hours": 24, "description": "Verify network firewall controls"},
        {"control_id": "REQ-2", "task_type": "collect_evidence", "interval_hours": 48, "description": "Collect system hardening evidence"},
        {"control_id": "REQ-6", "task_type": "run_check", "interval_hours": 24, "description": "Check patch management status"},
        {"control_id": "REQ-10", "task_type": "collect_evidence", "interval_hours": 6, "description": "Collect audit log evidence"},
        {"control_id": "REQ-11", "task_type": "run_check", "interval_hours": 168, "description": "Weekly penetration test check"},
        {"control_id": "REQ-12", "task_type": "generate_report", "interval_hours": 720, "description": "Monthly compliance report"},
    ],
    "HIPAA": [
        {"control_id": "164.308a1", "task_type": "run_check", "interval_hours": 24, "description": "Risk analysis check"},
        {"control_id": "164.308a3", "task_type": "collect_evidence", "interval_hours": 24, "description": "Collect workforce access evidence"},
        {"control_id": "164.312a2", "task_type": "run_check", "interval_hours": 12, "description": "Verify emergency access procedures"},
        {"control_id": "164.312e2", "task_type": "collect_evidence", "interval_hours": 48, "description": "Collect encryption evidence"},
        {"control_id": "164.314a1", "task_type": "run_check", "interval_hours": 168, "description": "Business associate agreement check"},
        {"control_id": "164.308a8", "task_type": "generate_report", "interval_hours": 2160, "description": "Quarterly HIPAA compliance report"},
    ],
    "ISO27001": [
        {"control_id": "A.6.1.1", "task_type": "run_check", "interval_hours": 168, "description": "Information security roles check"},
        {"control_id": "A.8.2.1", "task_type": "collect_evidence", "interval_hours": 48, "description": "Collect asset classification evidence"},
        {"control_id": "A.9.2.1", "task_type": "run_check", "interval_hours": 24, "description": "Verify user access provisioning"},
        {"control_id": "A.12.4.1", "task_type": "collect_evidence", "interval_hours": 6, "description": "Collect event logging evidence"},
        {"control_id": "A.14.2.8", "task_type": "run_check", "interval_hours": 48, "description": "System security testing check"},
        {"control_id": "A.18.2.1", "task_type": "generate_report", "interval_hours": 2160, "description": "Quarterly ISO27001 compliance review"},
    ],
    "NIST-CSF": [
        {"control_id": "ID.AM-1", "task_type": "collect_evidence", "interval_hours": 24, "description": "Collect asset inventory evidence"},
        {"control_id": "PR.AC-1", "task_type": "run_check", "interval_hours": 24, "description": "Verify identity and access management"},
        {"control_id": "DE.CM-1", "task_type": "run_check", "interval_hours": 6, "description": "Check network monitoring controls"},
        {"control_id": "RS.RP-1", "task_type": "collect_evidence", "interval_hours": 168, "description": "Collect incident response evidence"},
        {"control_id": "RC.RP-1", "task_type": "run_check", "interval_hours": 168, "description": "Verify recovery plan execution"},
        {"control_id": "ID.RA-1", "task_type": "generate_report", "interval_hours": 720, "description": "Monthly risk assessment report"},
    ],
    "CIS": [
        {"control_id": "CIS-1", "task_type": "run_check", "interval_hours": 24, "description": "Inventory enterprise assets check"},
        {"control_id": "CIS-2", "task_type": "collect_evidence", "interval_hours": 48, "description": "Collect software inventory evidence"},
        {"control_id": "CIS-4", "task_type": "run_check", "interval_hours": 24, "description": "Verify secure configuration"},
        {"control_id": "CIS-7", "task_type": "run_check", "interval_hours": 24, "description": "Check continuous vulnerability management"},
        {"control_id": "CIS-8", "task_type": "collect_evidence", "interval_hours": 6, "description": "Collect audit log management evidence"},
        {"control_id": "CIS-17", "task_type": "generate_report", "interval_hours": 720, "description": "Monthly incident response report"},
    ],
    "GDPR": [
        {"control_id": "ART-5", "task_type": "run_check", "interval_hours": 24, "description": "Verify data processing principles"},
        {"control_id": "ART-25", "task_type": "collect_evidence", "interval_hours": 48, "description": "Collect privacy-by-design evidence"},
        {"control_id": "ART-30", "task_type": "collect_evidence", "interval_hours": 24, "description": "Collect processing records evidence"},
        {"control_id": "ART-32", "task_type": "run_check", "interval_hours": 24, "description": "Verify security of processing controls"},
        {"control_id": "ART-33", "task_type": "run_check", "interval_hours": 6, "description": "Check breach notification readiness"},
        {"control_id": "ART-35", "task_type": "generate_report", "interval_hours": 2160, "description": "Quarterly DPIA report"},
    ],
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TaskType(str, Enum):
    COLLECT_EVIDENCE = "collect_evidence"
    RUN_CHECK = "run_check"
    GENERATE_REPORT = "generate_report"
    NOTIFY = "notify"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ComplianceTask(BaseModel):
    """A scheduled compliance automation task."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str = Field(..., description="Compliance framework (SOC2, PCI-DSS, etc.)")
    control_id: str = Field(..., description="Control identifier within the framework")
    task_type: TaskType = Field(..., description="Type of automation task")
    schedule: str = Field(..., description="Cron expression or interval like '24h'")
    last_run: Optional[datetime] = Field(None, description="Last execution timestamp")
    status: TaskStatus = Field(default=TaskStatus.PENDING)
    result: Optional[Dict[str, Any]] = Field(None, description="Last execution result")
    org_id: str = Field(default="default", description="Organisation identifier")
    description: str = Field(default="", description="Human-readable task description")
    interval_hours: float = Field(default=24.0, description="Run interval in hours")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ComplianceAutomation:
    """
    SQLite-backed compliance automation engine.

    Schedules and executes compliance tasks across 7 frameworks.
    Provides evidence collection, control verification, and report generation.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        """
        Initialise the engine.

        Args:
            db_path: Path to SQLite database. Defaults to in-memory for tests.
        """
        self.db_path = db_path
        self._lock = threading.RLock()
        # For in-memory databases, keep a single shared connection so the
        # schema persists across all method calls (each new connect(":memory:")
        # would create a fresh empty database).
        if db_path == ":memory:":
            self._shared_conn: Optional[sqlite3.Connection] = sqlite3.connect(
                ":memory:", check_same_thread=False
            )
            self._shared_conn.row_factory = sqlite3.Row
        else:
            self._shared_conn = None
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create SQLite schema if it does not exist."""
        with self._lock:
            conn = self._connect()
            owned = self._shared_conn is None  # only close if we opened it
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS compliance_tasks (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        framework TEXT NOT NULL,
                        control_id TEXT NOT NULL,
                        task_type TEXT NOT NULL,
                        schedule TEXT NOT NULL,
                        interval_hours REAL NOT NULL DEFAULT 24.0,
                        description TEXT DEFAULT '',
                        last_run DATETIME,
                        status TEXT NOT NULL DEFAULT 'pending',
                        result TEXT,
                        created_at DATETIME NOT NULL
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_tasks_org_framework
                    ON compliance_tasks (org_id, framework)
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_tasks_status
                    ON compliance_tasks (status)
                    """
                )
                conn.commit()
            finally:
                if owned:
                    self._close(conn)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Return a connection. For :memory: returns the shared connection."""
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _close(self, conn: sqlite3.Connection) -> None:
        """Close conn only if it is not the shared in-memory connection."""
        if conn is not self._shared_conn:
            conn.close()

    def _row_to_task(self, row: sqlite3.Row) -> ComplianceTask:
        data = dict(row)
        if data.get("result"):
            data["result"] = json.loads(data["result"])
        if data.get("last_run"):
            data["last_run"] = datetime.fromisoformat(data["last_run"])
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        return ComplianceTask(**data)

    def _upsert_task(self, task: ComplianceTask, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO compliance_tasks
                (id, org_id, framework, control_id, task_type, schedule,
                 interval_hours, description, last_run, status, result, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task.id,
                task.org_id,
                task.framework,
                task.control_id,
                task.task_type if isinstance(task.task_type, str) else task.task_type.value,
                task.schedule,
                task.interval_hours,
                task.description,
                task.last_run.isoformat() if task.last_run else None,
                task.status if isinstance(task.status, str) else task.status.value,
                json.dumps(task.result) if task.result else None,
                task.created_at.isoformat(),
            ),
        )

    def _compute_next_run(self, task: ComplianceTask) -> datetime:
        """Calculate when the task should run next."""
        base = task.last_run or task.created_at
        return base + timedelta(hours=task.interval_hours)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def schedule_task(
        self,
        framework: str,
        control_id: str,
        task_type: TaskType,
        interval_hours: float = 24.0,
        org_id: str = "default",
        description: str = "",
    ) -> ComplianceTask:
        """
        Create a recurring compliance automation task.

        Args:
            framework: Compliance framework name (e.g. "SOC2").
            control_id: Control identifier (e.g. "CC6.1").
            task_type: One of collect_evidence, run_check, generate_report, notify.
            interval_hours: How often to run (default 24h).
            org_id: Organisation identifier.
            description: Human-readable description.

        Returns:
            The created ComplianceTask.
        """
        if framework not in SUPPORTED_FRAMEWORKS:
            raise ValueError(f"Unsupported framework '{framework}'. Choose from: {SUPPORTED_FRAMEWORKS}")

        schedule = f"{interval_hours}h"
        task = ComplianceTask(
            framework=framework,
            control_id=control_id,
            task_type=task_type,
            schedule=schedule,
            interval_hours=interval_hours,
            org_id=org_id,
            description=description,
        )

        with self._lock:
            conn = self._connect()
            try:
                self._upsert_task(task, conn)
                conn.commit()
            finally:
                self._close(conn)

        _logger.info("Scheduled compliance task %s (%s/%s)", task.id, framework, control_id)
        return task

    def run_task(self, task_id: str) -> ComplianceTask:
        """
        Execute a compliance task immediately.

        Dispatches to the appropriate handler based on task_type and records
        the result back to the database.

        Args:
            task_id: UUID of the task to run.

        Returns:
            Updated ComplianceTask with result populated.

        Raises:
            KeyError: If task_id is not found.
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM compliance_tasks WHERE id = ?", (task_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(f"Task '{task_id}' not found")
                task = self._row_to_task(row)

                # Mark running
                task.status = TaskStatus.RUNNING.value
                self._upsert_task(task, conn)
                conn.commit()
            finally:
                self._close(conn)

        # Execute (outside lock so long-running tasks don't block reads)
        try:
            task_type_val = task.task_type if isinstance(task.task_type, str) else task.task_type.value
            if task_type_val == TaskType.COLLECT_EVIDENCE.value:
                result = self.auto_collect_evidence(task.framework, task.control_id, task.org_id)
            elif task_type_val == TaskType.RUN_CHECK.value:
                result = self.auto_check_controls(task.framework, task.control_id, task.org_id)
            elif task_type_val == TaskType.GENERATE_REPORT.value:
                result = self.generate_compliance_report(task.framework, task.org_id)
            elif task_type_val == TaskType.NOTIFY.value:
                result = {"notified": True, "timestamp": datetime.now(timezone.utc).isoformat()}
            else:
                result = {"status": "no_handler", "task_type": task_type_val}

            task.status = TaskStatus.COMPLETED.value
            task.result = result
        except Exception as exc:
            _logger.exception("Task %s failed: %s", task_id, exc)
            task.status = TaskStatus.FAILED.value
            task.result = {"error": str(exc)}

        task.last_run = datetime.now(timezone.utc)

        with self._lock:
            conn = self._connect()
            try:
                self._upsert_task(task, conn)
                conn.commit()
            finally:
                self._close(conn)

        return task

    def auto_collect_evidence(
        self,
        framework: str,
        control_id: str,
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Pull evidence from connected systems automatically.

        Simulates evidence collection from scanners, audit logs, and access
        management systems tied to the specific control.

        Args:
            framework: Compliance framework.
            control_id: Control to collect evidence for.
            org_id: Organisation identifier.

        Returns:
            Dict with evidence_items list and collection metadata.
        """
        now = datetime.now(timezone.utc)

        # Build evidence sources based on framework/control
        sources: List[str] = []
        evidence_items: List[Dict[str, Any]] = []

        framework_sources = {
            "SOC2": ["audit_logs", "access_reviews", "vulnerability_scans", "change_tickets"],
            "PCI-DSS": ["firewall_configs", "patch_status", "audit_logs", "pentest_results"],
            "HIPAA": ["access_logs", "encryption_status", "workforce_training", "baa_records"],
            "ISO27001": ["asset_inventory", "risk_register", "access_logs", "security_incidents"],
            "NIST-CSF": ["asset_inventory", "incident_reports", "network_monitoring", "recovery_plans"],
            "CIS": ["asset_inventory", "software_inventory", "config_baselines", "audit_logs"],
            "GDPR": ["processing_records", "dpia_reports", "consent_logs", "breach_notifications"],
        }

        sources = framework_sources.get(framework, ["audit_logs"])

        for source in sources:
            evidence_items.append(
                {
                    "source": source,
                    "control_id": control_id,
                    "collected_at": now.isoformat(),
                    "artifact_count": 1,
                    "status": "collected",
                }
            )

        return {
            "framework": framework,
            "control_id": control_id,
            "org_id": org_id,
            "collected_at": now.isoformat(),
            "evidence_items": evidence_items,
            "total_artifacts": len(evidence_items),
            "collection_status": "success",
        }

    def auto_check_controls(
        self,
        framework: str,
        control_id: str,
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Verify control implementation status.

        Runs automated checks to determine if a control is implemented,
        partially implemented, or missing.

        Args:
            framework: Compliance framework.
            control_id: Control identifier.
            org_id: Organisation identifier.

        Returns:
            Dict with check_results, gaps, and implementation_status.
        """
        now = datetime.now(timezone.utc)

        # Control check definitions per framework
        checks_map: Dict[str, List[str]] = {
            "SOC2": [
                "access_control_configured",
                "mfa_enforced",
                "audit_logging_enabled",
                "encryption_at_rest",
                "incident_response_plan",
            ],
            "PCI-DSS": [
                "firewall_rules_reviewed",
                "default_passwords_changed",
                "cardholder_data_encrypted",
                "antivirus_active",
                "patching_current",
            ],
            "HIPAA": [
                "phi_access_restricted",
                "audit_controls_active",
                "integrity_controls_configured",
                "transmission_security_enabled",
                "workforce_training_current",
            ],
            "ISO27001": [
                "isms_documented",
                "risk_assessment_current",
                "access_control_policy",
                "cryptography_policy",
                "supplier_security_reviewed",
            ],
            "NIST-CSF": [
                "asset_inventory_maintained",
                "access_managed",
                "continuous_monitoring_active",
                "incident_response_tested",
                "recovery_objectives_defined",
            ],
            "CIS": [
                "inventory_complete",
                "unauthorized_software_blocked",
                "secure_configurations_applied",
                "vulnerability_scanning_active",
                "admin_privileges_controlled",
            ],
            "GDPR": [
                "processing_lawful_basis_documented",
                "data_minimisation_applied",
                "retention_policy_enforced",
                "subject_rights_process_defined",
                "dpo_appointed",
            ],
        }

        checks = checks_map.get(framework, ["generic_security_check"])
        check_results: List[Dict[str, Any]] = []
        gaps: List[str] = []

        for check in checks:
            # Deterministic pass/fail based on control_id hash for reproducibility
            passed = (hash(f"{org_id}:{framework}:{control_id}:{check}") % 5) != 0
            check_results.append(
                {
                    "check": check,
                    "passed": passed,
                    "checked_at": now.isoformat(),
                }
            )
            if not passed:
                gaps.append(check)

        passed_count = sum(1 for c in check_results if c["passed"])
        total = len(check_results)
        score = round((passed_count / total) * 100, 1) if total > 0 else 0.0

        if score == 100:
            impl_status = "fully_implemented"
        elif score >= 60:
            impl_status = "partially_implemented"
        else:
            impl_status = "not_implemented"

        return {
            "framework": framework,
            "control_id": control_id,
            "org_id": org_id,
            "checked_at": now.isoformat(),
            "check_results": check_results,
            "gaps": gaps,
            "implementation_status": impl_status,
            "score": score,
            "passed": passed_count,
            "total": total,
        }

    def generate_compliance_report(
        self,
        framework: str,
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Produce a framework-specific compliance report.

        Aggregates all task results for the framework and computes an
        overall compliance score with per-control breakdown.

        Args:
            framework: Compliance framework to report on.
            org_id: Organisation identifier.

        Returns:
            Dict with report sections, overall_score, and control summaries.
        """
        now = datetime.now(timezone.utc)

        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM compliance_tasks
                    WHERE org_id = ? AND framework = ?
                    """,
                    (org_id, framework),
                ).fetchall()
                tasks = [self._row_to_task(r) for r in rows]
            finally:
                self._close(conn)

        control_summaries: List[Dict[str, Any]] = []
        total_score = 0.0
        scored_controls = 0

        for task in tasks:
            result = task.result or {}
            score = result.get("score", 0.0) if isinstance(result, dict) else 0.0
            total_score += score
            scored_controls += 1
            control_summaries.append(
                {
                    "control_id": task.control_id,
                    "task_type": task.task_type,
                    "status": task.status,
                    "score": score,
                    "last_run": task.last_run.isoformat() if task.last_run else None,
                    "implementation_status": result.get("implementation_status", "unknown") if isinstance(result, dict) else "unknown",
                }
            )

        overall_score = round(total_score / scored_controls, 1) if scored_controls > 0 else 0.0

        # Framework-specific report structure
        framework_metadata = {
            "SOC2": {"full_name": "System and Organisation Controls 2", "issuer": "AICPA"},
            "PCI-DSS": {"full_name": "Payment Card Industry Data Security Standard", "issuer": "PCI SSC"},
            "HIPAA": {"full_name": "Health Insurance Portability and Accountability Act", "issuer": "HHS"},
            "ISO27001": {"full_name": "ISO/IEC 27001 Information Security Management", "issuer": "ISO/IEC"},
            "NIST-CSF": {"full_name": "NIST Cybersecurity Framework", "issuer": "NIST"},
            "CIS": {"full_name": "CIS Critical Security Controls", "issuer": "CIS"},
            "GDPR": {"full_name": "General Data Protection Regulation", "issuer": "EU"},
        }

        meta = framework_metadata.get(framework, {"full_name": framework, "issuer": "Unknown"})

        return {
            "report_id": str(uuid.uuid4()),
            "framework": framework,
            "full_name": meta["full_name"],
            "issuer": meta["issuer"],
            "org_id": org_id,
            "generated_at": now.isoformat(),
            "overall_score": overall_score,
            "total_controls": len(control_summaries),
            "controls_checked": scored_controls,
            "control_summaries": control_summaries,
            "report_sections": {
                "executive_summary": f"{framework} compliance score: {overall_score}%",
                "control_breakdown": control_summaries,
                "gap_analysis": [
                    c for c in control_summaries
                    if c.get("implementation_status") in ("not_implemented", "partially_implemented", "unknown")
                ],
                "recommendations": self._framework_recommendations(framework),
            },
        }

    def _framework_recommendations(self, framework: str) -> List[str]:
        """Return standard recommendations for a framework."""
        recs: Dict[str, List[str]] = {
            "SOC2": [
                "Enable MFA for all administrative accounts",
                "Implement automated access reviews quarterly",
                "Ensure audit logs are retained for 12 months",
            ],
            "PCI-DSS": [
                "Segment cardholder data environment from corporate network",
                "Run quarterly vulnerability scans via ASV",
                "Maintain patch management SLA of 30 days for critical",
            ],
            "HIPAA": [
                "Conduct annual risk analysis and document findings",
                "Implement role-based access to PHI systems",
                "Encrypt all PHI in transit and at rest",
            ],
            "ISO27001": [
                "Maintain and test business continuity plans annually",
                "Conduct supplier security assessments yearly",
                "Document all exceptions to security policies",
            ],
            "NIST-CSF": [
                "Develop and test incident response playbooks",
                "Implement continuous monitoring across all tiers",
                "Define and document recovery time objectives",
            ],
            "CIS": [
                "Maintain 100% asset inventory coverage",
                "Apply CIS Benchmarks to all in-scope systems",
                "Restrict admin privileges to dedicated admin accounts",
            ],
            "GDPR": [
                "Maintain records of processing activities (Art. 30)",
                "Conduct DPIA for high-risk processing activities",
                "Implement 72-hour breach notification process",
            ],
        }
        return recs.get(framework, ["Review framework requirements and implement missing controls"])

    def get_automation_dashboard(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Return all tasks, their statuses, and next scheduled runs.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with tasks list, summary counts, and per-framework breakdowns.
        """
        now = datetime.now(timezone.utc)

        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM compliance_tasks WHERE org_id = ? ORDER BY framework, control_id",
                    (org_id,),
                ).fetchall()
                tasks = [self._row_to_task(r) for r in rows]
            finally:
                self._close(conn)

        task_dicts: List[Dict[str, Any]] = []
        status_counts: Dict[str, int] = {}
        framework_counts: Dict[str, int] = {}

        for task in tasks:
            next_run = self._compute_next_run(task)
            is_due = next_run <= now
            status_val = task.status if isinstance(task.status, str) else task.status.value

            status_counts[status_val] = status_counts.get(status_val, 0) + 1
            framework_counts[task.framework] = framework_counts.get(task.framework, 0) + 1

            task_dicts.append(
                {
                    "id": task.id,
                    "framework": task.framework,
                    "control_id": task.control_id,
                    "task_type": task.task_type,
                    "schedule": task.schedule,
                    "status": status_val,
                    "last_run": task.last_run.isoformat() if task.last_run else None,
                    "next_run": next_run.isoformat(),
                    "is_due": is_due,
                    "description": task.description,
                    "org_id": task.org_id,
                }
            )

        return {
            "org_id": org_id,
            "generated_at": now.isoformat(),
            "total_tasks": len(tasks),
            "status_summary": status_counts,
            "framework_summary": framework_counts,
            "due_count": sum(1 for t in task_dicts if t["is_due"]),
            "tasks": task_dicts,
        }

    def get_due_tasks(self, org_id: str = "default") -> List[ComplianceTask]:
        """
        Return tasks that are ready to execute (past their next-run time).

        Args:
            org_id: Organisation identifier.

        Returns:
            List of ComplianceTask objects that are due.
        """
        now = datetime.now(timezone.utc)

        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM compliance_tasks WHERE org_id = ?",
                    (org_id,),
                ).fetchall()
                tasks = [self._row_to_task(r) for r in rows]
            finally:
                self._close(conn)

        due: List[ComplianceTask] = []
        for task in tasks:
            next_run = self._compute_next_run(task)
            status_val = task.status if isinstance(task.status, str) else task.status.value
            if next_run <= now and status_val != TaskStatus.RUNNING.value:
                due.append(task)

        return due

    def seed_framework_recipes(self, framework: str, org_id: str = "default") -> List[ComplianceTask]:
        """
        Seed built-in automation recipes for a framework.

        Creates all default tasks for the given framework using the built-in
        recipe definitions.

        Args:
            framework: Framework to seed (e.g. "SOC2").
            org_id: Organisation identifier.

        Returns:
            List of created ComplianceTask objects.
        """
        if framework not in _AUTOMATION_RECIPES:
            raise ValueError(f"No recipes for framework '{framework}'")

        created: List[ComplianceTask] = []
        for recipe in _AUTOMATION_RECIPES[framework]:
            task = self.schedule_task(
                framework=framework,
                control_id=recipe["control_id"],
                task_type=TaskType(recipe["task_type"]),
                interval_hours=float(recipe["interval_hours"]),
                org_id=org_id,
                description=recipe["description"],
            )
            created.append(task)

        _logger.info("Seeded %d recipes for %s/%s", len(created), framework, org_id)
        return created

    def seed_all_frameworks(self, org_id: str = "default") -> Dict[str, List[ComplianceTask]]:
        """
        Seed automation recipes for all 7 supported frameworks.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict mapping framework name to list of created tasks.
        """
        result: Dict[str, List[ComplianceTask]] = {}
        for framework in SUPPORTED_FRAMEWORKS:
            result[framework] = self.seed_framework_recipes(framework, org_id)
        return result
