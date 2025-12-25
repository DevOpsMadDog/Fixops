"""Remediation Lifecycle Management - Track remediation tasks with SLA."""

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class RemediationStatus(str, Enum):
    """Status of a remediation task."""

    OPEN = "open"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    VERIFICATION = "verification"
    RESOLVED = "resolved"
    DEFERRED = "deferred"
    WONT_FIX = "wont_fix"


# Valid state transitions
VALID_TRANSITIONS = {
    RemediationStatus.OPEN: [
        RemediationStatus.ASSIGNED,
        RemediationStatus.DEFERRED,
        RemediationStatus.WONT_FIX,
    ],
    RemediationStatus.ASSIGNED: [
        RemediationStatus.IN_PROGRESS,
        RemediationStatus.DEFERRED,
        RemediationStatus.OPEN,
    ],
    RemediationStatus.IN_PROGRESS: [
        RemediationStatus.VERIFICATION,
        RemediationStatus.DEFERRED,
        RemediationStatus.ASSIGNED,
    ],
    RemediationStatus.VERIFICATION: [
        RemediationStatus.RESOLVED,
        RemediationStatus.IN_PROGRESS,
    ],
    RemediationStatus.RESOLVED: [RemediationStatus.OPEN],  # Can reopen
    RemediationStatus.DEFERRED: [
        RemediationStatus.OPEN,
        RemediationStatus.ASSIGNED,
    ],
    RemediationStatus.WONT_FIX: [RemediationStatus.OPEN],  # Can reopen
}

# Default SLA policies (in hours)
DEFAULT_SLA_POLICIES = {
    "critical": 24,
    "high": 72,
    "medium": 168,  # 7 days
    "low": 720,  # 30 days
}


class RemediationService:
    """Service for managing remediation tasks with SLA tracking."""

    def __init__(self, db_path: Path, sla_policies: Optional[Dict[str, int]] = None):
        """Initialize remediation service."""
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.sla_policies = sla_policies or DEFAULT_SLA_POLICIES
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Remediation tasks
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_tasks (
                task_id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                app_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                assignee TEXT,
                assignee_email TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                due_at TEXT,
                resolved_at TEXT,
                sla_hours INTEGER,
                sla_breached INTEGER DEFAULT 0,
                ticket_id TEXT,
                ticket_url TEXT,
                verification_evidence TEXT,
                metadata TEXT
            )
        """
        )

        # Task history for audit trail
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS task_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT NOT NULL,
                changed_by TEXT,
                reason TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (task_id) REFERENCES remediation_tasks(task_id)
            )
        """
        )

        # SLA breaches
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sla_breaches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                breach_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                sla_hours INTEGER NOT NULL,
                actual_hours REAL NOT NULL,
                breached_at TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                FOREIGN KEY (task_id) REFERENCES remediation_tasks(task_id)
            )
        """
        )

        # Verification evidence
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS verification_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                evidence_data TEXT NOT NULL,
                submitted_by TEXT,
                submitted_at TEXT NOT NULL,
                verified INTEGER DEFAULT 0,
                verified_by TEXT,
                verified_at TEXT,
                FOREIGN KEY (task_id) REFERENCES remediation_tasks(task_id)
            )
        """
        )

        # Indexes
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_tasks_cluster ON remediation_tasks(cluster_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_tasks_org_app ON remediation_tasks(org_id, app_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_tasks_status ON remediation_tasks(status)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON remediation_tasks(assignee)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_tasks_due ON remediation_tasks(due_at)"
        )

        conn.commit()
        conn.close()

    def create_task(
        self,
        cluster_id: str,
        org_id: str,
        app_id: str,
        title: str,
        severity: str,
        description: Optional[str] = None,
        assignee: Optional[str] = None,
        assignee_email: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a new remediation task."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            task_id = str(uuid.uuid4())
            now = datetime.utcnow()
            now_str = now.isoformat()

            sla_hours = self.sla_policies.get(severity.lower(), 168)
            due_at = (now + timedelta(hours=sla_hours)).isoformat()

            initial_status = (
                RemediationStatus.ASSIGNED.value
                if assignee
                else RemediationStatus.OPEN.value
            )

            cursor.execute(
                """
                INSERT INTO remediation_tasks (
                    task_id, cluster_id, org_id, app_id, title, description,
                    severity, status, assignee, assignee_email, created_at,
                    updated_at, due_at, sla_hours, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    task_id,
                    cluster_id,
                    org_id,
                    app_id,
                    title,
                    description,
                    severity.lower(),
                    initial_status,
                    assignee,
                    assignee_email,
                    now_str,
                    now_str,
                    due_at,
                    sla_hours,
                    json.dumps(metadata or {}),
                ),
            )

            cursor.execute(
                """
                INSERT INTO task_history (task_id, new_status, reason, timestamp)
                VALUES (?, ?, ?, ?)
            """,
                (task_id, initial_status, "Task created", now_str),
            )

            conn.commit()

            return {
                "task_id": task_id,
                "cluster_id": cluster_id,
                "status": initial_status,
                "severity": severity.lower(),
                "due_at": due_at,
                "sla_hours": sla_hours,
                "created_at": now_str,
            }
        finally:
            conn.close()

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task by ID."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM remediation_tasks WHERE task_id = ?", (task_id,)
            )
            row = cursor.fetchone()
            if row:
                task = dict(row)
                task["is_overdue"] = self._is_overdue(task)
                return task
            return None
        finally:
            conn.close()

    def get_tasks(
        self,
        org_id: str,
        app_id: Optional[str] = None,
        status: Optional[str] = None,
        assignee: Optional[str] = None,
        severity: Optional[str] = None,
        overdue_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get tasks with optional filters."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            query = "SELECT * FROM remediation_tasks WHERE org_id = ?"
            params: List[Any] = [org_id]

            if app_id:
                query += " AND app_id = ?"
                params.append(app_id)
            if status:
                query += " AND status = ?"
                params.append(status)
            if assignee:
                query += " AND assignee = ?"
                params.append(assignee)
            if severity:
                query += " AND severity = ?"
                params.append(severity.lower())
            if overdue_only:
                now = datetime.utcnow().isoformat()
                query += " AND due_at < ? AND status NOT IN ('resolved', 'wont_fix')"
                params.append(now)

            query += " ORDER BY due_at ASC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            rows = cursor.fetchall()

            tasks = []
            for row in rows:
                task = dict(row)
                task["is_overdue"] = self._is_overdue(task)
                tasks.append(task)

            return tasks
        finally:
            conn.close()

    def update_status(
        self,
        task_id: str,
        new_status: str,
        changed_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update task status with state machine validation."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM remediation_tasks WHERE task_id = ?", (task_id,)
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Task {task_id} not found")

            current_status = RemediationStatus(row["status"])
            try:
                target_status = RemediationStatus(new_status)
            except ValueError:
                valid = [s.value for s in RemediationStatus]
                raise ValueError(f"Invalid status. Must be one of: {valid}")

            valid_targets = VALID_TRANSITIONS.get(current_status, [])
            if target_status not in valid_targets:
                raise ValueError(
                    f"Invalid transition from {current_status.value} to {target_status.value}. "
                    f"Valid transitions: {[s.value for s in valid_targets]}"
                )

            now = datetime.utcnow().isoformat()
            updates = {"status": target_status.value, "updated_at": now}

            if target_status == RemediationStatus.RESOLVED:
                updates["resolved_at"] = now

            set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
            cursor.execute(
                f"UPDATE remediation_tasks SET {set_clause} WHERE task_id = ?",
                list(updates.values()) + [task_id],
            )

            cursor.execute(
                """
                INSERT INTO task_history (task_id, old_status, new_status, changed_by, reason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    task_id,
                    current_status.value,
                    target_status.value,
                    changed_by,
                    reason,
                    now,
                ),
            )

            conn.commit()

            return {
                "task_id": task_id,
                "old_status": current_status.value,
                "new_status": target_status.value,
                "updated_at": now,
            }
        finally:
            conn.close()

    def assign_task(
        self,
        task_id: str,
        assignee: str,
        assignee_email: Optional[str] = None,
        changed_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Assign task to a user."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT status FROM remediation_tasks WHERE task_id = ?", (task_id,)
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Task {task_id} not found")

            now = datetime.utcnow().isoformat()
            current_status = row["status"]

            new_status = current_status
            if current_status == RemediationStatus.OPEN.value:
                new_status = RemediationStatus.ASSIGNED.value

            cursor.execute(
                """
                UPDATE remediation_tasks
                SET assignee = ?, assignee_email = ?, status = ?, updated_at = ?
                WHERE task_id = ?
            """,
                (assignee, assignee_email, new_status, now, task_id),
            )

            if new_status != current_status:
                cursor.execute(
                    """
                    INSERT INTO task_history (task_id, old_status, new_status, changed_by, reason, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        task_id,
                        current_status,
                        new_status,
                        changed_by,
                        f"Assigned to {assignee}",
                        now,
                    ),
                )

            conn.commit()

            return {
                "task_id": task_id,
                "assignee": assignee,
                "status": new_status,
                "updated_at": now,
            }
        finally:
            conn.close()

    def submit_verification(
        self,
        task_id: str,
        evidence_type: str,
        evidence_data: Dict[str, Any],
        submitted_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit verification evidence for a task."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT status FROM remediation_tasks WHERE task_id = ?", (task_id,)
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Task {task_id} not found")

            now = datetime.utcnow().isoformat()

            cursor.execute(
                """
                INSERT INTO verification_evidence (
                    task_id, evidence_type, evidence_data, submitted_by, submitted_at
                ) VALUES (?, ?, ?, ?, ?)
            """,
                (task_id, evidence_type, json.dumps(evidence_data), submitted_by, now),
            )

            evidence_id = cursor.lastrowid

            current_status = row["status"]
            if current_status == RemediationStatus.IN_PROGRESS.value:
                cursor.execute(
                    """
                    UPDATE remediation_tasks SET status = ?, updated_at = ?
                    WHERE task_id = ?
                """,
                    (RemediationStatus.VERIFICATION.value, now, task_id),
                )
                cursor.execute(
                    """
                    INSERT INTO task_history (task_id, old_status, new_status, changed_by, reason, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        task_id,
                        current_status,
                        RemediationStatus.VERIFICATION.value,
                        submitted_by,
                        "Verification evidence submitted",
                        now,
                    ),
                )

            conn.commit()

            return {
                "evidence_id": evidence_id,
                "task_id": task_id,
                "evidence_type": evidence_type,
                "submitted_at": now,
            }
        finally:
            conn.close()

    def check_sla_breaches(self, org_id: str) -> List[Dict[str, Any]]:
        """Check for SLA breaches and record them."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            now = datetime.utcnow()
            now_str = now.isoformat()

            cursor.execute(
                """
                SELECT * FROM remediation_tasks
                WHERE org_id = ?
                AND due_at < ?
                AND status NOT IN ('resolved', 'wont_fix')
                AND sla_breached = 0
            """,
                (org_id, now_str),
            )

            breaches = []
            for row in cursor.fetchall():
                task = dict(row)
                created_at = datetime.fromisoformat(task["created_at"])
                actual_hours = (now - created_at).total_seconds() / 3600

                cursor.execute(
                    """
                    INSERT INTO sla_breaches (
                        task_id, breach_type, severity, sla_hours, actual_hours, breached_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        task["task_id"],
                        "resolution_sla",
                        task["severity"],
                        task["sla_hours"],
                        actual_hours,
                        now_str,
                    ),
                )

                cursor.execute(
                    "UPDATE remediation_tasks SET sla_breached = 1 WHERE task_id = ?",
                    (task["task_id"],),
                )

                breaches.append(
                    {
                        "task_id": task["task_id"],
                        "severity": task["severity"],
                        "sla_hours": task["sla_hours"],
                        "actual_hours": round(actual_hours, 1),
                        "overdue_hours": round(actual_hours - task["sla_hours"], 1),
                    }
                )

            conn.commit()
            return breaches
        finally:
            conn.close()

    def get_metrics(self, org_id: str, app_id: Optional[str] = None) -> Dict[str, Any]:
        """Get remediation metrics including MTTR."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            base_query = "FROM remediation_tasks WHERE org_id = ?"
            params: List[Any] = [org_id]
            if app_id:
                base_query += " AND app_id = ?"
                params.append(app_id)

            cursor.execute(
                f"SELECT status, COUNT(*) as count {base_query} GROUP BY status", params
            )
            status_counts = {row["status"]: row["count"] for row in cursor.fetchall()}

            cursor.execute(
                f"SELECT severity, COUNT(*) as count {base_query} GROUP BY severity",
                params,
            )
            severity_counts = {
                row["severity"]: row["count"] for row in cursor.fetchall()
            }

            cursor.execute(
                f"""
                SELECT severity,
                       AVG(julianday(resolved_at) - julianday(created_at)) * 24 as avg_hours
                {base_query} AND resolved_at IS NOT NULL
                GROUP BY severity
            """,
                params,
            )
            mttr_by_severity = {
                row["severity"]: (
                    round(row["avg_hours"], 1) if row["avg_hours"] else None
                )
                for row in cursor.fetchall()
            }

            cursor.execute(
                f"SELECT COUNT(*) as total {base_query} AND resolved_at IS NOT NULL",
                params,
            )
            total_resolved = cursor.fetchone()["total"]

            cursor.execute(
                f"SELECT COUNT(*) as breached {base_query} AND sla_breached = 1 AND resolved_at IS NOT NULL",
                params,
            )
            total_breached = cursor.fetchone()["breached"]

            sla_compliance = (
                round((1 - total_breached / total_resolved) * 100, 1)
                if total_resolved > 0
                else 100.0
            )

            now = datetime.utcnow().isoformat()
            cursor.execute(
                f"""
                SELECT COUNT(*) as overdue {base_query}
                AND due_at < ? AND status NOT IN ('resolved', 'wont_fix')
            """,
                params + [now],
            )
            overdue_count = cursor.fetchone()["overdue"]

            return {
                "status_breakdown": status_counts,
                "severity_breakdown": severity_counts,
                "mttr_by_severity_hours": mttr_by_severity,
                "sla_compliance_percent": sla_compliance,
                "overdue_count": overdue_count,
                "total_resolved": total_resolved,
                "total_breached": total_breached,
            }
        finally:
            conn.close()

    def _is_overdue(self, task: Dict[str, Any]) -> bool:
        """Check if task is overdue."""
        if task["status"] in ("resolved", "wont_fix"):
            return False
        if not task.get("due_at"):
            return False
        return datetime.utcnow() > datetime.fromisoformat(task["due_at"])

    def link_to_ticket(
        self, task_id: str, ticket_id: str, ticket_url: Optional[str] = None
    ) -> bool:
        """Link task to external ticket."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE remediation_tasks SET ticket_id = ?, ticket_url = ? WHERE task_id = ?",
                (ticket_id, ticket_url, task_id),
            )
            updated = cursor.rowcount > 0
            conn.commit()
            return updated
        finally:
            conn.close()

    def get_approaching_sla(
        self, org_id: str, hours_threshold: int = 24
    ) -> List[Dict[str, Any]]:
        """Get tasks approaching SLA breach within threshold hours.

        Args:
            org_id: Organization ID
            hours_threshold: Hours before SLA breach to alert (default 24)

        Returns:
            List of tasks approaching SLA breach
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            now = datetime.utcnow()
            threshold_time = (now + timedelta(hours=hours_threshold)).isoformat()

            cursor.execute(
                """
                SELECT * FROM remediation_tasks
                WHERE org_id = ?
                AND due_at > ?
                AND due_at <= ?
                AND status NOT IN ('resolved', 'wont_fix')
                AND sla_breached = 0
                ORDER BY due_at ASC
            """,
                (org_id, now.isoformat(), threshold_time),
            )

            tasks = []
            for row in cursor.fetchall():
                task = dict(row)
                due_at = datetime.fromisoformat(task["due_at"])
                task["hours_until_breach"] = round(
                    (due_at - now).total_seconds() / 3600, 1
                )
                tasks.append(task)

            return tasks
        finally:
            conn.close()

    def escalate_task(
        self,
        task_id: str,
        escalation_type: str,
        escalated_by: Optional[str] = None,
        reason: Optional[str] = None,
        new_assignee: Optional[str] = None,
        raise_priority: bool = False,
    ) -> Dict[str, Any]:
        """Escalate a task due to SLA breach or other reasons.

        Args:
            task_id: Task ID to escalate
            escalation_type: Type of escalation (sla_breach, manual, auto)
            escalated_by: User who triggered escalation
            reason: Reason for escalation
            new_assignee: New assignee for escalated task
            raise_priority: Whether to raise severity by one level

        Returns:
            Escalation result
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM remediation_tasks WHERE task_id = ?", (task_id,)
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Task {task_id} not found")

            task = dict(row)
            now = datetime.utcnow().isoformat()

            updates: Dict[str, Any] = {"updated_at": now}
            escalation_details: Dict[str, Any] = {
                "task_id": task_id,
                "escalation_type": escalation_type,
                "escalated_at": now,
                "escalated_by": escalated_by,
                "reason": reason,
            }

            # Raise priority if requested
            if raise_priority:
                severity_order = ["low", "medium", "high", "critical"]
                current_idx = severity_order.index(task["severity"])
                if current_idx < len(severity_order) - 1:
                    new_severity = severity_order[current_idx + 1]
                    updates["severity"] = new_severity
                    escalation_details["severity_raised"] = {
                        "from": task["severity"],
                        "to": new_severity,
                    }
                    # Update SLA based on new severity
                    new_sla_hours = self.sla_policies.get(new_severity, 168)
                    created_at = datetime.fromisoformat(task["created_at"])
                    new_due_at = (
                        created_at + timedelta(hours=new_sla_hours)
                    ).isoformat()
                    updates["sla_hours"] = new_sla_hours
                    updates["due_at"] = new_due_at

            # Reassign if new assignee provided
            if new_assignee:
                updates["assignee"] = new_assignee
                escalation_details["reassigned_to"] = new_assignee

            # Update task
            if updates:
                set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
                cursor.execute(
                    f"UPDATE remediation_tasks SET {set_clause} WHERE task_id = ?",
                    list(updates.values()) + [task_id],
                )

            # Record escalation in history
            cursor.execute(
                """
                INSERT INTO task_history (
                    task_id, old_status, new_status, changed_by, reason, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    task_id,
                    task["status"],
                    task["status"],
                    escalated_by,
                    f"Escalation ({escalation_type}): {reason or 'No reason provided'}",
                    now,
                ),
            )

            conn.commit()
            return escalation_details
        finally:
            conn.close()

    def run_sla_check_and_escalate(
        self,
        org_id: str,
        auto_escalate: bool = True,
        notify_callback: Optional[Callable[..., Any]] = None,
    ) -> Dict[str, Any]:
        """Run SLA check and optionally auto-escalate breached tasks.

        This is the main method to be called by the background scheduler.

        Args:
            org_id: Organization ID
            auto_escalate: Whether to auto-escalate breached tasks
            notify_callback: Optional callback for notifications

        Returns:
            Summary of SLA check results
        """
        results: Dict[str, Any] = {
            "checked_at": datetime.utcnow().isoformat(),
            "org_id": org_id,
            "breaches_detected": [],
            "approaching_breach": [],
            "escalations": [],
            "notifications_sent": [],
        }

        # Check for new SLA breaches
        breaches = self.check_sla_breaches(org_id)
        results["breaches_detected"] = breaches

        # Auto-escalate breached tasks
        if auto_escalate:
            for breach in breaches:
                try:
                    escalation = self.escalate_task(
                        task_id=breach["task_id"],
                        escalation_type="sla_breach",
                        escalated_by="system",
                        reason=f"SLA breached: {breach['actual_hours']}h vs {breach['sla_hours']}h target",
                        raise_priority=True,
                    )
                    results["escalations"].append(escalation)

                    # Send notification if callback provided
                    if notify_callback:
                        try:
                            notify_callback(
                                event_type="sla_breach",
                                task_id=breach["task_id"],
                                details=breach,
                            )
                            results["notifications_sent"].append(
                                {"task_id": breach["task_id"], "type": "sla_breach"}
                            )
                        except Exception as e:
                            logger.warning(
                                f"Failed to send SLA breach notification for task "
                                f"{breach['task_id']}: {e}"
                            )
                            results.setdefault("notification_failures", []).append(
                                {"task_id": breach["task_id"], "error": str(e)}
                            )
                except Exception as e:
                    logger.error(f"Failed to escalate task {breach['task_id']}: {e}")
                    results.setdefault("escalation_failures", []).append(
                        {"task_id": breach["task_id"], "error": str(e)}
                    )

        # Check for tasks approaching SLA breach (24h warning)
        approaching = self.get_approaching_sla(org_id, hours_threshold=24)
        results["approaching_breach"] = [
            {
                "task_id": t["task_id"],
                "severity": t["severity"],
                "hours_until_breach": t["hours_until_breach"],
            }
            for t in approaching
        ]

        # Send warning notifications for approaching breaches
        if notify_callback:
            for task in approaching:
                try:
                    notify_callback(
                        event_type="sla_warning",
                        task_id=task["task_id"],
                        details={
                            "hours_until_breach": task["hours_until_breach"],
                            "severity": task["severity"],
                        },
                    )
                    results["notifications_sent"].append(
                        {"task_id": task["task_id"], "type": "sla_warning"}
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to send SLA warning notification for task "
                        f"{task['task_id']}: {e}"
                    )
                    results.setdefault("notification_failures", []).append(
                        {"task_id": task["task_id"], "error": str(e)}
                    )

        return results

    def get_escalation_history(self, task_id: str) -> List[Dict[str, Any]]:
        """Get escalation history for a task.

        Args:
            task_id: Task ID

        Returns:
            List of escalation events
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM task_history
                WHERE task_id = ? AND reason LIKE 'Escalation%'
                ORDER BY timestamp DESC
            """,
                (task_id,),
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()


# ============================================================================
# SLA Background Scheduler
# ============================================================================


class SLAScheduler:
    """Background scheduler for SLA monitoring and escalation.

    This scheduler runs periodically to:
    1. Check for SLA breaches
    2. Auto-escalate breached tasks
    3. Send notifications for approaching breaches
    4. Generate SLA reports
    """

    def __init__(
        self,
        remediation_service: RemediationService,
        check_interval_minutes: int = 15,
        notify_callback: Optional[Callable[..., Any]] = None,
    ):
        """Initialize SLA scheduler.

        Args:
            remediation_service: RemediationService instance
            check_interval_minutes: How often to check SLAs (default 15 min)
            notify_callback: Callback for sending notifications
        """
        self.remediation_service = remediation_service
        self.check_interval_minutes = check_interval_minutes
        self.notify_callback = notify_callback
        self._running = False

    def run_check(self, org_id: str) -> Dict[str, Any]:
        """Run a single SLA check for an organization.

        Args:
            org_id: Organization ID to check

        Returns:
            Check results
        """
        return self.remediation_service.run_sla_check_and_escalate(
            org_id=org_id,
            auto_escalate=True,
            notify_callback=self.notify_callback,
        )

    def run_check_all_orgs(self, org_ids: List[str]) -> Dict[str, Any]:
        """Run SLA check for multiple organizations.

        Args:
            org_ids: List of organization IDs

        Returns:
            Aggregated results
        """
        results: Dict[str, Any] = {
            "checked_at": datetime.utcnow().isoformat(),
            "organizations_checked": len(org_ids),
            "total_breaches": 0,
            "total_escalations": 0,
            "total_warnings": 0,
            "by_org": {},
        }

        for org_id in org_ids:
            try:
                org_result = self.run_check(org_id)
                results["by_org"][org_id] = org_result
                results["total_breaches"] += len(
                    org_result.get("breaches_detected", [])
                )
                results["total_escalations"] += len(org_result.get("escalations", []))
                results["total_warnings"] += len(
                    org_result.get("approaching_breach", [])
                )
            except Exception as e:
                results["by_org"][org_id] = {"error": str(e)}

        return results

    async def start_async(self, org_ids: List[str]) -> None:
        """Start async background scheduler.

        Args:
            org_ids: List of organization IDs to monitor
        """
        import asyncio
        import logging

        logger = logging.getLogger(__name__)
        self._running = True
        delay_seconds = self.check_interval_minutes * 60

        logger.info(
            f"Starting SLA scheduler with {self.check_interval_minutes}min interval"
        )

        while self._running:
            try:
                logger.info("Running scheduled SLA check")
                # Run blocking DB operations in thread pool to avoid blocking event loop
                results = await asyncio.to_thread(self.run_check_all_orgs, org_ids)
                logger.info(
                    f"SLA check complete: {results['total_breaches']} breaches, "
                    f"{results['total_escalations']} escalations, "
                    f"{results['total_warnings']} warnings"
                )
            except Exception as e:
                logger.error(f"SLA check failed: {e}")

            await asyncio.sleep(delay_seconds)

    def stop(self) -> None:
        """Stop the background scheduler."""
        self._running = False
