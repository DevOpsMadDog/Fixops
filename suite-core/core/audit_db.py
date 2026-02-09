"""
Audit and compliance database manager using SQLite.
"""
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.audit_models import (
    AuditEventType,
    AuditLog,
    AuditSeverity,
    ComplianceControl,
    ComplianceFramework,
)


class AuditDB:
    """Database manager for audit and compliance records."""

    def __init__(self, db_path: str = "data/audit.db"):
        """Initialize database connection."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Initialize database tables."""
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    user_id TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS compliance_frameworks (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    version TEXT NOT NULL,
                    description TEXT NOT NULL,
                    controls TEXT,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS compliance_controls (
                    id TEXT PRIMARY KEY,
                    framework_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL,
                    requirements TEXT,
                    metadata TEXT,
                    FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(id)
                );

                CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
                CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
                CREATE INDEX IF NOT EXISTS idx_compliance_controls_framework ON compliance_controls(framework_id);
            """
            )
            conn.commit()
        finally:
            conn.close()

    def create_audit_log(self, log: AuditLog) -> AuditLog:
        """Create audit log entry."""
        if not log.id:
            log.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    log.id,
                    log.event_type.value,
                    log.severity.value,
                    log.user_id,
                    log.resource_type,
                    log.resource_id,
                    log.action,
                    json.dumps(log.details),
                    log.ip_address,
                    log.user_agent,
                    log.timestamp.isoformat(),
                ),
            )
            conn.commit()
            return log
        finally:
            conn.close()

    def list_audit_logs(
        self,
        event_type: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """List audit logs with optional filtering."""
        conn = self._get_connection()
        try:
            if event_type and user_id:
                rows = conn.execute(
                    "SELECT * FROM audit_logs WHERE event_type = ? AND user_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (event_type, user_id, limit, offset),
                ).fetchall()
            elif event_type:
                rows = conn.execute(
                    "SELECT * FROM audit_logs WHERE event_type = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (event_type, limit, offset),
                ).fetchall()
            elif user_id:
                rows = conn.execute(
                    "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (user_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_audit_log(row) for row in rows]
        finally:
            conn.close()

    def create_framework(self, framework: ComplianceFramework) -> ComplianceFramework:
        """Create compliance framework."""
        if not framework.id:
            framework.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO compliance_frameworks VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    framework.id,
                    framework.name,
                    framework.version,
                    framework.description,
                    json.dumps(framework.controls),
                    json.dumps(framework.metadata),
                    framework.created_at.isoformat(),
                    framework.updated_at.isoformat(),
                ),
            )
            conn.commit()
            return framework
        finally:
            conn.close()

    def get_framework(self, framework_id: str) -> Optional[ComplianceFramework]:
        """Get compliance framework by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM compliance_frameworks WHERE id = ?", (framework_id,)
            ).fetchone()
            if row:
                return self._row_to_framework(row)
            return None
        finally:
            conn.close()

    def list_frameworks(
        self, limit: int = 100, offset: int = 0
    ) -> List[ComplianceFramework]:
        """List compliance frameworks."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM compliance_frameworks ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [self._row_to_framework(row) for row in rows]
        finally:
            conn.close()

    def create_control(self, control: ComplianceControl) -> ComplianceControl:
        """Create compliance control."""
        if not control.id:
            control.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO compliance_controls VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    control.id,
                    control.framework_id,
                    control.control_id,
                    control.name,
                    control.description,
                    control.category,
                    json.dumps(control.requirements),
                    json.dumps(control.metadata),
                ),
            )
            conn.commit()
            return control
        finally:
            conn.close()

    def list_controls(
        self, framework_id: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[ComplianceControl]:
        """List compliance controls."""
        conn = self._get_connection()
        try:
            if framework_id:
                rows = conn.execute(
                    "SELECT * FROM compliance_controls WHERE framework_id = ? LIMIT ? OFFSET ?",
                    (framework_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM compliance_controls LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_control(row) for row in rows]
        finally:
            conn.close()

    def _row_to_audit_log(self, row) -> AuditLog:
        """Convert database row to AuditLog object."""
        return AuditLog(
            id=row["id"],
            event_type=AuditEventType(row["event_type"]),
            severity=AuditSeverity(row["severity"]),
            user_id=row["user_id"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            action=row["action"],
            details=json.loads(row["details"]) if row["details"] else {},
            ip_address=row["ip_address"],
            user_agent=row["user_agent"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
        )

    def _row_to_framework(self, row) -> ComplianceFramework:
        """Convert database row to ComplianceFramework object."""
        return ComplianceFramework(
            id=row["id"],
            name=row["name"],
            version=row["version"],
            description=row["description"],
            controls=json.loads(row["controls"]) if row["controls"] else [],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def _row_to_control(self, row) -> ComplianceControl:
        """Convert database row to ComplianceControl object."""
        return ComplianceControl(
            id=row["id"],
            framework_id=row["framework_id"],
            control_id=row["control_id"],
            name=row["name"],
            description=row["description"],
            category=row["category"],
            requirements=json.loads(row["requirements"]) if row["requirements"] else [],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )
