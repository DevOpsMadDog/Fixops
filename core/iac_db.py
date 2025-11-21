"""
IaC scanning database manager using SQLite.
"""
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.iac_models import IaCFinding, IaCFindingStatus, IaCProvider


class IaCDB:
    """Database manager for IaC scanning."""

    def __init__(self, db_path: str = "data/iac.db"):
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
                CREATE TABLE IF NOT EXISTS iac_findings (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_name TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    remediation TEXT,
                    metadata TEXT,
                    detected_at TEXT NOT NULL,
                    resolved_at TEXT
                );

                CREATE TABLE IF NOT EXISTS iac_scan_configs (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    provider TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    rules TEXT,
                    exclusions TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_iac_provider ON iac_findings(provider);
                CREATE INDEX IF NOT EXISTS idx_iac_status ON iac_findings(status);
                CREATE INDEX IF NOT EXISTS idx_iac_severity ON iac_findings(severity);
            """
            )
            conn.commit()
        finally:
            conn.close()

    def create_finding(self, finding: IaCFinding) -> IaCFinding:
        """Create new IaC finding."""
        if not finding.id:
            finding.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO iac_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.id,
                    finding.provider.value,
                    finding.status.value,
                    finding.severity,
                    finding.title,
                    finding.description,
                    finding.file_path,
                    finding.line_number,
                    finding.resource_type,
                    finding.resource_name,
                    finding.rule_id,
                    finding.remediation,
                    json.dumps(finding.metadata),
                    finding.detected_at.isoformat(),
                    finding.resolved_at.isoformat() if finding.resolved_at else None,
                ),
            )
            conn.commit()
            return finding
        finally:
            conn.close()

    def get_finding(self, finding_id: str) -> Optional[IaCFinding]:
        """Get IaC finding by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM iac_findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if row:
                return self._row_to_finding(row)
            return None
        finally:
            conn.close()

    def list_findings(
        self, provider: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[IaCFinding]:
        """List IaC findings with optional filtering."""
        conn = self._get_connection()
        try:
            if provider:
                rows = conn.execute(
                    "SELECT * FROM iac_findings WHERE provider = ? ORDER BY detected_at DESC LIMIT ? OFFSET ?",
                    (provider, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM iac_findings ORDER BY detected_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_finding(row) for row in rows]
        finally:
            conn.close()

    def update_finding(self, finding: IaCFinding) -> IaCFinding:
        """Update IaC finding."""
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE iac_findings SET status=?, resolved_at=? WHERE id=?""",
                (
                    finding.status.value,
                    finding.resolved_at.isoformat() if finding.resolved_at else None,
                    finding.id,
                ),
            )
            conn.commit()
            return finding
        finally:
            conn.close()

    def _row_to_finding(self, row) -> IaCFinding:
        """Convert database row to IaCFinding object."""
        return IaCFinding(
            id=row["id"],
            provider=IaCProvider(row["provider"]),
            status=IaCFindingStatus(row["status"]),
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            file_path=row["file_path"],
            line_number=row["line_number"],
            resource_type=row["resource_type"],
            resource_name=row["resource_name"],
            rule_id=row["rule_id"],
            remediation=row["remediation"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            detected_at=datetime.fromisoformat(row["detected_at"]),
            resolved_at=(
                datetime.fromisoformat(row["resolved_at"])
                if row["resolved_at"]
                else None
            ),
        )
