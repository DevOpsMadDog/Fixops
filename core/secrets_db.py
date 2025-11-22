"""
Secrets detection database manager using SQLite.
"""
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.secrets_models import SecretFinding, SecretStatus, SecretType


class SecretsDB:
    """Database manager for secrets detection."""

    def __init__(self, db_path: str = "data/secrets.db"):
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
                CREATE TABLE IF NOT EXISTS secret_findings (
                    id TEXT PRIMARY KEY,
                    secret_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    repository TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    commit_hash TEXT,
                    matched_pattern TEXT,
                    entropy_score REAL,
                    metadata TEXT,
                    detected_at TEXT NOT NULL,
                    resolved_at TEXT
                );

                CREATE TABLE IF NOT EXISTS secret_scan_configs (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    enabled INTEGER NOT NULL,
                    patterns TEXT,
                    exclusions TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_secret_type ON secret_findings(secret_type);
                CREATE INDEX IF NOT EXISTS idx_secret_status ON secret_findings(status);
                CREATE INDEX IF NOT EXISTS idx_secret_repo ON secret_findings(repository);
            """
            )
            conn.commit()
        finally:
            conn.close()

    def create_finding(self, finding: SecretFinding) -> SecretFinding:
        """Create new secret finding."""
        if not finding.id:
            finding.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO secret_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.id,
                    finding.secret_type.value,
                    finding.status.value,
                    finding.file_path,
                    finding.line_number,
                    finding.repository,
                    finding.branch,
                    finding.commit_hash,
                    finding.matched_pattern,
                    finding.entropy_score,
                    json.dumps(finding.metadata),
                    finding.detected_at.isoformat(),
                    finding.resolved_at.isoformat() if finding.resolved_at else None,
                ),
            )
            conn.commit()
            return finding
        finally:
            conn.close()

    def get_finding(self, finding_id: str) -> Optional[SecretFinding]:
        """Get secret finding by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM secret_findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if row:
                return self._row_to_finding(row)
            return None
        finally:
            conn.close()

    def list_findings(
        self, repository: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[SecretFinding]:
        """List secret findings with optional filtering."""
        conn = self._get_connection()
        try:
            if repository:
                rows = conn.execute(
                    "SELECT * FROM secret_findings WHERE repository = ? ORDER BY detected_at DESC LIMIT ? OFFSET ?",
                    (repository, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM secret_findings ORDER BY detected_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_finding(row) for row in rows]
        finally:
            conn.close()

    def update_finding(self, finding: SecretFinding) -> SecretFinding:
        """Update secret finding."""
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE secret_findings SET status=?, resolved_at=? WHERE id=?""",
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

    def _row_to_finding(self, row) -> SecretFinding:
        """Convert database row to SecretFinding object."""
        return SecretFinding(
            id=row["id"],
            secret_type=SecretType(row["secret_type"]),
            status=SecretStatus(row["status"]),
            file_path=row["file_path"],
            line_number=row["line_number"],
            repository=row["repository"],
            branch=row["branch"],
            commit_hash=row["commit_hash"],
            matched_pattern=row["matched_pattern"],
            entropy_score=row["entropy_score"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            detected_at=datetime.fromisoformat(row["detected_at"]),
            resolved_at=(
                datetime.fromisoformat(row["resolved_at"])
                if row["resolved_at"]
                else None
            ),
        )
