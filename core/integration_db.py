"""
Integration database manager using SQLite.
"""
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.integration_models import Integration, IntegrationStatus, IntegrationType


class IntegrationDB:
    """Database manager for integration records."""

    def __init__(self, db_path: str = "data/integrations.db"):
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
                CREATE TABLE IF NOT EXISTS integrations (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    integration_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    config TEXT NOT NULL,
                    last_sync_at TEXT,
                    last_sync_status TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations(integration_type);
                CREATE INDEX IF NOT EXISTS idx_integrations_status ON integrations(status);
            """
            )
            conn.commit()
        finally:
            conn.close()

    def create_integration(self, integration: Integration) -> Integration:
        """Create new integration."""
        if not integration.id:
            integration.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO integrations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    integration.id,
                    integration.name,
                    integration.integration_type.value,
                    integration.status.value,
                    json.dumps(integration.config),
                    integration.last_sync_at.isoformat()
                    if integration.last_sync_at
                    else None,
                    integration.last_sync_status,
                    integration.created_at.isoformat(),
                    integration.updated_at.isoformat(),
                ),
            )
            conn.commit()
            return integration
        finally:
            conn.close()

    def get_integration(self, integration_id: str) -> Optional[Integration]:
        """Get integration by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM integrations WHERE id = ?", (integration_id,)
            ).fetchone()
            if row:
                return self._row_to_integration(row)
            return None
        finally:
            conn.close()

    def list_integrations(
        self, integration_type: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[Integration]:
        """List integrations with optional filtering."""
        conn = self._get_connection()
        try:
            if integration_type:
                rows = conn.execute(
                    "SELECT * FROM integrations WHERE integration_type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (integration_type, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM integrations ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_integration(row) for row in rows]
        finally:
            conn.close()

    def update_integration(self, integration: Integration) -> Integration:
        """Update integration."""
        integration.updated_at = datetime.utcnow()
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE integrations SET name=?, integration_type=?, status=?, config=?,
                   last_sync_at=?, last_sync_status=?, updated_at=? WHERE id=?""",
                (
                    integration.name,
                    integration.integration_type.value,
                    integration.status.value,
                    json.dumps(integration.config),
                    integration.last_sync_at.isoformat()
                    if integration.last_sync_at
                    else None,
                    integration.last_sync_status,
                    integration.updated_at.isoformat(),
                    integration.id,
                ),
            )
            conn.commit()
            return integration
        finally:
            conn.close()

    def delete_integration(self, integration_id: str) -> bool:
        """Delete integration."""
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM integrations WHERE id = ?", (integration_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def _row_to_integration(self, row) -> Integration:
        """Convert database row to Integration object."""
        return Integration(
            id=row["id"],
            name=row["name"],
            integration_type=IntegrationType(row["integration_type"]),
            status=IntegrationStatus(row["status"]),
            config=json.loads(row["config"]) if row["config"] else {},
            last_sync_at=(
                datetime.fromisoformat(row["last_sync_at"])
                if row["last_sync_at"]
                else None
            ),
            last_sync_status=row["last_sync_status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
