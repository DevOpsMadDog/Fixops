"""
Authentication and SSO database manager using SQLite.
"""
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.auth_models import AuthProvider, SSOConfig, SSOStatus


class AuthDB:
    """Database manager for authentication and SSO."""

    def __init__(self, db_path: str = "data/auth.db"):
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
                CREATE TABLE IF NOT EXISTS sso_configs (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    provider TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metadata TEXT,
                    entity_id TEXT,
                    sso_url TEXT,
                    certificate TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS saml_assertions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    assertion_data TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_sso_provider ON sso_configs(provider);
                CREATE INDEX IF NOT EXISTS idx_saml_user ON saml_assertions(user_id);
            """
            )
            conn.commit()
        finally:
            conn.close()

    def create_sso_config(self, config: SSOConfig) -> SSOConfig:
        """Create new SSO configuration."""
        if not config.id:
            config.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO sso_configs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    config.id,
                    config.name,
                    config.provider.value,
                    config.status.value,
                    json.dumps(config.metadata),
                    config.entity_id,
                    config.sso_url,
                    config.certificate,
                    config.created_at.isoformat(),
                    config.updated_at.isoformat(),
                ),
            )
            conn.commit()
            return config
        finally:
            conn.close()

    def get_sso_config(self, config_id: str) -> Optional[SSOConfig]:
        """Get SSO configuration by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM sso_configs WHERE id = ?", (config_id,)
            ).fetchone()
            if row:
                return self._row_to_sso_config(row)
            return None
        finally:
            conn.close()

    def list_sso_configs(self, limit: int = 100, offset: int = 0) -> List[SSOConfig]:
        """List SSO configurations with pagination."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM sso_configs ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [self._row_to_sso_config(row) for row in rows]
        finally:
            conn.close()

    def update_sso_config(self, config: SSOConfig) -> SSOConfig:
        """Update SSO configuration."""
        config.updated_at = datetime.utcnow()
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE sso_configs SET name=?, provider=?, status=?, metadata=?,
                   entity_id=?, sso_url=?, certificate=?, updated_at=? WHERE id=?""",
                (
                    config.name,
                    config.provider.value,
                    config.status.value,
                    json.dumps(config.metadata),
                    config.entity_id,
                    config.sso_url,
                    config.certificate,
                    config.updated_at.isoformat(),
                    config.id,
                ),
            )
            conn.commit()
            return config
        finally:
            conn.close()

    def delete_sso_config(self, config_id: str) -> bool:
        """Delete SSO configuration."""
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM sso_configs WHERE id = ?", (config_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def _row_to_sso_config(self, row) -> SSOConfig:
        """Convert database row to SSOConfig object."""
        return SSOConfig(
            id=row["id"],
            name=row["name"],
            provider=AuthProvider(row["provider"]),
            status=SSOStatus(row["status"]),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            entity_id=row["entity_id"],
            sso_url=row["sso_url"],
            certificate=row["certificate"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
