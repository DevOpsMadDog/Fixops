"""
Authentication and SSO database manager using SQLite.

Manages: SSO configs, SAML assertions, users, and scoped API keys.
"""
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.auth_models import (
    APIKey,
    AuthProvider,
    SSOConfig,
    SSOStatus,
    User,
    UserRole,
)


class AuthDB:
    """Database manager for authentication, users, and API keys."""

    def __init__(self, db_path: str = "data/auth.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        conn = self._get_connection()
        try:
            conn.executescript("""
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
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    password_hash TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    org_id TEXT NOT NULL DEFAULT 'default',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    key_prefix TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    scopes TEXT NOT NULL DEFAULT '[]',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    expires_at TEXT,
                    last_used_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE INDEX IF NOT EXISTS idx_sso_provider ON sso_configs(provider);
                CREATE INDEX IF NOT EXISTS idx_saml_user ON saml_assertions(user_id);
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
                CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
                CREATE INDEX IF NOT EXISTS idx_apikeys_prefix ON api_keys(key_prefix);
                CREATE INDEX IF NOT EXISTS idx_apikeys_user ON api_keys(user_id);
                CREATE INDEX IF NOT EXISTS idx_apikeys_active ON api_keys(is_active);
            """)
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
        return SSOConfig(
            id=row["id"], name=row["name"],
            provider=AuthProvider(row["provider"]),
            status=SSOStatus(row["status"]),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            entity_id=row["entity_id"], sso_url=row["sso_url"],
            certificate=row["certificate"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    # ------------------------------------------------------------------
    # User CRUD
    # ------------------------------------------------------------------

    def create_user(self, user: User) -> User:
        if not user.id:
            user.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?)",
                (user.id, user.email, user.name, user.role.value,
                 user.password_hash, int(user.is_active), user.org_id,
                 user.created_at.isoformat(), user.updated_at.isoformat()),
            )
            conn.commit()
            return user
        finally:
            conn.close()

    def get_user(self, user_id: str) -> Optional[User]:
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return self._row_to_user(row) if row else None
        finally:
            conn.close()

    def get_user_by_email(self, email: str) -> Optional[User]:
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            return self._row_to_user(row) if row else None
        finally:
            conn.close()

    def list_users(self, org_id: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[User]:
        conn = self._get_connection()
        try:
            if org_id:
                rows = conn.execute(
                    "SELECT * FROM users WHERE org_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (org_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_user(r) for r in rows]
        finally:
            conn.close()

    def _row_to_user(self, row) -> User:
        return User(
            id=row["id"], email=row["email"], name=row["name"],
            role=UserRole(row["role"]), password_hash=row["password_hash"],
            is_active=bool(row["is_active"]), org_id=row["org_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    # ------------------------------------------------------------------
    # API Key CRUD
    # ------------------------------------------------------------------

    def create_api_key(self, key: APIKey) -> APIKey:
        if not key.id:
            key.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT INTO api_keys VALUES (?,?,?,?,?,?,?,?,?,?)",
                (key.id, key.key_prefix, key.key_hash, key.user_id, key.name,
                 json.dumps(key.scopes), int(key.is_active),
                 key.expires_at.isoformat() if key.expires_at else None,
                 key.last_used_at.isoformat() if key.last_used_at else None,
                 key.created_at.isoformat()),
            )
            conn.commit()
            return key
        finally:
            conn.close()

    def get_api_key_by_prefix(self, prefix: str) -> Optional[APIKey]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_prefix = ? AND is_active = 1",
                (prefix,),
            ).fetchone()
            return self._row_to_api_key(row) if row else None
        finally:
            conn.close()

    def list_api_keys(self, user_id: str) -> List[APIKey]:
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            return [self._row_to_api_key(r) for r in rows]
        finally:
            conn.close()

    def revoke_api_key(self, key_id: str) -> bool:
        conn = self._get_connection()
        try:
            conn.execute("UPDATE api_keys SET is_active = 0 WHERE id = ?", (key_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def touch_api_key(self, key_id: str):
        """Update last_used_at timestamp."""
        conn = self._get_connection()
        try:
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), key_id),
            )
            conn.commit()
        finally:
            conn.close()

    def _row_to_api_key(self, row) -> APIKey:
        return APIKey(
            id=row["id"], key_prefix=row["key_prefix"], key_hash=row["key_hash"],
            user_id=row["user_id"], name=row["name"],
            scopes=json.loads(row["scopes"]) if row["scopes"] else [],
            is_active=bool(row["is_active"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            last_used_at=datetime.fromisoformat(row["last_used_at"]) if row["last_used_at"] else None,
            created_at=datetime.fromisoformat(row["created_at"]),
        )
