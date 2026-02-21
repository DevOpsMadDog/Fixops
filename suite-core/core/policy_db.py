"""
Policy database manager using SQLite.
"""
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.policy_models import Policy, PolicyStatus


class PolicyDB:
    """Database manager for policy records."""

    def __init__(self, db_path: str = "data/policies.db"):
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
                CREATE TABLE IF NOT EXISTS policies (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL,
                    policy_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    rules TEXT NOT NULL,
                    metadata TEXT,
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(policy_type);
                CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status);
            """
            )
            conn.commit()
        finally:
            conn.close()

    def create_policy(self, policy: Policy) -> Policy:
        """Create new policy."""
        if not policy.id:
            policy.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO policies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    policy.id,
                    policy.name,
                    policy.description,
                    policy.policy_type,
                    policy.status.value,
                    json.dumps(policy.rules),
                    json.dumps(policy.metadata),
                    policy.created_by,
                    policy.created_at.isoformat(),
                    policy.updated_at.isoformat(),
                ),
            )
            conn.commit()
            return policy
        finally:
            conn.close()

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get policy by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM policies WHERE id = ?", (policy_id,)
            ).fetchone()
            if row:
                return self._row_to_policy(row)
            return None
        finally:
            conn.close()

    def list_policies(
        self, policy_type: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[Policy]:
        """List policies with optional filtering."""
        conn = self._get_connection()
        try:
            if policy_type:
                rows = conn.execute(
                    "SELECT * FROM policies WHERE policy_type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (policy_type, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM policies ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_policy(row) for row in rows]
        finally:
            conn.close()

    def update_policy(self, policy: Policy) -> Policy:
        """Update policy."""
        policy.updated_at = datetime.utcnow()
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE policies SET name=?, description=?, policy_type=?, status=?,
                   rules=?, metadata=?, updated_at=? WHERE id=?""",
                (
                    policy.name,
                    policy.description,
                    policy.policy_type,
                    policy.status.value,
                    json.dumps(policy.rules),
                    json.dumps(policy.metadata),
                    policy.updated_at.isoformat(),
                    policy.id,
                ),
            )
            conn.commit()
            return policy
        finally:
            conn.close()

    def delete_policy(self, policy_id: str) -> bool:
        """Delete policy."""
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def _row_to_policy(self, row) -> Policy:
        """Convert database row to Policy object."""
        return Policy(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            policy_type=row["policy_type"],
            status=PolicyStatus(row["status"]),
            rules=json.loads(row["rules"]) if row["rules"] else {},
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_by=row["created_by"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
