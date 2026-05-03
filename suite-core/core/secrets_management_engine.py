"""Secrets Management Engine — ALDECI.

Manages organizational secrets lifecycle: storage, rotation, revocation, and
access auditing. Never returns actual secret values — metadata only.

Capabilities:
  - Store secret metadata (name, type, path, tags, rotation policy)
  - List/get secrets by org_id (values never exposed)
  - Rotate secrets (records rotation timestamp)
  - Revoke secrets with reason
  - Detect expiring/overdue secrets
  - Full access audit log per secret

Compliance: NIST SP 800-57 (key management), CIS Control 3.11
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_SECRET_TYPES = {
    "api_key", "password", "certificate", "token", "ssh_key", "database"
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecretsManagementEngine:
    """SQLite WAL-backed Secrets Management engine.

    Thread-safe via RLock. Multi-tenant via org_id isolation.
    Secret values are NEVER stored or returned — metadata only.
    """

    def __init__(self, db_path: str = "") -> None:
        if not db_path:
            db_path = str(Path(_DEFAULT_DB_DIR) / "secrets_management.db")
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
                CREATE TABLE IF NOT EXISTS secrets (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    secret_type     TEXT NOT NULL DEFAULT 'api_key',
                    path            TEXT NOT NULL DEFAULT '',
                    tags            TEXT NOT NULL DEFAULT '[]',
                    rotation_days   INTEGER NOT NULL DEFAULT 90,
                    status          TEXT NOT NULL DEFAULT 'active',
                    created_at      TEXT NOT NULL,
                    last_rotated    TEXT,
                    revoked_at      TEXT,
                    revoke_reason   TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_secrets_org
                    ON secrets (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_secrets_org_type
                    ON secrets (org_id, secret_type);

                CREATE TABLE IF NOT EXISTS access_log (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    secret_id   TEXT NOT NULL,
                    accessor    TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    accessed_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_access_log_secret
                    ON access_log (org_id, secret_id, accessed_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "tags" in d and isinstance(d["tags"], str):
            try:
                d["tags"] = json.loads(d["tags"])
            except (json.JSONDecodeError, TypeError):
                d["tags"] = []
        return d

    # ------------------------------------------------------------------
    # Core CRUD
    # ------------------------------------------------------------------

    def store_secret(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Store secret metadata. The actual secret value is never persisted."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        secret_type = data.get("secret_type", "api_key")
        if secret_type not in _VALID_SECRET_TYPES:
            raise ValueError(
                f"Invalid secret_type: {secret_type}. Must be one of {_VALID_SECRET_TYPES}"
            )

        tags = data.get("tags", [])
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "secret_type": secret_type,
            "path": data.get("path", ""),
            "tags": json.dumps(tags if isinstance(tags, list) else []),
            "rotation_days": int(data.get("rotation_days", 90)),
            "status": "active",
            "created_at": now,
            "last_rotated": now,
            "revoked_at": None,
            "revoke_reason": "",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO secrets
                       (id, org_id, name, secret_type, path, tags, rotation_days,
                        status, created_at, last_rotated, revoked_at, revoke_reason)
                       VALUES (:id, :org_id, :name, :secret_type, :path, :tags,
                               :rotation_days, :status, :created_at, :last_rotated,
                               :revoked_at, :revoke_reason)""",
                    record,
                )
        record["tags"] = tags if isinstance(tags, list) else []
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "secrets_management", "org_id": org_id, "source_engine": "secrets_management"})
            except Exception:
                pass

        return record

    def list_secrets(
        self, org_id: str, secret_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List secret metadata for org. Secret values are never returned."""
        sql = "SELECT * FROM secrets WHERE org_id = ?"
        params: list = [org_id]
        if secret_type:
            sql += " AND secret_type = ?"
            params.append(secret_type)
        sql += " ORDER BY name ASC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_secret_metadata(self, org_id: str, secret_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve metadata for a single secret. No value returned."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM secrets WHERE org_id = ? AND id = ?",
                (org_id, secret_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def rotate_secret(self, org_id: str, secret_id: str) -> Dict[str, Any]:
        """Record secret rotation — updates last_rotated timestamp."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM secrets WHERE org_id = ? AND id = ?",
                    (org_id, secret_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Secret {secret_id} not found.")
                secret = self._row(row)
                if secret["status"] == "revoked":
                    raise ValueError("Cannot rotate a revoked secret.")
                conn.execute(
                    "UPDATE secrets SET last_rotated = ?, status = 'active' WHERE org_id = ? AND id = ?",
                    (now, org_id, secret_id),
                )
                updated = conn.execute(
                    "SELECT * FROM secrets WHERE org_id = ? AND id = ?",
                    (org_id, secret_id),
                ).fetchone()
        return self._row(updated)

    def revoke_secret(self, org_id: str, secret_id: str, reason: str) -> Dict[str, Any]:
        """Revoke a secret permanently with a stated reason."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM secrets WHERE org_id = ? AND id = ?",
                    (org_id, secret_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Secret {secret_id} not found.")
                conn.execute(
                    """UPDATE secrets SET status = 'revoked', revoked_at = ?,
                       revoke_reason = ? WHERE org_id = ? AND id = ?""",
                    (now, reason or "", org_id, secret_id),
                )
                updated = conn.execute(
                    "SELECT * FROM secrets WHERE org_id = ? AND id = ?",
                    (org_id, secret_id),
                ).fetchone()
        return self._row(updated)

    def get_expiring_secrets(self, org_id: str, days_ahead: int = 30) -> List[Dict[str, Any]]:
        """Return active secrets that are past or approaching their rotation window.

        A secret is considered expiring when:
          (julianday('now') - julianday(last_rotated)) >= (rotation_days - days_ahead)
        """
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM secrets
                   WHERE org_id = ?
                     AND status = 'active'
                     AND (julianday('now') - julianday(last_rotated)) >= (rotation_days - ?)
                   ORDER BY last_rotated ASC""",
                (org_id, days_ahead),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Access audit
    # ------------------------------------------------------------------

    def record_access(
        self, org_id: str, secret_id: str, accessor: str, action: str
    ) -> Dict[str, Any]:
        """Record an access event for audit purposes."""
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "secret_id": secret_id,
            "accessor": accessor,
            "action": action,
            "accessed_at": _now_iso(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO access_log
                       (id, org_id, secret_id, accessor, action, accessed_at)
                       VALUES (:id, :org_id, :secret_id, :accessor, :action, :accessed_at)""",
                    record,
                )
        return record

    def get_access_log(
        self, org_id: str, secret_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Return recent access events for a secret."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM access_log
                   WHERE org_id = ? AND secret_id = ?
                   ORDER BY accessed_at DESC LIMIT ?""",
                (org_id, secret_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_vault_audit_log(
        self,
        org_id: str,
        accessor: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return org-wide access audit log across all secrets.

        Optionally filter by accessor identity or action type.
        Results are ordered by accessed_at DESC.
        """
        sql = "SELECT * FROM access_log WHERE org_id = ?"
        params: list = [org_id]
        if accessor:
            sql += " AND accessor = ?"
            params.append(accessor)
        if action:
            sql += " AND action = ?"
            params.append(action)
        sql += " ORDER BY accessed_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_secrets_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated secrets stats for org."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM secrets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                """SELECT secret_type, COUNT(*) as cnt FROM secrets
                   WHERE org_id = ? GROUP BY secret_type""",
                (org_id,),
            ).fetchall()
            by_type = {r["secret_type"]: r["cnt"] for r in type_rows}

            revoked = conn.execute(
                "SELECT COUNT(*) FROM secrets WHERE org_id = ? AND status = 'revoked'",
                (org_id,),
            ).fetchone()[0]

            # Overdue: past their full rotation window
            overdue = conn.execute(
                """SELECT COUNT(*) FROM secrets
                   WHERE org_id = ?
                     AND status = 'active'
                     AND (julianday('now') - julianday(last_rotated)) >= rotation_days""",
                (org_id,),
            ).fetchone()[0]

        return {
            "total": total,
            "by_type": by_type,
            "overdue_rotation": overdue,
            "revoked": revoked,
        }
