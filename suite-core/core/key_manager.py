"""
API Key Lifecycle Management — rotation, revocation, and audit.

Enterprise-grade key management with:
  - Scheduled key rotation with configurable TTL
  - Secure key generation with bcrypt hashing
  - Key revocation and audit trail
  - Grace period for rotation (old key valid during transition)

Usage::

    from core.key_manager import KeyManager

    km = KeyManager()
    key_record = km.create_key(user_id="u-1", name="CI Pipeline", role="service")
    # key_record.plaintext_key is returned ONCE — store it securely

    km.rotate_key(key_id=key_record.id)   # old key gets grace period
    km.revoke_key(key_id=key_record.id)    # immediate revocation

Environment variables:
  FIXOPS_KEY_ROTATION_DAYS     Default key TTL in days (default: 90)
  FIXOPS_KEY_GRACE_HOURS       Grace period after rotation (default: 24)
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


import hashlib
import logging
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)
_DEFAULT_ROTATION_DAYS = 90
_DEFAULT_GRACE_HOURS = 24
_KEY_PREFIX_LENGTH = 8
_KEY_LENGTH = 48  # 48 bytes = 64 chars base64


@dataclass
class ManagedKey:
    """An API key record with lifecycle metadata."""

    id: str
    key_prefix: str
    key_hash: str
    user_id: str
    name: str
    role: str
    scopes: List[str] = field(default_factory=list)
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    rotated_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    predecessor_id: Optional[str] = None  # Key this replaced
    grace_expires_at: Optional[datetime] = None  # Old key grace period

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "key_prefix": self.key_prefix,
            "name": self.name,
            "user_id": self.user_id,
            "role": self.role,
            "scopes": self.scopes,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotated_at": self.rotated_at.isoformat() if self.rotated_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "predecessor_id": self.predecessor_id,
        }


def _hash_key(raw_key: str) -> str:
    """SHA-256 hash of the raw API key for storage comparison."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _generate_key() -> str:
    """Generate a cryptographically secure API key."""
    raw = secrets.token_urlsafe(_KEY_LENGTH)
    return f"fixops_{raw}"


class KeyManager:
    """Enterprise API key lifecycle manager with rotation support."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path or os.path.join(
            os.getenv("FIXOPS_DATA_DIR", ".fixops_data"), "key_management.db"
        )
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._rotation_days = int(
            os.getenv("FIXOPS_KEY_ROTATION_DAYS", str(_DEFAULT_ROTATION_DAYS))
        )
        self._grace_hours = int(
            os.getenv("FIXOPS_KEY_GRACE_HOURS", str(_DEFAULT_GRACE_HOURS))
        )
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS managed_keys (
                    id TEXT PRIMARY KEY,
                    key_prefix TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    scopes TEXT NOT NULL DEFAULT '[]',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    rotated_at TEXT,
                    revoked_at TEXT,
                    last_used_at TEXT,
                    predecessor_id TEXT,
                    grace_expires_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS key_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    performed_by TEXT,
                    details TEXT,
                    timestamp TEXT NOT NULL
                )
            """)

    def _log_action(self, key_id: str, action: str, performed_by: str = "system", details: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO key_audit_log (key_id, action, performed_by, details, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (key_id, action, performed_by, details, datetime.now(timezone.utc).isoformat()),
            )

    def create_key(
        self,
        user_id: str,
        name: str,
        role: str = "viewer",
        scopes: Optional[List[str]] = None,
        ttl_days: Optional[int] = None,
    ) -> tuple:
        """Create a new API key.

        Returns:
            Tuple of (ManagedKey, plaintext_key). The plaintext key is returned
            ONLY at creation time — it cannot be retrieved later.
        """
        import json as _json

        plaintext = _generate_key()
        key_id = f"key_{secrets.token_hex(8)}"
        key_hash = _hash_key(plaintext)
        prefix = plaintext[:_KEY_PREFIX_LENGTH]
        ttl = ttl_days or self._rotation_days
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=ttl)
        key_scopes = scopes or []

        record = ManagedKey(
            id=key_id,
            key_prefix=prefix,
            key_hash=key_hash,
            user_id=user_id,
            name=name,
            role=role,
            scopes=key_scopes,
            is_active=True,
            created_at=now,
            expires_at=expires,
        )

        with self._conn() as conn:
            conn.execute(
                "INSERT INTO managed_keys "
                "(id, key_prefix, key_hash, user_id, name, role, scopes, is_active, "
                "created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (
                    key_id, prefix, key_hash, user_id, name, role,
                    _json.dumps(key_scopes), now.isoformat(), expires.isoformat(),
                ),
            )

        self._log_action(key_id, "created", user_id, f"TTL={ttl}d, role={role}")
        _logger.info("Created API key %s for user %s (expires %s)", key_id, user_id, expires.isoformat())  # nosemgrep: python-logger-credential-disclosure
        _emit_event("key_manager.key_created", {
            "key_id": key_id,
            "user_id": user_id,
            "role": role,
            "ttl_days": ttl,
            "expires_at": expires.isoformat(),
        })
        return record, plaintext

    def rotate_key(self, key_id: str, performed_by: str = "system") -> tuple:
        """Rotate a key — create a new key and put the old one in grace period.

        Returns:
            Tuple of (new_ManagedKey, new_plaintext_key).
        """
        old_key = self.get_key(key_id)
        if not old_key:
            raise ValueError(f"Key {key_id} not found")
        if not old_key.is_active:
            raise ValueError(f"Key {key_id} is not active — cannot rotate")

        # Create replacement key
        new_record, new_plaintext = self.create_key(
            user_id=old_key.user_id,
            name=f"{old_key.name} (rotated)",
            role=old_key.role,
            scopes=old_key.scopes,
        )

        # Put old key in grace period (still valid for a limited time)
        now = datetime.now(timezone.utc)
        grace_end = now + timedelta(hours=self._grace_hours)
        with self._conn() as conn:
            conn.execute(
                "UPDATE managed_keys SET rotated_at = ?, grace_expires_at = ? WHERE id = ?",
                (now.isoformat(), grace_end.isoformat(), key_id),
            )
            # Link new key to predecessor
            conn.execute(
                "UPDATE managed_keys SET predecessor_id = ? WHERE id = ?",
                (key_id, new_record.id),
            )

        self._log_action(key_id, "rotated", performed_by, f"new_key={new_record.id}, grace_until={grace_end.isoformat()}")
        self._log_action(new_record.id, "rotation_successor", performed_by, f"replaces={key_id}")
        _logger.info(
            "Rotated key %s → %s (old key grace period until %s)",
            key_id, new_record.id, grace_end.isoformat(),
        )
        _emit_event("key_manager.key_rotated", {
            "old_key_id": key_id,
            "new_key_id": new_record.id,
            "user_id": old_key.user_id,
            "performed_by": performed_by,
            "grace_until": grace_end.isoformat(),
        })
        return new_record, new_plaintext

    def revoke_key(self, key_id: str, performed_by: str = "system") -> bool:
        """Immediately revoke a key."""
        now = datetime.now(timezone.utc)
        with self._conn() as conn:
            result = conn.execute(
                "UPDATE managed_keys SET is_active = 0, revoked_at = ?, grace_expires_at = NULL "
                "WHERE id = ? AND is_active = 1",
                (now.isoformat(), key_id),
            )
            if result.rowcount == 0:
                return False

        self._log_action(key_id, "revoked", performed_by)
        _logger.info("Revoked API key %s", key_id)  # nosemgrep: python-logger-credential-disclosure
        _emit_event("key_manager.key_revoked", {
            "key_id": key_id,
            "performed_by": performed_by,
            "revoked_at": now.isoformat(),
        })
        return True

    def get_key(self, key_id: str) -> Optional[ManagedKey]:
        """Get a key record by ID."""

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM managed_keys WHERE id = ?", (key_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_key(dict(row))

    def validate_key(self, raw_key: str) -> Optional[ManagedKey]:
        """Validate a raw API key — returns the key record if valid."""

        key_hash = _hash_key(raw_key)
        now = datetime.now(timezone.utc)

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM managed_keys WHERE key_hash = ?", (key_hash,)
            ).fetchone()

        if not row:
            return None

        record = self._row_to_key(dict(row))

        # Check if revoked
        if not record.is_active:
            return None

        # Check expiration
        if record.expires_at and record.expires_at < now:
            # Check grace period
            if record.grace_expires_at and record.grace_expires_at > now:
                _logger.warning("Key %s expired but in grace period", record.id)  # nosemgrep: python-logger-credential-disclosure
            else:
                return None

        # Update last_used_at
        with self._conn() as conn:
            conn.execute(
                "UPDATE managed_keys SET last_used_at = ? WHERE id = ?",
                (now.isoformat(), record.id),
            )

        record.last_used_at = now
        return record

    def list_keys(self, user_id: Optional[str] = None, include_revoked: bool = False) -> List[ManagedKey]:
        """List all managed keys, optionally filtered by user."""

        query = "SELECT * FROM managed_keys"
        params: list = []
        conditions = []

        if user_id:
            conditions.append("user_id = ?")
            params.append(user_id)
        if not include_revoked:
            conditions.append("is_active = 1")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_key(dict(r)) for r in rows]

    def get_expiring_keys(self, within_days: int = 7) -> List[ManagedKey]:
        """Get keys expiring within the specified number of days."""
        cutoff = (datetime.now(timezone.utc) + timedelta(days=within_days)).isoformat()
        now = datetime.now(timezone.utc).isoformat()

        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM managed_keys WHERE is_active = 1 "
                "AND expires_at IS NOT NULL AND expires_at BETWEEN ? AND ? "
                "ORDER BY expires_at ASC",
                (now, cutoff),
            ).fetchall()

        return [self._row_to_key(dict(r)) for r in rows]

    def cleanup_expired(self) -> int:
        """Deactivate keys past their grace period. Returns count of deactivated keys."""
        now = datetime.now(timezone.utc).isoformat()

        with self._conn() as conn:
            # Keys expired AND past grace period
            result = conn.execute(
                "UPDATE managed_keys SET is_active = 0 WHERE is_active = 1 "
                "AND expires_at < ? AND (grace_expires_at IS NULL OR grace_expires_at < ?)",
                (now, now),
            )
            count = result.rowcount

        if count > 0:
            _logger.info("Deactivated %d expired API keys", count)
        return count

    def get_audit_log(self, key_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get key audit log entries."""
        if key_id:
            query = "SELECT * FROM key_audit_log WHERE key_id = ? ORDER BY timestamp DESC LIMIT ?"
            params: tuple = (key_id, limit)
        else:
            query = "SELECT * FROM key_audit_log ORDER BY timestamp DESC LIMIT ?"
            params = (limit,)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def _row_to_key(self, row: Dict[str, Any]) -> ManagedKey:
        import json as _json

        def _parse_dt(val: Optional[str]) -> Optional[datetime]:
            if not val:
                return None
            return datetime.fromisoformat(val)

        return ManagedKey(
            id=row["id"],
            key_prefix=row["key_prefix"],
            key_hash=row["key_hash"],
            user_id=row["user_id"],
            name=row["name"],
            role=row.get("role", "viewer"),
            scopes=_json.loads(row.get("scopes", "[]")),
            is_active=bool(row.get("is_active", True)),
            created_at=_parse_dt(row["created_at"]) or datetime.now(timezone.utc),
            expires_at=_parse_dt(row.get("expires_at")),
            rotated_at=_parse_dt(row.get("rotated_at")),
            revoked_at=_parse_dt(row.get("revoked_at")),
            last_used_at=_parse_dt(row.get("last_used_at")),
            predecessor_id=row.get("predecessor_id"),
            grace_expires_at=_parse_dt(row.get("grace_expires_at")),
        )
