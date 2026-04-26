"""
API Key Lifecycle Management — scoped permissions, usage tracking, expiration.

Provides full key lifecycle: create, validate, rotate, revoke, list, update.

Key format: ``aldeci_`` + 32 hex chars  (e.g. ``aldeci_a1b2c3d4e5f6...``).
Keys are SHA-256 hashed before storage — plaintext is returned ONCE on creation.

Thread-safe via per-thread SQLite connections (WAL mode).

Usage::

    mgr = APIKeyManager()
    key, raw = mgr.create_key(name="CI", org_id="acme", role=RBACRole.ADMIN,
                               scopes=["read:findings"])
    validated = mgr.validate_key(raw)   # increments use_count + last_used_at
    mgr.revoke_key(key.id)

Environment:
    FIXOPS_DATA_DIR   directory for the SQLite DB (default: ``.fixops_data``)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.rbac import RBACRole

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_KEY_PREFIX = "aldeci_"
_KEY_HEX_LEN = 32        # 16 random bytes → 32 hex chars
_DB_ENV = "FIXOPS_DATA_DIR"
_DEFAULT_DB_DIR = ".fixops_data"


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class APIKey(BaseModel):
    """API key record.

    ``key_hash`` stores the SHA-256 digest and is excluded from all
    serialised output so it is never accidentally returned in API responses.
    """

    id: str
    name: str
    key_hash: str = Field(exclude=True)   # SHA-256 — never returned via API
    prefix: str                            # first 8 chars of raw key (display/lookup)
    org_id: str
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    use_count: int = 0
    rate_limit: int = 60                  # requests / minute
    scopes: List[str] = Field(default_factory=list)
    role: RBACRole = RBACRole.VIEWER
    is_active: bool = True
    description: str = ""

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _hash_key(raw: str) -> str:
    """SHA-256 hex digest of a raw API key."""
    return hashlib.sha256(raw.encode()).hexdigest()


def _generate_raw_key() -> str:
    """Generate ``aldeci_`` + 32 random hex chars."""
    return _KEY_PREFIX + secrets.token_hex(_KEY_HEX_LEN // 2)  # 16 bytes → 32 hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    return datetime.fromisoformat(val)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class APIKeyManager:
    """
    SQLite-backed API key manager.

    Thread-safe: each thread keeps its own connection via ``threading.local``.
    Singleton pattern: calling ``APIKeyManager()`` without arguments returns
    the same instance; pass an explicit ``db_path`` to create a separate
    instance (useful for testing).
    """

    _instance: Optional["APIKeyManager"] = None
    _class_lock: threading.Lock = threading.Lock()

    def __new__(cls, db_path: Optional[str] = None) -> "APIKeyManager":
        with cls._class_lock:
            if db_path is not None:
                # Explicit path — always create a fresh instance (tests, etc.)
                inst = object.__new__(cls)
                inst._init(db_path)
                return inst
            if cls._instance is None:
                inst = object.__new__(cls)
                default_path = os.path.join(
                    os.getenv(_DB_ENV, _DEFAULT_DB_DIR), "api_keys.db"
                )
                inst._init(default_path)
                cls._instance = inst
            return cls._instance  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init(self, db_path: str) -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
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
                CREATE TABLE IF NOT EXISTS api_keys (
                    id           TEXT PRIMARY KEY,
                    name         TEXT NOT NULL,
                    key_hash     TEXT NOT NULL UNIQUE,
                    prefix       TEXT NOT NULL,
                    org_id       TEXT NOT NULL,
                    created_by   TEXT NOT NULL,
                    created_at   TEXT NOT NULL,
                    expires_at   TEXT,
                    last_used_at TEXT,
                    use_count    INTEGER NOT NULL DEFAULT 0,
                    rate_limit   INTEGER NOT NULL DEFAULT 60,
                    scopes       TEXT    NOT NULL DEFAULT '[]',
                    role         TEXT    NOT NULL DEFAULT 'viewer',
                    is_active    INTEGER NOT NULL DEFAULT 1,
                    description  TEXT    NOT NULL DEFAULT ''
                )
            """)

    # ------------------------------------------------------------------
    # Row converter
    # ------------------------------------------------------------------

    def _row_to_key(self, row: Dict[str, Any]) -> APIKey:
        try:
            role = RBACRole(row["role"])
        except ValueError:
            role = RBACRole.VIEWER

        return APIKey(
            id=row["id"],
            name=row["name"],
            key_hash=row["key_hash"],
            prefix=row["prefix"],
            org_id=row["org_id"],
            created_by=row["created_by"],
            created_at=_parse_dt(row["created_at"]) or _now(),
            expires_at=_parse_dt(row.get("expires_at")),
            last_used_at=_parse_dt(row.get("last_used_at")),
            use_count=int(row.get("use_count", 0)),
            rate_limit=int(row.get("rate_limit", 60)),
            scopes=json.loads(row.get("scopes", "[]")),
            role=role,
            is_active=bool(row.get("is_active", True)),
            description=row.get("description", ""),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_key(
        self,
        name: str,
        org_id: str,
        role: RBACRole = RBACRole.VIEWER,
        scopes: Optional[List[str]] = None,
        expires_at: Optional[datetime] = None,
        rate_limit: int = 60,
        description: str = "",
        created_by: str = "system",
    ) -> tuple[APIKey, str]:
        """Create a new API key.

        Returns:
            ``(APIKey, raw_key)`` — raw_key is shown ONLY at creation time.
        """
        raw = _generate_raw_key()
        key_id = "ak_" + secrets.token_hex(8)
        key_hash = _hash_key(raw)
        prefix = raw[:8]
        now = _now()
        key_scopes = scopes or []

        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO api_keys
                    (id, name, key_hash, prefix, org_id, created_by, created_at,
                     expires_at, rate_limit, scopes, role, is_active, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    key_id, name, key_hash, prefix, org_id, created_by,
                    now.isoformat(),
                    expires_at.isoformat() if expires_at else None,
                    rate_limit,
                    json.dumps(key_scopes),
                    role.value,
                    description,
                ),
            )

        record = APIKey(
            id=key_id,
            name=name,
            key_hash=key_hash,
            prefix=prefix,
            org_id=org_id,
            created_by=created_by,
            created_at=now,
            expires_at=expires_at,
            rate_limit=rate_limit,
            scopes=key_scopes,
            role=role,
            is_active=True,
            description=description,
        )

        _logger.info("Created API key %s for org=%s role=%s", key_id, org_id, role.value)  # nosemgrep: python-logger-credential-disclosure
        self._emit_event(
            "api_key.created",
            {
                "key_id": key_id,
                "org_id": org_id,
                "role": role.value,
                "scopes": key_scopes,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )
        return record, raw

    def validate_key(self, raw_key: str) -> Optional[APIKey]:
        """Validate a raw API key.

        Returns the ``APIKey`` record if the key is valid, active, and not
        expired.  Also increments ``use_count`` and updates ``last_used_at``.

        Returns ``None`` for any invalid / expired / revoked key.
        """
        key_hash = _hash_key(raw_key)
        now = _now()

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)
            ).fetchone()

        if not row:
            return None

        record = self._row_to_key(dict(row))

        if not record.is_active:
            return None

        if record.expires_at and record.expires_at < now:
            return None

        # Update usage stats atomically
        with self._conn() as conn:
            conn.execute(
                "UPDATE api_keys SET use_count = use_count + 1, last_used_at = ? WHERE id = ?",
                (now.isoformat(), record.id),
            )

        record.use_count += 1
        record.last_used_at = now
        return record

    def rotate_key(self, key_id: str, created_by: str = "system") -> tuple[APIKey, str]:
        """Rotate a key — generate a new key with identical config and deactivate the old one.

        Returns:
            ``(new_APIKey, new_raw_key)``

        Raises:
            ValueError: if key not found or already inactive.
        """
        old = self.get_key(key_id)
        if old is None:
            raise ValueError(f"Key not found: {key_id}")
        if not old.is_active:
            raise ValueError(f"Key {key_id} is not active")

        new_key, new_raw = self.create_key(
            name=old.name,
            org_id=old.org_id,
            role=old.role,
            scopes=old.scopes,
            expires_at=old.expires_at,
            rate_limit=old.rate_limit,
            description=old.description,
            created_by=created_by,
        )

        # Deactivate the old key
        with self._conn() as conn:
            conn.execute(
                "UPDATE api_keys SET is_active = 0 WHERE id = ?",
                (key_id,),
            )

        _logger.info("Rotated key %s → %s", key_id, new_key.id)  # nosemgrep: python-logger-credential-disclosure
        self._emit_event(
            "api_key.rotated",
            {"old_key_id": key_id, "new_key_id": new_key.id, "org_id": old.org_id},
        )
        return new_key, new_raw

    def revoke_key(self, key_id: str) -> None:
        """Revoke a key (sets ``is_active = False``).

        Raises:
            ValueError: if key not found.
        """
        with self._conn() as conn:
            result = conn.execute(
                "UPDATE api_keys SET is_active = 0 WHERE id = ?", (key_id,)
            )
        if result.rowcount == 0:
            raise ValueError(f"Key not found: {key_id}")
        _logger.info("Revoked API key %s", key_id)  # nosemgrep: python-logger-credential-disclosure
        self._emit_event("api_key.revoked", {"key_id": key_id})

    def list_keys(self, org_id: str) -> List[APIKey]:
        """List all keys for an org ordered by creation date descending.

        ``key_hash`` is excluded via the ``APIKey`` model config — safe to
        return directly to API callers.
        """
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM api_keys WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row_to_key(dict(r)) for r in rows]

    def get_key(self, key_id: str) -> Optional[APIKey]:
        """Get a key record by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE id = ?", (key_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_key(dict(row))

    def update_key(self, key_id: str, updates: Dict[str, Any]) -> APIKey:
        """Update mutable key fields: ``name``, ``description``, ``scopes``, ``rate_limit``.

        Raises:
            ValueError: if key not found.
        """
        key = self.get_key(key_id)
        if key is None:
            raise ValueError(f"Key not found: {key_id}")

        allowed = {"name", "description", "scopes", "rate_limit"}
        cols: List[str] = []
        params: List[Any] = []

        for field_name, value in updates.items():
            if field_name not in allowed:
                continue
            if field_name == "scopes":
                cols.append("scopes = ?")
                params.append(json.dumps(value))
            else:
                cols.append(f"{field_name} = ?")
                params.append(value)

        if cols:
            params.append(key_id)
            with self._conn() as conn:
                conn.execute(
                    f"UPDATE api_keys SET {', '.join(cols)} WHERE id = ?",  # nosec B608
                    params,
                )

        updated = self.get_key(key_id)
        assert updated is not None
        return updated

    def delete_expired_keys(self) -> int:
        """Hard-delete inactive + expired keys.  Returns count removed."""
        now_str = _now().isoformat()
        with self._conn() as conn:
            result = conn.execute(
                "DELETE FROM api_keys "
                "WHERE is_active = 0 AND expires_at IS NOT NULL AND expires_at < ?",
                (now_str,),
            )
        count = result.rowcount
        if count:
            _logger.info("Deleted %d expired API keys", count)
        return count

    def get_usage_stats(self, key_id: str) -> Dict[str, Any]:
        """Return usage statistics for a single key.

        Raises:
            ValueError: if key not found.
        """
        key = self.get_key(key_id)
        if key is None:
            raise ValueError(f"Key not found: {key_id}")

        now = _now()
        age_seconds = (now - key.created_at).total_seconds()
        age_days: Optional[float] = age_seconds / 86400 if age_seconds > 0 else None
        rate_per_day: Optional[float] = (
            round(key.use_count / age_days, 2) if age_days else 0.0
        )

        return {
            "key_id": key_id,
            "use_count": key.use_count,
            "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
            "created_at": key.created_at.isoformat(),
            "age_days": round(age_days, 2) if age_days is not None else None,
            "rate_per_day": rate_per_day,
            "rate_limit": key.rate_limit,
            "is_active": key.is_active,
        }


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: "dict[str, Any]") -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
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
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            pass



def get_api_key_manager(db_path: Optional[str] = None) -> APIKeyManager:
    """Return the singleton ``APIKeyManager`` (or a new instance for a custom path)."""
    return APIKeyManager(db_path=db_path)
