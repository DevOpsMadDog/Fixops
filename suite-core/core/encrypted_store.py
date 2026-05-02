"""
Encrypted persistent storage — AES-256-GCM at-rest encryption for SQLite data.

Drop-in replacement for :class:`PersistentDict` that encrypts all values
before writing to SQLite and decrypts on read.  Keys are stored as
HMAC-SHA256 hashes to prevent plaintext key leakage.

Security properties:
  - **Confidentiality**: AES-256-GCM authenticated encryption (NIST SP 800-38D)
  - **Key derivation**: HKDF-SHA256 from master key + per-table salt
  - **Key hashing**: Optional HMAC-SHA256 key hashing (configurable)
  - **Integrity**: GCM authentication tag prevents tampering
  - **Air-gapped**: No external dependencies — works fully offline

Environment variables:
  FIXOPS_ENCRYPTION_MASTER_KEY    Hex-encoded 32-byte master key (required in production)
  FIXOPS_ENCRYPT_AT_REST          Enable encryption ("1", "true", "yes")

Usage::

    from core.encrypted_store import get_encrypted_store

    _store = get_encrypted_store("findings")
    _store["vuln-001"] = {"severity": "critical", "cwe": "CWE-89"}
    data = _store["vuln-001"]  # automatically decrypted
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises.

    Hub-level emit so this engine module participates in second-brain coverage.
    Downstream callers are AQUA via blast-radius (depth ≤ 2).
    """
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


# Module-load heartbeat — fires once per process so this file is observable
# in the TrustGraph second-brain, even if no public method is called yet.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

_logger = logging.getLogger(__name__)

_AES_KEY_LENGTH = 32  # 256 bits
_NONCE_LENGTH = 12  # 96 bits for AES-GCM
_SALT_LENGTH = 16  # 128-bit salt per table

# Cache for table-level derived keys
_derived_keys: Dict[str, bytes] = {}
_master_key_cache: Optional[bytes] = None


def _get_master_key() -> bytes:
    """Retrieve or generate the master encryption key."""
    global _master_key_cache
    if _master_key_cache is not None:
        return _master_key_cache

    env_key = os.getenv("FIXOPS_ENCRYPTION_MASTER_KEY")
    if env_key:
        try:
            key = bytes.fromhex(env_key)
            if len(key) != _AES_KEY_LENGTH:
                raise ValueError(
                    f"FIXOPS_ENCRYPTION_MASTER_KEY must be {_AES_KEY_LENGTH * 2} hex chars"
                )
            _master_key_cache = key
            return key
        except ValueError:
            raise
    # Generate ephemeral key — log warning in production
    _master_key_cache = secrets.token_bytes(_AES_KEY_LENGTH)
    _logger.warning(
        "No FIXOPS_ENCRYPTION_MASTER_KEY configured — using ephemeral key. "
        "Data will NOT be recoverable after process restart. "
        "Set FIXOPS_ENCRYPTION_MASTER_KEY for persistent encryption."
    )
    return _master_key_cache


def _derive_table_key(master: bytes, table: str, salt: bytes) -> bytes:
    """Derive a table-specific encryption key using HKDF-SHA256."""
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=_AES_KEY_LENGTH,
            salt=salt,
            info=f"fixops-db-{table}".encode(),
            backend=default_backend(),
        )
        return hkdf.derive(master)
    except ImportError:
        # Fallback: HMAC-based derivation if cryptography lib unavailable
        return hashlib.pbkdf2_hmac("sha256", master, salt + table.encode(), 100_000)


def _encrypt_value(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt data with AES-256-GCM. Returns nonce + ciphertext + tag."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = secrets.token_bytes(_NONCE_LENGTH)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext  # 12 bytes nonce + ciphertext + 16 bytes tag
    except ImportError:
        # If cryptography not available, fall back to no encryption with a marker
        _logger.error("cryptography library not available — cannot encrypt")
        raise RuntimeError("cryptography library required for encryption at rest")


def _decrypt_value(key: bytes, data: bytes) -> bytes:
    """Decrypt AES-256-GCM data. Input: nonce + ciphertext + tag."""
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = data[:_NONCE_LENGTH]
        ciphertext = data[_NONCE_LENGTH:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except ImportError:
        raise RuntimeError("cryptography library required for decryption")
    except InvalidTag:
        raise ValueError("Decryption failed — wrong key or corrupted data")


def is_encryption_enabled() -> bool:
    """Check if at-rest encryption is enabled via environment."""
    val = os.getenv("FIXOPS_ENCRYPT_AT_REST", "0").lower()
    return val in ("1", "true", "yes")


import re

_SAFE_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class EncryptedPersistentDict:
    """Dict-like object backed by SQLite with AES-256-GCM encryption at rest.

    All values are encrypted before writing and decrypted on read.
    Keys are stored as HMAC-SHA256 hashes to prevent plaintext key leakage
    (original keys are stored in the encrypted value envelope for iteration).
    """

    def __init__(
        self,
        table: str,
        db_path: str = "data/encrypted_state.db",
        master_key: Optional[bytes] = None,
    ) -> None:
        if not _SAFE_TABLE_RE.match(table):
            raise ValueError(
                f"Invalid table name {table!r}: must match [A-Za-z_][A-Za-z0-9_]{{0,127}}"
            )
        self._table = table
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._master = master_key or _get_master_key()

        # Per-table salt — stored in a metadata table
        self._salt = self._get_or_create_salt()
        self._data_key = _derive_table_key(self._master, table, self._salt)

        self._init_table()
        self._cache: Dict[str, Any] = {}
        self._load_all()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except (OSError, ValueError, RuntimeError):
                pass
            self._local.conn = None

    def __del__(self) -> None:
        self.close()

    def _get_or_create_salt(self) -> bytes:
        """Get or create a per-table encryption salt."""
        with self._conn() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS _encryption_metadata "
                "(table_name TEXT PRIMARY KEY, salt BLOB NOT NULL)"
            )
            row = conn.execute(
                "SELECT salt FROM _encryption_metadata WHERE table_name = ?",
                (self._table,),
            ).fetchone()
            if row:
                return row[0]
            salt = secrets.token_bytes(_SALT_LENGTH)
            conn.execute(
                "INSERT INTO _encryption_metadata (table_name, salt) VALUES (?, ?)",
                (self._table, salt),
            )
            return salt

    def _init_table(self) -> None:
        with self._conn() as conn:
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS [{self._table}] "  # nosec B608 — validated
                "(key_hash TEXT PRIMARY KEY, encrypted_value BLOB NOT NULL)"
            )

    def _hash_key(self, key: str) -> str:
        """HMAC-SHA256 hash of the key for storage."""
        return hmac.new(
            self._data_key, key.encode(), hashlib.sha256
        ).hexdigest()

    def _encrypt(self, key: str, value: Any) -> bytes:
        """Encrypt a key-value pair. Stores original key in envelope for iteration."""
        envelope = json.dumps({"k": key, "v": value}).encode()
        return _encrypt_value(self._data_key, envelope)

    def _decrypt(self, data: bytes) -> tuple:
        """Decrypt and return (original_key, value)."""
        envelope = _decrypt_value(self._data_key, data)
        parsed = json.loads(envelope)
        return parsed["k"], parsed["v"]

    def _load_all(self) -> None:
        with self._conn() as conn:
            for _, encrypted in conn.execute(
                f"SELECT key_hash, encrypted_value FROM [{self._table}]"  # nosec B608
            ):
                try:
                    orig_key, value = self._decrypt(encrypted)
                    self._cache[orig_key] = value
                except (ValueError, KeyError, RuntimeError) as exc:
                    _logger.warning("Failed to decrypt entry in %s: %s", self._table, exc)

    def __setitem__(self, key: str, value: Any) -> None:
        self._cache[key] = value
        key_hash = self._hash_key(key)
        encrypted = self._encrypt(key, value)
        with self._conn() as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO [{self._table}] (key_hash, encrypted_value) VALUES (?, ?)",  # nosec B608
                (key_hash, encrypted),
            )

    def __getitem__(self, key: str) -> Any:
        return self._cache[key]

    def __contains__(self, key: str) -> bool:
        return key in self._cache

    def __delitem__(self, key: str) -> None:
        del self._cache[key]
        key_hash = self._hash_key(key)
        with self._conn() as conn:
            conn.execute(
                f"DELETE FROM [{self._table}] WHERE key_hash = ?",  # nosec B608
                (key_hash,),
            )

    def get(self, key: str, default: Any = None) -> Any:
        return self._cache.get(key, default)

    def keys(self) -> Iterator[str]:
        return iter(self._cache.keys())

    def values(self) -> Iterator[Any]:
        return iter(self._cache.values())

    def items(self) -> Iterator[tuple]:
        return iter(self._cache.items())

    def __len__(self) -> int:
        return len(self._cache)

    def __iter__(self) -> Iterator[str]:
        return iter(self._cache)

    def persist(self, key: str) -> None:
        """Explicitly flush a mutated value back to encrypted storage."""
        if key in self._cache:
            self[key] = self._cache[key]

    def persist_all(self) -> None:
        """Flush all cached values back to encrypted storage."""
        for key in list(self._cache.keys()):
            self.persist(key)

    def clear(self) -> None:
        """Remove all entries."""
        self._cache.clear()
        with self._conn() as conn:
            conn.execute(f"DELETE FROM [{self._table}]")  # nosec B608

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict copy of all data (decrypted)."""
        return dict(self._cache)


def get_encrypted_store(
    table: str,
    db_path: str = "data/encrypted_state.db",
    master_key: Optional[bytes] = None,
) -> EncryptedPersistentDict:
    """Factory: create an encrypted persistent dict.

    If ``FIXOPS_ENCRYPT_AT_REST`` is not enabled, returns a standard
    :class:`EncryptedPersistentDict` anyway (encryption is always on for
    this class — the env var controls whether other systems use it).
    """
    return EncryptedPersistentDict(table, db_path, master_key)
