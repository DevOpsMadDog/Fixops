"""Crypto Key Management Engine — ALDECI.

Manages cryptographic keys across their full lifecycle: creation, rotation,
revocation, expiry tracking, and audit trail for usage events.

Compliance: NIST SP 800-57, FIPS 140-3, ISO/IEC 27001 A.10
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "crypto_key_management.db"
)

_VALID_KEY_TYPES = {"aes256", "rsa2048", "rsa4096", "ecdsa256", "ed25519"}
_VALID_PURPOSES = {"encryption", "signing", "authentication"}
_VALID_STATUSES = {"active", "rotating", "revoked", "expired"}


class CryptoKeyManagementEngine:
    """SQLite WAL-backed Crypto Key Management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
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
                CREATE TABLE IF NOT EXISTS crypto_keys (
                    key_id        TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    name          TEXT NOT NULL DEFAULT '',
                    key_type      TEXT NOT NULL DEFAULT 'aes256',
                    purpose       TEXT NOT NULL DEFAULT 'encryption',
                    status        TEXT NOT NULL DEFAULT 'active',
                    version       INTEGER NOT NULL DEFAULT 1,
                    expiry_date   TEXT NOT NULL DEFAULT '',
                    tags          TEXT NOT NULL DEFAULT '[]',
                    created_at    TEXT NOT NULL,
                    updated_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ckeys_org
                    ON crypto_keys (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_ckeys_expiry
                    ON crypto_keys (org_id, expiry_date);

                CREATE TABLE IF NOT EXISTS key_usage_log (
                    log_id        TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    key_id        TEXT NOT NULL,
                    usage_type    TEXT NOT NULL DEFAULT '',
                    recorded_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_klog_key
                    ON key_usage_log (org_id, key_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _row_to_dict(self, row: Any) -> Dict[str, Any]:
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        return d

    def _compute_expiry(self, expiry_days: int) -> str:
        """Return ISO expiry timestamp from now + expiry_days."""
        return (datetime.now(timezone.utc) + timedelta(days=expiry_days)).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_key(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new cryptographic key. Returns the full key record."""
        key_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        key_type = data.get("key_type", "aes256")
        if key_type not in _VALID_KEY_TYPES:
            key_type = "aes256"

        purpose = data.get("purpose", "encryption")
        if purpose not in _VALID_PURPOSES:
            purpose = "encryption"

        expiry_days = int(data.get("expiry_days", 365))
        expiry_date = self._compute_expiry(expiry_days)

        tags = data.get("tags", [])
        if not isinstance(tags, list):
            tags = []

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO crypto_keys
                        (key_id, org_id, name, key_type, purpose, status, version,
                         expiry_date, tags, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        key_id, org_id,
                        data.get("name", ""),
                        key_type, purpose,
                        "active", 1,
                        expiry_date,
                        json.dumps(tags),
                        now, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "crypto_key_management", "org_id": org_id, "source_engine": "crypto_key_management"})
            except Exception:
                pass

        return {
            "key_id": key_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "key_type": key_type,
            "purpose": purpose,
            "status": "active",
            "version": 1,
            "expiry_date": expiry_date,
            "tags": tags,
            "created_at": now,
            "updated_at": now,
        }

    def list_keys(
        self,
        org_id: str,
        key_type: Optional[str] = None,
        purpose: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List keys for an org, optionally filtered by key_type and/or purpose."""
        query = "SELECT * FROM crypto_keys WHERE org_id = ?"
        params: list = [org_id]
        if key_type:
            query += " AND key_type = ?"
            params.append(key_type)
        if purpose:
            query += " AND purpose = ?"
            params.append(purpose)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_key(self, org_id: str, key_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single key by key_id (org-scoped)."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM crypto_keys WHERE org_id = ? AND key_id = ?",
                    (org_id, key_id),
                ).fetchone()
        return self._row_to_dict(row) if row else None

    def rotate_key(self, org_id: str, key_id: str) -> Dict[str, Any]:
        """Rotate a key: mark old as 'rotating', create new version with incremented version number."""
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM crypto_keys WHERE org_id = ? AND key_id = ?",
                    (org_id, key_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Key not found: {key_id}")

                old = self._row_to_dict(row)

                # Mark existing key as rotating
                conn.execute(
                    "UPDATE crypto_keys SET status = 'rotating', updated_at = ? WHERE key_id = ?",
                    (now, key_id),
                )

                # Create new key version
                new_key_id = str(uuid.uuid4())
                new_version = old["version"] + 1
                # Re-use original expiry duration assumption: 365 days from now
                new_expiry = self._compute_expiry(365)

                conn.execute(
                    """
                    INSERT INTO crypto_keys
                        (key_id, org_id, name, key_type, purpose, status, version,
                         expiry_date, tags, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        new_key_id, org_id,
                        old["name"],
                        old["key_type"], old["purpose"],
                        "active", new_version,
                        new_expiry,
                        json.dumps(old["tags"]),
                        now, now,
                    ),
                )

        return {
            "rotated_key_id": key_id,
            "new_key_id": new_key_id,
            "new_version": new_version,
            "status": "rotating",
            "rotated_at": now,
        }

    def revoke_key(self, org_id: str, key_id: str, reason: str) -> Dict[str, Any]:
        """Revoke a key. Returns updated record."""
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM crypto_keys WHERE org_id = ? AND key_id = ?",
                    (org_id, key_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Key not found: {key_id}")

                conn.execute(
                    "UPDATE crypto_keys SET status = 'revoked', updated_at = ? WHERE key_id = ?",
                    (now, key_id),
                )

        return {
            "key_id": key_id,
            "org_id": org_id,
            "status": "revoked",
            "reason": reason,
            "revoked_at": now,
        }

    def get_expiring_keys(self, org_id: str, days_ahead: int = 30) -> List[Dict[str, Any]]:
        """Return active keys expiring within the next N days."""
        now = datetime.now(timezone.utc)
        cutoff = (now + timedelta(days=days_ahead)).isoformat()
        now_iso = now.isoformat()

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM crypto_keys
                    WHERE org_id = ?
                      AND status = 'active'
                      AND expiry_date != ''
                      AND expiry_date <= ?
                      AND expiry_date >= ?
                    ORDER BY expiry_date ASC
                    """,
                    (org_id, cutoff, now_iso),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def record_key_usage(
        self, org_id: str, key_id: str, usage_type: str
    ) -> Dict[str, Any]:
        """Record a key usage event for audit trail."""
        log_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO key_usage_log (log_id, org_id, key_id, usage_type, recorded_at)
                    VALUES (?,?,?,?,?)
                    """,
                    (log_id, org_id, key_id, usage_type, now),
                )

        return {
            "log_id": log_id,
            "org_id": org_id,
            "key_id": key_id,
            "usage_type": usage_type,
            "recorded_at": now,
        }

    def get_key_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated key statistics for the org."""
        now = datetime.now(timezone.utc)
        expiring_cutoff = (now + timedelta(days=30)).isoformat()
        now_iso = now.isoformat()

        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM crypto_keys WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                by_type_rows = conn.execute(
                    "SELECT key_type, COUNT(*) as cnt FROM crypto_keys WHERE org_id = ? GROUP BY key_type",
                    (org_id,),
                ).fetchall()

                by_purpose_rows = conn.execute(
                    "SELECT purpose, COUNT(*) as cnt FROM crypto_keys WHERE org_id = ? GROUP BY purpose",
                    (org_id,),
                ).fetchall()

                expiring_soon = conn.execute(
                    """
                    SELECT COUNT(*) FROM crypto_keys
                    WHERE org_id = ? AND status = 'active'
                      AND expiry_date != '' AND expiry_date <= ? AND expiry_date >= ?
                    """,
                    (org_id, expiring_cutoff, now_iso),
                ).fetchone()[0]

                revoked = conn.execute(
                    "SELECT COUNT(*) FROM crypto_keys WHERE org_id = ? AND status = 'revoked'",
                    (org_id,),
                ).fetchone()[0]

                total_usages = conn.execute(
                    "SELECT COUNT(*) FROM key_usage_log WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

        return {
            "org_id": org_id,
            "total_keys": total,
            "by_type": {r["key_type"]: r["cnt"] for r in by_type_rows},
            "by_purpose": {r["purpose"]: r["cnt"] for r in by_purpose_rows},
            "expiring_soon_30d": expiring_soon,
            "revoked": revoked,
            "total_usage_events": total_usages,
        }
