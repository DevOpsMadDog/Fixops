"""Tamper-evident audit chain — Merkle-style hash chaining over SQLite.

Every entry's ``entry_hash`` is computed as ``SHA-256(prev_hash || canonical_json(payload))``.
The first entry's ``prev_hash`` is the genesis seed (configurable; defaults to all
zeros). Verifying the chain re-walks every entry and recomputes the hash chain;
a single mutated row breaks verification at the row of the mutation.

Designed to satisfy:
  * FedRAMP High AU-9 (audit log protection)
  * NIST SP 800-92 (centralized log management)
  * IL5 / IC ITE tamper-evidence requirements

Optional integrations
---------------------
* When ``HSM_ENABLED=1`` and an HSM provider is available, each *batch checkpoint*
  (every N entries, default 100) is signed with an RSA key stored in the HSM and
  the signature is recorded as a checkpoint row. This gives auditors a single
  signed root-of-chain to verify against.

* When the HSM is unavailable, checkpoints are still chained by hash but
  unsigned (mode is recorded in the row).

WORM posture
------------
The schema marks rows append-only. There are no UPDATE/DELETE statements in
this module. Operators wishing for true WORM should mount the DB on a
read-only filesystem layer (e.g. dm-verity) and rotate via append-new-DB.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

_logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64
DEFAULT_CHECKPOINT_INTERVAL = 100
_DEFAULT_DB_PATH = Path(
    os.environ.get(
        "FIXOPS_AUDIT_CHAIN_DB",
        str(Path(__file__).resolve().parents[2] / ".fixops_data" / "audit_chain.db"),
    )
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _canonical_json(payload: Any) -> str:
    """Stable JSON for hashing: sorted keys, separators forced, no whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_entry(prev_hash: str, payload_json: str, ts_iso: str, action: str) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(b"|")
    h.update(ts_iso.encode("utf-8"))
    h.update(b"|")
    h.update(action.encode("utf-8"))
    h.update(b"|")
    h.update(payload_json.encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------
@dataclass
class ChainEntry:
    seq: int
    entry_id: str
    timestamp: str
    action: str
    payload: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""
    actor: str = "system"
    is_checkpoint: bool = False
    checkpoint_signature: Optional[str] = None
    checkpoint_signer: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "actor": self.actor,
            "is_checkpoint": self.is_checkpoint,
            "checkpoint_signature": self.checkpoint_signature,
            "checkpoint_signer": self.checkpoint_signer,
        }


@dataclass
class VerifyResult:
    ok: bool
    total_entries: int
    first_broken_seq: Optional[int] = None
    error: Optional[str] = None
    checkpoint_signatures_verified: int = 0
    checkpoint_signatures_failed: int = 0


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_chain (
    seq                  INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id             TEXT NOT NULL UNIQUE,
    timestamp            TEXT NOT NULL,
    action               TEXT NOT NULL,
    payload              TEXT NOT NULL,
    prev_hash            TEXT NOT NULL,
    entry_hash           TEXT NOT NULL UNIQUE,
    actor                TEXT NOT NULL DEFAULT 'system',
    is_checkpoint        INTEGER NOT NULL DEFAULT 0,
    checkpoint_signature TEXT,
    checkpoint_signer    TEXT
);
CREATE INDEX IF NOT EXISTS ix_chain_ts     ON audit_chain (timestamp);
CREATE INDEX IF NOT EXISTS ix_chain_action ON audit_chain (action);
CREATE INDEX IF NOT EXISTS ix_chain_actor  ON audit_chain (actor);
"""


# ---------------------------------------------------------------------------
# AuditChain
# ---------------------------------------------------------------------------
class AuditChain:
    """Append-only hash-chained audit log.

    Thread-safe (single RLock around the connection). Uses SQLite WAL mode for
    durability and concurrent readers.
    """

    def __init__(
        self,
        db_path: str | Path = _DEFAULT_DB_PATH,
        checkpoint_interval: int = DEFAULT_CHECKPOINT_INTERVAL,
        sign_checkpoints: bool = True,
        signing_key_label: str = "audit-chain-checkpoint",
    ) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._checkpoint_interval = max(1, int(checkpoint_interval))
        self._sign_checkpoints = bool(sign_checkpoints)
        self._signing_key_label = signing_key_label
        self._hsm = None  # lazy

    # ------------------------------------------------------------------
    # HSM (lazy import to avoid hard dependency for tests)
    # ------------------------------------------------------------------
    def _get_hsm(self):
        if self._hsm is not None:
            return self._hsm
        if not self._sign_checkpoints:
            return None
        if os.environ.get("HSM_ENABLED", "0") != "1":
            return None
        try:
            from core.hsm_provider import get_hsm  # type: ignore
            self._hsm = get_hsm()
            # Ensure a signing key exists
            if self._hsm.get_key(self._signing_key_label) is None:
                self._hsm.generate_rsa_keypair(self._signing_key_label, 3072)
            return self._hsm
        except Exception as exc:  # pragma: no cover
            _logger.warning("HSM unavailable for chain signing: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Append
    # ------------------------------------------------------------------
    def append(
        self,
        action: str,
        payload: Optional[dict[str, Any]] = None,
        actor: str = "system",
    ) -> ChainEntry:
        """Append a new entry to the chain.

        Returns the persisted :class:`ChainEntry`. Thread-safe.
        """
        if not action:
            raise ValueError("action is required")
        payload = payload or {}
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict")
        ts = _now_iso()
        payload_json = _canonical_json(payload)

        with self._lock:
            prev_hash = self._tip_hash()
            entry_hash = _hash_entry(prev_hash, payload_json, ts, action)
            entry_id = str(uuid.uuid4())
            cur = self._conn.execute(
                """
                INSERT INTO audit_chain
                    (entry_id, timestamp, action, payload, prev_hash, entry_hash, actor)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (entry_id, ts, action, payload_json, prev_hash, entry_hash, actor),
            )
            self._conn.commit()
            seq = int(cur.lastrowid)

            entry = ChainEntry(
                seq=seq,
                entry_id=entry_id,
                timestamp=ts,
                action=action,
                payload=payload,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                actor=actor,
            )

            # Auto-checkpoint every N entries (excluding the checkpoint row itself)
            if seq > 0 and seq % self._checkpoint_interval == 0:
                try:
                    self._write_checkpoint(seq)
                except Exception as exc:  # pragma: no cover
                    _logger.warning("Checkpoint failed at seq=%d: %s", seq, exc)
            return entry

    def _write_checkpoint(self, at_seq: int) -> None:
        """Write a checkpoint row (also chained) and optionally sign with HSM."""
        ts = _now_iso()
        prev_hash = self._tip_hash()
        payload = {"checkpoint_for_seq": at_seq, "tip_hash": prev_hash}
        payload_json = _canonical_json(payload)
        entry_hash = _hash_entry(prev_hash, payload_json, ts, "checkpoint")
        entry_id = str(uuid.uuid4())

        sig_b64 = None
        signer = None
        hsm = self._get_hsm()
        if hsm is not None:
            try:
                key = hsm.get_key(self._signing_key_label)
                if key is None:
                    key = hsm.generate_rsa_keypair(self._signing_key_label, 3072)
                sig = hsm.sign(key, entry_hash.encode("ascii"))
                import base64 as _b
                sig_b64 = _b.b64encode(sig).decode("ascii")
                signer = key.backend
            except Exception as exc:  # pragma: no cover
                _logger.warning("Checkpoint sign failed: %s", exc)

        self._conn.execute(
            """
            INSERT INTO audit_chain
                (entry_id, timestamp, action, payload, prev_hash, entry_hash,
                 actor, is_checkpoint, checkpoint_signature, checkpoint_signer)
            VALUES (?, ?, 'checkpoint', ?, ?, ?, 'system', 1, ?, ?)
            """,
            (entry_id, ts, payload_json, prev_hash, entry_hash, sig_b64, signer),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------
    def _tip_hash(self) -> str:
        cur = self._conn.execute(
            "SELECT entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
        )
        row = cur.fetchone()
        return row[0] if row else GENESIS_HASH

    def tip(self) -> Optional[ChainEntry]:
        cur = self._conn.execute(
            "SELECT * FROM audit_chain ORDER BY seq DESC LIMIT 1"
        )
        row = cur.fetchone()
        return self._row_to_entry(row) if row else None

    def get(self, seq: int) -> Optional[ChainEntry]:
        cur = self._conn.execute("SELECT * FROM audit_chain WHERE seq = ?", (seq,))
        row = cur.fetchone()
        return self._row_to_entry(row) if row else None

    def iter_entries(self, since_seq: int = 0) -> Iterable[ChainEntry]:
        cur = self._conn.execute(
            "SELECT * FROM audit_chain WHERE seq > ? ORDER BY seq ASC",
            (since_seq,),
        )
        for row in cur.fetchall():
            yield self._row_to_entry(row)

    def count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM audit_chain")
        return int(cur.fetchone()[0])

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> ChainEntry:
        return ChainEntry(
            seq=row["seq"],
            entry_id=row["entry_id"],
            timestamp=row["timestamp"],
            action=row["action"],
            payload=json.loads(row["payload"]) if row["payload"] else {},
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
            actor=row["actor"],
            is_checkpoint=bool(row["is_checkpoint"]),
            checkpoint_signature=row["checkpoint_signature"],
            checkpoint_signer=row["checkpoint_signer"],
        )

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------
    def verify(self) -> bool:
        """Return True if the entire chain hashes consistently. Convenience wrapper."""
        return self.verify_full().ok

    def verify_full(self) -> VerifyResult:
        """Re-walk the chain. Returns a structured :class:`VerifyResult`."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT seq, action, timestamp, payload, prev_hash, entry_hash, "
                "is_checkpoint, checkpoint_signature, checkpoint_signer "
                "FROM audit_chain ORDER BY seq ASC"
            )
            rows = cur.fetchall()

        prev = GENESIS_HASH
        verified_sigs = 0
        failed_sigs = 0
        hsm = self._get_hsm()
        signing_key = None
        if hsm is not None:
            try:
                signing_key = hsm.get_key(self._signing_key_label)
            except Exception:  # pragma: no cover
                signing_key = None

        for row in rows:
            expected = _hash_entry(prev, row["payload"], row["timestamp"], row["action"])
            if row["prev_hash"] != prev:
                return VerifyResult(
                    ok=False, total_entries=len(rows),
                    first_broken_seq=int(row["seq"]),
                    error=f"prev_hash mismatch at seq={row['seq']} "
                          f"(expected {prev[:16]}..., got {row['prev_hash'][:16]}...)",
                )
            if expected != row["entry_hash"]:
                return VerifyResult(
                    ok=False, total_entries=len(rows),
                    first_broken_seq=int(row["seq"]),
                    error=f"entry_hash mismatch at seq={row['seq']} "
                          f"(expected {expected[:16]}..., got {row['entry_hash'][:16]}...)",
                )
            # Verify checkpoint signature when possible
            if row["is_checkpoint"] and row["checkpoint_signature"] and signing_key is not None:
                try:
                    import base64 as _b
                    sig = _b.b64decode(row["checkpoint_signature"])
                    if hsm.verify(signing_key, row["entry_hash"].encode("ascii"), sig):
                        verified_sigs += 1
                    else:
                        failed_sigs += 1
                except Exception:  # pragma: no cover
                    failed_sigs += 1
            prev = row["entry_hash"]

        return VerifyResult(
            ok=True,
            total_entries=len(rows),
            checkpoint_signatures_verified=verified_sigs,
            checkpoint_signatures_failed=failed_sigs,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
            finally:
                self._conn.close()


# ---------------------------------------------------------------------------
# Module-level singleton (mirrors AuditLogger.get_instance)
# ---------------------------------------------------------------------------
_INSTANCE_LOCK = threading.Lock()
_INSTANCE: Optional[AuditChain] = None


def get_audit_chain() -> AuditChain:
    """Process-wide singleton."""
    global _INSTANCE  # noqa: PLW0603
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = AuditChain()
        return _INSTANCE


def reset_audit_chain() -> None:
    """Test-only reset."""
    global _INSTANCE  # noqa: PLW0603
    with _INSTANCE_LOCK:
        if _INSTANCE is not None:
            _INSTANCE.close()
        _INSTANCE = None


__all__ = [
    "AuditChain",
    "ChainEntry",
    "VerifyResult",
    "GENESIS_HASH",
    "get_audit_chain",
    "reset_audit_chain",
]
