"""
Cryptographic evidence chain — tamper-proof audit trail using hash chains.

Each entry links to the previous entry via SHA-256, forming a blockchain-style
immutable log. HMAC-SHA-256 signatures protect individual entries.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# HMAC key — sourced from env or a stable fallback for deterministic testing
# ---------------------------------------------------------------------------
_HMAC_KEY: bytes = os.environ.get("EVIDENCE_CHAIN_HMAC_KEY", "fixops-evidence-chain-key").encode()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ChainEntry(BaseModel):
    """A single tamper-proof entry in the evidence chain."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sequence_number: int
    event_type: str
    data_hash: str  # SHA-256 of the raw event data
    previous_hash: str  # SHA-256 of the previous entry (or "0"*64 for genesis)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str  # HMAC-SHA-256 over (id + sequence_number + data_hash + previous_hash)
    org_id: str


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _hmac_sign(entry_id: str, seq: int, data_hash: str, previous_hash: str) -> str:
    """Compute HMAC-SHA-256 signature for a chain entry."""
    payload = f"{entry_id}:{seq}:{data_hash}:{previous_hash}"
    return hmac.new(_HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()


def _hmac_verify(entry: ChainEntry) -> bool:
    """Return True if the entry's HMAC signature is valid."""
    expected = _hmac_sign(entry.id, entry.sequence_number, entry.data_hash, entry.previous_hash)
    return hmac.compare_digest(expected, entry.signature)


GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# EvidenceChain
# ---------------------------------------------------------------------------


class EvidenceChain:
    """SQLite-backed cryptographic evidence chain.

    Each org has an independent chain rooted at the genesis hash.

    Performance notes:
    - A single persistent connection (WAL mode, check_same_thread=False) is
      reused across all calls instead of opening/closing a new connection per
      operation.  This eliminates per-call connection-open overhead (~0.5 ms
      each on macOS).
    - detect_tampering() no longer calls get_chain() a second time; it reuses
      the entries already loaded inside verify_chain().
    - get_chain_stats() no longer calls get_chain() separately; it reads the
      chain once inside verify_chain().
    """

    def __init__(self, db_path: str = "data/evidence_chain.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Persistent, reusable connection — WAL mode for concurrent readers.
        # check_same_thread=False is safe because we hold _lock around every
        # write and sqlite3 serialises reads by itself in WAL mode.
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection = sqlite3.connect(
            str(self.db_path), check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_tables()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        """Return the shared persistent connection."""
        return self._conn

    def _init_tables(self) -> None:
        # Use the shared persistent connection — do NOT close it here.
        conn = self._get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS chain_entries (
                id              TEXT PRIMARY KEY,
                sequence_number INTEGER NOT NULL,
                event_type      TEXT NOT NULL,
                data_hash       TEXT NOT NULL,
                previous_hash   TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                signature       TEXT NOT NULL,
                org_id          TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chain_org_seq
                ON chain_entries (org_id, sequence_number);

            CREATE INDEX IF NOT EXISTS idx_chain_org_ts
                ON chain_entries (org_id, timestamp);
            """
        )
        conn.commit()

    def _row_to_entry(self, row: sqlite3.Row) -> ChainEntry:
        return ChainEntry(
            id=row["id"],
            sequence_number=row["sequence_number"],
            event_type=row["event_type"],
            data_hash=row["data_hash"],
            previous_hash=row["previous_hash"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            signature=row["signature"],
            org_id=row["org_id"],
        )

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def append(self, event_type: str, data: Any, org_id: str) -> ChainEntry:
        """Append a new entry to the chain for *org_id*.

        The entry hashes the serialised *data* and links to the previous
        entry's hash (blockchain-style).
        """
        serialised = json.dumps(data, sort_keys=True, default=str)
        data_hash = _sha256(serialised)

        prev = self.get_latest(org_id)
        if prev is None:
            previous_hash = GENESIS_HASH
        else:
            previous_hash = _sha256(
                f"{prev.id}:{prev.sequence_number}:{prev.data_hash}:{prev.previous_hash}"
            )

        seq = 0 if prev is None else prev.sequence_number + 1
        entry_id = str(uuid.uuid4())
        signature = _hmac_sign(entry_id, seq, data_hash, previous_hash)

        entry = ChainEntry(
            id=entry_id,
            sequence_number=seq,
            event_type=event_type,
            data_hash=data_hash,
            previous_hash=previous_hash,
            timestamp=datetime.now(timezone.utc),
            signature=signature,
            org_id=org_id,
        )

        conn = self._get_conn()
        with self._lock:
            conn.execute(
                """
                INSERT INTO chain_entries
                    (id, sequence_number, event_type, data_hash, previous_hash,
                     timestamp, signature, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.sequence_number,
                    entry.event_type,
                    entry.data_hash,
                    entry.previous_hash,
                    entry.timestamp.isoformat(),
                    entry.signature,
                    entry.org_id,
                ),
            )
            conn.commit()

        return entry

    def get_latest(self, org_id: str) -> Optional[ChainEntry]:
        """Return the most recent entry for *org_id*, or None if the chain is empty."""
        conn = self._get_conn()
        row = conn.execute(
            """
            SELECT * FROM chain_entries
            WHERE org_id = ?
            ORDER BY sequence_number DESC
            LIMIT 1
            """,
            (org_id,),
        ).fetchone()
        return self._row_to_entry(row) if row else None

    def get_chain(
        self,
        org_id: str,
        start: int = 0,
        end: Optional[int] = None,
    ) -> List[ChainEntry]:
        """Return entries with sequence_number in [start, end] for *org_id*."""
        conn = self._get_conn()
        if end is None:
            rows = conn.execute(
                """
                SELECT * FROM chain_entries
                WHERE org_id = ? AND sequence_number >= ?
                ORDER BY sequence_number ASC
                """,
                (org_id, start),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM chain_entries
                WHERE org_id = ? AND sequence_number >= ? AND sequence_number <= ?
                ORDER BY sequence_number ASC
                """,
                (org_id, start, end),
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_chain_length(self, org_id: str) -> int:
        """Return total number of entries for *org_id*."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM chain_entries WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # Integrity verification
    # ------------------------------------------------------------------

    def verify_chain(self, org_id: str) -> Dict[str, Any]:
        """Validate the entire chain for *org_id*.

        Re-derives each entry's expected previous_hash and checks HMAC
        signatures.  Returns a report dict.

        The loaded entries are embedded in the return value under the private
        key ``_entries`` so that callers like detect_tampering / get_chain_stats
        can reuse them without a second DB round-trip.
        """
        entries = self.get_chain(org_id)
        broken_links: List[int] = []
        invalid_signatures: List[int] = []

        expected_previous = GENESIS_HASH

        for entry in entries:
            # Check linkage
            if entry.previous_hash != expected_previous:
                broken_links.append(entry.sequence_number)

            # Check HMAC
            if not _hmac_verify(entry):
                invalid_signatures.append(entry.sequence_number)

            # Derive the hash that the *next* entry should reference
            expected_previous = _sha256(
                f"{entry.id}:{entry.sequence_number}:{entry.data_hash}:{entry.previous_hash}"
            )

        is_valid = not broken_links and not invalid_signatures
        return {
            "org_id": org_id,
            "chain_length": len(entries),
            "is_valid": is_valid,
            "broken_links": broken_links,
            "invalid_signatures": invalid_signatures,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            # Private key: reuse by detect_tampering / get_chain_stats to avoid
            # a redundant get_chain() DB call.
            "_entries": entries,
        }

    def detect_tampering(self, org_id: str) -> List[Dict[str, Any]]:
        """Return a list of tampered entries (broken hash link or bad HMAC).

        Perf fix: reuses the entries embedded in verify_chain() result instead
        of issuing a second get_chain() DB query.
        """
        result = self.verify_chain(org_id)
        broken = set(result["broken_links"]) | set(result["invalid_signatures"])
        # Reuse the entries already loaded by verify_chain — no second DB read.
        entries: List[ChainEntry] = result.pop("_entries", [])
        tampered = []
        for entry in entries:
            if entry.sequence_number in broken:
                reason = []
                if entry.sequence_number in result["broken_links"]:
                    reason.append("broken_hash_link")
                if entry.sequence_number in result["invalid_signatures"]:
                    reason.append("invalid_hmac")
                tampered.append(
                    {
                        "sequence_number": entry.sequence_number,
                        "entry_id": entry.id,
                        "reason": reason,
                    }
                )
        return tampered

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------

    def get_chain_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary statistics for *org_id*'s chain.

        Perf fix: verify_chain() already loads the full entry list; we extract
        that list from its result instead of calling get_chain() again.
        """
        verification = self.verify_chain(org_id)
        entries: List[ChainEntry] = verification.pop("_entries", [])
        if not entries:
            return {
                "org_id": org_id,
                "length": 0,
                "first_timestamp": None,
                "last_timestamp": None,
                "integrity_status": "empty",
            }
        return {
            "org_id": org_id,
            "length": len(entries),
            "first_timestamp": entries[0].timestamp.isoformat(),
            "last_timestamp": entries[-1].timestamp.isoformat(),
            "integrity_status": "valid" if verification["is_valid"] else "tampered",
        }

    def export_chain(self, org_id: str) -> List[Dict[str, Any]]:
        """Return the full chain as a list of dicts suitable for JSON export."""
        entries = self.get_chain(org_id)
        return [
            {
                "id": e.id,
                "sequence_number": e.sequence_number,
                "event_type": e.event_type,
                "data_hash": e.data_hash,
                "previous_hash": e.previous_hash,
                "timestamp": e.timestamp.isoformat(),
                "signature": e.signature,
                "org_id": e.org_id,
            }
            for e in entries
        ]
