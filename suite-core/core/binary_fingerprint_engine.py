"""Binary Fingerprint Engine — ALDECI (GAP-008).

Sonatype ABF-style (Advanced Binary Fingerprinting). Given a binary blob,
compute structural/size/TLSH-approx/ssdeep-approx fingerprints, then answer:
"Have we seen similar binaries before, and are any known-bad?"

Storage:
    binary_fingerprints       — per-org registry of seen artefacts
    known_bad_fingerprints    — global seed list of known-bad placeholders
    fingerprint_matches       — audit trail of candidate↔known-bad hits

Fingerprint components:
    sha256        — deterministic exact-match key (stdlib hashlib)
    tlsh_hash     — v0 locality-sensitive hash approximation (70 hex chars).
                    Does NOT depend on the python-tlsh native extension.
                    Swap with ``tlsh.hash(blob)`` when python-tlsh is installed.
    ssdeep_hash   — v0 fuzzy-hash approximation (blocksize:hash1:hash2).
                    Does NOT depend on python-ssdeep. Swap with
                    ``ssdeep.hash(blob)`` when that library is installed.
    size_bytes    — artefact byte length
    first_kb_hex  — first 1024 bytes of the blob, hex encoded (header signature)
    entropy       — Shannon byte-entropy (0.0..8.0)

Thread-safe via RLock. Multi-tenant via org_id. WAL journal mode.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover - optional dependency
    _get_tg_bus = None

try:
    import requests as _requests  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    _requests = None  # type: ignore


_logger = logging.getLogger(__name__)

# MalwareBazaar (abuse.ch) public API — no API key required.
_MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
_SYNTHETIC_SOURCE = "seed:synthetic-placeholder"

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "binary_fingerprint.db"
)

# Known-bad seed (synthetic placeholders — NOT real malware samples).
# Swap for a real feed (MalwareBazaar, VirusShare) when integration lands.
_KNOWN_BAD_SEED: List[Dict[str, str]] = [
    {
        "sha256": "a" * 64,
        "tlsh_hash": "T1" + "A" * 70,
        "ssdeep_hash": "3:MirA1VariantTestPlaceHolder:MirA1VariantTest",
        "threat_label": "mirai-variant-test-placeholder",
        "source": _SYNTHETIC_SOURCE,
    },
    {
        "sha256": "b" * 64,
        "tlsh_hash": "T1" + "B" * 70,
        "ssdeep_hash": "6:EmotetTestPlaceHolder:EmotetTestPH",
        "threat_label": "emotet-like-test-placeholder",
        "source": _SYNTHETIC_SOURCE,
    },
    {
        "sha256": "c" * 64,
        "tlsh_hash": "T1" + "C" * 70,
        "ssdeep_hash": "12:LokiBotTestPlaceHolder:LokiBotTestPH",
        "threat_label": "lokibot-test-placeholder",
        "source": _SYNTHETIC_SOURCE,
    },
    {
        "sha256": "d" * 64,
        "tlsh_hash": "T1" + "D" * 70,
        "ssdeep_hash": "24:TrickBotTestPlaceHolder:TrickBotTestPH",
        "threat_label": "trickbot-test-placeholder",
        "source": _SYNTHETIC_SOURCE,
    },
    {
        "sha256": "e" * 64,
        "tlsh_hash": "T1" + "E" * 70,
        "ssdeep_hash": "48:RansomNoteTestPlaceHolder:RansomTestPH",
        "threat_label": "ransomware-test-placeholder",
        "source": _SYNTHETIC_SOURCE,
    },
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _shannon_entropy(blob: bytes) -> float:
    """Compute Shannon entropy of byte frequencies in ``blob`` (0.0 .. 8.0)."""
    if not blob:
        return 0.0
    counts = [0] * 256
    for b in blob:
        counts[b] += 1
    length = len(blob)
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return round(entropy, 6)


def _compute_tlsh_approx(blob: bytes) -> str:
    """v0 TLSH approximation — 70-char hex, locality-sensitive across 5 buckets.

    NOT compatible with python-tlsh output. When python-tlsh becomes available,
    replace this with ``tlsh.hash(blob)``. Designed so:
      * Small edits preserve >= 4/5 bucket prefixes (similarity computable).
      * Tiny blobs still produce a stable 70-char string.
    """
    if not blob:
        return "T0" + "0" * 68
    n = len(blob)
    # 5 buckets, overlapping if blob small; each gives 14 hex chars (7 bytes)
    bucket_size = max(1, n // 5)
    parts: List[str] = []
    for i in range(5):
        start = i * bucket_size
        end = start + bucket_size if i < 4 else n
        chunk = blob[start:end] if start < n else blob[-bucket_size:]
        digest = hashlib.sha256(chunk).digest()[:7]
        parts.append(digest.hex())
    # Prefix "T1" marker keeps this visually distinct from a plain sha256
    return "T1" + "".join(parts)


def _compute_ssdeep_approx(blob: bytes) -> str:
    """v0 ssdeep-style fuzzy hash approximation.

    Format: ``blocksize:hashA:hashB`` where the two halves cover the blob
    with different blocksizes. Uses hashlib.blake2s (built-in rolling-friendly
    hash) rather than the native ssdeep algorithm.

    When python-ssdeep becomes available, replace with ``ssdeep.hash(blob)``.
    """
    if not blob:
        return "3::"
    n = len(blob)
    # pick blocksize similar to ssdeep's doubling strategy
    bs = max(3, min(12288, 1 << max(0, (n.bit_length() - 6))))

    def _trigram_hash(data: bytes, block: int) -> str:
        if not data:
            return ""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        out = []
        for i in range(0, len(data), block):
            window = data[i:i + block]
            if not window:
                break
            h = int.from_bytes(hashlib.blake2s(window, digest_size=2).digest(), "big")
            out.append(alphabet[h % len(alphabet)])
            if len(out) >= 64:
                break
        return "".join(out)

    hash_a = _trigram_hash(blob, bs)
    hash_b = _trigram_hash(blob, bs * 2)
    return f"{bs}:{hash_a}:{hash_b}"


def _tlsh_similarity(a: str, b: str) -> float:
    """Similarity in [0.0, 1.0] for two v0-approx TLSH hashes (70-char strings).

    Compares bucket-by-bucket (5 buckets, 14 hex chars each). Returns fraction
    of buckets whose first 4 hex chars match. Not directly comparable to real
    TLSH distance — good enough for ordering and threshold checks.
    """
    if not a or not b or not a.startswith("T1") or not b.startswith("T1"):
        return 0.0
    body_a = a[2:]
    body_b = b[2:]
    if len(body_a) != 70 or len(body_b) != 70:
        return 0.0
    matches = 0
    for i in range(5):
        seg_a = body_a[i * 14:(i * 14) + 14]
        seg_b = body_b[i * 14:(i * 14) + 14]
        # compare first 4 hex chars (2 bytes) per bucket for LSH locality
        if seg_a[:4] == seg_b[:4]:
            matches += 1
    return matches / 5.0


class BinaryFingerprintEngine:
    """SQLite WAL-backed binary fingerprint engine (GAP-008).

    Public API:
        ensure_schema()
        compute_fingerprint(blob)
        register_artifact(org_id, artifact_ref, blob)
        query_similar(org_id, blob, min_similarity=0.85)
        check_known_bad(blob)
        stats(org_id)
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._seeded = False
        self.ensure_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def ensure_schema(self) -> None:
        """Create tables if they don't exist. Idempotent."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self._conn() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS binary_fingerprints (
                        id             TEXT PRIMARY KEY,
                        org_id         TEXT NOT NULL,
                        artifact_ref   TEXT NOT NULL DEFAULT '',
                        sha256         TEXT NOT NULL,
                        tlsh_hash      TEXT NOT NULL DEFAULT '',
                        ssdeep_hash    TEXT NOT NULL DEFAULT '',
                        size_bytes     INTEGER NOT NULL DEFAULT 0,
                        first_kb_hex   TEXT NOT NULL DEFAULT '',
                        entropy        REAL NOT NULL DEFAULT 0.0,
                        created_at     TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_bf_org_sha
                        ON binary_fingerprints (org_id, sha256);
                    CREATE INDEX IF NOT EXISTS idx_bf_org_tlsh
                        ON binary_fingerprints (org_id, tlsh_hash);

                    CREATE TABLE IF NOT EXISTS known_bad_fingerprints (
                        id             TEXT PRIMARY KEY,
                        sha256         TEXT NOT NULL UNIQUE,
                        tlsh_hash      TEXT NOT NULL DEFAULT '',
                        ssdeep_hash    TEXT NOT NULL DEFAULT '',
                        threat_label   TEXT NOT NULL DEFAULT '',
                        source         TEXT NOT NULL DEFAULT '',
                        added_at       TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_kb_sha
                        ON known_bad_fingerprints (sha256);
                    CREATE INDEX IF NOT EXISTS idx_kb_tlsh
                        ON known_bad_fingerprints (tlsh_hash);

                    CREATE TABLE IF NOT EXISTS fingerprint_matches (
                        id                TEXT PRIMARY KEY,
                        org_id            TEXT NOT NULL,
                        candidate_id      TEXT NOT NULL DEFAULT '',
                        known_bad_id      TEXT NOT NULL DEFAULT '',
                        match_type        TEXT NOT NULL DEFAULT 'exact',
                        similarity_score  REAL NOT NULL DEFAULT 0.0,
                        matched_at        TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_fm_org
                        ON fingerprint_matches (org_id, matched_at);
                    """
                )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _seed_known_bad_once(self) -> None:
        """Populate known_bad_fingerprints — real feed first, synthetic fallback.

        Behavior:
            * If the table already has rows → no-op.
            * Else if FIXOPS_AIR_GAP=1 AND MalwareBazaar is unreachable
              (or returns no usable rows) → seed the 5 synthetic placeholders
              tagged ``source="seed:synthetic-placeholder"``.
            * Else (online and DB empty) → call ``sync_malwarebazaar_feed()``
              once to populate from the real feed. No synthetic placeholders.
            * Final fallback: if even the online sync produced 0 rows AND
              we are running air-gapped, still seed synthetic so the engine
              has *something* to match against in offline demos.
        """
        if self._seeded:
            return
        with self._lock:
            if self._seeded:
                return
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT COUNT(*) FROM known_bad_fingerprints"
                ).fetchone()[0]
            if existing > 0:
                self._seeded = True
                return

            airgap = os.environ.get("FIXOPS_AIR_GAP", "0").strip() in {
                "1",
                "true",
                "True",
                "yes",
            }

            imported = 0
            mb_reachable = False
            if not airgap:
                try:
                    imported = self.sync_malwarebazaar_feed()
                    mb_reachable = imported > 0
                except Exception:  # pragma: no cover - defence in depth
                    imported = 0
                    mb_reachable = False
            else:
                # In air-gap mode we still attempt a probe so we can decide
                # whether to fall back to synthetic — but it MUST NOT raise.
                try:
                    imported = self.sync_malwarebazaar_feed()
                    mb_reachable = imported > 0
                except Exception:  # pragma: no cover
                    imported = 0
                    mb_reachable = False

            # Synthetic fallback only when air-gapped AND MalwareBazaar
            # produced nothing usable.
            if airgap and not mb_reachable:
                now = _now()
                with self._conn() as conn:
                    for row in _KNOWN_BAD_SEED:
                        conn.execute(
                            """INSERT OR IGNORE INTO known_bad_fingerprints
                               (id, sha256, tlsh_hash, ssdeep_hash,
                                threat_label, source, added_at)
                               VALUES (?,?,?,?,?,?,?)""",
                            (
                                str(uuid.uuid4()),
                                row["sha256"],
                                row["tlsh_hash"],
                                row["ssdeep_hash"],
                                row["threat_label"],
                                row["source"],
                                now,
                            ),
                        )
            self._seeded = True

    # ------------------------------------------------------------------
    # Known-bad feed sync (MalwareBazaar / abuse.ch)
    # ------------------------------------------------------------------

    def _upsert_known_bad(self, row: Dict[str, Any]) -> None:
        """Insert or replace a known-bad row keyed on sha256.

        Thread-safe + WAL via the engine's RLock and connection helper.
        Silent on bad input — refuses to write if sha256 is blank.
        """
        sha256 = (row.get("sha256") or "").strip().lower()
        if not sha256:
            return
        tlsh_hash = (row.get("tlsh_hash") or "").strip()
        ssdeep_hash = (row.get("ssdeep_hash") or "").strip()
        threat_label = (row.get("threat_label") or "unknown").strip() or "unknown"
        source = (row.get("source") or "").strip() or "unknown"
        now = _now()
        with self._lock:
            with self._conn() as conn:
                # INSERT OR REPLACE keyed on sha256 unique index.
                existing = conn.execute(
                    "SELECT id FROM known_bad_fingerprints WHERE sha256=?",
                    (sha256,),
                ).fetchone()
                if existing:
                    conn.execute(
                        """UPDATE known_bad_fingerprints
                           SET tlsh_hash=?, ssdeep_hash=?, threat_label=?,
                               source=?, added_at=?
                           WHERE sha256=?""",
                        (tlsh_hash, ssdeep_hash, threat_label, source, now, sha256),
                    )
                else:
                    conn.execute(
                        """INSERT INTO known_bad_fingerprints
                           (id, sha256, tlsh_hash, ssdeep_hash,
                            threat_label, source, added_at)
                           VALUES (?,?,?,?,?,?,?)""",
                        (
                            str(uuid.uuid4()),
                            sha256,
                            tlsh_hash,
                            ssdeep_hash,
                            threat_label,
                            source,
                            now,
                        ),
                    )

    def sync_malwarebazaar_feed(self, limit: int = 1000) -> int:
        """Pull the most recent N samples from MalwareBazaar (abuse.ch).

        Public endpoint. As of 2024 abuse.ch requires an Auth-Key header
        for ``get_recent`` queries — set ``MALWAREBAZAAR_API_KEY`` env var
        to a free key from https://auth.abuse.ch/. When unset, the request
        still goes out (returns 401, we treat as 0) so the engine remains
        usable in air-gap test mode without leaking errors.

        Returns:
            int — number of samples successfully upserted.

        Never raises — returns 0 on any network/parse/auth failure.
        """
        if _requests is None:
            return 0
        try:
            headers = {}
            api_key = os.environ.get("MALWAREBAZAAR_API_KEY", "").strip()
            if api_key:
                headers["Auth-Key"] = api_key
            resp = _requests.post(
                _MALWAREBAZAAR_URL,
                data={
                    "query": "get_recent",
                    "selector": "time",
                    "limit": int(max(1, min(int(limit or 1000), 1000))),
                },
                headers=headers,
                timeout=30,
            )
            if resp.status_code != 200:
                return 0
            try:
                payload = resp.json()
            except Exception:
                return 0
            if not isinstance(payload, dict):
                return 0
            if payload.get("query_status") != "ok":
                return 0
            samples = payload.get("data") or []
            if not isinstance(samples, list):
                return 0
            count = 0
            for sample in samples:
                if not isinstance(sample, dict):
                    continue
                sha256 = (sample.get("sha256_hash") or "").strip().lower()
                if not sha256:
                    continue
                tags = sample.get("tags") or []
                if not isinstance(tags, list):
                    tags = []
                threat_label = (
                    sample.get("signature")
                    or (tags[0] if tags else None)
                    or "unknown"
                )
                try:
                    self._upsert_known_bad(
                        {
                            "sha256": sha256,
                            "tlsh_hash": sample.get("tlsh", "") or "",
                            "ssdeep_hash": sample.get("ssdeep", "") or "",
                            "threat_label": threat_label,
                            "source": "malwarebazaar",
                        }
                    )
                    count += 1
                except Exception:
                    # never abort the whole sync over one bad row
                    continue
            return count
        except Exception:
            return 0

    def sync_from_local_feed(self, feed_path: str) -> int:
        """Import a local MalwareBazaar-shaped JSON export (air-gap / USB).

        Accepts either a top-level ``{"data": [...]}`` envelope OR a bare
        list of sample dicts. Each sample uses the same field names as the
        MalwareBazaar HTTP API (``sha256_hash``, ``tlsh``, ``ssdeep``,
        ``signature``, ``tags``).

        Returns:
            int — number of samples successfully upserted. 0 on any error.

        Never raises.
        """
        try:
            path = Path(feed_path)
            if not path.is_file():
                return 0
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return 0
            if isinstance(payload, list):
                samples = payload
            elif isinstance(payload, dict):
                samples = payload.get("data") or []
            else:
                samples = []
            if not isinstance(samples, list):
                return 0
            count = 0
            for sample in samples:
                if not isinstance(sample, dict):
                    continue
                sha256 = (sample.get("sha256_hash") or "").strip().lower()
                if not sha256:
                    continue
                tags = sample.get("tags") or []
                if not isinstance(tags, list):
                    tags = []
                threat_label = (
                    sample.get("signature")
                    or (tags[0] if tags else None)
                    or "unknown"
                )
                try:
                    self._upsert_known_bad(
                        {
                            "sha256": sha256,
                            "tlsh_hash": sample.get("tlsh", "") or "",
                            "ssdeep_hash": sample.get("ssdeep", "") or "",
                            "threat_label": threat_label,
                            "source": "malwarebazaar:local-feed",
                        }
                    )
                    count += 1
                except Exception:
                    continue
            return count
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # Fingerprint computation
    # ------------------------------------------------------------------

    def compute_fingerprint(self, blob: bytes) -> Dict[str, Any]:
        """Compute the 6-component fingerprint for a binary blob.

        Returns a dict with keys:
            sha256, tlsh_hash, ssdeep_hash, size_bytes, first_kb_hex, entropy
        """
        if blob is None:
            blob = b""
        if not isinstance(blob, (bytes, bytearray)):
            raise TypeError("blob must be bytes-like")
        blob = bytes(blob)

        sha256 = hashlib.sha256(blob).hexdigest()
        tlsh_hash = _compute_tlsh_approx(blob)
        ssdeep_hash = _compute_ssdeep_approx(blob)
        size_bytes = len(blob)
        first_kb_hex = blob[:1024].hex()
        entropy = _shannon_entropy(blob)

        return {
            "sha256": sha256,
            "tlsh_hash": tlsh_hash,
            "ssdeep_hash": ssdeep_hash,
            "size_bytes": size_bytes,
            "first_kb_hex": first_kb_hex,
            "entropy": entropy,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def register_artifact(
        self,
        org_id: str,
        artifact_ref: str,
        blob: bytes,
    ) -> Dict[str, Any]:
        """Compute + persist a fingerprint for an artefact owned by ``org_id``."""
        if not org_id:
            raise ValueError("org_id is required")
        fp = self.compute_fingerprint(blob)
        rec_id = str(uuid.uuid4())
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO binary_fingerprints
                       (id, org_id, artifact_ref, sha256, tlsh_hash,
                        ssdeep_hash, size_bytes, first_kb_hex, entropy,
                        created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        rec_id,
                        org_id,
                        artifact_ref or "",
                        fp["sha256"],
                        fp["tlsh_hash"],
                        fp["ssdeep_hash"],
                        fp["size_bytes"],
                        fp["first_kb_hex"],
                        fp["entropy"],
                        now,
                    ),
                )
        record = {
            "id": rec_id,
            "org_id": org_id,
            "artifact_ref": artifact_ref or "",
            "created_at": now,
            **fp,
        }
        self._emit_bus_event("BINARY_FINGERPRINT_REGISTERED", org_id)
        return record

    # ------------------------------------------------------------------
    # Similarity query
    # ------------------------------------------------------------------

    def query_similar(
        self,
        org_id: str,
        blob: bytes,
        min_similarity: float = 0.85,
    ) -> Dict[str, Any]:
        """Scan this org's registry for fingerprints similar to ``blob``.

        Matches:
            * Exact sha256 match — similarity 1.0.
            * TLSH-approx bucket overlap >= ``min_similarity``.
        """
        if not org_id:
            raise ValueError("org_id is required")
        if not 0.0 <= min_similarity <= 1.0:
            raise ValueError("min_similarity must be within [0.0, 1.0]")

        fp = self.compute_fingerprint(blob)
        matches: List[Dict[str, Any]] = []
        exact: List[Dict[str, Any]] = []

        with self._lock:
            with self._conn() as conn:
                exact_rows = conn.execute(
                    """SELECT * FROM binary_fingerprints
                       WHERE org_id=? AND sha256=?""",
                    (org_id, fp["sha256"]),
                ).fetchall()
                for row in exact_rows:
                    rec = dict(row)
                    rec["similarity"] = 1.0
                    rec["match_type"] = "exact"
                    exact.append(rec)

                candidate_rows = conn.execute(
                    """SELECT * FROM binary_fingerprints
                       WHERE org_id=? AND sha256 != ?""",
                    (org_id, fp["sha256"]),
                ).fetchall()
                for row in candidate_rows:
                    sim = _tlsh_similarity(fp["tlsh_hash"], row["tlsh_hash"] or "")
                    if sim >= min_similarity:
                        rec = dict(row)
                        rec["similarity"] = sim
                        rec["match_type"] = "tlsh_approx"
                        matches.append(rec)

        matches.sort(key=lambda m: m["similarity"], reverse=True)
        all_matches = exact + matches
        return {
            "org_id": org_id,
            "query_fingerprint": fp,
            "min_similarity": min_similarity,
            "exact_matches": len(exact),
            "approx_matches": len(matches),
            "matches": all_matches,
        }

    # ------------------------------------------------------------------
    # Known-bad check
    # ------------------------------------------------------------------

    def check_known_bad(
        self,
        blob: bytes,
        org_id: Optional[str] = None,
        candidate_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Look up ``blob`` against known-bad registry.

        Returns verdict dict, or ``None`` if no match found.
        Also records a row in ``fingerprint_matches`` when ``org_id`` supplied.
        """
        self._seed_known_bad_once()
        fp = self.compute_fingerprint(blob)

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM known_bad_fingerprints WHERE sha256=?",
                    (fp["sha256"],),
                ).fetchone()
                match_type = "exact"
                similarity = 1.0
                if not row:
                    # scan all known-bad and compute tlsh similarity
                    all_bad = conn.execute(
                        "SELECT * FROM known_bad_fingerprints"
                    ).fetchall()
                    best_row = None
                    best_sim = 0.0
                    for candidate in all_bad:
                        sim = _tlsh_similarity(
                            fp["tlsh_hash"], candidate["tlsh_hash"] or ""
                        )
                        if sim > best_sim:
                            best_sim = sim
                            best_row = candidate
                    if best_row and best_sim >= 0.8:
                        row = best_row
                        match_type = "tlsh_approx"
                        similarity = best_sim

        if not row:
            return None

        verdict = {
            "verdict": "known_bad",
            "match_type": match_type,
            "similarity": similarity,
            "known_bad_id": row["id"],
            "sha256": row["sha256"],
            "threat_label": row["threat_label"],
            "source": row["source"],
            "query_fingerprint": fp,
        }

        if org_id:
            with self._lock:
                with self._conn() as conn:
                    conn.execute(
                        """INSERT INTO fingerprint_matches
                           (id, org_id, candidate_id, known_bad_id,
                            match_type, similarity_score, matched_at)
                           VALUES (?,?,?,?,?,?,?)""",
                        (
                            str(uuid.uuid4()),
                            org_id,
                            candidate_id or "",
                            row["id"],
                            match_type,
                            similarity,
                            _now(),
                        ),
                    )
            self._emit_bus_event("BINARY_FINGERPRINT_KNOWN_BAD_MATCH", org_id)

        return verdict

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self, org_id: str) -> Dict[str, Any]:
        """Return fingerprint counters for an org."""
        if not org_id:
            raise ValueError("org_id is required")
        with self._lock:
            with self._conn() as conn:
                fingerprints_seen = conn.execute(
                    "SELECT COUNT(*) FROM binary_fingerprints WHERE org_id=?",
                    (org_id,),
                ).fetchone()[0]
                unique_sha256 = conn.execute(
                    """SELECT COUNT(DISTINCT sha256) FROM binary_fingerprints
                       WHERE org_id=?""",
                    (org_id,),
                ).fetchone()[0]
                known_bad_matches = conn.execute(
                    "SELECT COUNT(*) FROM fingerprint_matches WHERE org_id=?",
                    (org_id,),
                ).fetchone()[0]
                total_bytes_row = conn.execute(
                    """SELECT COALESCE(SUM(size_bytes), 0) AS total
                       FROM binary_fingerprints WHERE org_id=?""",
                    (org_id,),
                ).fetchone()
                total_bytes = total_bytes_row["total"] if total_bytes_row else 0
                avg_entropy_row = conn.execute(
                    """SELECT COALESCE(AVG(entropy), 0.0) AS avg_e
                       FROM binary_fingerprints WHERE org_id=?""",
                    (org_id,),
                ).fetchone()
                avg_entropy = (
                    round(avg_entropy_row["avg_e"], 6)
                    if avg_entropy_row and avg_entropy_row["avg_e"] is not None
                    else 0.0
                )
        return {
            "org_id": org_id,
            "fingerprints_seen": fingerprints_seen,
            "unique_sha256": unique_sha256,
            "known_bad_matches": known_bad_matches,
            "total_bytes": total_bytes,
            "avg_entropy": avg_entropy,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _emit_bus_event(self, event_type: str, org_id: str) -> None:
        if _get_tg_bus is None:
            return
        try:
            import asyncio
            import inspect
            bus = _get_tg_bus()
            if not (bus and getattr(bus, "enabled", False)):
                return
            payload = {
                "entity_type": "binary_fingerprint_engine",
                "org_id": org_id,
                "source_engine": "binary_fingerprint_engine",
            }
            result = bus.emit(event_type, payload)
            # emit may be sync or async depending on bus implementation
            if inspect.iscoroutine(result):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    # no running loop — close the coroutine to avoid warnings
                    result.close()
        except Exception:  # pragma: no cover - bus optional
            pass
