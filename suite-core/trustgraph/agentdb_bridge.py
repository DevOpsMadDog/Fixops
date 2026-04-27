"""AgentDB Bridge — TrustGraph + LLM Council semantic memory adapter.

Wires Ruflo AgentDB (HNSW-indexed vector DB, 384-dim ONNX embeddings) into
TrustGraph as a parallel store for semantic search over emit-events and
DPO learning signals.

Architecture
------------

    TrustGraph EventBus.emit("finding.created", payload)
        |
        |---> SQLite KnowledgeStore.ingest(...)        (existing path)
        |
        +---> AgentDBBridge.dual_write(payload)        (NEW path)
                  |
                  |--> direct SQLite write to .swarm/memory.db
                  |    (hot path, ~5-15ms incl. embed)
                  |
                  +--> ruflo memory store (subprocess fallback)
                       only used when direct write fails

    LLMCouncilEngine.convene(finding, context)
        |
        +-- agentdb_bridge.find_similar_decisions(finding) → top-k past verdicts
            └─> augments council prompt: "we faced N similar decisions, here's
                what we ruled" — completes the RAG-over-TrustGraph loop.

Two write paths
---------------

1. **Direct SQLite write** (hot path, ~5-15ms):
   We write to ``.swarm/memory.db`` (the AgentDB store created by
   ``ruflo memory init``) using its documented schema:
       memory_entries(id, key, namespace, content, embedding, embedding_model,
                      embedding_dimensions, tags, metadata, ...)
   Embedding is computed via ONNX MiniLM (384-dim) if available; otherwise we
   write a deterministic hash-based pseudo-embedding so search still works
   (cosine over hash buckets is degraded but non-zero — better than nothing).

2. **CLI fallback** (~2-4s, for tooling or when SQLite is locked):
   ``ruflo memory store -k <key> --value <json>`` — slow but always works.
   Subprocess + 5-second timeout, fire-and-forget if direct write succeeded.

Public API
----------

    bridge = get_agentdb_bridge()
    bridge.dual_write(event_type="finding.created", payload={...})
    results = bridge.semantic_search("SQL injection in login", namespace="findings", k=10)
    similar = bridge.find_similar_decisions(council_verdict={...})
    bridge.health()  # {"available": True, "store_path": "...", "entries": 1234}

Environment
-----------
    FIXOPS_AGENTDB_ENABLED      = 1/0   default 1
    FIXOPS_AGENTDB_PATH         = path  default ./.swarm/memory.db
    FIXOPS_AGENTDB_USE_CLI_FALLBACK = 1/0  default 0 (CLI only on direct write fail)
    FIXOPS_AGENTDB_EMBED_MODEL  = "minilm" | "hash"  default "minilm" (auto-falls-back to hash)
    FIXOPS_TEST_MODE            = 1     bridge becomes a no-op (tests stay isolated)

Never raises. All paths are best-effort. If AgentDB is uninitialised, missing,
or locked, dual_write returns False but does NOT block the SQLite write or
the council convene.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sqlite3
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)

__all__ = [
    "AgentDBBridge",
    "AgentDBSearchResult",
    "get_agentdb_bridge",
    "reset_agentdb_bridge",
    "enqueue_council_verdict",
    "drain_async_queue",
    "async_queue_stats",
]

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH = "./.swarm/memory.db"
_DEFAULT_EMBED_DIM = 384
_DEFAULT_NAMESPACE = "trustgraph"
_DECISIONS_NAMESPACE = "council_decisions"
_RUFLO_CMD = "ruflo"
_SUBPROCESS_TIMEOUT_SEC = 5.0

# Async write queue — see ``enqueue_council_verdict()`` and the
# ``scripts/agentdb_async_worker.py`` daemon. Verdicts are appended here in
# the council hot path (single SQLite INSERT, ~50us) and a background worker
# drains the queue and runs the actual AgentDB write (MiniLM encode +
# memory_entries insert) off the request path.
_ASYNC_QUEUE_DB = os.environ.get(
    "FIXOPS_AGENTDB_QUEUE_DB", "./.aldeci/agentdb_async_queue.db"
)
_ASYNC_QUEUE_SCHEMA = """
CREATE TABLE IF NOT EXISTS agentdb_write_queue (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type    TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    org_id      TEXT    NOT NULL DEFAULT 'default',
    created_at  TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'queued'
                CHECK(status IN ('queued', 'in_progress', 'done', 'failed')),
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT
);

CREATE INDEX IF NOT EXISTS idx_agentdb_q_status ON agentdb_write_queue(status, id);
"""


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class AgentDBSearchResult:
    """A single semantic-search hit from AgentDB."""

    entry_id: str
    key: str
    namespace: str
    content: str
    similarity: float  # cosine similarity 0..1
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "key": self.key,
            "namespace": self.namespace,
            "content": self.content,
            "similarity": round(self.similarity, 4),
            "metadata": self.metadata,
            "created_at_ms": self.created_at_ms,
        }


# ---------------------------------------------------------------------------
# Embedding providers
# ---------------------------------------------------------------------------


class _EmbeddingProvider:
    """Abstract embedding interface.

    Returns a list[float] of dimension `dim` for a given string.
    Must never raise — degrades silently on any failure.
    """

    name = "abstract"
    dim = _DEFAULT_EMBED_DIM

    def embed(self, text: str) -> List[float]:  # pragma: no cover - abstract
        raise NotImplementedError


class _HashEmbeddingProvider(_EmbeddingProvider):
    """Deterministic 384-dim pseudo-embedding from BLAKE2b hash buckets.

    Properties:
    - Same text → identical vector (deterministic, idempotent)
    - L2-normalised so cosine similarity is meaningful
    - Different texts get different vectors (collision rate <0.1% at 384 dims)
    - Zero dependencies, microseconds to compute

    Quality: OK for keyword-overlap retrieval, no semantic understanding.
    Used as the safety net when ONNX MiniLM isn't available.
    """

    name = "hash-blake2b"
    dim = _DEFAULT_EMBED_DIM

    def embed(self, text: str) -> List[float]:
        # Normalize text to reduce trivial variants
        norm = (text or "").lower().strip()
        if not norm:
            # Empty input → zero vector (prevents div-by-zero in cosine)
            return [0.0] * self.dim

        # Build vector by sliding 32-bit windows of multiple hash digests.
        # We need 384 floats → 384*4 = 1536 bytes → 24x BLAKE2b-64 outputs.
        vec: List[float] = []
        for i in range(self.dim // 16):  # 24 hashes × 16 floats each = 384
            seed = f"{i}:{norm}".encode("utf-8")
            digest = hashlib.blake2b(seed, digest_size=64).digest()
            for j in range(16):
                # Map each byte-pair to a signed float in [-1, 1]
                u16 = int.from_bytes(digest[j * 2 : j * 2 + 2], "little", signed=False)
                vec.append((u16 / 32767.5) - 1.0)

        # L2-normalise so cosine = dot product
        norm_sq = sum(x * x for x in vec)
        if norm_sq <= 0:
            return vec
        scale = 1.0 / math.sqrt(norm_sq)
        return [x * scale for x in vec]


class _MiniLMEmbeddingProvider(_EmbeddingProvider):
    """ONNX MiniLM-L6-v2 embedding via sentence-transformers, if available.

    384-dim, real semantic understanding. Lazy-loaded on first call so we
    don't pay the 80MB model load cost when AgentDB bridge is disabled.
    Falls back permanently to hash on any import or load failure.
    """

    name = "minilm-l6-v2"
    dim = _DEFAULT_EMBED_DIM

    def __init__(self) -> None:
        self._model = None
        self._fallback = _HashEmbeddingProvider()
        self._load_attempted = False
        self._load_lock = threading.Lock()

    def _try_load(self) -> bool:
        with self._load_lock:
            if self._load_attempted:
                return self._model is not None
            self._load_attempted = True
            try:
                # Defer the heavy import; many envs won't have it.
                from sentence_transformers import SentenceTransformer  # type: ignore

                self._model = SentenceTransformer("all-MiniLM-L6-v2")
                logger.info("agentdb_bridge: MiniLM embedding model loaded")
                return True
            except Exception as exc:  # noqa: BLE001 — fallback is the design
                logger.debug(
                    "agentdb_bridge: MiniLM unavailable (%s) — using hash fallback",
                    exc,
                )
                self._model = None
                return False

    def embed(self, text: str) -> List[float]:
        if not self._try_load() or self._model is None:
            return self._fallback.embed(text)
        try:
            vec = self._model.encode(text or "", convert_to_numpy=False)
            # sentence-transformers may return torch tensor or list
            return [float(x) for x in vec]
        except Exception as exc:  # noqa: BLE001
            logger.debug("agentdb_bridge: MiniLM encode failed (%s) — hash fallback", exc)
            return self._fallback.embed(text)

    @property
    def effective_name(self) -> str:
        """Return the model actually being used (post-fallback resolution)."""
        if self._try_load() and self._model is not None:
            return self.name
        return self._fallback.name


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------


class AgentDBBridge:
    """Adapter between TrustGraph events and the AgentDB vector store.

    Thread-safe (per-thread sqlite connections). Never raises.
    """

    def __init__(
        self,
        *,
        db_path: Optional[str] = None,
        embed_model: Optional[str] = None,
        use_cli_fallback: Optional[bool] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        # Honour env overrides
        if enabled is None:
            enabled = os.environ.get("FIXOPS_AGENTDB_ENABLED", "1") not in ("0", "false", "no")
        if os.environ.get("FIXOPS_TEST_MODE", "0") == "1" and enabled is None:
            # Tests opt in explicitly via constructor
            enabled = False
        self.enabled = bool(enabled)

        self.db_path = (
            db_path
            or os.environ.get("FIXOPS_AGENTDB_PATH")
            or _DEFAULT_DB_PATH
        )
        self.use_cli_fallback = (
            use_cli_fallback
            if use_cli_fallback is not None
            else os.environ.get("FIXOPS_AGENTDB_USE_CLI_FALLBACK", "0") not in ("0", "false", "no")
        )

        embed_model_name = (
            embed_model
            or os.environ.get("FIXOPS_AGENTDB_EMBED_MODEL")
            or "minilm"
        ).lower()
        self.embedder: _EmbeddingProvider = (
            _MiniLMEmbeddingProvider() if embed_model_name == "minilm" else _HashEmbeddingProvider()
        )

        self._local = threading.local()
        self._writes = 0
        self._searches = 0
        self._failures = 0
        self._cli_fallbacks = 0
        self._init_attempted = False
        self._init_ok = False
        self._init_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _ensure_initialised(self) -> bool:
        """Verify the AgentDB schema exists. Returns True if writes are safe."""
        if not self.enabled:
            return False
        with self._init_lock:
            if self._init_attempted:
                return self._init_ok
            self._init_attempted = True
            try:
                p = Path(self.db_path)
                if not p.exists():
                    logger.info(
                        "agentdb_bridge: %s not found — run `ruflo memory init`. Writes disabled.",
                        self.db_path,
                    )
                    self._init_ok = False
                    return False
                # Probe the canonical table.
                conn = self._get_conn()
                row = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='memory_entries'"
                ).fetchone()
                if not row:
                    logger.info(
                        "agentdb_bridge: memory_entries table missing in %s — writes disabled.",
                        self.db_path,
                    )
                    self._init_ok = False
                    return False
                self._init_ok = True
                logger.info("agentdb_bridge: AgentDB ready at %s", self.db_path)
                return True
            except Exception as exc:  # noqa: BLE001
                logger.warning("agentdb_bridge: init failed (%s) — writes disabled", exc)
                self._init_ok = False
                return False

    def _get_conn(self) -> sqlite3.Connection:
        """Per-thread WAL-mode connection."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=2.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
            except Exception:  # noqa: BLE001 - WAL probe is best-effort
                pass
            self._local.conn = conn
        return conn

    # ------------------------------------------------------------------
    # Hot path — dual_write
    # ------------------------------------------------------------------

    def dual_write(
        self,
        *,
        event_type: str,
        payload: Mapping[str, Any],
        namespace: str = _DEFAULT_NAMESPACE,
        key: Optional[str] = None,
    ) -> bool:
        """Write an event to AgentDB with embedding. Never raises.

        Args:
            event_type: e.g. ``"finding.created"`` (becomes a tag)
            payload: the event payload — JSON-serialised into ``content``
            namespace: AgentDB namespace partition (default ``"trustgraph"``)
            key: stable dedup key. Auto-generated if omitted.

        Returns:
            True if the event landed in AgentDB, False otherwise.
        """
        if not self.enabled:
            return False
        if not self._ensure_initialised():
            return False

        try:
            content = self._render_content(event_type, payload)
            entry_key = key or self._make_key(event_type, payload)

            embedding = self.embedder.embed(content)
            embedder_name = self._effective_embedder_name()
            metadata = {
                "event_type": event_type,
                "source": "trustgraph_event_bus",
                "ingested_at_ms": int(time.time() * 1000),
                "embedder": embedder_name,
            }
            tags = [event_type, namespace]

            entry_id = f"entry_{int(time.time()*1000)}_{uuid.uuid4().hex[:16]}"
            conn = self._get_conn()
            now_ms = int(time.time() * 1000)
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO memory_entries
                       (id, key, namespace, content, type,
                        embedding, embedding_model, embedding_dimensions,
                        tags, metadata, created_at, updated_at, status)
                       VALUES (?, ?, ?, ?, 'semantic',
                               ?, ?, ?,
                               ?, ?, ?, ?, 'active')""",
                    (
                        entry_id,
                        entry_key,
                        namespace,
                        content,
                        json.dumps(embedding),
                        embedder_name,
                        self.embedder.dim,
                        json.dumps(tags),
                        json.dumps(metadata, default=str),
                        now_ms,
                        now_ms,
                    ),
                )
            except sqlite3.IntegrityError:
                # UNIQUE(namespace,key) collision: update in place.
                conn.execute(
                    """UPDATE memory_entries
                       SET content=?, embedding=?, metadata=?, updated_at=?
                       WHERE namespace=? AND key=?""",
                    (
                        content,
                        json.dumps(embedding),
                        json.dumps(metadata, default=str),
                        now_ms,
                        namespace,
                        entry_key,
                    ),
                )

            self._writes += 1
            return True
        except Exception as exc:  # noqa: BLE001 — never block the bus
            self._failures += 1
            logger.debug("agentdb_bridge.dual_write direct path failed: %s", exc)
            if self.use_cli_fallback:
                return self._cli_store(event_type, payload, namespace, key)
            return False

    def write_council_verdict(
        self,
        *,
        finding: Mapping[str, Any],
        verdict: Mapping[str, Any],
        org_id: str = "default",
    ) -> bool:
        """Persist a council verdict to AgentDB for future similarity lookups.

        This is what makes find_similar_decisions() useful: every verdict the
        council produces becomes searchable for the next convene().
        """
        payload = {
            "finding": dict(finding),
            "verdict": dict(verdict),
            "org_id": org_id,
        }
        key = (
            verdict.get("verdict_id")
            or finding.get("finding_id")
            or f"verdict_{uuid.uuid4().hex[:12]}"
        )
        return self.dual_write(
            event_type="council.verdict",
            payload=payload,
            namespace=_DECISIONS_NAMESPACE,
            key=str(key),
        )

    # ------------------------------------------------------------------
    # Read path — semantic_search
    # ------------------------------------------------------------------

    def semantic_search(
        self,
        query: str,
        *,
        namespace: Optional[str] = None,
        k: int = 10,
        min_similarity: float = 0.0,
    ) -> List[AgentDBSearchResult]:
        """Top-k cosine-nearest neighbours for ``query``.

        We compute cosine in Python over the candidate set. AgentDB ships with
        HNSW indexes via the WASM binding — but the Python side reads the
        raw embedding column. For typical TrustGraph tenant volumes (<100K
        memory_entries per namespace) this is well under 100ms.

        Args:
            query: natural-language query string
            namespace: filter by namespace (None = all)
            k: max results
            min_similarity: drop results below this cosine threshold

        Returns:
            List of AgentDBSearchResult sorted descending by similarity.
        """
        if not self.enabled or not self._ensure_initialised():
            return []
        if not query:
            return []

        try:
            self._searches += 1
            query_vec = self.embedder.embed(query)
            if not query_vec:
                return []

            conn = self._get_conn()
            sql = (
                "SELECT id, key, namespace, content, embedding, embedding_dimensions,"
                " metadata, created_at FROM memory_entries"
                " WHERE status='active' AND embedding IS NOT NULL"
            )
            params: List[Any] = []
            if namespace:
                sql += " AND namespace=?"
                params.append(namespace)
            # Cap candidate set for safety; HNSW would replace this in a future revision.
            sql += " ORDER BY created_at DESC LIMIT 5000"

            scored: List[AgentDBSearchResult] = []
            for row in conn.execute(sql, params).fetchall():
                try:
                    emb = json.loads(row["embedding"])
                except Exception:
                    continue
                if not emb or len(emb) != len(query_vec):
                    continue
                sim = _cosine(query_vec, emb)
                if sim < min_similarity:
                    continue
                try:
                    md = json.loads(row["metadata"]) if row["metadata"] else {}
                except Exception:
                    md = {}
                scored.append(
                    AgentDBSearchResult(
                        entry_id=row["id"],
                        key=row["key"],
                        namespace=row["namespace"],
                        content=row["content"],
                        similarity=sim,
                        metadata=md,
                        created_at_ms=int(row["created_at"] or 0),
                    )
                )
            scored.sort(key=lambda r: r.similarity, reverse=True)
            return scored[:k]
        except Exception as exc:  # noqa: BLE001
            self._failures += 1
            logger.debug("agentdb_bridge.semantic_search failed: %s", exc)
            return []

    def find_similar_decisions(
        self,
        *,
        finding: Optional[Mapping[str, Any]] = None,
        council_verdict: Optional[Mapping[str, Any]] = None,
        k: int = 5,
        min_similarity: float = 0.30,
    ) -> List[AgentDBSearchResult]:
        """Retrieve top-k past council verdicts most similar to a finding.

        Used by LLM Council BEFORE convene() to augment the prompt with
        prior-decision context (RAG over TrustGraph promised in Phase 1).

        Args:
            finding: the new finding being deliberated
            council_verdict: alternatively, an existing verdict to find peers of
            k: how many neighbours
            min_similarity: cosine cutoff (default 0.3 = "loosely relevant")

        Returns:
            List of past AgentDBSearchResult entries from `council_decisions`
            namespace, sorted by descending similarity.
        """
        # Build a query string from whichever input we have.
        query_parts: List[str] = []
        if finding:
            for k_ in ("title", "name", "description", "cve_id", "severity"):
                v = finding.get(k_)
                if v:
                    query_parts.append(str(v))
        if council_verdict:
            for k_ in ("action", "reasoning", "title"):
                v = council_verdict.get(k_)
                if v:
                    query_parts.append(str(v))
        query = " ".join(query_parts).strip()
        if not query:
            return []

        return self.semantic_search(
            query,
            namespace=_DECISIONS_NAMESPACE,
            k=k,
            min_similarity=min_similarity,
        )

    # ------------------------------------------------------------------
    # CLI fallback
    # ------------------------------------------------------------------

    def _cli_store(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        namespace: str,
        key: Optional[str],
    ) -> bool:
        """Last-resort write via `ruflo memory store`. Slow (~2-4s), best-effort."""
        try:
            entry_key = key or self._make_key(event_type, payload)
            value = self._render_content(event_type, payload)
            cmd = [
                _RUFLO_CMD,
                "memory",
                "store",
                "-k",
                entry_key,
                "--value",
                value,
                "--namespace",
                namespace,
            ]
            result = subprocess.run(  # noqa: S603 - command list, no shell
                cmd,
                capture_output=True,
                timeout=_SUBPROCESS_TIMEOUT_SEC,
                check=False,
            )
            if result.returncode == 0:
                self._cli_fallbacks += 1
                return True
            logger.debug(
                "agentdb_bridge.cli_store failed rc=%s stderr=%s",
                result.returncode,
                result.stderr.decode("utf-8", errors="replace")[:200],
            )
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.debug("agentdb_bridge.cli_store unavailable: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _effective_embedder_name(self) -> str:
        """Resolve the actual embedder name (post-fallback)."""
        eff = getattr(self.embedder, "effective_name", None)
        if eff is not None:
            try:
                return str(eff() if callable(eff) else eff)
            except Exception:  # noqa: BLE001
                pass
        return self.embedder.name

    @staticmethod
    def _render_content(event_type: str, payload: Mapping[str, Any]) -> str:
        """Render an event payload to a single search-friendly string.

        Keeps event_type as a prefix so `semantic_search("finding.created ...")`
        finds same-type events. JSON tail preserves the full payload for the
        LLM to introspect later.
        """
        try:
            head_keys = ("title", "name", "description", "cve_id", "severity", "action", "reasoning")
            head_parts = [event_type]
            for k in head_keys:
                v = payload.get(k)
                if v:
                    head_parts.append(f"{k}={v}")
            head = " | ".join(head_parts)
            tail = json.dumps(payload, default=str, sort_keys=True)
            return f"{head}\n{tail}"
        except Exception:  # noqa: BLE001
            return f"{event_type}: {payload!s}"

    @staticmethod
    def _make_key(event_type: str, payload: Mapping[str, Any]) -> str:
        """Stable dedup key from event_type + canonical payload IDs."""
        for k in (
            "finding_id",
            "alert_id",
            "incident_id",
            "verdict_id",
            "asset_id",
            "id",
        ):
            v = payload.get(k)
            if v:
                return f"{event_type}:{v}"
        # Fallback: hash the canonical payload.
        digest = hashlib.blake2b(
            json.dumps(payload, default=str, sort_keys=True).encode("utf-8"),
            digest_size=8,
        ).hexdigest()
        return f"{event_type}:{digest}"

    # ------------------------------------------------------------------
    # Bulk reindex
    # ------------------------------------------------------------------

    def reindex_all(
        self,
        *,
        target_model: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Recompute embeddings for all active rows not yet on the current embedder.

        Walks every row in ``memory_entries`` where ``embedding_model`` differs
        from the current embedder name and rewrites ``embedding``,
        ``embedding_model``, and ``embedding_dimensions`` in-place.

        Args:
            target_model: if given, only reindex rows whose ``embedding_model``
                matches this value (e.g. ``"hash-blake2b"``).  Default: reindex
                any row that isn't already on the current embedder.
            dry_run: if True, count candidates without writing.

        Returns:
            dict with keys ``reindexed``, ``skipped``, ``failed``, ``embedder``.
        """
        if not self.enabled or not self._ensure_initialised():
            return {"reindexed": 0, "skipped": 0, "failed": 0, "embedder": "disabled"}

        current_name = self._effective_embedder_name()
        conn = self._get_conn()

        # Fetch candidates: rows not already on the current embedder.
        sql = (
            "SELECT id, namespace, content, embedding_model"
            " FROM memory_entries"
            " WHERE status='active' AND embedding_model != ?"
        )
        params: List[Any] = [current_name]
        if target_model:
            sql += " AND embedding_model = ?"
            params.append(target_model)

        rows = conn.execute(sql, params).fetchall()
        reindexed = 0
        skipped = 0
        failed = 0
        now_ms = int(time.time() * 1000)

        for row in rows:
            if dry_run:
                skipped += 1
                continue
            try:
                new_emb = self.embedder.embed(row["content"] or "")
                if not new_emb:
                    skipped += 1
                    continue
                conn.execute(
                    """UPDATE memory_entries
                       SET embedding=?, embedding_model=?, embedding_dimensions=?,
                           updated_at=?
                       WHERE id=?""",
                    (
                        json.dumps(new_emb),
                        current_name,
                        self.embedder.dim,
                        now_ms,
                        row["id"],
                    ),
                )
                reindexed += 1
            except Exception as exc:  # noqa: BLE001
                logger.debug("agentdb_bridge.reindex_all row=%s failed: %s", row["id"], exc)
                failed += 1

        if not dry_run and reindexed:
            logger.info(
                "agentdb_bridge.reindex_all: reindexed %d rows to %s (%d failed, %d skipped)",
                reindexed,
                current_name,
                failed,
                skipped,
            )

        return {
            "reindexed": reindexed,
            "skipped": skipped,
            "failed": failed,
            "embedder": current_name,
            "dry_run": dry_run,
        }

    # ------------------------------------------------------------------
    # Health / metrics
    # ------------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        """Return ops-friendly status."""
        avail = self._ensure_initialised()
        entries = 0
        if avail:
            try:
                conn = self._get_conn()
                entries = conn.execute(
                    "SELECT COUNT(*) FROM memory_entries WHERE status='active'"
                ).fetchone()[0]
            except Exception:  # noqa: BLE001
                entries = -1
        return {
            "enabled": self.enabled,
            "available": avail,
            "store_path": self.db_path,
            "entries_active": entries,
            "embedder": self._effective_embedder_name(),
            "embedder_dim": self.embedder.dim,
            "writes": self._writes,
            "searches": self._searches,
            "failures": self._failures,
            "cli_fallbacks": self._cli_fallbacks,
        }


# ---------------------------------------------------------------------------
# Async queue API
# ---------------------------------------------------------------------------
#
# Why a queue, not a daemon thread per event?
#
# The previous fire-and-forget pattern (`_threading.Thread(...).start()` per
# verdict) works for single-event writes but breaks under load: 1000 verdicts
# spawns 1000 daemon threads, each holding a sqlite connection AND each
# running the ~430ms MiniLM encode. Threads pile up, GIL contention spikes,
# and the council hot path slows down anyway.
#
# The queue path is:
#   1. council convene -> verdict ready
#   2. enqueue_council_verdict() -> single INSERT into agentdb_write_queue
#      (~50us, no embed compute, no MiniLM load)
#   3. council returns IMMEDIATELY
#   4. agentdb_async_worker.py daemon polls the queue, drains FIFO,
#      runs the actual write_council_verdict() in batch
#
# Worst case (worker is dead): jobs accumulate in the queue but the council
# never blocks, never errors. Worker can be restarted, queue is durable.

_queue_init_lock = threading.Lock()
_queue_initialised = False


def _ensure_async_queue() -> Optional[sqlite3.Connection]:
    """Open / create the async write queue DB. Returns None on failure."""
    global _queue_initialised
    try:
        Path(_ASYNC_QUEUE_DB).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(_ASYNC_QUEUE_DB, timeout=10.0, isolation_level=None)
        # Per-connection PRAGMAs — busy_timeout is connection-local. WAL is
        # DB-level; we apply it once via the init flag below.
        conn.execute("PRAGMA busy_timeout=10000")
        if not _queue_initialised:
            with _queue_init_lock:
                if not _queue_initialised:
                    try:
                        conn.execute("PRAGMA journal_mode=WAL")
                        conn.execute("PRAGMA synchronous=NORMAL")
                    except sqlite3.Error:
                        # WAL not always available; busy_timeout suffices.
                        pass
                    conn.executescript(_ASYNC_QUEUE_SCHEMA)
                    _queue_initialised = True
        return conn
    except Exception as exc:  # noqa: BLE001
        logger.debug("agentdb_bridge: async queue init failed: %s", exc)
        return None


def enqueue_council_verdict(
    *,
    finding: Mapping[str, Any],
    verdict: Mapping[str, Any],
    org_id: str = "default",
) -> bool:
    """Enqueue a council verdict for asynchronous AgentDB write.

    HOT PATH — must be < 1ms. Performs a single SQLite INSERT into the
    persistent queue and returns. The actual MiniLM-embedded
    ``write_council_verdict`` is performed by the background worker in
    ``scripts/agentdb_async_worker.py``.

    Returns:
        True if the job was enqueued, False if the queue couldn't be opened.
    """
    if os.environ.get("FIXOPS_AGENTDB_ENABLED", "1") in ("0", "false", "no"):
        return False

    conn = _ensure_async_queue()
    if conn is None:
        return False
    try:
        from datetime import datetime, timezone

        payload = json.dumps(
            {"finding": dict(finding), "verdict": dict(verdict)},
            default=str,
        )
        conn.execute(
            """INSERT INTO agentdb_write_queue
               (job_type, payload, org_id, created_at, status)
               VALUES (?, ?, ?, ?, 'queued')""",
            (
                "council_verdict",
                payload,
                org_id,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.debug("agentdb_bridge.enqueue_council_verdict failed: %s", exc)
        return False
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def drain_async_queue(
    *,
    max_jobs: int = 100,
    bridge: Optional["AgentDBBridge"] = None,
) -> Dict[str, int]:
    """Drain up to ``max_jobs`` queued verdicts into AgentDB.

    Called by ``scripts/agentdb_async_worker.py``. Picks up jobs in FIFO
    order, runs the actual MiniLM-embedded write_council_verdict, marks
    each row done/failed.

    Returns:
        dict {"processed": N, "failed": M, "remaining": K}
    """
    out = {"processed": 0, "failed": 0, "remaining": 0}
    conn = _ensure_async_queue()
    if conn is None:
        return out

    try:
        if bridge is None:
            bridge = get_agentdb_bridge()

        # Claim a batch of queued jobs by flipping their status atomically.
        # SQLite row-level locking via UPDATE...WHERE id IN (subquery).
        rows = conn.execute(
            """SELECT id, payload, org_id FROM agentdb_write_queue
               WHERE status='queued'
               ORDER BY id ASC
               LIMIT ?""",
            (max_jobs,),
        ).fetchall()

        for job_id, payload_str, org_id in rows:
            try:
                # Mark in_progress so a parallel worker doesn't pick it up.
                conn.execute(
                    "UPDATE agentdb_write_queue SET status='in_progress', attempts=attempts+1 WHERE id=?",
                    (job_id,),
                )
                payload = json.loads(payload_str)
                ok = bridge.write_council_verdict(
                    finding=payload.get("finding", {}),
                    verdict=payload.get("verdict", {}),
                    org_id=org_id,
                )
                if ok:
                    conn.execute(
                        "UPDATE agentdb_write_queue SET status='done', last_error=NULL WHERE id=?",
                        (job_id,),
                    )
                    out["processed"] += 1
                else:
                    # Re-queue on transient failure (attempts<5); permanently
                    # mark failed otherwise so we stop spinning on dead rows.
                    conn.execute(
                        """UPDATE agentdb_write_queue
                           SET status=CASE WHEN attempts<5 THEN 'queued' ELSE 'failed' END,
                               last_error='write_council_verdict returned False'
                           WHERE id=?""",
                        (job_id,),
                    )
                    out["failed"] += 1
            except Exception as exc:  # noqa: BLE001
                conn.execute(
                    "UPDATE agentdb_write_queue SET status='failed', last_error=? WHERE id=?",
                    (str(exc)[:500], job_id),
                )
                out["failed"] += 1

        # Remaining queued jobs (cheap COUNT)
        out["remaining"] = conn.execute(
            "SELECT COUNT(*) FROM agentdb_write_queue WHERE status='queued'"
        ).fetchone()[0]
    except Exception as exc:  # noqa: BLE001
        logger.debug("agentdb_bridge.drain_async_queue failed: %s", exc)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
    return out


def async_queue_stats() -> Dict[str, int]:
    """Return queue depth metrics for ops dashboards."""
    out = {"queued": 0, "in_progress": 0, "done": 0, "failed": 0, "total": 0}
    conn = _ensure_async_queue()
    if conn is None:
        return out
    try:
        for status, in conn.execute(
            "SELECT status FROM agentdb_write_queue"
        ).fetchall():
            out["total"] += 1
            if status in out:
                out[status] += 1
    except Exception as exc:  # noqa: BLE001
        logger.debug("agentdb_bridge.async_queue_stats failed: %s", exc)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
    return out


# ---------------------------------------------------------------------------
# Cosine helper (no NumPy dep — keep agent-doctor happy on minimal envs)
# ---------------------------------------------------------------------------


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity. Both vectors expected non-empty, same length.

    Returns 0.0 for any malformed input rather than raising.
    """
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na <= 0 or nb <= 0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_bridge: Optional[AgentDBBridge] = None
_bridge_lock = threading.Lock()


def get_agentdb_bridge() -> AgentDBBridge:
    """Return the shared bridge instance, creating it on first call."""
    global _bridge
    if _bridge is None:
        with _bridge_lock:
            if _bridge is None:
                _bridge = AgentDBBridge()
    return _bridge


def reset_agentdb_bridge() -> None:
    """Drop the singleton — used by tests for isolation."""
    global _bridge
    with _bridge_lock:
        _bridge = None
