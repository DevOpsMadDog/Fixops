"""
Fuzzy Asset Identity Resolver — Step 3 of the ALdeci Brain Data Flow.

Resolves "payments-api-prod" == "payments_prod_api" == "PaymentsAPI-Production"
using multi-strategy matching:
  1. Exact match (canonical lookup)
  2. Levenshtein edit-distance
  3. Token-based (split on delimiters, compare token sets)
  4. Phonetic normalization (soundex-like)
  5. Abbreviation expansion ("prod" → "production", "svc" → "service")

Thread-safe, singleton, SQLite-persisted alias registry.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Common abbreviation expansions for infra/devops naming
# ---------------------------------------------------------------------------
ABBREVIATIONS: Dict[str, str] = {
    "prod": "production", "stg": "staging", "dev": "development",
    "svc": "service", "srv": "service", "api": "api", "fe": "frontend",
    "be": "backend", "db": "database", "k8s": "kubernetes", "eks": "kubernetes",
    "aks": "kubernetes", "gke": "kubernetes", "lb": "loadbalancer",
    "elb": "loadbalancer", "alb": "loadbalancer", "nlb": "loadbalancer",
    "rds": "database", "ec2": "compute", "vm": "compute", "fn": "function",
    "lambda": "function", "gw": "gateway", "agw": "gateway",
    "app": "application", "auth": "authentication", "authn": "authentication",
    "authz": "authorization", "cfg": "config", "conf": "config",
    "mgmt": "management", "mgt": "management", "mon": "monitoring",
    "obs": "observability", "sec": "security", "vuln": "vulnerability",
    "repo": "repository", "img": "image", "reg": "registry",
    "ns": "namespace", "env": "environment", "cls": "cluster",
    "wkr": "worker", "wrk": "worker", "msg": "message", "mq": "messagequeue",
    "sqs": "messagequeue", "sns": "notification", "cdn": "contentdelivery",
    "cf": "contentdelivery", "s3": "objectstorage", "gcs": "objectstorage",
    "az": "azure", "aws": "aws", "gcp": "gcp",
}

# Delimiters for token splitting
_DELIM_RE = re.compile(r"[-_./:\\+\s]+")
# CamelCase splitter
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


class MatchStrategy(str, Enum):
    EXACT = "exact"
    LEVENSHTEIN = "levenshtein"
    TOKEN_SET = "token_set"
    ABBREVIATION = "abbreviation"
    ALIAS = "alias"


@dataclass
class MatchResult:
    """Result of a fuzzy identity match."""
    canonical_id: str
    matched_name: str
    confidence: float  # 0.0 – 1.0
    strategy: MatchStrategy
    details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pure functions — Levenshtein & tokenization
# ---------------------------------------------------------------------------

def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            ins = prev_row[j + 1] + 1
            dele = curr_row[j] + 1
            sub = prev_row[j] + (0 if c1 == c2 else 1)
            curr_row.append(min(ins, dele, sub))
        prev_row = curr_row
    return prev_row[-1]


def levenshtein_similarity(s1: str, s2: str) -> float:
    """Normalized Levenshtein similarity (0.0 – 1.0)."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    return 1.0 - levenshtein_distance(s1, s2) / max_len


@lru_cache(maxsize=4096)
def tokenize(name: str) -> Tuple[str, ...]:
    """Split an asset name into normalized tokens."""
    # CamelCase → space-separated
    spaced = _CAMEL_RE.sub(" ", name)
    # Split on delimiters
    raw_tokens = _DELIM_RE.split(spaced.strip().lower())
    return tuple(t for t in raw_tokens if t)


def expand_tokens(tokens: Tuple[str, ...]) -> Tuple[str, ...]:
    """Expand abbreviations in token list."""
    return tuple(ABBREVIATIONS.get(t, t) for t in tokens)


def _fuzzy_token_match(t1: str, t2: str, threshold: float = 0.80) -> bool:
    """Check if two individual tokens are fuzzy-equal (handles plurals, typos)."""
    if t1 == t2:
        return True
    # Simple stemming: strip common suffixes for comparison
    stems = []
    for t in (t1, t2):
        for suffix in ("tion", "ing", "ed", "es", "s"):
            if t.endswith(suffix) and len(t) > len(suffix) + 2:
                stems.append(t[: -len(suffix)])
                break
        else:
            stems.append(t)
    if stems[0] == stems[1]:
        return True
    # Levenshtein on short tokens
    return levenshtein_similarity(t1, t2) >= threshold


def token_set_similarity(tokens_a: Tuple[str, ...], tokens_b: Tuple[str, ...]) -> float:
    """Fuzzy Jaccard similarity on token sets — handles plurals & near-matches."""
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    # Build fuzzy match pairs (greedy best-first)
    matched_a: Set[int] = set()
    matched_b: Set[int] = set()
    pairs: list = []
    for i, ta in enumerate(tokens_a):
        best_j, best_sim = -1, 0.0
        for j, tb in enumerate(tokens_b):
            if j in matched_b:
                continue
            sim = levenshtein_similarity(ta, tb)
            if sim > best_sim:
                best_sim = sim
                best_j = j
        if best_j >= 0 and _fuzzy_token_match(ta, tokens_b[best_j]):
            matched_a.add(i)
            matched_b.add(best_j)
            pairs.append((i, best_j, best_sim))
    fuzzy_intersection = len(pairs)
    total_unique = len(set(tokens_a) | set(tokens_b))
    # Fuzzy Jaccard: matched pairs / total unique tokens
    jaccard = fuzzy_intersection / max(total_unique, 1)
    # Ordering bonus — reward same relative order of matched tokens
    if len(pairs) >= 2:
        a_order = sorted(pairs, key=lambda p: p[0])
        b_order_vals = [p[1] for p in a_order]
        if b_order_vals == sorted(b_order_vals):
            jaccard = min(jaccard + 0.1, 1.0)
    # Coverage bonus — if one set fully covered, boost
    coverage_a = len(matched_a) / len(tokens_a)
    coverage_b = len(matched_b) / len(tokens_b)
    min_coverage = min(coverage_a, coverage_b)
    if min_coverage >= 0.9:
        jaccard = min(jaccard + 0.15, 1.0)
    return jaccard


def compute_match_score(name_a: str, name_b: str) -> Tuple[float, MatchStrategy]:
    """Compute best match score between two asset names across all strategies."""
    la, lb = name_a.lower(), name_b.lower()
    # 1. Exact
    if la == lb:
        return 1.0, MatchStrategy.EXACT
    # 2. Token-set with abbreviation expansion
    tok_a = tokenize(name_a)
    tok_b = tokenize(name_b)
    exp_a = expand_tokens(tok_a)
    exp_b = expand_tokens(tok_b)
    ts_raw = token_set_similarity(tok_a, tok_b)
    ts_exp = token_set_similarity(exp_a, exp_b)
    best_ts = max(ts_raw, ts_exp)
    strategy = MatchStrategy.ABBREVIATION if ts_exp > ts_raw else MatchStrategy.TOKEN_SET
    # 3. Levenshtein on normalized (no-delim) form
    norm_a = "".join(tok_a)
    norm_b = "".join(tok_b)
    lev = levenshtein_similarity(norm_a, norm_b)
    if lev > best_ts:
        best_ts = lev
        strategy = MatchStrategy.LEVENSHTEIN
    return best_ts, strategy


# ---------------------------------------------------------------------------
# FuzzyIdentityResolver — the main class
# ---------------------------------------------------------------------------

class FuzzyIdentityResolver:
    """
    Production-grade fuzzy asset identity resolver with SQLite-backed alias registry.

    Usage:
        resolver = FuzzyIdentityResolver.get_instance()
        resolver.register_canonical("payments-api", org_id="org_123")
        resolver.add_alias("payments-api", "payments_prod_api")
        resolver.add_alias("payments-api", "PaymentsAPI-Production")

        match = resolver.resolve("payment-api-prod", org_id="org_123")
        # → MatchResult(canonical_id="payments-api", confidence=0.87, ...)
    """

    _instance: Optional["FuzzyIdentityResolver"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: str = "fixops_identity.db") -> None:
        self.db_path = db_path
        self._conn_lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        # In-memory index for fast matching
        self._canonical_names: Dict[str, Set[str]] = {}  # canonical → {aliases}
        self._org_index: Dict[str, Set[str]] = {}  # org_id → {canonicals}
        self._load_index()
        logger.info(
            "FuzzyIdentityResolver initialized: %d canonical assets, db=%s",
            len(self._canonical_names), db_path,
        )

    @classmethod
    def get_instance(cls, db_path: str = "fixops_identity.db") -> "FuzzyIdentityResolver":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(db_path=db_path)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._lock:
            if cls._instance is not None:
                cls._instance.close()
                cls._instance = None

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def _create_tables(self) -> None:
        with self._conn_lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS canonical_assets (
                    canonical_id TEXT PRIMARY KEY,
                    org_id       TEXT,
                    properties   TEXT NOT NULL DEFAULT '{}',
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_canon_org ON canonical_assets(org_id);

                CREATE TABLE IF NOT EXISTS asset_aliases (
                    alias_name    TEXT NOT NULL,
                    canonical_id  TEXT NOT NULL REFERENCES canonical_assets(canonical_id),
                    source        TEXT NOT NULL DEFAULT 'manual',
                    confidence    REAL NOT NULL DEFAULT 1.0,
                    created_at    TEXT NOT NULL,
                    PRIMARY KEY (alias_name, canonical_id)
                );
                CREATE INDEX IF NOT EXISTS idx_alias_canon ON asset_aliases(canonical_id);

                CREATE TABLE IF NOT EXISTS resolution_log (
                    log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    input_name  TEXT NOT NULL,
                    resolved_to TEXT,
                    confidence  REAL,
                    strategy    TEXT,
                    org_id      TEXT,
                    created_at  TEXT NOT NULL
                );
            """)

    def _load_index(self) -> None:
        """Load canonical names and aliases into memory for fast matching."""
        with self._conn_lock:
            cursor = self._conn.execute("SELECT canonical_id, org_id FROM canonical_assets")
            for row in cursor:
                cid, org_id = row
                self._canonical_names.setdefault(cid, set())
                if org_id:
                    self._org_index.setdefault(org_id, set()).add(cid)
            cursor = self._conn.execute("SELECT alias_name, canonical_id FROM asset_aliases")
            for row in cursor:
                alias, cid = row
                self._canonical_names.setdefault(cid, set()).add(alias)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def register_canonical(
        self, canonical_id: str, org_id: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Register a canonical asset identity."""
        now = datetime.now(timezone.utc).isoformat()
        props_json = json.dumps(properties or {}, default=str)
        with self._conn_lock:
            self._conn.execute(
                """INSERT INTO canonical_assets (canonical_id, org_id, properties, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(canonical_id) DO UPDATE SET
                       org_id=excluded.org_id, properties=excluded.properties, updated_at=excluded.updated_at""",
                (canonical_id, org_id, props_json, now, now),
            )
            self._conn.commit()
        self._canonical_names.setdefault(canonical_id, set())
        if org_id:
            self._org_index.setdefault(org_id, set()).add(canonical_id)
        return canonical_id

    def add_alias(
        self, canonical_id: str, alias_name: str,
        source: str = "manual", confidence: float = 1.0,
    ) -> None:
        """Add an alias for a canonical asset."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn_lock:
            self._conn.execute(
                """INSERT INTO asset_aliases (alias_name, canonical_id, source, confidence, created_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(alias_name, canonical_id) DO UPDATE SET
                       confidence=excluded.confidence, source=excluded.source""",
                (alias_name.lower(), canonical_id, source, confidence, now),
            )
            self._conn.commit()
        self._canonical_names.setdefault(canonical_id, set()).add(alias_name.lower())

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------
    def resolve(
        self, name: str, org_id: Optional[str] = None,
        threshold: float = 0.65, top_k: int = 5,
    ) -> Optional[MatchResult]:
        """Resolve an asset name to its canonical identity.

        Returns the best match above the threshold, or None.
        """
        candidates = self._get_candidates(org_id)
        if not candidates:
            return None

        best: Optional[MatchResult] = None
        name_lower = name.lower()

        for canonical_id, aliases in candidates.items():
            # Check canonical name itself
            score, strategy = compute_match_score(name_lower, canonical_id)
            if score > (best.confidence if best else threshold - 0.01):
                if score >= threshold:
                    best = MatchResult(
                        canonical_id=canonical_id, matched_name=canonical_id,
                        confidence=score, strategy=strategy,
                    )

            # Check all aliases
            for alias in aliases:
                if alias == name_lower:
                    # Exact alias match
                    self._log_resolution(name, canonical_id, 1.0, MatchStrategy.ALIAS, org_id)
                    return MatchResult(
                        canonical_id=canonical_id, matched_name=alias,
                        confidence=1.0, strategy=MatchStrategy.ALIAS,
                    )
                score, strategy = compute_match_score(name_lower, alias)
                if score >= threshold and (best is None or score > best.confidence):
                    best = MatchResult(
                        canonical_id=canonical_id, matched_name=alias,
                        confidence=score, strategy=strategy,
                    )

        if best:
            self._log_resolution(name, best.canonical_id, best.confidence, best.strategy, org_id)
            # Auto-learn: if high confidence, register as alias
            if best.confidence >= 0.85 and best.strategy != MatchStrategy.ALIAS:
                self.add_alias(best.canonical_id, name, source="auto_learned", confidence=best.confidence)
        return best

    def resolve_batch(
        self, names: List[str], org_id: Optional[str] = None,
        threshold: float = 0.65,
    ) -> Dict[str, Optional[MatchResult]]:
        """Resolve a batch of asset names."""
        return {name: self.resolve(name, org_id=org_id, threshold=threshold) for name in names}

    def find_similar(
        self, name: str, org_id: Optional[str] = None,
        threshold: float = 0.5, top_k: int = 10,
    ) -> List[MatchResult]:
        """Find all similar canonical assets above threshold."""
        candidates = self._get_candidates(org_id)
        results: List[MatchResult] = []
        name_lower = name.lower()

        for canonical_id, aliases in candidates.items():
            best_score = 0.0
            best_strategy = MatchStrategy.TOKEN_SET
            best_matched = canonical_id

            score, strategy = compute_match_score(name_lower, canonical_id)
            if score > best_score:
                best_score, best_strategy, best_matched = score, strategy, canonical_id

            for alias in aliases:
                score, strategy = compute_match_score(name_lower, alias)
                if score > best_score:
                    best_score, best_strategy, best_matched = score, strategy, alias

            if best_score >= threshold:
                results.append(MatchResult(
                    canonical_id=canonical_id, matched_name=best_matched,
                    confidence=best_score, strategy=best_strategy,
                ))

        results.sort(key=lambda r: r.confidence, reverse=True)
        return results[:top_k]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _get_candidates(self, org_id: Optional[str]) -> Dict[str, Set[str]]:
        """Get candidate canonical assets, optionally filtered by org."""
        if org_id and org_id in self._org_index:
            return {cid: self._canonical_names.get(cid, set())
                    for cid in self._org_index[org_id]}
        return dict(self._canonical_names)

    def _log_resolution(
        self, input_name: str, resolved_to: Optional[str],
        confidence: float, strategy: MatchStrategy, org_id: Optional[str],
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._conn_lock:
                self._conn.execute(
                    "INSERT INTO resolution_log (input_name, resolved_to, confidence, strategy, org_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (input_name, resolved_to, confidence, strategy.value, org_id, now),
                )
                self._conn.commit()
        except Exception:
            pass  # Don't fail resolution on logging error

    def get_resolution_stats(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """Get resolution statistics."""
        with self._conn_lock:
            where = "WHERE org_id = ?" if org_id else ""
            params: list = [org_id] if org_id else []
            total = self._conn.execute(f"SELECT COUNT(*) FROM resolution_log {where}", params).fetchone()[0]
            resolved = self._conn.execute(
                f"SELECT COUNT(*) FROM resolution_log {where} {'AND' if org_id else 'WHERE'} resolved_to IS NOT NULL",
                params,
            ).fetchone()[0]
            by_strategy = {}
            cursor = self._conn.execute(
                f"SELECT strategy, COUNT(*) FROM resolution_log {where} GROUP BY strategy", params
            )
            for row in cursor:
                by_strategy[row[0]] = row[1]
        return {
            "total_resolutions": total,
            "successful": resolved,
            "resolution_rate": round(resolved / total, 4) if total else 0,
            "by_strategy": by_strategy,
            "canonical_assets": len(self._canonical_names),
            "total_aliases": sum(len(a) for a in self._canonical_names.values()),
        }

    def list_canonical(self, org_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """List canonical assets."""
        with self._conn_lock:
            if org_id:
                cursor = self._conn.execute(
                    "SELECT canonical_id, org_id, properties, created_at FROM canonical_assets WHERE org_id = ? LIMIT ?",
                    (org_id, limit),
                )
            else:
                cursor = self._conn.execute(
                    "SELECT canonical_id, org_id, properties, created_at FROM canonical_assets LIMIT ?",
                    (limit,),
                )
            return [
                {"canonical_id": r[0], "org_id": r[1], "properties": json.loads(r[2]),
                 "created_at": r[3], "aliases": list(self._canonical_names.get(r[0], set()))}
                for r in cursor
            ]

    def close(self) -> None:
        with self._conn_lock:
            self._conn.close()


def get_fuzzy_resolver(db_path: str = "fixops_identity.db") -> FuzzyIdentityResolver:
    """Get the global FuzzyIdentityResolver instance."""
    return FuzzyIdentityResolver.get_instance(db_path=db_path)

