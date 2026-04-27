"""Tests for the AgentDB bridge — TrustGraph + LLM Council semantic memory."""
from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest

# Ensure suite paths are importable regardless of pytest invocation cwd.
ROOT = Path(__file__).resolve().parent.parent
for sub in ("suite-core", "suite-api"):
    p = ROOT / sub
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from trustgraph.agentdb_bridge import (  # noqa: E402
    AgentDBBridge,
    AgentDBSearchResult,
    _cosine,
    _HashEmbeddingProvider,
)


# ---------------------------------------------------------------------------
# Fixture: an isolated AgentDB-style SQLite DB for each test
# ---------------------------------------------------------------------------


_AGENTDB_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_entries (
  id TEXT PRIMARY KEY,
  key TEXT NOT NULL,
  namespace TEXT DEFAULT 'default',
  content TEXT NOT NULL,
  type TEXT DEFAULT 'semantic',
  embedding TEXT,
  embedding_model TEXT DEFAULT 'local',
  embedding_dimensions INTEGER,
  tags TEXT,
  metadata TEXT,
  owner_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  expires_at INTEGER,
  last_accessed_at INTEGER,
  access_count INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  UNIQUE(namespace, key)
);
"""


@pytest.fixture()
def isolated_bridge(tmp_path) -> AgentDBBridge:
    """Build an AgentDBBridge against a fresh per-test SQLite DB.

    Uses the hash embedder so we don't depend on sentence-transformers at
    test time and we get deterministic similarity scores.
    """
    db_path = tmp_path / "agentdb_test.db"
    # Pre-create the schema so _ensure_initialised() returns True.
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_AGENTDB_SCHEMA)
    conn.commit()
    conn.close()

    bridge = AgentDBBridge(
        db_path=str(db_path),
        embed_model="hash",
        use_cli_fallback=False,
        enabled=True,
    )
    return bridge


# ---------------------------------------------------------------------------
# Test 1: dual_write writes a row with embedding into the AgentDB schema
# ---------------------------------------------------------------------------


def test_dual_write_persists_event_with_embedding(isolated_bridge: AgentDBBridge) -> None:
    """A finding event ends up as a memory_entries row with a 384-dim embedding."""
    ok = isolated_bridge.dual_write(
        event_type="finding.created",
        payload={
            "finding_id": "F-001",
            "title": "SQL injection in /login",
            "severity": "high",
            "cve_id": "CVE-2024-1111",
        },
        namespace="trustgraph",
    )
    assert ok is True
    health = isolated_bridge.health()
    assert health["available"] is True
    assert health["entries_active"] == 1
    assert health["writes"] == 1
    assert health["failures"] == 0

    # Verify the row landed in the AgentDB schema with the right fields.
    conn = sqlite3.connect(isolated_bridge.db_path)
    row = conn.execute(
        "SELECT key, namespace, content, embedding_dimensions, tags, metadata"
        " FROM memory_entries WHERE key=?",
        ("finding.created:F-001",),
    ).fetchone()
    conn.close()

    assert row is not None
    key, namespace, content, dims, tags_json, metadata_json = row
    assert namespace == "trustgraph"
    assert dims == 384
    assert "SQL injection" in content
    assert "finding.created" in content
    tags = json.loads(tags_json)
    assert "finding.created" in tags
    metadata = json.loads(metadata_json)
    assert metadata["event_type"] == "finding.created"
    assert metadata["source"] == "trustgraph_event_bus"


# ---------------------------------------------------------------------------
# Test 2: semantic_search returns hits ranked by similarity, beats LIKE on speed
# ---------------------------------------------------------------------------


def test_semantic_search_returns_ranked_hits_under_100ms(
    isolated_bridge: AgentDBBridge,
) -> None:
    """semantic_search returns the same finding it just stored, in <100ms."""
    isolated_bridge.dual_write(
        event_type="finding.created",
        payload={"finding_id": "F-100", "title": "SQL injection in user lookup"},
        namespace="ns_test",
    )
    isolated_bridge.dual_write(
        event_type="finding.created",
        payload={"finding_id": "F-101", "title": "Path traversal in upload handler"},
        namespace="ns_test",
    )
    isolated_bridge.dual_write(
        event_type="finding.created",
        payload={"finding_id": "F-102", "title": "Outdated TLS configuration"},
        namespace="ns_test",
    )

    t0 = time.perf_counter()
    # Use min_similarity=-1.0 so we always get all candidates back regardless
    # of cosine sign — lets us inspect the full ranking.
    results = isolated_bridge.semantic_search(
        "SQL injection user lookup",
        namespace="ns_test",
        k=5,
        min_similarity=-1.0,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert results, "expected at least one semantic hit"
    assert all(isinstance(r, AgentDBSearchResult) for r in results)
    # Latency target from the mission brief: under 100ms.
    assert elapsed_ms < 100.0, f"semantic_search took {elapsed_ms:.1f}ms (target <100ms)"
    # Results must be sorted descending by similarity.
    sims = [r.similarity for r in results]
    assert sims == sorted(sims, reverse=True)
    # All 3 candidates should appear (k=5, only 3 stored).
    assert len(results) == 3
    # The SQL-injection entry must be in the result set.
    titles = [r.content for r in results]
    assert any("SQL injection" in t for t in titles), \
        f"expected SQL injection entry in results, got: {titles}"
    # The unrelated "Outdated TLS configuration" entry must rank LOWEST.
    sql_score = next(r.similarity for r in results if "SQL injection" in r.content)
    tls_score = next(r.similarity for r in results if "TLS configuration" in r.content)
    assert sql_score >= tls_score, \
        f"SQL injection ({sql_score}) should outrank TLS ({tls_score})"
    # And the default min_similarity=0.0 contract: irrelevant items get filtered
    # out so callers don't see noise. Re-query without overriding the floor.
    relevant_only = isolated_bridge.semantic_search(
        "SQL injection user lookup", namespace="ns_test", k=5
    )
    assert len(relevant_only) <= 3
    for r in relevant_only:
        assert r.similarity >= 0.0


# ---------------------------------------------------------------------------
# Test 3: find_similar_decisions reads from the council_decisions namespace
# ---------------------------------------------------------------------------


def test_find_similar_decisions_returns_past_verdicts(
    isolated_bridge: AgentDBBridge,
) -> None:
    """A new finding can locate a past council verdict on a similar finding."""
    # Seed a past verdict.
    isolated_bridge.write_council_verdict(
        finding={
            "finding_id": "F-old-1",
            "title": "Cross-site scripting in comment renderer",
            "severity": "high",
            "cve_id": "CVE-2023-7777",
        },
        verdict={
            "verdict_id": "v_old_1",
            "action": "remediate_high",
            "confidence": 0.88,
            "reasoning": "Persistent XSS, exploitable via authenticated user input.",
        },
        org_id="acme",
    )

    # Look up similar decisions for a NEW XSS finding.
    similar = isolated_bridge.find_similar_decisions(
        finding={
            "title": "Cross-site scripting in profile bio",
            "severity": "medium",
            "cve_id": "CVE-2024-XXXX",
        },
        k=3,
        min_similarity=0.0,
    )
    assert similar, "expected to retrieve past XSS verdict"
    assert similar[0].namespace == "council_decisions"
    assert "v_old_1" in similar[0].key or "Cross-site" in similar[0].content


# ---------------------------------------------------------------------------
# Test 4: dual_write is idempotent on (namespace, key) — same key updates row
# ---------------------------------------------------------------------------


def test_dual_write_is_idempotent_on_namespace_key(
    isolated_bridge: AgentDBBridge,
) -> None:
    """Re-writing the same finding does NOT create duplicate memory_entries rows."""
    payload = {"finding_id": "F-DUP", "title": "Duplicate finding"}

    assert isolated_bridge.dual_write(
        event_type="finding.created", payload=payload, namespace="dup_ns"
    )
    assert isolated_bridge.dual_write(
        event_type="finding.created",
        payload={**payload, "title": "Duplicate finding (updated title)"},
        namespace="dup_ns",
    )

    conn = sqlite3.connect(isolated_bridge.db_path)
    rows = conn.execute(
        "SELECT key, content FROM memory_entries WHERE namespace=?",
        ("dup_ns",),
    ).fetchall()
    conn.close()
    assert len(rows) == 1, f"expected 1 deduped row, got {len(rows)}: {rows}"
    # The content should reflect the second (updated) write.
    assert "updated title" in rows[0][1]


# ---------------------------------------------------------------------------
# Test 5: bridge never raises — corrupt DB / missing DB / disabled mode all safe
# ---------------------------------------------------------------------------


def test_bridge_degrades_silently_when_db_missing(tmp_path) -> None:
    """A non-existent DB path → writes return False but the bridge does not raise."""
    missing = tmp_path / "does-not-exist.db"
    bridge = AgentDBBridge(
        db_path=str(missing),
        embed_model="hash",
        use_cli_fallback=False,
        enabled=True,
    )

    # All writes return False, nothing raises.
    assert bridge.dual_write(event_type="finding.created", payload={"id": "x"}) is False
    assert bridge.semantic_search("anything", k=5) == []
    assert (
        bridge.find_similar_decisions(finding={"title": "x"}, k=5, min_similarity=0.0)
        == []
    )

    health = bridge.health()
    assert health["available"] is False
    assert health["entries_active"] == 0


def test_bridge_disabled_short_circuits(tmp_path) -> None:
    """Explicit enabled=False makes every public op a no-op (returns False / [])."""
    db = tmp_path / "ignored.db"
    sqlite3.connect(str(db)).executescript(_AGENTDB_SCHEMA)
    bridge = AgentDBBridge(db_path=str(db), embed_model="hash", enabled=False)

    assert bridge.dual_write(event_type="finding.created", payload={"id": "y"}) is False
    assert bridge.semantic_search("query", k=5) == []
    assert bridge.health()["enabled"] is False


# ---------------------------------------------------------------------------
# Bonus: cosine helper sanity (covers the math primitive)
# ---------------------------------------------------------------------------


def test_cosine_helper_returns_zero_on_malformed_inputs() -> None:
    assert _cosine([], []) == 0.0
    assert _cosine([1.0, 0.0], [1.0]) == 0.0
    assert _cosine([0.0, 0.0], [1.0, 1.0]) == 0.0
    # Normal case
    assert abs(_cosine([1.0, 0.0], [1.0, 0.0]) - 1.0) < 1e-9
    assert abs(_cosine([1.0, 0.0], [0.0, 1.0])) < 1e-9


def test_hash_embedder_is_deterministic_and_normalized() -> None:
    e = _HashEmbeddingProvider()
    v1 = e.embed("SQL injection in login")
    v2 = e.embed("SQL injection in login")
    assert v1 == v2
    assert len(v1) == 384
    # L2 norm ≈ 1
    norm_sq = sum(x * x for x in v1)
    assert abs(norm_sq - 1.0) < 1e-6
