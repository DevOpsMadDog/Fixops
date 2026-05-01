"""
Tests for KnowledgeBrainAdapter — fallback store wiring for TrustGraphBackbone.

Goal: TrustGraphBackbone must NEVER silently no-op. When the external
``trustgraph.knowledge_store`` package is unavailable, the backbone falls
back to ``KnowledgeBrainAdapter`` which wraps the in-tree ``KnowledgeBrain``.

These tests verify:
1. Import-failure path resolves to KnowledgeBrainAdapter (not None).
2. ``ingest()`` writes a real node to the underlying SQLite KnowledgeBrain.
3. ``add_relationship()`` writes a real edge to the underlying KnowledgeBrain.
4. After ``_init_store()`` the backbone is always available — never no-op.
"""

from __future__ import annotations

import builtins
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def temp_db():
    """Per-test SQLite path so KnowledgeBrain instances don't collide."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    for suffix in ("", "-wal", "-shm"):
        Path(db_path + suffix).unlink(missing_ok=True)


@pytest.fixture
def force_external_unavailable():
    """Force ``from trustgraph.knowledge_store import KnowledgeStore`` to raise.

    The external trustgraph package is not installed in this repo, so the
    import already fails — but we patch ``__import__`` defensively so the
    test stays correct even if the package is later added to requirements.
    """
    real_import = builtins.__import__

    def _blocking_import(name, *args, **kwargs):
        if name == "trustgraph.knowledge_store" or name.startswith("trustgraph."):
            raise ImportError(f"forced for test: {name}")
        return real_import(name, *args, **kwargs)

    # Also evict anything already cached so the patched import path is hit.
    for mod in list(sys.modules):
        if mod.startswith("trustgraph"):
            sys.modules.pop(mod, None)

    with patch.object(builtins, "__import__", _blocking_import):
        yield


def test_external_trustgraph_unavailable_uses_kb_adapter(force_external_unavailable, temp_db):
    """When external trustgraph fails to import, the store must be a
    KnowledgeBrainAdapter — not None, not silent no-op."""
    from core.trustgraph_backbone import KnowledgeBrainAdapter, TrustGraphBackbone

    backbone = TrustGraphBackbone(db_path=temp_db, org_id="test_kb_adapter")

    assert backbone._store is not None, "store must NOT be None — silent no-op forbidden"
    assert backbone._available is True, "_available must be True after fallback wire-in"
    assert isinstance(backbone._store, KnowledgeBrainAdapter), (
        f"expected KnowledgeBrainAdapter, got {type(backbone._store).__name__}"
    )


def test_adapter_ingest_writes_to_kb(force_external_unavailable, temp_db):
    """index_finding must persist a node row to the underlying SQLite KB."""
    from core.trustgraph_backbone import TrustGraphBackbone

    backbone = TrustGraphBackbone(db_path=temp_db, org_id="ingest_org")
    entity_id = backbone.index_finding({
        "id": "kb_adapter_test_001",
        "title": "Test SQLi finding",
        "severity": "high",
        "cve_id": "CVE-2024-9999",
        "scanner": "pytest",
    })

    assert entity_id == "finding_kb_adapter_test_001"

    # Read directly from the underlying SQLite — bypassing the adapter — to
    # prove the write actually hit disk and was not just kept in memory.
    conn = sqlite3.connect(temp_db)
    try:
        row = conn.execute(
            "SELECT node_id, node_type, org_id FROM brain_nodes WHERE node_id = ?",
            (entity_id,),
        ).fetchone()
    finally:
        conn.close()

    assert row is not None, f"node {entity_id} missing from brain_nodes table"
    assert row[0] == entity_id
    # node_type is the raw string when EntityType enum has no matching value;
    # 'finding' is a real EntityType so it should resolve cleanly.
    assert row[1] in {"finding", "Finding"}
    assert row[2] == "ingest_org"


def test_adapter_add_relationship_writes_to_kb(force_external_unavailable, temp_db):
    """index_finding with cve_id + asset_id must create FINDING_EXPLOITS_CVE
    and FINDING_AFFECTS_ASSET edges in the underlying SQLite KB."""
    from core.trustgraph_backbone import TrustGraphBackbone

    backbone = TrustGraphBackbone(db_path=temp_db, org_id="rel_org")
    backbone.index_finding({
        "id": "rel_test_001",
        "title": "Cross-linked finding",
        "severity": "critical",
        "cve_id": "CVE-2024-1111",
        "asset_id": "prod_db",
    })

    conn = sqlite3.connect(temp_db)
    try:
        edges = conn.execute(
            "SELECT source_id, target_id, edge_type FROM brain_edges WHERE source_id = ?",
            ("finding_rel_test_001",),
        ).fetchall()
    finally:
        conn.close()

    edge_types = {e[2] for e in edges}
    targets = {e[1] for e in edges}

    assert len(edges) >= 2, f"expected ≥2 edges from finding, got {len(edges)}: {edges}"
    # Edge types are coerced to lowercase EdgeType enum values when matchable.
    # FINDING_EXPLOITS_CVE / FINDING_AFFECTS_ASSET have no enum match → kept raw.
    assert any("EXPLOITS_CVE" in t or "exploits" in t for t in edge_types), edge_types
    assert any("AFFECTS_ASSET" in t or "affects" in t for t in edge_types), edge_types
    assert "cve_cve_2024_1111" in targets, targets
    assert "asset_prod_db" in targets, targets


def test_backbone_never_no_op(force_external_unavailable, temp_db):
    """After _init_store, backbone is always usable. _store is never None,
    _available is always True. Stats reflect live data, not the empty no-op
    response."""
    from core.trustgraph_backbone import TrustGraphBackbone

    backbone = TrustGraphBackbone(db_path=temp_db, org_id="never_noop")

    # Hard guarantees post-init.
    assert backbone._store is not None
    assert backbone._available is True

    # Index something then verify stats path executes through the adapter
    # (not the silent-degraded `available: False` early-return branch).
    backbone.index_asset({
        "id": "noop_asset",
        "name": "Noop guard asset",
        "type": "service",
        "criticality": "high",
    })
    stats = backbone.get_stats()

    assert stats["available"] is True, "stats must report available=True via adapter"
    # Adapter approximates per-core counts — at minimum the asset we wrote
    # must show up in total entity counts.
    assert stats["total_entities"] >= 1, f"expected ≥1 entity post-ingest, got {stats}"
