"""tests/test_graph_populate.py — SPEC-005b acceptance tests.

AC-005b-01: 2 findings sharing an asset for org A → get_blast_radius() returns
            total_reachable > 0.
AC-005b-02: SPEC-001 enrichment (_enrich_attack_paths) for that finding →
            blast_radius > 0 (affected_assets > 0).
AC-005b-03: org B (no data) → blast_radius 0; org A nodes not visible to B.
AC-005b-04: single isolated finding (no asset link) → blast_radius 0 (honest).

These tests call the engine path directly (no full pipeline boot required) and
also run the pipeline thin-path to verify end-to-end integration.  All I/O uses
tmp in-process SQLite paths so tests are isolated and leave no side-effects.
"""
from __future__ import annotations

import tempfile
import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Ensure suite paths are importable (mirrors sitecustomize.py behaviour)
# ---------------------------------------------------------------------------
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _suite in (
    ".",
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-integrations",
    "suite-evidence-risk",
):
    _p = os.path.join(_REPO, _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ap_engine(tmp_db: str):
    """Return a fresh AttackPathEngine backed by a temp SQLite file."""
    from core.attack_path_engine import AttackPathEngine
    return AttackPathEngine(db_path=tmp_db)


def _populate_two_findings_shared_asset(ap, org_id: str):
    """
    Insert:
      finding-1  → asset-web  (finding→asset edge)
      finding-2  → asset-web  (finding→asset edge)
    So asset-web has 2 incoming edges; from finding-1 the graph depth is 1
    (finding-1 → asset-web) and total_reachable = 1.
    """
    ap.add_node("finding-1", "server", "Finding 1", risk_score=70.0, org_id=org_id)
    ap.add_node("finding-2", "server", "Finding 2", risk_score=60.0, org_id=org_id)
    ap.add_node("asset-web", "server", "Web Asset", risk_score=80.0, org_id=org_id)
    # finding-1 → asset-web
    ap.upsert_edge("finding-1", "asset-web", protocol="scan", org_id=org_id)
    # finding-2 → asset-web
    ap.upsert_edge("finding-2", "asset-web", protocol="scan", org_id=org_id)


# ===========================================================================
# AC-005b-01: 2 findings sharing an asset → blast radius > 0
# ===========================================================================

def test_ac_005b_01_blast_radius_nonzero_with_shared_asset():
    """AC-005b-01: get_blast_radius for finding-1 must return total_reachable > 0."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tmp_db = tf.name
    try:
        ap = _make_ap_engine(tmp_db)
        org_id = "test-org-a"
        _populate_two_findings_shared_asset(ap, org_id)

        br = ap.get_blast_radius("finding-1", org_id=org_id)

        assert br["total_reachable"] > 0, (
            f"Expected total_reachable > 0 but got {br['total_reachable']}. "
            f"Full result: {br}"
        )
        assert "asset-web" in [r["node_id"] for r in br["reachable_nodes"]], (
            "asset-web should be reachable from finding-1"
        )
    finally:
        try:
            os.unlink(tmp_db)
        except OSError:
            pass


# ===========================================================================
# AC-005b-02: SPEC-001 enrichment → blast_radius > 0
# ===========================================================================

def test_ac_005b_02_enrichment_blast_radius_nonzero():
    """AC-005b-02: _enrich_attack_paths sets finding['blast_radius'] > 0."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tmp_db = tf.name
    try:
        from core.attack_path_engine import AttackPathEngine

        ap = AttackPathEngine(db_path=tmp_db)
        org_id = "test-org-a"
        _populate_two_findings_shared_asset(ap, org_id)

        # Build the adapter closure that _enrich_post_pipeline uses
        def _adapter(node_id: str, max_hops: int = 3):  # noqa: ARG001
            br = ap.get_blast_radius(node_id, org_id=org_id)
            if not isinstance(br, dict):
                return {}
            return {
                "total_paths": br.get("total_reachable", 0),
                "affected_nodes": br.get("total_reachable", 0),
                "max_depth": br.get("max_depth", 0),
                "crown_jewels_at_risk": br.get("crown_jewels_at_risk", []),
            }

        from core.brain_pipeline import BrainPipeline
        pipeline = BrainPipeline.__new__(BrainPipeline)  # skip __init__ DB boot

        finding = {"id": "finding-1", "title": "XSS", "severity": "high"}
        stats: dict = {"attack_paths_enriched": 0}
        pipeline._enrich_attack_paths(finding, _adapter, stats)

        assert finding.get("blast_radius", 0) > 0, (
            f"Expected blast_radius > 0 in enriched finding but got: {finding}"
        )
        assert stats["attack_paths_enriched"] == 1
    finally:
        try:
            os.unlink(tmp_db)
        except OSError:
            pass


# ===========================================================================
# AC-005b-03: org B empty → 0, no cross-org leak
# ===========================================================================

def test_ac_005b_03_org_isolation():
    """AC-005b-03: org B sees blast_radius = 0; org A's nodes not visible to B."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tmp_db = tf.name
    try:
        ap = _make_ap_engine(tmp_db)
        org_a = "test-org-a"
        org_b = "test-org-b"

        # Populate only for org A
        _populate_two_findings_shared_asset(ap, org_a)

        # Org B query for the same node_id must return 0
        br_b = ap.get_blast_radius("finding-1", org_id=org_b)
        assert br_b["total_reachable"] == 0, (
            f"Cross-org leak: org B sees total_reachable={br_b['total_reachable']}"
        )
        assert br_b["reachable_nodes"] == [], (
            f"Cross-org leak: org B sees nodes {br_b['reachable_nodes']}"
        )

        # Org A still returns > 0
        br_a = ap.get_blast_radius("finding-1", org_id=org_a)
        assert br_a["total_reachable"] > 0, (
            "Org A blast_radius should still be > 0 after org B query"
        )
    finally:
        try:
            os.unlink(tmp_db)
        except OSError:
            pass


# ===========================================================================
# AC-005b-04: single isolated finding → 0 (honest)
# ===========================================================================

def test_ac_005b_04_isolated_finding_returns_zero():
    """AC-005b-04: a finding with no edges returns blast_radius = 0."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tmp_db = tf.name
    try:
        ap = _make_ap_engine(tmp_db)
        org_id = "test-org-isolated"

        # Only insert the node — no edges
        ap.add_node("isolated-finding", "server", "Isolated", risk_score=50.0, org_id=org_id)

        br = ap.get_blast_radius("isolated-finding", org_id=org_id)
        assert br["total_reachable"] == 0, (
            f"Expected 0 for isolated finding but got {br['total_reachable']}"
        )
    finally:
        try:
            os.unlink(tmp_db)
        except OSError:
            pass


# ===========================================================================
# Idempotency: upsert_edge must not duplicate edges on re-run
# ===========================================================================

def test_upsert_edge_idempotent():
    """upsert_edge called twice with same (from, to, org) must not duplicate."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tmp_db = tf.name
    try:
        ap = _make_ap_engine(tmp_db)
        org_id = "test-org-idem"
        ap.add_node("f1", "server", "F1", org_id=org_id)
        ap.add_node("a1", "server", "A1", org_id=org_id)

        ap.upsert_edge("f1", "a1", org_id=org_id)
        ap.upsert_edge("f1", "a1", org_id=org_id)  # second call — must be no-op

        import sqlite3
        conn = sqlite3.connect(tmp_db)
        count = conn.execute(
            "SELECT COUNT(*) FROM edges WHERE from_node=? AND to_node=? AND org_id=?",
            ("f1", "a1", org_id),
        ).fetchone()[0]
        conn.close()

        assert count == 1, f"Expected 1 edge after 2 upserts but got {count}"
    finally:
        try:
            os.unlink(tmp_db)
        except OSError:
            pass


# ===========================================================================
# Pipeline integration: _populate_attack_graph via _step_build_graph
# ===========================================================================

def test_populate_attack_graph_via_pipeline():
    """_populate_attack_graph populates the engine during pipeline step."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tmp_db = tf.name

    try:
        from core.brain_pipeline import BrainPipeline

        # Patch AttackPathEngine to use our isolated tmp_db
        import core.attack_path_engine as _ape_mod
        from core.attack_path_engine import AttackPathEngine

        original_init = AttackPathEngine.__init__

        def _patched_init(self, db_path="data/attack_paths.db"):
            original_init(self, db_path=tmp_db)

        AttackPathEngine.__init__ = _patched_init

        try:
            pipeline = BrainPipeline()
            org_id = "test-org-pipeline"
            ctx = {
                "org_id": org_id,
                "findings": [
                    {
                        "id": "fp-finding-1",
                        "title": "SQL Injection",
                        "severity": "critical",
                        "asset_name": "db-server",
                        "cve_id": "CVE-2024-9999",
                    },
                    {
                        "id": "fp-finding-2",
                        "title": "RCE",
                        "severity": "high",
                        "asset_name": "db-server",
                        "cve_id": "CVE-2024-9999",
                    },
                ],
                "assets": [],
            }

            ap_stats = pipeline._populate_attack_graph(ctx)

            assert ap_stats.get("nodes_upserted", 0) > 0, (
                f"Expected nodes_upserted > 0, got: {ap_stats}"
            )
            assert ap_stats.get("edges_upserted", 0) > 0, (
                f"Expected edges_upserted > 0, got: {ap_stats}"
            )

            # Verify blast radius is non-zero for fp-finding-1
            ap = AttackPathEngine()
            br = ap.get_blast_radius("fp-finding-1", org_id=org_id)
            assert br["total_reachable"] > 0, (
                f"After pipeline populate, blast_radius should be > 0, got: {br}"
            )

        finally:
            AttackPathEngine.__init__ = original_init

    finally:
        try:
            os.unlink(tmp_db)
        except OSError:
            pass
