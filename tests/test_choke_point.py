"""Tests for the choke-point analyzer (GAP-026).

Covers:
  * Edmonds-Karp correctness on known graphs
  * Min-cut edge identification
  * Blast-reduction ranking
  * Org_id isolation
  * Cache behaviour
  * Determinism under random shuffles
  * Edge cases (empty path, empty inputs, top_k cap)
"""
from __future__ import annotations

import random
import sys

sys.path.insert(0, "suite-core")

import pytest

from core.attack_path_engine import AttackPathEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return AttackPathEngine(db_path=str(tmp_path / "choke_point.db"))


def _add_node(eng, nid, org_id="default", is_crown=False):
    eng.add_node(nid, "server", f"node-{nid}", org_id=org_id, is_crown_jewel=is_crown)


def _add_edge(eng, u, v, org_id="default"):
    return eng.add_edge(from_node=u, to_node=v, org_id=org_id)["edge_id"]


# ---------------------------------------------------------------------------
# Edmonds-Karp correctness (unit tests on the algorithm itself)
# ---------------------------------------------------------------------------


def test_edmonds_karp_single_edge():
    cap = {"s": {"t": 1}}
    flow, _ = AttackPathEngine._edmonds_karp(cap, "s", "t")
    assert flow == 1


def test_edmonds_karp_two_parallel_paths():
    # s -> a -> t  and  s -> b -> t   => max flow = 2 with unit capacity
    cap = {
        "s": {"a": 1, "b": 1},
        "a": {"t": 1},
        "b": {"t": 1},
        "t": {},
    }
    flow, _ = AttackPathEngine._edmonds_karp(cap, "s", "t")
    assert flow == 2


def test_edmonds_karp_bottleneck():
    # s -> a -> b -> t with a single bottleneck edge a->b
    # Plus s -> a with cap 3, a->b cap 1, b->t cap 3.
    cap = {"s": {"a": 3}, "a": {"b": 1}, "b": {"t": 3}, "t": {}}
    flow, _ = AttackPathEngine._edmonds_karp(cap, "s", "t")
    assert flow == 1


def test_edmonds_karp_disconnected_returns_zero():
    cap = {"s": {"a": 1}, "a": {}, "t": {}}
    flow, _ = AttackPathEngine._edmonds_karp(cap, "s", "t")
    assert flow == 0


def test_edmonds_karp_missing_source_returns_zero():
    cap = {"a": {"b": 1}, "b": {}}
    flow, _ = AttackPathEngine._edmonds_karp(cap, "s", "b")
    assert flow == 0


def test_edmonds_karp_missing_sink_returns_zero():
    cap = {"s": {"a": 1}, "a": {}}
    flow, _ = AttackPathEngine._edmonds_karp(cap, "s", "t")
    assert flow == 0


def test_bfs_augmenting_path_finds_path():
    residual = {"s": {"a": 1}, "a": {"t": 1}, "t": {}}
    path = AttackPathEngine._bfs_augmenting_path(residual, "s", "t")
    assert path == ["s", "a", "t"]


def test_bfs_augmenting_path_none_when_blocked():
    residual = {"s": {"a": 0}, "a": {"t": 1}, "t": {}}
    path = AttackPathEngine._bfs_augmenting_path(residual, "s", "t")
    assert path is None


def test_bfs_augmenting_path_deterministic_order():
    # Two possible paths — deterministic tie-breaking by sorted neighbours.
    residual = {
        "s": {"b": 1, "a": 1},
        "a": {"t": 1},
        "b": {"t": 1},
        "t": {},
    }
    path = AttackPathEngine._bfs_augmenting_path(residual, "s", "t")
    # Sorted neighbour order → 'a' is visited first.
    assert path == ["s", "a", "t"]


# ---------------------------------------------------------------------------
# Diamond graph — 2 disjoint paths, both edges at mid-layer are min-cut
# ---------------------------------------------------------------------------


def test_diamond_graph_max_flow_is_two(engine):
    for n in ("src", "A", "B", "snk"):
        _add_node(engine, n)
    _add_edge(engine, "src", "A")
    _add_edge(engine, "src", "B")
    _add_edge(engine, "A", "snk")
    _add_edge(engine, "B", "snk")

    choke = engine.compute_choke_points(
        org_id="default", source_ids=["src"], sink_ids=["snk"], top_k=10
    )
    # With two disjoint paths every real edge is in some min-cut; the
    # routine returns all mid-layer cut edges that reduce blast radius.
    assert len(choke) >= 2


def test_diamond_graph_each_edge_has_flow_value_one(engine):
    for n in ("src", "A", "B", "snk"):
        _add_node(engine, n)
    _add_edge(engine, "src", "A")
    _add_edge(engine, "src", "B")
    _add_edge(engine, "A", "snk")
    _add_edge(engine, "B", "snk")

    choke = engine.compute_choke_points(
        org_id="default", source_ids=["src"], sink_ids=["snk"]
    )
    assert choke, "expected non-empty ranked list"
    for c in choke:
        assert c["flow_value"] == 1


# ---------------------------------------------------------------------------
# Single-bottleneck graph
# ---------------------------------------------------------------------------


def _build_bottleneck_graph(engine, org_id="default"):
    # src -> A -> MID -> B -> snk  (plus extra front path src->C->MID)
    # MID is a single node, but the single bottleneck EDGE is MID->B.
    for n in ("src", "A", "C", "MID", "B", "snk"):
        _add_node(engine, n, org_id=org_id)
    edges = {
        "sa": _add_edge(engine, "src", "A", org_id=org_id),
        "sc": _add_edge(engine, "src", "C", org_id=org_id),
        "am": _add_edge(engine, "A", "MID", org_id=org_id),
        "cm": _add_edge(engine, "C", "MID", org_id=org_id),
        "mb": _add_edge(engine, "MID", "B", org_id=org_id),
        "bs": _add_edge(engine, "B", "snk", org_id=org_id),
    }
    return edges


def test_bottleneck_graph_top_edge_is_bottleneck(engine):
    edges = _build_bottleneck_graph(engine)
    choke = engine.compute_choke_points(
        org_id="default", source_ids=["src"], sink_ids=["snk"], top_k=10
    )
    top = choke[0]
    # Either MID->B (mb) or B->snk (bs) alone cuts all flow to snk.
    assert top["edge_id"] in {edges["mb"], edges["bs"]}
    assert top["blast_reduction_pct"] == 100.0


def test_bottleneck_graph_reduction_percentage(engine):
    _build_bottleneck_graph(engine)
    choke = engine.compute_choke_points(
        org_id="default", source_ids=["src"], sink_ids=["snk"]
    )
    # Bottleneck cuts ALL reachable sinks (just one sink), so 100%.
    assert choke[0]["blast_reduction_pct"] == 100.0


# ---------------------------------------------------------------------------
# No-path graph
# ---------------------------------------------------------------------------


def test_no_path_graph_returns_empty(engine):
    _add_node(engine, "src")
    _add_node(engine, "isolated")
    _add_node(engine, "snk")
    # No edges at all.
    choke = engine.compute_choke_points(
        org_id="default", source_ids=["src"], sink_ids=["snk"]
    )
    assert choke == []


def test_no_path_graph_still_caches(engine):
    _add_node(engine, "src")
    _add_node(engine, "snk")
    engine.compute_choke_points(
        org_id="default", source_ids=["src"], sink_ids=["snk"]
    )
    analyses = engine.list_analyses("default")
    assert len(analyses) == 1


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_empty_sources_raises(engine):
    with pytest.raises(ValueError, match="source_ids"):
        engine.compute_choke_points(
            org_id="default", source_ids=[], sink_ids=["x"]
        )


def test_empty_sinks_raises(engine):
    with pytest.raises(ValueError, match="sink_ids"):
        engine.compute_choke_points(
            org_id="default", source_ids=["x"], sink_ids=[]
        )


def test_invalid_top_k_raises(engine):
    with pytest.raises(ValueError, match="top_k"):
        engine.compute_choke_points(
            org_id="default", source_ids=["s"], sink_ids=["t"], top_k=0
        )


# ---------------------------------------------------------------------------
# Org_id isolation
# ---------------------------------------------------------------------------


def test_org_isolation_sees_only_own_edges(engine):
    for n in ("src", "snk"):
        _add_node(engine, n, org_id="org-A")
        _add_node(engine, n, org_id="org-B")
    _add_edge(engine, "src", "snk", org_id="org-A")
    # org-B has no edges — its choke list must be empty.
    choke_b = engine.compute_choke_points(
        org_id="org-B", source_ids=["src"], sink_ids=["snk"]
    )
    assert choke_b == []


def test_list_analyses_is_org_scoped(engine):
    _add_node(engine, "s", org_id="A")
    _add_node(engine, "t", org_id="A")
    _add_edge(engine, "s", "t", org_id="A")
    engine.compute_choke_points("A", ["s"], ["t"])

    assert len(engine.list_analyses("A")) == 1
    assert engine.list_analyses("B") == []


def test_get_analysis_guards_cross_tenant_read(engine):
    _add_node(engine, "s", org_id="A")
    _add_node(engine, "t", org_id="A")
    _add_edge(engine, "s", "t", org_id="A")
    engine.compute_choke_points("A", ["s"], ["t"])
    aid = engine.list_analyses("A")[0]["id"]
    assert engine.get_analysis(aid, org_id="A") is not None
    assert engine.get_analysis(aid, org_id="B") is None


# ---------------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------------


def test_cache_returns_same_ranking(engine):
    for n in ("src", "A", "B", "snk"):
        _add_node(engine, n)
    _add_edge(engine, "src", "A")
    _add_edge(engine, "src", "B")
    _add_edge(engine, "A", "snk")
    _add_edge(engine, "B", "snk")

    first = engine.compute_choke_points("default", ["src"], ["snk"], top_k=10)
    second = engine.compute_choke_points("default", ["src"], ["snk"], top_k=10)
    assert first == second


def test_cache_does_not_create_duplicate_rows(engine):
    _add_node(engine, "s")
    _add_node(engine, "t")
    _add_edge(engine, "s", "t")
    engine.compute_choke_points("default", ["s"], ["t"])
    engine.compute_choke_points("default", ["s"], ["t"])
    engine.compute_choke_points("default", ["s"], ["t"])
    # Three calls, identical keys → single cached row.
    assert len(engine.list_analyses("default")) == 1


def test_cache_invalidates_on_topology_change(engine):
    _add_node(engine, "s")
    _add_node(engine, "t")
    _add_node(engine, "x")
    _add_edge(engine, "s", "t")
    engine.compute_choke_points("default", ["s"], ["t"])
    # Adding a new edge should produce a distinct cache key.
    _add_edge(engine, "s", "x")
    _add_edge(engine, "x", "t")
    engine.compute_choke_points("default", ["s"], ["t"])
    assert len(engine.list_analyses("default")) == 2


# ---------------------------------------------------------------------------
# Stats & list endpoints
# ---------------------------------------------------------------------------


def test_stats_empty_returns_zero(engine):
    s = engine.get_choke_point_stats("default")
    assert s["total_analyses"] == 0
    assert s["avg_top_blast_reduction_pct"] == 0.0
    assert s["max_top_blast_reduction_pct"] == 0.0


def test_stats_after_computation(engine):
    _build_bottleneck_graph(engine)
    engine.compute_choke_points("default", ["src"], ["snk"])
    s = engine.get_choke_point_stats("default")
    assert s["total_analyses"] == 1
    assert s["max_top_blast_reduction_pct"] == 100.0


def test_list_analyses_orders_newest_first(engine):
    _add_node(engine, "s")
    _add_node(engine, "t")
    _add_edge(engine, "s", "t")
    engine.compute_choke_points("default", ["s"], ["t"])
    # Adding a node + edge changes topology → new cache row.
    _add_node(engine, "u")
    _add_edge(engine, "s", "u")
    engine.compute_choke_points("default", ["s"], ["t"])
    analyses = engine.list_analyses("default")
    assert len(analyses) == 2
    # Newest first — computed_at non-increasing.
    assert analyses[0]["computed_at"] >= analyses[1]["computed_at"]


# ---------------------------------------------------------------------------
# Determinism & large random graphs
# ---------------------------------------------------------------------------


def test_large_random_graph_is_deterministic(tmp_path):
    """Same graph + same query → same ranking across fresh engines."""
    random.seed(42)
    node_ids = [f"n{i}" for i in range(50)]
    edges = []
    for i in range(50):
        for _ in range(2):
            j = random.randint(0, 49)
            if j != i:
                edges.append((f"n{i}", f"n{j}"))

    def run_once(db: str):
        eng = AttackPathEngine(db_path=db)
        for nid in node_ids:
            _add_node(eng, nid)
        for u, v in edges:
            _add_edge(eng, u, v)
        return eng.compute_choke_points(
            "default", ["n0"], ["n49"], top_k=5
        )

    a = run_once(str(tmp_path / "a.db"))
    b = run_once(str(tmp_path / "b.db"))
    # Ignore volatile per-row fields (none here); results should be equal.
    assert a == b


def test_blast_reduction_values_are_bounded(engine):
    for n in ("s", "a", "b", "c", "t"):
        _add_node(engine, n)
    _add_edge(engine, "s", "a")
    _add_edge(engine, "a", "b")
    _add_edge(engine, "b", "c")
    _add_edge(engine, "c", "t")
    choke = engine.compute_choke_points("default", ["s"], ["t"])
    for c in choke:
        assert 0.0 <= c["blast_reduction_pct"] <= 100.0


def test_top_k_respects_cap(engine):
    # Build wider diamond: one source, 5 middle nodes, one sink.
    _add_node(engine, "src")
    _add_node(engine, "snk")
    for i in range(5):
        _add_node(engine, f"m{i}")
        _add_edge(engine, "src", f"m{i}")
        _add_edge(engine, f"m{i}", "snk")
    choke = engine.compute_choke_points(
        "default", ["src"], ["snk"], top_k=3
    )
    assert len(choke) <= 3


# ---------------------------------------------------------------------------
# Multi-source / multi-sink
# ---------------------------------------------------------------------------


def test_multi_source_multi_sink(engine):
    # Two entry points, two crown jewels, each source has its OWN path.
    #   s1 -> t1,  s2 -> t2
    # Edge-disjoint paths → every real edge is a min-cut that saves one sink.
    for n in ("s1", "s2", "t1", "t2"):
        _add_node(engine, n)
    e1 = _add_edge(engine, "s1", "t1")
    e2 = _add_edge(engine, "s2", "t2")

    choke = engine.compute_choke_points(
        "default", ["s1", "s2"], ["t1", "t2"], top_k=5
    )
    pcts = sorted({c["blast_reduction_pct"] for c in choke})
    assert 50.0 in pcts
    ids = {c["edge_id"] for c in choke}
    assert e1 in ids and e2 in ids


def test_dedup_source_ids(engine):
    _add_node(engine, "s")
    _add_node(engine, "t")
    _add_edge(engine, "s", "t")
    choke_a = engine.compute_choke_points("default", ["s", "s"], ["t"])
    choke_b = engine.compute_choke_points("default", ["s"], ["t"])
    assert choke_a == choke_b


# ---------------------------------------------------------------------------
# Sanity: compute returns correct shape
# ---------------------------------------------------------------------------


def test_return_shape_has_all_keys(engine):
    _add_node(engine, "s")
    _add_node(engine, "t")
    _add_edge(engine, "s", "t")
    choke = engine.compute_choke_points("default", ["s"], ["t"])
    assert choke
    keys = set(choke[0].keys())
    assert keys == {
        "edge_id",
        "source",
        "target",
        "flow_value",
        "blast_reduction_pct",
        "sinks_saved",
    }


def test_sinks_saved_matches_reduction(engine):
    for n in ("s", "a", "t"):
        _add_node(engine, n)
    _add_edge(engine, "s", "a")
    _add_edge(engine, "a", "t")
    choke = engine.compute_choke_points("default", ["s"], ["t"])
    # Only one sink, one path → removing any edge on path saves 1 sink.
    assert any(c["sinks_saved"] == 1 for c in choke)
