"""Tests for the SQLite-backed AttackPathEngine.

22 tests covering node CRUD, edge creation, BFS path finding,
blast radius, crown jewel analysis, and graph stats.
"""
from __future__ import annotations

import sys

sys.path.insert(0, "suite-core")

import pytest

from core.attack_path_engine import AttackPathEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """Fresh AttackPathEngine backed by a temp SQLite DB."""
    return AttackPathEngine(db_path=str(tmp_path / "test_attack_paths.db"))


@pytest.fixture
def simple_graph(engine):
    """
    Topology:
        external (entry) --> dmz (server) --> db (database, crown jewel)
                                         --> cache (server)
    """
    engine.add_node("external", "external", "External Host", risk_score=80.0)
    engine.add_node("dmz", "server", "DMZ Server", risk_score=60.0)
    engine.add_node("db", "database", "Prod DB", risk_score=90.0, is_crown_jewel=True)
    engine.add_node("cache", "server", "Cache Server", risk_score=40.0)

    engine.add_edge("external", "dmz")
    engine.add_edge("dmz", "db")
    engine.add_edge("dmz", "cache")
    return engine


# ---------------------------------------------------------------------------
# Node tests
# ---------------------------------------------------------------------------


def test_add_node_returns_dict(engine):
    result = engine.add_node("host1", "server", "Web Server")
    assert isinstance(result, dict)
    assert result["node_id"] == "host1"


def test_add_node_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid node_type"):
        engine.add_node("x", "spaceship", "UFO")


def test_get_node_returns_added_node(engine):
    engine.add_node("srv1", "server", "My Server", risk_score=75.0)
    node = engine.get_node("srv1")
    assert node is not None
    assert node["node_id"] == "srv1"
    assert node["risk_score"] == 75.0


def test_get_node_unknown_returns_none(engine):
    assert engine.get_node("does-not-exist") is None


def test_list_nodes_returns_list(engine):
    engine.add_node("n1", "workstation", "WS1")
    engine.add_node("n2", "server", "SRV1")
    result = engine.list_nodes()
    assert isinstance(result, list)
    assert len(result) >= 2


def test_list_nodes_crown_jewel_filter(simple_graph):
    cjs = simple_graph.list_nodes(is_crown_jewel=True)
    non_cjs = simple_graph.list_nodes(is_crown_jewel=False)
    assert all(n["is_crown_jewel"] for n in cjs)
    assert all(not n["is_crown_jewel"] for n in non_cjs)
    assert len(cjs) == 1
    assert cjs[0]["node_id"] == "db"


def test_remove_node_returns_true(engine):
    engine.add_node("tmp", "workstation", "Temp")
    assert engine.remove_node("tmp") is True


def test_remove_node_unknown_returns_false(engine):
    assert engine.remove_node("ghost") is False


# ---------------------------------------------------------------------------
# Edge tests
# ---------------------------------------------------------------------------


def test_add_edge_returns_dict_with_edge_id(engine):
    engine.add_node("a", "server", "A")
    engine.add_node("b", "server", "B")
    result = engine.add_edge("a", "b")
    assert isinstance(result, dict)
    assert "edge_id" in result
    assert result["from_node"] == "a"
    assert result["to_node"] == "b"


# ---------------------------------------------------------------------------
# find_attack_paths tests
# ---------------------------------------------------------------------------


def test_find_attack_paths_direct_connection(engine):
    engine.add_node("entry", "external", "Entry")
    engine.add_node("crown", "database", "Crown", is_crown_jewel=True)
    engine.add_edge("entry", "crown")

    result = engine.find_attack_paths("entry", org_id="default")
    assert result["total_paths"] == 1
    path = result["paths"][0]
    assert path["hops"] == 1
    assert path["path"] == ["entry", "crown"]


def test_find_attack_paths_no_path(engine):
    engine.add_node("island", "server", "Island")
    engine.add_node("crown", "database", "Crown", is_crown_jewel=True)
    # No edge between them

    result = engine.find_attack_paths("island", org_id="default")
    assert result["paths"] == []
    assert result["total_paths"] == 0


def test_find_attack_paths_respects_max_hops(engine):
    # Chain: entry -> h1 -> h2 -> h3 -> crown (4 hops)
    for nid in ["entry", "h1", "h2", "h3", "crown"]:
        is_cj = nid == "crown"
        engine.add_node(nid, "server" if not is_cj else "database", nid, is_crown_jewel=is_cj)
    engine.add_edge("entry", "h1")
    engine.add_edge("h1", "h2")
    engine.add_edge("h2", "h3")
    engine.add_edge("h3", "crown")

    # max_hops=2 — crown is 4 hops away, should not be found
    result = engine.find_attack_paths("entry", max_hops=2, org_id="default")
    assert result["total_paths"] == 0

    # max_hops=4 — should find it
    result = engine.find_attack_paths("entry", max_hops=4, org_id="default")
    assert result["total_paths"] == 1


def test_find_attack_paths_to_specific_target(simple_graph):
    result = simple_graph.find_attack_paths("external", target="db")
    assert result["total_paths"] >= 1
    for path in result["paths"]:
        assert path["path"][-1] == "db"


def test_find_attack_paths_target_nodes_reached(simple_graph):
    result = simple_graph.find_attack_paths("external")
    assert "db" in result["target_nodes_reached"]


def test_find_attack_paths_risk_score_is_float(simple_graph):
    result = simple_graph.find_attack_paths("external")
    for path in result["paths"]:
        assert isinstance(path["risk_score"], float)


def test_find_attack_paths_vulnerabilities_required_list(engine):
    engine.add_node("a", "external", "A")
    engine.add_node("b", "database", "B", is_crown_jewel=True)
    engine.add_edge("a", "b", requires_vuln="CVE-2024-1234")

    result = engine.find_attack_paths("a", org_id="default")
    assert result["total_paths"] == 1
    path = result["paths"][0]
    assert isinstance(path["vulnerabilities_required"], list)
    assert "CVE-2024-1234" in path["vulnerabilities_required"]


# ---------------------------------------------------------------------------
# find_shortest_path tests
# ---------------------------------------------------------------------------


def test_find_shortest_path_known_nodes(simple_graph):
    result = simple_graph.find_shortest_path("external", "db")
    assert result is not None
    assert result["path"][0] == "external"
    assert result["path"][-1] == "db"


def test_find_shortest_path_disconnected_returns_none(simple_graph):
    simple_graph.add_node("isolated", "workstation", "Isolated")
    result = simple_graph.find_shortest_path("external", "isolated")
    assert result is None


# ---------------------------------------------------------------------------
# Blast radius tests
# ---------------------------------------------------------------------------


def test_get_blast_radius_returns_dict(simple_graph):
    result = simple_graph.get_blast_radius("external")
    assert isinstance(result, dict)
    assert "reachable_nodes" in result


def test_blast_radius_includes_directly_connected(simple_graph):
    result = simple_graph.get_blast_radius("external")
    reachable_ids = [r["node_id"] for r in result["reachable_nodes"]]
    assert "dmz" in reachable_ids


def test_blast_radius_crown_jewel_at_risk(simple_graph):
    result = simple_graph.get_blast_radius("external")
    cj_ids = [r["node_id"] for r in result["crown_jewels_at_risk"]]
    assert "db" in cj_ids


# ---------------------------------------------------------------------------
# get_crown_jewels_at_risk tests
# ---------------------------------------------------------------------------


def test_crown_jewels_at_risk_returns_list(simple_graph):
    result = simple_graph.get_crown_jewels_at_risk()
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["node_id"] == "db"
    assert "reachable_from" in result[0]


# ---------------------------------------------------------------------------
# get_graph_stats tests
# ---------------------------------------------------------------------------


def test_get_graph_stats_returns_numeric_dict(simple_graph):
    stats = simple_graph.get_graph_stats()
    assert isinstance(stats["total_nodes"], int)
    assert isinstance(stats["total_edges"], int)
    assert isinstance(stats["crown_jewel_count"], int)
    assert isinstance(stats["avg_connections_per_node"], float)
    assert stats["total_nodes"] == 4
    assert stats["total_edges"] == 3
    assert stats["crown_jewel_count"] == 1


# ---------------------------------------------------------------------------
# Multi-tenant isolation tests
# ---------------------------------------------------------------------------


def test_get_node_cross_tenant_returns_none(engine):
    """A node created in org1 must not be readable from org2."""
    engine.add_node("host-secret", "server", "Org1 Server", org_id="org1")
    # Same node_id, different org — must return None
    result = engine.get_node("host-secret", org_id="org2")
    assert result is None


def test_get_node_correct_tenant_returns_node(engine):
    """A node created in org1 is returned when queried with the correct org_id."""
    engine.add_node("host-secret", "server", "Org1 Server", org_id="org1")
    result = engine.get_node("host-secret", org_id="org1")
    assert result is not None
    assert result["node_id"] == "host-secret"
    assert result["org_id"] == "org1"


def test_remove_node_cross_tenant_returns_false_and_preserves_node(engine):
    """Attempting to remove org1's node while passing org2 must fail silently
    (returns False) and leave the original node intact."""
    engine.add_node("crown", "database", "Org1 Crown", is_crown_jewel=True, org_id="org1")
    # Cross-tenant delete — must not remove anything
    deleted = engine.remove_node("crown", org_id="org2")
    assert deleted is False
    # Node must still exist in org1
    still_there = engine.get_node("crown", org_id="org1")
    assert still_there is not None
    assert still_there["node_id"] == "crown"


# ---------------------------------------------------------------------------
# Toxic combinations tests
# ---------------------------------------------------------------------------


def test_toxic_combinations_detected_when_internet_exposed_with_3_vulns(engine):
    """An internet-exposed asset with 3+ CVEs must appear as a toxic combination."""
    engine.add_node("internet", "external", "Internet", risk_score=80.0)
    engine.add_node(
        "web-server",
        "server",
        "Web Server",
        risk_score=70.0,
        vulnerabilities=["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
    )
    engine.add_edge("internet", "web-server")

    combos = engine.get_toxic_combinations()
    assert len(combos) == 1
    combo = combos[0]
    assert combo["asset"]["node_id"] == "web-server"
    assert len(combo["findings"]) == 3
    # combined_risk = 70.0 * 1.5 = 105 capped to 100
    assert combo["combined_risk"] == 100.0
    assert "internet" in combo["attack_chain"]


def test_toxic_combinations_excluded_when_not_internet_exposed(engine):
    """An internal asset with 3+ CVEs but no external predecessor must NOT appear."""
    engine.add_node("internal-db", "database", "Internal DB", risk_score=60.0,
                    vulnerabilities=["CVE-2024-0010", "CVE-2024-0011", "CVE-2024-0012"])
    engine.add_node("internal-app", "server", "App Server", risk_score=50.0)
    # Only internal-to-internal edge — no external node reaches internal-db
    engine.add_edge("internal-app", "internal-db")

    combos = engine.get_toxic_combinations()
    assert combos == []
