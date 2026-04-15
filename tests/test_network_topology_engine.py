"""Tests for NetworkTopologyEngine — 25 tests covering all public methods."""

from __future__ import annotations

import os
import tempfile
import pytest

from core.network_topology_engine import NetworkTopologyEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "topo_test.db")
    return NetworkTopologyEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "init_test.db")
    eng = NetworkTopologyEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "init_idem.db")
    NetworkTopologyEngine(db_path=db)
    NetworkTopologyEngine(db_path=db)  # second init must not raise


# ---------------------------------------------------------------------------
# 2. Nodes — add
# ---------------------------------------------------------------------------

def test_add_node_returns_dict(engine):
    node = engine.add_node(ORG_A, {"hostname": "web01", "ip": "10.0.0.1", "node_type": "server"})
    assert node["node_id"]
    assert node["hostname"] == "web01"
    assert node["org_id"] == ORG_A


def test_add_node_defaults(engine):
    node = engine.add_node(ORG_A, {})
    assert node["node_type"] == "server"
    assert node["criticality"] == "medium"
    assert node["tags"] == []


def test_add_node_invalid_type_defaults(engine):
    node = engine.add_node(ORG_A, {"node_type": "spaceship"})
    assert node["node_type"] == "server"


def test_add_node_invalid_criticality_defaults(engine):
    node = engine.add_node(ORG_A, {"criticality": "extreme"})
    assert node["criticality"] == "medium"


def test_add_node_tags_stored(engine):
    node = engine.add_node(ORG_A, {"tags": ["prod", "dmz"]})
    assert "prod" in node["tags"]


# ---------------------------------------------------------------------------
# 3. Nodes — list
# ---------------------------------------------------------------------------

def test_list_nodes_empty(engine):
    assert engine.list_nodes(ORG_A) == []


def test_list_nodes_returns_all(engine):
    engine.add_node(ORG_A, {"hostname": "n1"})
    engine.add_node(ORG_A, {"hostname": "n2"})
    nodes = engine.list_nodes(ORG_A)
    assert len(nodes) == 2


def test_list_nodes_filter_type(engine):
    engine.add_node(ORG_A, {"node_type": "router"})
    engine.add_node(ORG_A, {"node_type": "server"})
    routers = engine.list_nodes(ORG_A, node_type="router")
    assert len(routers) == 1
    assert routers[0]["node_type"] == "router"


def test_list_nodes_filter_criticality(engine):
    engine.add_node(ORG_A, {"criticality": "critical"})
    engine.add_node(ORG_A, {"criticality": "low"})
    crits = engine.list_nodes(ORG_A, criticality="critical")
    assert len(crits) == 1


# ---------------------------------------------------------------------------
# 4. Edges — add / list
# ---------------------------------------------------------------------------

def test_add_edge_returns_dict(engine):
    n1 = engine.add_node(ORG_A, {"hostname": "fw"})
    n2 = engine.add_node(ORG_A, {"hostname": "web"})
    edge = engine.add_edge(ORG_A, n1["node_id"], n2["node_id"], "tcp", 443)
    assert edge["edge_id"]
    assert edge["protocol"] == "tcp"
    assert edge["port"] == 443
    assert edge["bidirectional"] is True


def test_add_edge_unidirectional(engine):
    n1 = engine.add_node(ORG_A, {})
    n2 = engine.add_node(ORG_A, {})
    edge = engine.add_edge(ORG_A, n1["node_id"], n2["node_id"], "udp", 53, bidirectional=False)
    assert edge["bidirectional"] is False


def test_list_edges_empty(engine):
    assert engine.list_edges(ORG_A) == []


def test_list_edges_all(engine):
    n1 = engine.add_node(ORG_A, {})
    n2 = engine.add_node(ORG_A, {})
    n3 = engine.add_node(ORG_A, {})
    engine.add_edge(ORG_A, n1["node_id"], n2["node_id"], "tcp", 80)
    engine.add_edge(ORG_A, n2["node_id"], n3["node_id"], "tcp", 443)
    assert len(engine.list_edges(ORG_A)) == 2


def test_list_edges_filter_node(engine):
    n1 = engine.add_node(ORG_A, {})
    n2 = engine.add_node(ORG_A, {})
    n3 = engine.add_node(ORG_A, {})
    engine.add_edge(ORG_A, n1["node_id"], n2["node_id"], "tcp", 80)
    engine.add_edge(ORG_A, n2["node_id"], n3["node_id"], "tcp", 443)
    edges = engine.list_edges(ORG_A, node_id=n1["node_id"])
    assert len(edges) == 1


# ---------------------------------------------------------------------------
# 5. Segments
# ---------------------------------------------------------------------------

def test_add_segment_returns_dict(engine):
    seg = engine.add_segment(ORG_A, {"name": "DMZ", "vlan": "100", "zone": "dmz"})
    assert seg["segment_id"]
    assert seg["zone"] == "dmz"


def test_add_segment_invalid_zone_defaults(engine):
    seg = engine.add_segment(ORG_A, {"zone": "nowhere"})
    assert seg["zone"] == "internal"


def test_list_segments(engine):
    engine.add_segment(ORG_A, {"name": "internal-net", "zone": "internal"})
    engine.add_segment(ORG_A, {"name": "dmz-net", "zone": "dmz"})
    segs = engine.list_segments(ORG_A)
    assert len(segs) == 2


# ---------------------------------------------------------------------------
# 6. get_neighbors
# ---------------------------------------------------------------------------

def test_get_neighbors_empty(engine):
    n1 = engine.add_node(ORG_A, {})
    assert engine.get_neighbors(ORG_A, n1["node_id"]) == []


def test_get_neighbors_bidirectional(engine):
    n1 = engine.add_node(ORG_A, {"hostname": "a"})
    n2 = engine.add_node(ORG_A, {"hostname": "b"})
    engine.add_edge(ORG_A, n1["node_id"], n2["node_id"], "tcp", 22)
    # From n1: should see n2
    neighbors = engine.get_neighbors(ORG_A, n1["node_id"])
    assert any(n["node_id"] == n2["node_id"] for n in neighbors)
    # From n2 (bidirectional): should see n1
    neighbors2 = engine.get_neighbors(ORG_A, n2["node_id"])
    assert any(n["node_id"] == n1["node_id"] for n in neighbors2)


# ---------------------------------------------------------------------------
# 7. find_path BFS
# ---------------------------------------------------------------------------

def test_find_path_same_node(engine):
    n1 = engine.add_node(ORG_A, {})
    path = engine.find_path(ORG_A, n1["node_id"], n1["node_id"])
    assert path == [n1["node_id"]]


def test_find_path_direct(engine):
    n1 = engine.add_node(ORG_A, {})
    n2 = engine.add_node(ORG_A, {})
    engine.add_edge(ORG_A, n1["node_id"], n2["node_id"], "tcp", 80)
    path = engine.find_path(ORG_A, n1["node_id"], n2["node_id"])
    assert path == [n1["node_id"], n2["node_id"]]


def test_find_path_multi_hop(engine):
    nodes = [engine.add_node(ORG_A, {}) for _ in range(4)]
    ids = [n["node_id"] for n in nodes]
    engine.add_edge(ORG_A, ids[0], ids[1], "tcp", 80)
    engine.add_edge(ORG_A, ids[1], ids[2], "tcp", 80)
    engine.add_edge(ORG_A, ids[2], ids[3], "tcp", 80)
    path = engine.find_path(ORG_A, ids[0], ids[3])
    assert path[0] == ids[0] and path[-1] == ids[3]
    assert len(path) == 4


def test_find_path_no_route(engine):
    n1 = engine.add_node(ORG_A, {})
    n2 = engine.add_node(ORG_A, {})
    path = engine.find_path(ORG_A, n1["node_id"], n2["node_id"])
    assert path == []


# ---------------------------------------------------------------------------
# 8. Stats
# ---------------------------------------------------------------------------

def test_get_topology_stats_empty(engine):
    stats = engine.get_topology_stats(ORG_A)
    assert stats["total_nodes"] == 0
    assert stats["total_edges"] == 0
    assert stats["segment_count"] == 0


def test_get_topology_stats_counts(engine):
    engine.add_node(ORG_A, {"node_type": "server", "criticality": "critical"})
    engine.add_node(ORG_A, {"node_type": "router", "criticality": "high"})
    engine.add_segment(ORG_A, {"name": "seg1"})
    stats = engine.get_topology_stats(ORG_A)
    assert stats["total_nodes"] == 2
    assert stats["segment_count"] == 1
    assert "server" in stats["by_type"]


# ---------------------------------------------------------------------------
# 9. detect_exposure
# ---------------------------------------------------------------------------

def test_detect_exposure_no_external(engine):
    engine.add_node(ORG_A, {"criticality": "critical", "location": "internal-dc"})
    assert engine.detect_exposure(ORG_A) == []


def test_detect_exposure_finds_path(engine):
    ext = engine.add_node(ORG_A, {"location": "external-fw", "criticality": "low"})
    crit = engine.add_node(ORG_A, {"location": "internal-dc", "criticality": "critical"})
    engine.add_edge(ORG_A, ext["node_id"], crit["node_id"], "tcp", 443)
    exposures = engine.detect_exposure(ORG_A)
    assert len(exposures) >= 1
    exp = exposures[0]
    assert exp["external_node_id"] == ext["node_id"]
    assert exp["internal_node_id"] == crit["node_id"]


# ---------------------------------------------------------------------------
# 10. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_nodes(engine):
    engine.add_node(ORG_A, {"hostname": "alpha-server"})
    engine.add_node(ORG_B, {"hostname": "beta-server"})
    a_nodes = engine.list_nodes(ORG_A)
    b_nodes = engine.list_nodes(ORG_B)
    assert len(a_nodes) == 1
    assert len(b_nodes) == 1
    assert a_nodes[0]["hostname"] == "alpha-server"
    assert b_nodes[0]["hostname"] == "beta-server"


def test_org_isolation_edges(engine):
    n_a = engine.add_node(ORG_A, {})
    n_a2 = engine.add_node(ORG_A, {})
    n_b = engine.add_node(ORG_B, {})
    n_b2 = engine.add_node(ORG_B, {})
    engine.add_edge(ORG_A, n_a["node_id"], n_a2["node_id"], "tcp", 80)
    engine.add_edge(ORG_B, n_b["node_id"], n_b2["node_id"], "tcp", 443)
    assert len(engine.list_edges(ORG_A)) == 1
    assert len(engine.list_edges(ORG_B)) == 1


def test_org_isolation_stats(engine):
    engine.add_node(ORG_A, {})
    engine.add_node(ORG_A, {})
    stats_a = engine.get_topology_stats(ORG_A)
    stats_b = engine.get_topology_stats(ORG_B)
    assert stats_a["total_nodes"] == 2
    assert stats_b["total_nodes"] == 0
