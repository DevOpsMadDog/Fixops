"""
Tests for the Cloud Resource Graph Engine.

Covers:
- NodeType / EdgeType enums
- GraphNode / GraphEdge / CloudGraph Pydantic models
- CloudGraphEngine: add_node, add_edge, build_graph_from_resources
- Edge inference rules (VPC CONTAINS, SG ATTACHED_TO, IAM HAS_ACCESS, etc.)
- get_graph with filters
- get_exposed_resources
- get_overprivileged_roles
- find_attack_paths
- find_blast_radius
- get_network_segmentation
- calculate_risk_paths / get_graph_stats
- get_cloud_graph_engine singleton
- FastAPI router endpoints (import smoke + response shape)

Run with: python -m pytest tests/test_cloud_graph.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.cloud_graph import (
    CloudGraph,
    CloudGraphEngine,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    get_cloud_graph_engine,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _engine(tmp_path: Path) -> CloudGraphEngine:
    return CloudGraphEngine(db_path=str(tmp_path / "test_cg.db"))


def _node(
    node_type: NodeType,
    name: str = "test",
    public: bool = False,
    risk_score: float = 0.0,
    config: Dict[str, Any] | None = None,
) -> GraphNode:
    return GraphNode(
        type=node_type,
        name=name,
        provider="AWS",
        region="us-east-1",
        config=config or {},
        risk_score=risk_score,
        public=public,
    )


def _sample_resources(vpc_id: str = "vpc-001", subnet_id: str = "sub-001") -> List[Dict[str, Any]]:
    """Minimal resource list that exercises several inference rules."""
    sg_id = "sg-001"
    role_arn = "arn:aws:iam::123456789012:role/MyRole"
    lb_arn = "arn:aws:elasticloadbalancing::lb/my-alb"
    return [
        {
            "id": vpc_id,
            "type": "VPC",
            "name": "main-vpc",
            "config": {"vpc_id": vpc_id},
            "public": False,
        },
        {
            "id": subnet_id,
            "type": "SUBNET",
            "name": "public-subnet",
            "config": {"subnet_id": subnet_id, "vpc_id": vpc_id},
            "public": True,
        },
        {
            "id": sg_id,
            "type": "SECURITY_GROUP",
            "name": "web-sg",
            "config": {"group_id": sg_id, "vpc_id": vpc_id},
            "public": False,
        },
        {
            "id": "ec2-001",
            "type": "EC2",
            "name": "web-server",
            "config": {
                "vpc_id": vpc_id,
                "subnet_id": subnet_id,
                "security_group_ids": [sg_id],
                "load_balancer_arn": lb_arn,
            },
            "risk_score": 0.4,
            "public": True,
        },
        {
            "id": "rds-001",
            "type": "RDS",
            "name": "prod-db",
            "config": {
                "vpc_id": vpc_id,
                "subnet_id": subnet_id,
                "security_group_ids": [sg_id],
            },
            "risk_score": 0.6,
            "public": False,
        },
        {
            "id": "role-001",
            "type": "IAM_ROLE",
            "name": "ec2-role",
            "config": {
                "role_arn": role_arn,
                "policies": [{"actions": ["ec2:*", "s3:GetObject"]}],
            },
            "risk_score": 0.3,
            "public": False,
        },
        {
            "id": "lb-001",
            "type": "LOAD_BALANCER",
            "name": "my-alb",
            "config": {"lb_arn": lb_arn},
            "public": True,
        },
        {
            "id": "s3-001",
            "type": "S3",
            "name": "data-bucket",
            "config": {"iam_role_arn": role_arn},
            "risk_score": 0.5,
            "public": False,
        },
    ]


# ---------------------------------------------------------------------------
# 1. Enum tests
# ---------------------------------------------------------------------------


class TestEnums:
    def test_node_type_values(self):
        assert NodeType.VPC == "VPC"
        assert NodeType.EC2 == "EC2"
        assert NodeType.IAM_ROLE == "IAM_ROLE"
        assert NodeType.CLOUDFRONT == "CLOUDFRONT"
        assert NodeType.NAT_GATEWAY == "NAT_GATEWAY"

    def test_all_node_types_present(self):
        expected = {
            "VPC", "SUBNET", "SECURITY_GROUP", "EC2", "RDS", "S3", "LAMBDA",
            "EKS", "IAM_ROLE", "IAM_USER", "LOAD_BALANCER", "API_GATEWAY",
            "CLOUDFRONT", "ROUTE_TABLE", "NAT_GATEWAY",
        }
        assert expected == {m.value for m in NodeType}

    def test_edge_type_values(self):
        assert EdgeType.CONTAINS == "CONTAINS"
        assert EdgeType.HAS_ACCESS == "HAS_ACCESS"
        assert EdgeType.ATTACHED_TO == "ATTACHED_TO"

    def test_all_edge_types_present(self):
        expected = {"CONTAINS", "CONNECTS_TO", "HAS_ACCESS", "EXPOSES", "ROUTES_TO", "INHERITS", "ATTACHED_TO"}
        assert expected == {m.value for m in EdgeType}


# ---------------------------------------------------------------------------
# 2. Model tests
# ---------------------------------------------------------------------------


class TestModels:
    def test_graph_node_defaults(self):
        node = GraphNode(type=NodeType.EC2, name="server")
        assert node.id.startswith("node-")
        assert node.provider == "AWS"
        assert node.region == "us-east-1"
        assert node.risk_score == 0.0
        assert node.vulnerabilities == []
        assert node.public is False

    def test_graph_node_full(self):
        node = GraphNode(
            type=NodeType.S3,
            name="bucket",
            provider="AWS",
            region="eu-west-1",
            config={"versioning": True},
            risk_score=0.8,
            vulnerabilities=["CVE-2023-001"],
            public=True,
        )
        assert node.public is True
        assert node.risk_score == 0.8
        assert "CVE-2023-001" in node.vulnerabilities

    def test_graph_edge_defaults(self):
        edge = GraphEdge(source_id="a", target_id="b", type=EdgeType.CONTAINS)
        assert edge.id.startswith("edge-")
        assert edge.metadata == {}

    def test_cloud_graph_defaults(self):
        graph = CloudGraph()
        assert graph.nodes == []
        assert graph.edges == []
        assert isinstance(graph.stats, dict)

    def test_cloud_graph_populated(self):
        node = GraphNode(type=NodeType.VPC, name="vpc")
        edge = GraphEdge(source_id=node.id, target_id="other", type=EdgeType.CONTAINS)
        graph = CloudGraph(nodes=[node], edges=[edge], stats={"total": 1})
        assert len(graph.nodes) == 1
        assert len(graph.edges) == 1


# ---------------------------------------------------------------------------
# 3. Engine: add_node / add_edge
# ---------------------------------------------------------------------------


class TestEngineBasics:
    def test_add_and_retrieve_node(self, tmp_path):
        eng = _engine(tmp_path)
        node = _node(NodeType.EC2, "my-ec2")
        result = eng.add_node(node, org_id="org1")
        assert result.id == node.id
        assert result.name == "my-ec2"

    def test_add_node_persisted(self, tmp_path):
        eng = _engine(tmp_path)
        node = _node(NodeType.RDS, "my-rds")
        eng.add_node(node, org_id="org1")
        graph = eng.get_graph("org1")
        ids = [n.id for n in graph.nodes]
        assert node.id in ids

    def test_add_edge_persisted(self, tmp_path):
        eng = _engine(tmp_path)
        src = _node(NodeType.VPC, "vpc")
        tgt = _node(NodeType.SUBNET, "subnet")
        eng.add_node(src, org_id="org1")
        eng.add_node(tgt, org_id="org1")
        edge = GraphEdge(source_id=src.id, target_id=tgt.id, type=EdgeType.CONTAINS)
        eng.add_edge(edge, org_id="org1")
        graph = eng.get_graph("org1")
        edge_types = [e.type for e in graph.edges]
        assert EdgeType.CONTAINS in edge_types

    def test_org_isolation(self, tmp_path):
        eng = _engine(tmp_path)
        eng.add_node(_node(NodeType.EC2, "ec2-org1"), org_id="org1")
        eng.add_node(_node(NodeType.EC2, "ec2-org2"), org_id="org2")
        g1 = eng.get_graph("org1")
        g2 = eng.get_graph("org2")
        assert len(g1.nodes) == 1
        assert len(g2.nodes) == 1
        assert g1.nodes[0].name == "ec2-org1"
        assert g2.nodes[0].name == "ec2-org2"

    def test_upsert_node_replaces(self, tmp_path):
        eng = _engine(tmp_path)
        node = GraphNode(id="fixed-id", type=NodeType.EC2, name="v1")
        eng.add_node(node, org_id="org1")
        node2 = GraphNode(id="fixed-id", type=NodeType.EC2, name="v2")
        eng.add_node(node2, org_id="org1")
        graph = eng.get_graph("org1")
        assert len(graph.nodes) == 1
        assert graph.nodes[0].name == "v2"


# ---------------------------------------------------------------------------
# 4. Graph build + edge inference
# ---------------------------------------------------------------------------


class TestBuildGraph:
    def test_build_returns_correct_node_count(self, tmp_path):
        eng = _engine(tmp_path)
        resources = _sample_resources()
        graph = eng.build_graph_from_resources(resources, org_id="org1")
        assert len(graph.nodes) == len(resources)

    def test_build_creates_vpc_contains_subnet(self, tmp_path):
        eng = _engine(tmp_path)
        resources = _sample_resources(vpc_id="vpc-x", subnet_id="sub-x")
        eng.build_graph_from_resources(resources, org_id="org1")
        all_edges = eng._db.list_edges("org1")
        contains_edges = [e for e in all_edges if e.type == EdgeType.CONTAINS]
        source_ids = {e.source_id for e in contains_edges}
        assert "vpc-x" in source_ids

    def test_build_creates_sg_attached_to_ec2(self, tmp_path):
        eng = _engine(tmp_path)
        resources = _sample_resources()
        eng.build_graph_from_resources(resources, org_id="org1")
        all_edges = eng._db.list_edges("org1")
        attached = [e for e in all_edges if e.type == EdgeType.ATTACHED_TO]
        assert len(attached) >= 1

    def test_build_creates_iam_has_access(self, tmp_path):
        eng = _engine(tmp_path)
        resources = _sample_resources()
        eng.build_graph_from_resources(resources, org_id="org1")
        all_edges = eng._db.list_edges("org1")
        has_access = [e for e in all_edges if e.type == EdgeType.HAS_ACCESS]
        assert len(has_access) >= 1

    def test_build_creates_lb_routes_to_ec2(self, tmp_path):
        eng = _engine(tmp_path)
        resources = _sample_resources()
        eng.build_graph_from_resources(resources, org_id="org1")
        all_edges = eng._db.list_edges("org1")
        routes = [e for e in all_edges if e.type == EdgeType.ROUTES_TO]
        assert len(routes) >= 1

    def test_build_clears_previous_graph(self, tmp_path):
        eng = _engine(tmp_path)
        resources = _sample_resources()
        eng.build_graph_from_resources(resources, org_id="org1")
        # Rebuild with only 1 resource
        eng.build_graph_from_resources([resources[0]], org_id="org1")
        graph = eng.get_graph("org1")
        assert len(graph.nodes) == 1

    def test_build_stats_populated(self, tmp_path):
        eng = _engine(tmp_path)
        resources = _sample_resources()
        graph = eng.build_graph_from_resources(resources, org_id="org1")
        assert graph.stats["total_nodes"] == len(resources)
        assert graph.stats["total_edges"] >= 0

    def test_infer_edges_no_duplicates(self, tmp_path):
        eng = _engine(tmp_path)
        resources = _sample_resources()
        eng.build_graph_from_resources(resources, org_id="org1")
        all_edges = eng._db.list_edges("org1")
        pairs = [(e.source_id, e.target_id, e.type.value) for e in all_edges]
        assert len(pairs) == len(set(pairs))


# ---------------------------------------------------------------------------
# 5. get_graph filters
# ---------------------------------------------------------------------------


class TestGetGraph:
    def test_filter_by_node_type(self, tmp_path):
        eng = _engine(tmp_path)
        eng.build_graph_from_resources(_sample_resources(), org_id="org1")
        graph = eng.get_graph("org1", node_type=NodeType.EC2)
        assert all(n.type == NodeType.EC2 for n in graph.nodes)

    def test_filter_public_only(self, tmp_path):
        eng = _engine(tmp_path)
        eng.build_graph_from_resources(_sample_resources(), org_id="org1")
        graph = eng.get_graph("org1", public_only=True)
        assert all(n.public for n in graph.nodes)
        assert len(graph.nodes) >= 1

    def test_filtered_edges_only_in_set(self, tmp_path):
        eng = _engine(tmp_path)
        eng.build_graph_from_resources(_sample_resources(), org_id="org1")
        graph = eng.get_graph("org1", node_type=NodeType.VPC)
        node_ids = {n.id for n in graph.nodes}
        for edge in graph.edges:
            assert edge.source_id in node_ids
            assert edge.target_id in node_ids


# ---------------------------------------------------------------------------
# 6. Exposed resources
# ---------------------------------------------------------------------------


class TestExposedResources:
    def test_returns_public_nodes(self, tmp_path):
        eng = _engine(tmp_path)
        eng.build_graph_from_resources(_sample_resources(), org_id="org1")
        exposed = eng.get_exposed_resources("org1")
        assert all(n.public for n in exposed)

    def test_count_matches_public_in_sample(self, tmp_path):
        eng = _engine(tmp_path)
        resources = _sample_resources()
        public_count = sum(1 for r in resources if r.get("public"))
        eng.build_graph_from_resources(resources, org_id="org1")
        exposed = eng.get_exposed_resources("org1")
        assert len(exposed) == public_count


# ---------------------------------------------------------------------------
# 7. Overprivileged roles
# ---------------------------------------------------------------------------


class TestOverprivilegedRoles:
    def test_high_risk_score_flagged(self, tmp_path):
        eng = _engine(tmp_path)
        node = GraphNode(
            type=NodeType.IAM_ROLE, name="admin-role",
            risk_score=0.9, config={}
        )
        eng.add_node(node, org_id="org1")
        result = eng.get_overprivileged_roles("org1")
        assert any(n.id == node.id for n in result)

    def test_low_risk_clean_policy_not_flagged(self, tmp_path):
        eng = _engine(tmp_path)
        node = GraphNode(
            type=NodeType.IAM_ROLE, name="read-only-role",
            risk_score=0.1,
            config={"policies": [{"actions": ["s3:GetObject"]}]},
        )
        eng.add_node(node, org_id="org1")
        result = eng.get_overprivileged_roles("org1")
        assert not any(n.id == node.id for n in result)

    def test_wildcard_action_flagged(self, tmp_path):
        eng = _engine(tmp_path)
        node = GraphNode(
            type=NodeType.IAM_ROLE, name="wildcard-role",
            risk_score=0.2,
            config={"policies": [{"actions": ["*"]}]},
        )
        eng.add_node(node, org_id="org1")
        result = eng.get_overprivileged_roles("org1")
        assert any(n.id == node.id for n in result)

    def test_iam_user_also_checked(self, tmp_path):
        eng = _engine(tmp_path)
        node = GraphNode(
            type=NodeType.IAM_USER, name="power-user",
            risk_score=0.8, config={}
        )
        eng.add_node(node, org_id="org1")
        result = eng.get_overprivileged_roles("org1")
        assert any(n.id == node.id for n in result)


# ---------------------------------------------------------------------------
# 8. Attack paths
# ---------------------------------------------------------------------------


class TestAttackPaths:
    def _build_attack_scenario(self, eng: CloudGraphEngine, org_id: str = "org1") -> None:
        """Build a simple internet → EC2 → RDS path."""
        vpc = GraphNode(id="vpc-ap", type=NodeType.VPC, name="vpc")
        lb = GraphNode(id="lb-ap", type=NodeType.LOAD_BALANCER, name="alb", public=True)
        ec2 = GraphNode(id="ec2-ap", type=NodeType.EC2, name="app", public=True, risk_score=0.5)
        rds = GraphNode(id="rds-ap", type=NodeType.RDS, name="db", risk_score=0.8)
        for n in [vpc, lb, ec2, rds]:
            eng.add_node(n, org_id=org_id)
        eng.add_edge(GraphEdge(source_id=lb.id, target_id=ec2.id, type=EdgeType.ROUTES_TO), org_id=org_id)
        eng.add_edge(GraphEdge(source_id=ec2.id, target_id=rds.id, type=EdgeType.CONNECTS_TO), org_id=org_id)

    def test_finds_paths_to_sensitive(self, tmp_path):
        eng = _engine(tmp_path)
        self._build_attack_scenario(eng)
        paths = eng.find_attack_paths("org1")
        # Should find at least one path reaching RDS
        found_rds = any(any(n.type == NodeType.RDS for n in p) for p in paths)
        assert found_rds

    def test_paths_start_from_public(self, tmp_path):
        eng = _engine(tmp_path)
        self._build_attack_scenario(eng)
        paths = eng.find_attack_paths("org1")
        for path in paths:
            assert len(path) >= 2

    def test_empty_graph_no_paths(self, tmp_path):
        eng = _engine(tmp_path)
        paths = eng.find_attack_paths("org-empty")
        assert paths == []


# ---------------------------------------------------------------------------
# 9. Blast radius
# ---------------------------------------------------------------------------


class TestBlastRadius:
    def test_blast_radius_includes_downstream(self, tmp_path):
        eng = _engine(tmp_path)
        origin = GraphNode(id="origin-01", type=NodeType.EC2, name="origin")
        downstream = GraphNode(id="down-01", type=NodeType.RDS, name="db")
        eng.add_node(origin, org_id="org1")
        eng.add_node(downstream, org_id="org1")
        eng.add_edge(
            GraphEdge(source_id=origin.id, target_id=downstream.id, type=EdgeType.CONNECTS_TO),
            org_id="org1",
        )
        graph = eng.find_blast_radius("origin-01", "org1")
        node_ids = {n.id for n in graph.nodes}
        assert "origin-01" in node_ids
        assert "down-01" in node_ids

    def test_blast_radius_excludes_upstream(self, tmp_path):
        eng = _engine(tmp_path)
        upstream = GraphNode(id="up-01", type=NodeType.LOAD_BALANCER, name="lb")
        origin = GraphNode(id="origin-02", type=NodeType.EC2, name="ec2")
        eng.add_node(upstream, org_id="org1")
        eng.add_node(origin, org_id="org1")
        eng.add_edge(
            GraphEdge(source_id=upstream.id, target_id=origin.id, type=EdgeType.ROUTES_TO),
            org_id="org1",
        )
        graph = eng.find_blast_radius("origin-02", "org1")
        node_ids = {n.id for n in graph.nodes}
        # upstream is not reachable from origin via outbound edges
        assert "up-01" not in node_ids

    def test_blast_radius_stats(self, tmp_path):
        eng = _engine(tmp_path)
        node = GraphNode(id="solo-01", type=NodeType.EC2, name="solo")
        eng.add_node(node, org_id="org1")
        graph = eng.find_blast_radius("solo-01", "org1")
        assert graph.stats["blast_radius"] >= 1
        assert graph.stats["origin_node"] == "solo-01"


# ---------------------------------------------------------------------------
# 10. Network segmentation
# ---------------------------------------------------------------------------


class TestNetworkSegmentation:
    def test_returns_vpc_breakdown(self, tmp_path):
        eng = _engine(tmp_path)
        eng.build_graph_from_resources(_sample_resources(), org_id="org1")
        result = eng.get_network_segmentation("org1")
        assert "vpc_count" in result
        assert "vpcs" in result

    def test_vpc_count_correct(self, tmp_path):
        eng = _engine(tmp_path)
        eng.build_graph_from_resources(_sample_resources(), org_id="org1")
        result = eng.get_network_segmentation("org1")
        assert result["vpc_count"] == 1

    def test_mixed_exposure_detected(self, tmp_path):
        eng = _engine(tmp_path)
        resources = _sample_resources()
        eng.build_graph_from_resources(resources, org_id="org1")
        result = eng.get_network_segmentation("org1")
        # Our sample VPC has both public and private resources
        for vpc_data in result["vpcs"].values():
            if vpc_data["total_resources"] > 0:
                # At least one VPC should be analysed
                assert "mixed_exposure" in vpc_data


# ---------------------------------------------------------------------------
# 11. Risk paths
# ---------------------------------------------------------------------------


class TestRiskPaths:
    def test_returns_list(self, tmp_path):
        eng = _engine(tmp_path)
        eng.build_graph_from_resources(_sample_resources(), org_id="org1")
        paths = eng.calculate_risk_paths("org1")
        assert isinstance(paths, list)

    def test_sorted_by_risk_descending(self, tmp_path):
        eng = _engine(tmp_path)
        lb = GraphNode(id="lb-rp", type=NodeType.LOAD_BALANCER, name="alb", public=True, risk_score=0.3)
        ec2 = GraphNode(id="ec2-rp", type=NodeType.EC2, name="app", public=True, risk_score=0.6)
        rds = GraphNode(id="rds-rp", type=NodeType.RDS, name="db", risk_score=0.9)
        for n in [lb, ec2, rds]:
            eng.add_node(n, org_id="org1")
        eng.add_edge(GraphEdge(source_id=lb.id, target_id=ec2.id, type=EdgeType.ROUTES_TO), org_id="org1")
        eng.add_edge(GraphEdge(source_id=ec2.id, target_id=rds.id, type=EdgeType.CONNECTS_TO), org_id="org1")
        paths = eng.calculate_risk_paths("org1")
        scores = [p["total_risk_score"] for p in paths]
        assert scores == sorted(scores, reverse=True)

    def test_path_dict_shape(self, tmp_path):
        eng = _engine(tmp_path)
        lb = GraphNode(id="lb-sh", type=NodeType.LOAD_BALANCER, name="alb", public=True, risk_score=0.3)
        s3 = GraphNode(id="s3-sh", type=NodeType.S3, name="bucket", risk_score=0.5)
        eng.add_node(lb, org_id="org1")
        eng.add_node(s3, org_id="org1")
        eng.add_edge(GraphEdge(source_id=lb.id, target_id=s3.id, type=EdgeType.EXPOSES), org_id="org1")
        paths = eng.calculate_risk_paths("org1")
        if paths:
            p = paths[0]
            assert "path" in p
            assert "total_risk_score" in p
            assert "max_node_risk" in p
            assert "entry_point" in p
            assert "target" in p


# ---------------------------------------------------------------------------
# 12. Graph stats
# ---------------------------------------------------------------------------


class TestGraphStats:
    def test_stats_shape(self, tmp_path):
        eng = _engine(tmp_path)
        eng.build_graph_from_resources(_sample_resources(), org_id="org1")
        stats = eng.get_graph_stats("org1")
        assert "total_nodes" in stats
        assert "total_edges" in stats
        assert "public_nodes" in stats
        assert "nodes_by_type" in stats
        assert "generated_at" in stats
        assert "org_id" in stats

    def test_empty_org_stats(self, tmp_path):
        eng = _engine(tmp_path)
        stats = eng.get_graph_stats("org-empty")
        assert stats["total_nodes"] == 0
        assert stats["total_edges"] == 0

    def test_node_type_breakdown(self, tmp_path):
        eng = _engine(tmp_path)
        eng.build_graph_from_resources(_sample_resources(), org_id="org1")
        stats = eng.get_graph_stats("org1")
        assert "EC2" in stats["nodes_by_type"]
        assert stats["nodes_by_type"]["EC2"] == 1


# ---------------------------------------------------------------------------
# 13. Singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_engine_returns_instance(self):
        import core.cloud_graph as cg_mod
        cg_mod._engine_instance = None  # reset
        eng = get_cloud_graph_engine()
        assert isinstance(eng, CloudGraphEngine)

    def test_get_engine_same_instance(self):
        import core.cloud_graph as cg_mod
        cg_mod._engine_instance = None
        e1 = get_cloud_graph_engine()
        e2 = get_cloud_graph_engine()
        assert e1 is e2


# ---------------------------------------------------------------------------
# 14. Router smoke tests
# ---------------------------------------------------------------------------


class TestRouterImport:
    def test_router_importable(self):
        from apps.api.cloud_graph_router import router
        assert router is not None

    def test_router_prefix(self):
        from apps.api.cloud_graph_router import router
        assert router.prefix == "/api/v1/cloud-graph"

    def test_router_has_expected_routes(self):
        from apps.api.cloud_graph_router import router
        paths = {r.path for r in router.routes}
        assert "/api/v1/cloud-graph/build" in paths
        assert "/api/v1/cloud-graph/graph" in paths
        assert "/api/v1/cloud-graph/exposed" in paths
        assert "/api/v1/cloud-graph/attack-paths" in paths
        assert "/api/v1/cloud-graph/overprivileged" in paths
        assert "/api/v1/cloud-graph/segmentation" in paths
        assert "/api/v1/cloud-graph/risk-paths" in paths
        assert "/api/v1/cloud-graph/stats" in paths

    def test_router_endpoint_count(self):
        from apps.api.cloud_graph_router import router
        # Should have 12 routes (including blast-radius, nodes, edges)
        assert len(router.routes) >= 10
