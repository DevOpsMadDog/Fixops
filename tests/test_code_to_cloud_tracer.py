"""Tests for Code-to-Cloud Tracer."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.code_to_cloud_tracer import (
    CodeToCloudTracer,
    TraceEdge,
    TraceEdgeType,
    TraceNode,
    TraceNodeType,
    TraceResult,
    get_code_to_cloud_tracer,
)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------
class TestTraceNodeType:
    def test_all_node_types(self):
        expected = [
            "source_code", "git_commit", "build_artifact", "container_image",
            "container_registry", "k8s_pod", "k8s_deployment", "cloud_instance",
            "cloud_service", "vulnerability", "finding",
        ]
        for val in expected:
            assert TraceNodeType(val).value == val

    def test_count(self):
        assert len(TraceNodeType) == 11


class TestTraceEdgeType:
    def test_all_edge_types(self):
        expected = [
            "committed_in", "built_into", "pushed_to", "deployed_as",
            "runs_on", "contains", "exploits", "exposes",
        ]
        for val in expected:
            assert TraceEdgeType(val).value == val

    def test_count(self):
        assert len(TraceEdgeType) == 8


# ---------------------------------------------------------------------------
# TraceNode / TraceEdge tests
# ---------------------------------------------------------------------------
class TestTraceNode:
    def test_to_dict(self):
        node = TraceNode(
            node_id="node-1",
            node_type=TraceNodeType.SOURCE_CODE,
            name="main.py",
            metadata={"line": 42},
        )
        d = node.to_dict()
        assert d["node_id"] == "node-1"
        assert d["node_type"] == "source_code"
        assert d["name"] == "main.py"
        assert d["metadata"]["line"] == 42

    def test_default_metadata(self):
        node = TraceNode(
            node_id="n", node_type=TraceNodeType.VULNERABILITY, name="CVE-2024-1234"
        )
        assert node.metadata == {}


class TestTraceEdge:
    def test_to_dict(self):
        edge = TraceEdge(
            source_id="a", target_id="b", edge_type=TraceEdgeType.EXPLOITS
        )
        d = edge.to_dict()
        assert d["source_id"] == "a"
        assert d["target_id"] == "b"
        assert d["edge_type"] == "exploits"


# ---------------------------------------------------------------------------
# TraceResult tests
# ---------------------------------------------------------------------------
class TestTraceResult:
    def test_to_dict(self):
        node = TraceNode("n1", TraceNodeType.VULNERABILITY, "CVE-2024-1")
        edge = TraceEdge("n1", "n2", TraceEdgeType.EXPLOITS)
        result = TraceResult(
            trace_id="t-1",
            vulnerability_id="CVE-2024-1",
            nodes=[node],
            edges=[edge],
            attack_path_length=1,
            risk_amplification=1.5,
            cloud_exposure="internal",
            remediation_points=[],
        )
        d = result.to_dict()
        assert d["trace_id"] == "t-1"
        assert d["vulnerability_id"] == "CVE-2024-1"
        assert len(d["nodes"]) == 1
        assert len(d["edges"]) == 1
        assert d["attack_path_length"] == 1
        assert d["risk_amplification"] == 1.5
        assert d["cloud_exposure"] == "internal"
        assert "timestamp" in d


# ---------------------------------------------------------------------------
# CodeToCloudTracer tests
# ---------------------------------------------------------------------------
class TestCodeToCloudTracer:
    def test_trace_minimal(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(vulnerability_id="CVE-2024-0001")
        assert result.vulnerability_id == "CVE-2024-0001"
        assert result.trace_id.startswith("trace-")
        assert len(result.nodes) == 1  # just the vulnerability node
        assert result.nodes[0].node_type == TraceNodeType.VULNERABILITY
        assert result.cloud_exposure == "none"
        assert result.risk_amplification == 1.0  # none exposure, 0 edges

    def test_trace_with_source_file(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-2024-0002",
            source_file="app/main.py",
            source_line=42,
        )
        assert len(result.nodes) == 2  # vuln + source
        source_node = [n for n in result.nodes if n.node_type == TraceNodeType.SOURCE_CODE][0]
        assert source_node.name == "app/main.py"
        assert source_node.metadata["line"] == 42
        # Should have EXPLOITS edge
        assert any(e.edge_type == TraceEdgeType.EXPLOITS for e in result.edges)

    def test_trace_with_git_commit(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-2024-0003",
            source_file="src/utils.py",
            git_commit="abc123def456789",
        )
        commit_nodes = [n for n in result.nodes if n.node_type == TraceNodeType.GIT_COMMIT]
        assert len(commit_nodes) == 1
        assert commit_nodes[0].metadata["full_sha"] == "abc123def456789"
        assert any(e.edge_type == TraceEdgeType.COMMITTED_IN for e in result.edges)

    def test_trace_with_container_image(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-2024-0004",
            source_file="app.py",
            git_commit="abc123",
            container_image="myapp:latest",
        )
        img_nodes = [n for n in result.nodes if n.node_type == TraceNodeType.CONTAINER_IMAGE]
        assert len(img_nodes) == 1
        assert img_nodes[0].name == "myapp:latest"
        assert any(e.edge_type == TraceEdgeType.BUILT_INTO for e in result.edges)

    def test_trace_with_k8s(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-2024-0005",
            container_image="myapp:v2",
            k8s_namespace="production",
            k8s_deployment="myapp-deploy",
        )
        k8s_nodes = [n for n in result.nodes if n.node_type == TraceNodeType.K8S_DEPLOYMENT]
        assert len(k8s_nodes) == 1
        assert k8s_nodes[0].name == "myapp-deploy"
        assert k8s_nodes[0].metadata["namespace"] == "production"
        assert any(e.edge_type == TraceEdgeType.DEPLOYED_AS for e in result.edges)

    def test_trace_with_cloud_service(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-2024-0006",
            cloud_service="aws-ecs",
            cloud_region="us-east-1",
            internet_facing=False,
        )
        cloud_nodes = [n for n in result.nodes if n.node_type == TraceNodeType.CLOUD_SERVICE]
        assert len(cloud_nodes) == 1
        assert cloud_nodes[0].metadata["region"] == "us-east-1"
        assert result.cloud_exposure == "internal"

    def test_trace_internet_facing(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-2024-0007",
            cloud_service="alb-public",
            internet_facing=True,
        )
        assert result.cloud_exposure == "internet"
        assert result.risk_amplification > 1.0

    def test_risk_amplification_increases_with_path(self):
        tracer = CodeToCloudTracer()
        short = tracer.trace(vulnerability_id="CVE-short")
        long_trace = tracer.trace(
            vulnerability_id="CVE-long",
            source_file="app.py",
            git_commit="abc123",
            container_image="app:v1",
            k8s_deployment="deploy",
            cloud_service="ecs",
            internet_facing=True,
        )
        assert long_trace.risk_amplification > short.risk_amplification

    def test_full_trace_chain(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-2024-FULL",
            source_file="vulnerable.py",
            source_line=100,
            git_commit="deadbeef12345678",
            container_image="myapp:1.2.3",
            k8s_namespace="prod",
            k8s_deployment="myapp",
            cloud_service="aws-eks",
            cloud_region="eu-west-1",
            internet_facing=True,
        )
        assert len(result.nodes) >= 5
        assert result.cloud_exposure == "internet"
        assert result.attack_path_length > 0
        assert result.duration_ms >= 0

    def test_remediation_points_source(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-rem",
            source_file="vuln.py",
            source_line=10,
        )
        code_fixes = [r for r in result.remediation_points if r["type"] == "code_fix"]
        assert len(code_fixes) == 1
        assert "vuln.py" in code_fixes[0]["action"]

    def test_remediation_points_container(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-rem2",
            container_image="app:old",
        )
        rebuilds = [r for r in result.remediation_points if r["type"] == "image_rebuild"]
        assert len(rebuilds) == 1

    def test_remediation_points_k8s(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-rem3",
            container_image="app:old",
            k8s_deployment="deploy",
        )
        rollouts = [r for r in result.remediation_points if r["type"] == "deploy_rollout"]
        assert len(rollouts) == 1

    def test_remediation_points_internet_facing(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-rem4",
            cloud_service="elb",
            internet_facing=True,
        )
        net_iso = [r for r in result.remediation_points if r["type"] == "network_isolation"]
        assert len(net_iso) == 1
        assert net_iso[0]["priority"] == "critical"

    def test_no_remediation_for_cloud_internal(self):
        tracer = CodeToCloudTracer()
        result = tracer.trace(
            vulnerability_id="CVE-rem5",
            cloud_service="internal-svc",
            internet_facing=False,
        )
        net_iso = [r for r in result.remediation_points if r["type"] == "network_isolation"]
        assert len(net_iso) == 0

    def test_risk_multipliers(self):
        assert CodeToCloudTracer.RISK_MULTIPLIERS["internet"] == 3.0
        assert CodeToCloudTracer.RISK_MULTIPLIERS["internal"] == 1.5
        assert CodeToCloudTracer.RISK_MULTIPLIERS["none"] == 1.0


# ---------------------------------------------------------------------------
# Singleton tests
# ---------------------------------------------------------------------------
class TestGetCodeToCloudTracer:
    def test_returns_instance(self):
        tracer = get_code_to_cloud_tracer()
        assert isinstance(tracer, CodeToCloudTracer)

    def test_returns_same_instance(self):
        t1 = get_code_to_cloud_tracer()
        t2 = get_code_to_cloud_tracer()
        assert t1 is t2
