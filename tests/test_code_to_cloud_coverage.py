"""Tests for core.code_to_cloud_tracer and core.causal_inference."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.code_to_cloud_tracer import (  # noqa: E402
    CodeToCloudTracer,
    TraceEdge,
    TraceEdgeType,
    TraceNode,
    TraceNodeType,
    get_code_to_cloud_tracer,
)
from core.causal_inference import (  # noqa: E402
    CausalRelation,
    SecurityFactor,
)


# ---------------------------------------------------------------------------
# TraceNodeType / TraceEdgeType enums
# ---------------------------------------------------------------------------


class TestTraceEnums:
    def test_node_types(self):
        assert TraceNodeType.SOURCE_CODE.value == "source_code"
        assert TraceNodeType.CONTAINER_IMAGE.value == "container_image"
        assert TraceNodeType.K8S_DEPLOYMENT.value == "k8s_deployment"
        assert TraceNodeType.CLOUD_SERVICE.value == "cloud_service"
        assert TraceNodeType.VULNERABILITY.value == "vulnerability"
        assert len(TraceNodeType) == 11

    def test_edge_types(self):
        assert TraceEdgeType.COMMITTED_IN.value == "committed_in"
        assert TraceEdgeType.BUILT_INTO.value == "built_into"
        assert TraceEdgeType.DEPLOYED_AS.value == "deployed_as"
        assert TraceEdgeType.RUNS_ON.value == "runs_on"
        assert TraceEdgeType.EXPLOITS.value == "exploits"
        assert len(TraceEdgeType) == 8


# ---------------------------------------------------------------------------
# TraceNode / TraceEdge data classes
# ---------------------------------------------------------------------------


class TestTraceNode:
    def test_create(self):
        node = TraceNode(
            node_id="n-1",
            node_type=TraceNodeType.SOURCE_CODE,
            name="app.py",
            metadata={"line": 42},
        )
        assert node.node_id == "n-1"
        assert node.name == "app.py"

    def test_to_dict(self):
        node = TraceNode("n-2", TraceNodeType.CONTAINER_IMAGE, "myapp:latest")
        d = node.to_dict()
        assert d["node_id"] == "n-2"
        assert d["node_type"] == "container_image"
        assert d["name"] == "myapp:latest"


class TestTraceEdge:
    def test_create(self):
        edge = TraceEdge("n-1", "n-2", TraceEdgeType.BUILT_INTO)
        assert edge.source_id == "n-1"
        assert edge.target_id == "n-2"

    def test_to_dict(self):
        edge = TraceEdge("a", "b", TraceEdgeType.EXPLOITS, {"severity": "high"})
        d = edge.to_dict()
        assert d["source_id"] == "a"
        assert d["edge_type"] == "exploits"
        assert d["metadata"]["severity"] == "high"


# ---------------------------------------------------------------------------
# CodeToCloudTracer
# ---------------------------------------------------------------------------


class TestCodeToCloudTracer:
    def setup_method(self):
        self.tracer = CodeToCloudTracer()

    def test_minimal_trace(self):
        result = self.tracer.trace(vulnerability_id="CVE-2024-1234")
        assert result.vulnerability_id == "CVE-2024-1234"
        assert result.trace_id.startswith("trace-")
        assert len(result.nodes) == 1  # Only vuln node
        assert len(result.edges) == 0
        assert result.cloud_exposure == "none"
        assert result.risk_amplification == 1.0

    def test_source_code_trace(self):
        result = self.tracer.trace(
            vulnerability_id="CVE-2024-5678",
            source_file="app/login.py",
            source_line=42,
        )
        assert len(result.nodes) == 2  # vuln + source
        assert len(result.edges) == 1  # exploits
        assert result.remediation_points[0]["type"] == "code_fix"
        assert "login.py" in result.remediation_points[0]["action"]

    def test_source_with_git_commit(self):
        result = self.tracer.trace(
            vulnerability_id="CVE-2024-9999",
            source_file="app.py",
            source_line=10,
            git_commit="abc123def456789",
        )
        assert len(result.nodes) == 3  # vuln + source + commit
        assert len(result.edges) == 2  # exploits + committed_in

    def test_full_trace_internet_facing(self):
        result = self.tracer.trace(
            vulnerability_id="CVE-2024-FULL",
            source_file="api/handler.py",
            source_line=100,
            git_commit="a1b2c3d4e5f6",
            container_image="registry.io/myapp:v1.0",
            k8s_namespace="production",
            k8s_deployment="api-deploy",
            cloud_service="aws-ecs",
            cloud_region="us-east-1",
            internet_facing=True,
        )
        assert result.cloud_exposure == "internet"
        assert result.risk_amplification > 3.0
        assert result.attack_path_length >= 4
        assert len(result.nodes) >= 5
        # Should have critical remediation for internet-facing
        priorities = [p["priority"] for p in result.remediation_points]
        assert "critical" in priorities

    def test_internal_cloud_service(self):
        result = self.tracer.trace(
            vulnerability_id="CVE-INT",
            cloud_service="internal-svc",
            internet_facing=False,
        )
        assert result.cloud_exposure == "internal"
        assert result.risk_amplification >= 1.5

    def test_container_without_git(self):
        result = self.tracer.trace(
            vulnerability_id="CVE-CONT",
            source_file="src/main.py",
            container_image="myapp:latest",
        )
        assert len(result.nodes) >= 3
        # Should have image_rebuild remediation
        types = [p["type"] for p in result.remediation_points]
        assert "image_rebuild" in types

    def test_k8s_deployment_remediation(self):
        result = self.tracer.trace(
            vulnerability_id="CVE-K8S",
            source_file="app.py",
            git_commit="abc123",
            container_image="img:v1",
            k8s_deployment="web-deploy",
        )
        types = [p["type"] for p in result.remediation_points]
        assert "deploy_rollout" in types

    def test_trace_result_to_dict(self):
        result = self.tracer.trace(
            vulnerability_id="CVE-DICT",
            source_file="test.py",
        )
        d = result.to_dict()
        assert "trace_id" in d
        assert "nodes" in d
        assert "edges" in d
        assert "remediation_points" in d
        assert "timestamp" in d

    def test_risk_multipliers(self):
        assert CodeToCloudTracer.RISK_MULTIPLIERS["internet"] == 3.0
        assert CodeToCloudTracer.RISK_MULTIPLIERS["internal"] == 1.5
        assert CodeToCloudTracer.RISK_MULTIPLIERS["none"] == 1.0


class TestGetTracer:
    def test_singleton(self):
        tracer = get_code_to_cloud_tracer()
        assert isinstance(tracer, CodeToCloudTracer)


# ---------------------------------------------------------------------------
# CausalRelation / SecurityFactor enums
# ---------------------------------------------------------------------------


class TestCausalInferenceEnums:
    def test_causal_relations(self):
        assert CausalRelation.ENABLES.value == "enables"
        assert CausalRelation.CAUSES.value == "causes"
        assert CausalRelation.AMPLIFIES.value == "amplifies"
        assert CausalRelation.MITIGATES.value == "mitigates"
        assert CausalRelation.REQUIRES.value == "requires"
        assert CausalRelation.CORRELATES.value == "correlates"
        assert len(CausalRelation) == 6

    def test_security_factors(self):
        # Vulnerability factors
        assert SecurityFactor.VULNERABILITY_EXISTS.value == "vulnerability_exists"
        assert SecurityFactor.CODE_REACHABLE.value == "code_reachable"
        assert SecurityFactor.EXPLOIT_AVAILABLE.value == "exploit_available"
        # Control factors
        assert SecurityFactor.WAF_ENABLED.value == "waf_enabled"
        assert SecurityFactor.PATCHED.value == "patched"
        # Attack factors
        assert SecurityFactor.ATTACK_SUCCESSFUL.value == "attack_successful"
        assert len(SecurityFactor) == 16
