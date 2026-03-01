"""Tests for risk.dependency_graph module — DependencyGraphBuilder.

Covers: node/edge creation, SBOM parsing, transitive dependency search,
vulnerable path detection, JSON/DOT export.
"""

from __future__ import annotations

import pytest

from risk.dependency_graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyGraphBuilder,
    DependencyNode,
)


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def builder() -> DependencyGraphBuilder:
    return DependencyGraphBuilder()


@pytest.fixture
def sample_sbom() -> dict:
    return {
        "components": [
            {
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
                "vulnerabilities": [],
            },
            {
                "name": "flask",
                "version": "3.0.0",
                "purl": "pkg:pypi/flask@3.0.0",
                "vulnerabilities": [
                    {"cve_id": "CVE-2024-0001", "severity": "high"}
                ],
            },
            {
                "name": "express",
                "version": "4.18.2",
                "purl": "pkg:npm/express@4.18.2",
                "vulnerabilities": [],
            },
            {
                "name": "spring-core",
                "version": "6.1.0",
                "purl": "pkg:maven/org.springframework/spring-core@6.1.0",
                "vulnerabilities": [],
            },
            {
                "name": "unknown-pkg",
                "version": "1.0.0",
                "purl": "",
                "vulnerabilities": [],
            },
        ]
    }


# ── DependencyNode ────────────────────────────────────────────────────────


class TestDependencyNode:
    def test_default_values(self):
        node = DependencyNode(
            name="foo", version="1.0", package_manager="pip"
        )
        assert node.vulnerabilities == []
        assert node.health_score == 0.0
        assert node.metadata == {}

    def test_with_vulns(self):
        node = DependencyNode(
            name="bar",
            version="2.0",
            package_manager="npm",
            vulnerabilities=[{"cve_id": "CVE-2024-0001"}],
            health_score=75.0,
        )
        assert len(node.vulnerabilities) == 1
        assert node.health_score == 75.0


# ── DependencyEdge ────────────────────────────────────────────────────────


class TestDependencyEdge:
    def test_creation(self):
        edge = DependencyEdge(
            source="a@1.0", target="b@2.0", relationship="direct"
        )
        assert edge.source == "a@1.0"
        assert edge.target == "b@2.0"
        assert edge.relationship == "direct"
        assert edge.metadata == {}


# ── DependencyGraph ───────────────────────────────────────────────────────


class TestDependencyGraph:
    def test_empty_graph(self):
        g = DependencyGraph()
        assert g.nodes == {}
        assert g.edges == []
        assert g.root_package is None


# ── DependencyGraphBuilder — SBOM parsing ─────────────────────────────────


class TestBuildFromSBOM:
    def test_builds_nodes_from_components(self, builder, sample_sbom):
        graph = builder.build_from_sbom(sample_sbom)
        assert len(graph.nodes) == 5

    def test_detects_pypi_package_manager(self, builder, sample_sbom):
        graph = builder.build_from_sbom(sample_sbom)
        assert graph.nodes["requests@2.31.0"].package_manager == "pip"

    def test_detects_npm_package_manager(self, builder, sample_sbom):
        graph = builder.build_from_sbom(sample_sbom)
        assert graph.nodes["express@4.18.2"].package_manager == "npm"

    def test_detects_maven_package_manager(self, builder, sample_sbom):
        graph = builder.build_from_sbom(sample_sbom)
        assert graph.nodes["spring-core@6.1.0"].package_manager == "maven"

    def test_unknown_package_manager_for_empty_purl(self, builder, sample_sbom):
        graph = builder.build_from_sbom(sample_sbom)
        assert graph.nodes["unknown-pkg@1.0.0"].package_manager == "unknown"

    def test_preserves_vulnerabilities(self, builder, sample_sbom):
        graph = builder.build_from_sbom(sample_sbom)
        flask = graph.nodes["flask@3.0.0"]
        assert len(flask.vulnerabilities) == 1
        assert flask.vulnerabilities[0]["cve_id"] == "CVE-2024-0001"

    def test_handles_packages_key(self, builder):
        """Test SBOM with 'packages' instead of 'components'."""
        sbom = {
            "packages": [
                {"name": "pkg1", "version": "1.0", "purl": "pkg:npm/pkg1@1.0"}
            ]
        }
        graph = builder.build_from_sbom(sbom)
        assert len(graph.nodes) == 1

    def test_empty_sbom(self, builder):
        graph = builder.build_from_sbom({})
        assert len(graph.nodes) == 0

    def test_missing_version_defaults(self, builder):
        sbom = {"components": [{"name": "x", "purl": ""}]}
        graph = builder.build_from_sbom(sbom)
        assert graph.nodes["x@unknown"].version == "unknown"


# ── DependencyGraphBuilder — manifest ─────────────────────────────────────


class TestBuildFromManifest:
    def test_sets_root_package(self, builder):
        graph = builder.build_from_manifest("/app/package.json", "npm")
        assert graph.root_package == "/app/package.json"

    def test_returns_empty_graph(self, builder):
        graph = builder.build_from_manifest("/app/requirements.txt", "pip")
        assert len(graph.nodes) == 0


# ── DependencyGraphBuilder — add_node / add_edge ─────────────────────────


class TestGraphBuilderMutations:
    def test_add_node(self, builder):
        node = DependencyNode(name="x", version="1.0", package_manager="pip")
        builder.add_node(node)
        assert "x@1.0" in builder.graph.nodes

    def test_add_edge(self, builder):
        builder.add_edge("a@1.0", "b@2.0", "transitive")
        assert len(builder.graph.edges) == 1
        assert builder.graph.edges[0].relationship == "transitive"


# ── Transitive dependencies ───────────────────────────────────────────────


class TestTransitiveDependencies:
    def test_finds_chain(self, builder):
        for name, ver in [("a", "1"), ("b", "1"), ("c", "1")]:
            builder.add_node(
                DependencyNode(name=name, version=ver, package_manager="pip")
            )
        builder.add_edge("a@1", "b@1")
        builder.add_edge("b@1", "c@1")
        result = builder.find_transitive_dependencies("a")
        assert "a@1" in result
        assert "b@1" in result
        assert "c@1" in result

    def test_no_package_found(self, builder):
        result = builder.find_transitive_dependencies("nonexistent")
        assert result == []

    def test_handles_cycles(self, builder):
        for name in ["x", "y"]:
            builder.add_node(
                DependencyNode(name=name, version="1", package_manager="pip")
            )
        builder.add_edge("x@1", "y@1")
        builder.add_edge("y@1", "x@1")
        result = builder.find_transitive_dependencies("x")
        assert len(result) == 2


# ── Vulnerable paths ─────────────────────────────────────────────────────


class TestVulnerablePaths:
    def test_finds_vulnerable_nodes(self, builder):
        builder.add_node(
            DependencyNode(
                name="vuln",
                version="1.0",
                package_manager="pip",
                vulnerabilities=[{"cve_id": "CVE-2024-9999"}],
            )
        )
        builder.graph.root_package = "vuln@1.0"
        paths = builder.find_vulnerable_paths("CVE-2024-9999")
        assert len(paths) == 1

    def test_no_vulnerable_nodes(self, builder):
        builder.add_node(
            DependencyNode(name="safe", version="1.0", package_manager="pip")
        )
        paths = builder.find_vulnerable_paths("CVE-2024-0001")
        assert paths == []

    def test_path_from_root(self, builder):
        for name in ["root", "mid", "vuln"]:
            builder.add_node(
                DependencyNode(
                    name=name,
                    version="1",
                    package_manager="pip",
                    vulnerabilities=(
                        [{"cve_id": "CVE-2024-1111"}]
                        if name == "vuln"
                        else []
                    ),
                )
            )
        builder.add_edge("root@1", "mid@1")
        builder.add_edge("mid@1", "vuln@1")
        builder.graph.root_package = "root@1"

        paths = builder.find_vulnerable_paths("CVE-2024-1111")
        assert len(paths) == 1
        assert paths[0] == ["root@1", "mid@1", "vuln@1"]

    def test_no_root_returns_empty_path(self, builder):
        builder.add_node(
            DependencyNode(
                name="x",
                version="1",
                package_manager="pip",
                vulnerabilities=[{"cve_id": "CVE-2024-0001"}],
            )
        )
        # No root_package set
        paths = builder.find_vulnerable_paths("CVE-2024-0001")
        assert all(p == [] for p in paths)


# ── JSON / DOT export ────────────────────────────────────────────────────


class TestExport:
    def test_to_json(self, builder, sample_sbom):
        builder.build_from_sbom(sample_sbom)
        j = builder.to_json()
        assert "nodes" in j
        assert "edges" in j
        assert "root" in j
        assert len(j["nodes"]) == 5

    def test_json_node_structure(self, builder):
        builder.add_node(
            DependencyNode(
                name="pkg",
                version="1.0",
                package_manager="pip",
                health_score=80.0,
                vulnerabilities=[{"cve_id": "CVE-1"}],
            )
        )
        j = builder.to_json()
        node = j["nodes"][0]
        assert node["name"] == "pkg"
        assert node["version"] == "1.0"
        assert node["vulnerability_count"] == 1
        assert node["health_score"] == 80.0

    def test_to_dot(self, builder):
        builder.add_node(
            DependencyNode(
                name="a",
                version="1",
                package_manager="pip",
                health_score=80.0,
            )
        )
        builder.add_node(
            DependencyNode(
                name="b",
                version="1",
                package_manager="pip",
                vulnerabilities=[{"cve_id": "CVE-1"}],
            )
        )
        builder.add_node(
            DependencyNode(
                name="c",
                version="1",
                package_manager="pip",
                health_score=30.0,
            )
        )
        builder.add_edge("a@1", "b@1")
        dot = builder.to_dot()
        assert "digraph DependencyGraph" in dot
        assert "color=green" in dot  # healthy node
        assert "color=red" in dot  # vulnerable node
        assert "color=orange" in dot  # low health
        assert '"a@1" -> "b@1"' in dot
