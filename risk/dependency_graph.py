"""FixOps Dependency Graph Visualization

Proprietary dependency graph construction and visualization.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class DependencyNode:
    """Dependency graph node."""
    
    name: str
    version: str
    package_manager: str
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    health_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyEdge:
    """Dependency graph edge."""
    
    source: str
    target: str
    relationship: str  # direct, transitive, peer
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyGraph:
    """Dependency graph representation."""
    
    nodes: Dict[str, DependencyNode] = field(default_factory=dict)
    edges: List[DependencyEdge] = field(default_factory=list)
    root_package: Optional[str] = None


class DependencyGraphBuilder:
    """FixOps Dependency Graph Builder - Proprietary graph construction."""
    
    def __init__(self):
        """Initialize graph builder."""
        self.graph = DependencyGraph()
    
    def build_from_sbom(self, sbom: Dict[str, Any]) -> DependencyGraph:
        """Build dependency graph from SBOM."""
        self.graph = DependencyGraph()
        
        # Extract components from SBOM
        components = sbom.get("components", []) or sbom.get("packages", [])
        
        # Build nodes
        for component in components:
            name = component.get("name", "")
            version = component.get("version", "unknown")
            purl = component.get("purl", "")
            
            # Extract package manager from PURL
            package_manager = "unknown"
            if purl.startswith("pkg:pypi/"):
                package_manager = "pip"
            elif purl.startswith("pkg:npm/"):
                package_manager = "npm"
            elif purl.startswith("pkg:maven/"):
                package_manager = "maven"
            
            node = DependencyNode(
                name=name,
                version=version,
                package_manager=package_manager,
                vulnerabilities=component.get("vulnerabilities", []),
                metadata=component,
            )
            
            self.graph.nodes[f"{name}@{version}"] = node
        
        # Build edges (dependencies)
        # This would parse dependency relationships from SBOM
        # For now, simplified implementation
        
        return self.graph
    
    def build_from_manifest(
        self, manifest_path: str, package_manager: str
    ) -> DependencyGraph:
        """Build dependency graph from package manifest."""
        # This would parse package.json, requirements.txt, pom.xml, etc.
        # and build the dependency graph
        
        self.graph = DependencyGraph()
        self.graph.root_package = manifest_path
        
        # Simplified implementation
        # In real implementation, would parse manifest and resolve dependencies
        
        return self.graph
    
    def add_node(self, node: DependencyNode):
        """Add node to graph."""
        key = f"{node.name}@{node.version}"
        self.graph.nodes[key] = node
    
    def add_edge(self, source: str, target: str, relationship: str = "direct"):
        """Add edge to graph."""
        edge = DependencyEdge(
            source=source,
            target=target,
            relationship=relationship,
        )
        self.graph.edges.append(edge)
    
    def find_transitive_dependencies(self, package_name: str) -> List[str]:
        """Find all transitive dependencies."""
        visited: Set[str] = set()
        result: List[str] = []
        
        def dfs(node_key: str):
            if node_key in visited:
                return
            visited.add(node_key)
            result.append(node_key)
            
            # Find all edges from this node
            for edge in self.graph.edges:
                if edge.source == node_key:
                    dfs(edge.target)
        
        # Find starting node
        start_key = None
        for key in self.graph.nodes.keys():
            if package_name in key:
                start_key = key
                break
        
        if start_key:
            dfs(start_key)
        
        return result
    
    def find_vulnerable_paths(self, vulnerability_cve: str) -> List[List[str]]:
        """Find all paths containing a vulnerability."""
        vulnerable_nodes = [
            key
            for key, node in self.graph.nodes.items()
            if any(v.get("cve_id") == vulnerability_cve for v in node.vulnerabilities)
        ]
        
        paths = []
        for vuln_node in vulnerable_nodes:
            # Find path from root to vulnerable node
            path = self._find_path_to_node(vuln_node)
            if path:
                paths.append(path)
        
        return paths
    
    def _find_path_to_node(self, target: str) -> List[str]:
        """Find path from root to target node."""
        if not self.graph.root_package:
            return []
        
        # BFS to find path
        queue = [(self.graph.root_package, [self.graph.root_package])]
        visited = {self.graph.root_package}
        
        while queue:
            current, path = queue.pop(0)
            
            if current == target:
                return path
            
            # Find edges from current node
            for edge in self.graph.edges:
                if edge.source == current and edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge.target]))
        
        return []
    
    def to_json(self) -> Dict[str, Any]:
        """Convert graph to JSON for visualization."""
        return {
            "nodes": [
                {
                    "id": key,
                    "name": node.name,
                    "version": node.version,
                    "package_manager": node.package_manager,
                    "vulnerability_count": len(node.vulnerabilities),
                    "health_score": node.health_score,
                }
                for key, node in self.graph.nodes.items()
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "relationship": edge.relationship,
                }
                for edge in self.graph.edges
            ],
            "root": self.graph.root_package,
        }
    
    def to_dot(self) -> str:
        """Convert graph to DOT format for Graphviz."""
        lines = ["digraph DependencyGraph {"]
        lines.append("  rankdir=LR;")
        lines.append("  node [shape=box];")
        
        # Add nodes
        for key, node in self.graph.nodes.items():
            label = f"{node.name}\\n{node.version}"
            if node.vulnerabilities:
                color = "red"
            elif node.health_score < 50:
                color = "orange"
            else:
                color = "green"
            
            lines.append(f'  "{key}" [label="{label}", color={color}];')
        
        # Add edges
        for edge in self.graph.edges:
            lines.append(f'  "{edge.source}" -> "{edge.target}";')
        
        lines.append("}")
        return "\n".join(lines)
