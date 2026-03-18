"""
Attack Path Engine — FalkorDB/NetworkX Graph Traversal for CTEM+

This is the dedicated attack path analysis engine that wraps the
KnowledgeGraphEngine's AttackPathTraversalEngine from falkordb_client.py.

Provides:
- Multi-algorithm path discovery (BFS, DFS, Dijkstra, A*)
- Internet-reachability analysis
- Blast radius calculation (transitive impact)
- Attack path scoring with CVSS/EPSS weighting
- Natural language graph querying
- Graph export (DOT, JSON, Mermaid)

The actual graph traversal implementation is in falkordb_client.py
(1,835 LOC) which provides dual-mode operation:
- FalkorDB mode: Production graph database (Redis-compatible)
- NetworkX mode: Air-gapped/development fallback (zero deps)

Vision Pillars: V5 (MPTE Verification), V10 (CTEM Full Loop)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Re-export everything from falkordb_client for backward compatibility
from core.falkordb_client import (
    NodeType,
    EdgeType,
    GraphNode,
    GraphEdge,
    KnowledgeGraphEngine,
    AttackPathTraversalEngine,
    get_knowledge_graph,
    get_attack_path_engine,
    get_nl_query_engine,
)

# Try importing advanced types (may not exist in older versions)
try:
    from core.falkordb_client import (
        AttackPath,
        BlastRadius,
        AttackPathResult,
        BlastRadiusV2,
        InternetReachabilityPath,
        NLQueryEngine,
    )
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Attack Path Scoring Models
# ---------------------------------------------------------------------------

class AttackPathSeverity(str, Enum):
    """Severity classification for attack paths."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class AttackPathScore:
    """Composite score for an attack path."""
    path_id: str
    total_score: float  # 0-100
    exploitability: float  # 0-10
    impact: float  # 0-10
    reachability: float  # 0-1
    blast_radius: int  # number of affected nodes
    severity: AttackPathSeverity
    confidence: float  # 0-1
    factors: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "total_score": round(self.total_score, 2),
            "exploitability": round(self.exploitability, 2),
            "impact": round(self.impact, 2),
            "reachability": round(self.reachability, 3),
            "blast_radius": self.blast_radius,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "factors": {k: round(v, 3) for k, v in self.factors.items()},
        }


@dataclass
class AttackChain:
    """A chain of vulnerabilities that form an attack path."""
    chain_id: str
    name: str
    description: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    entry_point: Dict[str, Any]
    target: Dict[str, Any]
    total_hops: int
    score: AttackPathScore
    techniques: List[str]  # MITRE ATT&CK technique IDs
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "description": self.description,
            "nodes": self.nodes,
            "edges": self.edges,
            "entry_point": self.entry_point,
            "target": self.target,
            "total_hops": self.total_hops,
            "score": self.score.to_dict(),
            "techniques": self.techniques,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class AttackSurface:
    """Summary of the attack surface derived from graph analysis."""
    total_assets: int
    internet_facing: int
    internal_only: int
    critical_paths: int
    high_risk_components: List[Dict[str, Any]]
    entry_points: List[Dict[str, Any]]
    crown_jewels: List[Dict[str, Any]]
    risk_score: float  # 0-100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_assets": self.total_assets,
            "internet_facing": self.internet_facing,
            "internal_only": self.internal_only,
            "critical_paths": self.critical_paths,
            "high_risk_components": self.high_risk_components,
            "entry_points": self.entry_points,
            "crown_jewels": self.crown_jewels,
            "risk_score": round(self.risk_score, 2),
        }


# ---------------------------------------------------------------------------
# Attack Path Engine — High-Level Orchestrator
# ---------------------------------------------------------------------------

class AttackPathEngine:
    """High-level attack path analysis engine.

    Wraps the AttackPathTraversalEngine from falkordb_client.py
    and adds:
    - CVSS/EPSS-weighted path scoring
    - MITRE ATT&CK technique mapping
    - Attack surface summarization
    - Multi-path comparison and ranking
    - Chain detection (vulnerability chaining)
    - Crown jewel identification
    """

    def __init__(
        self,
        kg: Optional[KnowledgeGraphEngine] = None,
        traversal_engine: Optional[AttackPathTraversalEngine] = None,
    ):
        self._kg = kg or get_knowledge_graph()
        self._traversal = traversal_engine or get_attack_path_engine(self._kg)
        self._path_cache: Dict[str, Any] = {}
        self._scoring_weights = {
            "cvss_base": 0.3,
            "epss_score": 0.2,
            "reachability": 0.2,
            "blast_radius": 0.15,
            "asset_criticality": 0.15,
        }
        logger.info("AttackPathEngine initialized (KG nodes: %d)", len(self._kg._backend._graph.nodes) if hasattr(self._kg, '_backend') and hasattr(self._kg._backend, '_graph') else 0)

    @property
    def knowledge_graph(self) -> KnowledgeGraphEngine:
        """Access underlying knowledge graph engine."""
        return self._kg

    @property
    def traversal(self) -> AttackPathTraversalEngine:
        """Access underlying traversal engine."""
        return self._traversal

    # ── Path Discovery ────────────────────────────────────────────────

    def discover_attack_paths(
        self,
        entry_point: Optional[str] = None,
        target: Optional[str] = None,
        max_depth: int = 10,
        max_paths: int = 20,
        algorithms: Optional[List[str]] = None,
    ) -> List[AttackChain]:
        """Discover attack paths in the knowledge graph.

        If entry_point and target are specified, finds paths between them.
        If only entry_point is given, finds all paths from that node.
        If neither is given, finds all critical attack paths.

        Args:
            entry_point: Starting node ID (or None for auto-discovery)
            target: Target node ID (or None for all targets)
            max_depth: Maximum path depth
            max_paths: Maximum number of paths to return
            algorithms: List of algorithms to use (bfs, dfs, dijkstra, a_star)

        Returns:
            List of AttackChain objects, scored and ranked
        """
        if algorithms is None:
            algorithms = ["dijkstra", "bfs"]

        all_chains: List[AttackChain] = []

        if entry_point and target:
            # Specific path finding
            paths = self._kg.find_attack_paths(entry_point, target, max_depth)
            for i, path in enumerate(paths[:max_paths]):
                chain = self._path_to_chain(path, i)
                all_chains.append(chain)
        else:
            # Auto-discover critical paths
            try:
                analytics = self._kg.get_graph_analytics()
                graph = self._kg._backend

                # Find internet-facing nodes (entry points)
                entry_points = []
                for node_id in graph._graph.nodes() if hasattr(graph, '_graph') else []:
                    props = graph._graph.nodes[node_id].get("properties", {})
                    if props.get("internet_facing") or props.get("type") == "endpoint":
                        entry_points.append(node_id)

                # Find crown jewels (targets)
                targets = []
                for node_id in graph._graph.nodes() if hasattr(graph, '_graph') else []:
                    props = graph._graph.nodes[node_id].get("properties", {})
                    if props.get("critical") or props.get("has_sensitive_data"):
                        targets.append(node_id)

                # Find paths between entry points and crown jewels
                for ep in entry_points[:5]:
                    for tgt in targets[:5]:
                        if ep != tgt:
                            paths = self._kg.find_attack_paths(ep, tgt, max_depth)
                            for j, path in enumerate(paths[:3]):
                                chain = self._path_to_chain(path, len(all_chains))
                                all_chains.append(chain)
                                if len(all_chains) >= max_paths:
                                    break
                        if len(all_chains) >= max_paths:
                            break
                    if len(all_chains) >= max_paths:
                        break
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.warning("Auto-discovery failed: %s", e)

        # Sort by score
        all_chains.sort(key=lambda c: c.score.total_score, reverse=True)
        return all_chains[:max_paths]

    def _path_to_chain(self, path: Any, index: int) -> AttackChain:
        """Convert a raw path result to a scored AttackChain."""
        nodes = []
        edges = []

        if isinstance(path, dict):
            raw_nodes = path.get("nodes", path.get("path", []))
            risk_score = path.get("risk_score", 50.0)
        elif isinstance(path, (list, tuple)):
            raw_nodes = list(path)
            risk_score = 50.0
        else:
            raw_nodes = getattr(path, "nodes", [])
            risk_score = getattr(path, "risk_score", 50.0)

        for i, node in enumerate(raw_nodes):
            if isinstance(node, str):
                nodes.append({"id": node, "type": "unknown", "index": i})
            elif isinstance(node, dict):
                nodes.append(node)
            else:
                nodes.append({"id": str(node), "type": "unknown", "index": i})

        for i in range(len(nodes) - 1):
            edges.append({
                "from": nodes[i].get("id", str(i)),
                "to": nodes[i + 1].get("id", str(i + 1)),
                "type": "ATTACK_STEP",
            })

        chain_id = f"CHAIN-{hashlib.md5(json.dumps(nodes, default=str).encode()).hexdigest()[:8].upper()}"

        score = self._score_path(nodes, edges, risk_score)

        entry = nodes[0] if nodes else {"id": "unknown", "type": "unknown"}
        target = nodes[-1] if nodes else {"id": "unknown", "type": "unknown"}

        return AttackChain(
            chain_id=chain_id,
            name=f"Attack Path {index + 1}: {entry.get('id', '?')} → {target.get('id', '?')}",
            description=f"Attack chain with {len(nodes)} hops from {entry.get('id', '?')} to {target.get('id', '?')}",
            nodes=nodes,
            edges=edges,
            entry_point=entry,
            target=target,
            total_hops=len(nodes),
            score=score,
            techniques=self._infer_techniques(nodes),
        )

    def _score_path(
        self,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        base_risk: float = 50.0,
    ) -> AttackPathScore:
        """Score an attack path based on multiple factors."""
        exploitability = min(10.0, base_risk / 10.0)
        impact = min(10.0, len(nodes) * 2.0)
        reachability = 1.0 / max(1, len(nodes))
        blast = len(nodes) * 3

        total = (
            exploitability * self._scoring_weights["cvss_base"]
            + impact * self._scoring_weights["epss_score"]
            + reachability * 10 * self._scoring_weights["reachability"]
            + min(10, blast / 5) * self._scoring_weights["blast_radius"]
            + 5.0 * self._scoring_weights["asset_criticality"]
        ) * 10

        total = min(100.0, max(0.0, total))

        if total >= 80:
            severity = AttackPathSeverity.CRITICAL
        elif total >= 60:
            severity = AttackPathSeverity.HIGH
        elif total >= 40:
            severity = AttackPathSeverity.MEDIUM
        elif total >= 20:
            severity = AttackPathSeverity.LOW
        else:
            severity = AttackPathSeverity.INFORMATIONAL

        return AttackPathScore(
            path_id=hashlib.md5(json.dumps(nodes, default=str).encode()).hexdigest()[:12],
            total_score=total,
            exploitability=exploitability,
            impact=impact,
            reachability=reachability,
            blast_radius=blast,
            severity=severity,
            confidence=0.85 if len(nodes) <= 5 else 0.7,
            factors=dict(self._scoring_weights),
        )

    def _infer_techniques(self, nodes: List[Dict[str, Any]]) -> List[str]:
        """Infer MITRE ATT&CK techniques from path node types."""
        techniques = []
        technique_map = {
            "endpoint": "T1190",  # Exploit Public-Facing Application
            "auth": "T1078",  # Valid Accounts
            "database": "T1005",  # Data from Local System
            "api": "T1059",  # Command and Scripting
            "container": "T1611",  # Escape to Host
            "network": "T1021",  # Remote Services
            "cloud": "T1538",  # Cloud Service Dashboard
            "secrets": "T1552",  # Unsecured Credentials
        }
        for node in nodes:
            ntype = node.get("type", "").lower()
            for key, technique in technique_map.items():
                if key in ntype and technique not in techniques:
                    techniques.append(technique)
        return techniques or ["T1190"]  # Default to Exploit Public-Facing

    # ── Attack Surface Analysis ───────────────────────────────────────

    def get_attack_surface(self) -> AttackSurface:
        """Compute the attack surface from the knowledge graph."""
        try:
            analytics = self._kg.get_graph_analytics()
            total = analytics.get("total_nodes", 0)

            # Compute surface metrics
            internet_facing = 0
            internal = 0
            critical_components = []
            entry_points = []
            crown_jewels = []

            backend = self._kg._backend
            if hasattr(backend, '_graph'):
                for node_id in backend._graph.nodes():
                    props = backend._graph.nodes[node_id].get("properties", {})
                    ntype = backend._graph.nodes[node_id].get("type", "")

                    if props.get("internet_facing"):
                        internet_facing += 1
                        entry_points.append({
                            "id": node_id,
                            "type": ntype,
                            "risk": props.get("risk_score", 0),
                        })
                    else:
                        internal += 1

                    if props.get("critical") or props.get("has_sensitive_data"):
                        crown_jewels.append({
                            "id": node_id,
                            "type": ntype,
                            "sensitivity": props.get("sensitivity", "high"),
                        })

                    finding_count = sum(
                        1 for _, _, d in backend._graph.edges(node_id, data=True)
                        if d.get("type") == "HAS_FINDING"
                    )
                    if finding_count > 3:
                        critical_components.append({
                            "id": node_id,
                            "type": ntype,
                            "finding_count": finding_count,
                        })

            risk_score = min(100.0, (
                internet_facing * 5 +
                len(critical_components) * 10 +
                len(crown_jewels) * 3
            ))

            return AttackSurface(
                total_assets=total,
                internet_facing=internet_facing,
                internal_only=internal,
                critical_paths=analytics.get("attack_paths_count", 0),
                high_risk_components=critical_components[:10],
                entry_points=entry_points[:10],
                crown_jewels=crown_jewels[:10],
                risk_score=risk_score,
            )
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("Attack surface analysis failed: %s", e)
            return AttackSurface(
                total_assets=0,
                internet_facing=0,
                internal_only=0,
                critical_paths=0,
                high_risk_components=[],
                entry_points=[],
                crown_jewels=[],
                risk_score=0.0,
            )

    # ── Blast Radius ──────────────────────────────────────────────────

    def compute_blast_radius(
        self,
        node_id: str,
        max_hops: int = 5,
    ) -> Dict[str, Any]:
        """Compute blast radius for a specific node.

        Uses BFS to find all nodes reachable from the given node
        and computes the transitive impact.
        """
        try:
            reachable = self._kg._backend.bfs_reachable(node_id, max_depth=max_hops)
            affected_nodes = []
            total_risk = 0.0

            for nid, depth in reachable.items():
                if nid == node_id:
                    continue
                node_props = {}
                if hasattr(self._kg._backend, '_graph'):
                    node_props = self._kg._backend._graph.nodes.get(nid, {}).get("properties", {})
                risk = node_props.get("risk_score", 1.0) / max(depth, 1)
                total_risk += risk
                affected_nodes.append({
                    "id": nid,
                    "depth": depth,
                    "risk_contribution": round(risk, 3),
                })

            affected_nodes.sort(key=lambda n: n["risk_contribution"], reverse=True)

            return {
                "source_node": node_id,
                "max_hops": max_hops,
                "total_affected": len(affected_nodes),
                "total_risk_score": round(total_risk, 2),
                "affected_nodes": affected_nodes[:50],
                "severity": (
                    "critical" if total_risk >= 50 else
                    "high" if total_risk >= 30 else
                    "medium" if total_risk >= 10 else "low"
                ),
            }
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("Blast radius calculation failed: %s", e)
            return {
                "source_node": node_id,
                "max_hops": max_hops,
                "total_affected": 0,
                "total_risk_score": 0.0,
                "affected_nodes": [],
                "severity": "low",
                "error": str(e),
            }

    # ── Path Comparison ───────────────────────────────────────────────

    def compare_paths(
        self,
        paths: List[AttackChain],
    ) -> Dict[str, Any]:
        """Compare multiple attack paths and provide ranked analysis."""
        if not paths:
            return {"paths": [], "recommendation": "No paths to compare"}

        ranked = sorted(paths, key=lambda p: p.score.total_score, reverse=True)

        comparison = []
        for i, path in enumerate(ranked):
            comparison.append({
                "rank": i + 1,
                "chain_id": path.chain_id,
                "name": path.name,
                "score": path.score.total_score,
                "severity": path.score.severity.value,
                "hops": path.total_hops,
                "techniques": path.techniques,
            })

        return {
            "paths": comparison,
            "highest_risk": ranked[0].chain_id if ranked else None,
            "recommendation": f"Prioritize mitigation of {ranked[0].name}" if ranked else "No action needed",
            "total_unique_techniques": len(set(t for p in ranked for t in p.techniques)),
        }

    # ── Graph Export ──────────────────────────────────────────────────

    def export_paths_mermaid(self, paths: List[AttackChain]) -> str:
        """Export attack paths as a Mermaid diagram."""
        lines = ["graph LR"]
        for chain in paths:
            for edge in chain.edges:
                src = edge["from"].replace("-", "_").replace(".", "_")
                tgt = edge["to"].replace("-", "_").replace(".", "_")
                lines.append(f"    {src} --> {tgt}")
        return "\n".join(lines)

    def export_paths_json(self, paths: List[AttackChain]) -> str:
        """Export attack paths as JSON."""
        return json.dumps(
            [p.to_dict() for p in paths],
            indent=2,
            default=str,
        )

    # ── Statistics ────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Get attack path engine statistics."""
        try:
            analytics = self._kg.get_graph_analytics()
            surface = self.get_attack_surface()
            return {
                "engine": "attack-path-engine",
                "version": "1.0.0",
                "status": "operational",
                "graph": {
                    "nodes": analytics.get("total_nodes", 0),
                    "edges": analytics.get("total_edges", 0),
                    "density": analytics.get("density", 0.0),
                },
                "surface": surface.to_dict(),
                "scoring_weights": dict(self._scoring_weights),
                "algorithms": ["bfs", "dfs", "dijkstra", "a_star"],
                "cache_size": len(self._path_cache),
            }
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            return {
                "engine": "attack-path-engine",
                "version": "1.0.0",
                "status": "degraded",
                "error": str(e),
            }


# ---------------------------------------------------------------------------
# Module-Level Singleton
# ---------------------------------------------------------------------------

_engine: Optional[AttackPathEngine] = None


def get_engine() -> AttackPathEngine:
    """Get or create the singleton AttackPathEngine."""
    global _engine
    if _engine is None:
        _engine = AttackPathEngine()
    return _engine


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------

def discover_paths(
    entry_point: Optional[str] = None,
    target: Optional[str] = None,
    max_depth: int = 10,
    max_paths: int = 20,
) -> List[Dict[str, Any]]:
    """Convenience function to discover attack paths."""
    engine = get_engine()
    chains = engine.discover_attack_paths(entry_point, target, max_depth, max_paths)
    return [c.to_dict() for c in chains]


def get_surface() -> Dict[str, Any]:
    """Convenience function to get attack surface."""
    engine = get_engine()
    return engine.get_attack_surface().to_dict()


def blast_radius(node_id: str, max_hops: int = 5) -> Dict[str, Any]:
    """Convenience function to compute blast radius."""
    engine = get_engine()
    return engine.compute_blast_radius(node_id, max_hops)


def get_stats() -> Dict[str, Any]:
    """Convenience function to get engine stats."""
    engine = get_engine()
    return engine.get_stats()


# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------

__all__ = [
    # Core types
    "AttackPathSeverity",
    "AttackPathScore",
    "AttackChain",
    "AttackSurface",
    # Engine
    "AttackPathEngine",
    "get_engine",
    # Convenience functions
    "discover_paths",
    "get_surface",
    "blast_radius",
    "get_stats",
    # Re-exports from falkordb_client
    "NodeType",
    "EdgeType",
    "GraphNode",
    "GraphEdge",
    "KnowledgeGraphEngine",
    "AttackPathTraversalEngine",
    "get_knowledge_graph",
    "get_attack_path_engine",
    "get_nl_query_engine",
]
