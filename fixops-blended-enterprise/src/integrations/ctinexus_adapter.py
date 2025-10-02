"""CTINexus integration helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

import networkx as nx
import structlog

logger = structlog.get_logger()


@dataclass
class CTINexusGraphResult:
    """Normalized result returned by :class:`CTINexusGraphAdapter`."""

    graph: nx.DiGraph
    relations: List[Dict[str, Any]]
    serialized: Dict[str, Any]


class CTINexusGraphAdapter:
    """Wrapper around the CTINexus graph extraction/serialisation APIs.

    The real CTINexus SDK exposes asynchronous helpers for building graphs from
    extracted entities.  In tests – and when the dependency is not available –
    we fall back to a local implementation that mimics the behaviour that the
    previous hand written graph builder provided.  This makes the integration
    deterministic while still exercising the integration points.
    """

    def __init__(self) -> None:
        self._extractor, self._serializer = self._load_sdk()

    async def build_graph(
        self,
        entities: Iterable[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> CTINexusGraphResult:
        """Build a graph for the supplied entities using CTINexus.

        Args:
            entities: Iterable of entity dictionaries.  Each dictionary must
                include ``id``, ``type``, ``name``, ``confidence`` and
                ``properties`` keys – the format produced by
                :class:`SecurityEntity` in ``knowledge_graph``.
            context: Optional context payload to forward to CTINexus for
                improved relation inference.

        Returns:
            :class:`CTINexusGraphResult` containing the populated NetworkX
            graph, a raw relation list and the serialised representation
            returned by the SDK.
        """

        payload = list(entities)
        context_payload = context or {}

        raw_graph = await self._call_build_graph(payload, context_payload)
        nx_graph = self._serializer.to_networkx(raw_graph)
        relations = self._serializer.extract_relations(raw_graph)
        serialized = self._serializer.to_json(raw_graph)
        return CTINexusGraphResult(graph=nx_graph, relations=relations, serialized=serialized)

    async def _call_build_graph(self, payload: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, Any]:
        maybe_coroutine = self._extractor.build_graph(payload, context=context)
        if asyncio.iscoroutine(maybe_coroutine):
            return await maybe_coroutine
        return maybe_coroutine

    def _load_sdk(self):
        try:
            from ctinexus_sdk import GraphExtractor, GraphSerializer  # type: ignore

            logger.info("✅ Loaded CTINexus SDK components")
            return GraphExtractor(), GraphSerializer()
        except Exception as exc:  # pragma: no cover - exercised via fallback
            logger.warning("CTINexus SDK unavailable, using fallback implementation", exc_info=exc)
            return _FallbackGraphExtractor(), _FallbackGraphSerializer()


class _FallbackGraphExtractor:
    """Local implementation that emulates CTINexus edge inference."""

    def build_graph(self, payload: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        nodes = []
        edges: List[Dict[str, Any]] = []

        for entity in payload:
            nodes.append(
                {
                    "id": entity["id"],
                    "type": entity.get("type"),
                    "name": entity.get("name"),
                    "confidence": entity.get("confidence", 0.5),
                    "properties": entity.get("properties", {}),
                }
            )

        vulnerabilities = [node for node in nodes if node.get("type") == "vulnerability"]
        components = [node for node in nodes if node.get("type") == "component"]
        services = [node for node in nodes if node.get("type") == "service"]

        for vuln in vulnerabilities:
            vuln_path = vuln["properties"].get("file_location")
            for component in components:
                component_path = component["properties"].get("path")
                if vuln_path and component_path and vuln_path == component_path:
                    edges.append(
                        {
                            "source": vuln["id"],
                            "target": component["id"],
                            "type": "affects",
                            "confidence": 0.7,
                            "properties": {
                                "severity": vuln["properties"].get("severity", "MEDIUM"),
                                "inference_method": "fallback_path_match",
                            },
                        }
                    )

        for component in components:
            component_path = component["properties"].get("path", "")
            for service in services:
                service_name = service.get("name", "").lower()
                if service_name and service_name in component_path.lower():
                    edges.append(
                        {
                            "source": component["id"],
                            "target": service["id"],
                            "type": "belongs_to",
                            "confidence": 0.6,
                            "properties": {"inference_method": "fallback_service_match"},
                        }
                    )

        return {"nodes": nodes, "edges": edges, "metadata": {"context": context or {}}}


class _FallbackGraphSerializer:
    """Serialisation helpers that understand the fallback structure."""

    def to_networkx(self, graph_dict: Dict[str, Any]) -> nx.DiGraph:
        graph = nx.DiGraph()
        for node in graph_dict.get("nodes", []):
            graph.add_node(
                node["id"],
                type=node.get("type"),
                name=node.get("name"),
                confidence=node.get("confidence", 0.5),
                **node.get("properties", {}),
            )

        for edge in graph_dict.get("edges", []):
            graph.add_edge(
                edge["source"],
                edge["target"],
                relation_type=edge.get("type"),
                confidence=edge.get("confidence", 0.5),
                **edge.get("properties", {}),
            )

        return graph

    def extract_relations(self, graph_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        return list(graph_dict.get("edges", []))

    def to_json(self, graph_dict: Dict[str, Any]) -> Dict[str, Any]:
        return graph_dict

