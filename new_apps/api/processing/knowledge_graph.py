"""Knowledge graph orchestration for enhanced decision analytics."""
from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

logger = logging.getLogger(__name__)


class KnowledgeGraphError(RuntimeError):
    """Raised when the CTINexus integration encounters an unrecoverable error."""


@dataclass
class _ExtractionResult:
    entities: List[Dict[str, Any]]
    relationships: List[Dict[str, Any]]


class KnowledgeGraphProcessor:
    """High level wrapper around the CTINexus knowledge-graph toolchain.

    The processor accepts normalized scan intelligence and orchestrates CTINexus
    to build, analyse, and serialise the resulting graph. The implementation
    intentionally avoids hand-crafted adjacency logic; all graph operations are
    delegated to CTINexus builders and serializers when available. When the
    proprietary module is not installed we fall back to a deterministic builder
    that mimics its contract so regressions can run without the dependency.
    """

    def __init__(
        self,
        builder_factory: Optional[Callable[[], Any]] = None,
        serializer_factory: Optional[Callable[[Any], Callable[[Any], Mapping[str, Any]]]] = None,
    ) -> None:
        self._builder_factory = builder_factory or self._default_builder_factory
        self._serializer_factory = serializer_factory or self._default_serializer_factory

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def build_graph(self, scan_snapshot: Mapping[str, Any]) -> Dict[str, Any]:
        """Build and serialise a knowledge graph from the supplied scan data."""

        builder = self._instantiate_builder()
        extraction = self._extract_components(builder, scan_snapshot)
        self._ingest_entities(builder, extraction.entities)
        self._ingest_relationships(builder, extraction.relationships)
        graph_object = self._materialise_graph(builder)
        serializer = self._resolve_serializer(builder)
        payload = dict(serializer(graph_object))
        payload.setdefault("graph", graph_object)
        payload.setdefault("entities", extraction.entities)
        payload.setdefault("relationships", extraction.relationships)
        payload["analytics"] = self._derive_analytics(builder, graph_object, extraction)
        return payload

    # ------------------------------------------------------------------
    # Builder helpers
    # ------------------------------------------------------------------
    def _instantiate_builder(self) -> Any:
        try:
            builder = self._builder_factory()
        except Exception as exc:  # pragma: no cover - defensive guard
            raise KnowledgeGraphError("Failed to construct CTINexus graph builder") from exc
        if builder is None:
            raise KnowledgeGraphError("CTINexus builder factory returned None")
        return builder

    def _default_builder_factory(self) -> Any:
        try:
            module = importlib.import_module("CTINexus")
        except ModuleNotFoundError:
            return _FallbackBuilder()
        for attr in ("GraphOrchestrator", "GraphBuilder", "KnowledgeGraphBuilder"):
            builder_cls = getattr(module, attr, None)
            if builder_cls is not None:
                return builder_cls()
        return _FallbackBuilder()

    def _default_serializer_factory(
        self, builder: Any
    ) -> Callable[[Any], Mapping[str, Any]]:
        serializer_candidates: Sequence[str] = (
            "serialize",
            "to_dict",
            "as_dict",
        )
        for name in serializer_candidates:
            method = getattr(builder, name, None)
            if callable(method):
                return method
        serializer = getattr(builder, "serializer", None)
        if serializer is not None:
            if callable(serializer):
                return serializer
            if hasattr(serializer, "to_dict") and callable(serializer.to_dict):
                return serializer.to_dict
        try:
            module = importlib.import_module("CTINexus")
        except ModuleNotFoundError:
            return lambda graph: graph if isinstance(graph, Mapping) else dict(graph)
        for attr in ("GraphSerializer", "Serializer"):
            serializer_cls = getattr(module, attr, None)
            if serializer_cls is not None:
                instance = serializer_cls()
                if hasattr(instance, "to_dict") and callable(instance.to_dict):
                    return instance.to_dict
                if callable(instance):
                    return instance
        raise KnowledgeGraphError("Unable to locate CTINexus serializer")

    def _resolve_serializer(self, builder: Any) -> Callable[[Any], Mapping[str, Any]]:
        try:
            return self._serializer_factory(builder)
        except KnowledgeGraphError:
            raise
        except Exception as exc:  # pragma: no cover - defensive guard
            raise KnowledgeGraphError("Failed to create CTINexus serializer") from exc

    # ------------------------------------------------------------------
    # Data extraction and ingestion
    # ------------------------------------------------------------------
    def _extract_components(
        self, builder: Any, scan_snapshot: Mapping[str, Any]
    ) -> _ExtractionResult:
        extractor = getattr(builder, "extract", None)
        if callable(extractor):
            result = extractor(scan_snapshot)
            entities = self._normalise_entities(result.get("entities", []))
            relationships = self._normalise_relationships(result.get("relationships", []))
            return _ExtractionResult(entities=entities, relationships=relationships)

        entities = self._normalise_entities(scan_snapshot.get("entities", []))
        relationships = self._normalise_relationships(
            scan_snapshot.get("relationships", [])
        )
        return _ExtractionResult(entities=entities, relationships=relationships)

    def _normalise_entities(self, raw_entities: Iterable[Any]) -> List[Dict[str, Any]]:
        normalised: List[Dict[str, Any]] = []
        for index, entity in enumerate(raw_entities):
            if isinstance(entity, Mapping):
                entity_dict: MutableMapping[str, Any] = dict(entity)
                entity_dict.setdefault(
                    "id",
                    entity_dict.get("id")
                    or entity_dict.get("name")
                    or entity_dict.get("entity_id")
                    or f"entity-{index}",
                )
                entity_dict.setdefault("type", entity_dict.get("type", "unknown"))
                entity_dict.setdefault("properties", {})
                normalised.append(dict(entity_dict))
                continue
            normalised.append(
                {
                    "id": f"entity-{index}",
                    "type": "unknown",
                    "label": str(entity),
                    "properties": {},
                }
            )
        return normalised

    def _normalise_relationships(
        self, raw_relationships: Iterable[Any]
    ) -> List[Dict[str, Any]]:
        normalised: List[Dict[str, Any]] = []
        for index, relation in enumerate(raw_relationships):
            if isinstance(relation, Mapping):
                relation_dict: MutableMapping[str, Any] = dict(relation)
                relation_dict.setdefault("id", relation_dict.get("relationship_id", f"edge-{index}"))
                relation_dict.setdefault("source", relation_dict.get("from") or relation_dict.get("source"))
                relation_dict.setdefault("target", relation_dict.get("to") or relation_dict.get("target"))
                relation_dict.setdefault("type", relation_dict.get("relationship", "related"))
                relation_dict.setdefault("metadata", relation_dict.get("metadata", {}))
                normalised.append(dict(relation_dict))
                continue
            normalised.append(
                {
                    "id": f"edge-{index}",
                    "source": None,
                    "target": None,
                    "type": "related",
                    "metadata": {"raw": relation},
                }
            )
        return normalised

    def _ingest_entities(self, builder: Any, entities: Sequence[Mapping[str, Any]]) -> None:
        self._invoke_builder(builder, ("ingest_entities", "add_entities", "add_nodes"), entities)

    def _ingest_relationships(
        self, builder: Any, relationships: Sequence[Mapping[str, Any]]
    ) -> None:
        self._invoke_builder(
            builder,
            ("ingest_relationships", "add_relationships", "add_edges", "connect"),
            relationships,
        )

    def _invoke_builder(self, builder: Any, candidate_names: Sequence[str], *args: Any) -> None:
        for name in candidate_names:
            method = getattr(builder, name, None)
            if callable(method):
                method(*args)
                return
        raise KnowledgeGraphError(
            f"Builder {builder!r} does not expose any ingestion methods {candidate_names}"
        )

    # ------------------------------------------------------------------
    # Graph materialisation & analytics
    # ------------------------------------------------------------------
    def _materialise_graph(self, builder: Any) -> Mapping[str, Any]:
        for name in ("materialise", "materialize", "build", "to_graph"):
            method = getattr(builder, name, None)
            if callable(method):
                graph = method()
                if isinstance(graph, Mapping):
                    return graph
                return dict(graph)
        raise KnowledgeGraphError("Builder does not expose a graph materialisation method")

    def _derive_analytics(
        self,
        builder: Any,
        graph_object: Mapping[str, Any],
        extraction: _ExtractionResult,
    ) -> Dict[str, Any]:
        analytics_method = getattr(builder, "analytics", None)
        if callable(analytics_method):
            try:
                analytics = analytics_method(graph_object)
                if isinstance(analytics, Mapping):
                    analytics_dict = dict(analytics)
                    analytics_dict.setdefault("entity_count", len(extraction.entities))
                    analytics_dict.setdefault("relationship_count", len(extraction.relationships))
                    return analytics_dict
            except Exception:  # pragma: no cover - best effort fallback
                logger.exception("CTINexus analytics callback failed; falling back to local metrics")
        return {
            "entity_count": len(extraction.entities),
            "relationship_count": len(extraction.relationships),
        }


class _FallbackBuilder:
    """Deterministic knowledge graph builder used during tests."""

    def __init__(self) -> None:
        self.entities: List[Mapping[str, Any]] = []
        self.relationships: List[Mapping[str, Any]] = []

    # compatibility with CTINexus contract --------------------------------
    def extract(self, snapshot: Mapping[str, Any]) -> Mapping[str, Any]:
        return snapshot

    def ingest_entities(self, entities: Iterable[Mapping[str, Any]]) -> None:
        self.entities.extend(list(entities))

    def ingest_relationships(self, relationships: Iterable[Mapping[str, Any]]) -> None:
        self.relationships.extend(list(relationships))

    def build(self) -> Mapping[str, Any]:
        return {
            "nodes": list(self.entities),
            "edges": list(self.relationships),
        }

    def serialize(self, graph: Mapping[str, Any]) -> Mapping[str, Any]:
        return dict(graph)

    def analytics(self, graph: Mapping[str, Any]) -> Mapping[str, Any]:
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        node_count = len(list(nodes))
        edge_count = len(list(edges))
        density = 0.0 if node_count <= 1 else round(edge_count / (node_count - 1), 3)
        return {
            "entity_count": node_count,
            "relationship_count": edge_count,
            "density": density,
        }


__all__ = ["KnowledgeGraphProcessor", "KnowledgeGraphError"]
