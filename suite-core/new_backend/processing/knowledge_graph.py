"""Knowledge graph processor using CTINexus."""

from __future__ import annotations

from typing import Any, Dict


class KnowledgeGraphProcessor:
    """Processor for building knowledge graphs from security data."""

    def __init__(self) -> None:
        self._builder = None

    def _get_builder(self):
        """Get or create the graph builder."""
        if self._builder is None:
            try:
                from CTINexus import GraphBuilder

                self._builder = GraphBuilder()
            except ImportError:
                raise ImportError("CTINexus is required for knowledge graph processing")
        return self._builder

    def build_graph(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Build a knowledge graph from a security snapshot.

        Args:
            snapshot: Dictionary containing entities and relationships

        Returns:
            Dictionary with graph data and analytics
        """
        builder = self._get_builder()

        # Extract data from snapshot
        builder.extract(snapshot)

        # Process entities
        entities = snapshot.get("entities", [])
        normalized_entities = []
        for entity in entities:
            normalized = {
                "id": entity.get("id") or entity.get("name"),
                "type": entity.get("type") or entity.get("category"),
                "properties": entity.get("properties", {}),
            }
            normalized_entities.append(normalized)
        builder.ingest_entities(normalized_entities)

        # Process relationships
        relationships = snapshot.get("relationships", [])
        normalized_relationships = []
        for rel in relationships:
            normalized = {
                "source": rel.get("from"),
                "target": rel.get("to"),
                "type": rel.get("relationship"),
            }
            normalized_relationships.append(normalized)
        builder.ingest_relationships(normalized_relationships)

        # Build and serialize the graph
        graph = builder.build()
        serialized = builder.serialize(graph)
        analytics = builder.analytics(graph)

        # Add entity and relationship counts to analytics
        analytics["entity_count"] = len(entities)
        analytics["relationship_count"] = len(relationships)

        return {
            "graph": serialized.get("graph", graph),
            "analytics": analytics,
        }


__all__ = ["KnowledgeGraphProcessor"]
