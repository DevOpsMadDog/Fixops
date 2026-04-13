"""
GraphRAG Retriever for TrustGraph.

Implements graph-based retrieval augmented generation for semantic security
intelligence queries. Traverses entity relationships in the knowledge graph
to build rich context for LLM consumption.

Usage:
    from trustgraph.graph_rag import GraphRAGRetriever

    retriever = GraphRAGRetriever()
    result = retriever.retrieve("critical vulnerabilities in production API", top_k=10, hops=2)
    # result["context_summary"] is ready to pass to an LLM
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

__all__ = ["GraphRAGRetriever"]


class GraphRAGRetriever:
    """Graph-based retrieval for semantic security intelligence queries.

    Uses the TrustGraph knowledge store to find relevant entities and traverse
    their relationships, producing LLM-ready context for security analysts.

    Gracefully degrades to empty results if knowledge store is unavailable.
    """

    def __init__(self, knowledge_store=None) -> None:
        """Initialize retriever.

        Args:
            knowledge_store: KnowledgeStore instance. If None, attempts lazy
                             load from the trustgraph package singleton.
        """
        self._store = knowledge_store
        if self._store is None:
            try:
                from trustgraph import get_knowledge_store
                self._store = get_knowledge_store()
            except Exception as exc:
                logger.warning(f"GraphRAGRetriever: knowledge store unavailable: {exc}")
                self._store = None

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def retrieve(self, query: str, top_k: int = 10, hops: int = 2) -> Dict[str, Any]:
        """Given a natural language query, find relevant entities and traverse
        their relationships up to `hops` levels.

        Args:
            query:  Natural language search query.
            top_k:  Maximum seed entities to retrieve from keyword search.
            hops:   Number of relationship hops to traverse from seed entities.

        Returns:
            {
                "query": str,
                "entities": [{"id": ..., "type": ..., "name": ..., "score": float}],
                "relationships": [{"from": ..., "to": ..., "type": ...}],
                "context_summary": str,
                "retrieval_method": "graph_rag",
            }
        """
        empty = self._empty_result(query)

        if not query or not query.strip():
            return empty

        try:
            seed_entities = self._keyword_to_entities(query, top_k=top_k)
            if not seed_entities:
                return empty

            if hops == 0:
                entities = seed_entities
                relationships: List[Dict[str, Any]] = []
            else:
                entities, relationships = self._traverse_graph(seed_entities, hops=hops)

            context_summary = self._build_context(entities, relationships)

            return {
                "query": query,
                "entities": entities,
                "relationships": relationships,
                "context_summary": context_summary,
                "retrieval_method": "graph_rag",
            }
        except Exception as exc:
            logger.error(f"GraphRAGRetriever.retrieve failed: {exc}")
            return empty

    def semantic_search(
        self,
        query: str,
        entity_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Search entities with optional entity-type filtering.

        Args:
            query:        Search query.
            entity_types: Optional list of entity types to restrict results
                          (e.g. ["CVE", "Asset", "Incident", "Control"]).

        Returns:
            List of entity dicts: [{"id", "type", "name", "score", "properties"}]
        """
        if not query or self._store is None:
            return []

        try:
            # Search across all 5 knowledge cores
            seen: Dict[str, Dict[str, Any]] = {}
            for core_id in range(1, 6):
                filters: Dict[str, Any] = {}
                if entity_types:
                    # Search each requested type separately
                    for etype in entity_types:
                        filters["entity_type"] = etype
                        results = self._safe_search(core_id, query, filters=filters)
                        for e in results:
                            if e.entity_id not in seen:
                                seen[e.entity_id] = {
                                    "id": e.entity_id,
                                    "type": e.entity_type,
                                    "name": e.name,
                                    "score": 1.0,
                                    "properties": e.properties,
                                }
                else:
                    results = self._safe_search(core_id, query)
                    for e in results:
                        if e.entity_id not in seen:
                            seen[e.entity_id] = {
                                "id": e.entity_id,
                                "type": e.entity_type,
                                "name": e.name,
                                "score": 1.0,
                                "properties": e.properties,
                            }

            return list(seen.values())
        except Exception as exc:
            logger.error(f"GraphRAGRetriever.semantic_search failed: {exc}")
            return []

    def get_entity_neighborhood(
        self, entity_id: str, hops: int = 1
    ) -> Dict[str, Any]:
        """Get all entities and relationships within N hops of a given entity.

        Args:
            entity_id: Starting entity ID.
            hops:      Number of relationship hops to traverse (1-3).

        Returns:
            {
                "entity_id": str,
                "entities": [...],
                "relationships": [...],
            }
        """
        empty: Dict[str, Any] = {
            "entity_id": entity_id,
            "entities": [],
            "relationships": [],
        }

        if not entity_id or self._store is None:
            return empty

        try:
            root = self._store.get_entity(entity_id)
            if not root:
                return empty

            root_dict = self._entity_to_dict(root)
            seed = [root_dict]
            entities, relationships = self._traverse_graph(seed, hops=max(1, hops))

            return {
                "entity_id": entity_id,
                "entities": entities,
                "relationships": relationships,
            }
        except Exception as exc:
            logger.error(f"GraphRAGRetriever.get_entity_neighborhood failed: {exc}")
            return empty

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _keyword_to_entities(
        self, query: str, top_k: int = 10
    ) -> List[Dict[str, Any]]:
        """Extract entities from knowledge store matching query keywords.

        Searches across all 5 knowledge cores and deduplicates by entity_id.

        Args:
            query:  Query string.
            top_k:  Max results per core.

        Returns:
            List of entity dicts with score field.
        """
        if self._store is None:
            return []

        seen: Dict[str, Dict[str, Any]] = {}
        for core_id in range(1, 6):
            results = self._safe_search(core_id, query, limit=top_k)
            for entity in results:
                if entity.entity_id not in seen:
                    seen[entity.entity_id] = self._entity_to_dict(entity)

        return list(seen.values())

    def _traverse_graph(
        self, seed_entities: List[Dict[str, Any]], hops: int
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """BFS traversal through entity relationships.

        Args:
            seed_entities: Starting entities (list of entity dicts).
            hops:          Number of hops to traverse.

        Returns:
            Tuple of (all_entities, all_relationships) as dicts.
        """
        if self._store is None or not seed_entities:
            return seed_entities, []

        all_entities: Dict[str, Dict[str, Any]] = {
            e["id"]: e for e in seed_entities
        }
        all_relationships: Dict[str, Dict[str, Any]] = {}

        frontier = set(e["id"] for e in seed_entities)

        for _ in range(max(1, hops)):
            next_frontier: set = set()

            for entity_id in frontier:
                rels = self._safe_get_relationships(entity_id)
                for rel in rels:
                    rel_key = rel.rel_id
                    if rel_key not in all_relationships:
                        all_relationships[rel_key] = {
                            "from": rel.source_id,
                            "to": rel.target_id,
                            "type": rel.rel_type,
                        }

                    # Collect the other end of each relationship
                    other_id = (
                        rel.target_id
                        if rel.source_id == entity_id
                        else rel.source_id
                    )
                    if other_id not in all_entities:
                        next_frontier.add(other_id)

            # Fetch entities for next frontier
            for eid in next_frontier:
                if eid not in all_entities:
                    entity = self._safe_get_entity(eid)
                    if entity:
                        all_entities[eid] = self._entity_to_dict(entity)

            frontier = next_frontier
            if not frontier:
                break

        return list(all_entities.values()), list(all_relationships.values())

    def _build_context(
        self,
        entities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
    ) -> str:
        """Build LLM-friendly context paragraph from graph data.

        Args:
            entities:      List of entity dicts.
            relationships: List of relationship dicts.

        Returns:
            A human-readable context string summarising the graph data.
        """
        if not entities:
            return ""

        # Group entities by type
        by_type: Dict[str, List[str]] = {}
        for e in entities:
            etype = e.get("type", "Unknown")
            by_type.setdefault(etype, []).append(e.get("name", e.get("id", "")))

        lines: List[str] = []
        lines.append(
            f"Found {len(entities)} related entities across "
            f"{len(by_type)} types with {len(relationships)} relationships."
        )

        for etype, names in by_type.items():
            names_str = ", ".join(names[:5])
            suffix = f" (and {len(names) - 5} more)" if len(names) > 5 else ""
            lines.append(f"- {etype}: {names_str}{suffix}")

        if relationships:
            sample_rels = relationships[:5]
            rel_lines = [
                f"  {r['from']} --[{r['type']}]--> {r['to']}"
                for r in sample_rels
            ]
            lines.append("Key relationships:")
            lines.extend(rel_lines)
            if len(relationships) > 5:
                lines.append(f"  (and {len(relationships) - 5} more relationships)")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Safe wrappers (graceful degradation)
    # -------------------------------------------------------------------------

    def _safe_search(self, core_id: int, query: str, filters=None, limit: int = 20):
        """Wrapper around KnowledgeStore.search that never raises."""
        try:
            return self._store.search(
                core_id=core_id,
                query_text=query,
                filters=filters,
                limit=limit,
            )
        except Exception as exc:
            logger.debug(f"search core={core_id} failed: {exc}")
            return []

    def _safe_get_relationships(self, entity_id: str):
        """Wrapper around KnowledgeStore.get_relationships that never raises."""
        try:
            return self._store.get_relationships(entity_id)
        except Exception as exc:
            logger.debug(f"get_relationships entity={entity_id} failed: {exc}")
            return []

    def _safe_get_entity(self, entity_id: str):
        """Wrapper around KnowledgeStore.get_entity that never raises."""
        try:
            return self._store.get_entity(entity_id)
        except Exception as exc:
            logger.debug(f"get_entity entity={entity_id} failed: {exc}")
            return None

    # -------------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------------

    @staticmethod
    def _entity_to_dict(entity) -> Dict[str, Any]:
        """Convert KnowledgeEntity to a serialisable dict."""
        return {
            "id": entity.entity_id,
            "type": entity.entity_type,
            "name": entity.name,
            "score": 1.0,
            "properties": entity.properties,
        }

    @staticmethod
    def _empty_result(query: str) -> Dict[str, Any]:
        """Return a well-formed empty result."""
        return {
            "query": query,
            "entities": [],
            "relationships": [],
            "context_summary": "",
            "retrieval_method": "graph_rag",
        }
