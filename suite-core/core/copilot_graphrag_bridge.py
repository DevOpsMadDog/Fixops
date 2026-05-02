"""Bridge between Copilot chat and TrustGraph GraphRAG for enriched security answers."""
from __future__ import annotations

import sys

import structlog

sys.path.insert(0, "suite-core")

_logger = structlog.get_logger(__name__)


class CopilotGraphRAGBridge:
    """Connects Copilot chat to TrustGraph GraphRAG for enriched security answers.

    Uses GraphRAGRetriever from trustgraph.graph_rag to perform semantic graph
    queries against the TrustGraph knowledge store. Returns structured context
    ready for injection into LLM prompts. Gracefully degrades to empty-result
    dicts if the retriever is unavailable.
    """

    def __init__(self, retriever=None) -> None:
        self._retriever = retriever
        self._queries_enriched: int = 0
        self._total_entities: int = 0
        self._cache_hits: int = 0

        if self._retriever is None:
            try:
                from trustgraph.graph_rag import GraphRAGRetriever
                self._retriever = GraphRAGRetriever()
                _logger.info("CopilotGraphRAGBridge: GraphRAGRetriever initialized")
            except Exception as exc:
                _logger.warning(
                    "CopilotGraphRAGBridge: GraphRAGRetriever unavailable, degrading gracefully",
                    error=str(exc),
                )
                self._retriever = None

    def enrich_query(self, query: str, top_k: int = 8, hops: int = 2) -> dict:
        """Retrieve GraphRAG context for a query. Returns enrichment dict with entities, relationships, and graph_context."""
        if self._retriever is None:
            return self._empty_enrichment(query)

        try:
            result = self._retriever.retrieve(query, top_k=top_k, hops=hops)
        except Exception as exc:
            _logger.warning("CopilotGraphRAGBridge.enrich_query: retriever error", error=str(exc))
            return self._empty_enrichment(query)

        entities: list = result.get("entities", [])
        relationships: list = result.get("relationships", [])
        context_summary: str = result.get("context_summary", "")

        enriched = bool(entities)

        if enriched:
            self._queries_enriched += 1
            self._total_entities += len(entities)

        return {
            "query": query,
            "graph_context": context_summary,
            "entities": entities,
            "relationships": relationships,
            "enriched": enriched,
        }

    def answer_with_context(
        self,
        query: str,
        conversation_history: list | None = None,
    ) -> dict:
        """Build a rule-based answer from GraphRAG context, or a fallback hint if unavailable.

        conversation_history is accepted for API compatibility but not used in the rule-based path.
        """
        enriched_data = self.enrich_query(query)

        if enriched_data["enriched"]:
            entities: list = enriched_data["entities"]
            sources: list[str] = [
                e.get("name", e.get("id", "unknown")) for e in entities[:10]
            ]
            graph_context: str = enriched_data["graph_context"]
            confidence = min(0.5 + (len(entities) * 0.05), 0.95)
            answer = (
                f"Based on TrustGraph knowledge context, here is what is relevant to your query: "
                f'"{query}"\n\n'
                f"{graph_context}\n\n"
                f"Sources consulted: {', '.join(sources[:5]) if sources else 'none'}."
            )
            return {
                "answer": answer,
                "sources": sources,
                "confidence": confidence,
                "graph_context": graph_context,
                "retrieval_method": "graph_rag",
            }

        answer = (
            f"I was unable to find specific knowledge graph context for your query: "
            f'"{query}". '
            "For security-related questions, consider reviewing your CVE feed, "
            "compliance controls, and asset inventory for relevant context."
        )
        return {
            "answer": answer,
            "sources": [],
            "confidence": 0.0,
            "graph_context": "",
            "retrieval_method": "fallback",
        }

    def get_bridge_stats(self) -> dict:
        """Return bridge usage statistics (queries_enriched, avg_entities_per_query, cache_hits)."""
        avg = (
            self._total_entities / self._queries_enriched
            if self._queries_enriched > 0
            else 0.0
        )
        return {
            "queries_enriched": self._queries_enriched,
            "avg_entities_per_query": avg,
            "cache_hits": self._cache_hits,
        }

    @staticmethod
    def _empty_enrichment(query: str) -> dict:
        return {
            "query": query,
            "graph_context": "",
            "entities": [],
            "relationships": [],
            "enriched": False,
        }
