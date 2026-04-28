"""GraphRAG adapter for Security Copilot.

Enriches copilot queries with semantic context from TrustGraph Knowledge Cores.
Performs multi-core entity search + graph neighborhood traversal, then returns
structured context suitable for injection into LLM prompts.

Knowledge Core mapping:
    1 = customer_env   — services, assets, infrastructure
    2 = threat_intel   — CVEs, TTPs, threat actors
    3 = compliance     — controls, frameworks, evidence
    4 = decision_memory — council verdicts, past decisions
    5 = external       — competitor intel, external references

Personas served: P03 (SOC T1), P04 (SOC T2), P20 (Security Architect)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)

# Knowledge Core IDs with human-readable labels
CORE_CUSTOMER_ENV = 1
CORE_THREAT_INTEL = 2
CORE_COMPLIANCE = 3
CORE_DECISION_MEMORY = 4
CORE_EXTERNAL = 5

# Which cores to query per agent type
_AGENT_CORE_MAP: Dict[str, List[int]] = {
    "security_analyst": [CORE_THREAT_INTEL, CORE_CUSTOMER_ENV, CORE_DECISION_MEMORY],
    "pentest": [CORE_THREAT_INTEL, CORE_CUSTOMER_ENV],
    "compliance": [CORE_COMPLIANCE, CORE_CUSTOMER_ENV, CORE_DECISION_MEMORY],
    "remediation": [CORE_THREAT_INTEL, CORE_CUSTOMER_ENV, CORE_COMPLIANCE],
    "general": [CORE_THREAT_INTEL, CORE_CUSTOMER_ENV, CORE_COMPLIANCE, CORE_DECISION_MEMORY],
}

_CORE_LABELS: Dict[int, str] = {
    CORE_CUSTOMER_ENV: "Customer Environment",
    CORE_THREAT_INTEL: "Threat Intelligence",
    CORE_COMPLIANCE: "Compliance Controls",
    CORE_DECISION_MEMORY: "Past Decisions",
    CORE_EXTERNAL: "External Intel",
}


@dataclass
class GraphRAGResult:
    """Structured result from a GraphRAG query.

    Attributes:
        entities: Matched entities across cores
        relationships: Graph relationships for matched entities
        context_text: Formatted context string for LLM injection
        sources: Source core IDs that contributed results
        entity_count: Total entities found
        available: Whether TrustGraph was reachable
    """

    entities: List[Dict[str, Any]] = field(default_factory=list)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    context_text: str = ""
    sources: List[int] = field(default_factory=list)
    entity_count: int = 0
    available: bool = True


class CopilotGraphRAGAdapter:
    """Wraps TrustGraph KnowledgeStore to provide GraphRAG context for copilot queries.

    Usage:
        adapter = CopilotGraphRAGAdapter()
        result = adapter.query("Log4j CVE remediation steps", agent_type="security_analyst")
        # result.context_text is ready for LLM prompt injection

    Graceful degradation:
        If TrustGraph is unavailable (import error, DB missing, etc.),
        query() returns a GraphRAGResult with available=False and empty fields.
        The copilot continues with keyword-based search only.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialize the adapter.

        Args:
            db_path: Path to TrustGraph SQLite database. Defaults to
                     the project-standard location at /tmp/trustgraph.db.
        """
        self._db_path = db_path
        self._store: Optional[Any] = None
        self._available: bool = True
        self._init_store()

    def _init_store(self) -> None:
        """Attempt to initialize KnowledgeStore, set _available=False on failure."""
        try:
            from trustgraph.knowledge_store import KnowledgeStore

            kwargs: Dict[str, Any] = {}
            if self._db_path is not None:
                kwargs["db_path"] = self._db_path
            self._store = KnowledgeStore(**kwargs)
            logger.info("CopilotGraphRAGAdapter: KnowledgeStore initialized")
        except Exception as exc:
            logger.warning(
                "CopilotGraphRAGAdapter: KnowledgeStore unavailable, will degrade gracefully",
                error=str(exc),
            )
            self._store = None
            self._available = False

    def _search_entities(
        self,
        core_id: int,
        query_text: str,
        org_id: str,
        limit: int,
    ) -> List[Any]:
        """Search entities using FTS with LIKE fallback.

        KnowledgeStore.search() uses FTS5 which silently returns empty results
        when the content-table rowid join is misconfigured.  This method first
        tries the store's search(), and if it returns nothing, falls back to a
        direct LIKE query against the SQLite connection.

        Args:
            core_id: Knowledge Core to search
            query_text: Search text
            org_id: Tenant org ID
            limit: Maximum results

        Returns:
            List of KnowledgeEntity objects
        """
        # Try the store's built-in search first
        entities = self._store.search(
            core_id=core_id,
            query_text=query_text,
            filters={"org_id": org_id},
            limit=limit,
        )
        if entities:
            return entities

        # Fallback: direct LIKE query bypassing FTS
        try:
            conn = self._store._get_conn()
            cursor = conn.cursor()
            like_term = f"%{query_text}%"
            cursor.execute(
                """
                SELECT * FROM entities
                WHERE (name LIKE ? OR properties LIKE ?)
                AND core_id = ?
                AND org_id = ?
                AND deleted_at IS NULL
                LIMIT ?
                """,
                (like_term, like_term, core_id, org_id, limit),
            )
            rows = cursor.fetchall()
            return [self._store._row_to_entity(row) for row in rows]
        except Exception as exc:
            logger.debug(
                "GraphRAG LIKE fallback failed",
                core_id=core_id,
                error=str(exc),
            )
            return []

    def query(
        self,
        query_text: str,
        agent_type: str = "general",
        org_id: str = "default",
        limit_per_core: int = 5,
        neighbor_depth: int = 1,
    ) -> GraphRAGResult:
        """Run a GraphRAG query against TrustGraph.

        Steps:
          1. Determine which cores to search based on agent_type
          2. Search each core for matching entities (FTS + LIKE fallback)
          3. For top hits, fetch graph neighbors (depth=1)
          4. Collect relationships for matched entities
          5. Format all results into a context_text string

        Args:
            query_text: Natural language query from copilot user
            agent_type: Copilot agent type — controls which cores are searched
            org_id: Tenant org ID for multi-tenant filtering
            limit_per_core: Max entities to fetch per core
            neighbor_depth: Graph traversal depth for neighborhood search

        Returns:
            GraphRAGResult with populated context_text (empty if unavailable)
        """
        if not self._available or self._store is None:
            return GraphRAGResult(available=False)

        cores_to_search = _AGENT_CORE_MAP.get(agent_type, _AGENT_CORE_MAP["general"])

        all_entities: List[Dict[str, Any]] = []
        all_relationships: List[Dict[str, Any]] = []
        contributing_cores: List[int] = []
        seen_entity_ids: set = set()

        try:
            for core_id in cores_to_search:
                entities = self._search_entities(
                    core_id=core_id,
                    query_text=query_text,
                    org_id=org_id,
                    limit=limit_per_core,
                )

                if not entities:
                    continue

                contributing_cores.append(core_id)

                for entity in entities:
                    if entity.entity_id in seen_entity_ids:
                        continue
                    seen_entity_ids.add(entity.entity_id)
                    all_entities.append(entity.to_dict())

                    # Fetch graph neighbors for richer context
                    try:
                        neighbors = self._store.get_neighbors(
                            entity_id=entity.entity_id,
                            depth=neighbor_depth,
                        )
                        for neighbor in neighbors:
                            if neighbor.entity_id not in seen_entity_ids:
                                seen_entity_ids.add(neighbor.entity_id)
                                all_entities.append(neighbor.to_dict())
                    except Exception as nb_exc:
                        logger.debug(
                            "GraphRAG: neighbor traversal failed",
                            entity_id=entity.entity_id,
                            error=str(nb_exc),
                        )

                    # Fetch relationships for matched entity
                    try:
                        rels = self._store.get_relationships(entity_id=entity.entity_id)
                        for rel in rels:
                            all_relationships.append(rel.to_dict())
                    except Exception as rel_exc:
                        logger.debug(
                            "GraphRAG: relationship fetch failed",
                            entity_id=entity.entity_id,
                            error=str(rel_exc),
                        )

        except Exception as exc:
            logger.warning(
                "CopilotGraphRAGAdapter.query: unexpected error during graph search",
                error=str(exc),
            )
            return GraphRAGResult(available=False)

        context_text = self._format_context(all_entities, all_relationships, contributing_cores)

        return GraphRAGResult(
            entities=all_entities,
            relationships=all_relationships,
            context_text=context_text,
            sources=contributing_cores,
            entity_count=len(all_entities),
            available=True,
        )

    def _format_context(
        self,
        entities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
        contributing_cores: List[int],
    ) -> str:
        """Format graph results into an LLM-ready context string.

        Args:
            entities: Serialized entity dicts
            relationships: Serialized relationship dicts
            contributing_cores: Core IDs that returned results

        Returns:
            Formatted markdown string for LLM prompt injection
        """
        if not entities:
            return ""

        lines: List[str] = []
        lines.append("**TrustGraph Knowledge Context:**")

        # Group entities by core for readable output
        by_core: Dict[int, List[Dict[str, Any]]] = {}
        for ent in entities:
            cid = ent.get("core_id", 0)
            by_core.setdefault(cid, []).append(ent)

        for core_id in sorted(by_core.keys()):
            label = _CORE_LABELS.get(core_id, f"Core {core_id}")
            lines.append(f"\n*{label}:*")
            for ent in by_core[core_id][:8]:  # cap per-core output for prompt budget
                name = ent.get("name", "Unknown")
                etype = ent.get("entity_type", "")
                props = ent.get("properties", {})
                # Truncate properties to avoid prompt bloat
                props_str = _truncate_props(props, max_chars=200)
                lines.append(f"  - [{etype}] {name}: {props_str}")

        if relationships:
            lines.append(f"\n*Graph Relationships ({len(relationships)} found):*")
            for rel in relationships[:10]:  # cap relationships
                lines.append(
                    f"  - {rel.get('source_id', '?')} --[{rel.get('rel_type', '?')}]--> "
                    f"{rel.get('target_id', '?')} (confidence: {rel.get('confidence', 0):.2f})"
                )

        return "\n".join(lines)


def _truncate_props(props: Dict[str, Any], max_chars: int = 200) -> str:
    """Serialize and truncate properties dict for prompt injection."""
    import json

    try:
        s = json.dumps(props, default=str)
        if len(s) > max_chars:
            return s[:max_chars] + "..."
        return s
    except Exception:
        return str(props)[:max_chars]


# Module-level singleton — lazy initialized on first use
_adapter: Optional[CopilotGraphRAGAdapter] = None


def get_graphrag_adapter() -> CopilotGraphRAGAdapter:
    """Return the module-level GraphRAG adapter singleton."""
    global _adapter
    if _adapter is None:
        _adapter = CopilotGraphRAGAdapter()
    return _adapter
