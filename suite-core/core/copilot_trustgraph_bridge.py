"""CopilotTrustGraphBridge — intent-aware TrustGraph context enrichment for Security Copilot.

Classifies the user's query intent (CVE lookup, asset query, compliance check,
past-decision recall) and routes to the relevant TrustGraph Knowledge Cores.
Returns a structured CopilotContext for LLM prompt injection.

Knowledge Core mapping:
    1 = customer_env   — services, assets, infrastructure
    2 = threat_intel   — CVEs, TTPs, threat actors
    3 = compliance     — controls, frameworks, evidence
    4 = decision_memory — council verdicts, past decisions
    5 = external       — competitor intel, external references

Personas served: P03 (SOC T1), P04 (SOC T2), P20 (Security Architect)

Usage:
    bridge = CopilotTrustGraphBridge()
    ctx = bridge.enrich_query("What CVEs affect our production API?", user_context={"org_id": "acme"})
    # ctx.context_text is ready for LLM system prompt injection
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Intent categories
# ---------------------------------------------------------------------------

INTENT_CVE = "cve"
INTENT_ASSET = "asset"
INTENT_COMPLIANCE = "compliance"
INTENT_DECISION = "decision"
INTENT_THREAT = "threat"
INTENT_GENERAL = "general"

# Keywords used to classify intent
_INTENT_PATTERNS: Dict[str, List[str]] = {
    INTENT_CVE: [
        r"\bcve[- ]?\d{4}[- ]?\d+\b",
        r"\bvulnerab",
        r"\bexploit",
        r"\bpatch",
        r"\blog4",
        r"\bzeroday\b",
        r"\b0day\b",
        r"\bcvss\b",
        r"\bepss\b",
    ],
    INTENT_ASSET: [
        r"\basset",
        r"\bservice",
        r"\binfrastructure",
        r"\bhost",
        r"\bserver",
        r"\bapplication",
        r"\bproduction",
        r"\bprod\b",
        r"\bapi\b",
        r"\bendpoint",
        r"\bcontainer",
        r"\bcluster",
    ],
    INTENT_COMPLIANCE: [
        r"\bcompliance",
        r"\bcontrol",
        r"\bframework",
        r"\baudit",
        r"\bsoc\s*2",
        r"\bpci\b",
        r"\bnist\b",
        r"\biso\s*27",
        r"\bgdpr\b",
        r"\bhipaa\b",
        r"\bevidence\b",
        r"\bgap\b",
    ],
    INTENT_DECISION: [
        r"\bdecision",
        r"\bverdict",
        r"\bfalse.?positive",
        r"\bprevious",
        r"\blast time",
        r"\bhistor",
        r"\bcouncil",
        r"\bapproved",
        r"\brejected",
        r"\bwaivers?\b",
    ],
    INTENT_THREAT: [
        r"\bthreat",
        r"\battack",
        r"\bactor",
        r"\bttp",
        r"\bmitre",
        r"\bcampaign",
        r"\bioc\b",
        r"\bmalware",
        r"\bransom",
        r"\bphish",
        r"\bbreach",
    ],
}

# Intent → Knowledge Core IDs to query
_INTENT_CORE_MAP: Dict[str, List[int]] = {
    INTENT_CVE: [2, 1],          # threat_intel + customer_env
    INTENT_ASSET: [1, 2],        # customer_env + threat_intel
    INTENT_COMPLIANCE: [3, 1, 4], # compliance + customer_env + decision_memory
    INTENT_DECISION: [4, 2, 3],  # decision_memory + threat_intel + compliance
    INTENT_THREAT: [2, 4, 1],    # threat_intel + decision_memory + customer_env
    INTENT_GENERAL: [2, 1, 3, 4],  # all main cores
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CopilotContext:
    """Structured TrustGraph context ready for LLM prompt injection.

    Attributes:
        intent: Detected query intent
        entities: Matched entities across cores
        relationships: Graph relationships for matched entities
        context_text: Formatted markdown string for LLM system prompt
        sources: Knowledge Core IDs that contributed results
        entity_count: Total entities returned
        available: Whether TrustGraph was reachable
    """

    intent: str = INTENT_GENERAL
    entities: List[Dict[str, Any]] = field(default_factory=list)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    context_text: str = ""
    sources: List[int] = field(default_factory=list)
    entity_count: int = 0
    available: bool = True


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------


class CopilotTrustGraphBridge:
    """Enriches Copilot queries with TrustGraph semantic context.

    Performs intent classification on the raw query, routes to relevant
    Knowledge Cores, and returns a CopilotContext suitable for injection
    into an LLM system prompt.

    Graceful degradation: if TrustGraph is unavailable the bridge returns a
    CopilotContext with available=False and empty fields — the Copilot
    continues without graph context.

    Usage:
        bridge = CopilotTrustGraphBridge()
        ctx = bridge.enrich_query(
            "CVE-2021-44228 remediation for Log4j",
            user_context={"org_id": "acme", "agent_type": "security_analyst"},
        )
        prompt += ctx.context_text
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialise the bridge.

        Args:
            db_path: Path to TrustGraph SQLite DB.  Defaults to the project
                     standard location used by KnowledgeStore.
        """
        self._db_path = db_path
        self._adapter: Optional[Any] = None
        self._available: bool = True
        self._init_adapter()

    def _init_adapter(self) -> None:
        """Attempt to build the underlying GraphRAG adapter."""
        try:
            from core.copilot_graphrag import CopilotGraphRAGAdapter

            kwargs: Dict[str, Any] = {}
            if self._db_path is not None:
                kwargs["db_path"] = self._db_path
            self._adapter = CopilotGraphRAGAdapter(**kwargs)
            self._available = self._adapter._available
            logger.info("CopilotTrustGraphBridge: adapter initialized", available=self._available)
        except Exception as exc:
            logger.warning(
                "CopilotTrustGraphBridge: could not initialize adapter, degrading gracefully",
                error=str(exc),
            )
            self._adapter = None
            self._available = False

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def enrich_query(self, query: str, user_context: Optional[Dict[str, Any]] = None) -> CopilotContext:
        """Classify query intent and retrieve relevant TrustGraph context.

        Steps:
          1. Detect intent from query text
          2. Map intent → Knowledge Cores to search
          3. Execute GraphRAG query on those cores
          4. Return structured CopilotContext

        Args:
            query: Raw natural-language query from the Copilot user
            user_context: Optional dict with keys like ``org_id``, ``agent_type``

        Returns:
            CopilotContext with populated context_text (empty when unavailable)
        """
        if not self._available or self._adapter is None:
            return CopilotContext(available=False)

        ctx = user_context or {}
        org_id: str = ctx.get("org_id", "default")
        # If caller already knows the agent type, honour it; otherwise derive
        # it from intent so the adapter queries the right cores.
        agent_type: str = ctx.get("agent_type", "general")

        intent = self._classify_intent(query)

        # Use intent-derived agent_type only when caller didn't specify one
        if agent_type == "general":
            agent_type = _intent_to_agent_type(intent)

        try:
            from core.copilot_graphrag import GraphRAGResult

            result: GraphRAGResult = self._adapter.query(
                query_text=query,
                agent_type=agent_type,
                org_id=org_id,
                limit_per_core=5,
                neighbor_depth=1,
            )

            return CopilotContext(
                intent=intent,
                entities=result.entities,
                relationships=result.relationships,
                context_text=result.context_text,
                sources=result.sources,
                entity_count=result.entity_count,
                available=result.available,
            )

        except Exception as exc:
            logger.warning(
                "CopilotTrustGraphBridge.enrich_query: error, degrading gracefully",
                error=str(exc),
            )
            return CopilotContext(available=False)

    def _classify_intent(self, query: str) -> str:
        """Classify the user's query into an intent category.

        Scans the query against keyword/regex patterns in priority order.
        Returns the first matching intent, or INTENT_GENERAL if none match.

        Args:
            query: Raw query text

        Returns:
            One of the INTENT_* constants
        """
        query_lower = query.lower()
        # Priority order: CVE > asset > compliance > decision > threat > general
        for intent in (INTENT_CVE, INTENT_ASSET, INTENT_COMPLIANCE, INTENT_DECISION, INTENT_THREAT):
            patterns = _INTENT_PATTERNS[intent]
            if any(re.search(pat, query_lower) for pat in patterns):
                return intent
        return INTENT_GENERAL

    def _query_threat_intel(self, query: str, org_id: str = "default") -> List[Dict[str, Any]]:
        """Query threat intelligence core (Core 2) directly.

        Convenience method for callers that need threat intel only.

        Args:
            query: Search text
            org_id: Tenant org ID

        Returns:
            List of entity dicts from threat intel core
        """
        if not self._available or self._adapter is None:
            return []
        try:
            entities = self._adapter._search_entities(
                core_id=2, query_text=query, org_id=org_id, limit=10
            )
            return [e.to_dict() for e in entities]
        except Exception as exc:
            logger.debug("_query_threat_intel failed", error=str(exc))
            return []

    def _query_compliance(self, query: str, org_id: str = "default") -> List[Dict[str, Any]]:
        """Query compliance core (Core 3) directly.

        Args:
            query: Search text
            org_id: Tenant org ID

        Returns:
            List of entity dicts from compliance core
        """
        if not self._available or self._adapter is None:
            return []
        try:
            entities = self._adapter._search_entities(
                core_id=3, query_text=query, org_id=org_id, limit=10
            )
            return [e.to_dict() for e in entities]
        except Exception as exc:
            logger.debug("_query_compliance failed", error=str(exc))
            return []

    def _query_assets(self, query: str, org_id: str = "default") -> List[Dict[str, Any]]:
        """Query customer environment core (Core 1) directly.

        Args:
            query: Search text
            org_id: Tenant org ID

        Returns:
            List of entity dicts from customer environment core
        """
        if not self._available or self._adapter is None:
            return []
        try:
            entities = self._adapter._search_entities(
                core_id=1, query_text=query, org_id=org_id, limit=10
            )
            return [e.to_dict() for e in entities]
        except Exception as exc:
            logger.debug("_query_assets failed", error=str(exc))
            return []

    def _query_decisions(self, query: str, org_id: str = "default") -> List[Dict[str, Any]]:
        """Query decision memory core (Core 4) directly.

        Args:
            query: Search text
            org_id: Tenant org ID

        Returns:
            List of entity dicts from decision memory core
        """
        if not self._available or self._adapter is None:
            return []
        try:
            entities = self._adapter._search_entities(
                core_id=4, query_text=query, org_id=org_id, limit=10
            )
            return [e.to_dict() for e in entities]
        except Exception as exc:
            logger.debug("_query_decisions failed", error=str(exc))
            return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _intent_to_agent_type(intent: str) -> str:
    """Map an intent label to a CopilotGraphRAGAdapter agent_type string."""
    _map = {
        INTENT_CVE: "security_analyst",
        INTENT_ASSET: "security_analyst",
        INTENT_COMPLIANCE: "compliance",
        INTENT_DECISION: "security_analyst",
        INTENT_THREAT: "security_analyst",
        INTENT_GENERAL: "general",
    }
    return _map.get(intent, "general")


# Module-level singleton
_bridge: Optional[CopilotTrustGraphBridge] = None


def get_bridge() -> CopilotTrustGraphBridge:
    """Return the module-level CopilotTrustGraphBridge singleton."""
    global _bridge
    if _bridge is None:
        _bridge = CopilotTrustGraphBridge()
    return _bridge
