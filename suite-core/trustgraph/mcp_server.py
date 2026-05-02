"""
TrustGraph MCP Server for ALDECI.

Implements the Model Context Protocol (MCP) server for TrustGraph, exposing
Knowledge Cores as tools and resources for LLM agents.

Tools:
- trustgraph.query — Natural language query across cores
- trustgraph.ingest — Add knowledge to a specific core
- trustgraph.search — Structured search with filters
- trustgraph.relate — Create relationship between entities
- trustgraph.get_entity — Get entity by ID with relationships
- trustgraph.list_cores — List all 5 cores with stats
- trustgraph.core_stats — Detailed statistics for a core

Resources:
- trustgraph://cores/{core_id} — Core metadata
- trustgraph://entities/{entity_id} — Entity details
- trustgraph://relationships/{entity_id} — Entity relationships

Usage:
    server = TrustGraphMCPServer()

    # List available tools
    tools = server.list_tools()

    # Call a tool
    result = server.call_tool("trustgraph.query", {
        "query": "What are critical vulnerabilities in production?",
        "org_id": "org_123"
    })

    # Read a resource
    core_data = server.read_resource("trustgraph://cores/1")
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.graphrag_engine import GraphQuery, GraphRAGEngine

from trustgraph.knowledge_store import (
    KnowledgeEntity,
    KnowledgeRelationship,
    KnowledgeStore,
)

logger = logging.getLogger(__name__)

__all__ = ["TrustGraphMCPServer"]


# ============================================================================
# MCP Protocol Types
# ============================================================================


@dataclass
class MCPTool:
    """MCP Tool definition."""

    name: str
    description: str
    inputSchema: Dict[str, Any]


@dataclass
class MCPResource:
    """MCP Resource definition."""

    uri: str
    name: str
    description: str
    mimeType: str = "application/json"


@dataclass
class ToolCallAudit:
    """Audit record for tool calls."""

    tool_id: str
    call_id: str
    org_id: str
    timestamp: datetime
    status: str  # "success", "error"
    params: Dict[str, Any]
    result_hash: str
    duration_ms: float
    error: Optional[str] = None


# ============================================================================
# TrustGraph MCP Server
# ============================================================================


class TrustGraphMCPServer:
    """MCP server for TrustGraph Knowledge Cores.

    Exposes TrustGraph as MCP tools and resources for integration with LLM agents.
    Handles tool execution, resource serving, and audit logging.
    """

    # The 5 Knowledge Cores
    CORE_DEFINITIONS = {
        1: {
            "name": "Customer Environment Core",
            "description": "Assets, configurations, network topology, business criticality",
            "entity_types": ["Organization", "Team", "Service", "Repository", "Artifact", "Host", "Network"],
        },
        2: {
            "name": "Threat Intelligence Core",
            "description": "CVEs, exploits, campaigns, TTPs, IOCs",
            "entity_types": ["CVE", "Exploit", "Campaign", "TTP", "IOC", "Threat", "Vulnerability"],
        },
        3: {
            "name": "Compliance & Regulatory Core",
            "description": "Frameworks (SOC2, HIPAA, PCI, ISO27001, NIST, GDPR, FedRAMP), controls, evidence",
            "entity_types": ["Framework", "Control", "Evidence", "Requirement", "Mapping", "Audit"],
        },
        4: {
            "name": "Decision Memory Core",
            "description": "Council verdicts, analyst overrides, false positive tracking, accuracy stats",
            "entity_types": ["Verdict", "Override", "Decision", "FalsePositive", "Accuracy", "Analysis"],
        },
        5: {
            "name": "Competitive Intelligence Core",
            "description": "Competitor features, market positioning, pricing",
            "entity_types": ["Competitor", "Product", "Feature", "Positioning", "Pricing", "Capability"],
        },
    }

    def __init__(self, knowledge_store: Optional[KnowledgeStore] = None) -> None:
        """Initialize MCP server.

        Args:
            knowledge_store: Optional KnowledgeStore instance (creates new one if not provided)
        """
        self.knowledge_store = knowledge_store or KnowledgeStore()
        self.graphrag_engine = GraphRAGEngine()
        self.audit_log: List[ToolCallAudit] = []
        self._tools_cache: Optional[List[MCPTool]] = None
        self._resources_cache: Optional[List[MCPResource]] = None
        logger.info("TrustGraphMCPServer initialized")

    # ========================================================================
    # MCP Protocol: Tool Management
    # ========================================================================

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available MCP tools.

        Returns:
            List of tool definitions matching MCP spec
        """
        if self._tools_cache:
            return [asdict(t) for t in self._tools_cache]

        tools = [
            MCPTool(
                name="trustgraph.query",
                description="Natural language query across Knowledge Cores using GraphRAG",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Natural language query (e.g., 'What are critical vulnerabilities in production?')",
                        },
                        "target_cores": {
                            "type": "array",
                            "items": {"type": "integer", "minimum": 1, "maximum": 5},
                            "description": "Which cores to query (1-5). Default: [1,2,3]",
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum results per core. Default: 20",
                        },
                        "org_id": {
                            "type": "string",
                            "description": "Organization/tenant ID for multi-tenancy. Default: 'default'",
                        },
                    },
                    "required": ["query"],
                },
            ),
            MCPTool(
                name="trustgraph.ingest",
                description="Add or update a knowledge entity in a specific core",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "entity_id": {
                            "type": "string",
                            "description": "Unique identifier for the entity",
                        },
                        "core_id": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 5,
                            "description": "Target Knowledge Core (1-5)",
                        },
                        "entity_type": {
                            "type": "string",
                            "description": "Type of entity (e.g., Service, CVE, Control)",
                        },
                        "name": {
                            "type": "string",
                            "description": "Human-readable name",
                        },
                        "properties": {
                            "type": "object",
                            "description": "Arbitrary properties as key-value pairs",
                        },
                        "org_id": {
                            "type": "string",
                            "description": "Organization/tenant ID",
                        },
                    },
                    "required": ["entity_id", "core_id", "entity_type", "name"],
                },
            ),
            MCPTool(
                name="trustgraph.search",
                description="Full-text search in a Knowledge Core",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "core_id": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 5,
                            "description": "Knowledge Core to search",
                        },
                        "query": {
                            "type": "string",
                            "description": "Search query text",
                        },
                        "entity_type": {
                            "type": "string",
                            "description": "Optional filter by entity type",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum results. Default: 20",
                        },
                        "org_id": {
                            "type": "string",
                            "description": "Organization/tenant ID",
                        },
                    },
                    "required": ["core_id", "query"],
                },
            ),
            MCPTool(
                name="trustgraph.relate",
                description="Create a relationship between two entities",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "source_id": {
                            "type": "string",
                            "description": "Source entity ID",
                        },
                        "target_id": {
                            "type": "string",
                            "description": "Target entity ID",
                        },
                        "rel_type": {
                            "type": "string",
                            "description": "Relationship type (e.g., depends_on, related_to, affects)",
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                            "description": "Confidence score (0-1). Default: 1.0",
                        },
                        "properties": {
                            "type": "object",
                            "description": "Optional relationship properties",
                        },
                    },
                    "required": ["source_id", "target_id", "rel_type"],
                },
            ),
            MCPTool(
                name="trustgraph.get_entity",
                description="Get a single entity by ID with its relationships",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "entity_id": {
                            "type": "string",
                            "description": "Entity ID to retrieve",
                        },
                    },
                    "required": ["entity_id"],
                },
            ),
            MCPTool(
                name="trustgraph.list_cores",
                description="List all 5 Knowledge Cores with summary statistics",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            MCPTool(
                name="trustgraph.core_stats",
                description="Get detailed statistics for a Knowledge Core",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "core_id": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 5,
                            "description": "Knowledge Core ID",
                        },
                    },
                    "required": ["core_id"],
                },
            ),
        ]

        self._tools_cache = tools
        return [asdict(t) for t in tools]

    def call_tool(self, tool_name: str, params: Dict[str, Any], org_id: str = "default") -> Dict[str, Any]:
        """Execute an MCP tool.

        Args:
            tool_name: Name of tool to call (e.g., "trustgraph.query")
            params: Tool parameters
            org_id: Organization/tenant ID

        Returns:
            Tool result as dictionary
        """
        call_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        status = "success"
        result: Dict[str, Any] = {}
        error: Optional[str] = None

        try:
            if tool_name == "trustgraph.query":
                result = self._tool_query(params, org_id)
            elif tool_name == "trustgraph.ingest":
                result = self._tool_ingest(params, org_id)
            elif tool_name == "trustgraph.search":
                result = self._tool_search(params, org_id)
            elif tool_name == "trustgraph.relate":
                result = self._tool_relate(params)
            elif tool_name == "trustgraph.get_entity":
                result = self._tool_get_entity(params)
            elif tool_name == "trustgraph.list_cores":
                result = self._tool_list_cores()
            elif tool_name == "trustgraph.core_stats":
                result = self._tool_core_stats(params)
            else:
                raise ValueError(f"Unknown tool: {tool_name}")

        except Exception as e:
            status = "error"
            error = str(e)
            result = {"error": error}
            logger.error(f"Tool execution failed: {tool_name} - {error}")

        # Audit logging
        duration_ms = (time.time() - start_time) * 1000
        result_hash = hashlib.sha256(json.dumps(result, default=str).encode()).hexdigest()

        audit = ToolCallAudit(
            tool_id=tool_name,
            call_id=call_id,
            org_id=org_id,
            timestamp=datetime.utcnow(),
            status=status,
            params=params,
            result_hash=result_hash,
            duration_ms=duration_ms,
            error=error,
        )
        self.audit_log.append(audit)

        logger.info(
            f"Tool call: {tool_name} [{call_id}] status={status} duration={duration_ms:.1f}ms org={org_id}"
        )

        return result

    # ========================================================================
    # MCP Protocol: Resource Management
    # ========================================================================

    def list_resources(self) -> List[Dict[str, Any]]:
        """List all available MCP resources.

        Returns:
            List of resource definitions
        """
        resources = [
            MCPResource(
                uri="trustgraph://cores/{core_id}",
                name="Knowledge Core",
                description="Get metadata and statistics for a Knowledge Core",
            ),
            MCPResource(
                uri="trustgraph://entities/{entity_id}",
                name="Entity Details",
                description="Get full details of an entity including properties",
            ),
            MCPResource(
                uri="trustgraph://relationships/{entity_id}",
                name="Entity Relationships",
                description="Get all relationships connected to an entity",
            ),
        ]

        return [asdict(r) for r in resources]

    def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a resource by URI.

        Args:
            uri: Resource URI (e.g., trustgraph://cores/1)

        Returns:
            Resource content as dictionary
        """
        try:
            if uri.startswith("trustgraph://cores/"):
                core_id = int(uri.split("/")[-1])
                return self._read_core_resource(core_id)
            elif uri.startswith("trustgraph://entities/"):
                entity_id = uri.split("/")[-1]
                return self._read_entity_resource(entity_id)
            elif uri.startswith("trustgraph://relationships/"):
                entity_id = uri.split("/")[-1]
                return self._read_relationships_resource(entity_id)
            else:
                return {"error": f"Unknown resource: {uri}"}
        except Exception as e:
            logger.error(f"Resource read failed: {uri} - {str(e)}")
            return {"error": str(e)}

    # ========================================================================
    # Tool Implementations
    # ========================================================================

    def _tool_query(self, params: Dict[str, Any], org_id: str) -> Dict[str, Any]:
        """Execute trustgraph.query tool."""
        query_text = params.get("query")
        if not query_text:
            raise ValueError("'query' parameter is required")

        target_cores = params.get("target_cores", [1, 2, 3])
        max_results = params.get("max_results", 20)

        # Build GraphQuery
        gq = GraphQuery(
            query_text=query_text,
            target_cores=target_cores,
            max_results=max_results,
            include_relationships=True,
        )

        # Execute via GraphRAG engine
        result = self.graphrag_engine.query(gq)

        return {
            "answer": result.answer,
            "evidence": result.evidence,
            "confidence": result.confidence,
            "sources": result.sources,
            "query_time_ms": result.query_time_ms,
            "cores_queried": result.cores_queried,
        }

    def _tool_ingest(self, params: Dict[str, Any], org_id: str) -> Dict[str, Any]:
        """Execute trustgraph.ingest tool."""
        entity = KnowledgeEntity(
            entity_id=params.get("entity_id"),
            core_id=params.get("core_id"),
            entity_type=params.get("entity_type"),
            name=params.get("name"),
            properties=params.get("properties", {}),
            org_id=params.get("org_id", org_id),
        )

        self.knowledge_store.ingest(entity)

        return {
            "status": "ingested",
            "entity_id": entity.entity_id,
            "core_id": entity.core_id,
            "org_id": entity.org_id,
        }

    def _tool_search(self, params: Dict[str, Any], org_id: str) -> Dict[str, Any]:
        """Execute trustgraph.search tool."""
        core_id = params.get("core_id")
        query_text = params.get("query")
        limit = params.get("limit", 20)

        if not core_id or not query_text:
            raise ValueError("'core_id' and 'query' parameters are required")

        filters = {}
        if "entity_type" in params:
            filters["entity_type"] = params["entity_type"]
        filters["org_id"] = params.get("org_id", org_id)

        results = self.knowledge_store.search(
            core_id=core_id,
            query_text=query_text,
            filters=filters,
            limit=limit,
        )

        return {
            "core_id": core_id,
            "query": query_text,
            "count": len(results),
            "results": [e.to_dict() for e in results],
        }

    def _tool_relate(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute trustgraph.relate tool."""
        rel = KnowledgeRelationship(
            rel_id=str(uuid.uuid4()),
            source_id=params.get("source_id"),
            target_id=params.get("target_id"),
            rel_type=params.get("rel_type"),
            confidence=params.get("confidence", 1.0),
            properties=params.get("properties", {}),
        )

        self.knowledge_store.add_relationship(rel)

        return {
            "status": "related",
            "rel_id": rel.rel_id,
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "rel_type": rel.rel_type,
            "confidence": rel.confidence,
        }

    def _tool_get_entity(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute trustgraph.get_entity tool."""
        entity_id = params.get("entity_id")
        if not entity_id:
            raise ValueError("'entity_id' parameter is required")

        entity = self.knowledge_store.get_entity(entity_id)
        if not entity:
            return {"error": f"Entity not found: {entity_id}"}

        relationships = self.knowledge_store.get_relationships(entity_id)

        return {
            "entity": entity.to_dict(),
            "relationships": [r.to_dict() for r in relationships],
            "relationship_count": len(relationships),
        }

    def _tool_list_cores(self) -> Dict[str, Any]:
        """Execute trustgraph.list_cores tool."""
        cores = []
        for core_id, definition in self.CORE_DEFINITIONS.items():
            stats = self.knowledge_store.core_stats(core_id)
            cores.append(
                {
                    "core_id": core_id,
                    "name": definition["name"],
                    "description": definition["description"],
                    "entity_types": definition["entity_types"],
                    "stats": stats,
                }
            )

        return {"cores": cores, "total_cores": len(cores)}

    def _tool_core_stats(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute trustgraph.core_stats tool."""
        core_id = params.get("core_id")
        if not core_id or not 1 <= core_id <= 5:
            raise ValueError("'core_id' must be 1-5")

        definition = self.CORE_DEFINITIONS[core_id]
        stats = self.knowledge_store.core_stats(core_id)

        return {
            "core_id": core_id,
            "name": definition["name"],
            "description": definition["description"],
            "entity_types": definition["entity_types"],
            "stats": stats,
        }

    # ========================================================================
    # Resource Implementations
    # ========================================================================

    def _read_core_resource(self, core_id: int) -> Dict[str, Any]:
        """Read trustgraph://cores/{core_id}"""
        if not 1 <= core_id <= 5:
            return {"error": f"Invalid core_id: {core_id}"}

        definition = self.CORE_DEFINITIONS[core_id]
        stats = self.knowledge_store.core_stats(core_id)

        return {
            "core_id": core_id,
            "name": definition["name"],
            "description": definition["description"],
            "entity_types": definition["entity_types"],
            "stats": stats,
        }

    def _read_entity_resource(self, entity_id: str) -> Dict[str, Any]:
        """Read trustgraph://entities/{entity_id}"""
        entity = self.knowledge_store.get_entity(entity_id)
        if not entity:
            return {"error": f"Entity not found: {entity_id}"}

        relationships = self.knowledge_store.get_relationships(entity_id)

        return {
            "entity": entity.to_dict(),
            "relationships": [r.to_dict() for r in relationships],
        }

    def _read_relationships_resource(self, entity_id: str) -> Dict[str, Any]:
        """Read trustgraph://relationships/{entity_id}"""
        entity = self.knowledge_store.get_entity(entity_id)
        if not entity:
            return {"error": f"Entity not found: {entity_id}"}

        relationships = self.knowledge_store.get_relationships(entity_id)
        neighbors = self.knowledge_store.get_neighbors(entity_id, depth=2)

        return {
            "entity_id": entity_id,
            "relationships": [r.to_dict() for r in relationships],
            "neighbors": [e.to_dict() for e in neighbors],
        }

    # ========================================================================
    # Audit and Introspection
    # ========================================================================

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent tool call audit logs.

        Args:
            limit: Maximum records to return

        Returns:
            List of audit records
        """
        logs = self.audit_log[-limit:]
        return [
            {
                "tool_id": log.tool_id,
                "call_id": log.call_id,
                "org_id": log.org_id,
                "timestamp": log.timestamp.isoformat(),
                "status": log.status,
                "duration_ms": log.duration_ms,
                "error": log.error,
            }
            for log in logs
        ]
