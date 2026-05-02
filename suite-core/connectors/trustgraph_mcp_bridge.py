"""
TrustGraph MCP Bridge for ALDECI Connector Framework

Bridges ALDECI's connector framework to TrustGraph's MCP (Model Context Protocol)
integration. Handles:
- Registration of ALDECI connectors as MCP tools in TrustGraph
- Routing normalized findings to appropriate Knowledge Cores
- Graph relationship creation and querying via GraphRAG
- On-demand connector invocation via MCP

Note: MCP auth is "emerging" — n8n handles all external API credential management.
TrustGraph MCP is for graph-internal tool invocation only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess  # nosec B404
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Try to import TrustGraph packages; provide graceful fallback
TRUSTGRAPH_AVAILABLE = False
try:
    import trustgraph
    from trustgraph import GraphQuery, KnowledgeCore
    TRUSTGRAPH_AVAILABLE = True
except ImportError:
    logger.warning(
        "trustgraph package not installed. "
        "TrustGraphMCPBridge will operate in simulation mode. "
        "Install with: pip install trustgraph trustgraph-cli"
    )


class TrustGraphMCPBridge:
    """
    Bridges ALDECI connectors to TrustGraph's MCP integration.

    Routes connector data to 5 Knowledge Cores:
    - Core 1: Customer Environment (per-tenant)
    - Core 2: Threat Intelligence (shared)
    - Core 3: Compliance & Regulatory (versioned)
    - Core 4: Decision Memory (append-only)
    - Core 5: Competitive Intelligence

    Attributes:
        pulsar_host (str): Pulsar message bus host for TrustGraph
        graph_store_url (str): TrustGraph Knowledge Graph storage URL
        registered_tools (Dict[str, Dict]): Cache of registered MCP tools
        knowledge_cores (Dict[int, Any]): Connected Knowledge Core clients
    """

    def __init__(
        self,
        pulsar_host: str = "localhost:6650",
        graph_store_url: str = "http://localhost:8000",
    ) -> None:
        """
        Initialize TrustGraph MCP Bridge.

        Args:
            pulsar_host: Pulsar message bus endpoint for async messaging
            graph_store_url: TrustGraph GraphRAG service URL
        """
        self.pulsar_host = pulsar_host
        self.graph_store_url = graph_store_url
        self.registered_tools: Dict[str, Dict[str, Any]] = {}
        self.knowledge_cores: Dict[int, Any] = {}
        self._tg_available = TRUSTGRAPH_AVAILABLE

        logger.info(
            f"TrustGraphMCPBridge initialized: "
            f"pulsar={pulsar_host}, graph_store={graph_store_url}, "
            f"trustgraph_available={self._tg_available}"
        )

    def register_connector(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler_path: str,
    ) -> Dict[str, Any]:
        """
        Register an ALDECI connector as an MCP tool in TrustGraph.

        Calls tg-set-mcp-tool CLI to register the connector, making it available
        as a callable MCP tool within the TrustGraph environment.

        Args:
            name: Unique connector name (e.g., 'github-repo-scanner')
            description: Human-readable description of connector purpose
            input_schema: JSON Schema describing connector input parameters
            handler_path: Path to connector handler or lambda function

        Returns:
            Dictionary with registration status and tool metadata:
                {
                    "success": bool,
                    "tool_id": str,
                    "name": str,
                    "description": str,
                    "input_schema": Dict,
                    "handler_path": str,
                    "registered_at": float (unix timestamp)
                }

        Raises:
            RuntimeError: If TrustGraph CLI is unavailable or registration fails
        """
        try:
            tool_id = f"aldeci-{name}-{int(time.time())}"

            if self._tg_available:
                # Use tg-set-mcp-tool CLI to register
                cmd = [
                    "tg-set-mcp-tool",
                    "--tool-id", tool_id,
                    "--name", name,
                    "--description", description,
                    "--input-schema", json.dumps(input_schema),
                    "--handler", handler_path,
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode != 0:
                    raise RuntimeError(
                        f"tg-set-mcp-tool failed: {result.stderr}"
                    )

                logger.info(f"Registered connector '{name}' as MCP tool: {tool_id}")
            else:
                logger.warning(
                    f"TrustGraph unavailable; simulating registration for '{name}'"
                )

            # Cache tool metadata
            tool_metadata = {
                "success": True,
                "tool_id": tool_id,
                "name": name,
                "description": description,
                "input_schema": input_schema,
                "handler_path": handler_path,
                "registered_at": time.time(),
            }
            self.registered_tools[name] = tool_metadata

            return tool_metadata

        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"tg-set-mcp-tool timed out registering connector '{name}'"
            )
        except Exception as e:
            logger.error(f"Failed to register connector '{name}': {e}")
            raise

    async def ingest_to_core(
        self,
        core_id: int,
        entities: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Ingest normalized findings into a specific Knowledge Core.

        Routes entities to the appropriate Knowledge Core based on their type:
        - Core 1: Customer Environment (per-tenant deployments, config, inventory)
        - Core 2: Threat Intelligence (CVEs, threat actors, malware, TTPs)
        - Core 3: Compliance & Regulatory (control mappings, audit logs, versioned)
        - Core 4: Decision Memory (remediation actions, closure reasons, append-only)
        - Core 5: Competitive Intelligence (competitor monitoring, market trends)

        Args:
            core_id: Knowledge Core ID (1-5)
            entities: List of normalized entity dictionaries with required fields:
                {
                    "entity_type": str,  # "vulnerability", "service", "team", etc.
                    "entity_id": str,    # unique identifier
                    "attributes": Dict,  # entity properties
                    "tenant_id": str,    # for Core 1 isolation
                    "timestamp": float,  # when discovered/updated
                }

        Returns:
            {
                "success": bool,
                "core_id": int,
                "entities_ingested": int,
                "ingestion_id": str,
                "errors": List[Dict]  # any per-entity errors
            }

        Raises:
            ValueError: If core_id is invalid (not 1-5)
            RuntimeError: If ingestion fails
        """
        if not 1 <= core_id <= 5:
            raise ValueError(f"core_id must be 1-5, got {core_id}")

        try:
            ingestion_id = f"ingest-core{core_id}-{int(time.time() * 1000)}"
            errors = []

            logger.info(
                f"Ingesting {len(entities)} entities to Core {core_id} "
                f"(ingestion_id={ingestion_id})"
            )

            if self._tg_available and core_id in self.knowledge_cores:
                # Use actual TrustGraph Knowledge Core client
                try:
                    core = self.knowledge_cores[core_id]
                    for entity in entities:
                        try:
                            await asyncio.to_thread(
                                core.ingest,
                                entity["entity_type"],
                                entity["entity_id"],
                                entity.get("attributes", {}),
                            )
                        except Exception as e:
                            errors.append({
                                "entity_id": entity.get("entity_id"),
                                "error": str(e)
                            })
                except Exception as e:
                    logger.error(f"Core {core_id} ingestion error: {e}")
                    raise
            else:
                # Simulation mode: just validate structure
                logger.warning(
                    f"TrustGraph unavailable; simulating ingestion to Core {core_id}"
                )
                for entity in entities:
                    if not entity.get("entity_id"):
                        errors.append({
                            "entity": entity,
                            "error": "Missing entity_id"
                        })

            return {
                "success": len(errors) == 0,
                "core_id": core_id,
                "entities_ingested": len(entities) - len(errors),
                "ingestion_id": ingestion_id,
                "errors": errors,
            }

        except Exception as e:
            logger.error(f"Ingestion to Core {core_id} failed: {e}")
            raise

    async def create_relationships(
        self,
        edges: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Create graph edges (relationships) between entities.

        Examples:
            - vulnerability --affects--> service
            - service --owned-by--> team
            - team --reports-to--> manager
            - finding --resolved-by--> remediation_action

        Args:
            edges: List of edge dictionaries:
                [
                    {
                        "source_id": str,
                        "source_type": str,
                        "target_id": str,
                        "target_type": str,
                        "relationship_type": str,  # e.g. "affects", "owned_by"
                        "properties": Dict,         # optional edge metadata
                    },
                    ...
                ]

        Returns:
            {
                "success": bool,
                "relationships_created": int,
                "errors": List[Dict]
            }
        """
        try:
            errors = []
            created_count = 0

            logger.info(f"Creating {len(edges)} graph relationships")

            if self._tg_available and 1 in self.knowledge_cores:
                for edge in edges:
                    try:
                        # Use Core 1 as the relationship hub
                        core = self.knowledge_cores[1]
                        await asyncio.to_thread(
                            core.create_relationship,
                            edge["source_id"],
                            edge["source_type"],
                            edge["target_id"],
                            edge["target_type"],
                            edge["relationship_type"],
                            edge.get("properties", {}),
                        )
                        created_count += 1
                    except Exception as e:
                        errors.append({
                            "edge": edge,
                            "error": str(e)
                        })
            else:
                logger.warning("TrustGraph unavailable; simulating relationships")
                created_count = len(edges)

            return {
                "success": len(errors) == 0,
                "relationships_created": created_count,
                "errors": errors,
            }

        except Exception as e:
            logger.error(f"Relationship creation failed: {e}")
            raise

    async def query_graph(
        self,
        query: str,
        core_ids: List[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query across Knowledge Cores using GraphRAG.

        Executes a natural language or structured query against the graph,
        returning related entities and their relationships.

        Args:
            query: Natural language or GraphQL query string
                Examples:
                  "Find all services affected by critical vulnerabilities"
                  "What teams own the database services?"
                  "Show the remediation path for CVE-2024-1234"
            core_ids: List of Core IDs to query (default: [1, 2, 3, 4, 5])

        Returns:
            List of query result dictionaries:
                [
                    {
                        "entity_id": str,
                        "entity_type": str,
                        "attributes": Dict,
                        "relationships": List[Dict],
                        "relevance_score": float,
                    },
                    ...
                ]
        """
        if core_ids is None:
            core_ids = [1, 2, 3, 4, 5]

        try:
            logger.info(f"Executing graph query: {query[:100]}... on cores {core_ids}")

            results = []

            if self._tg_available and 1 in self.knowledge_cores:
                # Use GraphRAG query engine
                try:
                    core = self.knowledge_cores[1]
                    results = await asyncio.to_thread(
                        core.query,
                        query,
                        core_ids,
                    )
                except Exception as e:
                    logger.error(f"GraphRAG query failed: {e}")
                    return []
            else:
                logger.warning(
                    "TrustGraph unavailable; returning empty results for query"
                )

            return results

        except Exception as e:
            logger.error(f"Graph query failed: {e}")
            raise

    async def invoke_connector(
        self,
        name: str,
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Invoke a registered connector via MCP.

        TrustGraph pulls on-demand execution from the registered MCP handler.
        This allows TrustGraph to request fresh data from connectors as needed
        within graph analysis flows.

        Args:
            name: Registered connector name (e.g., 'github-repo-scanner')
            params: Input parameters for the connector
                {
                    "org_name": "myorg",
                    "repos": ["repo1", "repo2"],
                    ...
                }

        Returns:
            Connector output:
                {
                    "success": bool,
                    "data": Any,           # connector output
                    "execution_time_ms": float,
                    "errors": List[str],
                }
        """
        try:
            if name not in self.registered_tools:
                raise ValueError(f"Connector '{name}' not registered")

            tool = self.registered_tools[name]
            tool_id = tool["tool_id"]

            logger.info(f"Invoking connector '{name}' with tool_id={tool_id}")

            start_time = time.time()

            if self._tg_available:
                # Use tg-invoke-mcp-tool CLI
                cmd = [
                    "tg-invoke-mcp-tool",
                    "--tool-id", tool_id,
                    "--params", json.dumps(params),
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout for connector execution
                )

                elapsed_ms = (time.time() - start_time) * 1000

                if result.returncode != 0:
                    logger.error(f"Connector '{name}' invocation failed: {result.stderr}")
                    return {
                        "success": False,
                        "data": None,
                        "execution_time_ms": elapsed_ms,
                        "errors": [result.stderr],
                    }

                try:
                    output = json.loads(result.stdout)
                except json.JSONDecodeError:
                    output = {"raw_output": result.stdout}

                return {
                    "success": True,
                    "data": output,
                    "execution_time_ms": elapsed_ms,
                    "errors": [],
                }
            else:
                # Simulation mode
                logger.warning("TrustGraph unavailable; simulating invocation")
                return {
                    "success": True,
                    "data": {"simulated": True, "params": params},
                    "execution_time_ms": 0.0,
                    "errors": [],
                }

        except subprocess.TimeoutExpired:
            elapsed_ms = (time.time() - start_time) * 1000
            logger.error(f"Connector '{name}' invocation timed out")
            return {
                "success": False,
                "data": None,
                "execution_time_ms": elapsed_ms,
                "errors": ["Invocation timed out (300s)"],
            }
        except Exception as e:
            logger.error(f"Failed to invoke connector '{name}': {e}")
            raise

    def get_registered_tools(self) -> List[Dict[str, Any]]:
        """
        List all registered MCP tools.

        Returns:
            List of tool metadata dictionaries:
                [
                    {
                        "tool_id": str,
                        "name": str,
                        "description": str,
                        "input_schema": Dict,
                        "registered_at": float,
                    },
                    ...
                ]
        """
        return list(self.registered_tools.values())

    def connect_knowledge_core(
        self,
        core_id: int,
        core_client: Any,
    ) -> None:
        """
        Register a Knowledge Core client for ingestion and querying.

        Args:
            core_id: Knowledge Core ID (1-5)
            core_client: Initialized TrustGraph KnowledgeCore client

        Raises:
            ValueError: If core_id is invalid
        """
        if not 1 <= core_id <= 5:
            raise ValueError(f"core_id must be 1-5, got {core_id}")

        self.knowledge_cores[core_id] = core_client
        logger.info(f"Connected Knowledge Core {core_id}")

    async def health_check(self) -> Dict[str, Any]:
        """
        Check bridge health and connectivity.

        Returns:
            {
                "healthy": bool,
                "pulsar_available": bool,
                "graph_store_available": bool,
                "trustgraph_available": bool,
                "registered_tools_count": int,
                "connected_cores": List[int],
            }
        """
        try:
            # In a real implementation, ping Pulsar and graph store
            return {
                "healthy": True,
                "pulsar_available": self._tg_available,
                "graph_store_available": self._tg_available,
                "trustgraph_available": self._tg_available,
                "registered_tools_count": len(self.registered_tools),
                "connected_cores": list(self.knowledge_cores.keys()),
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "healthy": False,
                "pulsar_available": False,
                "graph_store_available": False,
                "trustgraph_available": False,
                "registered_tools_count": len(self.registered_tools),
                "connected_cores": list(self.knowledge_cores.keys()),
            }
