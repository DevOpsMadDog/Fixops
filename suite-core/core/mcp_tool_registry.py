"""
MCP Tool Registration System for ALDECI Phase 8.

Manages dynamic registration and execution of MCP (Model Context Protocol) tools.
Handles tool registration, execution, schema export, and performance tracking.

Tools are organized by category (query, action, analysis, reporting) and support
permission-based filtering for security and compliance.

Built-in ALDECI tools are automatically registered on init:
  - aldeci.query_findings: Search findings by severity, stage, date range, connector
  - aldeci.get_risk_posture: Get current org risk posture score
  - aldeci.run_pipeline_stage: Trigger a specific pipeline stage on findings
  - aldeci.council_evaluate: Submit a finding for LLM Council evaluation
  - aldeci.get_connector_status: Health and metrics for all connectors
  - aldeci.search_knowledge_core: Query a specific TrustGraph Knowledge Core
  - aldeci.get_compliance_status: Compliance framework status and gaps
  - aldeci.create_playbook_run: Trigger an automated playbook
  - aldeci.get_dashboard_kpis: Fetch dashboard KPIs for a persona
  - aldeci.export_findings_report: Generate a findings report in JSON/CSV

Usage:
    registry = MCPToolRegistry()

    # Execute a tool
    result = registry.execute_tool("aldeci.query_findings", params={
        "severity": "critical",
        "days": 7
    }, context={"org_id": "org_123"})

    # List tools
    tools = registry.list_tools(category="query")

    # Export for MCP
    schemas = registry.export_all_schemas()
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "MCPToolSpec",
    "MCPToolResult",
    "MCPToolRegistry",
    "ToolExecutionStats",
]


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class MCPToolSpec:
    """Specification for an MCP tool.

    Attributes:
        tool_id: Unique tool identifier (e.g., "aldeci.query_findings")
        name: Human-readable tool name
        description: Tool purpose and usage
        parameters: JSON schema dict describing input parameters
        required_permissions: List of permission strings required to execute
        category: Tool category (query, action, analysis, reporting)
        version: Semantic version string
        enabled: Whether tool is currently enabled
    """

    tool_id: str
    name: str
    description: str
    parameters: Dict[str, Any]
    required_permissions: List[str] = field(default_factory=list)
    category: str = "query"
    version: str = "1.0.0"
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class MCPToolResult:
    """Result of executing an MCP tool.

    Attributes:
        tool_id: ID of the executed tool
        result: Tool output (any type)
        metadata: Additional execution metadata
        execution_time_ms: Execution time in milliseconds
        tokens_used: Estimated tokens used
        error: Optional error message if execution failed
        timestamp: When the tool was executed
    """

    tool_id: str
    result: Any
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0
    tokens_used: int = 0
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


@dataclass
class ToolExecutionStats:
    """Execution statistics for a tool.

    Attributes:
        tool_id: ID of the tool
        call_count: Total number of times executed
        success_count: Number of successful executions
        error_count: Number of failed executions
        total_time_ms: Total execution time in ms
        avg_time_ms: Average execution time in ms
        min_time_ms: Minimum execution time in ms
        max_time_ms: Maximum execution time in ms
        total_tokens: Total tokens used
        error_rate: Error rate as percentage (0-100)
    """

    tool_id: str
    call_count: int = 0
    success_count: int = 0
    error_count: int = 0
    total_time_ms: float = 0.0
    avg_time_ms: float = 0.0
    min_time_ms: float = float("inf")
    max_time_ms: float = 0.0
    total_tokens: int = 0
    error_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


# ============================================================================
# MCP Tool Registry (Singleton)
# ============================================================================


class MCPToolRegistry:
    """Singleton registry for MCP tools.

    Manages registration, execution, and tracking of MCP tools used by LLMs.
    Provides OpenAI-compatible tool schema export for use with LLM APIs.
    """

    _instance: Optional[MCPToolRegistry] = None

    def __new__(cls) -> MCPToolRegistry:
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize registry with built-in ALDECI tools."""
        if self._initialized:
            return

        self._tools: Dict[str, MCPToolSpec] = {}
        self._handlers: Dict[str, Callable] = {}
        self._stats: Dict[str, ToolExecutionStats] = {}
        self._execution_history: Deque[MCPToolResult] = deque(maxlen=1000)
        self._initialized = True

        logger.info("Initializing MCPToolRegistry with built-in ALDECI tools")
        self._register_builtin_tools()

    def register_tool(
        self,
        spec: MCPToolSpec,
        handler: Callable,
    ) -> None:
        """Register a new MCP tool.

        Args:
            spec: Tool specification
            handler: Async or sync callable that executes the tool

        Raises:
            ValueError: If tool_id already registered
        """
        if spec.tool_id in self._tools:
            raise ValueError(f"Tool {spec.tool_id} already registered")

        self._tools[spec.tool_id] = spec
        self._handlers[spec.tool_id] = handler
        self._stats[spec.tool_id] = ToolExecutionStats(tool_id=spec.tool_id)

        logger.info(
            f"Registered MCP tool: {spec.tool_id} "
            f"(category={spec.category}, version={spec.version})"
        )

    def unregister_tool(self, tool_id: str) -> None:
        """Unregister a tool.

        Args:
            tool_id: ID of tool to unregister

        Raises:
            KeyError: If tool not found
        """
        if tool_id not in self._tools:
            raise KeyError(f"Tool {tool_id} not found")

        del self._tools[tool_id]
        del self._handlers[tool_id]

        logger.info(f"Unregistered MCP tool: {tool_id}")

    def execute_tool(
        self,
        tool_id: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> MCPToolResult:
        """Execute a registered tool.

        Args:
            tool_id: ID of tool to execute
            params: Tool input parameters
            context: Execution context (org_id, user_id, etc.)

        Returns:
            MCPToolResult with output and metadata

        Raises:
            KeyError: If tool not found
            ValueError: If tool not enabled
        """
        if tool_id not in self._tools:
            raise KeyError(f"Tool {tool_id} not found")

        spec = self._tools[tool_id]
        if not spec.enabled:
            raise ValueError(f"Tool {tool_id} is disabled")

        handler = self._handlers[tool_id]
        stats = self._stats[tool_id]

        start_time = time.time()
        result = None
        error = None

        try:
            # Call handler with params and context
            result = handler(params, context or {})
            stats.success_count += 1

        except Exception as e:
            error = str(e)
            stats.error_count += 1
            logger.error(f"Error executing tool {tool_id}: {error}", exc_info=True)

        # Record execution metrics
        elapsed_ms = (time.time() - start_time) * 1000
        stats.call_count += 1
        stats.total_time_ms += elapsed_ms
        stats.avg_time_ms = stats.total_time_ms / stats.call_count
        stats.min_time_ms = min(stats.min_time_ms, elapsed_ms)
        stats.max_time_ms = max(stats.max_time_ms, elapsed_ms)
        stats.error_rate = (stats.error_count / stats.call_count) * 100 if stats.call_count > 0 else 0.0

        # Create result object
        tool_result = MCPToolResult(
            tool_id=tool_id,
            result=result,
            execution_time_ms=elapsed_ms,
            tokens_used=0,  # Would be populated by actual tool handlers
            error=error,
            metadata={
                "success": error is None,
                "context": context or {},
            }
        )

        # Add to history (deque enforces maxlen=1000 automatically)
        self._execution_history.append(tool_result)

        return tool_result

    def list_tools(
        self,
        category: Optional[str] = None,
        permission_filter: Optional[List[str]] = None,
        enabled_only: bool = True,
    ) -> List[MCPToolSpec]:
        """List registered tools.

        Args:
            category: Filter by tool category
            permission_filter: Only return tools requiring ANY of these permissions
            enabled_only: Only include enabled tools

        Returns:
            List of matching MCPToolSpec objects
        """
        tools = list(self._tools.values())

        if enabled_only:
            tools = [t for t in tools if t.enabled]

        if category:
            tools = [t for t in tools if t.category == category]

        if permission_filter:
            # Return tools that require ANY of the provided permissions
            tools = [
                t for t in tools
                if any(p in t.required_permissions for p in permission_filter)
                or not t.required_permissions
            ]

        return tools

    def get_tool_schema(self, tool_id: str) -> Dict[str, Any]:
        """Get OpenAI-compatible tool schema.

        Args:
            tool_id: ID of tool

        Returns:
            Tool schema as dict

        Raises:
            KeyError: If tool not found
        """
        if tool_id not in self._tools:
            raise KeyError(f"Tool {tool_id} not found")

        spec = self._tools[tool_id]

        return {
            "type": "function",
            "function": {
                "name": tool_id,
                "description": spec.description,
                "parameters": spec.parameters,
            }
        }

    def export_all_schemas(self) -> List[Dict[str, Any]]:
        """Export all tool schemas as MCP tool definitions.

        Returns:
            List of OpenAI-compatible tool schemas (single-pass, no redundant lookup).
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": t.tool_id,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in self._tools.values()
            if t.enabled
        ]

    def get_execution_stats(self, tool_id: Optional[str] = None) -> Dict[str, Any]:
        """Get execution statistics.

        Args:
            tool_id: Optional specific tool to get stats for

        Returns:
            Dictionary of stats (all tools if tool_id is None)
        """
        if tool_id:
            if tool_id not in self._stats:
                raise KeyError(f"No stats for tool {tool_id}")
            return self._stats[tool_id].to_dict()

        return {
            tool_id: stats.to_dict()
            for tool_id, stats in self._stats.items()
        }

    def get_execution_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent execution history.

        Args:
            limit: Maximum number of results to return

        Returns:
            List of recent execution results (deque-safe, no negative-slice).
        """
        import itertools
        start = max(0, len(self._execution_history) - limit)
        return [r.to_dict() for r in itertools.islice(self._execution_history, start, None)]

    def clear_stats(self) -> None:
        """Reset all execution statistics."""
        for stats in self._stats.values():
            stats.call_count = 0
            stats.success_count = 0
            stats.error_count = 0
            stats.total_time_ms = 0.0
            stats.avg_time_ms = 0.0
            stats.min_time_ms = float("inf")
            stats.max_time_ms = 0.0
            stats.total_tokens = 0
            stats.error_rate = 0.0

        logger.info("Cleared execution statistics for all tools")

    # ========================================================================
    # Built-in ALDECI Tools
    # ========================================================================

    def _register_builtin_tools(self) -> None:
        """Register built-in ALDECI MCP tools."""

        # Tool 1: Query findings
        self.register_tool(
            MCPToolSpec(
                tool_id="aldeci.query_findings",
                name="Query Findings",
                description="Search findings by severity, stage, date range, connector type",
                parameters={
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                            "description": "Minimum severity level"
                        },
                        "stage": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 15,
                            "description": "ALDECI pipeline stage (1-15)"
                        },
                        "days": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Days back to search"
                        },
                        "connector_type": {
                            "type": "string",
                            "description": "Filter by connector type (e.g. sonarqube, snyk)"
                        },
                        "limit": {
                            "type": "integer",
                            "default": 50,
                            "description": "Max results to return"
                        }
                    },
                    "required": ["severity"]
                },
                required_permissions=["findings:read"],
                category="query",
                version="1.0.0"
            ),
            handler=self._handle_query_findings
        )

        # Tool 2: Get risk posture
        self.register_tool(
            MCPToolSpec(
                tool_id="aldeci.get_risk_posture",
                name="Get Risk Posture",
                description="Get current organization risk posture score and breakdown",
                parameters={
                    "type": "object",
                    "properties": {
                        "include_timeline": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include historical trend data"
                        },
                        "breakdown_by": {
                            "type": "string",
                            "enum": ["connector", "stage", "severity", "none"],
                            "default": "connector",
                            "description": "How to break down scores"
                        }
                    }
                },
                required_permissions=["risk:read"],
                category="analysis"
            ),
            handler=self._handle_get_risk_posture
        )

        # Tool 3: Run pipeline stage
        self.register_tool(
            MCPToolSpec(
                tool_id="aldeci.run_pipeline_stage",
                name="Run Pipeline Stage",
                description="Trigger a specific ALDECI pipeline stage on findings",
                parameters={
                    "type": "object",
                    "properties": {
                        "stage": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 15,
                            "description": "Pipeline stage to run"
                        },
                        "finding_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific findings to process (empty = all)"
                        },
                        "async": {
                            "type": "boolean",
                            "default": True,
                            "description": "Run asynchronously"
                        }
                    },
                    "required": ["stage"]
                },
                required_permissions=["pipeline:write"],
                category="action"
            ),
            handler=self._handle_run_pipeline_stage
        )

        # Tool 4: Council evaluate
        self.register_tool(
            MCPToolSpec(
                tool_id="aldeci.council_evaluate",
                name="Council Evaluate",
                description="Submit a finding for LLM Council 3-stage decision synthesis",
                parameters={
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "Finding ID to evaluate"
                        },
                        "context": {
                            "type": "object",
                            "description": "Additional context for evaluation"
                        },
                        "expertise_focus": {
                            "type": "string",
                            "enum": ["vulnerability_assessment", "threat_modeling", "compliance_mapping", "code_analysis"],
                            "description": "Focus area for council deliberation"
                        }
                    },
                    "required": ["finding_id"]
                },
                required_permissions=["council:write"],
                category="analysis"
            ),
            handler=self._handle_council_evaluate
        )

        # Tool 5: Get connector status
        self.register_tool(
            MCPToolSpec(
                tool_id="aldeci.get_connector_status",
                name="Get Connector Status",
                description="Get health and metrics for all ALDECI connectors",
                parameters={
                    "type": "object",
                    "properties": {
                        "connector_type": {
                            "type": "string",
                            "description": "Filter to specific connector type"
                        },
                        "include_metrics": {
                            "type": "boolean",
                            "default": True,
                            "description": "Include detailed metrics"
                        }
                    }
                },
                required_permissions=["connectors:read"],
                category="query"
            ),
            handler=self._handle_get_connector_status
        )

        # Tool 6: Search knowledge core
        self.register_tool(
            MCPToolSpec(
                tool_id="aldeci.search_knowledge_core",
                name="Search Knowledge Core",
                description="Query a specific TrustGraph Knowledge Core",
                parameters={
                    "type": "object",
                    "properties": {
                        "core_id": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 5,
                            "description": "Knowledge Core ID (1-5)"
                        },
                        "entity_type": {
                            "type": "string",
                            "description": "Entity type to search (e.g. CVE, Vulnerability, Service)"
                        },
                        "query": {
                            "type": "string",
                            "description": "Search query text"
                        },
                        "limit": {
                            "type": "integer",
                            "default": 20,
                            "description": "Max results"
                        }
                    },
                    "required": ["core_id", "query"]
                },
                required_permissions=["knowledge:read"],
                category="query"
            ),
            handler=self._handle_search_knowledge_core
        )

        # Tool 7: Get compliance status
        self.register_tool(
            MCPToolSpec(
                tool_id="aldeci.get_compliance_status",
                name="Get Compliance Status",
                description="Get compliance framework status and gaps",
                parameters={
                    "type": "object",
                    "properties": {
                        "framework": {
                            "type": "string",
                            "enum": ["SOC2", "ISO27001", "HIPAA", "PCI-DSS", "GDPR"],
                            "description": "Compliance framework"
                        },
                        "include_evidence": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include supporting evidence"
                        }
                    }
                },
                required_permissions=["compliance:read"],
                category="query"
            ),
            handler=self._handle_get_compliance_status
        )

        # Tool 8: Create playbook run
        self.register_tool(
            MCPToolSpec(
                tool_id="aldeci.create_playbook_run",
                name="Create Playbook Run",
                description="Trigger an automated remediation playbook",
                parameters={
                    "type": "object",
                    "properties": {
                        "playbook_id": {
                            "type": "string",
                            "description": "Playbook template ID"
                        },
                        "target_findings": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Finding IDs to remediate"
                        },
                        "auto_approve": {
                            "type": "boolean",
                            "default": False,
                            "description": "Skip approval step"
                        }
                    },
                    "required": ["playbook_id"]
                },
                required_permissions=["playbook:write"],
                category="action"
            ),
            handler=self._handle_create_playbook_run
        )

        # Tool 9: Get dashboard KPIs
        self.register_tool(
            MCPToolSpec(
                tool_id="aldeci.get_dashboard_kpis",
                name="Get Dashboard KPIs",
                description="Fetch dashboard KPIs for a specific persona",
                parameters={
                    "type": "object",
                    "properties": {
                        "persona": {
                            "type": "string",
                            "enum": ["ciso", "developer", "devops", "analyst"],
                            "description": "Role/persona"
                        },
                        "time_range": {
                            "type": "string",
                            "enum": ["last_7_days", "last_30_days", "last_90_days"],
                            "default": "last_30_days",
                            "description": "Time range for metrics"
                        }
                    },
                    "required": ["persona"]
                },
                required_permissions=["dashboards:read"],
                category="query"
            ),
            handler=self._handle_get_dashboard_kpis
        )

        # Tool 10: Export findings report
        self.register_tool(
            MCPToolSpec(
                tool_id="aldeci.export_findings_report",
                name="Export Findings Report",
                description="Generate a findings report in JSON or CSV format",
                parameters={
                    "type": "object",
                    "properties": {
                        "format": {
                            "type": "string",
                            "enum": ["json", "csv"],
                            "default": "json",
                            "description": "Output format"
                        },
                        "filters": {
                            "type": "object",
                            "description": "Query filters (severity, stage, connector_type, etc.)"
                        },
                        "include_remediation": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include remediation guidance"
                        }
                    }
                },
                required_permissions=["reports:write"],
                category="reporting"
            ),
            handler=self._handle_export_findings_report
        )

    # ========================================================================
    # Built-in Tool Handlers
    # ========================================================================

    def _handle_query_findings(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handler for aldeci.query_findings."""
        logger.info(f"Querying findings with params: {params}")
        return {
            "count": 42,
            "findings": [
                {
                    "id": f"finding_{i}",
                    "severity": params.get("severity", "high"),
                    "stage": params.get("stage", 3),
                    "connector": params.get("connector_type", "sonarqube"),
                }
                for i in range(min(5, params.get("limit", 50)))
            ],
            "org_id": context.get("org_id"),
        }

    def _handle_get_risk_posture(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handler for aldeci.get_risk_posture."""
        return {
            "overall_score": 72.5,
            "score_out_of": 100,
            "risk_level": "medium",
            "breakdown_by": params.get("breakdown_by", "connector"),
            "breakdown": {
                "sonarqube": 65.0,
                "snyk": 75.0,
                "trivy": 80.0,
            },
            "org_id": context.get("org_id"),
        }

    def _handle_run_pipeline_stage(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handler for aldeci.run_pipeline_stage."""
        return {
            "stage": params.get("stage"),
            "status": "started",
            "run_id": f"run_{int(time.time())}",
            "async": params.get("async", True),
            "findings_count": len(params.get("finding_ids", [])) or 42,
        }

    def _handle_council_evaluate(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handler for aldeci.council_evaluate."""
        return {
            "finding_id": params.get("finding_id"),
            "verdict": "remediate_high",
            "confidence": 0.87,
            "reasoning": "Council consensus: immediate remediation required",
            "expertise_focus": params.get("expertise_focus", "vulnerability_assessment"),
        }

    def _handle_get_connector_status(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handler for aldeci.get_connector_status."""
        return {
            "connectors": [
                {
                    "type": "sonarqube",
                    "status": "healthy",
                    "last_sync": "2026-04-12T10:30:00Z",
                    "findings_count": 128,
                }
                for _ in range(3)
            ],
            "overall_status": "operational",
            "org_id": context.get("org_id"),
        }

    def _handle_search_knowledge_core(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handler for aldeci.search_knowledge_core."""
        return {
            "core_id": params.get("core_id"),
            "query": params.get("query"),
            "results_count": 8,
            "results": [
                {
                    "id": f"result_{i}",
                    "type": params.get("entity_type", "CVE"),
                    "score": 0.95 - (i * 0.05),
                }
                for i in range(3)
            ],
        }

    def _handle_get_compliance_status(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handler for aldeci.get_compliance_status."""
        return {
            "framework": params.get("framework", "SOC2"),
            "status": "in_progress",
            "completion_percentage": 78,
            "total_controls": 87,
            "compliant_controls": 68,
            "gaps": 19,
            "org_id": context.get("org_id"),
        }

    def _handle_create_playbook_run(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handler for aldeci.create_playbook_run."""
        return {
            "playbook_id": params.get("playbook_id"),
            "run_id": f"pb_run_{int(time.time())}",
            "status": "approved" if params.get("auto_approve") else "pending_approval",
            "target_findings": params.get("target_findings", []),
            "estimated_duration_minutes": 15,
        }

    def _handle_get_dashboard_kpis(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handler for aldeci.get_dashboard_kpis."""
        return {
            "persona": params.get("persona"),
            "time_range": params.get("time_range", "last_30_days"),
            "kpis": {
                "critical_findings": 12,
                "mttr_days": 3.5,
                "remediation_rate": 0.82,
                "risk_trend": "improving",
            },
            "org_id": context.get("org_id"),
        }

    def _handle_export_findings_report(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handler for aldeci.export_findings_report."""
        return {
            "report_id": f"report_{int(time.time())}",
            "format": params.get("format", "json"),
            "status": "generating",
            "findings_count": 156,
            "include_remediation": params.get("include_remediation", False),
            "org_id": context.get("org_id"),
        }
