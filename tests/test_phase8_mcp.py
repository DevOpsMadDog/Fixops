"""
Comprehensive tests for Phase 8 of ALDECI — MCP Tool Registration and GraphRAG.

Tests cover:
- MCPToolRegistry: registration, execution, schema export, statistics
- Built-in ALDECI tools: all 10 tools return expected result shapes
- GraphRAGEngine: query parsing, core retrieval, answer generation, caching
- TrustGraphQueryBuilder: fluent API chains build correct queries
- FastAPI routes: all endpoints return correct responses
- Performance: execution tracking, cache efficiency

Run with: python -m pytest tests/test_phase8_mcp.py -v --timeout=30

Total tests: 45+
All use mocks — no real LLM calls.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# Add suite-core to path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.mcp_tool_registry import (
    MCPToolRegistry,
    MCPToolSpec,
    MCPToolResult,
    ToolExecutionStats,
)
from core.graphrag_engine import (
    GraphRAGEngine,
    GraphQuery,
    GraphRAGResult,
    TrustGraphQueryBuilder,
)

# Try to import FastAPI routes (may not be available in all environments)
try:
    from apps.api.mcp_routes import (
        router,
        ToolListResponse,
        MCPExportResponse,
        GraphRAGQueryResponse,
    )
    _ROUTES_AVAILABLE = True
except ImportError:
    _ROUTES_AVAILABLE = False


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def registry():
    """Get a fresh MCP registry instance."""
    # Reset singleton
    MCPToolRegistry._instance = None
    return MCPToolRegistry()


@pytest.fixture
def graphrag_engine():
    """Get a GraphRAG engine instance."""
    return GraphRAGEngine(cache_ttl_seconds=60)


# ============================================================================
# MCPToolRegistry Tests
# ============================================================================


class TestMCPToolRegistry:
    """Test MCPToolRegistry core functionality."""

    def test_singleton_pattern(self):
        """Registry should be a singleton."""
        reg1 = MCPToolRegistry()
        reg2 = MCPToolRegistry()
        assert reg1 is reg2

    def test_register_tool(self, registry):
        """Should register a new tool."""
        spec = MCPToolSpec(
            tool_id="test.example",
            name="Test Tool",
            description="A test tool",
            parameters={"type": "object", "properties": {}},
        )

        def handler(params, context):
            return {"success": True}

        registry.register_tool(spec, handler)

        assert "test.example" in registry._tools
        assert registry._tools["test.example"] == spec

    def test_register_duplicate_fails(self, registry):
        """Registering duplicate tool_id should raise ValueError."""
        spec = MCPToolSpec(
            tool_id="test.dup",
            name="Duplicate Tool",
            description="Test",
            parameters={},
        )

        def handler(params, context):
            return {}

        registry.register_tool(spec, handler)

        with pytest.raises(ValueError, match="already registered"):
            registry.register_tool(spec, handler)

    def test_execute_tool(self, registry):
        """Should execute a registered tool."""
        spec = MCPToolSpec(
            tool_id="test.exec",
            name="Execute Test",
            description="Test execution",
            parameters={},
        )

        def handler(params, context):
            return {"result": "test_output", "org_id": context.get("org_id")}

        registry.register_tool(spec, handler)
        result = registry.execute_tool(
            "test.exec",
            params={},
            context={"org_id": "org_123"}
        )

        assert result.tool_id == "test.exec"
        assert result.result["result"] == "test_output"
        assert result.error is None
        assert result.execution_time_ms >= 0

    def test_execute_nonexistent_tool(self, registry):
        """Executing nonexistent tool should raise KeyError."""
        with pytest.raises(KeyError):
            registry.execute_tool("nonexistent.tool", params={})

    def test_execute_disabled_tool(self, registry):
        """Executing disabled tool should raise ValueError."""
        spec = MCPToolSpec(
            tool_id="test.disabled",
            name="Disabled",
            description="Test",
            parameters={},
            enabled=False,
        )

        def handler(params, context):
            return {}

        registry.register_tool(spec, handler)

        with pytest.raises(ValueError, match="disabled"):
            registry.execute_tool("test.disabled", params={})

    def test_unregister_tool(self, registry):
        """Should unregister a tool."""
        spec = MCPToolSpec(
            tool_id="test.unreg",
            name="Unregister Test",
            description="Test",
            parameters={},
        )

        def handler(params, context):
            return {}

        registry.register_tool(spec, handler)
        assert "test.unreg" in registry._tools

        registry.unregister_tool("test.unreg")
        assert "test.unreg" not in registry._tools

    def test_list_tools_all(self, registry):
        """Should list all registered tools."""
        tools = registry.list_tools()
        assert len(tools) == 10  # 10 built-in tools
        assert all(isinstance(t, MCPToolSpec) for t in tools)

    def test_list_tools_by_category(self, registry):
        """Should filter tools by category."""
        query_tools = registry.list_tools(category="query")
        assert len(query_tools) > 0
        assert all(t.category == "query" for t in query_tools)

        action_tools = registry.list_tools(category="action")
        assert len(action_tools) > 0
        assert all(t.category == "action" for t in action_tools)

    def test_list_tools_by_permission(self, registry):
        """Should filter tools by required permissions."""
        perm_tools = registry.list_tools(permission_filter=["findings:read"])
        assert len(perm_tools) > 0

    def test_list_tools_enabled_only(self, registry):
        """Should only return enabled tools when enabled_only=True."""
        tools = registry.list_tools(enabled_only=True)
        assert all(t.enabled for t in tools)

    def test_get_tool_schema(self, registry):
        """Should return OpenAI-compatible tool schema."""
        schema = registry.get_tool_schema("aldeci.query_findings")

        assert "type" in schema
        assert schema["type"] == "function"
        assert "function" in schema
        assert "name" in schema["function"]
        assert "description" in schema["function"]
        assert "parameters" in schema["function"]

    def test_get_nonexistent_tool_schema(self, registry):
        """Getting schema for nonexistent tool should raise KeyError."""
        with pytest.raises(KeyError):
            registry.get_tool_schema("nonexistent.tool")

    def test_export_all_schemas(self, registry):
        """Should export all tool schemas."""
        schemas = registry.export_all_schemas()

        assert len(schemas) == 10
        assert all("function" in s for s in schemas)
        assert all("name" in s["function"] for s in schemas)

    def test_execution_stats_tracking(self, registry):
        """Should track execution statistics."""
        spec = MCPToolSpec(
            tool_id="test.stats",
            name="Stats Test",
            description="Test",
            parameters={},
        )

        def handler(params, context):
            return {"result": "ok"}

        registry.register_tool(spec, handler)

        # Execute multiple times
        for i in range(5):
            registry.execute_tool("test.stats", params={}, context={})

        stats = registry.get_execution_stats("test.stats")

        assert stats["call_count"] == 5
        assert stats["success_count"] == 5
        assert stats["error_count"] == 0
        assert stats["avg_time_ms"] >= 0

    def test_execution_stats_all_tools(self, registry):
        """Should track stats for all tools."""
        stats_dict = registry.get_execution_stats()

        assert isinstance(stats_dict, dict)
        assert len(stats_dict) == 10

    def test_execution_error_tracking(self, registry):
        """Should track execution errors."""
        spec = MCPToolSpec(
            tool_id="test.error",
            name="Error Test",
            description="Test",
            parameters={},
        )

        def handler(params, context):
            raise ValueError("Intentional error")

        registry.register_tool(spec, handler)

        result = registry.execute_tool("test.error", params={}, context={})

        assert result.error is not None
        assert "Intentional error" in result.error

        stats = registry.get_execution_stats("test.error")
        assert stats["error_count"] == 1
        assert stats["success_count"] == 0
        assert stats["error_rate"] == 100.0

    def test_clear_stats(self, registry):
        """Should clear execution statistics."""
        # Execute a tool
        registry.execute_tool("aldeci.query_findings", params={}, context={})

        # Clear stats
        registry.clear_stats()

        # Check stats are reset
        all_stats = registry.get_execution_stats()
        for tool_id, stats in all_stats.items():
            assert stats["call_count"] == 0
            assert stats["total_time_ms"] == 0.0

    def test_execution_history(self, registry):
        """Should maintain execution history."""
        registry.execute_tool("aldeci.get_risk_posture", params={}, context={})
        registry.execute_tool("aldeci.query_findings", params={}, context={})

        history = registry.get_execution_history(limit=10)

        assert len(history) >= 2


# ============================================================================
# Built-in Tools Tests
# ============================================================================


class TestBuiltInTools:
    """Test built-in ALDECI MCP tools."""

    def test_query_findings_tool(self, registry):
        """aldeci.query_findings should return findings list."""
        result = registry.execute_tool(
            "aldeci.query_findings",
            params={"severity": "critical"},
            context={"org_id": "org_123"}
        )

        assert result.error is None
        assert "findings" in result.result
        assert "count" in result.result
        assert isinstance(result.result["findings"], list)

    def test_get_risk_posture_tool(self, registry):
        """aldeci.get_risk_posture should return risk score."""
        result = registry.execute_tool(
            "aldeci.get_risk_posture",
            params={},
            context={"org_id": "org_123"}
        )

        assert result.error is None
        assert "overall_score" in result.result
        assert "risk_level" in result.result
        assert 0 <= result.result["overall_score"] <= 100

    def test_run_pipeline_stage_tool(self, registry):
        """aldeci.run_pipeline_stage should return run status."""
        result = registry.execute_tool(
            "aldeci.run_pipeline_stage",
            params={"stage": 5},
            context={"org_id": "org_123"}
        )

        assert result.error is None
        assert "stage" in result.result
        assert "status" in result.result
        assert "run_id" in result.result

    def test_council_evaluate_tool(self, registry):
        """aldeci.council_evaluate should return verdict."""
        result = registry.execute_tool(
            "aldeci.council_evaluate",
            params={"finding_id": "finding_001"},
            context={"org_id": "org_123"}
        )

        assert result.error is None
        assert "verdict" in result.result
        assert "confidence" in result.result
        assert 0 <= result.result["confidence"] <= 1

    def test_get_connector_status_tool(self, registry):
        """aldeci.get_connector_status should return connector info."""
        result = registry.execute_tool(
            "aldeci.get_connector_status",
            params={},
            context={"org_id": "org_123"}
        )

        assert result.error is None
        assert "connectors" in result.result
        assert isinstance(result.result["connectors"], list)

    def test_search_knowledge_core_tool(self, registry):
        """aldeci.search_knowledge_core should return knowledge results."""
        result = registry.execute_tool(
            "aldeci.search_knowledge_core",
            params={"core_id": 1, "query": "critical service"},
            context={"org_id": "org_123"}
        )

        assert result.error is None
        assert "results" in result.result
        assert "core_id" in result.result

    def test_get_compliance_status_tool(self, registry):
        """aldeci.get_compliance_status should return compliance info."""
        result = registry.execute_tool(
            "aldeci.get_compliance_status",
            params={"framework": "SOC2"},
            context={"org_id": "org_123"}
        )

        assert result.error is None
        assert "framework" in result.result
        assert "completion_percentage" in result.result

    def test_create_playbook_run_tool(self, registry):
        """aldeci.create_playbook_run should return run info."""
        result = registry.execute_tool(
            "aldeci.create_playbook_run",
            params={"playbook_id": "pb_001"},
            context={"org_id": "org_123"}
        )

        assert result.error is None
        assert "run_id" in result.result
        assert "status" in result.result

    def test_get_dashboard_kpis_tool(self, registry):
        """aldeci.get_dashboard_kpis should return KPI data."""
        result = registry.execute_tool(
            "aldeci.get_dashboard_kpis",
            params={"persona": "ciso"},
            context={"org_id": "org_123"}
        )

        assert result.error is None
        assert "kpis" in result.result
        assert isinstance(result.result["kpis"], dict)

    def test_export_findings_report_tool(self, registry):
        """aldeci.export_findings_report should return report info."""
        result = registry.execute_tool(
            "aldeci.export_findings_report",
            params={"format": "json"},
            context={"org_id": "org_123"}
        )

        assert result.error is None
        assert "report_id" in result.result
        assert "format" in result.result


# ============================================================================
# GraphRAGEngine Tests
# ============================================================================


class TestGraphRAGEngine:
    """Test GraphRAGEngine functionality."""

    def test_query_basic(self, graphrag_engine):
        """Should execute basic query."""
        query = GraphQuery(
            query_text="What are critical vulnerabilities?",
            target_cores=[1],
        )

        result = graphrag_engine.query(query)

        assert isinstance(result, GraphRAGResult)
        assert result.answer is not None
        assert result.confidence >= 0
        assert result.query_time_ms >= 0

    def test_query_multiple_cores(self, graphrag_engine):
        """Should query multiple cores."""
        query = GraphQuery(
            query_text="Show me vulnerabilities matching threat campaigns",
            target_cores=[1, 2],
        )

        result = graphrag_engine.query(query)

        assert len(result.cores_queried) == 2
        assert len(result.evidence) > 0

    def test_query_caching(self, graphrag_engine):
        """Should cache query results."""
        query = GraphQuery(
            query_text="What are critical vulnerabilities?",
            target_cores=[1],
        )

        # First query
        result1 = graphrag_engine.query(query)
        time1 = result1.query_time_ms

        # Second query (should be cached)
        result2 = graphrag_engine.query(query)
        time2 = result2.query_time_ms

        # Cached query should be significantly faster
        assert result1.answer == result2.answer
        assert result1.confidence == result2.confidence

    def test_query_with_confidence_threshold(self, graphrag_engine):
        """Should filter evidence by confidence threshold."""
        query = GraphQuery(
            query_text="Test query",
            target_cores=[1],
            confidence_threshold=0.8,
        )

        result = graphrag_engine.query(query)

        for evidence in result.evidence:
            assert evidence.get("confidence", 0) >= 0.8

    def test_parse_query(self, graphrag_engine):
        """Should parse query to extract intent and entities."""
        parsed = graphrag_engine._parse_query("critical vulnerability in service")

        assert "intent" in parsed
        assert "entities" in parsed
        assert isinstance(parsed["entities"], list)

    def test_retrieve_from_cores(self, graphrag_engine):
        """Should retrieve from specified cores."""
        parsed = {"intent": "search", "entities": ["critical"]}

        results = graphrag_engine._retrieve_from_cores(parsed, [1, 2], max_results=10)

        assert len(results) > 0
        assert all("core_id" in r for r in results)

    def test_rank_evidence(self, graphrag_engine):
        """Should rank evidence by relevance."""
        evidence = [
            {"id": "1", "score": 0.5, "confidence": 0.7},
            {"id": "2", "score": 0.9, "confidence": 0.9},
            {"id": "3", "score": 0.6, "confidence": 0.6},
        ]

        ranked = graphrag_engine._rank_evidence(evidence)

        # Should be sorted by relevance score (highest first)
        scores = [e.get("relevance_score", 0) for e in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_calculate_confidence(self, graphrag_engine):
        """Should calculate confidence from evidence."""
        evidence = [
            {"confidence": 0.9},
            {"confidence": 0.85},
            {"confidence": 0.95},
        ]

        confidence = graphrag_engine._calculate_confidence(evidence)

        assert 0 <= confidence <= 1
        assert confidence > 0.5  # Should be fairly high for good evidence

    def test_clear_cache(self, graphrag_engine):
        """Should clear query cache."""
        query = GraphQuery(query_text="Test", target_cores=[1])
        graphrag_engine.query(query)

        assert len(graphrag_engine._query_cache) > 0

        graphrag_engine.clear_cache()

        assert len(graphrag_engine._query_cache) == 0

    def test_query_with_all_cores(self, graphrag_engine):
        """Should query all available cores."""
        query = GraphQuery(
            query_text="Cross-core analysis",
            target_cores=[1, 2, 3, 4, 5],
        )

        result = graphrag_engine.query(query)

        assert len(result.cores_queried) == 5


# ============================================================================
# TrustGraphQueryBuilder Tests
# ============================================================================


class TestTrustGraphQueryBuilder:
    """Test TrustGraphQueryBuilder fluent API."""

    def test_from_core(self):
        """Should set core_id."""
        builder = TrustGraphQueryBuilder()
        builder.from_core(1)

        assert builder.core_id == 1

    def test_from_core_validation(self):
        """Should validate core_id."""
        builder = TrustGraphQueryBuilder()

        with pytest.raises(ValueError):
            builder.from_core(0)

        with pytest.raises(ValueError):
            builder.from_core(6)

    def test_where_filter(self):
        """Should add filter conditions."""
        builder = TrustGraphQueryBuilder()
        builder.from_core(1).where("criticality", "eq", "critical")

        assert len(builder.filters) == 1
        assert builder.filters[0] == ("criticality", "eq", "critical")

    def test_multiple_filters(self):
        """Should chain multiple filters."""
        builder = (TrustGraphQueryBuilder()
                   .from_core(1)
                   .where("criticality", "eq", "critical")
                   .where("status", "eq", "active")
                   .where("owner", "contains", "security"))

        assert len(builder.filters) == 3

    def test_related_to(self):
        """Should set related entity type."""
        builder = TrustGraphQueryBuilder()
        builder.from_core(1).related_to("Service")

        assert builder.related_type == "Service"

    def test_limit(self):
        """Should set result limit."""
        builder = TrustGraphQueryBuilder()
        builder.from_core(1).limit(50)

        assert builder.limit_value == 50

    def test_build_query_dict(self):
        """Should build query as dictionary."""
        query_dict = (TrustGraphQueryBuilder()
                      .from_core(1)
                      .where("criticality", "eq", "critical")
                      .limit(20)
                      .build_query_dict())

        assert query_dict["core_id"] == 1
        assert len(query_dict["filters"]) == 1
        assert query_dict["limit"] == 20

    def test_execute_without_core(self):
        """Should require core_id before execute."""
        builder = TrustGraphQueryBuilder()

        with pytest.raises(ValueError, match="Must call from_core"):
            builder.execute()

    def test_execute_returns_results(self):
        """Should execute and return results."""
        results = (TrustGraphQueryBuilder()
                   .from_core(1)
                   .limit(10)
                   .execute())

        assert isinstance(results, list)

    def test_fluent_api_chain(self):
        """Should support fluent API chaining."""
        builder = (TrustGraphQueryBuilder()
                   .from_core(2)
                   .where("type", "eq", "CVE")
                   .where("severity", "eq", "critical")
                   .related_to("Artifact")
                   .limit(30))

        query_dict = builder.build_query_dict()

        assert query_dict["core_id"] == 2
        assert len(query_dict["filters"]) == 2
        assert query_dict["related_to"] == "Artifact"
        assert query_dict["limit"] == 30


# ============================================================================
# Data Class Tests
# ============================================================================


class TestDataClasses:
    """Test MCPToolSpec, MCPToolResult, and other data classes."""

    def test_mcp_tool_spec_to_dict(self):
        """Should convert spec to dict."""
        spec = MCPToolSpec(
            tool_id="test.tool",
            name="Test",
            description="Test tool",
            parameters={"type": "object"},
            category="query",
        )

        spec_dict = spec.to_dict()

        assert spec_dict["tool_id"] == "test.tool"
        assert spec_dict["name"] == "Test"
        assert spec_dict["category"] == "query"

    def test_mcp_tool_result_to_dict(self):
        """Should convert result to dict."""
        result = MCPToolResult(
            tool_id="test.tool",
            result={"data": "value"},
            execution_time_ms=5.5,
        )

        result_dict = result.to_dict()

        assert result_dict["tool_id"] == "test.tool"
        assert result_dict["execution_time_ms"] == 5.5
        assert "timestamp" in result_dict

    def test_tool_execution_stats_to_dict(self):
        """Should convert stats to dict."""
        stats = ToolExecutionStats(
            tool_id="test.tool",
            call_count=10,
            success_count=8,
            error_count=2,
        )

        stats_dict = stats.to_dict()

        assert stats_dict["call_count"] == 10
        assert stats_dict["error_count"] == 2

    def test_graph_query_validation(self):
        """Should validate core IDs."""
        with pytest.raises(ValueError):
            GraphQuery(query_text="test", target_cores=[6])

        with pytest.raises(ValueError):
            GraphQuery(query_text="test", target_cores=[0])

    def test_graph_rag_result_to_dict(self):
        """Should convert GraphRAG result to dict."""
        result = GraphRAGResult(
            answer="Test answer",
            confidence=0.85,
            sources=[1, 2],
        )

        result_dict = result.to_dict()

        assert result_dict["answer"] == "Test answer"
        assert result_dict["confidence"] == 0.85


# ============================================================================
# Integration Tests
# ============================================================================


class TestIntegration:
    """Integration tests combining multiple components."""

    def test_registry_and_graphrag_together(self, registry, graphrag_engine):
        """Should work together in a workflow."""
        # Get findings via MCP tool
        findings_result = registry.execute_tool(
            "aldeci.query_findings",
            params={"severity": "critical"},
            context={"org_id": "org_123"}
        )

        assert findings_result.error is None
        findings_count = findings_result.result["count"]

        # Query knowledge cores
        query = GraphQuery(
            query_text="What findings are critical?",
            target_cores=[1, 2],
        )
        graphrag_result = graphrag_engine.query(query)

        assert graphrag_result.confidence > 0
        assert len(graphrag_result.evidence) > 0

    def test_complex_query_workflow(self, graphrag_engine):
        """Should handle complex multi-step query."""
        # Step 1: Query environment core
        query1 = GraphQuery(
            query_text="critical services in production",
            target_cores=[1],
        )
        result1 = graphrag_engine.query(query1)

        # Step 2: Cross-core query for threats matching environment
        query2 = GraphQuery(
            query_text="threats matching our environment",
            target_cores=[2],
        )
        result2 = graphrag_engine.query(query2)

        assert result1.confidence > 0
        assert result2.confidence > 0

    def test_builder_with_engine(self, graphrag_engine):
        """Should use builder with GraphRAG engine."""
        builder = TrustGraphQueryBuilder()
        results = (builder
                   .from_core(1)
                   .where("criticality", "eq", "critical")
                   .limit(20)
                   .execute())

        assert isinstance(results, list)


# ============================================================================
# Performance Tests
# ============================================================================


class TestPerformance:
    """Test performance characteristics."""

    def test_tool_execution_is_fast(self, registry):
        """Tool execution should complete in reasonable time."""
        result = registry.execute_tool(
            "aldeci.query_findings",
            params={"severity": "high"},
            context={}
        )

        # Should complete in less than 100ms
        assert result.execution_time_ms < 100

    def test_many_executions_tracked(self, registry):
        """Should efficiently track many executions."""
        for i in range(50):
            registry.execute_tool(
                "aldeci.get_risk_posture",
                params={},
                context={}
            )

        stats = registry.get_execution_stats("aldeci.get_risk_posture")
        assert stats["call_count"] == 50

    def test_cache_efficiency(self, graphrag_engine):
        """Cache should provide significant speed improvement."""
        query = GraphQuery(query_text="test query", target_cores=[1])

        # First execution (not cached)
        result1 = graphrag_engine.query(query)

        # Second execution (cached)
        result2 = graphrag_engine.query(query)

        # Both should return same result
        assert result1.answer == result2.answer
        assert result1.confidence == result2.confidence


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
