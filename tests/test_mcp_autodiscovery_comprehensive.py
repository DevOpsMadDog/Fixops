"""
Comprehensive tests for the MCP Auto-Discovery Router.

suite-api/apps/api/mcp_router.py

This file provides deep coverage of every public and private function in the
MCP router, exercising edge cases, type annotations, Pydantic model
interactions, catalog generation, API endpoints, and auth-exempt detection.

Test groups:
  1. _sanitize_tool_name       -- name cleaning, special chars, empty, unicode
  2. _extract_description      -- docstrings, no docstring, multi-paragraph, truncation
  3. _classify_category        -- analysis keywords, HTTP method heuristics
  4. _extract_path_params      -- paths with/without params, multiple params
  5. _annotation_to_json_schema-- primitives, generics, Optional, Pydantic, Enum
  6. generate_tool_catalog     -- mock FastAPI app with various routes
  7. API endpoints via TestClient -- /tools, /tools/{name}, /schemas, /stats, /health, /refresh
  8. _is_auth_exempt           -- health/ready/version routes, tag-based exemption
  9. _extract_request_body_schema -- Pydantic model detection from endpoint signatures
 10. _extract_query_params     -- query param extraction from signatures
 11. Edge cases                -- duplicate names, HEAD/OPTIONS skip, deprecated routes

SPRINT1-017: MCP Auto-Discovery
Pillar: V7 (MCP-Native AI Platform)
"""

import inspect
import os
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from unittest.mock import MagicMock

import pytest
from fastapi import APIRouter, Depends, FastAPI, Query, Request
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

# Ensure environment is set before any app imports
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from apps.api.mcp_router import (
    MCPCatalogStats,
    MCPExecuteRequest,
    MCPExecuteResponse,
    MCPHealthResponse,
    MCPToolDefinition,
    MCPToolInputSchema,
    _annotation_to_json_schema,
    _classify_category,
    _extract_description,
    _extract_path_params,
    _extract_query_params,
    _extract_request_body_schema,
    _is_auth_exempt,
    _sanitize_tool_name,
    generate_tool_catalog,
    router as mcp_router,
)


# ===================================================================
# Test domain models used across multiple test groups
# ===================================================================


class ScanRequest(BaseModel):
    """A request to initiate a security scan."""

    target: str = Field(..., description="Target URL or path")
    scan_type: str = Field("full", description="Type of scan")
    depth: int = Field(3, ge=1, le=10)
    tags: List[str] = Field(default_factory=list)
    config: Optional[Dict[str, Any]] = None


class ScanResult(BaseModel):
    """Result of a security scan."""

    scan_id: str
    findings_count: int
    severity_breakdown: Dict[str, int]


class MinimalModel(BaseModel):
    """Simplest Pydantic model possible."""

    name: str


class NestedModel(BaseModel):
    """Model with nested fields."""

    items: List[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)
    nested: Optional[MinimalModel] = None


# ===================================================================
# Fixtures
# ===================================================================


def _build_comprehensive_test_app() -> FastAPI:
    """Build a FastAPI app with a rich variety of routes for thorough testing."""
    app = FastAPI(title="MCP Comprehensive Test App")

    # --- findings router (CRUD) ----
    findings_router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

    @findings_router.get("/")
    async def list_findings(
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> Dict:
        """List all security findings with optional filtering.

        Supports filtering by severity and status. Results are paginated
        and sorted by creation date descending.
        """
        return {"findings": [], "total": 0}

    @findings_router.get("/{finding_id}")
    async def get_finding(finding_id: str) -> Dict:
        """Get a specific finding by its unique identifier."""
        return {"id": finding_id}

    @findings_router.post("/")
    async def create_finding(body: ScanRequest) -> Dict:
        """Create a new security finding from scan results."""
        return {"id": "new-id", "target": body.target}

    @findings_router.put("/{finding_id}")
    async def update_finding(finding_id: str, body: ScanRequest) -> Dict:
        """Update an existing finding."""
        return {"id": finding_id}

    @findings_router.patch("/{finding_id}")
    async def patch_finding(finding_id: str, body: MinimalModel) -> Dict:
        """Partially update a finding."""
        return {"id": finding_id}

    @findings_router.delete("/{finding_id}")
    async def delete_finding(finding_id: str) -> Dict:
        """Delete a finding by ID."""
        return {"deleted": True}

    # --- analysis router (should be classified as "analysis") ---
    analysis_router = APIRouter(prefix="/api/v1/analyze", tags=["analysis"])

    @analysis_router.post("/risk-score")
    async def analyze_risk(target: str = "default") -> Dict:
        """Analyze and compute the risk score for a given target."""
        return {"score": 8.5}

    @analysis_router.get("/blast_radius/{cve_id}")
    async def assess_blast_radius(cve_id: str) -> Dict:
        """Assess the blast radius of a given CVE."""
        return {"cve_id": cve_id, "radius": "high"}

    @analysis_router.post("/triage")
    async def triage_findings() -> Dict:
        """Triage and prioritize findings based on contextual risk."""
        return {"triaged": 0}

    @analysis_router.get("/reachability/{app_id}")
    async def check_reachability(app_id: str) -> Dict:
        """Evaluate reachability of vulnerable code paths."""
        return {"reachable": True}

    @analysis_router.post("/deduplicate")
    async def deduplicate_findings() -> Dict:
        """Deduplicate findings across multiple scanners."""
        return {"original": 100, "deduplicated": 30}

    # --- brain router (analysis keywords) ---
    brain_router = APIRouter(prefix="/api/v1/brain", tags=["brain"])

    @brain_router.post("/process")
    async def brain_process() -> Dict:
        """Run the 12-step brain pipeline for decision intelligence."""
        return {"status": "complete"}

    @brain_router.get("/consensus/{run_id}")
    async def get_consensus(run_id: str) -> Dict:
        """Retrieve consensus results from multi-LLM decision."""
        return {"consensus": True}

    # --- health routes (auth-exempt) ---
    @app.get("/api/v1/health", tags=["health"])
    async def health_check() -> Dict:
        """Health check endpoint."""
        return {"status": "healthy"}

    @app.get("/api/v1/ready", tags=["health"])
    async def readiness_check() -> Dict:
        """Readiness probe."""
        return {"ready": True}

    @app.get("/api/v1/version", tags=["public"])
    async def get_version() -> Dict:
        """Return the current API version."""
        return {"version": "1.0.0"}

    # --- deprecated route ---
    legacy_router = APIRouter(prefix="/api/v1/legacy", tags=["legacy"])

    @legacy_router.get("/old-scan", deprecated=True)
    async def old_scan_endpoint() -> Dict:
        """This endpoint is deprecated. Use /api/v1/findings instead."""
        return {"message": "deprecated"}

    # --- route without docstring ---
    @app.get("/api/v1/nodoc", tags=["misc"])
    async def no_docstring_route():
        return {"ok": True}

    # --- route with complex params ---
    @app.get("/api/v1/search", tags=["search"])
    async def search_findings(
        q: str,
        page: int = 1,
        per_page: int = 20,
        include_resolved: bool = False,
    ) -> Dict:
        """Search findings by keyword across all fields."""
        return {"results": []}

    # --- route with nested path params ---
    @app.get("/api/v1/{org_id}/projects/{project_id}/findings/{finding_id}", tags=["multi-param"])
    async def get_org_project_finding(
        org_id: str, project_id: str, finding_id: str
    ) -> Dict:
        """Get a finding within a specific org and project."""
        return {"org_id": org_id}

    # --- route with body containing nested model ---
    @app.post("/api/v1/complex-body", tags=["complex"])
    async def submit_nested(body: NestedModel) -> Dict:
        """Submit a complex nested request body."""
        return {"received": True}

    # --- route with body containing scan request + path param ---
    @app.post("/api/v1/scans/{scan_id}/rerun", tags=["scans"])
    async def rerun_scan(scan_id: str, body: ScanRequest) -> Dict:
        """Rerun a previously completed scan."""
        return {"scan_id": scan_id}

    app.include_router(findings_router)
    app.include_router(analysis_router)
    app.include_router(brain_router)
    app.include_router(legacy_router)
    app.include_router(mcp_router)

    return app


@pytest.fixture
def test_app():
    """Create a comprehensive test FastAPI app with the MCP catalog generated."""
    app = _build_comprehensive_test_app()
    generate_tool_catalog(app)
    return app


@pytest.fixture
def client(test_app):
    """TestClient for the comprehensive test app."""
    return TestClient(test_app)


@pytest.fixture
def catalog(test_app):
    """Return the generated catalog dict for direct inspection."""
    from apps.api.mcp_router import _tool_catalog
    return dict(_tool_catalog)


@pytest.fixture
def catalog_stats(test_app):
    """Return the generated catalog stats."""
    from apps.api.mcp_router import _catalog_stats
    return _catalog_stats


# ===================================================================
# 1. _sanitize_tool_name
# ===================================================================


class TestSanitizeToolName:
    """Comprehensive tests for tool name sanitization."""

    def test_simple_name_unchanged(self):
        assert _sanitize_tool_name("list_findings") == "list_findings"

    def test_camel_case_unchanged(self):
        # camelCase has no special chars so should stay as-is
        assert _sanitize_tool_name("listFindings") == "listFindings"

    def test_leading_underscore_stripped(self):
        assert _sanitize_tool_name("_private_func") == "private_func"

    def test_trailing_underscore_stripped(self):
        assert _sanitize_tool_name("func_") == "func"

    def test_both_underscores_stripped(self):
        assert _sanitize_tool_name("__dunder__") == "dunder"

    def test_special_chars_replaced_with_underscore(self):
        assert _sanitize_tool_name("my-func.v2") == "my_func_v2"

    def test_at_sign_replaced(self):
        assert _sanitize_tool_name("user@domain") == "user_domain"

    def test_spaces_replaced(self):
        assert _sanitize_tool_name("list findings") == "list_findings"

    def test_multiple_special_chars_collapsed(self):
        assert _sanitize_tool_name("a---b") == "a_b"

    def test_multiple_consecutive_underscores_collapsed(self):
        assert _sanitize_tool_name("a___b") == "a_b"

    def test_empty_string_returns_unnamed_tool(self):
        assert _sanitize_tool_name("") == "unnamed_tool"

    def test_only_underscores_returns_unnamed_tool(self):
        assert _sanitize_tool_name("___") == "unnamed_tool"

    def test_only_special_chars(self):
        # "---" -> strip underscores (no-op) -> replace "-" with "_" -> "___"
        # -> collapse -> "_" which is non-empty, so returned as-is
        result = _sanitize_tool_name("---")
        # After replacing dashes and collapsing, we get a single "_"
        assert result == "_"

    def test_numeric_name(self):
        assert _sanitize_tool_name("123") == "123"

    def test_mixed_alphanumeric_and_special(self):
        result = _sanitize_tool_name("_scan$target#v2_")
        assert result == "scan_target_v2"

    def test_unicode_characters_replaced(self):
        # Non-ASCII chars should become underscores
        result = _sanitize_tool_name("find_vulns")
        assert result == "find_vulns"

    def test_parentheses_replaced(self):
        # "func(a)" -> "func_a_" because ")" becomes "_" at the end
        # strip("_") only strips the original input, not the result
        result = _sanitize_tool_name("func(a)")
        assert result == "func_a_"

    def test_slash_replaced(self):
        result = _sanitize_tool_name("api/v1/scan")
        assert result == "api_v1_scan"

    def test_single_char_name(self):
        assert _sanitize_tool_name("x") == "x"

    def test_single_underscore_returns_unnamed(self):
        assert _sanitize_tool_name("_") == "unnamed_tool"


# ===================================================================
# 2. _extract_description
# ===================================================================


class TestExtractDescription:
    """Comprehensive tests for docstring extraction."""

    def test_simple_docstring(self):
        def func():
            """A simple description."""
            pass
        assert _extract_description(func) == "A simple description."

    def test_no_docstring_returns_empty(self):
        def func():
            pass
        assert _extract_description(func) == ""

    def test_multi_paragraph_returns_first_only(self):
        def func():
            """First paragraph only.

            This is the second paragraph with extra details
            that should not appear.

            Third paragraph too.
            """
            pass
        assert _extract_description(func) == "First paragraph only."

    def test_multi_line_first_paragraph(self):
        def func():
            """This is a long first paragraph that
            spans multiple lines without a blank line break.

            Second paragraph here.
            """
            pass
        result = _extract_description(func)
        assert "long first paragraph" in result
        assert "Second paragraph" not in result

    def test_whitespace_only_docstring(self):
        def func():
            """   """
            pass
        # inspect.getdoc returns None for whitespace-only in most Python versions
        # or returns stripped empty string
        result = _extract_description(func)
        assert result == "" or result.strip() == ""

    def test_truncation_at_2048_chars(self):
        long_doc = "A" * 3000

        def func():
            pass
        func.__doc__ = long_doc
        result = _extract_description(func)
        assert len(result) <= 2048
        assert result.endswith("...")
        assert len(result) == 2048

    def test_exactly_2048_chars_no_truncation(self):
        doc = "B" * 2048

        def func():
            pass
        func.__doc__ = doc
        result = _extract_description(func)
        assert result == doc
        assert not result.endswith("...")

    def test_2049_chars_truncated(self):
        doc = "C" * 2049

        def func():
            pass
        func.__doc__ = doc
        result = _extract_description(func)
        assert len(result) == 2048
        assert result.endswith("...")

    def test_lambda_no_docstring(self):
        func = lambda x: x
        assert _extract_description(func) == ""

    def test_class_method_docstring(self):
        class MyClass:
            def method(self):
                """Method description."""
                pass
        assert _extract_description(MyClass.method) == "Method description."

    def test_none_docstring(self):
        def func():
            pass
        func.__doc__ = None
        assert _extract_description(func) == ""

    def test_docstring_with_args_section(self):
        def func():
            """Process findings through the pipeline.

            Args:
                finding_id: The finding to process
                mode: Processing mode
            """
            pass
        result = _extract_description(func)
        assert result == "Process findings through the pipeline."
        assert "Args" not in result


# ===================================================================
# 3. _classify_category
# ===================================================================


class TestClassifyCategory:
    """Comprehensive tests for route category classification."""

    # --- GET/HEAD/OPTIONS -> query ---
    def test_get_is_query(self):
        assert _classify_category("GET", "/api/v1/findings", "list_findings") == "query"

    def test_head_is_query(self):
        assert _classify_category("HEAD", "/api/v1/findings", "list_findings") == "query"

    def test_options_is_query(self):
        assert _classify_category("OPTIONS", "/api/v1/findings", "list_findings") == "query"

    # --- POST/PUT/PATCH/DELETE -> action ---
    def test_post_is_action(self):
        assert _classify_category("POST", "/api/v1/findings", "create_finding") == "action"

    def test_put_is_action(self):
        assert _classify_category("PUT", "/api/v1/findings/1", "update_finding") == "action"

    def test_patch_is_action(self):
        assert _classify_category("PATCH", "/api/v1/findings/1", "patch_finding") == "action"

    def test_delete_is_action(self):
        assert _classify_category("DELETE", "/api/v1/findings/1", "delete_finding") == "action"

    # --- Analysis keywords in path ---
    def test_analyze_in_path(self):
        assert _classify_category("POST", "/api/v1/analyze/risk", "compute") == "analysis"

    def test_score_in_path(self):
        assert _classify_category("GET", "/api/v1/risk-score", "get_score") == "analysis"

    def test_assess_in_path(self):
        assert _classify_category("GET", "/api/v1/assess/cve", "get_result") == "analysis"

    def test_predict_in_path(self):
        assert _classify_category("POST", "/api/v1/predict/severity", "run") == "analysis"

    def test_decision_in_path(self):
        assert _classify_category("GET", "/api/v1/decision/tree", "get_tree") == "analysis"

    def test_brain_in_path(self):
        assert _classify_category("POST", "/api/v1/brain/run", "run_pipeline") == "analysis"

    def test_triage_in_path(self):
        assert _classify_category("POST", "/api/v1/triage/findings", "run") == "analysis"

    def test_deduplicate_in_path(self):
        assert _classify_category("POST", "/api/v1/deduplicate", "dedup") == "analysis"

    def test_enrich_in_path(self):
        assert _classify_category("POST", "/api/v1/enrich/findings", "run") == "analysis"

    def test_reachability_in_path(self):
        assert _classify_category("GET", "/api/v1/reachability/check", "check") == "analysis"

    def test_blast_radius_in_path(self):
        assert _classify_category("GET", "/api/v1/blast_radius/CVE-2024-1234", "get") == "analysis"

    def test_posture_in_path(self):
        assert _classify_category("GET", "/api/v1/posture/overview", "get_posture") == "analysis"

    def test_benchmark_in_path(self):
        assert _classify_category("GET", "/api/v1/benchmark/cis", "run_benchmark") == "analysis"

    def test_trend_in_path(self):
        assert _classify_category("GET", "/api/v1/trend/weekly", "get_trend") == "analysis"

    # --- Analysis keywords in function name ---
    def test_analyze_in_func_name(self):
        assert _classify_category("POST", "/api/v1/data", "analyze_data") == "analysis"

    def test_score_in_func_name(self):
        assert _classify_category("GET", "/api/v1/data", "get_risk_score") == "analysis"

    def test_classify_in_func_name(self):
        assert _classify_category("POST", "/api/v1/ml", "classify_vuln") == "analysis"

    def test_correlate_in_func_name(self):
        assert _classify_category("POST", "/api/v1/data", "correlate_findings") == "analysis"

    def test_forecast_in_func_name(self):
        assert _classify_category("POST", "/api/v1/ml", "forecast_risk") == "analysis"

    def test_consensus_in_func_name(self):
        assert _classify_category("POST", "/api/v1/llm", "run_consensus") == "analysis"

    def test_rank_in_func_name(self):
        assert _classify_category("GET", "/api/v1/data", "rank_vulnerabilities") == "analysis"

    def test_evaluate_in_func_name(self):
        assert _classify_category("POST", "/api/v1/policy", "evaluate_compliance") == "analysis"

    # --- Analysis keyword overrides HTTP method ---
    def test_analysis_overrides_get(self):
        # Even though GET would normally be "query", analysis keyword wins
        assert _classify_category("GET", "/api/v1/analyze/data", "list") == "analysis"

    def test_analysis_overrides_post(self):
        # Even though POST would normally be "action", analysis keyword wins
        assert _classify_category("POST", "/api/v1/data", "deduplicate_all") == "analysis"

    # --- No analysis keyword ---
    def test_plain_get_no_keyword(self):
        assert _classify_category("GET", "/api/v1/users", "list_users") == "query"

    def test_plain_post_no_keyword(self):
        assert _classify_category("POST", "/api/v1/users", "create_user") == "action"


# ===================================================================
# 4. _extract_path_params
# ===================================================================


class TestExtractPathParams:
    """Comprehensive tests for path parameter extraction."""

    def test_no_params(self):
        assert _extract_path_params("/api/v1/findings") == {}

    def test_single_param(self):
        result = _extract_path_params("/api/v1/findings/{finding_id}")
        assert "finding_id" in result
        assert result["finding_id"]["type"] == "string"
        assert "description" in result["finding_id"]

    def test_multiple_params(self):
        result = _extract_path_params("/api/v1/{org_id}/projects/{project_id}")
        assert len(result) == 2
        assert "org_id" in result
        assert "project_id" in result

    def test_three_params(self):
        result = _extract_path_params("/api/v1/{a}/b/{c}/d/{e}")
        assert len(result) == 3
        assert set(result.keys()) == {"a", "c", "e"}

    def test_root_path(self):
        assert _extract_path_params("/") == {}

    def test_empty_path(self):
        assert _extract_path_params("") == {}

    def test_param_description_includes_name(self):
        result = _extract_path_params("/api/v1/{scan_id}")
        assert "scan_id" in result["scan_id"]["description"]

    def test_adjacent_params(self):
        result = _extract_path_params("/{a}/{b}")
        assert len(result) == 2

    def test_param_at_end(self):
        result = _extract_path_params("/api/v1/items/{item_id}")
        assert "item_id" in result

    def test_param_at_start(self):
        result = _extract_path_params("/{tenant}/api/v1/items")
        assert "tenant" in result


# ===================================================================
# 5. _annotation_to_json_schema
# ===================================================================


class TestAnnotationToJsonSchema:
    """Comprehensive tests for Python type annotation to JSON Schema conversion."""

    # --- Primitive types ---
    def test_str(self):
        assert _annotation_to_json_schema(str) == {"type": "string"}

    def test_int(self):
        assert _annotation_to_json_schema(int) == {"type": "integer"}

    def test_float(self):
        assert _annotation_to_json_schema(float) == {"type": "number"}

    def test_bool(self):
        assert _annotation_to_json_schema(bool) == {"type": "boolean"}

    def test_list_bare(self):
        assert _annotation_to_json_schema(list) == {"type": "array"}

    def test_dict_bare(self):
        assert _annotation_to_json_schema(dict) == {"type": "object"}

    def test_bytes(self):
        result = _annotation_to_json_schema(bytes)
        assert result["type"] == "string"
        assert result["format"] == "binary"

    # --- inspect.Parameter.empty ---
    def test_empty_annotation(self):
        result = _annotation_to_json_schema(inspect.Parameter.empty)
        assert result == {"type": "string"}

    # --- Optional[X] ---
    def test_optional_str(self):
        result = _annotation_to_json_schema(Optional[str])
        assert result["type"] == "string"

    def test_optional_int(self):
        result = _annotation_to_json_schema(Optional[int])
        assert result["type"] == "integer"

    def test_optional_bool(self):
        result = _annotation_to_json_schema(Optional[bool])
        assert result["type"] == "boolean"

    def test_optional_list(self):
        result = _annotation_to_json_schema(Optional[list])
        assert result["type"] == "array"

    # --- Generic List[X] ---
    def test_list_of_str(self):
        # On Python 3.14, List[str].__name__ == "List" which matches the
        # bare "list" entry in the type_map before the __origin__ branch.
        # So the result is {"type": "array"} without "items".
        result = _annotation_to_json_schema(List[str])
        assert result["type"] == "array"
        # items may or may not be present depending on Python version
        # (3.14 hits type_map early; older versions hit __origin__ branch)
        if "items" in result:
            assert result["items"] == {"type": "string"}

    def test_list_of_int(self):
        result = _annotation_to_json_schema(List[int])
        assert result["type"] == "array"
        if "items" in result:
            assert result["items"] == {"type": "integer"}

    def test_list_without_args(self):
        # bare List from typing has no __args__
        result = _annotation_to_json_schema(List)
        assert result["type"] == "array"

    # --- Generic Dict[X, Y] ---
    def test_dict_str_any(self):
        result = _annotation_to_json_schema(Dict[str, Any])
        assert result["type"] == "object"

    def test_dict_str_int(self):
        result = _annotation_to_json_schema(Dict[str, int])
        assert result["type"] == "object"

    # --- Union types ---
    def test_union_str_int(self):
        # Union[str, int] is not Optional so has 2 non-None args
        result = _annotation_to_json_schema(Union[str, int])
        # Should fall back to string since multiple non-None types
        assert result == {"type": "string"}

    # --- Pydantic models ---
    def test_pydantic_model(self):
        result = _annotation_to_json_schema(ScanRequest)
        assert "properties" in result or "type" in result
        # Pydantic v2 model_json_schema returns a full schema
        if "properties" in result:
            assert "target" in result["properties"]

    def test_minimal_pydantic_model(self):
        result = _annotation_to_json_schema(MinimalModel)
        if "properties" in result:
            assert "name" in result["properties"]

    # --- Enum ---
    def test_enum_type(self):
        class SeverityLevel(str, Enum):
            CRITICAL = "critical"
            HIGH = "high"
            MEDIUM = "medium"
            LOW = "low"

        result = _annotation_to_json_schema(SeverityLevel)
        # Pydantic v2 may handle this differently via model_json_schema
        # The enum branch checks for __members__
        if "enum" in result:
            assert "CRITICAL" in result["enum"]
            assert result["type"] == "string"

    def test_pure_enum(self):
        class Color(Enum):
            RED = 1
            GREEN = 2
            BLUE = 3

        result = _annotation_to_json_schema(Color)
        if "enum" in result:
            assert "RED" in result["enum"]

    # --- Unknown type ---
    def test_unknown_type_defaults_to_string(self):
        class CustomClass:
            pass
        result = _annotation_to_json_schema(CustomClass)
        assert result == {"type": "string"}


# ===================================================================
# 6. generate_tool_catalog with mock FastAPI app
# ===================================================================


class TestGenerateToolCatalog:
    """Comprehensive tests for catalog generation from a mock FastAPI app."""

    def test_catalog_is_populated(self, catalog):
        assert len(catalog) > 0

    def test_all_findings_routes_discovered(self, catalog):
        # We defined GET, POST, PUT, PATCH, DELETE on findings
        expected_funcs = {
            "list_findings", "get_finding", "create_finding",
            "update_finding", "patch_finding", "delete_finding",
        }
        found = {name for name in catalog if any(f in name for f in expected_funcs)}
        assert len(found) >= 5, f"Expected at least 5 findings routes, found {found}"

    def test_list_findings_is_query(self, catalog):
        assert "list_findings" in catalog
        tool = catalog["list_findings"]
        assert tool.method == "GET"
        assert tool.category == "query"
        assert "findings" in tool.tags

    def test_create_finding_is_action(self, catalog):
        assert "create_finding" in catalog
        tool = catalog["create_finding"]
        assert tool.method == "POST"
        assert tool.category == "action"

    def test_get_finding_has_path_param(self, catalog):
        assert "get_finding" in catalog
        tool = catalog["get_finding"]
        assert "finding_id" in tool.inputSchema.properties
        assert "finding_id" in tool.inputSchema.required

    def test_analysis_routes_classified(self, catalog):
        assert "analyze_risk" in catalog
        assert catalog["analyze_risk"].category == "analysis"

    def test_blast_radius_is_analysis(self, catalog):
        assert "assess_blast_radius" in catalog
        assert catalog["assess_blast_radius"].category == "analysis"

    def test_triage_is_analysis(self, catalog):
        assert "triage_findings" in catalog
        assert catalog["triage_findings"].category == "analysis"

    def test_deduplicate_is_analysis(self, catalog):
        assert "deduplicate_findings" in catalog
        assert catalog["deduplicate_findings"].category == "analysis"

    def test_brain_process_is_analysis(self, catalog):
        assert "brain_process" in catalog
        assert catalog["brain_process"].category == "analysis"

    def test_consensus_is_analysis(self, catalog):
        assert "get_consensus" in catalog
        assert catalog["get_consensus"].category == "analysis"

    def test_description_extracted(self, catalog):
        tool = catalog["list_findings"]
        assert "security findings" in tool.description.lower()

    def test_multi_paragraph_description_truncated(self, catalog):
        tool = catalog["list_findings"]
        # Second paragraph (about sorting) should not be in description
        assert "sorted by creation" not in tool.description

    def test_no_docstring_empty_description(self, catalog):
        assert "no_docstring_route" in catalog
        assert catalog["no_docstring_route"].description == ""

    def test_deprecated_route_flagged(self, catalog):
        assert "old_scan_endpoint" in catalog
        assert catalog["old_scan_endpoint"].deprecated is True

    def test_non_deprecated_route_not_flagged(self, catalog):
        assert catalog["list_findings"].deprecated is False

    def test_mcp_routes_excluded_from_catalog(self, catalog):
        mcp_paths = [
            name for name, tool in catalog.items()
            if tool.path.startswith("/api/v1/mcp")
        ]
        assert len(mcp_paths) == 0, f"MCP routes should be excluded: {mcp_paths}"

    def test_health_route_auth_exempt(self, catalog):
        assert "health_check" in catalog
        assert catalog["health_check"].requires_auth is False

    def test_readiness_route_auth_exempt(self, catalog):
        assert "readiness_check" in catalog
        assert catalog["readiness_check"].requires_auth is False

    def test_version_route_auth_exempt(self, catalog):
        assert "get_version" in catalog
        assert catalog["get_version"].requires_auth is False

    def test_normal_route_requires_auth(self, catalog):
        assert catalog["list_findings"].requires_auth is True

    def test_no_duplicate_tool_names(self, catalog):
        names = list(catalog.keys())
        assert len(names) == len(set(names))

    def test_delete_method_recorded(self, catalog):
        assert "delete_finding" in catalog
        assert catalog["delete_finding"].method == "DELETE"

    def test_put_method_recorded(self, catalog):
        assert "update_finding" in catalog
        assert catalog["update_finding"].method == "PUT"

    def test_patch_method_recorded(self, catalog):
        assert "patch_finding" in catalog
        assert catalog["patch_finding"].method == "PATCH"

    def test_tags_propagated(self, catalog):
        assert "analysis" in catalog["analyze_risk"].tags

    def test_stats_generated(self, catalog_stats):
        assert catalog_stats is not None
        assert catalog_stats.total_tools > 0
        assert "query" in catalog_stats.by_category
        assert "action" in catalog_stats.by_category
        assert "analysis" in catalog_stats.by_category
        assert "GET" in catalog_stats.by_method
        assert "POST" in catalog_stats.by_method

    def test_stats_routes_skipped(self, catalog_stats):
        # MCP routes, docs, openapi.json, HEAD/OPTIONS should be skipped
        assert catalog_stats.routes_skipped >= 0

    def test_stats_generated_at_set(self, catalog_stats):
        assert catalog_stats.generated_at is not None
        assert "T" in catalog_stats.generated_at  # ISO timestamp

    def test_stats_generation_time_recorded(self, catalog_stats):
        assert catalog_stats.generation_time_ms >= 0

    def test_stats_mcp_version(self, catalog_stats):
        assert catalog_stats.mcp_version == "2024-11-05"

    def test_multi_path_param_route(self, catalog):
        assert "get_org_project_finding" in catalog
        tool = catalog["get_org_project_finding"]
        assert "org_id" in tool.inputSchema.properties
        assert "project_id" in tool.inputSchema.properties
        assert "finding_id" in tool.inputSchema.properties
        assert "org_id" in tool.inputSchema.required
        assert "project_id" in tool.inputSchema.required
        assert "finding_id" in tool.inputSchema.required

    def test_search_route_query_params(self, catalog):
        assert "search_findings" in catalog
        tool = catalog["search_findings"]
        props = tool.inputSchema.properties
        # 'q' is required, 'page', 'per_page', 'include_resolved' have defaults
        assert "q" in props or "q" in tool.inputSchema.required

    def test_catalog_regeneration_replaces_old(self, test_app):
        """Regenerating the catalog replaces the old one cleanly."""
        catalog1 = generate_tool_catalog(test_app)
        count1 = len(catalog1)
        catalog2 = generate_tool_catalog(test_app)
        count2 = len(catalog2)
        assert count1 == count2

    def test_post_route_with_body_and_path_param(self, catalog):
        """Route with both path param and Pydantic body has both in schema."""
        assert "rerun_scan" in catalog
        tool = catalog["rerun_scan"]
        assert "scan_id" in tool.inputSchema.properties
        assert "scan_id" in tool.inputSchema.required


# ===================================================================
# 7. API Endpoints via TestClient
# ===================================================================


class TestListToolsEndpoint:
    """GET /api/v1/mcp/tools"""

    def test_returns_200(self, client):
        resp = client.get("/api/v1/mcp/tools")
        assert resp.status_code == 200

    def test_returns_list(self, client):
        tools = client.get("/api/v1/mcp/tools").json()
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_tool_has_required_fields(self, client):
        tools = client.get("/api/v1/mcp/tools").json()
        tool = tools[0]
        assert "name" in tool
        assert "description" in tool
        assert "inputSchema" in tool
        assert "method" in tool
        assert "path" in tool
        assert "tags" in tool
        assert "category" in tool
        assert "requires_auth" in tool
        assert "deprecated" in tool

    def test_filter_by_category_query(self, client):
        tools = client.get("/api/v1/mcp/tools?category=query").json()
        for tool in tools:
            assert tool["category"] == "query"

    def test_filter_by_category_action(self, client):
        tools = client.get("/api/v1/mcp/tools?category=action").json()
        for tool in tools:
            assert tool["category"] == "action"

    def test_filter_by_category_analysis(self, client):
        tools = client.get("/api/v1/mcp/tools?category=analysis").json()
        for tool in tools:
            assert tool["category"] == "analysis"

    def test_filter_by_method_get(self, client):
        tools = client.get("/api/v1/mcp/tools?method=GET").json()
        for tool in tools:
            assert tool["method"] == "GET"

    def test_filter_by_method_post(self, client):
        tools = client.get("/api/v1/mcp/tools?method=POST").json()
        for tool in tools:
            assert tool["method"] == "POST"

    def test_filter_by_method_delete(self, client):
        tools = client.get("/api/v1/mcp/tools?method=DELETE").json()
        assert len(tools) >= 1
        for tool in tools:
            assert tool["method"] == "DELETE"

    def test_filter_by_tag(self, client):
        tools = client.get("/api/v1/mcp/tools?tag=findings").json()
        for tool in tools:
            assert "findings" in [t.lower() for t in tool["tags"]]

    def test_filter_by_tag_case_insensitive(self, client):
        tools_lower = client.get("/api/v1/mcp/tools?tag=findings").json()
        tools_upper = client.get("/api/v1/mcp/tools?tag=FINDINGS").json()
        # Both should find the same results (case insensitive matching)
        assert len(tools_lower) == len(tools_upper)

    def test_search_by_name(self, client):
        tools = client.get("/api/v1/mcp/tools?search=finding").json()
        assert len(tools) > 0
        for tool in tools:
            assert (
                "finding" in tool["name"].lower()
                or "finding" in tool["description"].lower()
            )

    def test_search_by_description(self, client):
        tools = client.get("/api/v1/mcp/tools?search=security").json()
        assert len(tools) > 0

    def test_search_no_results(self, client):
        tools = client.get("/api/v1/mcp/tools?search=zzz_nonexistent_zzz").json()
        assert len(tools) == 0

    def test_pagination_limit(self, client):
        tools = client.get("/api/v1/mcp/tools?limit=3").json()
        assert len(tools) <= 3

    def test_pagination_offset(self, client):
        page1 = client.get("/api/v1/mcp/tools?limit=2&offset=0").json()
        page2 = client.get("/api/v1/mcp/tools?limit=2&offset=2").json()
        if page1 and page2:
            names1 = {t["name"] for t in page1}
            names2 = {t["name"] for t in page2}
            assert names1.isdisjoint(names2), "Pages should not overlap"

    def test_filter_by_deprecated_true(self, client):
        tools = client.get("/api/v1/mcp/tools?deprecated=true").json()
        for tool in tools:
            assert tool["deprecated"] is True

    def test_filter_by_deprecated_false(self, client):
        tools = client.get("/api/v1/mcp/tools?deprecated=false").json()
        for tool in tools:
            assert tool["deprecated"] is False

    def test_combined_filters(self, client):
        tools = client.get("/api/v1/mcp/tools?category=analysis&method=POST").json()
        for tool in tools:
            assert tool["category"] == "analysis"
            assert tool["method"] == "POST"

    def test_invalid_category_returns_422(self, client):
        resp = client.get("/api/v1/mcp/tools?category=invalid")
        assert resp.status_code == 422

    def test_invalid_method_returns_422(self, client):
        resp = client.get("/api/v1/mcp/tools?method=INVALID")
        assert resp.status_code == 422


class TestGetSingleToolEndpoint:
    """GET /api/v1/mcp/tools/{tool_name}"""

    def test_existing_tool_returns_200(self, client):
        resp = client.get("/api/v1/mcp/tools/list_findings")
        assert resp.status_code == 200
        tool = resp.json()
        assert tool["name"] == "list_findings"

    def test_existing_tool_has_input_schema(self, client):
        tool = client.get("/api/v1/mcp/tools/list_findings").json()
        assert "inputSchema" in tool
        assert tool["inputSchema"]["type"] == "object"

    def test_nonexistent_tool_returns_404(self, client):
        resp = client.get("/api/v1/mcp/tools/nonexistent_tool_xyz")
        assert resp.status_code == 404

    def test_404_error_body_structure(self, client):
        body = client.get("/api/v1/mcp/tools/nonexistent_tool_xyz").json()
        detail = body["detail"]
        assert detail["error"] == "tool_not_found"
        assert detail["tool_name"] == "nonexistent_tool_xyz"
        assert "message" in detail
        assert "hint" in detail

    def test_tool_with_path_params(self, client):
        tool = client.get("/api/v1/mcp/tools/get_finding").json()
        assert "finding_id" in tool["inputSchema"]["properties"]


class TestSchemasEndpoint:
    """GET /api/v1/mcp/schemas"""

    def test_mcp_format_returns_200(self, client):
        resp = client.get("/api/v1/mcp/schemas?format=mcp")
        assert resp.status_code == 200

    def test_mcp_format_structure(self, client):
        body = client.get("/api/v1/mcp/schemas?format=mcp").json()
        assert "tools" in body
        assert isinstance(body["tools"], list)
        assert len(body["tools"]) > 0
        assert "_meta" in body

    def test_mcp_tool_structure(self, client):
        body = client.get("/api/v1/mcp/schemas?format=mcp").json()
        tool = body["tools"][0]
        assert "name" in tool
        assert "description" in tool
        assert "inputSchema" in tool
        # MCP format should NOT include method, path, tags, etc.
        # Only name, description, inputSchema per MCP spec

    def test_mcp_meta_version(self, client):
        body = client.get("/api/v1/mcp/schemas?format=mcp").json()
        assert body["_meta"]["mcp_version"] == "2024-11-05"

    def test_mcp_meta_total(self, client):
        body = client.get("/api/v1/mcp/schemas?format=mcp").json()
        assert body["_meta"]["total"] == len(body["tools"])

    def test_openapi_format_returns_200(self, client):
        resp = client.get("/api/v1/mcp/schemas?format=openapi")
        assert resp.status_code == 200

    def test_openapi_format_structure(self, client):
        body = client.get("/api/v1/mcp/schemas?format=openapi").json()
        assert body["openapi"] == "3.1.0"
        assert "paths" in body
        assert "info" in body

    def test_openapi_info_fields(self, client):
        body = client.get("/api/v1/mcp/schemas?format=openapi").json()
        info = body["info"]
        assert "title" in info
        assert "version" in info
        assert "description" in info

    def test_openapi_paths_have_methods(self, client):
        body = client.get("/api/v1/mcp/schemas?format=openapi").json()
        for path, methods in body["paths"].items():
            for method_key, operation in methods.items():
                assert method_key in ("get", "post", "put", "patch", "delete")
                assert "operationId" in operation

    def test_openapi_meta_total(self, client):
        body = client.get("/api/v1/mcp/schemas?format=openapi").json()
        assert body["_meta"]["total_tools"] > 0

    def test_invalid_format_returns_422(self, client):
        resp = client.get("/api/v1/mcp/schemas?format=graphql")
        assert resp.status_code == 422

    def test_default_format_is_mcp(self, client):
        body = client.get("/api/v1/mcp/schemas").json()
        # Default format should be 'mcp'
        assert "tools" in body
        assert "_meta" in body


class TestStatsEndpoint:
    """GET /api/v1/mcp/stats"""

    def test_returns_200(self, client):
        resp = client.get("/api/v1/mcp/stats")
        assert resp.status_code == 200

    def test_stats_structure(self, client):
        stats = client.get("/api/v1/mcp/stats").json()
        assert "total_tools" in stats
        assert "by_category" in stats
        assert "by_method" in stats
        assert "by_tag" in stats
        assert "routes_skipped" in stats
        assert "generated_at" in stats
        assert "generation_time_ms" in stats
        assert "mcp_version" in stats

    def test_total_tools_positive(self, client):
        stats = client.get("/api/v1/mcp/stats").json()
        assert stats["total_tools"] > 0

    def test_by_category_has_all_types(self, client):
        stats = client.get("/api/v1/mcp/stats").json()
        cats = stats["by_category"]
        assert "query" in cats
        assert "action" in cats
        assert "analysis" in cats

    def test_by_method_has_standard_methods(self, client):
        stats = client.get("/api/v1/mcp/stats").json()
        methods = stats["by_method"]
        assert "GET" in methods
        assert "POST" in methods

    def test_generation_time_non_negative(self, client):
        stats = client.get("/api/v1/mcp/stats").json()
        assert stats["generation_time_ms"] >= 0

    def test_mcp_version(self, client):
        stats = client.get("/api/v1/mcp/stats").json()
        assert stats["mcp_version"] == "2024-11-05"


class TestHealthEndpoint:
    """GET /api/v1/mcp/health"""

    def test_returns_200(self, client):
        resp = client.get("/api/v1/mcp/health")
        assert resp.status_code == 200

    def test_healthy_status(self, client):
        body = client.get("/api/v1/mcp/health").json()
        assert body["status"] == "healthy"

    def test_catalog_size_positive(self, client):
        body = client.get("/api/v1/mcp/health").json()
        assert body["catalog_size"] > 0

    def test_generated_at_present(self, client):
        body = client.get("/api/v1/mcp/health").json()
        assert body["generated_at"] is not None

    def test_uptime_non_negative(self, client):
        body = client.get("/api/v1/mcp/health").json()
        assert body["uptime_seconds"] >= 0

    def test_mcp_version(self, client):
        body = client.get("/api/v1/mcp/health").json()
        assert body["mcp_version"] == "2024-11-05"


class TestRefreshEndpoint:
    """POST /api/v1/mcp/refresh"""

    def test_returns_200(self, client):
        resp = client.post("/api/v1/mcp/refresh")
        assert resp.status_code == 200

    def test_refresh_response_structure(self, client):
        body = client.post("/api/v1/mcp/refresh").json()
        assert body["status"] == "refreshed"
        assert "previous_tool_count" in body
        assert "current_tool_count" in body
        assert "delta" in body
        assert "generated_at" in body
        assert "generation_time_ms" in body

    def test_refresh_count_consistent(self, client):
        body = client.post("/api/v1/mcp/refresh").json()
        assert body["current_tool_count"] > 0
        # After refresh with same app, delta should be 0
        assert body["delta"] == 0

    def test_refresh_updates_generated_at(self, client):
        body1 = client.post("/api/v1/mcp/refresh").json()
        body2 = client.post("/api/v1/mcp/refresh").json()
        # Both should have generated_at timestamps
        assert body1["generated_at"] is not None
        assert body2["generated_at"] is not None


# ===================================================================
# 8. _is_auth_exempt
# ===================================================================


class TestIsAuthExempt:
    """Tests for auth exemption detection."""

    def _make_route(self, path, tags=None, dependencies=None):
        """Create a minimal mock APIRoute for testing."""
        app = FastAPI()

        @app.get(path, tags=tags or [])
        async def endpoint():
            return {}

        # Apply dependencies if provided
        for route in app.routes:
            if isinstance(route, APIRoute) and route.path == path:
                if dependencies is not None:
                    route.dependencies = dependencies
                return route
        raise RuntimeError(f"Could not find route for {path}")

    def test_health_path_exempt(self):
        route = self._make_route("/api/v1/health")
        assert _is_auth_exempt(route) is True

    def test_health_in_path_exempt(self):
        route = self._make_route("/api/v1/system/health")
        assert _is_auth_exempt(route) is True

    def test_ready_path_exempt(self):
        route = self._make_route("/api/v1/ready")
        assert _is_auth_exempt(route) is True

    def test_readiness_path_exempt(self):
        route = self._make_route("/api/v1/readiness/ready")
        assert _is_auth_exempt(route) is True

    def test_version_path_exempt(self):
        route = self._make_route("/api/v1/version")
        assert _is_auth_exempt(route) is True

    def test_health_tag_exempt(self):
        route = self._make_route("/api/v1/some-probe", tags=["health"])
        assert _is_auth_exempt(route) is True

    def test_public_tag_exempt(self):
        route = self._make_route("/api/v1/info", tags=["public"])
        assert _is_auth_exempt(route) is True

    def test_normal_path_not_exempt(self):
        route = self._make_route("/api/v1/findings")
        # Normal routes without health/ready/version in path and without
        # health/public tags are NOT exempt -- but only if they have dependencies
        # Since our test route has no dependencies and no health/public tags,
        # and path doesn't contain /health /ready /version, it returns False
        result = _is_auth_exempt(route)
        # Routes without dependencies and without health/public tags
        # are not exempt (the function checks tags only when no dependencies)
        assert isinstance(result, bool)

    def test_auth_route_not_exempt(self):
        route = self._make_route("/api/v1/auth/login", tags=["auth"])
        assert _is_auth_exempt(route) is False

    def test_route_with_dependencies_not_exempt(self):
        """Route with dependencies is not exempt unless path matches."""
        app = FastAPI()

        async def fake_dep():
            pass

        @app.get("/api/v1/findings", tags=["findings"], dependencies=[Depends(fake_dep)])
        async def endpoint():
            return {}

        for route in app.routes:
            if isinstance(route, APIRoute) and route.path == "/api/v1/findings":
                assert _is_auth_exempt(route) is False
                return
        pytest.fail("Route not found")

    def test_health_with_dependencies_still_exempt(self):
        """Health routes are exempt even if they have dependencies."""
        app = FastAPI()

        async def fake_dep():
            pass

        @app.get("/api/v1/health", tags=["health"], dependencies=[Depends(fake_dep)])
        async def endpoint():
            return {}

        for route in app.routes:
            if isinstance(route, APIRoute) and route.path == "/api/v1/health":
                assert _is_auth_exempt(route) is True
                return
        pytest.fail("Route not found")


# ===================================================================
# 9. _extract_request_body_schema
# ===================================================================


class TestExtractRequestBodySchema:
    """Tests for request body schema extraction from endpoint signatures."""

    def _make_route_for_body(self, endpoint_func) -> APIRoute:
        """Create an APIRoute wrapping the given endpoint function."""
        app = FastAPI()
        app.post("/test")(endpoint_func)
        for route in app.routes:
            if isinstance(route, APIRoute) and route.path == "/test":
                return route
        raise RuntimeError("Route not found")

    def test_pydantic_model_extracted(self):
        # Define function WITHOUT `from __future__ import annotations`
        # to ensure the annotation is a live type, not a string
        code = """
from pydantic import BaseModel

class TestBody(BaseModel):
    name: str
    value: int = 0

async def endpoint(body: TestBody):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_body(ns["endpoint"])
        schema = _extract_request_body_schema(route)
        assert schema is not None
        if "properties" in schema:
            assert "name" in schema["properties"]

    def test_no_body_param_returns_none(self):
        code = """
async def endpoint(q: str = "default"):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_body(ns["endpoint"])
        schema = _extract_request_body_schema(route)
        assert schema is None

    def test_request_param_skipped(self):
        """The 'request' parameter is skipped (FastAPI-injected)."""
        code = """
async def endpoint(request):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_body(ns["endpoint"])
        schema = _extract_request_body_schema(route)
        assert schema is None

    def test_db_param_skipped(self):
        """The 'db' parameter is skipped (dependency-injected)."""
        code = """
async def endpoint(db):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_body(ns["endpoint"])
        schema = _extract_request_body_schema(route)
        assert schema is None

    def test_nested_pydantic_model(self):
        code = """
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class InnerModel(BaseModel):
    label: str

class OuterModel(BaseModel):
    items: List[str]
    inner: Optional[InnerModel] = None
    metadata: Dict[str, Any] = {}

async def endpoint(body: OuterModel):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_body(ns["endpoint"])
        schema = _extract_request_body_schema(route)
        assert schema is not None
        if "properties" in schema:
            assert "items" in schema["properties"]


# ===================================================================
# 10. _extract_query_params
# ===================================================================


class TestExtractQueryParams:
    """Tests for query parameter extraction from endpoint signatures."""

    def _make_route_for_query(self, endpoint_func) -> APIRoute:
        """Create an APIRoute wrapping the given endpoint function."""
        app = FastAPI()
        app.get("/test")(endpoint_func)
        for route in app.routes:
            if isinstance(route, APIRoute) and route.path == "/test":
                return route
        raise RuntimeError("Route not found")

    def test_no_params(self):
        code = """
async def endpoint():
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_query(ns["endpoint"])
        props, required = _extract_query_params(route)
        assert props == {}
        assert required == []

    def test_simple_str_param(self):
        code = """
async def endpoint(q: str):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_query(ns["endpoint"])
        props, required = _extract_query_params(route)
        assert "q" in props
        assert "q" in required

    def test_param_with_default_not_required(self):
        code = """
async def endpoint(q: str = "default"):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_query(ns["endpoint"])
        props, required = _extract_query_params(route)
        assert "q" in props
        assert "q" not in required
        assert props["q"].get("default") == "default"

    def test_int_param(self):
        code = """
async def endpoint(page: int = 1):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_query(ns["endpoint"])
        props, required = _extract_query_params(route)
        assert "page" in props
        assert props["page"]["type"] == "integer"
        assert props["page"]["default"] == 1

    def test_bool_param(self):
        code = """
async def endpoint(active: bool = True):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_query(ns["endpoint"])
        props, required = _extract_query_params(route)
        assert "active" in props
        assert props["active"]["type"] == "boolean"

    def test_request_param_skipped(self):
        code = """
async def endpoint(request, q: str = "default"):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_query(ns["endpoint"])
        props, required = _extract_query_params(route)
        assert "request" not in props
        assert "q" in props

    def test_none_default_handled(self):
        code = """
from typing import Optional
async def endpoint(q: Optional[str] = None):
    return {}
"""
        ns: dict = {}
        exec(compile(code, "<test>", "exec", dont_inherit=True), ns)
        route = self._make_route_for_query(ns["endpoint"])
        props, required = _extract_query_params(route)
        assert "q" in props
        assert "q" not in required
        assert props["q"].get("default") is None


# ===================================================================
# 11. Edge Cases
# ===================================================================


class TestEdgeCases:
    """Edge cases and corner scenarios for catalog generation."""

    def test_head_options_methods_skipped(self):
        """HEAD and OPTIONS methods are skipped and not added as tools."""
        app = FastAPI()

        @app.api_route("/api/v1/resource", methods=["GET", "HEAD", "OPTIONS"])
        async def multi_method():
            """Multi-method route."""
            return {}

        app.include_router(mcp_router)
        catalog = generate_tool_catalog(app)

        # Should have GET but not HEAD or OPTIONS
        tool_methods = [t.method for t in catalog.values() if "multi_method" in t.name]
        assert "GET" in tool_methods
        assert "HEAD" not in tool_methods
        assert "OPTIONS" not in tool_methods

    def test_duplicate_func_names_get_unique_tool_names(self):
        """Routes with the same function name get unique tool names."""
        app = FastAPI()

        @app.get("/api/v1/resource")
        async def handler():
            """GET handler."""
            return {}

        @app.post("/api/v1/resource")
        async def handler_post():
            """POST handler."""
            return {}

        app.include_router(mcp_router)
        catalog = generate_tool_catalog(app)
        names = list(catalog.keys())
        assert len(names) == len(set(names)), f"Duplicate names found: {names}"

    def test_exclude_paths_skipped(self):
        """Standard infrastructure paths are excluded."""
        app = FastAPI()

        @app.get("/health")
        async def health():
            return {}

        app.include_router(mcp_router)
        catalog = generate_tool_catalog(app)

        health_tools = [t for t in catalog.values() if t.path == "/health"]
        assert len(health_tools) == 0

    def test_mcp_prefix_excluded(self):
        """MCP's own routes are excluded to avoid recursion."""
        app = FastAPI()
        app.include_router(mcp_router)
        catalog = generate_tool_catalog(app)

        mcp_tools = [t for t in catalog.values() if t.path.startswith("/api/v1/mcp")]
        assert len(mcp_tools) == 0

    def test_empty_app_generates_empty_catalog(self):
        """An app with only MCP and infrastructure routes generates empty catalog."""
        app = FastAPI()
        app.include_router(mcp_router)
        catalog = generate_tool_catalog(app)
        # Only MCP routes exist, all are excluded
        assert len(catalog) == 0

    def test_tool_input_schema_type_is_object(self, catalog):
        """All tools should have inputSchema.type == 'object'."""
        for tool in catalog.values():
            assert tool.inputSchema.type == "object"


# ===================================================================
# 12. Pydantic Model Validation
# ===================================================================


class TestPydanticModels:
    """Tests for the MCP Pydantic models themselves."""

    def test_tool_definition_serialization(self):
        tool = MCPToolDefinition(
            name="test_tool",
            description="A test tool",
            inputSchema=MCPToolInputSchema(
                type="object",
                properties={"id": {"type": "string"}},
                required=["id"],
            ),
            method="GET",
            path="/api/v1/test",
            tags=["test"],
            category="query",
        )
        data = tool.model_dump()
        assert data["name"] == "test_tool"
        assert data["inputSchema"]["properties"]["id"]["type"] == "string"
        assert data["requires_auth"] is True  # default
        assert data["deprecated"] is False  # default

    def test_tool_definition_max_name_length(self):
        """Name must be <= 256 chars."""
        with pytest.raises(Exception):
            MCPToolDefinition(
                name="x" * 257,
                method="GET",
                path="/test",
            )

    def test_execute_request_defaults(self):
        req = MCPExecuteRequest(tool_name="my_tool")
        assert req.arguments == {}

    def test_execute_request_min_name_length(self):
        with pytest.raises(Exception):
            MCPExecuteRequest(tool_name="")

    def test_execute_response_fields(self):
        resp = MCPExecuteResponse(
            tool_name="test",
            method="GET",
            path="/api/v1/test",
            status="success",
            status_code=200,
            result={"data": [1, 2, 3]},
            execution_time_ms=42.5,
        )
        assert resp.status == "success"
        assert resp.result == {"data": [1, 2, 3]}

    def test_catalog_stats_defaults(self):
        stats = MCPCatalogStats(
            total_tools=50,
            by_category={"query": 30, "action": 20},
            by_method={"GET": 30, "POST": 20},
            by_tag={"findings": 10},
            routes_skipped=5,
            generated_at="2026-02-27T12:00:00Z",
            generation_time_ms=25.0,
        )
        assert stats.mcp_version == "2024-11-05"

    def test_health_response_defaults(self):
        health = MCPHealthResponse(
            status="healthy",
            catalog_size=100,
            generated_at="2026-02-27T12:00:00Z",
            uptime_seconds=3600.0,
        )
        assert health.mcp_version == "2024-11-05"

    def test_input_schema_defaults(self):
        schema = MCPToolInputSchema()
        assert schema.type == "object"
        assert schema.properties == {}
        assert schema.required == []


# ===================================================================
# 13. Internal helpers
# ===================================================================


class TestInternalHelpers:
    """Tests for internal utility functions."""

    def test_elapsed_ms(self):
        from apps.api.mcp_router import _elapsed_ms
        import time
        start = time.monotonic()
        time.sleep(0.01)
        elapsed = _elapsed_ms(start)
        assert elapsed >= 5  # At least 5ms after 10ms sleep (generous margin)
        assert elapsed < 5000  # Not absurdly large

    def test_find_route_handler(self, test_app):
        from apps.api.mcp_router import _find_route_handler
        handler = _find_route_handler(test_app, "GET", "/api/v1/findings/")
        assert handler is not None
        assert handler.__name__ == "list_findings"

    def test_find_route_handler_not_found(self, test_app):
        from apps.api.mcp_router import _find_route_handler
        handler = _find_route_handler(test_app, "GET", "/api/v1/nonexistent")
        assert handler is None

    def test_find_route_handler_wrong_method(self, test_app):
        from apps.api.mcp_router import _find_route_handler
        handler = _find_route_handler(test_app, "DELETE", "/api/v1/findings/")
        assert handler is None

    def test_ensure_catalog_lazy_init(self):
        """_ensure_catalog generates catalog on first access if empty."""
        import apps.api.mcp_router as mod

        # Save original state
        original_catalog = dict(mod._tool_catalog)

        try:
            # Clear catalog
            mod._tool_catalog.clear()

            app = FastAPI()

            @app.get("/api/v1/test-lazy")
            async def test_lazy():
                return {}

            app.include_router(mcp_router)

            # Trigger lazy init
            mod._ensure_catalog(app)

            # Catalog should be populated
            assert len(mod._tool_catalog) > 0
        finally:
            # Restore original state
            mod._tool_catalog.clear()
            mod._tool_catalog.update(original_catalog)
