"""
ALdeci MCP Auto-Discovery Router

Auto-generates an MCP tool catalog by introspecting ALL FastAPI routes at startup.
Replaces the 9 hard-coded tools in suite-integrations/api/mcp_router.py with a
dynamically generated catalog covering every route in the application.

This makes ALdeci the first AppSec platform with MCP-native AI agent support,
exposing 500+ tools from 20+ routers for programmatic consumption by AI agents.

Model Context Protocol (MCP) spec version: 2024-11-05
"""

from __future__ import annotations

import inspect
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/mcp", tags=["mcp-discovery"])

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class MCPToolInputSchema(BaseModel):
    """JSON Schema describing the input parameters for an MCP tool."""

    type: str = "object"
    properties: Dict[str, Any] = Field(default_factory=dict)
    required: List[str] = Field(default_factory=list)


class MCPToolDefinition(BaseModel):
    """A single MCP tool definition generated from a FastAPI route."""

    name: str = Field(
        ...,
        description="Unique tool name derived from the route's endpoint function name",
        max_length=256,
    )
    description: str = Field(
        "",
        description="Human-readable description from the endpoint docstring",
        max_length=2048,
    )
    inputSchema: MCPToolInputSchema = Field(
        default_factory=MCPToolInputSchema,
        description="JSON Schema for tool input parameters",
    )
    method: str = Field(..., description="HTTP method (GET, POST, PUT, DELETE, PATCH)")
    path: str = Field(..., description="API route path")
    tags: List[str] = Field(default_factory=list, description="OpenAPI tags")
    category: str = Field(
        "query",
        description="Tool category: query, action, or analysis",
    )
    requires_auth: bool = Field(True, description="Whether the endpoint requires auth")
    deprecated: bool = Field(False, description="Whether the route is deprecated")


class MCPExecuteRequest(BaseModel):
    """Request body for executing an MCP tool by name."""

    tool_name: str = Field(
        ...,
        description="The tool name to execute",
        min_length=1,
        max_length=256,
    )
    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments matching the tool's inputSchema",
    )


class MCPExecuteResponse(BaseModel):
    """Response from MCP tool execution."""

    tool_name: str
    method: str
    path: str
    status: str  # "success", "error", "not_found"
    status_code: int
    result: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0


class MCPCatalogStats(BaseModel):
    """Statistics about the auto-generated tool catalog."""

    total_tools: int
    by_category: Dict[str, int]
    by_method: Dict[str, int]
    by_tag: Dict[str, int]
    routes_skipped: int
    generated_at: str
    generation_time_ms: float
    mcp_version: str = "2024-11-05"


class MCPHealthResponse(BaseModel):
    """Health check for the MCP auto-discovery service."""

    status: str
    catalog_size: int
    generated_at: Optional[str]
    uptime_seconds: float
    mcp_version: str = "2024-11-05"


# ---------------------------------------------------------------------------
# Module-level catalog state (populated once at startup, refreshable)
# ---------------------------------------------------------------------------

_tool_catalog: Dict[str, MCPToolDefinition] = {}
_catalog_stats: Optional[MCPCatalogStats] = None
_catalog_generated_at: Optional[str] = None
_catalog_generation_time_ms: float = 0.0
_routes_skipped: int = 0
_startup_time: float = time.monotonic()

# Routes to exclude from auto-discovery (internal/infrastructure)
_EXCLUDE_PATHS: Set[str] = {
    "/health",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
}

# Path prefixes to exclude (MCP's own routes to avoid recursion)
_EXCLUDE_PREFIXES: tuple = ("/api/v1/mcp",)

# Tags that should be excluded from MCP tool discovery (demo/admin endpoints)
_EXCLUDE_TAGS: Set[str] = {"admin", "demo"}

# Path substrings that should be excluded from MCP tool discovery
_EXCLUDE_PATH_SUBSTRINGS: tuple = ("/demo/", "/seed-demo",)

# Keywords used to classify a route as "analysis" category
_ANALYSIS_KEYWORDS: Set[str] = {
    "analyze",
    "analyse",
    "score",
    "assess",
    "evaluate",
    "predict",
    "forecast",
    "classify",
    "correlate",
    "deduplicate",
    "enrich",
    "triage",
    "risk",
    "brain",
    "decision",
    "consensus",
    "rank",
    "trend",
    "benchmark",
    "posture",
    "blast_radius",
    "reachability",
}


# ---------------------------------------------------------------------------
# Core auto-discovery logic
# ---------------------------------------------------------------------------


def _sanitize_tool_name(name: str) -> str:
    """Convert a Python function name into a clean MCP tool name.

    Examples:
        "list_findings" -> "list_findings"
        "get_finding_by_id" -> "get_finding_by_id"
        "ingest_sbom" -> "ingest_sbom"
    """
    # Remove leading/trailing underscores (private functions exposed as routes)
    cleaned = name.strip("_")
    # Replace non-alphanumeric chars (except underscore) with underscore
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", cleaned)
    # Collapse multiple underscores
    cleaned = re.sub(r"_+", "_", cleaned)
    # Ensure non-empty
    return cleaned or "unnamed_tool"


def _extract_description(endpoint_func: Any) -> str:
    """Extract a clean description from the endpoint's docstring."""
    doc = inspect.getdoc(endpoint_func)
    if not doc:
        return ""
    # Take the first paragraph (up to first blank line)
    paragraphs = doc.split("\n\n")
    first = paragraphs[0].strip()
    # Truncate to 2048 chars
    if len(first) > 2048:
        first = first[:2045] + "..."
    return first


def _classify_category(method: str, path: str, func_name: str) -> str:
    """Classify a route into query, action, or analysis category.

    Rules:
    - If path or function name contains analysis keywords -> "analysis"
    - GET/HEAD/OPTIONS -> "query"
    - POST/PUT/PATCH/DELETE -> "action"
    """
    path_lower = path.lower()
    name_lower = func_name.lower()

    for keyword in _ANALYSIS_KEYWORDS:
        if keyword in path_lower or keyword in name_lower:
            return "analysis"

    if method in ("GET", "HEAD", "OPTIONS"):
        return "query"
    return "action"


def _extract_path_params(path: str) -> Dict[str, Any]:
    """Extract path parameters from a FastAPI path template.

    Example: "/api/v1/findings/{finding_id}" -> {"finding_id": {"type": "string"}}
    """
    params: Dict[str, Any] = {}
    for match in re.finditer(r"\{(\w+)\}", path):
        param_name = match.group(1)
        params[param_name] = {"type": "string", "description": f"Path parameter: {param_name}"}
    return params


def _extract_query_params(route: APIRoute) -> tuple:
    """Extract query parameters from the route's endpoint signature.

    Returns (properties_dict, required_list) suitable for JSON Schema.
    """
    properties: Dict[str, Any] = {}
    required: List[str] = []
    endpoint = route.endpoint

    try:
        sig = inspect.signature(endpoint)
    except (ValueError, TypeError):
        return properties, required

    # Names of parameters injected by FastAPI (not user-supplied)
    _SKIP_PARAMS = {"request", "response", "self", "cls", "db", "session", "background_tasks"}

    for param_name, param in sig.parameters.items():
        if param_name in _SKIP_PARAMS:
            continue

        annotation = param.annotation
        if annotation is inspect.Parameter.empty:
            # Can't determine type; skip dependency-injected params
            # If default is inspect.Parameter.empty, it might be a Depends()
            if param.default is inspect.Parameter.empty:
                continue
            # If there's a default that's not a simple type, skip
            if not isinstance(param.default, (str, int, float, bool, type(None))):
                continue

        # Determine JSON schema type from annotation
        schema: Dict[str, Any] = _annotation_to_json_schema(annotation)

        # Handle default values
        if param.default is not inspect.Parameter.empty:
            if isinstance(param.default, (str, int, float, bool)):
                schema["default"] = param.default
            elif param.default is None:
                schema["default"] = None
        else:
            # No default = required (unless it looks like a dependency)
            if annotation is not inspect.Parameter.empty:
                required.append(param_name)

        if schema.get("type") or schema.get("anyOf"):
            properties[param_name] = schema

    return properties, required


def _annotation_to_json_schema(annotation: Any) -> Dict[str, Any]:
    """Convert a Python type annotation to a JSON Schema fragment."""
    if annotation is inspect.Parameter.empty:
        return {"type": "string"}

    # Handle string representation of types
    type_name = getattr(annotation, "__name__", str(annotation)).lower()

    # Direct type mappings
    type_map = {
        "str": {"type": "string"},
        "int": {"type": "integer"},
        "float": {"type": "number"},
        "bool": {"type": "boolean"},
        "list": {"type": "array"},
        "dict": {"type": "object"},
        "bytes": {"type": "string", "format": "binary"},
    }

    if type_name in type_map:
        return type_map[type_name]

    # Handle Optional[X] (Union[X, None])
    origin = getattr(annotation, "__origin__", None)
    if origin is not None:
        args = getattr(annotation, "__args__", ())
        origin_name = getattr(origin, "__name__", str(origin)).lower()

        if origin_name == "union":
            # Optional[X] is Union[X, None]
            non_none = [a for a in args if a is not type(None)]
            if len(non_none) == 1:
                inner = _annotation_to_json_schema(non_none[0])
                return inner
            return {"type": "string"}

        if origin_name == "list" or str(origin) == "typing.List":
            if args:
                item_schema = _annotation_to_json_schema(args[0])
                return {"type": "array", "items": item_schema}
            return {"type": "array"}

        if origin_name == "dict" or str(origin) == "typing.Dict":
            return {"type": "object"}

    # Pydantic models -> reference their schema
    if hasattr(annotation, "model_json_schema"):
        try:
            return annotation.model_json_schema()
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            return {"type": "object"}
    if hasattr(annotation, "schema"):
        try:
            return annotation.schema()
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            return {"type": "object"}

    # Enum types
    if hasattr(annotation, "__members__"):
        members = list(annotation.__members__.keys())
        return {"type": "string", "enum": members}

    return {"type": "string"}


def _extract_request_body_schema(route: APIRoute) -> Optional[Dict[str, Any]]:
    """Extract request body schema from the route if it has one.

    Checks for Pydantic model parameters in the endpoint signature
    that would be deserialized from the request body.
    """
    endpoint = route.endpoint
    try:
        sig = inspect.signature(endpoint)
    except (ValueError, TypeError):
        return None

    _SKIP_PARAMS = {"request", "response", "self", "cls", "db", "session", "background_tasks"}

    for param_name, param in sig.parameters.items():
        if param_name in _SKIP_PARAMS:
            continue

        annotation = param.annotation
        if annotation is inspect.Parameter.empty:
            continue

        # Check if this is a Pydantic BaseModel
        if isinstance(annotation, type) and hasattr(annotation, "model_json_schema"):
            try:
                return annotation.model_json_schema()
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
                return {"type": "object", "description": f"Request body: {annotation.__name__}"}
        # Legacy Pydantic v1
        if isinstance(annotation, type) and hasattr(annotation, "schema"):
            try:
                return annotation.schema()
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
                return {"type": "object", "description": f"Request body: {annotation.__name__}"}

    return None


def _is_auth_exempt(route: APIRoute) -> bool:
    """Check if a route is exempt from authentication.

    Routes without dependency overrides or with explicit health/public tags
    are considered auth-exempt.
    """
    path = route.path.lower()
    if "/health" in path or "/ready" in path or "/version" in path:
        return True
    # Check if route has no dependencies (no auth)
    if not route.dependencies:
        # Also check if it's a sub-route with inherited dependencies
        tags = [t.lower() for t in (route.tags or [])]
        if "health" in tags or "public" in tags:
            return True
    return False


def generate_tool_catalog(app: FastAPI) -> Dict[str, MCPToolDefinition]:
    """Introspect all FastAPI routes and generate MCP tool definitions.

    This is called once at startup and cached. It iterates over every
    registered APIRoute in the application, extracting:
    - Function name -> tool name
    - Docstring -> description
    - Path parameters + query parameters + request body -> inputSchema
    - HTTP method -> method
    - Tags -> tags
    - Heuristic classification -> category

    Skips internal routes (docs, openapi, health) and the MCP router itself.
    """
    global _tool_catalog, _catalog_stats, _catalog_generated_at
    global _catalog_generation_time_ms, _routes_skipped

    start = time.monotonic()
    catalog: Dict[str, MCPToolDefinition] = {}
    skipped = 0
    name_counts: Dict[str, int] = {}

    for route in app.routes:
        if not isinstance(route, APIRoute):
            skipped += 1
            continue

        path = route.path

        # Skip excluded paths
        if path in _EXCLUDE_PATHS:
            skipped += 1
            continue

        # Skip MCP's own routes to avoid recursion
        if any(path.startswith(prefix) for prefix in _EXCLUDE_PREFIXES):
            skipped += 1
            continue

        # Each route can support multiple methods (GET, POST, etc.)
        methods = route.methods or {"GET"}
        endpoint = route.endpoint
        func_name = getattr(endpoint, "__name__", "unknown")
        description = _extract_description(endpoint)
        tags = list(route.tags or [])
        is_deprecated = getattr(route, "deprecated", False) or False

        # Skip routes tagged with excluded tags (demo/admin endpoints)
        route_tags_lower = {t.lower() for t in tags}
        if route_tags_lower & _EXCLUDE_TAGS:
            skipped += 1
            continue

        # Skip routes with excluded path substrings
        if any(sub in path for sub in _EXCLUDE_PATH_SUBSTRINGS):
            skipped += 1
            continue

        for method in sorted(methods):
            # Skip HEAD and OPTIONS (not useful as MCP tools)
            if method in ("HEAD", "OPTIONS"):
                skipped += 1
                continue

            # Generate unique tool name
            base_name = _sanitize_tool_name(func_name)

            # If multiple methods share the same function name, differentiate
            tool_name = base_name
            if tool_name in name_counts:
                name_counts[tool_name] += 1
                tool_name = f"{base_name}_{method.lower()}"
            else:
                name_counts[base_name] = 1

            # If still duplicate (rare), append a counter
            if tool_name in catalog:
                counter = 2
                while f"{tool_name}_{counter}" in catalog:
                    counter += 1
                tool_name = f"{tool_name}_{counter}"

            # Build input schema
            path_params = _extract_path_params(path)
            query_props, query_required = _extract_query_params(route)
            body_schema = None

            if method in ("POST", "PUT", "PATCH"):
                body_schema = _extract_request_body_schema(route)

            # Merge all properties
            all_properties: Dict[str, Any] = {}
            all_required: List[str] = []

            # Path params are always required
            for pname, pschema in path_params.items():
                all_properties[pname] = pschema
                all_required.append(pname)

            # Query params
            all_properties.update(query_props)
            all_required.extend(query_required)

            # Body schema
            if body_schema:
                if body_schema.get("type") == "object" and "properties" in body_schema:
                    # Flatten body properties into the top-level schema
                    body_props = body_schema.get("properties", {})
                    body_required = body_schema.get("required", [])
                    for bp_name, bp_schema in body_props.items():
                        if bp_name not in all_properties:
                            all_properties[bp_name] = bp_schema
                    for br in body_required:
                        if br not in all_required:
                            all_required.append(br)
                else:
                    # Complex body - add as a "body" property
                    all_properties["body"] = body_schema

            input_schema = MCPToolInputSchema(
                type="object",
                properties=all_properties,
                required=all_required,
            )

            category = _classify_category(method, path, func_name)
            requires_auth = not _is_auth_exempt(route)

            tool = MCPToolDefinition(
                name=tool_name,
                description=description,
                inputSchema=input_schema,
                method=method,
                path=path,
                tags=tags,
                category=category,
                requires_auth=requires_auth,
                deprecated=is_deprecated,
            )

            catalog[tool_name] = tool

    # Compute stats
    elapsed_ms = (time.monotonic() - start) * 1000
    now = datetime.now(timezone.utc).isoformat() + "Z"

    by_category: Dict[str, int] = {}
    by_method: Dict[str, int] = {}
    by_tag: Dict[str, int] = {}

    for tool in catalog.values():
        by_category[tool.category] = by_category.get(tool.category, 0) + 1
        by_method[tool.method] = by_method.get(tool.method, 0) + 1
        for tag in tool.tags:
            by_tag[tag] = by_tag.get(tag, 0) + 1

    stats = MCPCatalogStats(
        total_tools=len(catalog),
        by_category=by_category,
        by_method=by_method,
        by_tag=by_tag,
        routes_skipped=skipped,
        generated_at=now,
        generation_time_ms=round(elapsed_ms, 2),
    )

    # Store in module state
    _tool_catalog = catalog
    _catalog_stats = stats
    _catalog_generated_at = now
    _catalog_generation_time_ms = elapsed_ms
    _routes_skipped = skipped

    logger.info(
        "MCP auto-discovery complete: %d tools generated from %d routes "
        "(%d skipped) in %.1fms",
        len(catalog),
        len(catalog) + skipped,
        skipped,
        elapsed_ms,
    )

    return catalog


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------


@router.get("/tools", response_model=List[MCPToolDefinition])
async def list_mcp_tools(
    request: Request,
    category: Optional[str] = Query(
        None,
        description="Filter by category: query, action, analysis",
        pattern="^(query|action|analysis)$",
    ),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    method: Optional[str] = Query(
        None,
        description="Filter by HTTP method: GET, POST, PUT, DELETE, PATCH",
        pattern="^(GET|POST|PUT|DELETE|PATCH)$",
    ),
    search: Optional[str] = Query(
        None,
        description="Search tool names and descriptions",
        max_length=200,
    ),
    deprecated: Optional[bool] = Query(
        None, description="Filter by deprecation status"
    ),
    limit: int = Query(100, ge=1, le=1000, description="Max tools to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
) -> List[MCPToolDefinition]:
    """Return the complete MCP tool catalog with optional filtering.

    This endpoint returns auto-discovered tools generated from all FastAPI
    routes registered in the application. Tools are generated once at
    startup and cached for performance.

    Supports filtering by category (query/action/analysis), tag, HTTP method,
    and free-text search across tool names and descriptions.
    """
    _ensure_catalog(request.app)

    tools = list(_tool_catalog.values())

    if category:
        tools = [t for t in tools if t.category == category]
    if tag:
        tag_lower = tag.lower()
        tools = [t for t in tools if any(tag_lower == tg.lower() for tg in t.tags)]
    if method:
        tools = [t for t in tools if t.method == method.upper()]
    if deprecated is not None:
        tools = [t for t in tools if t.deprecated == deprecated]
    if search:
        search_lower = search.lower()
        tools = [
            t
            for t in tools
            if search_lower in t.name.lower() or search_lower in t.description.lower()
        ]

    # Apply pagination
    _total = len(tools)
    tools = tools[offset : offset + limit]

    return tools


@router.get("/tools/{tool_name}", response_model=MCPToolDefinition)
async def get_mcp_tool(request: Request, tool_name: str) -> MCPToolDefinition:
    """Return the schema for a single MCP tool by name.

    Raises 404 if the tool does not exist in the catalog.
    """
    _ensure_catalog(request.app)

    if tool_name not in _tool_catalog:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "tool_not_found",
                "tool_name": tool_name,
                "message": f"Tool '{tool_name}' not found in catalog",
                "hint": "Use GET /api/v1/mcp/tools to list available tools",
            },
        )
    return _tool_catalog[tool_name]


@router.post("/execute", response_model=MCPExecuteResponse)
async def execute_mcp_tool(
    request: Request,
    body: MCPExecuteRequest,
    org_id: str = Depends(get_org_id),
) -> MCPExecuteResponse:
    """Execute an MCP tool by name with the given arguments.

    This endpoint resolves the tool name to its backing FastAPI route,
    constructs the appropriate HTTP request, and forwards it internally.
    The result is returned in a standardized MCP response envelope.

    Note: This is a proxy endpoint. The actual execution happens by
    forwarding to the underlying route handler. Authentication and
    authorization are inherited from the caller's session.
    """
    _ensure_catalog(request.app)

    tool_name = body.tool_name
    if tool_name not in _tool_catalog:
        return MCPExecuteResponse(
            tool_name=tool_name,
            method="",
            path="",
            status="not_found",
            status_code=404,
            error=f"Tool '{tool_name}' not found in catalog",
        )

    tool = _tool_catalog[tool_name]
    start = time.monotonic()

    try:
        # Resolve the route handler
        handler = _find_route_handler(request.app, tool.method, tool.path)
        if handler is None:
            return MCPExecuteResponse(
                tool_name=tool_name,
                method=tool.method,
                path=tool.path,
                status="error",
                status_code=500,
                error="Could not resolve route handler",
                execution_time_ms=_elapsed_ms(start),
            )

        # Build path with substituted parameters
        resolved_path = tool.path
        remaining_args = dict(body.arguments)

        # Substitute path parameters
        for match in re.finditer(r"\{(\w+)\}", tool.path):
            param_name = match.group(1)
            if param_name in remaining_args:
                value = str(remaining_args.pop(param_name))
                # Validate path parameter to prevent path traversal / injection
                if len(value) > 255:
                    return MCPExecuteResponse(
                        tool_name=tool_name,
                        method=tool.method,
                        path=tool.path,
                        status="error",
                        status_code=400,
                        error=f"Path parameter '{param_name}' exceeds maximum length of 255 characters",
                        execution_time_ms=_elapsed_ms(start),
                    )
                if not re.fullmatch(r"[A-Za-z0-9_\-\.]+", value):
                    return MCPExecuteResponse(
                        tool_name=tool_name,
                        method=tool.method,
                        path=tool.path,
                        status="error",
                        status_code=400,
                        error=f"Path parameter '{param_name}' contains invalid characters; only alphanumeric, dash, underscore, and dot are allowed",
                        execution_time_ms=_elapsed_ms(start),
                    )
                if ".." in value:
                    return MCPExecuteResponse(
                        tool_name=tool_name,
                        method=tool.method,
                        path=tool.path,
                        status="error",
                        status_code=400,
                        error=f"Path parameter '{param_name}' must not contain '..'",
                        execution_time_ms=_elapsed_ms(start),
                    )
                resolved_path = resolved_path.replace(f"{{{param_name}}}", value)
            else:
                return MCPExecuteResponse(
                    tool_name=tool_name,
                    method=tool.method,
                    path=tool.path,
                    status="error",
                    status_code=400,
                    error=f"Missing required path parameter: {param_name}",
                    execution_time_ms=_elapsed_ms(start),
                )

        # Use the ASGI test client approach for internal routing
        from starlette.testclient import TestClient

        # Build request kwargs
        client = TestClient(request.app, raise_server_exceptions=False)

        # Forward auth headers from the original request
        headers: Dict[str, str] = {}
        for header_name in ("authorization", "x-api-key", "cookie"):
            val = request.headers.get(header_name)
            if val:
                headers[header_name] = val

        if tool.method == "GET":
            resp = client.get(resolved_path, params=remaining_args, headers=headers)
        elif tool.method == "DELETE":
            resp = client.delete(resolved_path, params=remaining_args, headers=headers)
        elif tool.method in ("POST", "PUT", "PATCH"):
            req_method = getattr(client, tool.method.lower())
            resp = req_method(resolved_path, json=remaining_args, headers=headers)
        else:
            resp = client.get(resolved_path, params=remaining_args, headers=headers)

        # Parse response
        try:
            result = resp.json()
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
            result = resp.text

        elapsed = _elapsed_ms(start)
        return MCPExecuteResponse(
            tool_name=tool_name,
            method=tool.method,
            path=resolved_path,
            status="success" if resp.status_code < 400 else "error",
            status_code=resp.status_code,
            result=result,
            execution_time_ms=elapsed,
        )

    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("MCP tool execution failed: %s", tool_name)
        return MCPExecuteResponse(
            tool_name=tool_name,
            method=tool.method,
            path=tool.path,
            status="error",
            status_code=500,
            error=f"Execution failed: {type(exc).__name__}",
            execution_time_ms=_elapsed_ms(start),
        )


@router.get("/schemas")
async def get_mcp_schemas(
    request: Request,
    format: str = Query(
        "mcp",
        description="Schema format: mcp (MCP protocol), openapi",
        pattern="^(mcp|openapi)$",
    ),
) -> Dict[str, Any]:
    """Return all tool schemas in MCP-compliant format.

    The 'mcp' format returns the standard MCP tools/list response
    compatible with the Model Context Protocol specification.

    The 'openapi' format returns a simplified OpenAPI-style schema.
    """
    _ensure_catalog(request.app)

    if format == "mcp":
        # MCP protocol format: tools/list response
        tools_list = []
        for tool in _tool_catalog.values():
            tools_list.append(
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.inputSchema.model_dump(),
                }
            )
        return {
            "tools": tools_list,
            "_meta": {
                "total": len(tools_list),
                "generated_at": _catalog_generated_at,
                "mcp_version": "2024-11-05",
            },
        }

    # openapi format
    paths: Dict[str, Any] = {}
    for tool in _tool_catalog.values():
        method_lower = tool.method.lower()
        if tool.path not in paths:
            paths[tool.path] = {}
        paths[tool.path][method_lower] = {
            "operationId": tool.name,
            "summary": tool.description[:200] if tool.description else "",
            "tags": tool.tags,
            "parameters": [
                {
                    "name": prop_name,
                    "in": "path" if f"{{{prop_name}}}" in tool.path else "query",
                    "schema": prop_schema,
                    "required": prop_name in tool.inputSchema.required,
                }
                for prop_name, prop_schema in tool.inputSchema.properties.items()
            ],
        }

    return {
        "openapi": "3.1.0",
        "info": {
            "title": "ALdeci MCP Tool Catalog",
            "version": "1.0.0",
            "description": "Auto-generated from FastAPI routes",
        },
        "paths": paths,
        "_meta": {
            "total_tools": len(_tool_catalog),
            "generated_at": _catalog_generated_at,
        },
    }


@router.get("/health", response_model=MCPHealthResponse)
async def mcp_health(request: Request) -> MCPHealthResponse:
    """Health check for the MCP auto-discovery service.

    Returns the catalog size, generation timestamp, and service uptime.
    """
    _ensure_catalog(request.app)

    uptime = time.monotonic() - _startup_time
    return MCPHealthResponse(
        status="healthy" if _tool_catalog else "degraded",
        catalog_size=len(_tool_catalog),
        generated_at=_catalog_generated_at,
        uptime_seconds=round(uptime, 2),
    )


@router.get("/status")
async def mcp_status(request: Request) -> dict:
    """Status alias for MCP auto-discovery (mirrors /health)."""
    result = await mcp_health(request)
    return result.model_dump()


@router.get("/stats", response_model=MCPCatalogStats)
async def mcp_stats(request: Request) -> MCPCatalogStats:
    """Return statistics about the auto-generated tool catalog.

    Includes breakdowns by category, HTTP method, and tag, plus
    generation timing information.
    """
    _ensure_catalog(request.app)

    if _catalog_stats is None:
        raise HTTPException(
            status_code=503,
            detail="Catalog not yet generated",
        )
    return _catalog_stats


@router.get("/manifest")
async def get_mcp_manifest(request: Request) -> Dict[str, Any]:
    """Return the MCP server manifest for IDE/agent configuration.

    This returns JSON that can be added to VS Code settings (.vscode/mcp.json),
    Cursor (.cursor/mcp.json), or Claude Desktop config.
    """
    _ensure_catalog(request.app)
    base_url = str(request.base_url).rstrip("/")
    return {
        "mcpServers": {
            "fixops": {
                "url": f"{base_url}/api/v1/mcp-protocol/sse",
                "env": {
                    "FIXOPS_API_URL": base_url,
                    "FIXOPS_API_KEY": "${FIXOPS_API_KEY}",
                },
                "description": "FixOps CTEM+ security platform — findings, scans, evidence, remediation",
                "transport": "sse",
            }
        },
        "http_config": {
            "tools_url": f"{base_url}/api/v1/mcp/tools",
            "execute_url": f"{base_url}/api/v1/mcp/execute",
            "schemas_url": f"{base_url}/api/v1/mcp/schemas",
            "headers": {
                "X-API-Key": "${FIXOPS_API_KEY}",
            },
        },
        "catalog_size": len(_tool_catalog),
        "generated_at": _catalog_generated_at,
    }


@router.post("/refresh")
async def refresh_catalog(request: Request) -> Dict[str, Any]:
    """Manually refresh the MCP tool catalog.

    Re-introspects all FastAPI routes and regenerates the catalog.
    This is useful if routes are dynamically added after startup.
    """
    old_count = len(_tool_catalog)
    catalog = generate_tool_catalog(request.app)
    new_count = len(catalog)

    return {
        "status": "refreshed",
        "previous_tool_count": old_count,
        "current_tool_count": new_count,
        "delta": new_count - old_count,
        "generated_at": _catalog_generated_at,
        "generation_time_ms": round(_catalog_generation_time_ms, 2),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ensure_catalog(app: FastAPI) -> None:
    """Generate the catalog on first access if not yet populated.

    The catalog is typically generated at startup via the on_event hook,
    but this provides a safety net for lazy initialization.
    """
    if not _tool_catalog:
        generate_tool_catalog(app)


def _find_route_handler(app: FastAPI, method: str, path_template: str) -> Any:
    """Find the route handler function for a given method and path."""
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path == path_template and method in (route.methods or set()):
            return route.endpoint
    return None


def _elapsed_ms(start: float) -> float:
    """Calculate elapsed milliseconds since start."""
    return round((time.monotonic() - start) * 1000, 2)


# ---------------------------------------------------------------------------
# Startup hook (called from app.py after all routers are mounted)
# ---------------------------------------------------------------------------


def register_startup_hook(app: FastAPI) -> None:
    """Register the MCP catalog generation as a startup event.

    This must be called AFTER all routers are included in the app,
    so that the introspection can see every route.
    """

    @app.on_event("startup")
    async def _generate_mcp_catalog():
        """Generate MCP tool catalog from all registered FastAPI routes."""
        try:
            catalog = generate_tool_catalog(app)
            logger.info(
                "MCP tool catalog ready: %d tools across %d categories",
                len(catalog),
                len(set(t.category for t in catalog.values())),
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("MCP catalog generation failed: %s", exc, exc_info=True)
