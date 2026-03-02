# ADR-009: MCP Auto-Discovery Architecture

- **Status**: Accepted
- **Date**: 2026-03-02
- **Context**: ALdeci positions as the first MCP-native AppSec platform (V7). AI agents need to discover and invoke ALdeci's 700+ API endpoints programmatically. A static tool catalog would require manual maintenance for every new endpoint. A dynamic approach was needed.
- **Pillar**: V7 (MCP-Native AI Platform)
- **Author**: enterprise-architect

## Decision

ALdeci implements **two complementary MCP subsystems** that together enable full AI agent interoperability:

### 1. MCP Auto-Discovery Router (Dynamic Catalog)
**File**: `suite-api/apps/api/mcp_router.py` (977 LOC)
**Prefix**: `/api/v1/mcp/*`

Auto-generates MCP tool definitions by introspecting all FastAPI routes at startup:

```
Application Startup
  └─ generate_tool_catalog(app) called once
       └─ Iterates all app.routes (APIRoute instances)
       └─ For each route:
            ├─ Extracts function name → tool name
            ├─ Extracts docstring → description
            ├─ Introspects signature → inputSchema (path + query + body params)
            ├─ Classifies category: query | action | analysis
            └─ Produces MCPToolDefinition (Pydantic model)
       └─ Stores in module-level _tool_catalog dict (705+ tools)
       └─ Computes MCPCatalogStats (by_category, by_method, by_tag)
```

**Key design decisions**:
- **Startup-time generation**: Catalog computed once at `app.startup`, cached in module-level dict. No per-request overhead.
- **Self-exclusion**: Routes under `/api/v1/mcp` excluded to prevent recursive tool discovery.
- **Name deduplication**: If multiple methods share a function name, method suffix is appended (`foo` → `foo_get`, `foo_post`). Counter-based fallback for remaining conflicts.
- **Type introspection**: Supports Pydantic v2 (`model_json_schema()`), Pydantic v1 (`.schema()`), Python enums, and primitive type annotations.
- **Category classification**: Heuristic-based using 20 analysis keywords (e.g., "score", "triage", "risk") and HTTP method (GET→query, POST→action).

**Endpoints**:
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/mcp/tools` | List all tools (paginated, filtered by category/tag/method/search) |
| GET | `/api/v1/mcp/tools/{name}` | Get single tool schema |
| POST | `/api/v1/mcp/execute` | Execute tool by name (proxy to underlying endpoint) |
| GET | `/api/v1/mcp/stats` | Catalog statistics |
| POST | `/api/v1/mcp/refresh` | Regenerate catalog from live routes |
| GET | `/api/v1/mcp/health` | MCP subsystem health |
| GET | `/api/v1/mcp/status` | Alias for health |

### 2. MCP Protocol Engine (JSON-RPC 2.0)
**File**: `suite-core/core/mcp_server.py` (979 LOC)
**Prefix**: `/api/v1/mcp-protocol/*` (via `suite-core/api/mcp_protocol_router.py`)

Full MCP 2024-11-05 spec implementation:

```
AI Agent → POST /api/v1/mcp-protocol/rpc
         → JSON-RPC 2.0 request: {"method": "tools/list", "id": 1}
         → MCPProtocolHandler dispatches to appropriate handler
         → Returns JSON-RPC 2.0 response with tool list or execution result
```

**Components**:
- `MCPToolRegistry`: Auto-discovers tools from FastAPI routes (shared with mcp_router)
- `MCPResourceServer`: Serves security data as MCP resources (findings, compliance)
- `MCPPromptLibrary`: Curated prompt templates for security workflows
- `MCPSessionManager`: Client session lifecycle with capability negotiation
- `MCPProtocolHandler`: JSON-RPC 2.0 message processing

**Protocol methods supported**:
- `initialize` / `notifications/initialized` — Session lifecycle
- `tools/list` / `tools/call` — Tool discovery and execution
- `resources/list` / `resources/read` — Resource access
- `prompts/list` / `prompts/get` — Prompt templates
- `ping` — Health check

### Architecture Relationship

```
┌─────────────────────────────────────────────────────────┐
│                    FastAPI Application                    │
│                    (769 routes total)                     │
├──────────────┬──────────────┬───────────────────────────┤
│  /api/v1/*   │ /api/v1/mcp/*│ /api/v1/mcp-protocol/*    │
│  (All other  │ (Auto-Disc.) │ (JSON-RPC 2.0)            │
│   routers)   │              │                            │
│              │ Introspects  │ Wraps                      │
│              │ all routes   │ tool catalog               │
│              │ at startup   │ + resources + prompts      │
│              │    ↓         │    ↓                       │
│              │ _tool_catalog│ MCPToolRegistry             │
│              │ (705 tools)  │ (shared discovery logic)    │
├──────────────┴──────────────┴───────────────────────────┤
│                   Shared: FastAPI route introspection     │
└─────────────────────────────────────────────────────────┘
```

## Consequences

### Positive
- **Zero maintenance**: New endpoints automatically appear in MCP catalog after restart
- **Full coverage**: 705 tools from 769 routes — 92% coverage (excludes health/docs/MCP-self)
- **Type-safe**: Input schemas generated from Python type annotations and Pydantic models
- **Filterable**: Category, tag, method, search, deprecation filters for targeted discovery
- **Standard-compliant**: JSON-RPC 2.0 per MCP 2024-11-05 specification
- **First mover**: No other AppSec platform has MCP support (verified 2026-03-01)

### Negative
- **Startup cost**: Catalog generation takes ~50-100ms for 769 routes. Acceptable but grows linearly.
- **Name collision risk**: Two endpoints with same function name get suffixed. Could confuse AI agents. Mitigated by including path in tool definition.
- **Stale catalog**: Catalog is static after startup. Dynamic route changes (unlikely in production) require manual `/api/v1/mcp/refresh`.
- **Self-referential discovery**: 705 tools are ALdeci's own endpoints — real auto-discovery, but the tools only expose ALdeci capabilities (not external scanners).

### Honesty Note
The 705 MCP tools are self-discovered from ALdeci's own 769 API endpoints. This is genuine auto-discovery (reads live OpenAPI spec at runtime), but self-referential — the tools expose ALdeci's capabilities, not third-party services. This is still valuable: it makes ALdeci the first AppSec platform that AI agents can programmatically consume.

## Alternatives Considered

1. **Static tool catalog** — Manually maintained list of ~50 key tools. Rejected: high maintenance burden, always stale.
2. **OpenAPI-to-MCP conversion** — Generate tools from OpenAPI spec JSON. Rejected: OpenAPI spec is already generated by FastAPI, so introspecting routes directly is more precise (access to Python type annotations).
3. **Plugin architecture** — Each router registers its own MCP tools. Rejected: requires changes to all 34+ routers. Auto-discovery is zero-change.

## References

- MCP Specification: https://spec.modelcontextprotocol.io/specification/2024-11-05/
- `suite-api/apps/api/mcp_router.py` — Auto-discovery router (977 LOC)
- `suite-core/core/mcp_server.py` — Protocol engine (979 LOC)
- `suite-core/api/mcp_protocol_router.py` — JSON-RPC HTTP adapter
- ADR-007: API Gateway Security (auth mechanism shared with MCP)

---

*Written by enterprise-architect on 2026-03-02. Serves pillar: V7 (MCP-Native AI Platform).*
