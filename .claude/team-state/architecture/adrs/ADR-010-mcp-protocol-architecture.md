# ADR-010: MCP Protocol Architecture — Dual Subsystem Design

- **Status**: Accepted
- **Date**: 2026-03-03
- **Context**: ALdeci's MCP (Model Context Protocol) implementation comprises two subsystems that evolved independently: an Auto-Discovery Router (startup-time catalog from FastAPI routes) and a Protocol Engine (full JSON-RPC 2.0 MCP handler). A deep review revealed critical bugs (broken attribute access, auth bypass) and architectural decisions that need to be formalized.
- **Pillar**: V7 — MCP-Native AI Platform
- **Related ADRs**: ADR-009 (MCP Auto-Discovery), ADR-002 (FastAPI Backend)
- **Review**: review-007-mcp-architecture-2026-03-03.md

## Decision

### 1. Dual Subsystem Architecture (Accepted)

The MCP subsystem has two complementary halves:

| Subsystem | Prefix | File | Purpose |
|-----------|--------|------|---------|
| Auto-Discovery Router | `/api/v1/mcp/*` | `suite-api/apps/api/mcp_router.py` | Startup catalog from FastAPI routes |
| Protocol Engine | `/api/v1/mcp-protocol/*` | `suite-core/api/mcp_protocol_router.py` + `suite-core/core/mcp_server.py` | Full JSON-RPC 2.0 MCP handler |

**Rationale**: The Auto-Discovery Router provides the OpenAPI-compatible REST interface that web clients and Postman use. The Protocol Engine provides the native MCP JSON-RPC interface that AI agents (Claude, GPT, etc.) use directly. Both generate tools from the same FastAPI routes but serve different clients.

**Consequence**: Two code paths to maintain. But the separation is clean: Auto-Discovery is REST, Protocol Engine is JSON-RPC. They share the same underlying route data.

### 2. Singleton Protocol Handler (Accepted — Fixed in Run 9)

The Protocol Engine MUST use `get_mcp_handler()` singleton, NOT create new instances per request.

**Why**: `MCPProtocolHandler()` holds session state, tool registry, and audit log. Creating new instances per request loses all state and makes the MCP protocol useless (no session continuity, no tools discovered, no audit trail).

**Fixed**: All 10 protocol router endpoints now use `_get_handler()` which delegates to `get_mcp_handler()`.

### 3. Auth Bypass in tools/call (Known Risk, Deferred to Phase 2)

`_handle_tools_call` in `mcp_server.py` directly invokes endpoint functions, bypassing FastAPI's dependency injection (including `Depends(_verify_api_key)`).

**Risk**: MCP clients can execute tools without per-endpoint authorization checks.

**Mitigation**: The protocol router endpoints themselves require app-level authentication. The bypass only matters if MCP has weaker auth than individual endpoints.

**Phase 2 Fix**: Add explicit auth verification in `_handle_tools_call` before handler invocation, or route through the ASGI stack.

### 4. Tool Execution Strategy

Two execution paths exist:
- **REST /execute**: Uses `starlette.testclient.TestClient` for internal routing. Preserves auth but expensive.
- **JSON-RPC tools/call**: Direct handler invocation. Fast but bypasses auth.

**Decision**: Both paths are valid. REST /execute is the recommended path for security-sensitive environments. JSON-RPC tools/call is acceptable when the MCP session itself is authenticated.

**Phase 2**: Replace TestClient with direct ASGI routing (`app.router.handle()`) to get both auth preservation and performance.

### 5. Protocol Version

**Current**: Two version strings exist:
- `mcp_server.py`: `PROTOCOL_VERSION = "2025-03-26"`
- `mcp_router.py`: `mcp_version = "2024-11-05"`

**Decision**: The Protocol Engine version (2025-03-26) is authoritative. The Auto-Discovery Router should update to match. This is a non-breaking cosmetic fix (TD-032).

## Consequences

### Positive
- Full MCP 2025 protocol compliance (JSON-RPC 2.0)
- 705+ auto-discovered tools from FastAPI routes
- SSE transport for real-time AI agent integration
- Session management with LRU eviction (max 50 clients)
- Audit logging with bounded memory (10K entries, 50% eviction)

### Negative
- Two subsystems to maintain (but clean separation)
- Auth bypass in JSON-RPC path (deferred to Phase 2)
- In-memory state only (sessions, audit lost on restart)
- SSE uses blocking time.sleep() (must fix for production async)

### Risks
- If someone adds routes after startup, the catalog is stale until `/refresh` is called
- No rate limiting per MCP session (only global rate limit)
- Tool execution errors don't have structured error codes beyond generic -32603

## Files

| File | LOC | Role |
|------|-----|------|
| `suite-core/core/mcp_server.py` | 979 | Protocol engine (5 classes, 10 methods) |
| `suite-api/apps/api/mcp_router.py` | 1,016 | Auto-discovery router (7 endpoints) |
| `suite-core/api/mcp_protocol_router.py` | 220 | Protocol router (10 endpoints) |
