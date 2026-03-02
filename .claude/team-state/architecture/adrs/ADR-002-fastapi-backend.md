# ADR-002: FastAPI Single-Process Backend

- **Status**: Accepted
- **Date**: 2026-02-27 (documented 2026-03-02)
- **Author**: enterprise-architect
- **Pillar**: V3 (Decision Intelligence), V7 (MCP-Native), V9 (Air-Gapped)

## Context

ALdeci needs a Python web framework that supports:
1. 759+ REST endpoints across 64 router files
2. Async I/O for LLM API calls and scanner webhooks
3. Auto-generated OpenAPI spec for MCP tool discovery (V7)
4. Pydantic v2 for request/response validation
5. Low-overhead deployment for air-gapped environments (V9)
6. WebSocket support for real-time pipeline progress

Alternatives considered:
- **Django REST Framework**: Too heavyweight, ORM not needed (we use SQLite directly)
- **Flask**: No native async, no auto-OpenAPI, manual Pydantic integration
- **Starlette raw**: Too low-level for 759+ endpoints
- **gRPC**: Not HTTP — would break MCP JSON-RPC requirement

## Decision

Use **FastAPI** as the single-process backend framework with:
- `uvicorn` ASGI server (single worker for demo, multi-worker for production)
- Factory pattern: `create_app()` in `suite-api/apps/api/app.py`
- 34 router mounts, each with prefix and tags
- Pydantic v2 for all request/response models
- OpenAPI JSON auto-generated at `/openapi.json`
- CORS middleware with configurable origins

### Router Mounting Pattern
```python
# suite-api/apps/api/app.py
app.include_router(brain_router, tags=["brain"])
app.include_router(autofix_router, tags=["autofix"])
# ... 34 total mounts
```

### Auth Pattern
```python
# Two auth mechanisms:
1. API Key: X-API-Key header → _verify_api_key dependency
2. JWT Token: Bearer token → require_auth dependency
# Rate limiting: configurable, disabled for demo
```

## Consequences

### Positive
- Auto-generated OpenAPI spec enables MCP tool auto-discovery (665+ tools from 759 endpoints)
- Pydantic v2 provides free request validation and documentation
- Async support for non-blocking LLM/scanner calls
- Single binary deployment (uvicorn + app.py) — air-gapped friendly
- FastAPI's dependency injection simplifies auth middleware

### Negative
- Single-process = no horizontal scaling (OK for Phase 1)
- 34 router mounts in one file is approaching maintainability limit
- OpenAPI serialization of 759 endpoints can be slow (known `/openapi.json` 500 bug)
- No built-in background task queue (using in-process event bus)
- Synchronous Brain Pipeline blocks uvicorn event loop during LLM steps

### Trade-offs
- Chose simplicity (single process) over scale (multi-service)
- Chose auto-OpenAPI over manual API docs
- Chose SQLite over PostgreSQL for Phase 1 simplicity

## Metrics (Verified 2026-03-02)

| Metric | Value |
|--------|-------|
| Endpoints | 759 |
| Router files | 64 |
| Router mounts in app.py | 34 |
| app.py LOC | 2,742 |
| Auth methods | 2 (API key + JWT) |

## Verification

- `python -m uvicorn apps.api.app:create_app --factory --port 8000` starts server: ✅
- 34 routers mount without error: ✅
- Brain Pipeline, AutoFix, MPTE all reachable via HTTP: ✅
