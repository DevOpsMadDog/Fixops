# PRD — Community 380: API Endpoints Module (aldeci-ui-new)

## Master Goal Mapping
- **Platform Goal**: Typed function calls for all 574+ backend routes — single source of truth for API contract
- **Persona**: Frontend Engineers — ensures type-safe communication with FastAPI backend
- **ALDECI Pillar**: API Layer / Type Safety

## Architecture Diagram
```mermaid
graph TD
    A[Dashboard Pages] -->|import endpoint fns| B[endpoints.ts]
    B --> C[getApiClient()]
    B --> D[Type imports from types.ts]
    B --> E[Finding endpoints: getFindings, createFinding...]
    B --> F[Pipeline endpoints: getPipelineHealth...]
    B --> G[Compliance endpoints: getComplianceTemplates...]
    B --> H[TrustGraph endpoints: queryGraph, graphRAG...]
    B --> I[MCP endpoints: callMCPTool...]
    C --> J[ApiClient instance]
    J --> K[FastAPI Backend - port 8000]
```

## Code Proof
- **File**: `suite-ui/aldeci-ui-new/src/api/endpoints.ts:1-50+`
- **Pattern**: `export async function getFoo(...): Promise<Bar> { return getApiClient().get('/api/v1/foo') }`
- **Type imports**: `Finding`, `PaginatedResponse`, `PipelineHealth`, `ComplianceTemplate`, `TrustGraphEntity`, `GraphRAGResult`, `MCPTool`, `StreamEvent`, and 40+ more
- **Domains**: Findings, Pipeline, Dashboard, Connectors, Playbooks, Compliance, TrustGraph, MCP, Streaming

## Inter-Dependencies
- **Upstream**: `./client` (ApiClient), `./types` (all domain types)
- **Downstream**: React Query hooks (`useQuery`, `useMutation`), direct component calls
- **Backend**: Maps to `suite-api/apps/api/*_router.py` endpoints

## Data Flow
```
React component → endpoint fn → ApiClient.get/post/put/delete →
fetch with timeout + retry → JSON parse → typed return value →
useQuery caches result → component renders data
```

## Referenced Docs
- Backend routers: `suite-api/apps/api/`
- `docs/ALDECI_REARCHITECTURE_v2.md` — API architecture

## Acceptance Criteria
- [ ] Every domain has typed endpoint functions
- [ ] Return types match Pydantic backend models
- [ ] `PaginatedResponse<T>` used for list endpoints
- [ ] Endpoint paths match backend router prefixes
- [ ] No hardcoded base URLs (uses `getApiClient()`)

## Effort Estimate
**M** — 3 days (complex, many domains — complete)

## Status
**DONE** — Stable, comprehensive endpoint registry
