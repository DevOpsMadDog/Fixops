# PRD: Community 126 — Streaming API Router (SSE / Pipeline Events)

> **Status**: `PARTIAL (engine/router only)`
> **Size**: XS — 10 graph nodes · 1 source files
> **Effort Estimate**: 0.5-1 day
> **Community ID**: 126 of 878 total communities
> **Generated**: 2026-04-16 · Beast Mode v6 Autonomous Build

---

## 1. Master Goal Mapping

1. **Expose Server-Sent Event streams for pipeline progress via stream_pipeline_progress()**
2. **Stream real-time security events to dashboard clients via stream_events()**
3. **Provide streaming_health() liveness endpoint for SSE infrastructure**

**Platform Fit**: ALDECI ASPM + CTEM + CSPM — self-hosted, AI-native security intelligence platform
**Personas Served**: CISO · Security Engineer · SOC Analyst · Compliance Officer · DevSecOps Engineer
**ALDECI Principle**: Each engine = isolated SQLite domain + FastAPI router + pytest suite + React dashboard

---

## 2. Architecture Diagram

```mermaid
graph TD
    C126["Security Domain Module (Comm"]
    streaming_router_p126["streaming_router.py"] --> C126
    C126 --> DC0["Community 0\n(1 edges)"]
```

### Layer Breakdown

| Layer | Files | Responsibility |
|-------|-------|----------------|
| **Engine** | N/A | Business logic · SQLite persistence · RLock threading · org_id scoping |
| **Router** | streaming_router.py | FastAPI endpoints · Pydantic validation · api_key_auth injection |
| **Tests** | N/A | pytest lifecycle coverage · org isolation tests · edge case validation |
| **UI** | Pending | React 19 dashboard · Tailwind v4 · live API wiring |

---

## 3. Code Proof (file:line + key constructs)


**Router** — `suite-core/api/streaming_router.py`:
```python
router = APIRouter(prefix="/api/v1/security-domain-module-(community-126)", tags=["Security Domain Module (Community 126)"])
@router.get("/", dependencies=[Depends(api_key_auth)])
async def list_items(org_id: str = Query(...)):
    return engine.list_items(org_id)
```


### Key Graph Nodes (10 total in community)

| # | Label | Source File |
|---|-------|-------------|
| 1 | `streaming_router.py` | `suite-core/api/streaming_router.py` |
| 2 | `stream_pipeline_progress()` | `N/A` |
| 3 | `stream_events()` | `N/A` |
| 4 | `streaming_health()` | `N/A` |
| 5 | `streaming_status()` | `N/A` |
| 6 | `SSE (Server-Sent Events) streaming endpoints.` | `N/A` |
| 7 | `Stream pipeline run progress as SSE events.` | `N/A` |
| 8 | `Stream EventBus events in real-time via SSE.` | `N/A` |
| 9 | `Streaming/SSE service health check.` | `N/A` |
| 10 | `Streaming/SSE service status (alias for /heal` | `N/A` |


### All Source Files (1)

- `suite-core/api/streaming_router.py`

---

## 4. Inter-Dependencies

### Cross-Community Edge Counts

- **Community 0**: 1 shared edges

### Standard ALDECI Internal Dependencies

| Dependency | Purpose | Pattern |
|-----------|---------|---------|
| **SQLite WAL** | Per-domain persistence | `PRAGMA journal_mode=WAL` on init |
| **RLock** | Write thread safety | `threading.RLock()` wraps all mutations |
| **org_id** | Multi-tenant isolation | Parameterized WHERE clause on every query |
| **api_key_auth** | Endpoint security | `Depends(api_key_auth)` on all FastAPI routes |
| **app.py** | Router mounting | `app.include_router(router)` in suite-api |
| **Redis Queue** | Horizontal scaling | org_id-scoped keys via `/api/v1/queue` |
| **TrustGraph** | Knowledge graph | Event bus integration (97% pending — roadmap) |

---

## 5. Data Flow

```
HTTP Request (X-API-Key header)
        │
        ▼
FastAPI Router ─── Depends(api_key_auth) ──► 401 if invalid
        │
        ▼ Pydantic model validation
Engine Layer
        │  org_id = request.query_params["org_id"]
        │  with self._lock:
        │      cursor.execute("... WHERE org_id = ?", (org_id,))
        ▼
SQLite Database (WAL mode · per-domain .db file)
        │
        ▼
JSON Response ──► Client
```

**Scaling path**: Redis pub/sub → horizontal workers → PostgreSQL migration via SQLAlchemy.
**Knowledge graph**: TrustGraph event bus wires domain events to GraphRAG knowledge cores (roadmap item).

---

## 6. Referenced Documentation

- `CLAUDE.md` — Beast Mode v6 CTO Operating Manual
- `docs/ALDECI_REARCHITECTURE_v2.md` — Platform architecture source of truth
- `suite-api/apps/api/` — Router definitions and app.py mounts
- Rationale: _SSE (Server-Sent Events) streaming endpoints.  Provides real-time streaming for:_  
- Rationale: _Stream pipeline run progress as SSE events._  
- Rationale: _Stream EventBus events in real-time via SSE._  


---

## 7. Acceptance Criteria

- [ ] Expose Server-Sent Event streams for pipeline progress via stream_pipeline_progress()
- [ ] Stream real-time security events to dashboard clients via stream_events()
- [ ] Expose Security Domain Module (Community 126) via authenticated FastAPI endpoints with org_id isolation
- [ ] All endpoints require `api_key_auth` dependency injection
- [ ] SQLite WAL mode enabled with `PRAGMA journal_mode=WAL`
- [ ] `threading.RLock()` wraps all write operations
- [ ] `org_id` isolation enforced on all DB queries
- [ ] Beast Mode test suite passes with zero regressions
- [ ] Provide streaming_health() liveness endpoint for SSE infrastructure

---

## 8. Effort Estimate

| Dimension | Value |
|-----------|-------|
| T-shirt size | **XS** |
| Calendar effort | **0.5-1 day** |
| Graph nodes | 10 |
| Source files | 1 |
| Engine files | 0 |
| Router files | 1 |
| Test files | 0 |
| UI dashboard files | 0 |
| Inter-community deps | 1 communities |

**Complexity drivers**:
- Focused single-domain schema with standard ALDECI patterns
- Requires cross-community coordination with C0

---

## 9. Status

| Field | Value |
|-------|-------|
| **Implementation** | `PARTIAL (engine/router only)` |
| **Tests** | `MISSING` |
| **Router** | `WIRED — 1 file(s)` |
| **UI Dashboard** | `PENDING` |
| **Beast Mode Wave** | Waves 6-41 (see CLAUDE.md DONE sections) |
| **Next Action** | `Implement engine + router + tests following ALDECI patterns` |

---

*Auto-generated by Beast Mode v6 PRD Generator · graphify-out/graph.json · 10 nodes · Community 126/878*
