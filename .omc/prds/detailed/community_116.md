# PRD: Community 116 — Frontend API Hooks Library (api-hooks.ts)

> **Status**: `IDENTIFIED`
> **Size**: XS — 13 graph nodes · 1 source files
> **Effort Estimate**: 0.5-1 day
> **Community ID**: 116 of 878 total communities
> **Generated**: 2026-04-16 · Beast Mode v6 Autonomous Build

---

## 1. Master Goal Mapping

1. **Centralise useApiQuery() and useFindings() hooks for React dashboards**
2. **Implement isApiUnavailable() for graceful offline degradation**
3. **Provide typed wrappers over fetch for all ALDECI REST endpoints**

**Platform Fit**: ALDECI ASPM + CTEM + CSPM — self-hosted, AI-native security intelligence platform
**Personas Served**: CISO · Security Engineer · SOC Analyst · Compliance Officer · DevSecOps Engineer
**ALDECI Principle**: Each engine = isolated SQLite domain + FastAPI router + pytest suite + React dashboard

---

## 2. Architecture Diagram

```mermaid
graph TD
    C116["Security Domain Module (Comm"]
    api_hooks_ts116["api-hooks.ts"] --> C116
```

### Layer Breakdown

| Layer | Files | Responsibility |
|-------|-------|----------------|
| **Engine** | N/A | Business logic · SQLite persistence · RLock threading · org_id scoping |
| **Router** | N/A | FastAPI endpoints · Pydantic validation · api_key_auth injection |
| **Tests** | N/A | pytest lifecycle coverage · org isolation tests · edge case validation |
| **UI** | api-hooks.ts | React 19 dashboard · Tailwind v4 · live API wiring |

---

## 3. Code Proof (file:line + key constructs)

> Source files identified in graph — see All Source Files below for implementation locations.

### Key Graph Nodes (13 total in community)

| # | Label | Source File |
|---|-------|-------------|
| 1 | `api-hooks.ts` | `suite-ui/aldeci-ui-new/src/lib/api-hooks.ts` |
| 2 | `isApiUnavailable()` | `N/A` |
| 3 | `useApiQuery()` | `N/A` |
| 4 | `useFindings()` | `N/A` |
| 5 | `usePosture()` | `N/A` |
| 6 | `useCompliance()` | `N/A` |
| 7 | `useSLA()` | `N/A` |
| 8 | `useAttackSurface()` | `N/A` |
| 9 | `useIncidents()` | `N/A` |
| 10 | `useVendors()` | `N/A` |


### All Source Files (1)

- `suite-ui/aldeci-ui-new/src/lib/api-hooks.ts`

---

## 4. Inter-Dependencies

### Cross-Community Edge Counts

- No strong inter-community dependencies detected

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
- `suite-ui/aldeci-ui-new/src/pages/` — React 19 UI dashboards


---

## 7. Acceptance Criteria

- [ ] Centralise useApiQuery() and useFindings() hooks for React dashboards
- [ ] Implement isApiUnavailable() for graceful offline degradation
- [ ] Expose Security Domain Module (Community 116) via authenticated FastAPI endpoints with org_id isolation
- [ ] All endpoints require `api_key_auth` dependency injection
- [ ] SQLite WAL mode enabled with `PRAGMA journal_mode=WAL`
- [ ] `threading.RLock()` wraps all write operations
- [ ] `org_id` isolation enforced on all DB queries
- [ ] Beast Mode test suite passes with zero regressions
- [ ] Provide typed wrappers over fetch for all ALDECI REST endpoints

---

## 8. Effort Estimate

| Dimension | Value |
|-----------|-------|
| T-shirt size | **XS** |
| Calendar effort | **0.5-1 day** |
| Graph nodes | 13 |
| Source files | 1 |
| Engine files | 0 |
| Router files | 0 |
| Test files | 0 |
| UI dashboard files | 1 |
| Inter-community deps | 0 communities |

**Complexity drivers**:
- Focused single-domain schema with standard ALDECI patterns
- Self-contained — minimal cross-community dependencies

---

## 9. Status

| Field | Value |
|-------|-------|
| **Implementation** | `IDENTIFIED` |
| **Tests** | `MISSING` |
| **Router** | `PENDING` |
| **UI Dashboard** | `PRESENT — 1 file(s)` |
| **Beast Mode Wave** | Waves 6-41 (see CLAUDE.md DONE sections) |
| **Next Action** | `Implement engine + router + tests following ALDECI patterns` |

---

*Auto-generated by Beast Mode v6 PRD Generator · graphify-out/graph.json · 13 nodes · Community 116/878*
