# PRD: Community 113 — Frontend UI Components

> **Status**: `IDENTIFIED`
> **Size**: S — 16 graph nodes · 2 source files
> **Effort Estimate**: 1-3 days
> **Community ID**: 113 of 878 total communities
> **Generated**: 2026-04-16 · Beast Mode v6 Autonomous Build

---

## 1. Master Goal Mapping


1. **Build React 19 security dashboard pages**
2. **Wire pages to live backend APIs**
3. **Implement responsive Tailwind v4 layouts**

**Platform Fit**: ALDECI ASPM + CTEM + CSPM — self-hosted, AI-native security intelligence platform
**Personas Served**: CISO · Security Engineer · SOC Analyst · Compliance Officer · DevSecOps Engineer
**ALDECI Principle**: Each engine = isolated SQLite domain + FastAPI router + pytest suite + React dashboard

---

## 2. Architecture Diagram

```mermaid
graph TD
    C113["Frontend UI Components"]
    RiskRegister_tsx113["RiskRegister.tsx"] --> C113
    RiskRegister_tsx113["RiskRegister.tsx"] --> C113
    C113 --> DC1["Community 1\n(2 edges)"]
```

### Layer Breakdown

| Layer | Files | Responsibility |
|-------|-------|----------------|
| **Engine** | N/A | Business logic · SQLite persistence · RLock threading · org_id scoping |
| **Router** | N/A | FastAPI endpoints · Pydantic validation · api_key_auth injection |
| **Tests** | N/A | pytest lifecycle coverage · org isolation tests · edge case validation |
| **UI** | RiskRegister.tsx, RiskRegister.tsx | React 19 dashboard · Tailwind v4 · live API wiring |

---

## 3. Code Proof (file:line + key constructs)

> Source files identified in graph — see All Source Files below for implementation locations.

### Key Graph Nodes (16 total in community)

| # | Label | Source File |
|---|-------|-------------|
| 1 | `RiskRegister.tsx` | `suite-ui/aldeci-ui-new/src/pages/RiskRegister.tsx` |
| 2 | `apiFetch()` | `suite-ui/aldeci-ui-new/src/pages/mission-control/RiskRegister.tsx` |
| 3 | `scoreColor()` | `N/A` |
| 4 | `scoreBg()` | `N/A` |
| 5 | `statusBadge()` | `N/A` |
| 6 | `categoryBadge()` | `N/A` |
| 7 | `matrixCellColor()` | `N/A` |
| 8 | `fetchRisks()` | `N/A` |
| 9 | `RiskRegister.tsx` | `N/A` |
| 10 | `generateTrendData()` | `N/A` |


### All Source Files (2)

- `suite-ui/aldeci-ui-new/src/pages/RiskRegister.tsx`
- `suite-ui/aldeci-ui-new/src/pages/mission-control/RiskRegister.tsx`

---

## 4. Inter-Dependencies

### Cross-Community Edge Counts

- **Community 1**: 2 shared edges

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

- [ ] Build React 19 security dashboard pages
- [ ] Wire pages to live backend APIs
- [ ] Implement responsive Tailwind v4 layouts
- [ ] All endpoints require `api_key_auth` dependency injection
- [ ] SQLite WAL mode enabled with `PRAGMA journal_mode=WAL`
- [ ] `threading.RLock()` wraps all write operations
- [ ] `org_id` isolation enforced on all DB queries
- [ ] Beast Mode test suite passes with zero regressions
- [ ] No bare `except:` clauses — all exceptions typed

---

## 8. Effort Estimate

| Dimension | Value |
|-----------|-------|
| T-shirt size | **S** |
| Calendar effort | **1-3 days** |
| Graph nodes | 16 |
| Source files | 2 |
| Engine files | 0 |
| Router files | 0 |
| Test files | 0 |
| UI dashboard files | 2 |
| Inter-community deps | 1 communities |

**Complexity drivers**:
- Focused single-domain schema with standard ALDECI patterns
- Requires cross-community coordination with C1

---

## 9. Status

| Field | Value |
|-------|-------|
| **Implementation** | `IDENTIFIED` |
| **Tests** | `MISSING` |
| **Router** | `PENDING` |
| **UI Dashboard** | `PRESENT — 2 file(s)` |
| **Beast Mode Wave** | Waves 6-41 (see CLAUDE.md DONE sections) |
| **Next Action** | `Implement engine + router + tests following ALDECI patterns` |

---

*Auto-generated by Beast Mode v6 PRD Generator · graphify-out/graph.json · 16 nodes · Community 113/878*
