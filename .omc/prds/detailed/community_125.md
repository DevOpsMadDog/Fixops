# PRD: Community 125 — Frontend UI Components

> **Status**: `IDENTIFIED`
> **Size**: XS — 10 graph nodes · 1 source files
> **Effort Estimate**: 0.5-1 day
> **Community ID**: 125 of 878 total communities
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
    C125["Frontend UI Components"]
    OnboardingWizard_t125["OnboardingWizard.tsx"] --> C125
    C125 --> DC1["Community 1\n(1 edges)"]
```

### Layer Breakdown

| Layer | Files | Responsibility |
|-------|-------|----------------|
| **Engine** | N/A | Business logic · SQLite persistence · RLock threading · org_id scoping |
| **Router** | N/A | FastAPI endpoints · Pydantic validation · api_key_auth injection |
| **Tests** | N/A | pytest lifecycle coverage · org isolation tests · edge case validation |
| **UI** | OnboardingWizard.tsx | React 19 dashboard · Tailwind v4 · live API wiring |

---

## 3. Code Proof (file:line + key constructs)

> Source files identified in graph — see All Source Files below for implementation locations.

### Key Graph Nodes (10 total in community)

| # | Label | Source File |
|---|-------|-------------|
| 1 | `OnboardingWizard.tsx` | `suite-ui/aldeci-ui-new/src/pages/onboarding/OnboardingWizard.tsx` |
| 2 | `handleRunScan()` | `N/A` |
| 3 | `toggleScanner()` | `N/A` |
| 4 | `handleAppChange()` | `N/A` |
| 5 | `handlePrefsChange()` | `N/A` |
| 6 | `canProceed()` | `N/A` |
| 7 | `handleNext()` | `N/A` |
| 8 | `handleBack()` | `N/A` |
| 9 | `handleSkip()` | `N/A` |
| 10 | `handleComplete()` | `N/A` |


### All Source Files (1)

- `suite-ui/aldeci-ui-new/src/pages/onboarding/OnboardingWizard.tsx`

---

## 4. Inter-Dependencies

### Cross-Community Edge Counts

- **Community 1**: 1 shared edges

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
| T-shirt size | **XS** |
| Calendar effort | **0.5-1 day** |
| Graph nodes | 10 |
| Source files | 1 |
| Engine files | 0 |
| Router files | 0 |
| Test files | 0 |
| UI dashboard files | 1 |
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
| **UI Dashboard** | `PRESENT — 1 file(s)` |
| **Beast Mode Wave** | Waves 6-41 (see CLAUDE.md DONE sections) |
| **Next Action** | `Implement engine + router + tests following ALDECI patterns` |

---

*Auto-generated by Beast Mode v6 PRD Generator · graphify-out/graph.json · 10 nodes · Community 125/878*
