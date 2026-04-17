# PRD: Community 119 — File Usage Inventory Generator

> **Status**: `IDENTIFIED`
> **Size**: XS — 12 graph nodes · 1 source files
> **Effort Estimate**: 0.5-1 day
> **Community ID**: 119 of 878 total communities
> **Generated**: 2026-04-16 · Beast Mode v6 Autonomous Build

---

## 1. Master Goal Mapping

1. **Scan codebase and generate a structured file-usage inventory**
2. **Apply Rule.matches() pattern matching against source files**
3. **Output InventoryEntry records for dependency and dead-code analysis**

**Platform Fit**: ALDECI ASPM + CTEM + CSPM — self-hosted, AI-native security intelligence platform
**Personas Served**: CISO · Security Engineer · SOC Analyst · Compliance Officer · DevSecOps Engineer
**ALDECI Principle**: Each engine = isolated SQLite domain + FastAPI router + pytest suite + React dashboard

---

## 2. Architecture Diagram

```mermaid
graph TD
    C119["Security Domain Module (Comm"]
    generate_file_usag119["generate_file_usage_in"] --> C119
    C119 --> DC0["Community 0\n(6 edges)"]
    C119 --> DC1["Community 1\n(2 edges)"]
    C119 --> DC4["Community 4\n(1 edges)"]
```

### Layer Breakdown

| Layer | Files | Responsibility |
|-------|-------|----------------|
| **Engine** | N/A | Business logic · SQLite persistence · RLock threading · org_id scoping |
| **Router** | N/A | FastAPI endpoints · Pydantic validation · api_key_auth injection |
| **Tests** | N/A | pytest lifecycle coverage · org isolation tests · edge case validation |
| **UI** | Pending | React 19 dashboard · Tailwind v4 · live API wiring |

---

## 3. Code Proof (file:line + key constructs)

> Source files identified in graph — see All Source Files below for implementation locations.

### Key Graph Nodes (12 total in community)

| # | Label | Source File |
|---|-------|-------------|
| 1 | `generate_file_usage_inventory.py` | `scripts/generate_file_usage_inventory.py` |
| 2 | `Rule` | `N/A` |
| 3 | `.matches()` | `N/A` |
| 4 | `InventoryEntry` | `N/A` |
| 5 | `git_tracked_files()` | `N/A` |
| 6 | `count_lines()` | `N/A` |
| 7 | `classify()` | `N/A` |
| 8 | `write_summary()` | `N/A` |
| 9 | `write_totals()` | `N/A` |
| 10 | `write_report()` | `N/A` |


### All Source Files (1)

- `scripts/generate_file_usage_inventory.py`

---

## 4. Inter-Dependencies

### Cross-Community Edge Counts

- **Community 0**: 6 shared edges
- **Community 1**: 2 shared edges
- **Community 4**: 1 shared edges

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
- Rationale: _Generate file usage inventory with heuristic classifications.  This module scans_  


---

## 7. Acceptance Criteria

- [ ] Scan codebase and generate a structured file-usage inventory
- [ ] Apply Rule.matches() pattern matching against source files
- [ ] Expose Security Domain Module (Community 119) via authenticated FastAPI endpoints with org_id isolation
- [ ] All endpoints require `api_key_auth` dependency injection
- [ ] SQLite WAL mode enabled with `PRAGMA journal_mode=WAL`
- [ ] `threading.RLock()` wraps all write operations
- [ ] `org_id` isolation enforced on all DB queries
- [ ] Beast Mode test suite passes with zero regressions
- [ ] Output InventoryEntry records for dependency and dead-code analysis

---

## 8. Effort Estimate

| Dimension | Value |
|-----------|-------|
| T-shirt size | **XS** |
| Calendar effort | **0.5-1 day** |
| Graph nodes | 12 |
| Source files | 1 |
| Engine files | 0 |
| Router files | 0 |
| Test files | 0 |
| UI dashboard files | 0 |
| Inter-community deps | 3 communities |

**Complexity drivers**:
- Focused single-domain schema with standard ALDECI patterns
- Requires cross-community coordination with C0, C1, C4

---

## 9. Status

| Field | Value |
|-------|-------|
| **Implementation** | `IDENTIFIED` |
| **Tests** | `MISSING` |
| **Router** | `PENDING` |
| **UI Dashboard** | `PENDING` |
| **Beast Mode Wave** | Waves 6-41 (see CLAUDE.md DONE sections) |
| **Next Action** | `Implement engine + router + tests following ALDECI patterns` |

---

*Auto-generated by Beast Mode v6 PRD Generator · graphify-out/graph.json · 12 nodes · Community 119/878*
