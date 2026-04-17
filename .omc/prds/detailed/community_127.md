# PRD: Community 127 — GNU Internationalization (libgnuintl) — bash dependency

> **Status**: `IDENTIFIED`
> **Size**: XS — 10 graph nodes · 1 source files
> **Effort Estimate**: 0.5-1 day
> **Community ID**: 127 of 878 total communities
> **Generated**: 2026-04-16 · Beast Mode v6 Autonomous Build

---

## 1. Master Goal Mapping

1. **Provide gettext()/dgettext()/dcgettext() i18n primitives for bash-5.1 build**
2. **Support locale-aware string formatting in shell environment**
3. **Part of vendored bash-5.1 source — no ALDECI-specific changes needed**

**Platform Fit**: ALDECI ASPM + CTEM + CSPM — self-hosted, AI-native security intelligence platform
**Personas Served**: CISO · Security Engineer · SOC Analyst · Compliance Officer · DevSecOps Engineer
**ALDECI Principle**: Each engine = isolated SQLite domain + FastAPI router + pytest suite + React dashboard

---

## 2. Architecture Diagram

```mermaid
graph TD
    C127["Security Domain Module (Comm"]
    libgnuintl_h127["libgnuintl.h"] --> C127
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

### Key Graph Nodes (10 total in community)

| # | Label | Source File |
|---|-------|-------------|
| 1 | `libgnuintl.h` | `bash-5.1/lib/intl/libgnuintl.h` |
| 2 | `gettext()` | `N/A` |
| 3 | `dgettext()` | `N/A` |
| 4 | `dcgettext()` | `N/A` |
| 5 | `ngettext()` | `N/A` |
| 6 | `dngettext()` | `N/A` |
| 7 | `dcngettext()` | `N/A` |
| 8 | `textdomain()` | `N/A` |
| 9 | `bindtextdomain()` | `N/A` |
| 10 | `bind_textdomain_codeset()` | `N/A` |


### All Source Files (1)

- `bash-5.1/lib/intl/libgnuintl.h`

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


---

## 7. Acceptance Criteria

- [ ] Provide gettext()/dgettext()/dcgettext() i18n primitives for bash-5.1 build
- [ ] Support locale-aware string formatting in shell environment
- [ ] Expose Security Domain Module (Community 127) via authenticated FastAPI endpoints with org_id isolation
- [ ] All endpoints require `api_key_auth` dependency injection
- [ ] SQLite WAL mode enabled with `PRAGMA journal_mode=WAL`
- [ ] `threading.RLock()` wraps all write operations
- [ ] `org_id` isolation enforced on all DB queries
- [ ] Beast Mode test suite passes with zero regressions
- [ ] Part of vendored bash-5.1 source — no ALDECI-specific changes needed

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
| UI dashboard files | 0 |
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
| **UI Dashboard** | `PENDING` |
| **Beast Mode Wave** | Waves 6-41 (see CLAUDE.md DONE sections) |
| **Next Action** | `Implement engine + router + tests following ALDECI patterns` |

---

*Auto-generated by Beast Mode v6 PRD Generator · graphify-out/graph.json · 10 nodes · Community 127/878*
