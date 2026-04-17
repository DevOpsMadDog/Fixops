# PRD: Community 105 — API Gateway / Router Registry

> **Status**: `PARTIAL (tests only)`
> **Size**: M — 40 graph nodes · 1 source files
> **Effort Estimate**: 3-5 days
> **Community ID**: 105 of 878 total communities
> **Generated**: 2026-04-16 · Beast Mode v6 Autonomous Build

---

## 1. Master Goal Mapping


1. **Wire all API routers into FastAPI application**
2. **Manage route prefix namespacing**
3. **Inject auth dependency on all endpoints**

**Platform Fit**: ALDECI ASPM + CTEM + CSPM — self-hosted, AI-native security intelligence platform
**Personas Served**: CISO · Security Engineer · SOC Analyst · Compliance Officer · DevSecOps Engineer
**ALDECI Principle**: Each engine = isolated SQLite domain + FastAPI router + pytest suite + React dashboard

---

## 2. Architecture Diagram

```mermaid
graph TD
    C105["API Gateway / Router Registr"]
    test_pr1_official_105["test_pr1_official_ui.p"] --> C105
    C105 --> DC0["Community 0\n(10 edges)"]
```

### Layer Breakdown

| Layer | Files | Responsibility |
|-------|-------|----------------|
| **Engine** | N/A | Business logic · SQLite persistence · RLock threading · org_id scoping |
| **Router** | N/A | FastAPI endpoints · Pydantic validation · api_key_auth injection |
| **Tests** | test_pr1_official_ui.py | pytest lifecycle coverage · org isolation tests · edge case validation |
| **UI** | Pending | React 19 dashboard · Tailwind v4 · live API wiring |

---

## 3. Code Proof (file:line + key constructs)


**Tests** — `tests/test_pr1_official_ui.py`:
```python
# 1 test file(s) — pytest, @pytest.mark.timeout(10)
@pytest.fixture
def engine(tmp_path):
    return Engine(str(tmp_path / "test.db"), "test_org")
def test_create_and_retrieve(engine):
    item = engine.create({"name": "test"}, "test_org")
    assert item["id"]
    assert engine.get(item["id"], "test_org")
```


### Key Graph Nodes (40 total in community)

| # | Label | Source File |
|---|-------|-------------|
| 1 | `test_pr1_official_ui.py` | `tests/test_pr1_official_ui.py` |
| 2 | `TestUIAldeciIsOfficialUI` | `N/A` |
| 3 | `.test_ui_aldeci_directory_exists()` | `N/A` |
| 4 | `.test_ui_aldeci_has_package_json()` | `N/A` |
| 5 | `.test_ui_aldeci_has_vite_config()` | `N/A` |
| 6 | `.test_ui_aldeci_has_src_directory()` | `N/A` |
| 7 | `.test_ui_aldeci_has_env_example()` | `N/A` |
| 8 | `.test_ui_aldeci_env_example_has_vite_api_url(` | `N/A` |
| 9 | `.test_ui_aldeci_has_screen_api_mapping()` | `N/A` |
| 10 | `TestLegacyMFEsDeprecated` | `N/A` |


### All Source Files (1)

- `tests/test_pr1_official_ui.py`

---

## 4. Inter-Dependencies

### Cross-Community Edge Counts

- **Community 0**: 10 shared edges

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
- `tests/` — pytest test suite (10s timeout)
- Rationale: _PR1 Tests: Validate suite-ui/aldeci is the official UI and web/ MFEs are depreca_  
- Rationale: _Verify suite-ui/aldeci is the official frontend._  
- Rationale: _suite-ui/aldeci directory must exist._  


---

## 7. Acceptance Criteria

- [ ] Wire all API routers into FastAPI application
- [ ] Manage route prefix namespacing
- [ ] Inject auth dependency on all endpoints
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
| T-shirt size | **M** |
| Calendar effort | **3-5 days** |
| Graph nodes | 40 |
| Source files | 1 |
| Engine files | 0 |
| Router files | 0 |
| Test files | 1 |
| UI dashboard files | 0 |
| Inter-community deps | 1 communities |

**Complexity drivers**:
- Multi-table SQLite schema with WAL, RLock threading, and org_id isolation
- Requires cross-community coordination with C0

---

## 9. Status

| Field | Value |
|-------|-------|
| **Implementation** | `PARTIAL (tests only)` |
| **Tests** | `PRESENT — 1 file(s)` |
| **Router** | `PENDING` |
| **UI Dashboard** | `PENDING` |
| **Beast Mode Wave** | Waves 6-41 (see CLAUDE.md DONE sections) |
| **Next Action** | `Implement engine + router + tests following ALDECI patterns` |

---

*Auto-generated by Beast Mode v6 PRD Generator · graphify-out/graph.json · 40 nodes · Community 105/878*
