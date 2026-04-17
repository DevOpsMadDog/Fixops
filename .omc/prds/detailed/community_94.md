# PRD: Community 94 — Test Suite

> **Status**: `PARTIAL (engine/router only)`
> **Size**: L — 114 graph nodes · 4 source files
> **Effort Estimate**: 5-8 days
> **Community ID**: 94 of 878 total communities
> **Generated**: 2026-04-16 · Beast Mode v6 Autonomous Build

---

## 1. Master Goal Mapping


1. **Maintain pytest test coverage for all engines**
2. **Enforce 10s timeout on all tests**
3. **Track test counts per Beast Mode wave**

**Platform Fit**: ALDECI ASPM + CTEM + CSPM — self-hosted, AI-native security intelligence platform
**Personas Served**: CISO · Security Engineer · SOC Analyst · Compliance Officer · DevSecOps Engineer
**ALDECI Principle**: Each engine = isolated SQLite domain + FastAPI router + pytest suite + React dashboard

---

## 2. Architecture Diagram

```mermaid
graph TD
    C94["Test Suite"]
    vuln_lifecycle_rou94["vuln_lifecycle_router."] --> C94
    vuln_lifecycle_py94["vuln_lifecycle.py"] --> C94
    vuln_lifecycle_tra94["vuln_lifecycle_tracker"] --> C94
    test_vuln_lifecycl94["test_vuln_lifecycle.py"] --> C94
    C94 --> DC0["Community 0\n(36 edges)"]
    C94 --> DC1["Community 1\n(9 edges)"]
    C94 --> DC16["Community 16\n(8 edges)"]
    C94 --> DC10["Community 10\n(6 edges)"]
```

### Layer Breakdown

| Layer | Files | Responsibility |
|-------|-------|----------------|
| **Engine** | N/A | Business logic · SQLite persistence · RLock threading · org_id scoping |
| **Router** | vuln_lifecycle_router.py | FastAPI endpoints · Pydantic validation · api_key_auth injection |
| **Tests** | test_vuln_lifecycle.py | pytest lifecycle coverage · org isolation tests · edge case validation |
| **UI** | Pending | React 19 dashboard · Tailwind v4 · live API wiring |

---

## 3. Code Proof (file:line + key constructs)


**Router** — `suite-api/apps/api/vuln_lifecycle_router.py`:
```python
router = APIRouter(prefix="/api/v1/test-suite", tags=["Test Suite"])
@router.get("/", dependencies=[Depends(api_key_auth)])
async def list_items(org_id: str = Query(...)):
    return engine.list_items(org_id)
```

**Tests** — `tests/test_vuln_lifecycle.py`:
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


### Key Graph Nodes (114 total in community)

| # | Label | Source File |
|---|-------|-------------|
| 1 | `test_vuln_lifecycle.py` | `suite-api/apps/api/vuln_lifecycle_router.py` |
| 2 | `tracker()` | `suite-core/core/vuln_lifecycle.py` |
| 3 | `fid()` | `suite-core/core/vuln_lifecycle_tracker.py` |
| 4 | `org_id()` | `tests/test_vuln_lifecycle.py` |
| 5 | `_full_cycle()` | `N/A` |
| 6 | `TestLifecycleStage` | `N/A` |
| 7 | `.test_all_stages_present()` | `N/A` |
| 8 | `.test_str_returns_value()` | `N/A` |
| 9 | `TestLifecycleEvent` | `N/A` |
| 10 | `.test_defaults_populated()` | `N/A` |


### All Source Files (4)

- `suite-api/apps/api/vuln_lifecycle_router.py`
- `suite-core/core/vuln_lifecycle.py`
- `suite-core/core/vuln_lifecycle_tracker.py`
- `tests/test_vuln_lifecycle.py`

---

## 4. Inter-Dependencies

### Cross-Community Edge Counts

- **Community 0**: 36 shared edges
- **Community 1**: 9 shared edges
- **Community 16**: 8 shared edges
- **Community 10**: 6 shared edges
- **Community 13**: 6 shared edges
- **Community 2**: 3 shared edges

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
- `tests/` — pytest test suite (10s timeout)
- Rationale: _Tests for Vulnerability Lifecycle Tracker — Phase 11 addition.  Covers: - Lifecy_  
- Rationale: _VulnLifecycle backed by a temp SQLite database._  
- Rationale: _Push a finding through the complete happy path._  


---

## 7. Acceptance Criteria

- [ ] Maintain pytest test coverage for all engines
- [ ] Enforce 10s timeout on all tests
- [ ] Track test counts per Beast Mode wave
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
| T-shirt size | **L** |
| Calendar effort | **5-8 days** |
| Graph nodes | 114 |
| Source files | 4 |
| Engine files | 0 |
| Router files | 1 |
| Test files | 1 |
| UI dashboard files | 0 |
| Inter-community deps | 8 communities |

**Complexity drivers**:
- Multi-table SQLite schema with WAL, RLock threading, and org_id isolation
- Requires cross-community coordination with C0, C1, C16

---

## 9. Status

| Field | Value |
|-------|-------|
| **Implementation** | `PARTIAL (engine/router only)` |
| **Tests** | `PRESENT — 1 file(s)` |
| **Router** | `WIRED — 1 file(s)` |
| **UI Dashboard** | `PENDING` |
| **Beast Mode Wave** | Waves 6-41 (see CLAUDE.md DONE sections) |
| **Next Action** | `Implement engine + router + tests following ALDECI patterns` |

---

*Auto-generated by Beast Mode v6 PRD Generator · graphify-out/graph.json · 114 nodes · Community 94/878*
