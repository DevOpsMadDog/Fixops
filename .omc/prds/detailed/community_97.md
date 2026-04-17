# PRD: Community 97 — Access Governance

> **Status**: `IMPLEMENTED`
> **Size**: L — 100 graph nodes · 3 source files
> **Effort Estimate**: 5-8 days
> **Community ID**: 97 of 878 total communities
> **Generated**: 2026-04-16 · Beast Mode v6 Autonomous Build

---

## 1. Master Goal Mapping


1. **Enforce separation of duties with ALL-match validation**
2. **Auto-grant entitlements from role assignments**
3. **Track expiry windows for access grants (exclude past-expired)**

**Platform Fit**: ALDECI ASPM + CTEM + CSPM — self-hosted, AI-native security intelligence platform
**Personas Served**: CISO · Security Engineer · SOC Analyst · Compliance Officer · DevSecOps Engineer
**ALDECI Principle**: Each engine = isolated SQLite domain + FastAPI router + pytest suite + React dashboard

---

## 2. Architecture Diagram

```mermaid
graph TD
    C97["Access Governance"]
    access_governance_97["access_governance_rout"] --> C97
    access_governance_97["access_governance_engi"] --> C97
    test_access_govern97["test_access_governance"] --> C97
    C97 --> DC0["Community 0\n(36 edges)"]
    C97 --> DC10["Community 10\n(6 edges)"]
    C97 --> DC1["Community 1\n(1 edges)"]
    C97 --> DC11["Community 11\n(1 edges)"]
```

### Layer Breakdown

| Layer | Files | Responsibility |
|-------|-------|----------------|
| **Engine** | access_governance_engine.py, test_access_governance_engine.py | Business logic · SQLite persistence · RLock threading · org_id scoping |
| **Router** | access_governance_router.py | FastAPI endpoints · Pydantic validation · api_key_auth injection |
| **Tests** | test_access_governance_engine.py | pytest lifecycle coverage · org isolation tests · edge case validation |
| **UI** | Pending | React 19 dashboard · Tailwind v4 · live API wiring |

---

## 3. Code Proof (file:line + key constructs)


**Engine** — `suite-core/core/access_governance_engine.py`:
```python
# Key constructs: engine(), TestGrantEntitlement, .test_basic_grant()
class Engine:
    def __init__(self, db_path, org_id):
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
    # All writes: with self._lock: cursor.execute(..., (org_id, ...))
```

**Router** — `suite-api/apps/api/access_governance_router.py`:
```python
router = APIRouter(prefix="/api/v1/access-governance", tags=["Access Governance"])
@router.get("/", dependencies=[Depends(api_key_auth)])
async def list_items(org_id: str = Query(...)):
    return engine.list_items(org_id)
```

**Tests** — `tests/test_access_governance_engine.py`:
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


### Key Graph Nodes (100 total in community)

| # | Label | Source File |
|---|-------|-------------|
| 1 | `test_access_governance_engine.py` | `suite-api/apps/api/access_governance_router.py` |
| 2 | `engine()` | `suite-core/core/access_governance_engine.py` |
| 3 | `TestGrantEntitlement` | `tests/test_access_governance_engine.py` |
| 4 | `.test_basic_grant()` | `N/A` |
| 5 | `.test_all_resource_types()` | `N/A` |
| 6 | `.test_all_access_levels()` | `N/A` |
| 7 | `.test_invalid_resource_type_raises()` | `N/A` |
| 8 | `.test_invalid_access_level_raises()` | `N/A` |
| 9 | `.test_with_expires_at()` | `N/A` |
| 10 | `.test_org_isolation()` | `N/A` |


### All Source Files (3)

- `suite-api/apps/api/access_governance_router.py`
- `suite-core/core/access_governance_engine.py`
- `tests/test_access_governance_engine.py`

---

## 4. Inter-Dependencies

### Cross-Community Edge Counts

- **Community 0**: 36 shared edges
- **Community 10**: 6 shared edges
- **Community 1**: 1 shared edges
- **Community 11**: 1 shared edges
- **Community 25**: 1 shared edges

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
- `suite-core/core/` — Engine implementations
- `suite-api/apps/api/` — Router definitions and app.py mounts
- `tests/` — pytest test suite (10s timeout)
- Rationale: _Tests for AccessGovernanceEngine — 35+ tests._  
- Rationale: _Access Governance Engine — ALDECI.  Identity Governance and Administration (IGA)_  
- Rationale: _SQLite WAL-backed Access Governance (IGA) engine.      Thread-safe via RLock. Mu_  


---

## 7. Acceptance Criteria

- [ ] Enforce separation of duties with ALL-match validation
- [ ] Auto-grant entitlements from role assignments
- [ ] Track expiry windows for access grants (exclude past-expired)
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
| Graph nodes | 100 |
| Source files | 3 |
| Engine files | 2 |
| Router files | 1 |
| Test files | 1 |
| UI dashboard files | 0 |
| Inter-community deps | 5 communities |

**Complexity drivers**:
- Multi-table SQLite schema with WAL, RLock threading, and org_id isolation
- Requires cross-community coordination with C0, C10, C1

---

## 9. Status

| Field | Value |
|-------|-------|
| **Implementation** | `IMPLEMENTED` |
| **Tests** | `PRESENT — 1 file(s)` |
| **Router** | `WIRED — 1 file(s)` |
| **UI Dashboard** | `PENDING` |
| **Beast Mode Wave** | Waves 6-41 (see CLAUDE.md DONE sections) |
| **Next Action** | `Verify test coverage completeness and router auth guards` |

---

*Auto-generated by Beast Mode v6 PRD Generator · graphify-out/graph.json · 100 nodes · Community 97/878*
