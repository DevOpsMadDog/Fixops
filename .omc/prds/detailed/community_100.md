# PRD: Community 100 — SBOM / Software Bill of Materials

> **Status**: `PARTIAL (engine/router only)`
> **Size**: M — 67 graph nodes · 5 source files
> **Effort Estimate**: 3-5 days
> **Community ID**: 100 of 878 total communities
> **Generated**: 2026-04-16 · Beast Mode v6 Autonomous Build

---

## 1. Master Goal Mapping


1. **Generate CycloneDX 1.4 and SPDX 2.3 SBOMs**
2. **Track all software components and licenses**
3. **Enable supply chain vulnerability correlation**

**Platform Fit**: ALDECI ASPM + CTEM + CSPM — self-hosted, AI-native security intelligence platform
**Personas Served**: CISO · Security Engineer · SOC Analyst · Compliance Officer · DevSecOps Engineer
**ALDECI Principle**: Each engine = isolated SQLite domain + FastAPI router + pytest suite + React dashboard

---

## 2. Architecture Diagram

```mermaid
graph TD
    C100["SBOM / Software Bill of Mate"]
    error_audit_router100["error_audit_router.py"] --> C100
    semgrep_router_py100["semgrep_router.py"] --> C100
    error_handling_aud100["error_handling_auditor"] --> C100
    test_error_handlin100["test_error_handling_au"] --> C100
    test_sbom_py100["test_sbom.py"] --> C100
    C100 --> DC0["Community 0\n(49 edges)"]
    C100 --> DC1["Community 1\n(13 edges)"]
    C100 --> DC19["Community 19\n(4 edges)"]
    C100 --> DC20["Community 20\n(2 edges)"]
```

### Layer Breakdown

| Layer | Files | Responsibility |
|-------|-------|----------------|
| **Engine** | N/A | Business logic · SQLite persistence · RLock threading · org_id scoping |
| **Router** | error_audit_router.py, semgrep_router.py | FastAPI endpoints · Pydantic validation · api_key_auth injection |
| **Tests** | test_error_handling_auditor.py, test_sbom.py | pytest lifecycle coverage · org isolation tests · edge case validation |
| **UI** | Pending | React 19 dashboard · Tailwind v4 · live API wiring |

---

## 3. Code Proof (file:line + key constructs)


**Router** — `suite-api/apps/api/error_audit_router.py`:
```python
router = APIRouter(prefix="/api/v1/sbom---software-bill-of-materials", tags=["SBOM / Software Bill of Materials"])
@router.get("/", dependencies=[Depends(api_key_auth)])
async def list_items(org_id: str = Query(...)):
    return engine.list_items(org_id)
```

**Tests** — `tests/test_error_handling_auditor.py`:
```python
# 2 test file(s) — pytest, @pytest.mark.timeout(10)
@pytest.fixture
def engine(tmp_path):
    return Engine(str(tmp_path / "test.db"), "test_org")
def test_create_and_retrieve(engine):
    item = engine.create({"name": "test"}, "test_org")
    assert item["id"]
    assert engine.get(item["id"], "test_org")
```


### Key Graph Nodes (67 total in community)

| # | Label | Source File |
|---|-------|-------------|
| 1 | `test_error_handling_auditor.py` | `suite-api/apps/api/error_audit_router.py` |
| 2 | `_write()` | `suite-api/apps/api/semgrep_router.py` |
| 3 | `TestScanFileBareExcept` | `suite-core/core/error_handling_auditor.py` |
| 4 | `.test_bare_except_detected_as_critical()` | `tests/test_error_handling_auditor.py` |
| 5 | `.test_bare_except_snippet_captured()` | `tests/test_sbom.py` |
| 6 | `.test_multiple_bare_excepts_all_detected()` | `N/A` |
| 7 | `TestScanFileExceptExceptionPass` | `N/A` |
| 8 | `.test_except_exception_pass_detected_as_high(` | `N/A` |
| 9 | `.test_except_exception_with_body_not_flagged_` | `N/A` |
| 10 | `TestScanFilePrintException` | `N/A` |


### All Source Files (5)

- `suite-api/apps/api/error_audit_router.py`
- `suite-api/apps/api/semgrep_router.py`
- `suite-core/core/error_handling_auditor.py`
- `tests/test_error_handling_auditor.py`
- `tests/test_sbom.py`

---

## 4. Inter-Dependencies

### Cross-Community Edge Counts

- **Community 0**: 49 shared edges
- **Community 1**: 13 shared edges
- **Community 19**: 4 shared edges
- **Community 20**: 2 shared edges
- **Community 38**: 2 shared edges
- **Community 5**: 1 shared edges

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
- Rationale: _Tests for ErrorHandlingAuditor — 15+ tests covering detection, categorization, r_  
- Rationale: _Error Handling Auditor — ALDECI static analysis tool.  Scans the codebase for po_  
- Rationale: _True when the handler body contains only ``pass`` (and possibly docstring)._  


---

## 7. Acceptance Criteria

- [ ] Generate CycloneDX 1.4 and SPDX 2.3 SBOMs
- [ ] Track all software components and licenses
- [ ] Enable supply chain vulnerability correlation
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
| Graph nodes | 67 |
| Source files | 5 |
| Engine files | 0 |
| Router files | 2 |
| Test files | 2 |
| UI dashboard files | 0 |
| Inter-community deps | 8 communities |

**Complexity drivers**:
- Multi-table SQLite schema with WAL, RLock threading, and org_id isolation
- Requires cross-community coordination with C0, C1, C19

---

## 9. Status

| Field | Value |
|-------|-------|
| **Implementation** | `PARTIAL (engine/router only)` |
| **Tests** | `PRESENT — 2 file(s)` |
| **Router** | `WIRED — 2 file(s)` |
| **UI Dashboard** | `PENDING` |
| **Beast Mode Wave** | Waves 6-41 (see CLAUDE.md DONE sections) |
| **Next Action** | `Implement engine + router + tests following ALDECI patterns` |

---

*Auto-generated by Beast Mode v6 PRD Generator · graphify-out/graph.json · 67 nodes · Community 100/878*
