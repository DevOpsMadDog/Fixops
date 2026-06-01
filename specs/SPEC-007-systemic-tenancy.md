# SPEC-007 — Systemic Tenancy (stop the whack-a-mole)

- **Status**: IMPLEMENTED
- **Owner family**: Platform / Tenancy
- **Engines**: `core/tenant_isolation.py` (TenantContext), `apps/api/org_middleware.py` (get_org_id), CI
- **Depends on**: PM-3
- **Last updated**: 2026-06-01

## 1. Intent
PM-3: tenancy is opt-in, not systemic — `TenantContext` uses `threading.local` (BROKEN under asyncio:
coroutines share a thread, so Request B can overwrite Request A's org), 3007 routes use
`Query(default="default")`, 7 shadow `get_org_id` definitions. In a SCIF one cross-tenant leak =
spillage = contract over. This spec makes tenancy SAFE-BY-CONSTRUCTION for the asyncio bug + adds a
CI gate that BLOCKS new leaks — so the next router/engine can't silently reintroduce one. (The mass
refactor of 548 engines is tracked separately; this closes the structural hole + stops regression.)

## 2. Scope
1. Fix `TenantContext`: `threading.local` → `contextvars.ContextVar` (asyncio-correct isolation).
2. CI lint gate (`tests/test_tenancy_lint.py` or a scripts/ check wired into CI) that FAILS on:
   - `Query(... default="default")` (or `="default"`) used for an org_id parameter in any router,
   - importing `get_org_id` from anywhere except the canonical `apps.api.org_middleware` / `apps.api.dependencies`,
   - new shadow `def get_org_id` definitions outside the canonical modules.
   Existing violations captured in an allowlist (so CI is green now) that can ONLY shrink.
3. Document the canonical pattern in specs/README + a short CONTRIBUTING note.
Out of scope: rewriting the 548 engines (separate effort) — but the lint makes the debt visible + frozen.

## 3. Contracts
- `TenantContext` get/set is per-async-task correct (concurrent coroutines never see each other's org).
- CI lint emits a count of violations + an allowlist file; build fails if a NEW violation appears.

## 4. Functional requirements
- **REQ-007-01**: `TenantContext` uses ContextVar; a concurrency test proves two interleaved async tasks keep separate org_id (the threading.local bug is gone).
- **REQ-007-02**: A lint check enumerates `Query(default="default")` org params + non-canonical get_org_id imports/defs, compares against an allowlist, and FAILS if the set grows.
- **REQ-007-03**: The allowlist is generated from the CURRENT violations (so CI is green today) and documented as debt that may only shrink.
- **REQ-007-04**: Canonical pattern documented: org_id ONLY via `Depends(get_org_id)` from the canonical module; never a query default.

## 5. Non-functional
- No behaviour change for correct callers; the ContextVar swap is transparent.

## 6. Acceptance criteria (executable)
- **AC-007-01**: `tests/test_tenant_context_asyncio.py` — two interleaved `asyncio` tasks set different orgs; each reads back its OWN org (fails on threading.local, passes on ContextVar).
- **AC-007-02**: `tests/test_tenancy_lint.py` runs the scanner; with the allowlist it PASSES; a synthetic new `Query(default="default")` makes it FAIL (prove the gate bites).
- **AC-007-03**: the allowlist file exists with the current violation count recorded.
- **AC-007-04**: boot create_app() succeeds; no regression in tests/test_multi_tenant_isolation.py + test_cross_tenant_isolation_wave2.py.

## 7. Debate log (internal role-debate)
| Date | Mode | Verdict |
|------|------|---------|
| (after build) | Red-Team | can the lint be trivially bypassed? does ContextVar leak across task boundaries? |

## 8. Implementation notes

Implemented 2026-06-01.

### REQ-007-01 — TenantContext: threading.local → ContextVar

**File**: `suite-core/core/tenant_isolation.py`

Removed `import threading` and `threading.local`. Added `from contextvars import ContextVar, Token`
and a module-level `_tenant_org_id_var: ContextVar[Optional[str]] = ContextVar("tenant_org_id", default=None)`.

`TenantContext.set()` now returns the `Token` (so `OrgIdMiddleware` can call `_tenant_org_id_var.reset(token)`
for clean scoped teardown). `TenantContext.get()` and `TenantContext.clear()` delegate to the ContextVar.
Public API (set/get/clear) is unchanged — all callers work without modification.

The `OrgIdMiddleware` in `suite-api/apps/api/org_middleware.py` already used its own `ContextVar`
for request-level isolation; it also calls `TenantContext.set/clear` to sync the core module.
That sync path is now also ContextVar-backed and therefore asyncio-correct end-to-end.

### REQ-007-02/03 — Lint scanner + allowlist

**Files**:
- `scripts/tenancy_lint.py` — standalone scanner (also importable by tests)
- `specs/tenancy_allowlist.txt` — 1730 frozen violations (baseline 2026-06-01)

Three violation categories:
- **V1** (1724): `org_id` parameter using `Query(default="default")` or bare `str = "default"`
- **V2** (1): `from X import get_org_id` where X is not `apps.api.org_middleware` or `apps.api.dependencies`
- **V3** (5): `def get_org_id` outside the canonical modules

The gate PASSES if the current violation set is a subset of the allowlist. Any new violation (set grows)
causes exit code 1. The allowlist may only shrink as violations are fixed.

Shadow defs found (V3): `analytics_routes.py:35`, `exposure_case_router.py:42` (x2),
`mcp_routes.py:63`, `trustgraph_routes.py:144`.

### REQ-007-04 — Canonical pattern doc

Appended to `specs/README.md`: correct `Depends(get_org_id)` pattern, anti-patterns for all three
violation categories, explanation of why ContextVar vs threading.local, and CI gate usage.

### Acceptance criteria results

| AC | Test | Result |
|----|------|--------|
| AC-007-01 | `tests/test_tenant_context_asyncio.py` — 7 tests | 7/7 PASS |
| AC-007-02 | `tests/test_tenancy_lint.py` — 11 tests (gate + synthetic bites) | 11/11 PASS |
| AC-007-03 | `specs/tenancy_allowlist.txt` exists, 1730 entries | EXISTS |
| AC-007-04 | `create_app()` → 8301 routes, no boot error; `test_multi_tenant_isolation.py` + `test_cross_tenant_isolation_wave2.py` | 45 passed, 16 skipped (engine-not-configured) |

### Violation count at implementation time

| Category | Count |
|----------|-------|
| V1 — Query(default="default") org_id params | 1724 |
| V2 — non-canonical get_org_id imports | 1 |
| V3 — shadow def get_org_id | 5 |
| **Total frozen in allowlist** | **1730** |

Mass remediation of the 1724 V1 violations is tracked separately (out of scope for this spec per §2).
