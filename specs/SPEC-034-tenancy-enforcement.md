# SPEC-034 — Tenancy Enforcement (org_id from auth context, not client param)

- **Status**: IN PROGRESS — scope quantified 2026-06-22; migration batched (see §5)
- **Owner family**: Security / Multi-tenancy / Customer-Readiness
- **Closes**: R1/R2 in `docs/architecture/system-overview.md`; the dominant cross-tenant gap
- **Last updated**: 2026-06-22

## 1. Intent
A SCIF deployment is multi-tenant-isolated. `org_id` must come from the **authenticated
context** (`apps.api.dependencies.get_org_id` → contextvar/JWT > query > header > default),
never from a raw client-supplied parameter. A router that declares
`org_id: str = Query(...)` reads the client's value directly, **bypassing the auth context**
→ any authenticated caller can read/write another tenant's data.

## 2. Scope (measured 2026-06-22 — the real number, not the audit sample)
- **277 router files** under `suite-api/apps/api/` + `suite-core/api/` contain
  `org_id ... = Query(...)`.
- **~1,900 occurrences** total. Dominant patterns:
  - `org_id: str = Query("X")` (~519) and `Query("X", description=...)` (~394) — defaulted
  - `org_id: str = Query(..., description=...)` (~341) — **REQUIRED** (see caveat)
  - `Optional[str] = Query(None/default=None)` (~60) — optional → all-orgs aggregate (worst)
  - `Query(..., min_length=.., max_length=..)` (~40) — required + input validation

## 3. The fix (per occurrence)
`org_id: <type> = Query(<...>)` → `org_id: str = Depends(get_org_id)` (+ ensure
`from apps.api.dependencies import get_org_id` and `Depends` are imported).
**Backward-compatible**: `get_org_id` still reads `?org_id=` as a fallback, so existing
clients/tests sending the query param keep working — but the contextvar/JWT now wins.

## 4. Why NOT a blanket codemod (the caveats that make this a migration)
1. **Required → defaulted**: `Query(...)` means org_id was *required* (422 if absent).
   `Depends(get_org_id)` always resolves (defaults to "default"). Endpoints/tests that
   asserted a 422-without-org_id will change behavior — must be reviewed per batch.
2. **False matches**: `org_id), save: bool = Query(...)` (org_id is a *path* param) and
   `org_id_param`/`org_id_q` (notably **`get_org_id`'s own internal param** in
   dependencies.py / org_middleware.py — MUST NOT be touched). Anchor on `\borg_id\s*:`.
3. **Multiline `Query(\n …)`** calls need AST-aware handling, not a line regex.
4. **Lost validation**: `min_length/max_length` on org_id is dropped — acceptable
   (get_org_id returns a resolved value), but note it.

## 5. Migration plan (batched, each batch fully verified)
Per batch (~10–20 routers): convert, ensure imports, then verify
`test_engine_router_import_sweep` + `create_app` boot + the batch routers' own tests +
Beast smoke; commit + push. Prioritise customer-facing first (evidence, grc, compliance,
siem, threat-intel, cloud, vuln). Track required→default behavior changes per batch.

## 6. Acceptance criteria
- **AC-034-01**: a CI gate (extend `tests/test_no_fail_open_auth.py` sibling) asserts no
  router declares `org_id ... = Query(` (only `Depends(get_org_id)`), allowlisting any
  legitimate cross-org/admin endpoints.
- **AC-034-02**: every data route resolves org_id from auth context; a fresh org sees 0.
- **AC-034-03**: the org_id `Query` count trends to 0 (from ~1,900) across batches.

## 7. Proof (first batch, 2026-06-22)
See the commit converting the first proof router(s); pattern + verification demonstrated.
Founder note: this is a large but backward-compatible migration — the single biggest
cross-tenant hardening in the codebase.
