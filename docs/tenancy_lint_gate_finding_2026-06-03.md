# SPEC-007 Tenancy-Lint Gate — Broken Baseline Finding (2026-06-03)

## What
`tests/test_tenancy_lint.py` FAILS (verified alone, 1.27s — not test-pollution):
- `test_allowlist_has_entries` — `specs/tenancy_allowlist.txt` has 0 entries (header only).
- `test_no_new_violations_beyond_allowlist` — scanner finds **100 V1 violations** (`org_id: str = "default"`
  param-defaults) across **99 suite-api routers + 1 suite-core**, none in the (empty) allowlist → all read as "new".

## Is it an active cross-tenant leak? NO (verified)
`tests/test_multi_tenant_isolation.py` passes **19/19 in isolation** — including FindingsV2 cross-tenant
id-lookup→404, org-scoped lists, admin-users isolation. The `="default"` is only the *unscoped fallback*;
when a real org is supplied (JWT/header/query) scoping holds. So V1 is **defense-in-depth hygiene debt**, not a
live leak. (The 61 batch ERRORs seen in the 16-file tenancy slice were TestClient-pollution — each file passes alone.)

## Why this is FOUNDER-GATED (not auto-fixed)
1. The allowlist header states: *"This list may only SHRINK. Never add new entries manually."* Auto-running
   `--generate-allowlist` to freeze 100 would violate that policy and could MASK a regression.
2. The underlying pattern (`org_id` defaulting to `"default"`) is **org-precedence** — explicitly founder-blocked.
3. Freeze-as-accepted-debt vs fix-to-`Depends(get_org_id)` is a deliberate founder decision.

## Founder decision needed
- **Option A (freeze):** `python scripts/tenancy_lint.py --generate-allowlist` — accepts the 100 as frozen debt,
  restores the gate to catch *future* new violations. Fast; the documented workflow; debt burned down over time.
- **Option B (fix):** convert the 100 `org_id: str = "default"` params to `Depends(get_org_id)` (org-precedence
  work) — larger, behaviour-sensitive (changes unscoped-call behaviour), needs org-precedence sign-off first.

Recommendation: A now (restore the gate so no NEW leaks slip in), then B incrementally as the org-precedence
epic lands. Both are founder calls. NO code change made — recorded only.
