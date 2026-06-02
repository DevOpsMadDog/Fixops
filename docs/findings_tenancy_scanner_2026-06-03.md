# FINDING — Tenancy lint scanner is inaccurate; true V1 debt is ~948, not 0

**Date:** 2026-06-03
**Severity:** HIGH (affects the SCIF multi-tenancy posture claim)
**Status:** RECORDED for founder decision — NOT auto-fixed (founder-blocked: org-precedence; redefines a security milestone)

## Summary

`scripts/tenancy_lint.py` (SPEC-007) gates multi-tenancy by counting "V1"
violations — endpoints that let a caller fall back to the `"default"` tenant.
Git history shows this was driven to **"allowlist 0"** (wave 16, `2ec67ee2`),
i.e. the milestone claim is "zero tenancy violations".

That claim is **based on a gap-ridden scanner**. The current regex-based V1
check has BOTH a large false-negative gap AND false positives:

### False negatives (the serious part)
The V1 regex only matches the **keyword** form:
```
org_id ... Query( ... default = "default" )
```
It does **NOT** match the far more common **positional** form:
```python
org_id: str = Query("default")
```
An AST-based scan (function-parameter defaults only) finds **948 V1
violations across 185 files** — of which the old regex catches only **2**.
~946 real `org_id` "default" endpoint/function parameters are invisible to the
gate today.

### False positives
Of the 100 the old regex *does* report, an AST classification shows **98 are
Pydantic model FIELDS** (`org_id: str = "default"` as a class attribute), which
are NOT endpoint parameters and not the V1 tenancy risk. Only **2** are real
function parameters (a deliberate `except ImportError` fallback in
`deduplication_router.py:20`).

| Form | Old regex | AST (function params only) |
|------|-----------|----------------------------|
| `Query("default")` positional | ❌ missed | ✅ 540+ |
| `Query(default="default")` keyword | ✅ | ✅ 2 |
| bare `org_id: str = "default"` (function param) | ✅ | ✅ |
| `org_id: str = "default"` (Pydantic model field) | ❌ false positive (98) | ✅ excluded |
| **Total real V1 (function params)** | **2 of 100 (rest FP)** | **~948** |

## Why this is a real risk
`org_id: str = Query("default")` takes the tenant id from the **query string**
with a `"default"` fallback. Unless every downstream engine independently
validates org against the authenticated context, a caller can pass
`?org_id=<other-tenant>` (cross-tenant read) or omit it (operate on the
"default" tenant). The canonical safe pattern is `org_id = Depends(get_org_id)`
(tenant derived from auth, not caller-supplied).

## Ready fix (NOT applied — needs founder approval)
1. **Scanner correctness** — replace the V1 regex with AST detection: walk
   `FunctionDef`/`AsyncFunctionDef` args for `org_id` whose default is a bare
   `"default"` or `Query/Path/Header/Cookie/Form(...)` resolving to `"default"`.
   This removes the 98 model-field false positives and catches the 946 missed
   positional-`Query("default")` violations. (Implementation was prototyped and
   verified this session, then reverted to avoid unilaterally redefining the
   gate.)
2. **Tenancy wave 17** — migrate the ~948 `org_id = Query("default")` endpoint
   params to `Depends(get_org_id)` (the wave-12–16 pattern), per router, with
   per-route verification. This is **founder-blocked (org-precedence)** + large
   (185 files, auth blast radius) — needs a dedicated, supervised wave.
3. Until (2) is done, the honest interim is `--generate-allowlist` to FREEZE the
   948 as a visible debt register (gate guards against NEW violations) — but
   that re-labels "tenancy 0" as "tenancy 948 frozen", a posture decision for
   the founder.

## Recommendation
Adopt the AST scanner (1) so the gate stops fabricating "clean", then schedule
wave 17 (2). Do NOT keep shipping the "tenancy 0" claim on the current scanner.
