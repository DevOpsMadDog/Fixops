# T3 evidence/crypto/compliance slice — finding (2026-06-03, Multica #9085)

## Result
**1078 passed, 8 failed, 14 skipped** across the evidence / crypto / compliance / audit-chain lane.
The SCIF-critical engines (crypto, key-manager, hsm, evidence-chain, compliance-engine,
evidence-collector, gap-engine) are **GREEN**.

## The 8 failures — STALE TESTS, not code/security bugs (verified)
`test_audit_api.py` (7) + `test_evidence_router_unit.py` (1) fail **alone** (not pollution), but the
root cause is an outdated test contract:
- `test_audit_api` assumes `POST /api/v1/audit/compliance/frameworks` (full CRUD). That route is
  **GET-only by design** (`audit_router`) → POST returns **405**, so the test's create step no-ops →
  empty lists (`assert 0>=1`) + `404` on `/{id}/status|gaps|report`.
- Framework **creation** actually lives on other routers: `POST /api/v1/grc/frameworks`,
  `POST /api/v1/compliance-seed/frameworks`, `POST /api/v1/compliance/{framework}/...`. The audit
  router exposes **read-only** audit/compliance views (GET 200, honest-empty when unseeded).

So this is the CLAUDE.md T3 "legacy test with outdated assumptions" case — NOT a runtime bug,
data-integrity issue, or security gap.

## Recommended (founder/triage — NOT auto-done)
- Either update `test_audit_api.py` to the read-only contract (seed via grc/compliance-seed, then
  GET-assert), OR — if a CRUD audit-compliance API is intended — implement POST on audit_router
  (product decision; would add API surface). Do not silently delete the test.
- This also touches the `/api/v1/audit/` + `/api/v1/compliance/` shadow-collision zone (#9080) —
  resolving consolidation should include confirming the canonical create/read owners here.

## Update — the 8th failure confirmed (test_evidence_router_unit)
`test_evidence_router_unit.py` alone: **48 passed, 1 failed**. The 1 failure
(`TestEvidenceBundles::test_bundles_from_default_app`) asserts `data["total"] > 0` on an unseeded
default app, which honestly returns 0 — a **seed-dependent stale assertion** (expects pre-existing
bundles without creating one), same class as the audit-API stale tests. The evidence router itself
works (48/49). So all 8 slice failures = stale/seed-dependent test assumptions, NOT code/security
bugs. Triage = update the tests to seed-then-assert (or mark seed-dependent); founder/triage call.
