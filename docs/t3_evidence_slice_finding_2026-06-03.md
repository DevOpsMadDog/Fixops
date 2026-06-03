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
