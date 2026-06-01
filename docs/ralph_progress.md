# RALPH LOOP — Customer-Ready (SCIF $100K) persistence tracker

**Completion promise:** loop runs until every story below is IMPLEMENTED+VERIFIED and the SCIF
pre-mortem's disqualifying/major failures are closed. Each story = a spec through the loop
(architect → role-debate → senior-dev build → tester verify → commit). No stopping, no asking.

## Stories (priority order) — status
| # | Spec / story | Priority | Status |
|---|---|---|---|
| 1 | SPEC-001 TrustGraph correlation bridge | moat | ✅ VERIFIED |
| 2 | SPEC-005 air-gap enforced-by-default (+debate fixes) | P0 | ✅ VERIFIED |
| 3 | SPEC-006 honest compliance (+debate round 2) | P0 | ✅ VERIFIED |
| 4 | SPEC-009 reproducible build / lockfile / dependabot | P0 | ✅ VERIFIED |
| 5 | SPEC-002 local Nuclei pentest connector (real exploitability) | P1 | ✅ VERIFIED |
| 6 | **SPEC-003 local Qwen council (distill + AirGapLLMProvider)** | P1 | 🔄 IN PROGRESS |
| 7 | SPEC-005b auto-populate TrustGraph + attack-path from scans | P1 | ⏳ TODO |
| 8 | SPEC-007 systemic tenancy (TenantScopedEngine + ContextVar + CI lint) | P1 | ⏳ TODO |
| 9 | SPEC-004 multi-language reachability (tree-sitter TS/Java/Go) | P2 | ⏳ TODO |
| 10 | SPEC-008 HA / Litestream replication | P1 | ⏳ TODO |
| 11 | starlette 1.0 + torch CVE bump (own verified pass) | P1 | ⏳ TODO |
| 12 | SPEC-010 dead-router purge + SQLite migration registry | P2 | ⏳ TODO |
| 13 | SPEC-006b FIPS-validated crypto + at-rest encryption + immutable audit + PIV-CAC | P2 | ⏳ TODO (long) |

## Loop log
- 2026-06-01: stories 1-4 done. Starting story 5 (SPEC-002 Nuclei).
- 2026-06-01: story 5 (SPEC-002 Nuclei) VERIFIED — real connector, honest 503, no random. Starting story 6 (SPEC-003 local council).
