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
| 6 | SPEC-003 local council (real inference + honest labels) | P1 | ✅ VERIFIED |
| 7 | SPEC-005b auto-populate graph (blast_radius != 0) | P1 | ✅ VERIFIED |
| 8 | SPEC-007 systemic tenancy (ContextVar fix + CI lint gate) | P1 | ✅ VERIFIED |
| 9 | SPEC-004 multi-language reachability (Python/TS/JS/Java/Go + auto-run) | P2 | ✅ VERIFIED |
| 10 | **SPEC-008 HA / Litestream replication** | P1 | 🔄 NEXT |
| 11 | starlette 1.0 + torch CVE bump (own verified pass) | P1 | ⏳ TODO |
| 12 | SPEC-010 dead-router purge + SQLite migration registry | P2 | ⏳ TODO |
| 13 | SPEC-006b FIPS-validated crypto + at-rest encryption + immutable audit + PIV-CAC | P2 | ⏳ TODO (long) |

## Loop log
- 2026-06-01: stories 1-4 done. Starting story 5 (SPEC-002 Nuclei).
- 2026-06-01: story 5 (SPEC-002 Nuclei) VERIFIED — real connector, honest 503, no random. Starting story 6 (SPEC-003 local council).
- 2026-06-01: story 6 (SPEC-003 local council) VERIFIED — real local inference + honest is_real_inference labels. Next: story 8 (SPEC-007 systemic tenancy — highest-value spillage fix).
- 2026-06-01: story 8 (SPEC-007 tenancy) VERIFIED — threading.local→ContextVar asyncio fix + lint gate (1730 frozen). 5 stories done this session (001/002/003/005/006/007/009). Loop continues: next SPEC-005b → 004 → 008 → starlette bump → 010 → 006b.
- 2026-06-01: story 7 (SPEC-005b graph-populate) VERIFIED — blast_radius>0 from real scans, org-scoped, idempotent. Moat now real (SPEC-001+005b). Next: SPEC-004 reachability.
- 2026-06-01: story 9 (SPEC-004 reachability) VERIFIED — TS/JS/Java/Go all work + auto-run + coverage metric. 9 specs done. Next: SPEC-008 HA replication → starlette/torch bump → SPEC-010 → SPEC-006b.
