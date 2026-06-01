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
| 10 | SPEC-008 HA / Litestream replication + restore | P1 | ✅ VERIFIED |
| 11 | starlette CVE — DEFERRED (needs httpx2 migration, 561 files); torch dispositioned | P1 | 🟡 DOCUMENTED/BLOCKED |
| 11b | starlette PYSEC-2026-161 CLOSED (starlette 1.2.1 + fastapi 0.136.3 + httpx2) | P1 | ✅ VERIFIED |
| 12 | SPEC-010 maintainability (inventory+gate+schema-registry; only 5 dead, archived) | P2 | ✅ VERIFIED |
| 13 | SPEC-006b crypto hardening (key-at-rest + immutable audit + honest posture) | P2 | ✅ VERIFIED |
| 14 | FIPS-CMVP cert + PIV-CAC hardware | P2 | 🔒 FOUNDER-BLOCKED |

## Loop log
- 2026-06-01: stories 1-4 done. Starting story 5 (SPEC-002 Nuclei).
- 2026-06-01: story 5 (SPEC-002 Nuclei) VERIFIED — real connector, honest 503, no random. Starting story 6 (SPEC-003 local council).
- 2026-06-01: story 6 (SPEC-003 local council) VERIFIED — real local inference + honest is_real_inference labels. Next: story 8 (SPEC-007 systemic tenancy — highest-value spillage fix).
- 2026-06-01: story 8 (SPEC-007 tenancy) VERIFIED — threading.local→ContextVar asyncio fix + lint gate (1730 frozen). 5 stories done this session (001/002/003/005/006/007/009). Loop continues: next SPEC-005b → 004 → 008 → starlette bump → 010 → 006b.
- 2026-06-01: story 7 (SPEC-005b graph-populate) VERIFIED — blast_radius>0 from real scans, org-scoped, idempotent. Moat now real (SPEC-001+005b). Next: SPEC-004 reachability.
- 2026-06-01: story 9 (SPEC-004 reachability) VERIFIED — TS/JS/Java/Go all work + auto-run + coverage metric. 9 specs done. Next: SPEC-008 HA replication → starlette/torch bump → SPEC-010 → SPEC-006b.
- 2026-06-01: story 10 (SPEC-008 HA) VERIFIED — litestream config 19 DBs + honest backup_verify + restore runbook + boot durability warning. 10 specs done. Next: starlette/torch CVE bump (careful, own pass).
- 2026-06-01: story 11 — starlette 1.x bump REVERTED (needs project-wide httpx2 test migration; boot was fine but Beast collection hard-errors on httpx-testclient deprecation). Documented close-path (story 11b). torch = training-only, not in SCIF runtime, no upstream fix. requirements unchanged. Next: SPEC-010.
- 2026-06-01: story 12 (SPEC-010) VERIFIED — PM-5 '686 dead' was STALE; real=5 unmounted (archived), 875/880 mounted. Inventory tool + CI gate + schema_registry. boot 8301 unchanged. Next: SPEC-006b (achievable FIPS increments).
- 2026-06-01: story 13 (SPEC-006b) VERIFIED — key passphrase-encryption, append-only audit triggers, HMAC key separation, honest crypto_posture (fips/piv=false). FIPS-CMVP+PIV-CAC=founder-blocked. BUILDABLE BACKLOG EXHAUSTED. Remaining: founder-blocked (push, FIPS cert, PIV hardware, GPU training, httpx2 migration). Writing handoff + stopping loop.
- 2026-06-01: story 11b DONE — starlette 1.2.1/fastapi 0.136.3/httpx2 2.2.0, 756/756 Beast green, boot 8301 both modes. DISQUALIFYING starlette CVE CLOSED. All buildable + the one risky CVE now done.
- 2026-06-01: GROUP-E DEEP-VERIFY DONE — onboarded 14 real GitHub repos via real scanners → 1236 real findings (45 crit/337 high) for a SCIF tenant. Read each line + exercised: micro-pentest/reachability/9 prediction engines/design→runtime/12-step brain pipeline ALL REAL on real data. Built CVSS cross-tool reconciliation (was missing); activated real ML-DSA PQC evidence (dilithium-py); fixed safe TrustGraph emit + syft SBOM + honest code-to-cloud map. 42 commits.
- 2026-06-02: SPEC-016 (SCIF stack-fit) COMPLETE — 6 commits. Method: Understand-Anything assessed (redundant w/ graphify, used fresh graph), code-truth audit reframed "build connectors" → "wire existing real connectors + close loop". SCIF-Accreditor + Red-Team debate → 6 hardened REQs (07-12). Built+verified LIVE: inc1 WIZ /ingest→brain + assert_egress_allowed SSRF/air-gap guard + classification marking; inc2 Prisma router+/ingest; inc3 closed-loop /decide→Jira/ServiceNow/Splunk + ML-DSA-signed append-only evidence + dedup (caught REAL council-factory unbound-call bug that silently killed the AI path); REQ-016-13 Black Duck SCA connector+normalizer; inc4 Confluence design-context import. Snyk/Veracode confirmed already-real. 18/18 SPEC-016 tests + 756/756 Beast green. Commits 359b05e6..aa136168. NEXT buildables: GraphRAG→council wiring, full-pipeline-on-ingest, Postgres migration, tenancy-debt drawdown. Recurring self-kick cron armed (15-min).
- 2026-06-02: SPEC-017 (full-pipeline-on-ingest) IMPLEMENTED — config-gated (FIXOPS_PIPELINE_ON_INGEST, default OFF), non-blocking daemon dispatch, debate-hardened: air-gap hard-check (never egress in enforced+no-local-LLM), BoundedSemaphore (drop-not-queue, thread-DoS guard), per-org token-bucket (LLM-cost-DoS guard), durable pipeline_runs.db + stats (observability). Wired scanner-ingest upload+webhook + wiz/prisma/blackduck. 7 helper tests + WIZ HTTP dispatch. 26/26 spec016+017 + 756/756 Beast green. Commit c4d6bb2e. NEXT: GraphRAG→council wiring, Postgres migration, tenancy-debt drawdown.
- 2026-06-02: GraphRAG→council — CODE-TRUTH: ALREADY DONE, not a build gap. Verified by reading llm_council.py: convene() runs _enrich_with_trustgraph (BrainCorrelator multi-hop blast_radius depth-2 + correlate_cve/finding over Store B, org-scoped) + _augment_with_similar_decisions (AgentDB MiniLM semantic top-5 past verdicts). _build_analysis_prompt RENDERS both as a "TrustGraph Enrichment" block + "Past similar council decisions" block into every stage-1/2/3 prompt. This IS GraphRAG (multi-hop graph retrieval + vector RAG, textualized into the LLM context). No redundant spec built (no-fabrication rule). NEXT: tenancy-debt drawdown.
- 2026-06-02: tenancy-debt drawdown waves 1+2 — allowlist 1726->1620 (-106 V1 cross-tenant default-org gaps closed across 8 routers: sbom, firewall_management, privacy_gdpr, scheduled_reports, ai_governance, mdm, vuln_intelligence, data_governance). Backward-compatible recipe (get_org_id honors ?org_id=/X-Org-ID/contextvar). Boot 8316, lint clean, Beast 755/756 (1 known load-flake). Commits e0aa082c + this. Recipe is mechanical+proven — remaining ~1620 scalable in further waves. Postgres migration = large infra, founder-visibility warranted (deferred). GraphRAG→council already done. Backlog now: continue tenancy waves; Postgres migration (founder infra decision).
- 2026-06-02: tenancy-debt wave 3 — allowlist 1620->1551 (-69 across 6 routers: container_registry_security, threat_landscape, supply_chain_intel, security_maturity, red_team_mgmt, mfa_management). Cumulative 1726->1551 (-175, 14 routers). 756/756 Beast, boot 8316, lint clean. Recipe proven across 3 waves.
- 2026-06-02: tenancy-debt wave 4 — allowlist 1551->1465 (-86 across 8 routers: vuln_prioritization, pentest_mgmt, iot_security, edr, digital_forensics, application_security, user_access_review, tprm_exchange). Enhanced recipe ensures Depends import too. Cumulative 1726->1465 (-261, 22 routers). 756/756 Beast, boot 8316, lint clean.
- 2026-06-02: tenancy-debt wave 5 — allowlist 1465->1368 (-97 across 10 routers: threat_actor, software_license_security, software_composition_analysis, security_scorecard_engine, security_questionnaire, security_health, security_chaos, risk_scenario, regulatory_tracker_engine, privileged_identity). Cumulative 1726->1368 (-358, 32 routers). 756/756 Beast, boot 8316, lint clean.
- 2026-06-02: tenancy-debt wave 6 — allowlist 1368->1228 (-140 across 14 routers). Cumulative 1726->1228 (-498, 46 routers, ~29%). 756/756 Beast, boot 8316, lint clean.
- 2026-06-02: tenancy-debt wave 7 — allowlist 1228->1101 (-127 across 14 routers). Cumulative 1726->1101 (-625, 60 routers, ~36%). 756/756 Beast, boot 8316, lint clean.
- 2026-06-02: tenancy-debt wave 8 — allowlist 1101->975 (-126 across 15 routers, broke under 1000). Cumulative 1726->975 (-751, 75 routers, ~44%). 756/756 Beast, boot 8316, lint clean.
- 2026-06-02: tenancy-debt wave 9 — allowlist 975->831 (-144 across 18 routers). Cumulative 1726->831 (-895, 93 routers, ~52% — past halfway). 756/756 Beast, boot 8316, lint clean.
- 2026-06-02: tenancy-debt wave 10 — allowlist 831->696 (-135 across 18 routers). Cumulative 1726->696 (-1030, 111 routers, ~60%). 756/756 Beast, boot 8316, lint clean.
- 2026-06-02: tenancy-debt wave 11 — allowlist 696->581 (-115 across 20 routers). Cumulative 1726->581 (-1145, 131 routers, ~66%). 756/756 Beast, boot 8316, lint clean.
- 2026-06-02: tenancy-debt wave 12 — allowlist 581->499 (-82 across 19 routers, under 500). Cumulative 1726->499 (-1227, 150 routers, ~71%). 756/756 Beast, boot 8316, lint clean.
- 2026-06-02: tenancy-debt wave 13 — allowlist 499->461 (-38 across 14 fully-clean routers; exhausts simple==total set). Cumulative 1726->461 (-1265, 164 routers, ~73%). 45 mixed-pattern files still hold simple Query(default) occurrences — next waves convert those per-occurrence (safe). 756/756 Beast, boot 8316, lint clean.
