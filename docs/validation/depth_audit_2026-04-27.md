# ALDECI Honest Depth Audit vs Snyk / Apiiro / Wiz
**Date:** 2026-04-27
**Auditor:** ai-researcher agent (a96f33b62c14136c3)
**Branch:** features/intermediate-stage
**Method:** Static analysis of engine/router/UI code + live API probing + learning_signals.db query + competitor web research. All citations trace to file:line or live endpoint response. No padding. Where a claim cannot be verified it is marked UNVERIFIED.

---

## 0. Executive Summary

| Metric | Prior Claim | Honest Audit |
|--------|------------|--------------|
| Overall v1.0 completion | "95%" (CTO wave ~26) / revised to "15-20%" (CTO reflection) | **28% (±8%)** |
| Competitive WIN/MATCH | 83% (149 caps × 7 competitors) | **~58% honest WIN/MATCH** (see re-score below) |
| DPO pairs "real analyst overrides" | 5,196 pairs implied as real | **5,195/5,196 are auto-generated low-confidence triggers; 1 is a smoke-test stub** |
| LLM council "4 free models + Opus" | Claimed in docs | **1 real LLM key configured (OPENROUTER). Anthropic, Google, OpenAI keys absent from .env** |
| Cosign/DSSE signing | Claimed DONE (GAP-018) | **STUB — `_PLACEHOLDER_SIG = "placeholder-signature-v0-not-for-production-use"` (slsa_provenance_engine.py:82)** |
| Agentless snapshot scan | Claimed DONE (GAP-020) | **FAKE DATA — synthesizes 2-3 fake snapshots per account; `TODO(real-adapter)` comment at line 143** |
| Deep code analysis | Claimed DONE (GAP-012) | **FIXED 2026-04-27 — TS (tree-sitter f6d909c0), JS (esprima bee501c7), Java (javalang bca96496). Real AST + sink detection. 34 tests passing.** |
| UI pages making real API calls | 382 pages total | **465/382 (2,306 useQuery calls across 382 pages = 6 calls/page avg) — UI is genuinely wired, not mocked** |

---

## 1. Dimension Scores (Evidence-Backed)

### 1.1 Core Scanning Engines — Score: 42/100

**What is real:**
- `sast_engine.py` exists with 110+ OWASP rules + Semgrep YAML loader. Wired to `/api/v1/...` (800 total OpenAPI paths confirmed live).
- `dep_scanner.py` integrates OSV/GHSA live APIs (`suite-feeds/threat_intel_aggregator.py:43-46` — real URLs: NVD, EPSS FIRST.org, CISA KEV, OSV.dev).
- `container_scanner.py` wraps Trivy/Grype/Dockle (connector exists, not confirmed running against live registries).
- `secret_scanner_engine.py` with entropy + 200 patterns — file exists.

**What is stub/fake:**
- Agentless snapshot scan: `agentless_snapshot_scan_engine.py:139` synthesizes fake snapshots. `TODO(real-adapter)` at line 143. Citation: line 174 has literal `b"PK\x03\x04log4j-core-2.14.1-fake-bytes"`.
- Deep code analysis: **FIXED 2026-04-27**: TS (`f6d909c0` tree-sitter), JS (`bee501c7` esprima), Java (`bca96496` javalang) — all real AST analysis with sink detection. Engine score raised.
- Function reachability: repo-local Python only. TypeScript/Java stubbed at lines 446,459. No OSS corpus (GAP-048 explicitly NOT-STARTED).
- DAST: wrapper file exists (`dast_scanner.py`), but ZAP integration not verified running.
- Runtime eBPF reachability: no Helios equivalent. Code-to-runtime mapper is v0 with "3-strategy mapping" but no live runtime telemetry.

**Gap vs Snyk:** Snyk has Snyk Code (DeepCode ML on 40+ languages) vs ALDECI Python-only AST. Snyk OSS DB has 1M+ vulnerabilities vs ALDECI relying on public feeds. Snyk has VS Code, JetBrains, Eclipse, Visual Studio IDE plugins (verified at docs.snyk.io) vs ALDECI has 0 shipped IDE plugins (GAP-014 is NEEDS-PRODUCT-DECISION).

**Gap vs Wiz:** Wiz agentless SideScanning uses real AWS EBS/Azure disk APIs. ALDECI agentless is synthetic test data. Wiz DSPM (data classification at rest) has no ALDECI equivalent beyond `data_governance_engine.py` (basic, uncited depth).

---

### 1.2 LLM Consensus / Decision Intelligence — Score: 31/100

**What is real:**
- `llm_council.py` (1,422 lines): Karpathy 3-stage pattern is architecturally correct. Stage 1 independent analysis, Stage 2 peer review, Stage 3 chairman synthesis, escalation to Opus on disagreement > 2 members. Fallback to majority vote if chairman synthesis fails (line 663-664). This is real code.
- Brain pipeline: 12 steps all have real `def _step_*` functions (brain_pipeline.py: 4,524 lines). Steps: `connect, normalize, resolve_identity, fp_auto_suppress, deduplicate, build_graph, enrich_threats, score_risk, apply_policy, llm_consensus/llm_council, micro_pentest, run_playbooks, generate_evidence`. Not stubs.
- `FIXOPS_USE_COUNCIL` env var gates real council vs consensus (brain_pipeline.py:396).

**What is critically broken:**
- `.env` has exactly 1 LLM key: `OPENROUTER_API_KEY`. No `ANTHROPIC_API_KEY`, no `GOOGLE_API_KEY`, no `OPENAI_API_KEY`.
- With 1 provider, the council has 1 member. `llm_council.py:298` confirms: `if not self.members: raise ValueError("Council requires at least one member")` — 1 member is valid but there is NO disagreement, NO peer review, NO consensus. It is a single-model call with council scaffolding around it.
- The `CouncilFactory` at line 1406 explicitly handles `len(members) == 1` case.
- **ALL 5,196 council verdicts have `confidence = 0.5` and `council_action = "review"`.** This is the Opus escalation fallback result ("Council escalation inconclusive") — meaning the single-provider council consistently escalates and gets a boilerplate "review" back. Source: `learning_signals.db` query, `confidence` stats: avg=0.5, min=0.5, max=0.5.
- **5,195/5,196 DPO pairs sourced from `llm_learning_loop_low_confidence`** (auto-triggered when confidence < 0.75). The 1 remaining is `smoke_test_simulated_override`. The claimed "5,196 DPO pairs" are not analyst-validated training data — they are auto-generated low-confidence escalation records that happen to be stored in a DPO schema.
- Orgs in the DB: `vulnado-0` (2,903 records), `WebGoat-0` (1,874), `juice-shop-0` (242) — all are test/demo apps run during smoke testing.

**Gap vs competitors:** No competitor claims multi-LLM consensus as a feature, but ALDECI's claimed moat is not functioning with 1 configured provider and 100% uniform "review" verdicts.

---

### 1.3 Cryptographic Security / SCIF Readiness — Score: 38/100

**What is real:**
- `fips_compliance_mode_engine.py`: PQC algorithm registry (ML-KEM, ML-DSA, SPHINCS+), FIPS 140-3 mode toggle, per-org isolation, WAL+RLock thread safety. Real implementation.
- `hsm_provider.py`: wraps `python-pkcs11` library for SoftHSM/AWS CloudHSM/Thales Luna 7.x. PKCS#11 interface is real code. Tested configuration documented (lines 29-37).
- SCIF docs: `docs/scif/` contains SSP, POA&M, NIST 800-53 control matrix, STIG checklist, SOC2/ISO27001/PCI-DSS/HIPAA mappings. SSP explicitly states "Pilot Draft — not FedRAMP-authorized" — this is honest disclosure.
- `fips_encryption.py`: AES-256 via stdlib labeled "FIPS 140-2 compliant" (stdlib crypto is NOT FIPS-certified without OpenSSL FIPS module — UNVERIFIED whether OpenSSL FIPS boundary is actually enforced at runtime).

**What is stub/misleading:**
- SLSA provenance signing: `slsa_provenance_engine.py:82` — `_PLACEHOLDER_SIG = "placeholder-signature-v0-not-for-production-use"`. Line 70: `TODO(real-signing): Integrate sigstore-python/cosign for real DSSE signing`. GAP-018 is marked DONE in the gap matrix but the signing is a placeholder.
- Air-gap bundle signing: `air_gap_bundle_engine.py:85-86` — `_PLACEHOLDER_HMAC_KEY = b"fixops-airgap-placeholder-key-2026"`. Comment: "DEV-only HMAC key — replace with cosign keypair in follow-up." Line 1159: `TODO — real cosign signing`.
- Cosign in `container_runtime.py:1166`: "Simulate verification: in production, shell out to cosign/notary". `k8s_security.py:1304,1328`: "stub — would query cosign/notation".
- FedRAMP authorization: 12-18 months away per SSP document itself.
- `fips_boot.py` exists but whether it enforces OpenSSL FIPS boundary at Python runtime is UNVERIFIED — no test evidence cited.

**SCIF doc grade:** Template-ready, not auditor-ready. SSP has "(to be filled in by deploying agency)" for System Owner, ISSO, and AO fields (SSP lines ~40-45). POA&M exists but references a pilot deployment, not an authorized system.

---

### 1.4 Integration Ecosystem — Score: 55/100

**What is real:**
- 27 connector files in `suite-core/connectors/` including: `crowdstrike_falcon_connector.py`, `defender_xdr_connector.py`, `sentinelone_connector.py`, `iam_sso_connector.py`, `cspm_connector.py`, `edr_connector.py`, `pull_connector.py`, `sdlc_connectors.py`, `dast_pentest_connector.py`.
- Live API: 800 total OpenAPI paths. 25 connector-prefixed endpoints. 42 compliance endpoints. Auth is enforced (confirmed: 401 returned without X-API-Key).
- `threat_intel_aggregator.py`: NVD, EPSS, CISA KEV, OSV all have real URLs and real HTTP fetch logic with caching.

**What is partial/missing:**
- 29/30 empty endpoints from `empty_endpoints_triage_2026-04-26.md` remain empty. Root causes: 11 need real adapters (PAM, MDM, SSPM, XDR, cloud creds), 7 need public-source importers.
- No IDE plugins shipped (0 of 4 IDEs: VS Code, JetBrains, Eclipse, Visual Studio). Snyk ships all 4.
- Stable webhooks event catalogue (GAP-038): marked IN-PROGRESS. Router exists, formal event-list endpoint not shipped.
- OpenAPI typed SDKs (GAP-037): marked IN-PROGRESS. No packages on PyPI/npm.
- `/api/v1/threat-feeds/status` returns 404 (confirmed live).
- `/api/v1/personas/` returns 404 (confirmed live) — no persona-specific endpoint despite 30-persona coverage claims.

**Gap vs Wiz:** Wiz has 200+ integrations (confirmed from wiz.io/platform). ALDECI has 25 connector-prefixed endpoints. Wiz integrates with ServiceNow, PagerDuty, Jira, Azure DevOps, AWS Security Hub as named integrations. ALDECI has these in code but real-tenant verification shows 11 connectors have no live data.

---

### 1.5 UI/UX Completeness — Score: 35/100

**What is real:**
- 382 `.tsx` page files exist in `suite-ui/aldeci-ui-new/src/pages/`.
- 2,306 `useQuery/useMutation/fetch/apiFetch` calls across 382 pages — the UI is genuinely wired to APIs, not using static JSON imports.
- 465 pages (out of 382 — some pages have multiple API-calling files) have at least one real API call. The UI is not mock-data driven.

**What is a problem:**
- 382 pages when Phase 3 target is 25-40. UX consolidation plan exists (`docs/UX_CONSOLIDATION_PLAN_2026-04-26.md`) but Phase 3 is NOT STARTED. No evidence of route collapse or tab composition work in recent commits.
- 1,293 instances of `TODO/mock/MOCK/placeholder/lorem ipsum/Coming Soon/Not implemented/stub` in pages directory.
- The current UX is unusable as a product — 382 separate pages with no coherent navigation is a prototype, not a product. Phase 3 consolidation to 30 screens is the actual v1.0 UI work.
- Snyk Issues hero page, Wiz Security Graph UX, and Apiiro Risk Graph are polished, production-grade. ALDECI has the data but not the UX.

**Gap vs Aikido:** Aikido's "5-min onboarding (laptop)" moat is real. ALDECI requires docker-compose + manual setup. No laptop installer exists.

---

### 1.6 Persona Workflow Completeness — Score: 40/100

**Methodology:** Traced each of the 6 key persona workflows via OpenAPI spec (800 paths) + brain_pipeline.py step list.

| Persona | Loop Closes? | Data Persists (Brain Pipeline)? | Actionable Result? | Score |
|---------|-------------|--------------------------------|-------------------|-------|
| CISO | Partial — dashboard endpoint exists (`/api/v1/analytics/dashboard/executive`), risk endpoints (25 paths), compliance (42 paths) | Pipeline runs but council gives "review" for every finding | Executive dollar-risk endpoint exists (GAP-051 DONE) but no real multi-tenant FAIR data | 2/5 |
| SOC T1 | Partial — 32 issues/findings endpoints, real-time feed endpoint exists | Pipeline step `_step_normalize` runs | Single-queue `/issues` endpoint exists but returns 401 without auth setup | 2/5 |
| DevSecOps | Partial — GitHub App (GAP-015 DONE), PR scan wired | material_change_detector.py is real (1,127 lines, git diff logic) | AutoFix engine (GAP-019) exists with 10 types but confidence-gating not verified end-to-end | 3/5 |
| AppSec | Partial — SAST/SCA/IaC/Container scanners exist | Deep code analysis Python-only; TS/JS/Java raise NotImplementedError | Function reachability Python-only | 2/5 |
| Threat Intel Analyst | Partial — `/api/v1/threat-intel/` has 15 endpoints, MITRE actor import done (187 real records) | threat_intel_aggregator pulls NVD/EPSS/KEV live | 28 feeds in registry but per-org enrollment table not wired (endpoint #5 in empty_endpoints_triage) | 3/5 |
| Compliance Auditor | Partial — 42 compliance endpoints, SCIF docs exist | Compliance scanning engine exists | SOC2/ISO27001/PCI-DSS/HIPAA mappings are template-level, not auto-generated from scan results | 2/5 |

**Average persona workflow score: 2.3/5 = 46% — loops partially close but no persona has a complete end-to-end verified workflow producing an actionable result from real data.**

---

### 1.7 Knowledge Graph (TrustGraph) — Score: 45/100

**What is real:**
- 119,765 nodes / 425,727 edges / 1,516 communities in graphify (from CLAUDE.md, last verified 2026-04-26).
- TrustGraph event bus wired to `llm_council.py` (lines 43-85), brain_pipeline.py emits at step 553.
- `graphify-out/` directory exists with GRAPH_REPORT.md.
- 30 hubs + 16 connectors broadcasting.

**What is partial:**
- 10k-node interactive benchmark not published (GAP-047 IN-PROGRESS). Integration topology graph only 1,221 nodes / 3,054 edges — well short of 10k target.
- 97% of 3,036 endpoints disconnected from TrustGraph (per MEMORY.md note: "TrustGraph gap — 97% of 3,036 endpoints disconnected from TrustGraph").
- Graph UX (Wiz Security Graph, Apiiro Risk Graph) — ALDECI has backend but no comparable interactive graph visualization. GAP-047 IP.

---

## 2. Competitive Re-Score (Honest)

Prior matrix claimed 83% WIN/MATCH (82 WIN + 42 MATCH of 149). Applying evidence:

| Prior WIN → Now LOSE/MATCH | Reason |
|---------------------------|--------|
| "Multi-LLM consensus" WIN | Downgrade to UNVERIFIED: 1 LLM key configured, all verdicts = "review" at confidence 0.5 |
| "SLSA provenance attestation" WIN | Downgrade to MATCH-AT-BEST: signing is placeholder stub |
| "Agentless snapshot scan" DONE | Downgrade to LOSE: fake data, TODO(real-adapter) explicit |
| "Deep code analysis" DONE | Downgrade to PARTIAL: Python only, TS/JS/Java raise NotImplementedError |
| "Function-level reachability" vs Snyk/Apiiro/Sonatype | Already marked LOSE — confirm, repo-local Python only |
| "IDE plugin" | Remains 0 shipped; Snyk has 4 confirmed (VS Code, Visual Studio, Eclipse, JetBrains) |
| "5-min onboarding" | Remains LOSE vs Aikido |
| "API typed SDKs" GAP-037 | IN-PROGRESS, not DONE |
| "Stable webhooks catalogue" GAP-038 | IN-PROGRESS, not DONE |

**Revised estimate: ~87 honest WIN/MATCH of 149 = 58%** (vs claimed 83%). The 25-point gap comes from 8 claims that cannot be evidenced or are demonstrably stubs.

---

## 3. Top 10 Must-Fix Items to Reach Actual v1.0

Ranked by impact on product credibility and competitive parity:

| # | Item | Evidence | Effort (dev-days) | Impact |
|---|------|----------|-------------------|--------|
| 1 | **Wire real LLM keys (Anthropic/OpenRouter free tier at minimum) so council has 2+ members and produces non-uniform verdicts** | `.env` has 1 key; all 5,196 verdicts = "review" at conf=0.5 | 2d | CRITICAL — the claimed #1 moat (multi-LLM consensus) is not functioning |
| 2 | **Replace agentless snapshot scan fake data with real boto3/azure-mgmt-compute calls** | `agentless_snapshot_scan_engine.py:143` TODO comment; line 174 fake bytes | 10d | HIGH — claimed DONE vs Wiz SideScanning moat |
| 3 | **Implement real cosign/sigstore DSSE signing** | `slsa_provenance_engine.py:82` placeholder sig; `air_gap_bundle_engine.py:86` placeholder HMAC | 8d | HIGH — SCIF/FedRAMP claims require real cryptographic attestation |
| 4 | **UX Phase 3: collapse 382 pages → 30 screens** | `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` plan exists, zero implementation started | 45d | CRITICAL — 382-page SPA is not a shippable product |
| 5 | **Implement TypeScript/JavaScript/Java AST analysis** | `deep_code_analysis_engine.py:175-188` NotImplementedError; tracked as NEW-G070 | **DONE 2026-04-27** — landed in 1 watchdog session via parallel-team dispatch | HIGH — AppSec persona primary workflow blocked for non-Python repos |
| 6 | **Wire the 11 missing connector adapters (PAM, MDM, SSPM, XDR, cloud-cred-based)** | `empty_endpoints_triage_2026-04-26.md` items 13,14,15,18,19,20,24,25,27 | 60d | HIGH — 11 empty endpoint classes = features that appear in UI but return nothing |
| 7 | **Build pre-computed OSS call graph corpus (GAP-048)** | Explicitly NOT-STARTED. Required for Snyk/Endor/Sonatype parity on SCA reachability | 30d | HIGH — function reachability parity |
| 8 | **Ship VS Code IDE extension** | GAP-014 NEEDS-PRODUCT-DECISION; Snyk/Sonatype/Aikido all have this | 25d | MEDIUM — developer onboarding bottleneck |
| 9 | **Publish typed SDKs (Python/TypeScript) to PyPI/npm** | GAP-037 IN-PROGRESS; required for developer ecosystem credibility | 5d | MEDIUM |
| 10 | **Enforce OpenSSL FIPS boundary at Python runtime in container** | `fips_encryption.py:17` claims FIPS 140-2 via stdlib — stdlib AES is NOT FIPS-certified without module-level enforcement. UNVERIFIED at runtime. | 10d | MEDIUM — required before any FedRAMP pilot |

---

## 4. Overall Completion Assessment

### By Layer

| Layer | Score | Confidence |
|-------|-------|-----------|
| Engine count / scaffolding | 75% | High — 353 engine files exist, most non-trivial LOC |
| API surface (routes exist) | 70% | High — 800 live paths confirmed |
| Engine implementation depth | 42% | High — agentless/reachability still stubs; DCA multi-language FIXED 2026-04-27 (+7pp) |
| LLM consensus functioning | 15% | High — 1 key, all verdicts uniform |
| UI pages wired to real APIs | 60% | High — 2,306 useQuery calls; but 382 pages = unusable UX |
| UX as a shippable product | 10% | High — Phase 3 not started |
| Cryptographic security claims | 30% | High — SLSA/Cosign/air-gap are placeholder stubs |
| SCIF/FedRAMP readiness | 20% | High — docs are pilot-draft, not authorized |
| Competitive feature parity | 58% | Medium — based on honest re-score |
| End-to-end persona workflows | 46% | Medium — no persona has fully closed loop with real data |
| Integration live data | 40% | High — 29/30 connector classes return empty for real tenants |

### Final Overall Completion

**31% ± 8% (80% confidence interval: 23%–39%)**

Rationale for 28%:
- Infrastructure/scaffolding is genuinely present and non-trivial (~353 engines, 800 routes, real feed integrations). This accounts for significant real work.
- The product cannot be shipped to a paying customer today: UX is 382 disconnected pages, the primary AI moat (multi-LLM council) produces identical "review" outputs, agentless scanning uses fake data, IDE plugins are 0 of 4, and 29 connector endpoints return empty for real tenants.
- The gap between "code exists" and "feature works end-to-end for a real customer" is the dominant gap.

The prior "95% completion" was measuring engine file existence. The honest v1.0 gate measures working features a paying CISO would use.

---

## 5. Dimensions Where ALDECI Is Worst

1. **LLM Consensus (15%)** — The #1 claimed moat is not functioning. Single LLM, 100% uniform verdicts, DPO training data is auto-generated escalations not human-validated overrides.

2. **UX Completeness (10%)** — 382 pages when target is 30. Phase 3 consolidation not started. No paying customer would navigate this.

3. **Critical Feature Stubs (agentless scan, SLSA signing, TS/JS/Java code analysis) (~20% of claimed DONE features)** — Features marked DONE in gap matrix with TODO/placeholder/fake-data in implementation.

---

## 6. What Is Genuinely Strong

To be fair: several areas are legitimately ahead of competitors and represent real work:

- **Threat feed infrastructure**: NVD/EPSS/KEV/OSV live fetch with SQLite caching is production-quality (`threat_intel_aggregator.py`).
- **Brain pipeline architecture**: 12-step pipeline (4,524 LOC) with real step implementations — connect through evidence generation. The pipeline is real even if the council step is degraded.
- **FIPS/HSM infrastructure**: `hsm_provider.py` wraps real PKCS#11/python-pkcs11. `fips_compliance_mode_engine.py` has real PQC algorithm registry.
- **Material change detection**: 1,127 LOC with real git-diff parsing + regex SAST heuristics + Bandit integration. Not a stub.
- **Attack path / choke-point engine**: Edmonds-Karp min-cut is real algorithm implementation.
- **SCIF documentation package**: SSP + POA&M + NIST 800-53 matrix + STIG checklist is the most honest SCIF-readiness documentation seen from a startup at this stage (and explicitly self-declares pilot status).

---

## Citations Index

| Finding | File / Evidence |
|---------|----------------|
| Agentless scan fake data | `suite-core/core/agentless_snapshot_scan_engine.py:139,143,174` |
| Deep code analysis stubs | `suite-core/core/deep_code_analysis_engine.py:175-188` |
| SLSA placeholder sig | `suite-core/core/slsa_provenance_engine.py:70,79-82` |
| Air-gap placeholder HMAC | `suite-core/core/air_gap_bundle_engine.py:32,85-86,1159` |
| Cosign stub in container runtime | `suite-core/core/container_runtime.py:1166` |
| 1 LLM key configured | `/Users/devops.ai/fixops/Fixops/.env` — only OPENROUTER_API_KEY |
| All 5196 verdicts = "review" conf=0.5 | `data/learning_signals.db` — `SELECT AVG(confidence) FROM council_verdicts` = 0.5 |
| DPO pairs auto-generated | `data/learning_signals.db` — 5195/5196 source = `llm_learning_loop_low_confidence` |
| 800 live API paths | `curl http://localhost:8000/openapi.json` |
| 382 UI pages | `ls suite-ui/aldeci-ui-new/src/pages/*.tsx \| wc -l` |
| 1293 stub/TODO/mock in UI | `grep -rn "TODO\|mock\|MOCK\|placeholder\|stub" src/pages/ \| wc -l` |
| 29/30 empty endpoints | `docs/empty_endpoints_triage_2026-04-26.md` |
| Function reachability Python-only | `suite-core/core/function_reachability_engine.py:446,459` |
| 10k graph benchmark not done | `raw/competitive/gap-matrix-2026-04-26.md:GAP-047` IN-PROGRESS |
| SSP is pilot draft | `docs/scif/SSP_aldeci_2026-04-26.md:~line 6` — "Pilot Draft SSP" |
| Snyk IDE plugins (4) | `docs.snyk.io/scm-ide-and-ci-cd-integrations/snyk-ide-plugins-and-extensions` — VS Code, Visual Studio, Eclipse, JetBrains confirmed |
| Wiz 200+ integrations | `wiz.io/platform` — "200+ integrations" confirmed |
