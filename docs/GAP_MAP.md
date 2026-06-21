# FixOps — Capability Gap Map

> **Generated**: 2026-06-21 via deep multi-agent audit (`wf_45600e71-faa`).
> **Scale**: 142 agents / 9.4M tokens / 58 min. 34 spec capabilities + 20 domain buckets = 54 audits.
> **Method**: each capability audited for implemented / real-vs-stub / tested / CI-gated / UI-wired with file:line evidence; every critical/high gap adversarially re-verified by a skeptic agent (**52 claimed gaps refuted and dropped**).
> Honest-empty (0/None/404 when un-ingested) is treated as CORRECT, not a gap.

## Executive summary

- **54 capabilities** audited. Realness: the moats are overwhelmingly **real** — almost nothing is a hollow stub.
- **0 critical · 18 high · 103 medium · 49 low** verified-real gaps (170 total).
- **Systemic finding**: only ~8 of 54 capabilities have a **blocking CI gate**. The moats are real and (partly) tested but **ungated** — they can silently regress. CI-gating is the single highest-leverage investment.
- **Highest-risk cluster**: **tenant isolation** — 6+ routers accept `org_id` as a spoofable query/body param instead of `Depends(get_org_id)`, allowing cross-tenant data read/write on a shared deployment. All are code fixes (not founder-gated).
- **NO-MOCKS violations**: 3 endpoints serve hardcoded/fabricated data as if real (threat-intel feed counts, MITRE techniques, AI advisor fallback).
- **2 real functional bugs**: TS/Java reachability parse always 500s; MPTE consensus `_execute_step` is an explicit stub (always fails).

## Themes (high-severity, ranked by leverage)

### A. Tenant isolation — `org_id` spoofing (customer-facing security)
Routers take `org_id` from the client instead of the auth context. On a multi-tenant SCIF deployment this is cross-tenant data leakage. Fix pattern: `org_id: str = Query('default')` / body field → `org_id: str = Depends(get_org_id)`.
- **[SPEC-019-to-SPEC-030-batch-audit]** SPEC-030: zones/flows/violations tables have no org_id column. On a shared multi-tenant deployment all orgs share one network store with no cross-tenant isolation. Schema migration (add org_id) is founder-gated.
  - `suite-core/core/network_analyzer.py _init_tables()`
- **[SPEC-012-ctem]** ctem_engine_router.py POST /cycles uses request.org_id (Pydantic body field, default='default') not the auth-derived get_org_id dependency. An authenticated caller can fabricate any org_id on cycle creation, breaking tenant isolation for that code path.
  - `suite-api/apps/api/ctem_engine_router.py:72,86,117`
- **[SPEC-021-mpte]** REQ-021-03 violated: /api/v1/mpte/stats (line 1348) has no org_id parameter and calls db.list_requests/list_results without org filter — returns all tenants' scan counts and verified_vulnerable data to any authenticated caller. Also /verify, /scan/comprehensive, /configs, /findings/{id}/exploitability, /verifications lack Depends(get_org_id) entirely.
  - `suite-attack/api/mpte_router.py:1348-1389 (stats), also lines 952, 868, 1073, 1242, 1294`
- **[SPEC-032 customer-journey E2E gate]** test_customer_journey_e2e.py step 5 tenant-isolation assertion is structurally weakened to assert isinstance(findings_a, list) — always True. The test itself documents (lines 450-455) that the ingest-to-retrieve loop may be broken: scanner-ingest writes to SecurityFindingsEngine DB while /api/v1/findings reads from an in-memory store. The CI gate passes even if ingested findings are completely invisible.
  - `tests/test_customer_journey_e2e.py:433-488`
- **[domain:network]** network_traffic_router takes org_id as a plain str query parameter on all 8 endpoints instead of Depends(get_org_id). Any authenticated caller can read or overwrite another tenant's flows, anomalies, rules, and stats by supplying an arbitrary org_id. Cross-tenant data leakage via org_id spoofing.
  - `suite-api/apps/api/network_traffic_router.py:67,78,88,97,106,114,122,127`
- **[domain:data]** data_exfiltration_router.py: all 9 endpoints use org_id = Query('default') instead of Depends(get_org_id). Any caller that omits the org_id query param silently reads/writes org 'default', collapsing all tenant data into a single namespace. Router-level api_key_auth is present (line 29 dependencies=[Depends(api_key_auth)]) but tenancy isolation is broken.
  - `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/data_exfiltration_router.py:90,104,117,129,146,157,170,181,194`
- **[domain:data]** data_retention_router.py: all 10 endpoints use org_id = Query('default'). Same cross-tenant collapse as data_exfiltration_router. Router-level auth is present (dependencies=[Depends(api_key_auth)] line 38) but org isolation is bypassed.
  - `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/data_retention_router.py:100,114,131,148,170,191,210,231,253,265`
- **[domain:data]** data_lake_security_router.py: 5 of 7 endpoints use org_id = Query('default') (lines 83,97,132,146,153). The two POST endpoints that accept a request body embed org_id in the body model (DataStoreCreate.org_id Field('default')), still defaulting to 'default'. Router auth is per-route Depends(api_key_auth) but tenant isolation broken.
  - `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/data_lake_security_router.py:51,83,97,132,146,153`
- **[domain:risk]** risk_acceptance_router.py is double-mounted in grc_app.py: line 1075 with only Depends(_verify_api_key) (no scope), and line 1404 with Depends(_verify_api_key) + Depends(_require_scope('write:findings')). FastAPI registers both route sets; the weaker-auth duplicate shadows or races the scoped version. Effective write:findings scope enforcement on the acceptance workflow is broken.
  - `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/sub_apps/grc_app.py:1075 and 1404`

### B. NO-MOCKS violations (fabricated data served as real)
- **[SPEC-022-threat-intel]** GET /api/v1/threat-intel/feeds/status returns fabricated ioc_count values for unrefreshed/unconfigured feeds: URLhaus=3200, ThreatFox=8900, feodo fallback=600, KEV fallback=1100 (lines 505,516,525,534,601,605,606,610,613,616,617 of threat_intel_router.py). These are not real cache counts — they are hardcoded magic numbers that violate REQ-022-01 (honest-empty guarantee). Correct behavior: return ioc_count=0 and health=degraded/no_data when the feed has never been fetched.
  - `suite-api/apps/api/threat_intel_router.py:505,516,525,534,601,605,606,610,613,616,617`
- **[SPEC-022-threat-intel]** GET /api/v1/feeds/mitre/techniques returns a 12-entry static Python list (_MITRE_TECHNIQUES, line 438) hardcoded in feeds_router.py. The data_source block (line 828) returns last_updated=datetime.utcnow() making it appear dynamically fetched, but no STIX/TAXII fetch ever occurs. This is stub data presented as live feed data.
  - `suite-core/api/feeds_router.py:438-856`
- **[domain:ai]** ai_security_advisor_engine.py: FALLBACK_RECOMMENDATIONS (5 hardcoded generic security recommendations) is silently served as completed advisor output when MULEROUTER_API_KEY is absent or LLM returns non-JSON. The session status field is 'completed' with no synthetic_fallback flag, so callers cannot distinguish real LLM advice from the static list. Violates NO-MOCKS rule — fabricated canned content passed off as AI-generated. Evidence: line 167 returns 'LLM not configured' string; that string fails JSON parse; line 510 sets recs_data=FALLBACK_RECOMMENDATIONS; line 516 marks session completed.
  - `suite-core/core/ai_security_advisor_engine.py:51-132,499-513`

### C. Real functional bugs
- **[SPEC-011-aspm]** function_reachability_router.py:88-89 has a logic bug: for language='typescript' it calls eng.parse_typescript_repo() then immediately raises RuntimeError('unreachable') — the nodes_added result is discarded and a 500 is always returned. TypeScript/JS parse via POST /api/v1/reachability/parse never succeeds at the router level even though the engine itself works. Same pattern at line 91-92 for Java.
  - `suite-api/apps/api/function_reachability_router.py:88-92`
- **[SPEC-021-mpte]** AdvancedMPTEClient._execute_step is an explicit stub (mpte_advanced.py:939-956): every call logs 'mpte_step_not_implemented' and returns success:False, error:not_implemented. The entire consensus execution plan path (execute_pentest_with_consensus -> _execute_consensus_plan -> _execute_step) therefore always reports failure, making multi-AI consensus execution non-functional.
  - `suite-core/core/mpte_advanced.py:939-956`

### D. CI-gate / test-integrity
- **[SPEC-019-to-SPEC-030-batch-audit]** SPEC-030: zones/flows/violations tables have no org_id column. On a shared multi-tenant deployment all orgs share one network store with no cross-tenant isolation. Schema migration (add org_id) is founder-gated.
  - `suite-core/core/network_analyzer.py _init_tables()`
- **[SPEC-007-systemic-tenancy]** 2 of 18 acceptance tests fail: test_tenancy_lint.py::test_allowlist_has_entries and test_tenancy_lint.py::test_no_new_violations_beyond_allowlist. AC-007-02 and AC-007-03 are not met. 100 real V1 violations exist untracked.
  - `tests/test_tenancy_lint.py:51 (test_allowlist_has_entries), tests/test_tenancy_lint.py:71 (test_no_new_violations_beyond_allowlist)`
- **[SPEC-009-supplychain-lockfile]** CI pip-audit gate is toothless: ci.yml step uses '|| true' on the pip-audit command AND 'continue-on-error: true' on the step — CVE failures never fail CI. regression-gates.yml has no pip-audit/SBOM gate at all. REQ-009-04 (fail on HIGH/CRITICAL CVEs) is not enforced in CI.
  - `/Users/devops.ai/fixops/Fixops/.github/workflows/ci.yml line ~98 (continue-on-error: true on pip-audit step)`
- **[SPEC-032 customer-journey E2E gate]** test_customer_journey_e2e.py step 5 tenant-isolation assertion is structurally weakened to assert isinstance(findings_a, list) — always True. The test itself documents (lines 450-455) that the ingest-to-retrieve loop may be broken: scanner-ingest writes to SecurityFindingsEngine DB while /api/v1/findings reads from an in-memory store. The CI gate passes even if ingested findings are completely invisible.
  - `tests/test_customer_journey_e2e.py:433-488`

## Full HIGH gap list (18, verified-real)

1. **[SPEC-019-to-SPEC-030-batch-audit]** SPEC-030: zones/flows/violations tables have no org_id column. On a shared multi-tenant deployment all orgs share one network store with no cross-tenant isolation. Schema migration (add org_id) is founder-gated.
   - `suite-core/core/network_analyzer.py _init_tables()`
2. **[SPEC-007-systemic-tenancy]** 2 of 18 acceptance tests fail: test_tenancy_lint.py::test_allowlist_has_entries and test_tenancy_lint.py::test_no_new_violations_beyond_allowlist. AC-007-02 and AC-007-03 are not met. 100 real V1 violations exist untracked.
   - `tests/test_tenancy_lint.py:51 (test_allowlist_has_entries), tests/test_tenancy_lint.py:71 (test_no_new_violations_beyond_allowlist)`
3. **[SPEC-009-supplychain-lockfile]** CI pip-audit gate is toothless: ci.yml step uses '|| true' on the pip-audit command AND 'continue-on-error: true' on the step — CVE failures never fail CI. regression-gates.yml has no pip-audit/SBOM gate at all. REQ-009-04 (fail on HIGH/CRITICAL CVEs) is not enforced in CI.
   - `/Users/devops.ai/fixops/Fixops/.github/workflows/ci.yml line ~98 (continue-on-error: true on pip-audit step)`
4. **[SPEC-011-aspm]** function_reachability_router.py:88-89 has a logic bug: for language='typescript' it calls eng.parse_typescript_repo() then immediately raises RuntimeError('unreachable') — the nodes_added result is discarded and a 500 is always returned. TypeScript/JS parse via POST /api/v1/reachability/parse never succeeds at the router level even though the engine itself works. Same pattern at line 91-92 for Java.
   - `suite-api/apps/api/function_reachability_router.py:88-92`
5. **[SPEC-012-ctem]** ctem_engine_router.py POST /cycles uses request.org_id (Pydantic body field, default='default') not the auth-derived get_org_id dependency. An authenticated caller can fabricate any org_id on cycle creation, breaking tenant isolation for that code path.
   - `suite-api/apps/api/ctem_engine_router.py:72,86,117`
6. **[SPEC-016-scif-stack-fit]** REQ-016-12: POST /api/v1/wiz/graphql passthrough carries only router-level api_key_auth (any valid API key) — no admin-scope enforcement and no per-request audit log entry. The spec requires 'admin-scope + audit-logged'; neither is implemented.
   - `suite-api/apps/api/wiz_router.py:227-234 — @router.post('/graphql') has no additional scope dependency or audit call`
7. **[SPEC-021-mpte]** REQ-021-03 violated: /api/v1/mpte/stats (line 1348) has no org_id parameter and calls db.list_requests/list_results without org filter — returns all tenants' scan counts and verified_vulnerable data to any authenticated caller. Also /verify, /scan/comprehensive, /configs, /findings/{id}/exploitability, /verifications lack Depends(get_org_id) entirely.
   - `suite-attack/api/mpte_router.py:1348-1389 (stats), also lines 952, 868, 1073, 1242, 1294`
8. **[SPEC-021-mpte]** AdvancedMPTEClient._execute_step is an explicit stub (mpte_advanced.py:939-956): every call logs 'mpte_step_not_implemented' and returns success:False, error:not_implemented. The entire consensus execution plan path (execute_pentest_with_consensus -> _execute_consensus_plan -> _execute_step) therefore always reports failure, making multi-AI consensus execution non-functional.
   - `suite-core/core/mpte_advanced.py:939-956`
9. **[SPEC-022-threat-intel]** GET /api/v1/threat-intel/feeds/status returns fabricated ioc_count values for unrefreshed/unconfigured feeds: URLhaus=3200, ThreatFox=8900, feodo fallback=600, KEV fallback=1100 (lines 505,516,525,534,601,605,606,610,613,616,617 of threat_intel_router.py). These are not real cache counts — they are hardcoded magic numbers that violate REQ-022-01 (honest-empty guarantee). Correct behavior: return ioc_count=0 and health=degraded/no_data when the feed has never been fetched.
   - `suite-api/apps/api/threat_intel_router.py:505,516,525,534,601,605,606,610,613,616,617`
10. **[SPEC-022-threat-intel]** GET /api/v1/feeds/mitre/techniques returns a 12-entry static Python list (_MITRE_TECHNIQUES, line 438) hardcoded in feeds_router.py. The data_source block (line 828) returns last_updated=datetime.utcnow() making it appear dynamically fetched, but no STIX/TAXII fetch ever occurs. This is stub data presented as live feed data.
   - `suite-core/api/feeds_router.py:438-856`
11. **[SPEC-024-deception]** Primary /api/v1/deception/ endpoints (canaries, alerts, stats, honeypots) have no UI consumer. DeceptionHub engine tab (DeceptionHub.tsx:130-134) renders FAILStatsPanel which calls failApi (/api/v1/fail/...) not the deception engine. No deceptionApi client exists in lib/api.ts. Hub comment on line 11 falsely documents this tab as calling /api/v1/deception/{stats,canaries,alerts}.
   - `suite-ui/aldeci-ui-new/src/pages/DeceptionHub.tsx:130-134 and suite-ui/aldeci-ui-new/src/lib/api.ts (no deceptionApi export)`
12. **[SPEC-032 customer-journey E2E gate]** test_customer_journey_e2e.py step 5 tenant-isolation assertion is structurally weakened to assert isinstance(findings_a, list) — always True. The test itself documents (lines 450-455) that the ingest-to-retrieve loop may be broken: scanner-ingest writes to SecurityFindingsEngine DB while /api/v1/findings reads from an in-memory store. The CI gate passes even if ingested findings are completely invisible.
   - `tests/test_customer_journey_e2e.py:433-488`
13. **[domain:network]** network_traffic_router takes org_id as a plain str query parameter on all 8 endpoints instead of Depends(get_org_id). Any authenticated caller can read or overwrite another tenant's flows, anomalies, rules, and stats by supplying an arbitrary org_id. Cross-tenant data leakage via org_id spoofing.
   - `suite-api/apps/api/network_traffic_router.py:67,78,88,97,106,114,122,127`
14. **[domain:data]** data_exfiltration_router.py: all 9 endpoints use org_id = Query('default') instead of Depends(get_org_id). Any caller that omits the org_id query param silently reads/writes org 'default', collapsing all tenant data into a single namespace. Router-level api_key_auth is present (line 29 dependencies=[Depends(api_key_auth)]) but tenancy isolation is broken.
   - `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/data_exfiltration_router.py:90,104,117,129,146,157,170,181,194`
15. **[domain:data]** data_retention_router.py: all 10 endpoints use org_id = Query('default'). Same cross-tenant collapse as data_exfiltration_router. Router-level auth is present (dependencies=[Depends(api_key_auth)] line 38) but org isolation is bypassed.
   - `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/data_retention_router.py:100,114,131,148,170,191,210,231,253,265`
16. **[domain:data]** data_lake_security_router.py: 5 of 7 endpoints use org_id = Query('default') (lines 83,97,132,146,153). The two POST endpoints that accept a request body embed org_id in the body model (DataStoreCreate.org_id Field('default')), still defaulting to 'default'. Router auth is per-route Depends(api_key_auth) but tenant isolation broken.
   - `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/data_lake_security_router.py:51,83,97,132,146,153`
17. **[domain:risk]** risk_acceptance_router.py is double-mounted in grc_app.py: line 1075 with only Depends(_verify_api_key) (no scope), and line 1404 with Depends(_verify_api_key) + Depends(_require_scope('write:findings')). FastAPI registers both route sets; the weaker-auth duplicate shadows or races the scoped version. Effective write:findings scope enforcement on the acceptance workflow is broken.
   - `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/sub_apps/grc_app.py:1075 and 1404`
18. **[domain:ai]** ai_security_advisor_engine.py: FALLBACK_RECOMMENDATIONS (5 hardcoded generic security recommendations) is silently served as completed advisor output when MULEROUTER_API_KEY is absent or LLM returns non-JSON. The session status field is 'completed' with no synthetic_fallback flag, so callers cannot distinguish real LLM advice from the static list. Violates NO-MOCKS rule — fabricated canned content passed off as AI-generated. Evidence: line 167 returns 'LLM not configured' string; that string fails JSON parse; line 510 sets recs_data=FALLBACK_RECOMMENDATIONS; line 516 marks session completed.
   - `suite-core/core/ai_security_advisor_engine.py:51-132,499-513`

## Status matrix (all 54)

| Capability | Impl | Real | Tested | CI-gated | UI-wired |
|---|---|---|---|---|---|
| Connector domain — engines (connectors.py, cloud_connectors.py, security_connectors.py, connector_ingestion_scheduler.py, suite-core/connectors/pull_connector.py) and routers (connectors_router, connector_routes, container_security_connector_router, admin_connectors_router, cspm_connector_router, cloud_connectors_router, threat_intel_connector_router, 11 vendor live routers) | yes | real | yes | yes | no |
| SPEC-001-trustgraph-correlation | yes | real | partial | no | no |
| SPEC-002-nuclei-pentest | yes | real | yes | no | no |
| SPEC-004-trustgraph-council | no | unknown | no | no | no |
| SPEC-005-airgap-enforced-default | yes | real | partial | no | yes |
| SPEC-005b-graph-populate | yes | real | yes | no | yes |
| SPEC-006-honest-compliance-reporting | yes | real | yes | no | yes |
| SPEC-006b-crypto-hardening | yes | real | partial | no | no |
| SPEC-007-systemic-tenancy | partial | mixed | partial | no | na |
| SPEC-008-ha-durability | yes | real | yes | no | na |
| SPEC-009-supplychain-lockfile | yes | real | partial | no | yes |
| SPEC-010-maintainability | yes | real | yes | no | na |
| SPEC-011-aspm | yes | real | yes | no | yes |
| SPEC-012-ctem | partial | real | yes | no | yes |
| SPEC-013-cspm | yes | mixed | yes | no | yes |
| SPEC-014-auth-tenancy | yes | real | partial | no | yes |
| SPEC-015-connectors | yes | real | partial | yes | yes |
| SPEC-016-scif-stack-fit | yes | real | partial | no | no |
| SPEC-017-full-pipeline-on-ingest | yes | real | yes | no | na |
| SPEC-019-evidence-chain-of-custody | yes | real | partial | no | no |
| SPEC-019-to-SPEC-030-batch-audit | yes | real | yes | no | yes |
| SPEC-020-council-verdict | partial | mixed | partial | yes | yes |
| SPEC-021-mpte | yes | real | partial | no | no |
| SPEC-021-mpte | partial | mixed | partial | no | yes |
| SPEC-022-threat-intel | partial | mixed | partial | no | yes |
| SPEC-023-soar-playbooks | partial | mixed | partial | no | yes |
| SPEC-024-deception | yes | real | yes | no | no |
| SPEC-025-forensics | yes | real | yes | no | yes |
| SPEC-026-exec-reporting | yes | real | partial | no | yes |
| SPEC-027-auth-hardening | yes | real | yes | yes | yes |
| SPEC-028-ui-no-mocks | yes | real | yes | yes | yes |
| SPEC-029-analytics-org-scoping | yes | real | yes | yes | yes |
| SPEC-030-network-segmentation | partial | mixed | partial | no | no |
| SPEC-031-ui-routing-integrity | yes | real | yes | yes | yes |
| SPEC-032 customer-journey E2E gate | yes | mixed | partial | yes | na |
| SPEC-032-real-moat-e2e | yes | real | yes | yes | yes |
| domain:access | yes | real | partial | no | na |
| domain:ai | partial | mixed | partial | no | na |
| domain:asset | yes | real | partial | no | no |
| domain:attack | yes | real | partial | no | na |
| domain:compliance | yes | mixed | partial | yes | no |
| domain:container | partial | real | partial | no | yes |
| domain:data | partial | mixed | partial | no | na |
| domain:deception | yes | real | partial | no | na |
| domain:forensics | yes | real | partial | yes | na |
| domain:incident | partial | mixed | partial | no | na |
| domain:llm | partial | mixed | partial | no | na |
| domain:network | yes | real | partial | no | no |
| domain:risk | yes | mixed | partial | no | na |
| domain:security | yes | real | partial | no | na |
| domain:supply | yes | real | partial | no | na |
| domain:threat | yes | mixed | partial | yes | no |
| domain:threat-intel | yes | real | partial | no | na |
| domain:webhook | yes | real | partial | no | na |

## Medium gaps (103) — grouped by capability

### Connector domain — engines (connectors.py, cloud_connectors.py, security_connectors.py, connector_ingestion_scheduler.py, suite-core/connectors/pull_connector.py) and routers (connectors_router, connector_routes, container_security_connector_router, admin_connectors_router, cspm_connector_router, cloud_connectors_router, threat_intel_connector_router, 11 vendor live routers)
- cspm_connector_router ImportError fallback defines 'def api_key_auth() -> None: pass' (silent no-op callable). If auth_deps becomes unimportable, all CSPM connector endpoints silently become unauthenticated with no startup error.  
  `suite-api/apps/api/cspm_connector_router.py:23-30`

### SPEC-001-trustgraph-correlation
- test_create_app_mounts_correlations_route times out (>30s) because create_app() loads the entire app within pytest's 30s timeout. The boot-smoke test always fails in CI, giving a false red signal. The test should use direct router inspection (as confirmed manually) instead of create_app().  
  `tests/test_trustgraph_correlation.py:367-382`
- GET /api/v1/brain/correlations/{finding_id} is not consumed by any UI page in suite-ui/aldeci-ui-new/src/. Findings hubs and dashboard pages do not surface TrustGraph blast-radius or correlated-CVE data to users. AC-001-04 (live curl showing populated trustgraph block in a pipeline verdict) is noted in the spec but has no automated test verifying the end-to-end pipeline path.  
  `suite-ui/aldeci-ui-new/src/ (zero hits for brain/correlations)`

### SPEC-002-nuclei-pentest
- openclaw_router.py line 583 calls _get_engine() with no org_id argument, which will raise TypeError at runtime on the GET / index endpoint (the function signature requires org_id). This is a latent bug in the router's catch-all index route.  
  `suite-api/apps/api/openclaw_router.py line 583: engine = _get_engine() — missing org_id positional arg`

### SPEC-005-airgap-enforced-default
- TestCreateAppBoot::test_create_app_succeeds_default_mode times out (>30s) on create_app() startup — the --timeout=30 budget is exhausted by the full app mount sequence. The test that exercises AC-005-01 (enforced boot) is masked by this; enforced mode variant is not independently verified at the create_app level under CI timeout constraints.  
  `tests/test_airgap_enforced.py::TestCreateAppBoot::test_create_app_succeeds_default_mode`

### SPEC-005b-graph-populate
- Regression test test_trustgraph_correlation.py::TestBootSmoke::test_create_app_mounts_correlations_route times out (>30s) during create_app() boot. This is a pre-existing flake unrelated to SPEC-005b logic, but it means the spec claim '57/57 PASS' in the implementation notes is currently false (56/57 in practice).  
  `tests/test_trustgraph_correlation.py:367`

### SPEC-006-honest-compliance-reporting
- _check_scan_results, _check_policy_exists, _check_incident_reports, and _check_training_records have no real data path wired and are permanently not_assessed. Honest-empty per spec scope, but silently excludes these controls from the score denominator, masking coverage gaps from operators. Resolution deferred to SPEC-006 P2 / SPEC-008.  
  `suite-core/core/compliance_engine.py lines 958-1091`

### SPEC-006b-crypto-hardening
- TestBootAndImports::test_create_app_boots_default has a 30s timeout that is consistently exceeded by create_app() cold-start (~17s on this host). At the CI-configured 30s limit in regression-gates.yml it would fail intermittently, masking actual regressions. Test itself passes logic-wise at 120s.  
  `tests/test_crypto_hardening.py:552 (test_create_app_boots_default) — timeout mismatch with create_app cold-start`

### SPEC-007-systemic-tenancy
- Spec claims 1730 violations (V1=1724, V2=1, V3=5) but actual scan finds only 100 (all V1, V2=0, V3=0). The scanner only scans suite-api/apps/api and suite-core/api directories. Either the scope shrank, routers were renamed/deleted, or the spec's counts were fabricated. V3 shadow defs cited in spec (analytics_routes.py:35, exposure_case_router.py:42, mcp_routes.py:63, trustgraph_routes.py:144) produce zero hits in current scan — those files either were fixed or do not exist at those paths.  
  `scripts/tenancy_lint.py:44 (SCAN_DIRS_REL); specs/SPEC-007-systemic-tenancy.md:76-78 (claimed counts)`

### SPEC-009-supplychain-lockfile
- No executable tests for SPEC-009 acceptance criteria: no test validates requirements.lock exists and is fully pinned (AC-009-01), no test checks dependabot.yml ecosystem (AC-009-02), no test runs pip install --dry-run against the lockfile (AC-009-05). test_pip_audit_sarif.py only tests the SARIF converter utility, not the supply-chain lockfile spec.  
  `/Users/devops.ai/fixops/Fixops/tests/test_pip_audit_sarif.py (24 tests, none cover AC-009-01/02/03/05)`
- pip-audit output (docs/sbom/pip-audit-2026-06-01.txt) lists 17 known vulnerabilities in 9 packages including dulwich 0.23.0 CVE-2026-42305 and gitpython 3.1.46 CVE-2026-42215. No documented allowlist exists and CI does not block on them — contradicts REQ-009-04.  
  `/Users/devops.ai/fixops/Fixops/docs/sbom/pip-audit-2026-06-01.txt`

### SPEC-011-aspm
- Spec REQ-011-18 states TypeScript/Java MUST raise NotImplementedError (stubs) and be surfaced as HTTP 501, implying these are not yet implemented. In reality the engine has full tree-sitter implementations for both (suite-core/core/function_reachability_engine.py:902 and 1020). The spec is outdated on this point — the engine is real but the router bug (gap 1) prevents it from being reachable.  
  `suite-core/core/function_reachability_engine.py:902,1020 vs specs/SPEC-011-aspm.md:REQ-011-18`
- AC-011-01 states test_different_file_path_no_merge and test_different_line_no_merge must be in tests/test_smart_dedup.py but they live in tests/test_dedup_cross_scanner.py:102,109. test_smart_dedup.py has test_same_location_different_files (line 394) which covers the same logic. Tests pass but the acceptance criteria file attribution is wrong.  
  `tests/test_smart_dedup.py vs tests/test_dedup_cross_scanner.py:102,109`

### SPEC-012-ctem
- MEASUREMENT stage missing from CTEMStage enum and _STAGE_ORDER. Spec REQ-012-16 and §3c specify 6 stages ending in MEASUREMENT; ctem_engine.py:46-68 defines only 5 stages ending at MOBILIZATION. advance_stage() raises ValueError('already at final stage MOBILIZATION') instead of advancing to MEASUREMENT.  
  `suite-core/core/ctem_engine.py:46-69, line 338`
- Monte Carlo router (/api/v1/risk/simulate/*) has no api_key_auth or rate-limit dependency. Any unauthenticated caller can trigger CPU-intensive simulations (up to 100,000 iterations). Spec §2e notes 'none' auth but §7 flags it as an open gap.  
  `suite-core/api/monte_carlo_router.py`
- None of the 8 named AC test files (test_exposure_case_unit.py, test_ctem_engine.py, test_risk_aggregator_engine.py, test_attack_path_engine.py, etc.) are included in any step of regression-gates.yml. SPEC-012 behaviour is tested locally but not CI-gated on PR-to-main.  
  `.github/workflows/regression-gates.yml (all steps)`

### SPEC-013-cspm
- CSPMConnector._build_prowler_sample() (line 688-705) fabricates prowler findings with synthetic resource IDs (e.g. cspm-public-{org_id}, sg-cspm-open-22 at connector line 100) and account ID 000000000000, then ingests them into SecurityFindingsEngine as source_tool=cspm_via_prowler when both prowler CLI and boto3 fail. This violates the NO-MOCKS rule: fabricated data is silently presented as real scanner output to callers of list_findings_with_cspm_fallback.  
  `suite-core/connectors/cspm_connector.py:688-705 and :54-100 (_PROWLER_SAMPLE_AWS)`

### SPEC-014-auth-tenancy
- tests/test_tenant_lease_b2.py referenced in AC-014-11 does not exist on disk. That acceptance criterion is permanently unsatisfiable.  
  `specs/SPEC-014-auth-tenancy.md:235 (AC-014-11); tests/test_tenant_lease_b2.py absent`
- test_api_auth.py contains only 1 test function (test_api_key_header_enforcement), far below AC-014-01 expectations.  
  `tests/test_api_auth.py`
- verify_api_key lazy-imports rate-limit, security audit, and failure tracking from apps.api.app at call time (lines 459-471). When apps.api.app is not yet in sys.modules all three are silently None and skipped, so managed-key and JWT paths bypass rate limiting with no error or log.  
  `suite-api/apps/api/auth_deps.py:459-471`

### SPEC-015-connectors
- AC-015-05 not enforced: pytest tests/test_phase2_connectors.py -k github selects 0 tests — no test exercises GitHubAPIEngine -> HTTP 503 path when GITHUB_TOKEN is unset. The spec requires this verified by that exact command.  
  `tests/test_phase2_connectors.py (0 github-keyed tests); suite-core/core/github_api_engine.py:139`
- Three AC test files (test_connector_ingestion_scheduler.py, test_connector_health_endpoint.py, test_connector_event_emit.py) and test_pip_audit_sarif.py pass locally but are absent from all .github/workflows/ files — not CI-gated on PR-to-main. Only test_connector_framework.py is in ci.yml beast-mode.  
  `.github/workflows/regression-gates.yml and .github/workflows/ci.yml — no reference to these 4 files`

### SPEC-016-scif-stack-fit
- REQ-016-11 second half: brain read-path (get_node) does not filter by classification_level vs. org clearance. The write-path stamps classification_level in node properties (scanner_ingest_router._index_findings_into_brain), but knowledge_brain.py:get_node() (line 488) returns the raw row with no clearance check. Cross-clearance reads are not blocked.  
  `suite-core/core/knowledge_brain.py:488-504 — get_node() has no classification_level vs clearance enforcement`

### SPEC-019-evidence-chain-of-custody
- AC-019-04 (cross-org isolation: org-A cannot read org-B cases/evidence) has no test. The spec calls it out as an acceptance criterion but no test file covers it.  
  `tests/ — no test_evidence_chain_org_isolation.py or equivalent; test_evidence_integrity_rehash.py lines 1-93 cover only single-org scenarios`
- UI has no page calling /api/v1/evidence-chain/* endpoints. The suite-ui/aldeci-ui-new/src/lib/api.ts calls /api/v1/evidence/bundles (the vault router). AuditorEvidenceHub.tsx and IncidentResponse.tsx reference 'evidence chain' only in description text — zero real API calls to the chain-of-custody router.  
  `suite-ui/aldeci-ui-new/src/lib/api.ts lines 362-369; suite-ui/aldeci-ui-new/src/pages/comply/AuditorEvidenceHub.tsx`

### SPEC-019-to-SPEC-030-batch-audit
- SPEC-023: 4-router shadow collision at /api/v1/playbooks (gap_router, playbook_routes, playbook_router, ir_playbook_runner_router register overlapping paths). /playbooks/builtin returns 404 because the route exists only in the unmounted playbook_router.py. Consolidation is a founder epic.  
  `suite-api/apps/api/ — multiple playbook router files`
- SPEC-027: SCIF posture endpoints (/api/v1/scif/boot, /audit-chain/verify, /hsm/*) remain intentionally public pending a founder decision to gate or keep public.  
  `specs/SPEC-027-auth-hardening.md §2 allowlist`
- SPEC-020: no per-org rate-limit on POST /api/v1/council/convene. Crafted findings can inflate LLM council spend per org (economic DoS).  
  `suite-api/apps/api/council_router.py — /convene endpoint`

### SPEC-020-council-verdict
- No TestClient test exercises POST /convene -> HTTP 503 (AC-020-01). test_real_moat_e2e.py:68 skips correctly when no key but never asserts status_code==503. test_phase3_llm_council.py covers LLMCouncilEngine with mock providers only, not the real HTTP endpoint.  
  `tests/test_real_moat_e2e.py:68-83, tests/test_phase3_llm_council.py`

### SPEC-021-mpte
- No HTTP-level router tests: 210 passing tests are all unit-level. No TestClient tests exercise the actual FastAPI routes for AC-021-01 through AC-021-05 (401 on missing key, 200 health shape, stats shape, tenant isolation).  
  `tests/test_mpte_*.py (5 files, 210 tests — all unit, zero router HTTP tests)`
- UI dead call: suite-ui/aldeci-ui-new/src/lib/api.ts:339 calls mpteApi.comprehensiveScan to POST /api/v1/mpte/campaigns — this route does not exist (real route is POST /api/v1/mpte/scan/comprehensive). Any UI action that triggers a comprehensive scan will get a 404/405.  
  `suite-ui/aldeci-ui-new/src/lib/api.ts:339`
- UI dead call: api.ts:328 calls mpteApi.stats() to GET /api/v1/mpte/monitoring — that path is a POST-only endpoint for setting up continuous monitoring (not a stats GET). Stats should call GET /api/v1/mpte/stats (which exists at mpte_router.py:1348). The UI stats tab will receive 405 Method Not Allowed.  
  `suite-ui/aldeci-ui-new/src/lib/api.ts:328`

### SPEC-022-threat-intel
- GET /api/v1/threat-intel/summary is listed in spec §2 endpoint table but does not exist in threat_intel_router.py. The closest route is /feeds/summary (line 595), which itself contains fabricated fallback counts. AC-022-02 references this path implicitly.  
  `suite-api/apps/api/threat_intel_router.py (missing route), specs/SPEC-022-threat-intel.md:26`
- test_threat_intel_router.py mocks both ThreatIntelCorrelator and ThreatIntelAggregator at module level (lines 37-62) so router tests never exercise real DB/feed behavior. The fabricated ioc_count fallbacks in GET /feeds/status are not caught by any test.  
  `tests/test_threat_intel_router.py:37-62`
- No CI gate for SPEC-022 in .github/workflows/regression-gates.yml. The honest-empty guarantee (REQ-022-01), auth gate (AC-022-06), and feed-status correctness are not enforced on every PR. The existing ingest-first gate (SPEC-029 step) does not cover threat-intel endpoints.  
  `.github/workflows/regression-gates.yml`

### SPEC-023-soar-playbooks
- REQ-023-04 (TrustGraph playbook.executed event) is unimplemented. _get_tg_bus is imported at soar_engine.py:47 but never invoked anywhere in the file — no emit call exists. The close-the-loop correlation requirement has zero code coverage.  
  `suite-core/core/soar_engine.py:47 (import only, never called)`
- No CI gate for SOAR/playbook in regression-gates.yml. Neither test_soar_engine.py nor test_phase9_playbooks.py appear in any blocking step, so SOAR regressions are not caught on PR-to-main.  
  `.github/workflows/regression-gates.yml (no soar/playbook step)`
- AC-023-08 names test_phase9_playbooks.py as the SOAR acceptance test but that file exercises core.playbook_engine + core.compliance_templates (a separate engine), not SOAREngine or soar_router. The SOAR HTTP endpoints have no router-level test coverage under the named AC.  
  `tests/test_phase9_playbooks.py:25-39 (imports PlaybookEngine, not SOAREngine)`
- All playbook action dispatch is simulated — _dispatch_action() unconditionally calls _simulate_action() with fabricated ticket/scan/evidence IDs (TKT-, SCAN-, EVD-). Real connector path is commented out (lines 462-463). Self-declared via simulated=True so honest, but no real SOAR action is ever taken.  
  `suite-core/core/soar_engine.py:446-464 (_dispatch_action), lines 426-444 (_simulate_action)`

### SPEC-024-deception
- No CI gate in regression-gates.yml for SPEC-024. Deception engines are real moats (canary trip detection, honeypot registry) but no blocking test step enforces them on PR-to-main.  
  `.github/workflows/regression-gates.yml (no deception step present)`

### SPEC-025-forensics
- The /api/v1/forensics-readiness/* surface (7 endpoints: sources, assess, plans, execute, complete, stats) has no UI consumer. No .tsx or .ts file in suite-ui/aldeci-ui-new/src calls any /api/v1/forensics-readiness endpoint. The ForensicsHub only surfaces the digital-forensics tab via DigitalForensicsPanel; forensic readiness is entirely invisible in the UI.  
  `suite-ui/aldeci-ui-new/src/ (no file references /api/v1/forensics-readiness)`
- UI stats field mismatch: DigitalForensicsPanel.tsx reads stats.total_cases (line 100) and stats.closed_cases (line 94) but DigitalForensicsEngine.get_forensics_stats() returns open_cases, evidence_items, analyses_completed, avg_case_duration_days — no total_cases or closed_cases keys. The panel silently degrades to computing those from the cases array on the client, so the stat badges show client-computed values rather than authoritative server counts.  
  `suite-ui/aldeci-ui-new/src/components/forensics/DigitalForensicsPanel.tsx:94,100 vs suite-core/core/digital_forensics_engine.py:482-487`

### SPEC-026-exec-reporting
- evidence_router.py declares APIRouter at line 77 with no router-level dependencies=[Depends(api_key_auth)]. The exec-reporting router was explicitly fixed for this (SPEC-026 §8, line 53). The evidence_router relies on app-level mounting for auth injection, but app.py shows no include_router(evidence_router) call with dependencies= — the mounting is conditional (line 1781-1783) and no auth-wrapping grep match was found. REQ-026-01 requires auth on all /api/v1/evidence/export* endpoints; this is unverified.  
  `suite-evidence-risk/api/evidence_router.py:77, suite-api/apps/api/app.py:1781-1783`

### SPEC-028-ui-no-mocks
- Heuristic NO-MOCKS signatures are not CI-enforced: set-but-unused liveX state, useState(MOCK_CONST), frozen hardcoded dates, and fallback-to-mock patterns (data || CONST, .catch(setMock)) are explicitly excluded from test_ui_no_mocks_static.py (per spec §2 and test file header) and rely on human review only. A future page could ship fabricated fallback data that passes all 5 CI tests.  
  `tests/test_ui_no_mocks_static.py:1-18 (scope exclusion note); specs/SPEC-028-ui-no-mocks.md:29-31 (heuristic signatures §2)`

### SPEC-029-analytics-org-scoping
- GET /api/v1/analytics/ root handler (analytics_router.py L1304-1315) calls db.get_dashboard_overview() without passing org_id — it reads org_id from a plain Query param defaulting to 'default', not Depends(get_org_id), so it can return cross-tenant aggregate counts when no org_id is supplied.  
  `suite-api/apps/api/analytics_router.py:1304-1315`
- GET /false-positive-rate (analytics_router.py L1264-1301) uses org_id: Optional[str] = Query(None) (plain query param, not Depends(get_org_id)) and is not covered by SPEC-029 Class A/B list but is an analytics endpoint that can be called without org_id, silently returning cross-tenant FP rates.  
  `suite-api/apps/api/analytics_router.py:1264-1301`

### SPEC-030-network-segmentation
- network_analyzer_router.py uses a single-tenant NetworkAnalyzer (no org_id column in zones/flows/violations tables — acknowledged in spec §8) while network_segmentation_engine.py is multi-tenant. The spec documents this as founder-gated but it means the mounted spec-named router shares zone/flow data across all tenants in multi-tenant deployments.  
  `/Users/devops.ai/fixops/Fixops/suite-core/core/network_analyzer.py lines 217-248 (_init_tables schema has no org_id) + SPEC-030 §8`

### SPEC-032 customer-journey E2E gate
- test_council_never_silently_fabricates skips (not fails) when no LLM API key is present. In standard CI with no OPENROUTER_API_KEY secret, this test always skips — every PR gate passes without ever proving the anti-fabrication invariant. Guard is enforcement-free in the common CI path.  
  `tests/test_real_moat_e2e.py:68-84`
- test_customer_journey_e2e.py runs with FIXOPS_MODE=dev which disables real auth enforcement. The customer journey proves the API flow but not the auth surface a real customer would face. Step 6 also documents a real auth gap: /pipeline/run router uses get_org_id not api_key_auth.  
  `tests/test_customer_journey_e2e.py:60-61`

### domain:access
- cloud_access_security_router.py and network_access_control_router.py have no dedicated router-level HTTP tests. Only engine-unit tests exist (test_cloud_access_security_engine.py, test_network_access_control_engine.py). Router auth, request validation, 404/400 error paths, and response shapes are untested via HTTP.  
  `tests/test_cloud_access_security_engine.py, tests/test_network_access_control_engine.py`
- access_governance_router.py has no dedicated router test file. Only test_bug2_root_list_endpoints.py touches it generically. The SoD detection, entitlement grant/revoke, role assignment, and expiring-entitlements HTTP paths are not covered by any contract test.  
  `suite-api/apps/api/access_governance_router.py`
- access_matrix_router.py and cloud_access_security_router.py define APIRouter without api_key_auth in the constructor or per-route dependencies. Auth is applied only at app.py include_router() time (app.py:5694, app.py:6565 with _verify_api_key). Fragile: if the router is mounted via any other include_router call or tested in isolation, all endpoints become unauthenticated.  
  `suite-api/apps/api/access_matrix_router.py:22, suite-api/apps/api/cloud_access_security_router.py:29-33`

### domain:ai
- No test asserts 401/403 on unauthenticated calls to any /api/v1/ai-orchestrator/* route. The 73 tests in test_ai_orchestrator.py exercise happy-path task creation/execution but never send a request without an API key. The auth gap would not be caught by the test suite.  
  `tests/test_ai_orchestrator.py:1-end (73 tests, zero auth-rejection assertions)`
- None of the ai-domain test files are referenced in regression-gates.yml, ci.yml, or fixops-ci.yml. The ai domain has no CI gate — regressions in these engines/routers will not block PRs to main.  
  `.github/workflows/regression-gates.yml, .github/workflows/ci.yml, .github/workflows/fixops-ci.yml`

### domain:asset
- asset_risk_calculator_router.py POST /assets (create_asset) uses org_id: str = Query(...) at line 72 instead of Depends(get_org_id). This exposes org_id as a query parameter rather than deriving it from the X-Org-ID header, breaking tenant isolation consistency with every other route in this router (which all use Depends(get_org_id)).  
  `suite-api/apps/api/asset_risk_calculator_router.py:72`
- asset_group_engine.py defines bulk_add_members twice (lines 387 and 410, noqa: F811 on second). Python silently discards the first definition. The first implementation also has broken dedup accounting (increments count unconditionally). Dead code and incorrect logic coexist in the same file.  
  `suite-core/core/asset_group_engine.py:387-441`
- asset_group_engine.py remove_member() emits bus.emit('ASSET_DISCOVERED', ...) twice in sequence (lines 255-268, copy-paste error). Duplicate TrustGraph event fires on every member removal, polluting the event stream.  
  `suite-core/core/asset_group_engine.py:255-268`
- asset_inventory_router.py GET / calls inv.get_stats(org_id=org_id) at line 570, but AssetInventory has no get_stats() method — only get_inventory_stats() and get_asset_stats(). The call silently falls into except Exception: stats = {} (line 571), returning empty stats on every request to the index route.  
  `suite-api/apps/api/asset_inventory_router.py:570 vs suite-core/core/asset_inventory.py:1168`

### domain:attack
- No spec exists for attack_chain (kill-chain registry), attack_simulation (BAS campaigns), or attack_surface (EASM) despite all three having real engines, multiple routers, and existing tests. These high-value moat capabilities are invisible to the spec governance system — no CI gate can enforce correctness, auth, or honest-empty behavior for these domains.  
  `specs/INDEX.md (no row for attack_chain, attack_simulation, attack_surface); suite-core/core/attack_chain_engine.py; suite-core/core/attack_simulation_engine.py; suite-core/core/attack_surface_engine.py`
- attack_surface_router.py carries the comment 'Auth is applied centrally by app.py' (line 6) but has zero per-route or router-level Depends(). It is mounted with _verify_api_key in ctem_app.py:1247-1250 at runtime, providing protection. However if this router were ever mounted elsewhere (e.g. in a sub-app refactor or test harness) without the mount-level dependency, it would be fully open. Violates SPEC-027 self-documenting auth pattern.  
  `suite-api/apps/api/attack_surface_router.py:1-6 (no Depends anywhere in file); suite-api/apps/api/sub_apps/ctem_app.py:1247-1250`
- No CI gate covers the attack domain. test_attack_chain_engine.py (35 tests), test_attack_surface_engine.py (30 tests), test_attack_simulation_engine.py (31 tests), test_attack_simulation_unit.py (63 tests) are not in the Beast Mode 13-file smoke set and no .github/workflows entry references them. A regression in any attack engine would not be caught before merge.  
  `tests/test_attack_chain_engine.py; tests/test_attack_simulation_engine.py; tests/test_attack_surface_engine.py; .github/workflows/ (no attack domain entries found)`

### domain:compliance
- _FRAMEWORK_CONTROLS dict (lines 83-151) defines 48 hardcoded control definitions across 7 frameworks (SOC2, ISO27001, NIST_CSF, PCI_DSS, HIPAA, GDPR, CIS) but is NEVER referenced anywhere else in the file. Real scan results come exclusively from checkov output parsed by _parse_checkov_output (line 425). This dead code misleads maintainers and is a latent stub-injection risk if a future developer wires it in instead of the real checkov path.  
  `suite-core/core/compliance_scanner_engine.py:83-151`
- No HTTP-level (TestClient) router integration tests exist for compliance-mapping, compliance-calendar, compliance-workflow, or compliance-scanner router paths. Only engine-unit tests exist. The single compliance-mapping reference is a D3FEND-specific test (test_d3fend_real_data.py:1). Router auth enforcement, error-handling, and org_id isolation are untested at the HTTP layer for these 4 routers.  
  `tests/ — no test_compliance_*_router.py files for mapping/calendar/workflow/scanner`

### domain:container
- container_runtime_security_router.py:33-42 silent auth-drop: _AUTH_DEP=[Depends(_api_key_auth)] on success, _AUTH_DEP=[] on import failure. If auth_deps import fails at boot, all 10 endpoints under /api/v1/container-runtime silently become unauthenticated with no operator-visible error.  
  `suite-api/apps/api/container_runtime_security_router.py:33-42`
- No dedicated container spec and no CI gate. SPEC-013 explicitly excludes container scanning. regression-gates.yml has no container step. Auth enforcement, tenancy isolation, and no-mocks invariants for this domain are not enforced in CI.  
  `specs/ (no SPEC-container*.md), .github/workflows/regression-gates.yml`
- container_security_connector_router.py GET /health and GET /status (lines 112-119) return full import_error exception string to unauthenticated callers. APIRouter() at line 46 has no dependencies=; those routes carry no per-route Depends, so mount-level _verify_api_key at app.py:3500 does not protect them.  
  `suite-api/apps/api/container_security_connector_router.py:46-49, 112-119`

### domain:data
- data_classification_engine.py scan_asset() (line 356-424) is a stub scanner — it only performs a static dictionary lookup (_ASSET_PII_HEURISTICS, line 372) based on asset_type. Docstring explicitly says 'Simulate a PII scan'. No real content scanning, no regex, no ML model call. Returns identical results for every asset of the same type regardless of actual content.  
  `/Users/devops.ai/fixops/Fixops/suite-core/core/data_classification_engine.py:356-424`
- data_lake_security_engine.py run_security_assessment() line 245 has dead code: 'if cls == "confidential" and cls == "public"' is logically impossible (a string cannot equal two different literals simultaneously). The 'confidential_data_public' finding and its 35-point deduction are never triggered. Security score is silently wrong for confidential+public stores.  
  `/Users/devops.ai/fixops/Fixops/suite-core/core/data_lake_security_engine.py:245-251`
- No test coverage for data_security_router (/api/v1/data) endpoint behaviour. No test file for data_residency_router (/api/v1/data-residency). These are the two routers with confirmed or suspected auth gaps.  
  `/Users/devops.ai/fixops/Fixops/tests/ (missing: test_data_security_router.py, test_data_residency_router.py)`

### domain:deception
- deception_router.py wraps api_key_auth import in try/except ImportError (lines 22-29): on import failure _AUTH_DEP=[] and all 7 /api/v1/deception/* endpoints become unauthenticated. The other two deception routers (deception_analytics_router.py:27, threat_deception_management_router.py:24) use hard imports with no fallback — deception_router.py should match that pattern.  
  `suite-api/apps/api/deception_router.py:22-29`
- No automated test asserts 401 on missing X-API-Key for any /api/v1/deception/* endpoint. SPEC-024 AC-024-07 claims 'verified' but the only HTTP test (test_deception_honeypot_list.py:123) overrides auth with lambda: None. A regression in auth wiring would not be caught by any test.  
  `tests/test_deception_honeypot_list.py:110-136`

### domain:forensics
- network_forensics_router GET / (line 54) uses `org_id: str = Query("default")` instead of `Depends(get_org_id)`. An authenticated caller who omits ?org_id= receives captures scoped to the literal string 'default', not their real tenant. All other endpoints on this router correctly use Depends(get_org_id). Auth is not bypassed (router-level dep at line 13 covers all routes) but tenant isolation is broken for this specific endpoint.  
  `suite-api/apps/api/network_forensics_router.py:54`
- network_forensics_router and NetworkForensicsEngine have no spec. SPEC-025 explicitly lists only digital_forensics_router and forensics_readiness_router in its Routers section. The /api/v1/network-forensics prefix, its data contracts, honest-empty requirements, and tenancy requirements are undocumented in any spec file.  
  `suite-api/apps/api/network_forensics_router.py, suite-core/core/network_forensics_engine.py`
- Zero router-level (HTTP/TestClient) tests for digital_forensics_router and forensics_readiness_router. All three forensics test files test only engine internals directly. Router wiring, Pydantic request model validation, HTTP status codes (400/404/422), and 401 behavior on these two spec-covered routers are untested. network_forensics_router has partial HTTP coverage only in test_empty_endpoints_batch7.py and test_empty_endpoints_2026_04_27.py.  
  `tests/test_digital_forensics_engine.py, tests/test_forensics_readiness_engine.py`

### domain:incident
- incident_response_router auth is conditional: api_key_auth is wrapped in try/except (lines 24-30) and _router_deps is empty list if import fails (line 56). If auth_deps import ever fails at boot, /api/v1/incidents becomes fully unauthenticated with no error. All other incident routers use unconditional direct import — this router is the outlier.  
  `suite-api/apps/api/incident_response_router.py:24-57`
- MTTD (Mean Time to Detect) is a hardcoded constant stub: avg_mttd = 0.0 with comment '# MTTD: placeholder 0 (no pre-detection timestamp)'. This value is persisted into metric_snapshots table and returned to API callers as if it were a real metric. Should return None/null when no detection-timestamp data exists (honest-empty), not a fabricated zero.  
  `suite-core/core/incident_metrics_engine.py:344-345`
- incident_response_engine.py (SQLite WAL engine with full CRUD, tasks, artifacts, SLA) has zero router exposure. The incident_response_router.py imports core.incident_response (IncidentResponseManager, older Pydantic-model-based engine) instead. The newer engine is dead weight with no HTTP surface.  
  `suite-core/core/incident_response_engine.py (entire file), suite-api/apps/api/incident_response_router.py:35-55`
- No router-level HTTP tests for 7 of 9 incident routers: incident_triage_router, incident_orchestration_router, incident_metrics_router have zero HTTP tests. incident_comms_router, incident_cost_router, incident_kb_router, incident_lessons_router each have GET / only (test_ir_empty_endpoints.py). Mutation paths (POST/PUT/PATCH/DELETE) are entirely untested at the HTTP layer.  
  `tests/test_ir_empty_endpoints.py (covers 4 routers GET / only); no test_incident_triage_router.py, test_incident_orchestration_router.py, or test_incident_metrics_router.py exist`

### domain:llm
- council_enhanced_router.py has no file-level auth. Line 9 explicitly states 'no auth required (internal-facing)'. Auth only injected at platform_app.py:1489 mount time. Any mount outside platform_app leaves feedback ingestion and calibration data fully open.  
  `suite-api/apps/api/council_enhanced_router.py:9 / suite-api/apps/api/sub_apps/platform_app.py:1489`
- llm_monitor_router.py has no file-level auth (grep confirmed 0 Depends/api_key_auth hits) and no dedicated test file. All four endpoints (/analyze, /scan/prompt, /patterns, /health) rely entirely on platform_app.py:1647 for protection. No test verifies the auth-at-mount path.  
  `suite-api/apps/api/llm_monitor_router.py:1-72 / suite-api/apps/api/sub_apps/platform_app.py:1646-1647`
- llm_explanation_engine.py hardcodes 'gpt-5' model name at lines 105, 112, 119, 126. Model does not exist in OpenAI API; ChatGPTClient init silently falls to rule-based fallback with no exception or warning surfaced. No dedicated test file.  
  `suite-core/core/services/enterprise/llm_explanation_engine.py:105,112,119,126`
- vllm_router.py has no file-level auth; relies entirely on platform_app.py:1721 mount-time Depends+admin:all. /health (lines 80-81) returns hardcoded {'status':'healthy'} without probing actual vLLM/Ollama backend state, making it useless as an operational health signal.  
  `suite-api/apps/api/vllm_router.py:78-81 / suite-api/apps/api/sub_apps/platform_app.py:1720-1721`

### domain:network
- network_segmentation_router has no router-level dependencies= parameter — auth is per-endpoint only. Any future endpoint added without explicit annotation will be unauthenticated by default. Additionally there is no GET / root handler, which returns 404 for the router index path.  
  `suite-api/apps/api/network_segmentation_router.py:29-33`
- Zero spec coverage for 8 engines and 9 routers beyond SPEC-030. No honest-empty invariant tests, no ingest-first contracts, no CI gate for NetworkAccessControlEngine, NetworkAnomalyEngine, NetworkForensicsEngine, NetworkMonitoringEngine, NetworkSegmentationEngine, NetworkThreatEngine, NetworkTopologyEngine, NetworkTrafficEngine, NDREngine.  
  `specs/ (only SPEC-030 exists for network domain); suite-core/core/network_*_engine.py and suite-core/core/network_security.py`
- cspm_app.py and ctem_app.py mount seven network routers bare (app.include_router with no dependencies=) while sibling routers in the same register functions receive _verify_api_key injection. Structural drift risk — inconsistent auth enforcement pattern.  
  `suite-api/apps/api/sub_apps/cspm_app.py:183,269,312,371 and suite-api/apps/api/sub_apps/ctem_app.py:816,926,1044`

### domain:risk
- risk_router.py (prefix /risk, 8 endpoints: GET /, /component/{slug}, /cve/{cve_id}, /overview, /score, /scores, /health, /status) is imported as risk_router_ext at app.py:1789-1791 but never passed to any app.include_router() call. The entire /risk/* surface is dead and unreachable in production. The file also has zero Depends(api_key_auth) on any route — if ever mounted it would be fully unauthenticated.  
  `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/app.py:1789-1791 and /Users/devops.ai/fixops/Fixops/suite-api/apps/api/risk_router.py:22,57,85,98,129,167,190,215,221`
- risk_quantification_router.py (prefix /api/v1/risk-quantification) uses org_id: str = Query('default', ...) on all 9 endpoints instead of Depends(get_org_id). Callers who omit org_id silently operate on the 'default' org, bypassing tenant isolation.  
  `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/risk_quantification_router.py:93,98,111,132,152,161,178,187,204`
- developer_risk_profiler.py has no dedicated test file (no test_developer_risk*.py exists) and no router — a core engine with no API surface and no test coverage.  
  `/Users/devops.ai/fixops/Fixops/suite-core/core/developer_risk_profiler.py`
- 13 of 14 risk sub-capabilities have no spec: risk_scenario, risk_treatment, risk_quantification, risk_acceptance, risk_register_engine, vendor_risk, supply_chain_risk, application_risk, identity_risk, asset_risk_calculator, composite_risk_scorer, security_dependency_risk, vuln_risk_scoring, developer_risk_profiler. Only SPEC-018 (risk_aggregator) exists for the entire domain — no CI behavioral gate on any of these.  
  `/Users/devops.ai/fixops/Fixops/specs/ (only SPEC-018-risk-aggregator.md)`

### domain:security
- 48 of 58 security routers have no dedicated router-level test file. Engine unit tests provide indirect logic coverage but do not exercise HTTP-layer concerns: status codes, request validation, tenant scoping, or 401/403 rejection on any of these routers.  
  `tests/ — missing test_security_*_router.py for security_architecture_review_router, security_automation_router, security_awareness_gamification_router, security_awareness_program_router, security_benchmark_router, security_budget_router, security_capacity_planning_router, security_champions_router, security_change_management_router, security_chaos_router, security_culture_router, security_data_pipeline_router, security_dependency_mapping_router, security_dependency_risk_router, security_event_correlation_router, security_event_timeline_router, security_exception_router, security_exception_workflow_router, security_gap_analysis_router, security_health_router, security_health_scorecard_router, security_investment_router, security_kpi_router, security_maturity_router, security_metrics_aggregator_router, security_metrics_dashboard_router, security_okr_router, security_operations_metrics_router, security_playbook_router, security_posture_benchmarking_router, security_posture_history_router, security_posture_maturity_router, security_posture_reporting_router, security_posture_scoring_router, security_posture_trend_router, security_program_maturity_router, security_query_router, security_questionnaire_router, security_registry_router, security_roadmap_router, security_scoreboard_router, security_service_catalog_router, security_tabletop_router, security_telemetry_router, security_tool_inventory_router, security_training_effectiveness_router`
- No test_security_* unit tests are in the CI regression-gates.yml pipeline. The 60+ security test files only run in the broad T3 sweep (periodic/pre-release). A regression in any security engine would not block a PR merge to main.  
  `.github/workflows/regression-gates.yml — owasp-lockdown job has no test_security_* entries; security tests absent from all 8 gate steps`

### domain:supply
- supply_chain_router.py defines _AUTH_DEP with a try/except fallback to [] (lines 36-43): if auth_deps import fails at startup the router has zero auth. It is mounted at aspm_app.py:236 with no mount-level dependencies=, so ImportError at boot = all /api/v1/supply-chain/* endpoints unprotected. There is no startup assertion or test that verifies the import succeeds.  
  `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/supply_chain_router.py:36-43 and /Users/devops.ai/fixops/Fixops/suite-api/apps/api/sub_apps/aspm_app.py:235-237`
- No spec exists for the 5 runtime supply-chain engines (typosquatting detection, risk engine, intel engine, attack detection, monitoring). SPEC-009 covers only the build/lockfile. The runtime capabilities — supplier registry, SBOM ingestion, behavioral risk scoring, quarantine queue, malicious signal ingestion — have no acceptance criteria and no CI gate. Any regression has no spec to detect it against.  
  `/Users/devops.ai/fixops/Fixops/specs/ (only SPEC-009-supplychain-lockfile.md exists)`
- supply_chain_monitoring_router.py and supply_chain_attack_detection_router.py are both mounted in sub-apps without mount-level dependencies= (aspm_app.py:285, ctem_app.py:708). Both carry router-level dependencies=[Depends(api_key_auth)] so are currently protected, but the inconsistency makes auth audits unreliable and creates risk if router-level dep is ever refactored away.  
  `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/sub_apps/aspm_app.py:285 and /Users/devops.ai/fixops/Fixops/suite-api/apps/api/sub_apps/ctem_app.py:708`
- No CI gate in .github/workflows/ci.yml covers supply-chain engine tests. The test files exist (test_supply_chain_*.py) but are not in the Beast Mode T1 smoke set or any named CI gate job. A supply-chain engine regression would only be caught by the broad T3 periodic suite.  
  `/Users/devops.ai/fixops/Fixops/.github/workflows/ci.yml`

### domain:threat
- _hunt_behavior_pattern() explicitly simulates SIEM event matching: comment says 'Simulate process event matching — in production this queries SIEM events', uses variable named simulated_hits. Reachable via POST /api/v1/hunting/sessions/{id}/run with hunt_type=behavior_pattern. Not a full stub (queries hunt_results history) but fabricates structure for non-existent process event log integration.  
  `suite-core/core/threat_hunting_engine.py:516-545`
- threat_correlation_router.py uses a try/except ImportError fallback: if auth_deps import fails at runtime, api_key_auth() returns string 'anon' (not an enforcing dependency). Any import-order or circular-import failure silently opens /api/v1/threat-correlation/* to unauthenticated access.  
  `suite-api/apps/api/threat_correlation_router.py:18-22`
- threat_feed_subscription_router.py, threat_intel_sharing_router.py, and threat_modeling_router.py have NO router-level or endpoint-level api_key_auth. Auth applied only at sub-app mount time (ctem_app.py:944, app.py:7059-7060, app.py:7199-7200). Any future direct mount (test harness, standalone) exposes all endpoints unauthenticated with no router-level defense-in-depth.  
  `suite-api/apps/api/threat_feed_subscription_router.py:34 | suite-api/apps/api/threat_intel_sharing_router.py:24-27 | suite-api/apps/api/threat_modeling_router.py:25`
- test_ironclad_authz.py TestThreatIntelNoAuth class tests /api/v1/threat-sharing/indicators and /api/v1/threat-modeling-pipeline/ for 401 enforcement but this file is NOT in .github/workflows/regression-gates.yml — the CI auth gate runs only test_no_unauthenticated_endpoints.py. Threat-specific ironclad assertions are not CI-gated.  
  `tests/test_ironclad_authz.py:459-470 | .github/workflows/regression-gates.yml:56-64`

### domain:threat-intel
- threat_modeling_router.py has NO self-auth (no api_key_auth import, no router-level dependencies=, no per-endpoint Depends). Currently safe only because both mount sites (app.py:7200, ctem_app.py:1230) inject _verify_api_key. Any future re-mount without injection silently opens all STRIDE threat modeling endpoints.  
  `suite-api/apps/api/threat_modeling_router.py:25`
- threat_intel_sharing_router.py has NO self-auth (APIRouter at line 24 has no dependencies=, no api_key_auth imported). Protected only by mount-site injection at app.py:7060 and ctem_app.py:404. STIX bundle export/import and sharing group endpoints are fragile.  
  `suite-api/apps/api/threat_intel_sharing_router.py:24`
- threat_feed_subscription_router.py has NO self-auth (APIRouter at line 34 has no dependencies=, comment says Auth: _verify_api_key but no per-endpoint Depends either). Single mount at ctem_app.py:944 injects _verify_api_key. Feed subscription CRUD is fragile.  
  `suite-api/apps/api/threat_feed_subscription_router.py:34`

### domain:webhook
- No dedicated webhook spec. SPEC-011/015/017/027 mention webhooks tangentially only. No normative definition of auth contract, SSRF rules, DLQ replay authorization, or HMAC key rotation requirements.  
  `specs/ — grep -il webhook returns SPEC-011, SPEC-015, SPEC-017, SPEC-027 only`

## Low gaps (49) — grouped by capability

**Connector domain — engines (connectors.py, cloud_connectors.py, security_connectors.py, connector_ingestion_scheduler.py, suite-core/connectors/pull_connector.py) and routers (connectors_router, connector_routes, container_security_connector_router, admin_connectors_router, cspm_connector_router, cloud_connectors_router, threat_intel_connector_router, 11 vendor live routers)**: siem_connector_router, edr_connector_router, sentinelone_connector_router moved to ctem_app.py (app.py:6223,6230,6341) b · 8 test_connector_*_live.py files require real external credentials and are excluded from all CI gates. No mock-mode path
**SPEC-005-airgap-enforced-default**: HF_DATASETS_OFFLINE env var set in app.py:2219 area but the grep shows only TRANSFORMERS_OFFLINE and HF_HUB_OFFLINE at l
**SPEC-005b-graph-populate**: The UI's blast_radius field in AttackPaths.tsx:181 includes a client-side fabrication fallback: `blast_radius: (p.blast_
**SPEC-006b-crypto-hardening**: crypto_posture() (REQ-006b-05, AC-006b-03) is not exposed via any HTTP endpoint. The function exists only in suite-core/ · ML-DSA key-at-rest tests (TestMLDSAKeyAtRest, 2 tests) are skipped whenever dilithium_py is not installed (CI environmen
**SPEC-009-supplychain-lockfile**: SBOMManagement.tsx line 735 has a silent catch fallback ('Silently fall back to mock components if API fails') on the se
**SPEC-013-cspm**: OCI, Alibaba, and IBM provider adapters in cspm_engine.py (OCIProviderAdapter line 1037, AlibabaProviderAdapter line 107 · SPEC-007 tenancy gap documented in spec section 8: cloud_posture_router.py takes org_id from query params with default='
**SPEC-014-auth-tenancy**: SAML SP-initiated flows exist in auth_router.py but are not wired to a real IdP and no test confirms they return a corre
**SPEC-015-connectors**: No UI component calls POST /api/v1/connectors/register, POST /create-ticket, DELETE /{name}, or GET /{name}/health. Only
**SPEC-016-scif-stack-fit**: No UI page calls the SPEC-016 /api/v1/wiz, /prisma, /closed-loop, /blackduck, or /design-context endpoints — operators c
**SPEC-019-evidence-chain-of-custody**: Double-auth on router mount: the router already declares api_key_auth as a router-level dependency (evidence_chain_route
**SPEC-020-council-verdict**: Two separate council routers coexist: council_router.py at /api/v1/council (spec-named) and llm_council_router.py at /ap
**SPEC-021-mpte**: mpte_router.py:644-650 references ExploitabilityLevel.CONFIRMED, .LIKELY, .POSSIBLE, .NOT_EXPLOITABLE — none of these me
**SPEC-022-threat-intel**: ThreatActor model uses field name associated_campaigns (threat_intel_correlator.py line 61) but list_campaigns endpoint 
**SPEC-024-deception**: deception_router.py auth dependency uses a try/except import fallback: if auth_deps import fails at module load, _AUTH_D
**SPEC-027-auth-hardening**: cloud_native_security_router.py has a dead local `def api_key_auth(): return True` (line 34) that endpoint-level Depends · SCIF router mounted at app.py:2351 with no auth dependencies (app.include_router(_scif_router) bare). Spec section 2 rec · 219 of 813 routers (27%) have no api_key_auth or verify_api_key reference at file level. Most receive auth via app.py in
**SPEC-028-ui-no-mocks**: 90 of 299 page files have no direct apiFetch/fetch/useQuery call and are not individually verified by the static gate — 
**SPEC-029-analytics-org-scoping**: decisions table has no org_id column in its DDL (analytics_db.py L64-75). Scoping goes via subquery through findings.org · Only /dashboard/top-risks and /dashboard/trends are wired in the UI (src/lib/api.ts L223-224). The majority of SPEC-029 
**SPEC-032 customer-journey E2E gate**: test_customer_journey_e2e.py has no SPEC-032 pytestmark or docstring reference — traceability from spec to test relies s
**domain:access**: cloud_access_security_router.py is missing a root GET '/' endpoint. Routes begin at /apps, /events, /policies, /stats —  · No spec document covers any access subdomain. All 9 engines/routers are real but spec-uncovered — behavioural contracts 
**domain:ai**: No spec exists for ai_governance, ai_powered_soc, ai_security_advisor, ai_orchestrator, or ai_code_scanner capabilities.
**domain:asset**: No router-layer HTTP tests exist for any asset router. All test_asset_*.py files test engines directly. Auth enforcement
**domain:attack**: AttackSimulationEngine (in-memory singleton, attack_simulation_engine.py:1135-1143) stores campaigns and scenarios in pr
**domain:compliance**: CI Beast Mode gate (ci.yml:590-606, 13 named test files) does not include any compliance-specific test files. Compliance · _REMEDIATION_TEMPLATES dict (lines 153-158) uses hardcoded SLA string templates (critical=24h, high=7d, medium=30d, low=
**domain:container**: ui_alias_router.py container_security_alias runs raw SELECT * FROM container_findings (line 178) and SELECT COUNT(*) FRO
**domain:data**: No spec exists for the domain:data capability set. Zero entries in specs/ directory cover data classification, data gove
**domain:deception**: /api/v1/threat-deception (8 routes, threat_deception_management_router.py, mounted ctem_app.py:841-845) has no spec cove · No HTTP-layer (TestClient) tests for any of the 10 /api/v1/deception-analytics/* endpoints — only engine unit tests exis
**domain:forensics**: Forensics tests are not included in the Beast Mode 13-file smoke set (CLAUDE.md). They run only via the ci.yml wildcard 
**domain:incident**: No CI gate for the incident domain. Zero references to incident test files in any of the 15 .github/workflows/*.yml file
**domain:llm**: LLM-domain unit tests (test_llm_firewall_router, test_llm_guard_router, test_llm_loop_metrics, test_vllm_router_unit, te
**domain:network**: network_security_router uses the same try/except ImportError fail-open fallback (_AUTH_DEP = [] on failure). Mitigated i
**domain:risk**: identity_risk_router.py and application_risk_router.py are mounted without mount-level dependencies=[Depends(_verify_api · vendor_risk_engine.py KNOWN_BREACHES is a hardcoded static dict of named incidents (SolarWinds, Log4j, Okta, etc.) with 
**domain:security**: security_investment_router.py defines a dead _verify_api_key() stub at lines 46-51 that returns the api_key_auth functio · 49 of 50 security engines and 57 of 58 security routers have no covering spec. Only security_findings_engine/router is d
**domain:supply**: supply_chain_engine.py typosquatting uses a small embedded known-package allowlist (~50 npm, ~60 pypi, ~11 maven entries
**domain:threat**: 30 of 31 threat routers have zero spec coverage. SPEC-022 covers only threat_intel_router.py. Uncovered high-value surfa · No router-level HTTP integration tests for threat_feed_subscription_router (/api/v1/feed-subscriptions), threat_intel_sh
**domain:threat-intel**: No HTTP-layer auth tests for the 30 uncovered threat routers. test_threat_intel_router.py uses engine mocks and tests ze · No threat-intel-specific CI gate in regression-gates.yml. The 43 threat test files run only in the broad T3 suite, not i
**domain:webhook**: _build_test_fire_payload (webhook_notifications_router.py:562-572) embeds hardcoded sample data: finding_id='test-findin
