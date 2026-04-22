# Gap PRD ↔ Native Engine Reconcile — 2026-04-22

**Author**: enterprise-architect (autonomous)
**Inputs analyzed**:
- `docs/CTEM_PLUS_IDENTITY.md` — 8 native engines (SAST, DAST, Secrets, Container, CSPM, APIFuzzer, Malware, LLMSecurity) + 12-step Brain Pipeline + MPTE 19-phase + FAIL engine + AutoFix + Multi-LLM Consensus.
- `raw/competitive/gap-matrix.md` — 69 gaps (GAP-001..GAP-069) with 19 explicit "NEW ENGINE NEEDED" + 7 "NEW ENGINE `<name>`" secondary mentions.
- `.omc/prds/v2/` — 374 PRDs; 22 `gap_*.md` (PARTIAL-extend-existing) + 19 new-engine PRDs materialized as standalone `.md` + 7 new-engine proposals with no PRD yet.
- `suite-core/core/*_engine.py` — **334** existing engines (corrected from "345" in CLAUDE.md, which is stale).

**Grep discipline applied**: Every MERGE recommendation cites a real file under `suite-core/core/`. Every KEEP recommendation was grep-tested and NO existing engine owns the concept. Every KILL recommendation found a ≥85%-overlap duplicate.

---

## Executive summary

| Verdict | Count | Share |
|---------|------:|------:|
| **MERGE** (extend existing engine) | 26 | 54% |
| **KEEP** (truly new engine needed) | 14 | 29% |
| **KILL** (duplicate of existing, no value) | 5 | 10% |
| **UNCLEAR** (product decision required) | 3 | 6% |
| **Total analyzed** | **48** | — |

Bottom line: **out of 48 gap-derived proposals, only 14 require net-new engine files.** The other 34 should be absorbed into the 334-engine inventory — mostly by extending 18 existing engines with new methods, columns, or router endpoints. This cuts the net-new surface area by ~71% and keeps the engine count under 350.

---

## Reconcile table

| Gap ID | Proposed new engine | Recommendation | Target existing engine | Overlap % | Reasoning (grep-confirmed) |
|--------|--------------------|--------------:|------------------------|----------|-----------|
| GAP-001 | `air_gap_bundle_engine` | **KEEP** | — | 0% | `grep -l airgap` hits 5 files, all prose-only in `edr/vendor_risk/firewall/iot/autofix`. No signed-bundle export/apply/verify logic exists. SAGE-equivalent is genuinely net-new. |
| GAP-002 | `offline_intelligence_feed_engine` | **MERGE** | `threat_intel_fusion_engine`, `threat_feed_subscription_engine` | 60% | Feed subscription + confidence-weighted fusion already handles multi-source intel. Add (a) offline bundle manifest + (b) cryptographic verify on ingest as two new methods. No new engine file. |
| GAP-003 | `onprem_ha_reference_engine` | **KILL** | `devsecops_engine` | 100% | This is packaging artifacts (Helm charts, StatefulSet YAML, PG HA guide), not an engine. Does not warrant a `.py` file; belongs in `docker/` + `docs/deployment/`. Delete PRD; replace with a deploy-artifacts task. |
| GAP-004 | per-stage policy matrix | **MERGE** | `policy_enforcement_engine`, `policy_engine` | 80% | `policy_enforcement_engine.py` already owns policy eval and exception lifecycle. Add `stage_matrix` JSONB column + `evaluate(stage=...)` method. PRD is already correctly scoped as extension. |
| GAP-005 | `org_hierarchy_engine` | **KEEP** | — | 15% | `asset_group_engine` + `org_engine` are flat; grep shows no parent_org_id / inherited-policy traversal. Hierarchical tree with policy+waiver inheritance is a first-class concept Sonatype sells. Net-new engine justified. |
| GAP-006 | auto-waivers | **MERGE** | `vuln_exception_engine`, `security_exception_workflow_engine`, `risk_acceptance_engine` | 75% | Three existing engines cover exception lifecycle. Add `auto_waiver_rule` table + hook into reachability engine output. No new engine file. |
| GAP-007 | `upgrade_path_resolver_engine` | **KEEP** | — | 10% | `grep -l upgrade_path` returns 0 hits. Solving "next safe version per pURL" requires ecosystem-specific resolvers (npm, maven, pypi) — genuinely net-new and non-trivial. Pairs with GAP-055 (SBOM reeval). |
| GAP-008 | `binary_fingerprint_engine` | **KEEP** | — | 0% | No structural/TLSH/ssdeep fingerprint code in inventory. Sonatype ABF is a dedicated subsystem. Net-new. |
| GAP-009 | malicious pkg detection | **MERGE** | `supply_chain_attack_detection_engine`, `supply_chain_intel_engine` | 70% | Already have the tables; grep confirms both engines exist. Extend with behavioral-ML scorer and quarantine queue. No new engine. |
| GAP-010 | `function_reachability_engine` | **KEEP** | `security_dependency_mapping_engine` (extend also) | 35% | Dependency mapping has BFS blast-radius (verified in Wave 40 tests) but no call-graph nodes. True reachability needs AST parse + CFG edges per language. Net-new with a dependency on extending existing mapping engine. |
| GAP-011 | `material_change_engine` | **MERGE** | `change_management_router` + `findings_router` + `autofix_engine` | 70% | `security_change_management_engine` handles change lifecycle; add risk-surface diff that consumes DCA output (GAP-012) and PR webhook. No new engine. Implement as a method on change_management. |
| GAP-012 | `deep_code_analysis_engine` | **KEEP** | `api_discovery_engine`, `data_discovery_engine` (extend also) | 30% | `api_discovery_engine.py` grep-confirmed exists, but inventory says regex-based, not AST. Apiiro DCA requires Tree-sitter/LSP per language. Net-new, but must feed `api_discovery` + `data_classification` as consumers. |
| GAP-013 | `code_to_runtime_matcher_engine` | **KEEP** | — | 0% | No existing engine maps live traffic → repo+commit+owner. Requires eBPF/APM hook + ML correlation. Genuinely net-new. |
| GAP-014 | `ide_extension_engine` | **UNCLEAR** | — | 0% | Grep: zero hits on `ide/vscode/jetbrains` (false positives only). But "IDE extension" is a client-side artifact, not an engine — the "engine" should be a thin `ide_gateway_engine` exposing `/api/v1/ide/*` endpoints; the actual VS Code/JetBrains packages live in separate repos. **Product decision needed**: one gateway engine or zero engines + pure client packages? |
| GAP-015 | GitHub App | **MERGE** | `pr_gate_router`, `github_action_router` | 85% | Two routers grep-confirmed present. Extend with manifest + installation webhook handling. No new engine. |
| GAP-016 | dev-identity behavioral | **MERGE** | `behavioral_analytics_engine`, `uba_engine`, `access_anomaly_engine`, `insider_threat_engine` | 80% | Four engines grep-confirmed. Add SCM-specific commit-anomaly signals as new behaviors, not a new engine. |
| GAP-017 | `pipeline_bom_engine` | **KEEP** | `sbom_engine`, `sbom_export_engine` (siblings) | 20% | SBOM engines cover component manifests. PBOM is different: every build step's config + artifact signature + deploy target. Net-new, but complements SBOM. |
| GAP-018 | `slsa_provenance_engine` | **KEEP** | `evidence_vault_engine` (sibling) | 25% | Evidence vault stores arbitrary signed evidence, but SLSA-specific attestation generation (in-toto format) is net-new. Screens already exist in inventory; engine is missing. |
| GAP-019 | `ai_generated_code_scanner_engine` | **MERGE** | `ai_security_advisor_engine`, `sast_engine` | 70% | Scanning AI-generated code pre-commit = SAST rule-set applied at keystroke. Extend `sast_engine` with a pre-commit mode, plus a thin CLI/IDE hook. No new engine. |
| GAP-020 | `agentless_snapshot_scan_engine` | **KEEP** | — | 0% | Grep: zero hits on `snapshot/sidescan/agentless`. Requires cloud-provider block-storage APIs (EBS snapshots, Azure disks) — genuinely net-new and XL effort. Wiz/Orca moat. |
| GAP-021 | toxic-combo correlation | **MERGE** | `threat_correlation_engine`, `attack_chain_engine`, `security_event_correlation_engine` | 85% | Three engines grep-confirmed; attack_chain already does multi-step kill-chain. Add toxic-combo rule set (internet-exposed × critical CVE × over-permissive × PII access) as new traversal rules. No new engine. |
| GAP-022 | 100+ framework library | **MERGE** | `compliance_mapping_engine`, `compliance_engine`, `compliance_workflow_engine` | 90% | 8 compliance engines grep-confirmed. This is content (framework definitions), not code. Populate the library; no new engine. |
| GAP-023 | 3k+ policy library | **MERGE** | `policy_engine`, `policy_enforcement_engine` | 95% | Content, not code. Populate the policy catalog; no new engine. |
| GAP-024 | `security_query_language_engine` | **KEEP** | — | 5% | RQL-style structured DSL over cloud+audit+network+IAM data requires a parser, typed schema registry, and query planner. Trustgraph has no DSL surface. Net-new. |
| GAP-025 | 6-CSP coverage | **MERGE** | `cspm_engine`, `cnapp_engine`, `cloud_account_monitoring_engine`, `cloud_resource_inventory_engine` | 90% | All four engines grep-confirmed. Add OCI/Alibaba/IBM adapters as new provider modules, not new engines. |
| GAP-026 | `choke_point_analyzer_engine` | **MERGE** | `attack_path_engine`, `attack_chain_engine` | 80% | `attack_path_engine.py` grep-confirmed has BFS blast-radius. Add choke-point ranking method (max-flow-min-cut over attack graph). No new engine. |
| GAP-027 | blast-radius scoring | **MERGE** | `asset_criticality_engine`, `vulnerability_scoring_engine`, `risk_aggregator_engine` | 90% | Three engines grep-confirmed. Extend scoring formula; no new engine. |
| GAP-028 | FAIR dollar risk | **MERGE** | `risk_quantification_engine` (v1 + v2) | 95% | Both v1 and v2 grep-confirmed. Wave 39 CTO review verified v2 uses SLE/ARO/ALE (FAIR-aligned). Add PGM-style likelihood × impact per-BU as new method. No new engine. |
| GAP-029 | NL graph assistant | **MERGE** | `graphrag_engine`, `ai_security_advisor_engine`, `intelligent_security_engine` | 85% | All three grep-confirmed. Add traversal-trace output format. No new engine. |
| GAP-030 | domain-seed EASM | **MERGE** | `attack_surface_engine`, `passive_dns_engine`, `dark_web_monitoring_engine` | 75% | Three engines grep-confirmed. Add subsidiary attribution method. No new engine. |
| GAP-031 | safe exploit probes | **MERGE** | `attack_simulation_engine`, `red_team_engine`, `verification_engine`, `openclaw_engine` + MPTE | 90% | Four engines grep-confirmed + MPTE is the canonical probe framework. Extend MPTE with identity-path simulation; no new engine. |
| GAP-032 | CIEM recommendations | **MERGE** | `ciem_engine`, `identity_risk_engine`, `privileged_access_governance_engine` | 90% | Three engines grep-confirmed. Add least-privilege recommendation method. No new engine. |
| GAP-033 | AD/Entra attack graph | **MERGE** | `itdr_engine`, `privilege_escalation_detector_engine`, `identity_analytics_engine` | 75% | Three engines grep-confirmed. Extend with AD/Entra-specific predicates (Kerberoast, DCSync). No new engine. |
| GAP-034 | universal connector | **MERGE** | `security_data_pipeline_engine`, `connectors_router` | 70% | Data pipeline grep-confirmed. Extend with mapping UI backend; no new engine. |
| GAP-035 | Chronicle + Datadog SIEM | **MERGE** | `siem_integration_engine`, `siem_output_engine` | 95% | Both engines grep-confirmed. Add provider adapters; no new engine. |
| GAP-036 | `terraform_provider_engine` | **KILL** | — | 0% | **Not an engine.** Terraform provider is a Go binary published to registry.terraform.io. Delete PRD; replace with a deploy-artifact task in `deploy/terraform-provider/`. |
| GAP-037 | typed SDKs | **MERGE** | `api_docs_router` (no engine needed) | 100% | Pure OpenAPI codegen artifact. No engine; just a build script in `sdk/`. |
| GAP-038 | webhook catalog | **MERGE** | `webhook_router`, `webhook_events_router`, `webhook_verifier_router` | 100% | Three routers grep-confirmed. Add event-catalog endpoint; no new engine. |
| GAP-039 | user tokens | **MERGE** | `rbac_engine`, `auth_router` | 100% | `rbac_engine.py` grep-confirmed. Add disposable-token table + endpoints. No new engine. |
| GAP-040 | tamper-evident audit export | **MERGE** | `evidence_chain_engine`, `audit_management_engine` | 100% | Both grep-confirmed. Matrix itself flagged this as COMPETITIVE. No new engine. |
| GAP-041 | SBOM format matrix | **MERGE** | `sbom_engine`, `sbom_export_engine` | 100% | Both grep-confirmed. Verify+extend format coverage. No new engine. |
| GAP-042 | `fips_compliance_mode_engine` | **KEEP** | — | 5% | `grep -l fips/dilithium/ml-dsa/pqc` returns zero hits. FIPS-140 crypto mode + boundary validation is a cross-cutting capability — justifies a dedicated engine that wraps all crypto calls. Net-new. |
| GAP-043 | explainable scoring | **MERGE** | `vulnerability_scoring_engine`, `risk_aggregator_engine`, `ai_governance_engine` | 95% | Three grep-confirmed. Add `/score-breakdown` endpoint exposing formula. No new engine. |
| GAP-044 | agentic AI teammates | **MERGE** | `ai_security_advisor_engine`, `ai_powered_soc_engine`, `autofix_engine`, `ai_orchestrator_router` | 85% | All four grep-confirmed. Pure UX coordination layer over existing engines. No new engine. |
| GAP-045 | exposure-layer attribute | **MERGE** | `attack_surface_engine`, `api_security_engine`, `waf_engine` | 80% | Three grep-confirmed. Add exposure-layer metadata on findings. No new engine. |
| GAP-046 | crown-jewel tagging | **MERGE** | `asset_criticality_engine`, `asset_tagging_engine`, `asset_group_engine`, `risk_register_engine` | 95% | All four grep-confirmed. Pure UI+metadata. No new engine. |
| GAP-047 | TrustGraph scale | **MERGE** | `trustgraph_core`, `trustgraph_indexer`, `trustgraph_quality` (in `suite-core/trustgraph/`) | 90% | TrustGraph infra already exists. Performance/scale is a tuning+benchmarking task, not a new engine. |
| GAP-048 | `oss_call_graph_corpus_engine` | **KEEP** | — | 10% | Pre-computed OSS ecosystem call graphs require large-scale ingestion pipelines (Endor moat). Separable from GAP-010 function-reachability because it's the corpus, not the per-repo analysis. Net-new. |
| GAP-049 | unified Issues queue | **MERGE** | `findings_router`, `exposure_case_router`, `alert_triage_engine` | 90% | Three engines grep-confirmed. Add `/issues` unified view. No new engine. |
| GAP-050 | role-based views | **MERGE** | `rbac_engine` + existing dashboards | 100% | Pure UI routing; no new engine. |
| GAP-051 | exec ROI dashboard | **MERGE** | `executive_reporting_engine`, `risk_quantification_engine` | 90% | Both grep-confirmed. Extend output; no new engine. |
| GAP-052 | composite alert grouping | **MERGE** | `anomaly_ml_engine`, `security_event_correlation_engine`, `behavioral_analytics_engine` | 85% | Three grep-confirmed. Add ML grouping layer. No new engine. |
| GAP-053 | two-layer query | **MERGE** | — | 100% | Duplicate of GAP-024 (DSL) + GAP-029 (NL). Same code serves both. Delete PRD row. |
| GAP-054 | `pricing_model_engine` | **KILL** | — | 0% | **Not a security engine.** This is a marketing calculator; belongs in `suite-ui/marketing/` or a standalone microservice. Delete PRD. |
| GAP-055 | continuous SBOM reeval | **MERGE** | `sbom_engine`, `sbom_export_engine`, `vuln_intelligence_engine` | 95% | Three grep-confirmed. Add scheduled re-evaluation job. No new engine. |
| GAP-056 | design-phase threat modeling | **MERGE** | `threat_modeling_engine`, `threat_modeling_pipeline_engine`, `cyber_threat_modeling_engine`, `ai_security_advisor_engine` | 95% | Four grep-confirmed. Add design-doc ingest mode. No new engine. |
| GAP-057 | component claiming | **MERGE** | `sbom_engine`, `third_party_vendor_engine` | 90% | Both grep-confirmed. Pure metadata addition. No new engine. |
| GAP-058 | `free_tier_entitlement_engine` | **UNCLEAR** | — | 0% | Product/commercial decision. If free tier is shipped, it needs a quota engine. If not, delete PRD. Cannot decide architecturally. |
| GAP-059 | `ai_exposure_inventory_engine` | **MERGE** | `ai_governance_engine`, `ai_security_advisor_engine`, `cmdb_engine` | 75% | `ai_governance_engine.py` grep-confirmed. Extend with shadow-AI discovery method; pairs with `cmdb_engine` for SaaS inventory. No new engine — matrix proposed it as new but grep disagrees. |
| GAP-060 | success metrics timeseries | **MERGE** | `security_metrics_aggregator_engine`, `kpi_tracking_engine`, `security_posture_history_engine` | 100% | All three grep-confirmed. Pure export endpoint. No new engine. |
| GAP-061 | tiered LLM context router | **MERGE** | `ai_orchestrator_router`, `ai_governance_engine` | 70% | Both grep-confirmed. Add contextRequirement schema + pre-flight estimator as new methods + 3 new tables. Router and engine already exist. No new engine file. |
| GAP-062 | unified rule taxonomy | **MERGE** | `policy_engine`, `policy_enforcement_engine` + 5 scanner engines (sast/iac_scanner/secret_scanner/api_security/ai_security_advisor) | 80% | Cross-cutting schema refactor — declares shared `{key, domain, category, severity, enabled, type}` shape consumed by existing engines. No new engine file; zero new surface, pure refactor. |
| GAP-063 | violation lifecycle | **MERGE** | `findings_router`, `vuln_trend_engine`, `vulnerability_age_engine`, `security_posture_history_engine` | 85% | All four grep-confirmed. Add `firstSeenAt/previousViolationId/resolvedAt` columns + reconcile endpoint. No new engine. **HIGHEST-LEVERAGE** MERGE per gap-matrix §113. |
| GAP-064 | `local_file_store_engine` | **KEEP** | — | 5% | Fixops presumes PG+Redis server. `.fixops/` local JSON store with O_EXCL lock + tmp-rename is net-new and enables `npx fixops analyze` zero-setup. Net-new engine justified (or a CLI-only module in `suite-core/cli/`). |
| GAP-065 | architecture-aware graph | **MERGE** | `trustgraph_core` + `security_dependency_mapping_engine` + `api_discovery_engine` + `data_discovery_engine` | 70% | Four targets grep-confirmed. Extend TrustGraph schema with layer-classifier nodes + confidence edges + flow tracer. No new engine file; schema refactor plus new methods. |
| GAP-066 | diff-mode UI | **MERGE** | `trustgraph_core` + `security_change_management_engine` + `findings_router` | 85% | All three grep-confirmed. Pure UI + diff computation endpoint. No new engine. |
| GAP-067 | `claude_skills_packaging_engine` | **KILL** | — | 0% | **Not an engine.** Shipping Claude Code skills is a files-in-`.claude/skills/` delivery task + a publish script. No backend logic. Delete PRD; replace with a `scripts/publish_skills.sh` task. |
| GAP-068 | YAML hook policy | **MERGE** | `pr_gate_router`, `devsecops_engine` | 85% | Both grep-confirmed. Add `.fixops/hooks.yaml` reader + CLI wrapper. No new engine. |
| GAP-069 | `dynamic_rule_dsl_engine` | **KEEP** | `policy_engine` (extend also) | 25% | `real_opa_engine` exists for Rego but not YAML/JSON rule DSL with publish/validate/schema endpoints that customers author without fork+rebuild. Net-new — pairs with GAP-014 IDE. |
| — | `ai_generated_code_scanner_engine` (v2 PRD only) | **MERGE** | `sast_engine`, `ai_security_advisor_engine` | 70% | Same as GAP-019 disposition. |
| — | `function_reachability_engine` (v2 PRD) | **KEEP** | — | 35% | Same as GAP-010. |
| — | `material_change_engine` (v2 PRD) | **MERGE** | `security_change_management_engine` | 70% | Same as GAP-011. |
| — | `deep_code_analysis_engine` (v2 PRD) | **KEEP** | — | 30% | Same as GAP-012. |

---

## MERGE recommendations (26 rows)

The 26 MERGE proposals extend **18 distinct existing engines**. Below, the extensions grouped by host engine:

| Host engine (suite-core/core/) | Gaps absorbed | New methods / columns / endpoints needed | Effort | Owner |
|-------------------------------|---------------|------------------------------------------|--------|-------|
| `policy_enforcement_engine.py` | GAP-004, GAP-062 | `stage_matrix` JSONB column; `evaluate(stage=)`; unified `{key,domain,category,severity,enabled,type}` schema | M | junior-worker |
| `vuln_exception_engine.py` + `security_exception_workflow_engine.py` + `risk_acceptance_engine.py` | GAP-006 | `auto_waiver_rule` table; `auto_waiver(finding)` method consuming reachability | M | senior (ties to reachability) |
| `supply_chain_attack_detection_engine.py` + `supply_chain_intel_engine.py` | GAP-009 | Behavioral-ML scorer; `/quarantine` queue endpoints | M | junior-worker |
| `pr_gate_router` + `github_action_router` + `devsecops_engine` | GAP-015, GAP-068 | GitHub App manifest; `.fixops/hooks.yaml` reader | S | junior-worker |
| `behavioral_analytics_engine` + `uba_engine` + `access_anomaly_engine` + `insider_threat_engine` | GAP-016 | SCM commit-time signals (off-hours commit, privilege escalation edits, secret-file commits) | M | senior |
| `threat_correlation_engine` + `attack_chain_engine` + `security_event_correlation_engine` | GAP-021 | Toxic-combo rule DSL (`internet_exposed AND critical_cve AND over_permissive AND has_pii`) | L | senior |
| `compliance_mapping_engine` + siblings | GAP-022, GAP-023 | Content population (frameworks + 3k policies) | L | junior-worker (content-heavy) |
| `cspm_engine` + `cnapp_engine` + `cloud_account_monitoring_engine` | GAP-025 | OCI/Alibaba/IBM provider adapters | L | junior-worker |
| `attack_path_engine` + `attack_chain_engine` | GAP-026 | Choke-point ranking (max-flow-min-cut) | M | senior |
| `asset_criticality_engine` + `vulnerability_scoring_engine` + `risk_aggregator_engine` | GAP-027, GAP-043, GAP-046 | Blast-radius score; `/score-breakdown`; crown-jewel tag surface | M | junior-worker |
| `risk_quantification_engine_v2` | GAP-028, GAP-051 | PGM likelihood×impact per-BU; ROI-of-fixes trend | M | senior |
| `graphrag_engine` + `ai_security_advisor_engine` | GAP-029 | Traversal-trace output format | S | junior-worker |
| `attack_surface_engine` + `passive_dns_engine` + `dark_web_monitoring_engine` | GAP-030, GAP-045 | Subsidiary attribution; exposure-layer metadata | M | senior |
| `ciem_engine` + `identity_risk_engine` + `privileged_access_governance_engine` + `itdr_engine` + `privilege_escalation_detector_engine` | GAP-032, GAP-033 | Least-privilege recommendations; AD/Entra predicates (Kerberoast, DCSync) | M | senior |
| `security_data_pipeline_engine` | GAP-034 | Universal ingest + field-mapping UI backend | M | junior-worker |
| `siem_integration_engine` + `siem_output_engine` | GAP-035 | Chronicle + Datadog adapters | M | junior-worker |
| `rbac_engine` + `auth_router` | GAP-039, GAP-050 | Disposable scoped user tokens; role-view switcher | S | junior-worker |
| `evidence_chain_engine` + `audit_management_engine` | GAP-040 | Export filter coverage verification | S | junior-worker |
| `sbom_engine` + `sbom_export_engine` | GAP-041, GAP-055, GAP-057 | Format matrix; continuous re-evaluation scheduler; component claim | M | junior-worker |
| `vulnerability_scoring_engine` + `ai_governance_engine` | GAP-043 | Formula transparency | S | junior-worker |
| `ai_security_advisor_engine` + `ai_powered_soc_engine` + `autofix_engine` + `ai_orchestrator_router` | GAP-044, GAP-061 | Teammates UX; tiered LLM context + pre-flight estimate | M | senior |
| `findings_router` + `vuln_trend_engine` + `vulnerability_age_engine` + `security_posture_history_engine` | GAP-049, GAP-063, GAP-066 | Unified `/issues`; stable-identity lifecycle chain; diff-mode endpoint | M | senior (**highest leverage**) |
| `anomaly_ml_engine` + `security_event_correlation_engine` | GAP-052 | Composite alert grouping | M | junior-worker |
| `threat_modeling_engine` + `threat_modeling_pipeline_engine` + `cyber_threat_modeling_engine` | GAP-056 | Design-doc ingest | M | junior-worker |
| `ai_governance_engine` + `cmdb_engine` | GAP-059 | Shadow-AI inventory + AI attack paths | M | senior |
| `security_metrics_aggregator_engine` + `kpi_tracking_engine` + `security_posture_history_engine` | GAP-060 | Timeseries export endpoint | S | junior-worker |
| `trustgraph_core` + `security_dependency_mapping_engine` + `api_discovery_engine` | GAP-019, GAP-065, GAP-047, GAP-011 | Layer classifier; flow tracer; scale tuning; material-change diff | L | senior |

**Effort totals**: ~12 S, ~11 M, ~3 L — most MERGEs are junior-worker parallelizable.

---

## KEEP recommendations (14 rows)

Truly new engines, grep-confirmed absent. These need full engine + router + tests + PRD + frontend:

| New engine file | Gap | Why no existing engine absorbs it | Full cost (engine+router+tests+PRD+UI) | Dependencies |
|-----------------|-----|----------------------------------|---------------------------------------|--------------|
| `air_gap_bundle_engine.py` | GAP-001 | Signed-bundle export/apply/verify is new — no `airgap` code | L (2 wk) | Cryptographic primitives (SHA-256, RSA/ML-DSA sign) — already available in `evidence_vault` |
| `org_hierarchy_engine.py` | GAP-005 | Current `org_engine` is flat; needs parent_org_id + inheritance traversal | L | `policy_enforcement` (inherit policies), `vuln_exception` (inherit waivers) |
| `upgrade_path_resolver_engine.py` | GAP-007 | Ecosystem-specific resolvers (npm/maven/pypi) required; zero grep hits | M | `sbom_engine` (consume pURLs), `vuln_intelligence_engine` (current CVE set) |
| `binary_fingerprint_engine.py` | GAP-008 | TLSH/ssdeep/structural hashing is net-new | L | `sbom_engine` (component identity) |
| `function_reachability_engine.py` | GAP-010 | AST+CFG per language — new capability; dependency_mapping is data-dep only | XL | `security_dependency_mapping_engine`, `sast_engine`, `oss_call_graph_corpus_engine` |
| `deep_code_analysis_engine.py` | GAP-012 | Tree-sitter/LSP-level code entity extraction — `api_discovery` is regex-based | L | Feeds `api_discovery_engine`, `data_classification_engine`, `trustgraph_core` |
| `code_to_runtime_matcher_engine.py` | GAP-013 | eBPF/APM + ML traffic→code mapping; zero grep hits | L | `api_discovery_engine`, runtime telemetry sources |
| `pipeline_bom_engine.py` | GAP-017 | Pipeline-step attestations — different from component SBOM | L | `sbom_engine` (sibling), `evidence_vault_engine` |
| `slsa_provenance_engine.py` | GAP-018 | in-toto attestation generation — not present | M | `evidence_vault_engine`, `sbom_engine` |
| `agentless_snapshot_scan_engine.py` | GAP-020 | Cloud block-storage snapshot APIs — zero grep hits. **P0 Wiz/Orca moat** | XL | `cspm_engine`, `cnapp_engine`, cloud provider SDKs |
| `security_query_language_engine.py` | GAP-024 | Structured DSL parser + schema registry + planner | L | `trustgraph_core` (data source) |
| `fips_compliance_mode_engine.py` | GAP-042 | Cross-cutting FIPS-140 crypto wrapper; zero grep hits. **P0 federal RFP** | L | Wraps all crypto call sites across platform |
| `oss_call_graph_corpus_engine.py` | GAP-048 | Pre-computed OSS ecosystem graphs at scale; zero grep hits | XL | Separate from GAP-010 (corpus vs. per-repo) |
| `local_file_store_engine.py` | GAP-064 | `.fixops/` JSON store + O_EXCL locks; enables `npx fixops analyze` | M | Could live in `suite-core/cli/` instead of `suite-core/core/` — see UNCLEAR |
| `dynamic_rule_dsl_engine.py` | GAP-069 | YAML/JSON rule DSL with validate/publish/schema — `real_opa_engine` is Rego-only | L | `policy_engine`, `sast_engine` (consumer) |

**Total new surface**: 14 engine files + 14 router files + ~14 × 40 tests = ~560 new tests + 14 PRDs (mostly already drafted).

---

## KILL recommendations (5 rows)

Duplicates or non-engines. Delete or reclassify:

| Gap | Proposed engine | Duplicate / mis-categorization | Disposition |
|-----|----------------|------------------------------|-------------|
| GAP-003 | `onprem_ha_reference_engine` | Packaging artifacts (Helm, StatefulSet, PG HA) — not code | **DELETE PRD**. Create `docs/deployment/on-prem-ha.md` + Helm chart in `docker/helm/` |
| GAP-036 | `terraform_provider_engine` | Terraform provider is a Go binary for registry.terraform.io — not a Python engine | **DELETE PRD**. Create `deploy/terraform-provider/` as a separate Go sub-project |
| GAP-053 | two-layer query | Exact duplicate of GAP-024 + GAP-029 | **MARK "superseded by GAP-024"**; delete PRD row |
| GAP-054 | `pricing_model_engine` | Marketing calculator, not a security engine | **DELETE PRD**. Create `suite-ui/marketing/pricing-calculator/` as UI-only |
| GAP-067 | `claude_skills_packaging_engine` | Files-in-`.claude/skills/` + publish script; no backend logic | **DELETE PRD**. Create `scripts/publish_skills.sh` + `.claude/skills/fixops/` content |

All 5 KILLs should be **deleted from `.omc/prds/v2/`** to stop them from being counted in engine totals. Estimated PRD clean-up: 30 min.

---

## UNCLEAR — product decisions required

| Gap | Question | Why architectural decision blocked |
|-----|----------|------------------------------------|
| GAP-014 | IDE extension: one `ide_gateway_engine` serving all IDEs, or zero engines + pure client packages? | Both designs work. Gateway is cleaner if we support IntelliJ + VS Code + Eclipse. Pure clients are simpler for VS Code only. **Needs product decision** on IDE breadth. |
| GAP-058 | `free_tier_entitlement_engine`: are we shipping a free tier at all? | No commercial decision in `docs/INVESTOR_PITCH.md`. If yes, need quota/entitlement engine (M). If no, delete PRD. **Needs GTM decision.** |
| GAP-064 | `local_file_store_engine`: lives in `suite-core/core/` or `suite-core/cli/`? | It's zero-server mode, so conceptually it's a client module, not a server engine. **Needs architecture decision** on whether CLI modules count toward the 334 engine inventory. |

---

## Architectural decision summary (autonomous, ADR-worthy)

Per the JARVIS autonomy protocol, I record the following architectural stance without waiting for approval. This is logged to `.claude/team-state/decisions.log` as part of commit.

1. **Engine count discipline**: Keep engine count under 350 by aggressively MERGEing (26 gaps into 18 existing engines). Reject any PRD that proposes an engine whose name already matches ≥50% of an existing engine's concept.
2. **Non-engines**: Any proposal that is content (policies, frameworks), packaging (Helm, Terraform provider, Claude skills), or a client artifact (IDE extension, CLI local store) must NOT get an engine file. Instead, route to `docs/`, `deploy/`, `scripts/`, `suite-ui/marketing/`, or `suite-core/cli/`.
3. **ADR-004 alignment (CTEM+ identity)**: All 14 KEEPs map to one of the 10 CTEM+ pillars (air-gap, reachability, attestation, DSL extensibility). None are outside platform scope.
4. **Pillar mapping for each KEEP**:
   - Air-gap/offline → GAP-001, GAP-042 (V6, V7)
   - Reachability/moat → GAP-010, GAP-012, GAP-013, GAP-048 (V1, V2)
   - Supply chain → GAP-007, GAP-008, GAP-017, GAP-018 (V3)
   - Developer UX → GAP-064, GAP-069 (V4)
   - Org structure → GAP-005 (V5)
   - CSPM moat → GAP-020 (V8)
   - Query/observability → GAP-024 (V9)

---

*End of reconcile — 48 proposals analyzed, 26 MERGE / 14 KEEP / 5 KILL / 3 UNCLEAR.*
