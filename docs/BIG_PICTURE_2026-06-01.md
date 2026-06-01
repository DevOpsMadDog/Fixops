# ALDECI / FixOps — Chief-Architect Big-Picture Map
**Date:** 2026-06-01  
**Author:** Chief-Architect sweep (read-only, code-grounded)  
**Source of truth:** live codebase at `/Users/devops.ai/fixops/Fixops`  
**Graph:** graphify-out/GRAPH_REPORT.md — 209,493 nodes / 671,164 edges / 11,902 communities

---

## 0. Measured Baseline (code census, not doc claims)

| Dimension | Measured count | How |
|-----------|---------------|-----|
| API routers (`*_router.py`) | **812** files | `ls suite-api/apps/api/*_router.py \| wc -l` |
| Routers mounted in `create_app()` | **~181** `include_router` calls | `grep include_router app.py \| wc -l` |
| Core engines (`*_engine.py`) | **463** files | `ls suite-core/core/*_engine.py \| wc -l` |
| Honest-501 endpoints | **52** `raise HTTPException(501…)` | grep across routers |
| UI pages (`.tsx` in pages/) | **299** | `find … -name "*.tsx" \| wc -l` |
| Threat-intel feed directories | **27** | `ls suite-feeds/feeds/` |
| Scanner normalizer classes | **20+** | `scanner_parsers.py` |
| Connector classes | **30+** | `suite-core/connectors/` |
| LLM provider adapters | **10+** | `llm_providers.py` |
| Brain pipeline steps | **13** named steps | `STEP_NAMES` list |

> **Note on inflation:** 812 router files exist on disk but only ~181 are wired into `create_app()` at boot (the remainder are importable but not mounted). The previously cited "8,298 mounted routes" figure reflects FastAPI route-object expansion (one `include_router` call with 10+ endpoints = 10+ route objects). Actual mounted endpoints are several thousand, not 8k distinct business operations.

---

## 1. What the Product IS — Security Domain Families

ALDECI is an **Application Security Posture Management (ASPM) + Continuous Threat Exposure Management (CTEM) + Cloud Security Posture Management (CSPM)** platform. It is a self-hosted, AI-native security intelligence layer that connects to existing scanners and cloud accounts, normalises their output into a unified finding model, runs a 12-step AI pipeline to prioritise and triage, and produces compliance evidence — replacing point tools from Snyk, Apiiro, Wiz, Tenable, and XM Cyber.

The 812 routers collapse into **16 capability families** below. For each, the table lists the key router files, what the family does, and whether the backend is real-engine-backed or honest-501.

### Family 1 — SAST / SCA / Secret Scanning
**Key routers:** `sast_router.py`, `software_composition_analysis_router.py`, `semgrep_router.py`, `semgrep_scan_router.py`, `snyk_router.py`, `snyk_oss_router.py`, `sonarqube_router.py`, `checkmarx_router.py`, `veracode_router.py`, `secret_scanner_router.py`, `gitleaks_router.py`, `bandit_scan_router.py`  
**What it does:** Static analysis of code, open-source dependency scanning (SCA), secret detection in repos. Normalises output from Bandit, Semgrep, SonarQube, Checkmarx, Snyk, Veracode, Gitleaks into `UnifiedFinding`.  
**Engine backing:** REAL — `sast_engine.py`, `software_composition_analysis_engine.py`, `semgrep_scan_engine.py`, `snyk_vuln_engine.py`, `secret_scanner_engine.py`. Scanner parsers in `scanner_parsers.py` have working `ZAPNormalizer`, `BanditNormalizer`, `CheckmarxNormalizer`, `SonarQubeNormalizer`, `SnykNormalizer`, `SemgrepScannerNormalizer`, `DependabotScannerNormalizer`. SAST router returns real policy evaluation against latest scan summary.  
**Gaps:** Checkmarx and Veracode routers depend on external API credentials (`FIXOPS_CHECKMARX_URL`, `FIXOPS_VERACODE_API_KEY`) — without them the connector gracefully skips, not a 501 but an empty result.

---

### Family 2 — DAST / API Security
**Key routers:** `dast_router.py`, `api_security_router.py`, `api_security_engine_router.py`, `api_security_mgmt_router.py`, `api_discovery_router.py`, `api_inventory_router.py`, `api_fuzzer_router.py`, `api_threat_protection_router.py`, `zap_scan_router.py`, `trivy_scan_router.py`, `nuclei_scan_router.py`  
**What it does:** Dynamic testing of running applications, API discovery and cataloguing, fuzz testing, ZAP/Nuclei scans.  
**Engine backing:** REAL — `dast_scanner.py`, `api_security_engine.py`, `api_discovery_engine.py`, `zap_scan_engine.py`, `trivy_scan_engine.py`, `nuclei_scan_engine.py`. Scanner parsers include `ZAPNormalizer`, `NiktoNormalizer`, `NucleiNormalizer`. MicroPenTest (`micro_pentest.py`) provides CVE-targeted validation.  
**Gaps:** Active DAST against live targets requires `FIXOPS_DAST_TARGET_URL`. Without it, the engine returns findings from stored scan data only.

---

### Family 3 — Container / IaC / Supply Chain
**Key routers:** `container_security_router.py`, `trivy_router.py`, `syft_router.py`, `sbom_router.py`, `sbom_export_router.py`, `checkov_router.py`, `tfsec_router.py`, `slsa_provenance_router.py`, `supply_chain_router.py`, `supply_chain_risk_router.py`, `supply_chain_attack_detection_router.py`, `supply_chain_monitoring_router.py`, `supply_chain_intel_router.py`  
**What it does:** Container image scanning (Trivy, Grype), Infrastructure-as-Code scanning (Checkov, tfsec), SBOM generation (Syft), SLSA provenance, software supply chain risk.  
**Engine backing:** REAL — `trivy_scan_engine.py`, `checkov_scan_engine.py`, `tfsec_scan_engine.py`, `sbom_engine.py`, `syft_sbom_engine.py`, `slsa_provenance_engine.py`, `supply_chain_engine.py`. Scanner parsers include `TrivyScannerNormalizer`, `GrypeScannerNormalizer`, `OSVScannerNormalizer`, `CheckovNormalizer`.  
**Gaps:** SBOM export to CycloneDX/SPDX works; signing via SLSA requires Rekor/Sigstore connectivity.

---

### Family 4 — Cloud Security / CSPM
**Key routers:** `cloud_compliance_router.py`, `cloud_drift_router.py`, `cloud_governance_router.py`, `cloud_account_monitoring_router.py`, `aws_security_hub_router.py`, `aws_iam_router.py`, `aws_s3_router.py`, `aws_waf_router.py`, `aws_eks_router.py`, `aws_ecr_router.py`, `azure_sentinel_router.py`, `azure_keyvault_router.py`, `azure_defender_router.py`, `cloud_discovery_router.py`, `prowler_router.py`, `agentless_snapshot_router.py`  
**What it does:** Cloud misconfiguration detection, AWS/Azure resource posture, agentless snapshot scanning, cloud drift detection, Prowler-based CIS benchmark checks.  
**Engine backing:** REAL — `cloud_compliance_engine.py`, `cloud_drift_engine.py`, `aws_securityhub_engine.py`, `aws_iam_engine.py`, `aws_s3_engine.py`, `prowler_scan_engine.py`, `agentless_snapshot_scan_engine.py`. Prowler normaliser (`prowler_normalizer.py`) processes CIS findings.  
**Gaps:** All AWS/Azure engines require live credentials (`AWS_ACCESS_KEY_ID`, `AZURE_CLIENT_ID`). Without credentials they return empty posture data (not 501 — real engine, no data). GCP CSPM exists as `GCPSecurityConnector` in `sdlc_connectors.py` but no dedicated GCP router is mounted.

---

### Family 5 — Identity / CIEM / Privileged Access
**Key routers:** `ciem_router.py`, `access_control_router.py`, `access_governance_router.py`, `access_matrix_router.py`, `access_anomaly_router.py`, `privileged_access_router.py`, `service_account_auditor_router.py`, `user_access_review_router.py`, `access_request_management_router.py`, `auth0_router.py`, `okta_router.py`  
**What it does:** Cloud Identity and Entitlement Management — over-permissioned roles, dormant accounts, privilege escalation paths, access reviews, just-in-time access, Okta/Auth0 integration.  
**Engine backing:** REAL — `ciem_engine.py`, `access_control_engine.py`, `access_governance_engine.py`, `rbac_engine.py` (multi-tenant SQLite, role hierarchy, disposable tokens), `access_request_management_engine.py`, `service_account_auditor_engine.py`. Connectors: `okta_connector.py`, `intune_connector.py`, `iam_sso_connector.py`.  
**Gaps:** Okta/Auth0 require live API tokens. CIEM cross-account analysis is single-account only (no AWS Organizations sweep yet).

---

### Family 6 — Threat Intelligence / Feeds
**Key routers:** `threat_intel_router.py`, `threat_intel_platform_router.py`, `threat_intel_fusion_router.py`, `threat_feed_aggregator_router.py`, `threat_intelligence_automation_router.py`, `threat_indicator_router.py`, `threat_actor_router.py`, `threat_actor_tracking_router.py`, `virustotal_router.py`, `shodan_router.py`, `abuseipdb_router.py`, `spamhaus_router.py`, `tor_exit_nodes_router.py`, `urlhaus_router.py`, `greynoise_router.py`  
**What it does:** 27 threat intelligence feed directories (CISA KEV, EPSS, NVD CVE, MITRE ATT&CK, GHSA, OSV, ExploitDB, Censys, GreyNoise, OTX, MalwareBazaar, PhishTank, Spamhaus, TOR exit nodes, URLhaus, URLscan, SANS ISC, SecurityTrails, SigmaHQ, DBIR, D3FEND, HIBP, Security Blogs, NucleiTemplates), threat actor tracking, indicator enrichment.  
**Engine backing:** REAL — `threat_intel_platform_engine.py`, `threat_intel_fusion_engine.py`, `threat_indicator_engine.py`, `threat_actor_engine.py`. Feed data in `suite-feeds/feeds/` with per-source directories and a `registry.py`. EPSS and KEV are used directly in Brain Pipeline step 6 (`_step_enrich_threats`).  
**Gaps:** Several feeds (Censys, SecurityTrails, GreyNoise, VirusTotal, Shodan) require paid API keys. Without keys they return cached/offline data or empty. MalwareBazaar, CISA KEV, NVD, OTX are free and operational.

---

### Family 7 — Vulnerability Management / Risk Scoring
**Key routers:** `vuln_scan_router.py`, `vuln_scanner_router.py`, `vuln_prioritization_router.py`, `vuln_prioritizer_router.py`, `vuln_intelligence_router.py`, `vuln_lifecycle_router.py`, `vuln_workflow_router.py`, `vuln_exception_router.py`, `vulnerability_scoring_router.py`, `vulnerability_correlation_router.py`, `vulnerability_remediation_router.py`, `attack_path_router.py`, `attack_surface_router.py`, `risk_register_router.py`  
**What it does:** End-to-end vulnerability lifecycle — ingest, deduplicate, enrich with EPSS/KEV/CVSS, prioritise by risk score (0.0–1.0), attack path graph, exposure case grouping, SLA assignment, exception management, remediation tracking.  
**Engine backing:** REAL — `vuln_scan_engine.py`, `vuln_prioritization_engine.py`, `vuln_intelligence_engine.py`, `vulnerability_scoring_engine.py`, `attack_path_engine.py`. Risk scoring uses CVSS base × EPSS × KEV reachability × asset criticality in Brain Pipeline step 7 (`_step_score_risk`).  
**Gaps:** Attack path GNN (`_run_attack_graph_gnn`) falls back gracefully when `networkx`/`torch` not installed; path analysis still works via BFS fallback.

---

### Family 8 — Incident Response / SOAR / SOC
**Key routers:** `soar_router.py`, `soc_triage_router.py`, `soc_workflow_router.py`, `soc_automation_router.py`, `incident_router.py`, `incident_response_router.py`, `playbook_router.py`, `workflow_router.py`, `alert_triage_router.py`, `alert_correlation_router.py`, `alert_enrichment_router.py`, `xsoar_router.py`, `splunk_soar_router.py`, `servicenow_router.py`, `servicenow_sync_router.py`  
**What it does:** SOAR playbook execution, SOC triage workflows, alert correlation and enrichment, incident lifecycle, Jira/ServiceNow bidirectional sync, Splunk SOAR integration, chatops (Slack/Teams).  
**Engine backing:** REAL — `soar_engine.py` (SQLite-persisted playbooks, trigger conditions, action dispatch, stats), `playbook_engine.py` (step execution, run tracking), `soc_triage_engine.py`, `alert_enrichment_engine.py`. Brain Pipeline step 11 (`_step_run_playbooks`) calls the playbook engine directly.  
**Gaps:** XSOAR/Splunk SOAR require external API credentials. ServiceNow sync (`servicenow_itsm_engine.py`) requires SNOW instance URL + credentials. Chatops (Slack bot) requires `SLACK_BOT_TOKEN`.

---

### Family 9 — Compliance / Evidence / Audit
**Key routers:** `compliance_router.py`, `compliance_planner_router.py`, `evidence_router.py`, `evidence_chain_router.py`, `auto_evidence_router.py`, `audit_router.py`, `audit_evidence_export_router.py`, `audit_management_router.py`, `regulatory_tracker_router.py`, `vanta_router.py`, `vendor_compliance_router.py`, `gdpr_router.py`, `hipaa_router.py`, `pci_router.py`, `fedramp_router.py`  
**What it does:** SOC2 Type II, ISO 27001, GDPR, HIPAA, PCI-DSS, FedRAMP evidence generation. Cryptographically-signed evidence bundles, tamper-proof audit trails, control effectiveness scoring, regulatory reporting.  
**Engine backing:** REAL — `compliance_engine.py`, `evidence_collector.py`, `audit_management_engine.py`, `regulatory_tracker_engine.py`. Brain Pipeline step 12 (`_step_generate_evidence`) produces a SOC2/FedRAMP evidence JSON signed with **hybrid RSA-4096 + ML-DSA-65** (Dilithium) via `quantum_crypto.py`. Falls back to RSA-only if `dilithium-py` not installed, and to unsigned if no keys — never fails the pipeline.  
**Gaps:** Vanta integration (`vanta_compliance_engine.py`) requires Vanta API token. The evidence bundle is JSON — it has not been tested with a real SOC2 auditor tool yet. Control effectiveness scoring uses heuristics (avg risk score < 0.6 → "effective"), not a real auditor framework mapping.

---

### Family 10 — Attack Simulation / Red Team / MPTE
**Key routers:** `attack_sim_router.py`, `attack_simulation_router.py`, `red_team_router.py`, `fail_router.py`, `threat_simulation_router.py`, `attack_chain_router.py`, `toxic_combo_router.py`, `threat_hunting_router.py`, `threat_hunting_playbook_router.py`  
**What it does:** FAIL (Fact-Assess-Impact-Likelihood) scoring engine for findings validation, MicroPenTest Engine (MPTE) for CVE-targeted automated pen-testing, red team management, threat simulation drills, attack chain analysis, deception technology.  
**Engine backing:** REAL — `fail_engine.py` (full FAIL scoring with grades, 4-axis scoring: Fact/Assess/Impact/Likelihood), `fail_router.py` (DrillEngine with inject/detect/triage/remediate/grade lifecycle), `micro_pentest.py` (`run_micro_pentest()` called from pipeline step 10, with batch support and status tracking). The MPTE step in Brain Pipeline is **opt-in** (`run_pentest=False` by default) to avoid live exploitation in automated runs.  
**Gaps:** MPTE requires `run_pentest=True` explicitly. Without it, step 10 is skipped. The red team management engine (`red_team_mgmt_engine.py`) is scaffolded; deep integration with Metasploit/Cobalt Strike requires external connectivity.

---

### Family 11 — Posture / Risk Quantification / Analytics
**Key routers:** `posture_score_router.py`, `posture_advisor_router.py`, `risk_quantification_router.py`, `risk_register_router.py`, `security_scorecard_router.py`, `security_scorecard_engine_router.py`, `security_roadmap_router.py`, `security_roi_router.py`, `analytics_router.py`, `analytics_dashboard_router.py`, `analytics_engine_router.py`, `unified_dashboard_router.py`, `security_maturity_router.py`  
**What it does:** Organisation-wide security posture score, FAIR/risk quantification, board-level ROI reports, security KPIs, maturity scoring, investment prioritisation, historical trend tracking.  
**Engine backing:** REAL — `posture_score_engine.py` (`posture_scoring.py`), `security_scorecard_engine.py`, `risk_quantification_engine.py`, `analytics_engine.py`. Metrics sync from Brain Pipeline results via `_sync_to_analytics()`.  
**Gaps:** Dashboard visualisations are React 19 components pulling real API data; historical trend data requires multiple pipeline runs to accumulate. FAIR quantification uses a simplified model — not the full Open FAIR standard.

---

### Family 12 — Connectors / Integrations
**Key routers:** `connectors_router.py`, `admin_connectors_router.py`, `cloud_connectors_router.py`, `wave_d_integrations_router.py`, `github_router.py`, `gitlab_router.py`, `bitbucket_router.py`, `jira_router.py`, `slack_router.py`, `teams_router.py`, `argocd_router.py`, `terraform_cloud_router.py`, `crowdstrike_router.py`, `sentinelone_router.py`, `tanium_router.py`  
**What it does:** 30+ bidirectional connectors — GitHub/GitLab/Bitbucket SCM, Jira (bidirectional), Jenkins CI, ArgoCD, Terraform Cloud, CrowdStrike Falcon, SentinelOne, Tanium, Okta, Intune, Jamf, Splunk SOAR, N8n, Adaptive Shield, AppOmni, Vault, Workspace ONE.  
**Engine backing:** REAL — `sdlc_connectors.py` (`GitHubSCMConnector`, `JiraBidirectionalConnector`, `JenkinsPipelineConnector`, etc.), `crowdstrike_falcon_connector.py`, `sentinelone_connector.py`, `okta_connector.py`, `intune_connector.py`. All extend `PullConnector` base class with standardised `fetch_findings()` → `UnifiedFinding` normalisation.  
**Gaps:** Every connector requires live credentials in env vars (`FIXOPS_GITHUB_TOKEN`, `FIXOPS_JIRA_URL`, etc.). Without credentials, `ConnectorIngestionScheduler.collect_all_findings()` silently skips them. The connector framework is real; the data depends on the customer's env vars being set.

---

### Family 13 — Multi-LLM Council / AI Decision Layer
**Key routers:** `ai_orchestrator_router.py`, `llm_router.py` (if mounted), `vllm_router.py`, `single_agent_router.py`, `ai_security_advisor_router.py`, `ai_governance_router.py`  
**What it does:** Karpathy 3-stage LLM Council — independent analysis → anonymous peer review → chairman synthesis. Supports OpenRouter (DeepSeek, Qwen, Llama, Gemma), mulerouter.ai (Qwen3-6b-Max), Anthropic, OpenAI, Gemini, vLLM (air-gap), Ollama (air-gap). Escalates to Claude Opus 4.x when confidence < 0.7. Powers Brain Pipeline step 9.  
**Engine backing:** REAL — `llm_council.py`, `llm_council_real.py`, `council_enhanced.py`, `council_pipeline_adapter.py`, `llm_providers.py` (10 provider adapters including `OpenRouterProvider`, `MuleRouterProvider`, `AnthropicProvider`, `OpenAIProvider`). DPO self-learning loop captures verdicts in `llm_learning_loop.py` (~5,196 pairs, targeting 10K for Phase 2 distillation). Council adapter implements full 3-stage Karpathy pattern with memory (`agentdb` via `reasoning_bank.py`) and Opus escalation (cost-guarded at max 10/hour).  
**Gaps:** Active council requires at least one API key (`OPENROUTER_API_KEY` or `MULEROUTER_API_KEY` or `ANTHROPIC_API_KEY`). Without keys, pipeline falls back to deterministic rule-based consensus — still functional, not a 501, but not AI.

---

### Family 14 — TrustGraph / Knowledge Graph
**Key routers:** `trustgraph_backbone_router.py`, `trustgraph_integration_router.py`, `trustgraph_maintenance_router.py`, `trustgraph_quality_router.py`, `arch_graph_router.py`  
**What it does:** Second brain — a SQLite-backed knowledge graph (`KnowledgeStore`) correlating findings, assets, CVEs, MITRE techniques, compliance controls, and relationships. Graph-RAG (`graph_rag.py`) enables semantic query over the security knowledge base. MCP server exposes TrustGraph to external AI tools (650+ tools exposed). Maintenance agent (`TrustGraphMaintenanceAgent`) prunes and deduplicates the graph.  
**Engine backing:** REAL — `suite-core/trustgraph/knowledge_store.py` (full SQLite entity/relationship store with `ingest()`, `search()`, `get_relationships()`), `graph_rag.py` (RAG wrapper with safe fallbacks), `mcp_server.py` (`TrustGraphMCPServer`), `agentdb_bridge.py` (AgentDB vector sync). Event bus (`trustgraph_event_bus.py`) receives emissions from Brain Pipeline and 548 other emit-sites across engines and routers.  
**Gaps:** ~97% of 3,036 endpoints were not wired to TrustGraph event bus as of 2026-05-31 (arch sweep confirmed 13 tenant leaks and 5 auth gaps at DB-schema layer, now patched). Graph RAG quality depends on how many findings have been processed through the pipeline — a fresh install starts with an empty graph.

---

### Family 15 — Zero Trust / Network / Endpoint
**Key routers:** `zero_trust_router.py`, `zero_trust_policy_router.py`, `zero_trust_enforcement_router.py`, `network_security_router.py`, `network_topology_router.py`, `waf_router.py`, `waf_engine_router.py`, `xdr_router.py`, `edr_router.py`, `endpoint_router.py`, `uba_router.py`, `wireless_security_router.py`  
**What it does:** Zero trust policy enforcement, micro-segmentation, network topology mapping, WAF management, XDR/EDR correlation, user behaviour analytics (UEBA), endpoint security.  
**Engine backing:** PARTIAL — `zero_trust_engine.py`, `zero_trust_enforcement_engine.py`, `waf_engine.py`, `xdr_engine.py`, `uba_engine.py` exist and are real engines. Network topology router has its own local `_verify_api_key`. WAF engine wraps AWS WAF and Akamai APIs.  
**Gaps:** True zero trust enforcement (block/allow at network layer) requires integration with a network enforcement point (Zscaler, Palo Alto) — `zscaler_zia_router.py` exists but needs `ZSCALER_API_KEY`. XDR correlation is real within ALDECI's data; cross-vendor XDR (native CrowdStrike/SentinelOne telemetry) requires connector credentials.

---

### Family 16 — Platform / Auth / Admin / Webhooks
**Key routers:** `auth_router.py`, `apikey_router.py`, `users_router.py`, `tenant_router.py`, `admin_router.py`, `admin_db_router.py`, `session_router.py`, `sso_router.py`, `rbac_router.py`, `webhook_router.py`, `webhook_events_router.py`, `webhook_subscriptions_router.py`, `streaming_router.py`, `sse_router.py`, `system_health_router.py`, `version_router.py`, `stripe_webhook_router.py`  
**What it does:** Multi-tenant auth (JWT + API key), org scoping, RBAC (6 roles), SSO, admin CRUD, server-sent events for real-time pipeline progress, webhook delivery, Stripe billing integration.  
**Engine backing:** REAL — full implementation in `app.py`. Auth model detailed in section 4 below.  
**Gaps:** SSO (`sso_router.py`) requires an external IdP (Okta, Auth0). Stripe webhook (`stripe_webhook_router.py`) requires `STRIPE_WEBHOOK_SECRET`. Multi-org admin (super-admin role managing multiple orgs) is partially implemented.

---

## 2. Core Value Flow — How a Finding Travels Through the System

This traces a single finding from scanner output to compliance evidence.

```
External Scanner (Snyk / Trivy / Semgrep / ZAP / Prowler / …)
        │
        ▼
[INGEST] ConnectorIngestionScheduler.collect_all_findings()
  ↳ suite-core/connectors/sdlc_connectors.py (PullConnector.fetch_findings())
  ↳ suite-core/connectors/pull_connector.py (normalise → UnifiedFinding dict)
  ↳ suite-api/apps/api/universal_ingest_router.py (POST /api/v1/ingest)
  ↳ SmartDedup: location-aware dedup (file:line:rule) — prevents title-only collapse
        │
        ▼
[BRAIN PIPELINE] suite-core/core/brain_pipeline.py — BrainPipeline.run()
  Step 1  _step_connect         Pull from configured connectors + env-var creds
  Step 2  _step_normalize       UnifiedFinding normalisation (severity coercion,
                                 field defaulting, connector_source tagging)
  Step 3  _step_resolve_identity  Fuzzy entity matching — deduplicate asset IDs,
                                   hostname variants, cloud resource ARNs
  Step 3b _step_fp_auto_suppress  False-positive suppression rules
  Step 4  _step_deduplicate     Cluster findings by CVE + file + component →
                                  exposure_cases (was: title-only, fixed 2026-05-27)
  Step 5  _step_build_graph     Build in-memory knowledge graph (NetworkX);
                                  emit to TrustGraph event bus
  Step 6  _step_enrich_threats  EPSS score lookup, CISA KEV check, CVSS enrichment,
                                  MITRE ATT&CK mapping, IOC correlation
  Step 7  _step_score_risk      Risk score = CVSS_base × EPSS × KEV_bonus ×
                                  asset_criticality × reachability (0.0–1.0)
  Step 8  _step_apply_policy    OPA policy eval OR built-in condition engine →
                                  BLOCK / REVIEW / ALLOW decisions per finding
  Step 9  _step_llm_council     3-stage Karpathy council (Qwen+DeepSeek+Gemma+Llama
            OR                    via OpenRouter/mulerouter) → weighted consensus verdict
          _step_llm_consensus   Fallback: deterministic rule-based if no API key
  Step 10 _step_micro_pentest   (opt-in, run_pentest=True) — CVE-targeted MPTE
                                  validates exploitability on real targets
  Step 11 _step_run_playbooks   Trigger SOAR playbooks matching findings (SOAREngine +
                                  PlaybookEngine); generate autofix suggestions
  Step 12 _step_generate_evidence  SOC2/FedRAMP evidence JSON, hybrid RSA-4096 +
                                    ML-DSA-65 cryptographic signature
        │
        ▼
[STORAGE] suite-core/core/security_findings_engine.py
  ↳ _mirror_to_security_findings_engine() — persists findings to SQLite
  ↳ _sync_to_analytics() — propagates to DuckDB analytics layer
  ↳ _enrich_post_pipeline() — blast radius, compliance tags, SLA, attack paths
        │
        ▼
[TRUSTGRAPH] trustgraph_event_bus emits: FINDING_INGESTED, EXPOSURE_CASE_CREATED,
  RISK_SCORED, POLICY_DECISION, COUNCIL_VERDICT → KnowledgeStore.ingest()
  → AgentDB vector index for semantic search
        │
        ▼
[API / UI] suite-api/ exposes results via:
  GET /api/v1/findings, /exposure-cases, /risk-scores, /evidence
  GET /api/v1/pipeline/runs/{run_id}/progress (SSE real-time)
  React 19 UI (suite-ui/aldeci-ui-new/) — 299 pages consume these endpoints
```

**Is this flow end-to-end real?**  
Yes, with caveats:
- Steps 1–8 and 11–12 execute unconditionally and are real.
- Step 9 (council) is real when an API key is present; deterministic fallback otherwise.
- Step 10 (MPTE) requires explicit opt-in and real target URLs.
- The flow from a customer's Snyk account to a signed SOC2 evidence bundle has been demonstrated in self-scan mode (ALDECI scanning itself — see `project_moat_audit_2026-05-27.md`).
- SmartDedup bug (title-merge collapsing 1,636 findings → 8) was caught by dogfooding and fixed 2026-05-27 (now location-aware, tested live: 19 → 1,318 findings).

---

## 3. The Moats — What Makes ALDECI Defensible

### Moat 1 — Multi-LLM Consensus Council
**Status: REAL**  
Evidence: `llm_council.py`, `llm_council_real.py`, `council_pipeline_adapter.py`, `llm_providers.py`.  
What it does: 3-stage Karpathy pattern — (1) independent analysis, (2) anonymous peer review, (3) chairman synthesis. 4 models vote (Qwen, DeepSeek, Gemma, Llama via OpenRouter/mulerouter). Weighted confidence voting. Disagreement → conservative (block > review > allow). Escalates to Claude Opus 4.x when confidence < 0.7, cost-guarded at 10 calls/hour. DPO self-learning loop captures every verdict for fine-tuning (5,196 pairs accumulated).  
**Customer requirement:** At least one of `OPENROUTER_API_KEY`, `MULEROUTER_API_KEY`, `ANTHROPIC_API_KEY` must be set. Without any key the council step returns `method: llm_not_configured` and the pipeline continues with a deterministic fallback — not a crash, but not a moat.

---

### Moat 2 — 12-Step Brain Pipeline
**Status: REAL**  
Evidence: `brain_pipeline.py` — 4,600+ lines, 13 step functions fully implemented.  
What it does: End-to-end orchestrator from connector pull to signed evidence. Each step has `findings_in`/`findings_out` tracking, step-level status, TrustGraph emission, and error isolation (one step's failure never kills the pipeline). Real connector calls in step 1 (Snyk, SonarQube, GitHub Advanced Security, Trivy, Checkmarx, Semgrep, Gitleaks + 10 more env-var configured connectors).  
**Honest caveat:** The pipeline runs in-process synchronously. For large finding sets (10K+), it will be slow. Step 7 risk scoring caps at 1,000 findings for the full EPSS lookup; the rest get heuristic scoring. There is no async queue/worker pool for production-scale parallel pipeline runs (though `run_async_batch()` and `pipeline_worker.py` exist for multi-org batch).

---

### Moat 3 — MPTE (MicroPenTest Engine)
**Status: REAL (opt-in only)**  
Evidence: `micro_pentest.py` — `run_micro_pentest(cve_ids, target_urls)` with batch support, status polling, async execution. Called from Brain Pipeline step 10.  
What it does: CVE-targeted automated pen-testing. Given a list of CVE IDs and target URLs, launches lightweight probes to validate actual exploitability (rather than just declared CVSS scores). Validates "is this CVE actually reachable on THIS target?" — the key CTEM differentiator.  
**Honest caveat:** Opt-in (`run_pentest=True`) for obvious reasons — you don't want every CI pipeline run actively attacking your infra. Without explicit enablement, this moat is dormant in every automated run. The MPTE module also depends on having target URLs configured.

---

### Moat 4 — TrustGraph Correlation
**Status: REAL (graph structure real; population depth depends on pipeline runs)**  
Evidence: `knowledge_store.py` (SQLite entity/relationship store), `graph_rag.py` (semantic RAG), `mcp_server.py` (MCP tool server), `agentdb_bridge.py` (vector sync).  
What it does: Correlates findings, assets, CVEs, MITRE techniques, compliance controls, and relationships in a versioned knowledge graph. Enables semantic search ("what CVEs are related to my critical auth service?"). MCP server exposes 650+ tools for external AI agent consumption.  
**Honest caveat:** TrustGraph quality is proportional to pipeline runs — a fresh install has an empty graph. The `trustgraph_event_bus` has 548 emit-sites but they fire only when the associated engine routes are called. The arch sweep (2026-05-31) patched 13 cross-tenant leaks at the DB-schema layer; tenant isolation in TrustGraph is now enforced at the schema level.

---

### Moat 5 — Quantum-Safe Evidence
**Status: REAL (code-complete; library dependency is optional)**  
Evidence: `quantum_crypto.py` (`HybridQuantumSigner`, `_keygen_dilithium()`), `quantum_safe_crypto_engine.py`.  
What it does: Evidence bundles are signed with **hybrid RSA-4096 + ML-DSA-65** (FIPS 204 / Dilithium). This means signatures remain valid even if RSA is broken by a quantum computer. Brain Pipeline step 12 attempts hybrid signing, falls back to RSA-4096-only, then to unsigned — never fails the pipeline.  
**Honest caveat:** Requires `dilithium-py` pip package. Without it, signing degrades to RSA-only (still strong by current standards, but not the marketing claim). The `quantum_safe_crypto_engine.py` also provides a management API for crypto inventory. This is a genuine differentiator but the operational claim depends on `dilithium-py` being installed.

---

### Moat 6 — Self-Learning DPO Loop
**Status: REAL (infrastructure real; scale modest)**  
Evidence: `llm_learning_loop.py` (`LLMLearningLoop`), `reasoning_bank.py`, `.swarm/memory.db` (AgentDB, 8,034+ entries, MiniLM-l6-v2 384-dim).  
What it does: Every council verdict is recorded as a DPO (Direct Preference Optimisation) pair. SOC analyst overrides are captured as preference labels. Phase 1: 5,196 pairs accumulated (~52% to 10K threshold for Phase 2). Phase 2: Qwen 2.5 7B + LoRA r=16 + 4-bit nf4 fine-tuning on 10K pairs.  
**Honest caveat:** Phase 2 distillation has not run yet (triggered at 10K pairs). The fine-tuned model is aspirational until that threshold is reached. However, Phase 1 (verdict storage + retrieval-augmented council via top-5 past trajectories) is operational today.

---

## 4. API Big Picture

### Authentication Model

ALDECI supports **three auth strategies** selectable via `FIXOPS_AUTH_STRATEGY` env var (or auto-detected):

| Strategy | Mechanism | Header | Notes |
|----------|-----------|--------|-------|
| `token` | Static API token | `X-API-Key: <FIXOPS_API_TOKEN>` | Default for production. Token set via env var. |
| `jwt` | Signed JWT (HS256) | `Authorization: Bearer <jwt>` | 30-minute expiry. Secret via `FIXOPS_JWT_SECRET` (min 32 chars). Ephemeral dev key auto-generated if not set. |
| `managed` | Per-org managed keys | `X-API-Key: <managed_key>` | Keys created via `POST /api/v1/apikeys`. Stored in SQLite with org_id binding. |
| `open` | No auth | — | Dev/local mode only. **Never for production.** |

Auto-promotion: if `FIXOPS_API_TOKEN` is set in env and strategy is `open`, the app auto-promotes to `token` mode at startup.

**Auth middleware chain** (applied in `create_app()` via FastAPI middleware):
1. Request-ID correlation (`X-Request-ID`)
2. JWT decode or API-key lookup → populates `request.state.org_id`, `request.state.role`
3. Org-ID middleware → exposes `get_current_org_id()` to all route handlers
4. CORS middleware (configurable allowed origins)

### Tenancy Model

Every API call is scoped to an `org_id`. The org_id is resolved in priority order:
1. `request.state.org_id` (from JWT claim `org_id`)
2. `X-Org-ID` request header
3. `?org_id=` query parameter (fallback for dev tooling)

This means **every database query, every pipeline run, every finding, every evidence bundle is namespaced to an org_id**. Cross-tenant data leaks at the schema level were audited (2026-05-31) and 13 cross-tenant leaks were patched at the DB-schema layer. The `tenant_rate_limiter_router.py` provides per-org rate limiting.

### Key API Surface Areas

| Path prefix | Purpose |
|-------------|---------|
| `POST /api/v1/auth/dev-token` | Mint a dev JWT for org_id + role |
| `POST /api/v1/pipeline/run` | Trigger Brain Pipeline for an org |
| `GET /api/v1/pipeline/runs/{id}/progress` | SSE stream of pipeline progress |
| `GET /api/v1/findings` | Paginated findings list (org-scoped) |
| `GET /api/v1/exposure-cases` | Deduplicated exposure case clusters |
| `GET /api/v1/risk-scores/summary` | Org risk posture summary |
| `GET /api/v1/evidence/{run_id}` | Download signed evidence bundle |
| `POST /api/v1/ingest` | Universal finding ingest endpoint |
| `GET /api/v1/trustgraph/search` | Semantic search over knowledge graph |
| `GET /api/v1/system/health` | Health check (unauthenticated) |
| `POST /api/v1/apikeys` | Create managed API key (admin role) |
| `GET /api/v1/compliance/{framework}/status` | Compliance posture for SOC2/ISO/etc. |

### Pagination
Standard pagination via `?page=N&page_size=M` query params. Default page_size = 20. Max = 500. Cursor-based pagination is not implemented (offset-based only) — this will be a limitation at scale (>100K findings).

### Honest-501 Endpoints
52 endpoints return `HTTPException(501)`. These represent features that have router/schema scaffolding but no engine implementation yet (primarily niche integrations like Tanium, ThousandEyes, some Workday/Snowflake modules). When a customer hits a 501, they get a clear "not implemented" response rather than silent failure or fake data.

---

## 5. Customer-Readiness Scorecard

### Capability-Level Table

| Capability Family | Status | Gating Reason |
|-------------------|--------|---------------|
| SAST / SCA / Secrets | **Ready** | Works with Snyk/Semgrep/Bandit/Gitleaks tokens |
| DAST / API Security | **Partial** | Needs `FIXOPS_DAST_TARGET_URL` for active scans |
| Container / IaC / SBOM | **Ready** | Trivy/Checkov/Syft work offline |
| CSPM — AWS | **Partial** | Needs `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| CSPM — Azure | **Partial** | Needs `AZURE_CLIENT_ID` + `AZURE_TENANT_ID` |
| CSPM — GCP | **Not ready** | No dedicated GCP CSPM router mounted |
| Identity / CIEM | **Partial** | Needs Okta/Intune/Auth0 credentials |
| Threat Intel (free feeds) | **Ready** | CISA KEV, NVD, MITRE, EPSS, OTX work offline |
| Threat Intel (paid feeds) | **Partial** | Censys/GreyNoise/VirusTotal need API keys |
| Vuln Management / Risk | **Ready** | Core pipeline runs on any finding input |
| Attack Path Analysis | **Ready** | BFS fallback works; GNN needs networkx |
| Incident Response / SOAR | **Partial** | Internal playbooks ready; XSOAR/SNOW need creds |
| Compliance Evidence (SOC2) | **Ready** | Evidence generation + signing is end-to-end |
| Compliance Evidence (others) | **Partial** | Framework logic present; auditor-tool integration not tested |
| Multi-LLM Council | **Partial** | Needs ≥1 API key (OpenRouter/mulerouter/Anthropic) |
| MPTE / Red Team | **Partial** | Opt-in; needs target URLs and explicit enablement |
| TrustGraph Correlation | **Partial** | Graph structure real; quality scales with pipeline runs |
| Quantum-Safe Evidence | **Partial** | Needs `dilithium-py` pip package; falls back to RSA-4096 |
| RBAC / Multi-tenant | **Ready** | SQLite RBAC engine, org scoping, JWT/API-key auth |
| UI (React 19 + Vite 6) | **Partial** | 299 pages, production build 3.1s; some pages still need real API wiring |
| Webhooks / SSE | **Ready** | Event delivery + real-time pipeline progress |
| Self-learning DPO | **Partial** | Phase 1 operational (5,196 pairs); Phase 2 at 10K threshold |

### Top 10 Things Still Needed for Full Customer Implementation

These are ordered by customer-blocking severity. Each item is tagged: **[our code]** = engineering work; **[creds/config]** = customer provides.

1. **Customer credential onboarding wizard [our code + customer creds]**  
   The single biggest friction point. A customer must provide 5–20 env vars (scanner tokens, cloud creds, LLM keys) to unlock the platform's full potential. Today this is a raw `.env` file edit. A guided onboarding wizard (connector-by-connector) that validates each credential and reports "connected / needs attention / not configured" is needed before any enterprise sale. The UI has `DomainSeedDiscoveryWizard.tsx` and `AdminAuditLogPage.tsx` but no unified connector credential setup flow.

2. **LLM Council API key — customer-provided [creds]**  
   Without `OPENROUTER_API_KEY` or `MULEROUTER_API_KEY`, Step 9 returns a deterministic rule-based verdict. This is the headline differentiator. Every demo and every customer deployment needs at minimum an OpenRouter key ($0/month on free tier models). This should be the first thing the installer prompts for.

3. **Persistent multi-org database (production-grade) [our code]**  
   Current persistence is SQLite (100+ domain DBs, one per engine). SQLite is fine for single-server, but multi-instance deployment (k8s horizontal scaling) will require migrating hot paths to Postgres. The `admin_db_router.py` manages DB migrations but the underlying engines use `PersistentDict` / direct SQLite. A PostgreSQL adapter for the 5 hottest engines (findings, risk scores, evidence, SOAR, TrustGraph) is needed before multi-node production.

4. **MPTE target URL configuration [our code + customer creds]**  
   The MicroPenTest moat is opt-in and requires explicit `target_urls`. There is no UI workflow for a customer to say "here are my test/staging environments, run MPTE against them." Without this, the pentest moat is invisible to customers. A "Target Registration" page + safe-targets whitelist + MPTE run scheduler is the gap.

5. **GCP CSPM [our code]**  
   `GCPSecurityConnector` exists in `sdlc_connectors.py` but no dedicated GCP router is mounted in `create_app()`. Customers running on GCP (a large segment of mid-market SaaS) get no cloud posture coverage. Wiring the GCP connector to a mounted router + adding GCP-specific findings normalisation is a 1–2 day engineering task.

6. **SOC2 evidence bundle tested with a real auditor tool [our code]**  
   The evidence JSON is cryptographically signed and structurally correct, but it has not been submitted to a real SOC2 auditor tool (Vanta, Drata, Secureframe). Control IDs are ALDECI-internal. Mapping ALDECI controls to Vanta/Drata control IDs (the industry standard) so the evidence can be imported directly into auditor workflows is required for the "SOC2 compliance acceleration" pitch to land.

7. **Cursor-based pagination and >100K finding scale [our code]**  
   All list endpoints use offset-based pagination (`?page=N`). At 100K+ findings, `OFFSET 50000` is a full table scan. Migrating hot list endpoints (`/findings`, `/exposure-cases`) to cursor-based pagination (keyset on `(created_at, id)`) is needed before a large enterprise customer onboards. This is a correctness issue — the API will time out or return wrong data on large datasets.

8. **`dilithium-py` in default requirements [our code]**  
   The quantum-safe signing moat degrades silently to RSA-only if `dilithium-py` is not installed. Add it to `requirements.txt` and validate CI build. Also document the fallback behaviour explicitly so customers understand what they are getting.

9. **Multi-node connector scheduler [our code]**  
   `ConnectorIngestionScheduler` runs in-process. For a customer with 20 connectors, all 20 are polled sequentially in Step 1 of the pipeline. A proper background job queue (Celery / ARQ / background asyncio task with per-connector schedule) is needed for production reliability. Right now, a slow Snyk API call in Step 1 blocks the entire pipeline.

10. **UI mock-data cleanup in remaining pages [our code]**  
    Of the 299 UI pages, a subset still render with hardcoded/fixture data rather than calling the real API (the "NO MOCKS" audit is ongoing). A systematic pass to confirm every page fires at least one real `/api/v1/…` call on mount is required before customer demos. Pages known to be real-API-wired: Brain Pipeline visualisation, Findings list, Risk Scores, Evidence, SOAR dashboard, Connector status. Pages at risk: niche feature pages (physical security, firmware, wireless security) that have no real backend data.

---

## 6. Architecture Summary Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        CUSTOMER SURFACE                          │
│  React 19 UI (299 pages)  │  REST API (812 routers, ~181 wired) │
│  Vite 6 + Tailwind v4     │  FastAPI + JWT/API-key auth          │
│  :5173 (dev) / nginx (prod)│  :8000 (API gateway)               │
└──────────────┬────────────────────────────┬───────────────────-─┘
               │                            │
    ┌──────────▼────────┐         ┌──────────▼─────────────┐
    │  Auth + Tenancy   │         │  Multi-LLM Council      │
    │  JWT (HS256, 30m) │         │  Karpathy 3-stage       │
    │  API-key managed  │         │  OpenRouter + mulerouter │
    │  RBAC 6 roles     │         │  +Anthropic+Ollama+vLLM │
    │  org_id scoping   │         │  DPO self-learning loop │
    └──────────┬────────┘         └──────────┬──────────────┘
               │                             │
    ┌──────────▼─────────────────────────────▼──────────────────┐
    │                    BRAIN PIPELINE (12 steps)               │
    │  1:connect→2:normalize→3:identity→4:dedup→5:build_graph    │
    │  6:enrich_threats(EPSS/KEV)→7:score_risk→8:policy          │
    │  9:council/consensus→10:MPTE(opt-in)→11:playbooks→12:evidence│
    └──────┬─────────────────┬───────────────┬───────────────────┘
           │                 │               │
  ┌────────▼──────┐  ┌───────▼──────┐  ┌─────▼──────────────┐
  │  CONNECTORS   │  │  TRUSTGRAPH  │  │  EVIDENCE          │
  │  30+ classes  │  │  KnowledgeStore│  │  SOC2/FedRAMP JSON │
  │  PullConnector│  │  Graph RAG   │  │  RSA-4096 +        │
  │  GitHub/Snyk/ │  │  AgentDB vec │  │  ML-DSA-65 signed  │
  │  CrowdStrike/ │  │  MCP server  │  │  (quantum-safe)    │
  │  Okta/AWS/…   │  │  548 emitters│  └────────────────────┘
  └───────────────┘  └──────────────┘
           │
  ┌────────▼──────────────────────────────────────────────────┐
  │               SCANNER NORMALISATION LAYER                  │
  │  ZAP│Bandit│Semgrep│SonarQube│Snyk│Trivy│Grype│OSV       │
  │  Checkmarx│Veracode│Prowler│Checkov│Nuclei│Gitleaks       │
  │  Dependabot│Fortify│Nessus│OpenVAS│Nikto│Nmap             │
  │  → UnifiedFinding (common schema, org_id tagged)          │
  └───────────────────────────────────────────────────────────┘
           │
  ┌────────▼──────────────────────────────────────────────────┐
  │               THREAT INTEL (27 feeds)                      │
  │  CISA KEV │ NVD CVE │ EPSS │ MITRE ATT&CK │ GHSA │ OSV   │
  │  OTX │ MalwareBazaar │ PhishTank │ Spamhaus │ TOR          │
  │  URLhaus │ GreyNoise │ Censys │ ExploitDB │ SigmaHQ       │
  └───────────────────────────────────────────────────────────┘
```

---

## 7. Key Files Quick Reference

| What you want to understand | File |
|-----------------------------|------|
| Full 12-step pipeline | `suite-core/core/brain_pipeline.py` |
| Auth model, JWT, org scoping | `suite-api/apps/api/app.py` |
| Auth endpoints (JWT mint, managed keys) | `suite-api/apps/api/auth_router.py` |
| LLM council (3-stage Karpathy) | `suite-core/core/council_pipeline_adapter.py` |
| LLM provider adapters (OpenRouter, mulerouter, Anthropic…) | `suite-core/core/llm_providers.py` |
| Scanner normaliser classes (20+) | `suite-core/core/scanner_parsers.py` |
| Connector base class + SDLC connectors | `suite-core/connectors/pull_connector.py`, `sdlc_connectors.py` |
| TrustGraph knowledge store | `suite-core/trustgraph/knowledge_store.py` |
| RBAC engine | `suite-core/core/rbac_engine.py` |
| SOAR engine | `suite-core/core/soar_engine.py` |
| FAIL scoring engine | `suite-core/core/fail_engine.py` |
| Quantum-safe signing | `suite-core/core/quantum_crypto.py` |
| DPO self-learning loop | `suite-core/core/llm_learning_loop.py` |
| Threat feed registry | `suite-feeds/feeds/registry.py` |
| MicroPenTest engine | `suite-core/core/micro_pentest.py` |
| React UI entry | `suite-ui/aldeci-ui-new/src/` |
