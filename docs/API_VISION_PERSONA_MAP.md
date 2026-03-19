# ALdeci — API → Vision → Persona Map

> **Generated**: 2026-03-18 | **Source**: Full codebase re-audit of all 6 suites
> **Purpose**: Maps every API router to the CEO Vision pillars (V1–V10), the 25 personas, and the 5 Workflow Spaces.
> **Authority**: `docs/CEO_VISION.md` is the north star. This document is the implementation map.

---

## I. Executive Summary

| Metric | Count |
|--------|-------|
| **Suites** | 6 (`suite-api`, `suite-core`, `suite-attack`, `suite-feeds`, `suite-evidence-risk`, `suite-integrations`) |
| **Router files** | 64+ (plus gap routers for UI-expected endpoints not yet backed by real engines) |
| **Total endpoints** | ~771 |
| **Vision Pillars covered** | 10/10 (V1–V10) |
| **Personas served** | 25/25 |
| **Workflow Spaces** | 5/5 (Mission Control, Discover, Validate, Remediate, Comply) |

---

## II. Complete API Router Inventory

### A. suite-api — Gateway Layer (20 routers)

The gateway layer. All user-facing APIs live here. Handles auth, CORS, rate limiting.

| # | Router File | Prefix | ~Endpoints | Purpose | Pillar(s) |
|---|------------|--------|------------|---------|-----------|
| 1 | `analytics_router.py` | `/api/v1/analytics` | 12 | Dashboard stats, trends, executive metrics, risk overview | V3 |
| 2 | `audit_router.py` | `/api/v1/audit` | 10 | Audit trail, compliance logs, chain-of-custody, retention | V10 |
| 3 | `auth_router.py` | `/api/v1/auth` | 6 | JWT login, token refresh, API key management | — |
| 4 | `bulk_router.py` | `/api/v1/bulk` | 8 | Bulk finding operations (status change, assign, export) | V1 |
| 5 | `collaboration_router.py` | `/api/v1/collaboration` | 6 | Comments, annotations, team sharing on findings | V1 |
| 6 | `connectors_router.py` | `/api/v1/connectors` | 8 | Jira, ServiceNow, GitLab, GitHub, Slack, Confluence connectors | V7 |
| 7 | `fail_router.py` | `/api/v1/fail` | 12 | FAIL Engine — chaos/fault injection for security testing | V3 |
| 8 | `inventory_router.py` | `/api/v1/inventory` | 15 | SBOM, components, services, APIs, dependencies, license compliance | V1, V10 |
| 9 | `policies_router.py` | `/api/v1/policies` | 8 | Security policy CRUD, enforcement, violation tracking | V3, V10 |
| 10 | `remediation_router.py` | `/api/v1/remediation` | 10 | Remediation tasks, auto-fix triggers, bulk remediation | V3 |
| 11 | `reports_router.py` | `/api/v1/reports` | 8 | Report generation (executive, compliance, technical) | V10 |
| 12 | `admin_router.py` | `/api/v1/admin` | 5 | Admin operations, system config, data management | — |
| 13 | `system_router.py` | `/api/v1/system` | 4 | System status, version info, diagnostics | — |
| 14 | `teams_router.py` | `/api/v1/teams` | 6 | Team CRUD, member management, role assignment | V1 |
| 15 | `users_router.py` | `/api/v1/users` | 8 | User CRUD, preferences, login, API key management | — |
| 16 | `workflows_router.py` | `/api/v1/workflows` | 12 | Workflow orchestration, SLA tracking, escalation | V2 |
| 17 | `sla_router.py` | `/api/v1/sla` | 5 | SLA definitions, breach tracking, alerts | V2 |
| 18 | `scanner_ingest_router.py` | `/api/v1/scanner-ingest` | 7 | Ingest findings from external scanners (SARIF, JSON) | V1, V7 |
| 19 | `marketplace_router.py` | `/api/v1/marketplace` | 5 | Plugin/integration marketplace | V7 |
| 20 | `mcp_router.py` (auto-discovery) | `/api/v1/mcp-discovery` | 6 | MCP auto-discovery — reflects all routes as AI agent tools | V7 |

### B. suite-core — Intelligence & Decision Layer (27 routers)

The "brain" of ALdeci. All decision logic, AI, ML, and pipeline orchestration.

| # | Router File | Prefix | ~Endpoints | Purpose | Pillar(s) |
|---|------------|--------|------------|---------|-----------|
| 21 | `brain_router.py` | `/api/v1/brain` | 24 | Knowledge graph queries, node/edge management, stats | V3, V1 |
| 22 | `nerve_center.py` | `/api/v1/nerve-center` | 8 | Central monitoring, health dashboard, alert feed | V3 |
| 23 | `decisions.py` | `/api/v1/decisions` | 6 | Decision records, audit trail for AI decisions | V3 |
| 24 | `deduplication_router.py` | `/api/v1/dedup` | 5 | Cross-scanner deduplication engine | V3 |
| 25 | `autofix_router.py` | `/api/v1/autofix` | 13 | AI-powered auto-remediation (10 fix types) | V3 |
| 26 | `autofix_verify_router.py` | `/api/v1/autofix-verify` | 4 | Post-fix verification (did the fix work?) | V3, V5 |
| 27 | `postfix_verify_router.py` | `/api/v1/postfix-verify` | 3 | MPTE post-fix re-verification | V5 |
| 28 | `pipeline_router.py` | `/api/v1/pipeline` | 6 | 12-step brain pipeline orchestration | V3, V2 |
| 29 | `copilot_router.py` | `/api/v1/copilot` | 10 | AI Copilot chat, sessions, context-aware Q&A | V3, V4 |
| 30 | `agents_router.py` | `/api/v1/agents` | 32 | AI agent tasks, remediation agents, pentest agents | V3, V5 |
| 31 | `predictions_router.py` | `/api/v1/predictions` | 6 | Predictive analytics, risk forecasting, trend analysis | V8 |
| 32 | `llm_router.py` | `/api/v1/llm` | 8 | LLM provider config, model selection, consensus settings | V4 |
| 33 | `algorithmic_router.py` | `/api/v1/algorithmic` | 5 | Markov chains, Bayesian models, ML scoring | V8 |
| 34 | `llm_monitor_router.py` | `/api/v1/llm-monitor` | 4 | Prompt injection detection, jailbreak guard, PII leak | V4 |
| 35 | `streaming_router.py` | `/api/v1/stream` | 2 | SSE streaming for pipeline progress and events | V7 |
| 36 | `code_to_cloud_router.py` | `/api/v1/code-to-cloud` | 5 | Code→Build→Deploy→Runtime tracing | V2 |
| 37 | `quantum_crypto_router.py` | `/api/v1/quantum-crypto` | 6 | Hybrid RSA + ML-DSA signatures, evidence signing | V6 |
| 38 | `zero_gravity_router.py` | `/api/v1/zero-gravity` | 5 | Data compression, coreset selection, MinHash dedup | V9 |
| 39 | `single_agent_router.py` | `/api/v1/ai-agent` | 4 | Self-hosted Llama 3.1 70B single-agent mode | V4, V9 |
| 40 | `knowledge_graph_router.py` | `/api/v1/knowledge-graph` | 8 | Graph queries, attack paths, blast radius, visualization | V3 |
| 41 | `vllm_router.py` | `/api/v1/vllm` | 4 | vLLM self-hosted inference (air-gapped LLM) | V4, V9 |
| 42 | `mcp_protocol_router.py` | `/api/v1/mcp-protocol` | 15 | MCP JSON-RPC 2.0, SSE, WebSocket, tool execution | V7 |
| 43 | `self_learning_router.py` | `/api/v1/self-learning` | 6 | Feedback loops, model retraining, outcome tracking | V8 |
| 44 | `mitre_mapper_router.py` | `/api/v1/mitre` | 4 | MITRE ATT&CK mapping for findings | V3 |
| 45 | `airgap_router.py` | `/api/v1/airgap` | 5 | Air-gap operations, offline sync, data bundles | V9 |
| 46 | `fuzzy_identity_router.py` | `/api/v1/fuzzy-identity` | 3 | Cross-scanner finding identity resolution | V1, V3 |
| 47 | `exposure_case_router.py` | `/api/v1/exposure-cases` | 6 | Exposure case management, grouping, triage | V3, V10 |
| 48 | `mindsdb_router.py` | `/api/v1/ml` | 5 | ML model training/inference via MindsDB | V8 |
| 49 | `dtrack_router.py` | `/api/v1/dtrack` | 8 | Dependency-Track SBOM analysis (OWASP) | V1, V10 |
| 50 | `material_change_router.py` | `/api/v1/material-changes` | 4 | Track material changes for compliance (SOX, SOC2) | V10 |
| 51 | `feeds_router.py` | `/api/v1/feeds` | 31 | NVD, KEV, EPSS, ExploitDB, OSV, GitHub advisories | V3 |



### C. suite-attack — Offensive Security Layer (14 routers)

Scanners, MPTE, attack simulation — the "sword" of ALdeci.

| # | Router File | Prefix | ~Endpoints | Purpose | Pillar(s) |
|---|------------|--------|------------|---------|-----------|
| 52 | `mpte_router.py` | `/api/v1/mpte` | 23 | MPTE Enhanced — micro-pentest requests, results, scheduling | V5 |
| 53 | `micro_pentest_router.py` | `/api/v1/micro-pentest` | 20 | Core MPTE — 19-phase pentest engine, exploit verification | V5 |
| 54 | `mpte_orchestrator_router.py` | `/api/v1/mpte-orchestrator` | 6 | MPTE campaign orchestration, multi-target coordination | V5 |
| 55 | `vuln_discovery_router.py` | `/api/v1/vuln-discovery` | 5 | ML-based vulnerability discovery (MindsDB-backed) | V5, V8 |
| 56 | `secrets_router.py` | `/api/v1/secrets` | 7 | Native secrets scanner (200+ patterns, entropy analysis) | V2 |
| 57 | `attack_sim_router.py` | `/api/v1/attack-sim` | 8 | BAS (Breach & Attack Simulation) engine | V5 |
| 58 | `sast_router.py` | `/api/v1/sast` | 4 | Native SAST scanner (Python, JS, Java, Go) | V2 |
| 59 | `dast_router.py` | `/api/v1/dast` | 2 | Native DAST scanner (XSS, SQLi, SSRF) | V2 |
| 60 | `container_router.py` | `/api/v1/container` | 3 | Native container scanner (Dockerfile, image layers) | V2 |
| 61 | `cspm_router.py` | `/api/v1/cspm` | 4 | Native CSPM/IaC scanner (Terraform, CloudFormation) | V2 |
| 62 | `api_fuzzer_router.py` | `/api/v1/api-fuzzer` | 3 | Native API fuzzer (parameter fuzzing, auth bypass) | V2, V5 |
| 63 | `malware_router.py` | `/api/v1/malware` | 4 | Native malware content scanner | V2 |
| 64 | `fail_router.py` | `/api/v1/fail` | 12 | FAIL Engine (Fault & Attack Injection Layer) | V3 |

### D. suite-feeds — Threat Intelligence Layer (1 router)

| # | Router File | Prefix | ~Endpoints | Purpose | Pillar(s) |
|---|------------|--------|------------|---------|-----------|
| 65 | `feeds_router.py` | `/api/v1/feeds` | 31 | NVD, KEV, EPSS, ExploitDB, OSV, GitHub Advisory feeds, enrichment scheduler | V3 |

### E. suite-evidence-risk — Compliance & Evidence Layer (7 routers)

| # | Router File | Prefix | ~Endpoints | Purpose | Pillar(s) |
|---|------------|--------|------------|---------|-----------|
| 66 | `evidence_router.py` | `/api/v1/evidence` | 5 | Evidence vault, bundles, verification, signed artifacts | V6, V10 |
| 67 | `risk_router.py` | `/api/v1/risk` | 3 | Risk scoring by component, by CVE, aggregate risk | V3 |
| 68 | `graph_router.py` | `/api/v1/graph` | 4 | Supply chain lineage, KEV-affected components, anomaly detection | V1, V10 |
| 69 | `provenance_router.py` | `/api/v1/provenance` | 2 | Artifact provenance tracking (SLSA-style) | V10 |
| 70 | `compliance_engine_router.py` | `/api/v1/compliance` | 8 | Compliance framework management (SOC2, PCI-DSS, HIPAA, NIST) | V10 |
| 71 | `business_context.py` | `/api/v1/business-context` | 3 | Jira/Confluence business context enrichment | V1, V3 |
| 72 | `business_context_enhanced.py` | `/api/v1/business-context` | 6 | SSVC business context upload (FixOps YAML, OTM, SSVC) | V3, V10 |

### F. suite-integrations — External Tool Integration Layer (6 routers)

| # | Router File | Prefix | ~Endpoints | Purpose | Pillar(s) |
|---|------------|--------|------------|---------|-----------|
| 73 | `integrations_router.py` | `/api/v1/integrations` | 8 | Integration CRUD, test connections, sync status | V7 |
| 74 | `webhooks_router.py` | `/api/v1/webhooks` | 18 | Webhook management, ALM drift, outbox, work items | V7 |
| 75 | `iac_router.py` | `/api/v1/iac` | 8 | IaC findings, Terraform/CloudFormation remediation | V2 |
| 76 | `ide_router.py` | `/api/v1/ide` | 5 | IDE plugin (VS Code, JetBrains) — inline scan, SARIF | V2 |
| 77 | `oss_tools.py` | `/api/v1/oss` | 9 | Trivy, Grype, Sigstore/Cosign, OPA integration | V1 |
| 78 | `mcp_router.py` | `/api/v1/mcp` | 11 | MCP client management, tool registry, resources, prompts | V7 |

### G. Gap Routers (26 stub routers)

Lightweight stubs for UI-expected endpoints not yet backed by full engines. Return sensible defaults.

| Router Stubs | Purpose |
|-------------|---------|
| `audit_gap`, `bulk_gap`, `copilot_gap`, `fail_gap`, `graph_gap`, `integrations_gap`, `mpte_gap`, `playbooks_gap`, `predictions_gap`, `reports_gap`, `scanner_gap`, `evidence_gap`, `compliance_gap`, `changes_gap`, `workflows_gap`, `sbom_gap`, `attack_paths_gap`, `data_fabric_gap`, `correlation_gap`, `scanner_registry_gap`, `notifications_gap`, `app_config_gap`, `attack_simulation_gap`, `slsa_gap`, `findings_gap`, `compliance_status_gap`, `activity_feed_gap` | Fill UI contract gaps so the frontend doesn't break while real engines are being built |

---

## III. Vision Pillar → API Mapping

> Source: `docs/CEO_VISION.md` lines 133–144

### V1 — APP_ID-Centric: "Every finding traces to App → Component → Feature"

| API | What it does for V1 |
|-----|---------------------|
| `inventory_router.py` | SBOM, app inventory, component registry, service catalog |
| `bulk_router.py` | Bulk operations scoped by APP_ID |
| `collaboration_router.py` | Team annotations on app-scoped findings |
| `brain_router.py` | Knowledge graph nodes tied to APP_ID |
| `fuzzy_identity_router.py` | Cross-scanner finding identity resolution per component |
| `scanner_ingest_router.py` | Ingests findings tagged with APP_ID |
| `graph_router.py` (evidence-risk) | Supply chain lineage per component |
| `oss_tools.py` | Trivy/Grype results mapped to components |
| `dtrack_router.py` | Dependency-Track SBOM tied to projects |

### V2 — 10-Phase Lifecycle: "Design → IDE → ALM → Pre-merge → Build → IaC → Graph → AI → Remediate → Learn"

| API | Phase(s) covered |
|-----|-----------------|
| `sast_router.py` | Pre-merge (static analysis) |
| `dast_router.py` | Build/Deploy (dynamic testing) |
| `secrets_router.py` | Pre-merge (secrets detection) |
| `container_router.py` | Build (image scanning) |
| `cspm_router.py` | IaC (Terraform/CloudFormation) |
| `iac_router.py` | IaC (findings + remediation) |
| `ide_router.py` | IDE (inline scanning) |
| `api_fuzzer_router.py` | Build (API fuzzing) |
| `malware_router.py` | Build (malware content scan) |
| `code_to_cloud_router.py` | Full lifecycle tracing |
| `workflows_router.py` | Orchestrates lifecycle phases |
| `sla_router.py` | SLA tracking across phases |

### V3 — Decision Intelligence: "What to DO, not just what the risk IS"

| API | Decision capability |
|-----|-------------------|
| `brain_router.py` | 12-step brain pipeline, knowledge graph queries |
| `autofix_router.py` | AI-powered auto-remediation (10 fix types) |
| `fail_router.py` | FAIL scoring, chaos/fault injection |
| `deduplication_router.py` | Cross-scanner dedup → noise reduction |
| `nerve_center.py` | Central monitoring, alert feed |
| `decisions.py` | Decision records, audit trail |
| `pipeline_router.py` | Pipeline orchestration |
| `copilot_router.py` | AI Copilot — context-aware Q&A |
| `analytics_router.py` | Dashboard stats, trends, risk velocity |
| `feeds_router.py` | NVD/KEV/EPSS enrichment for decisions |
| `risk_router.py` | Risk scoring engine |
| `knowledge_graph_router.py` | Graph analytics, blast radius |
| `mitre_mapper_router.py` | MITRE ATT&CK context |
| `exposure_case_router.py` | Exposure case triage |
| `remediation_router.py` | Remediation task management |

### V4 — Multi-LLM / Self-Hosted AI: "3 LLMs with 85% threshold OR zero-token self-hosted"

| API | AI capability |
|-----|-------------|
| `llm_router.py` | LLM provider config, model selection, consensus |
| `llm_monitor_router.py` | Prompt injection detection, jailbreak guard, PII leak |
| `copilot_router.py` | Multi-LLM copilot sessions |
| `single_agent_router.py` | Self-hosted Llama 3.1 70B single-agent mode |
| `vllm_router.py` | vLLM self-hosted inference |

### V5 — MPTE Verification: "Prove exploitability, don't just detect vulnerability"

| API | Verification capability |
|-----|----------------------|
| `mpte_router.py` | MPTE Enhanced — requests, results, scheduling |
| `micro_pentest_router.py` | 19-phase pentest engine |
| `mpte_orchestrator_router.py` | Campaign orchestration |
| `attack_sim_router.py` | BAS engine, MITRE heatmap |
| `autofix_verify_router.py` | Post-fix verification |
| `postfix_verify_router.py` | MPTE re-verification |
| `api_fuzzer_router.py` | API parameter fuzzing |
| `vuln_discovery_router.py` | ML-based vuln discovery |

### V6 — Quantum-Secure Evidence: "FIPS 204 ML-DSA hybrid signatures, 7-year WORM"

| API | Crypto capability |
|-----|-----------------|
| `quantum_crypto_router.py` | Hybrid RSA + ML-DSA signatures |
| `evidence_router.py` | Evidence vault, signed bundles |

### V7 — MCP-Native AI Platform: "First platform AI agents can programmatically use"

| API | MCP capability |
|-----|--------------|
| `mcp_router.py` (suite-api) | Auto-discovery — reflects all routes as AI tools |
| `mcp_router.py` (suite-integrations) | MCP client management, tool registry |
| `mcp_protocol_router.py` | JSON-RPC 2.0, SSE, WebSocket, tool execution |
| `scanner_ingest_router.py` | Scanner ingest consumable by AI agents |
| `connectors_router.py` | Jira/ServiceNow/GitHub/Slack connectors |
| `webhooks_router.py` | Webhook management, ALM drift, outbox |
| `integrations_router.py` | Integration CRUD, test connections |
| `marketplace_router.py` | Plugin/integration marketplace |
| `streaming_router.py` | SSE for pipeline progress |

### V8 — Self-Learning: "5 feedback loops, continuous improvement"

| API | Learning capability |
|-----|-------------------|
| `self_learning_router.py` | Feedback loops, model retraining, outcome tracking |
| `predictions_router.py` | Risk forecasting, trend analysis |
| `algorithmic_router.py` | Markov chains, Bayesian models |
| `mindsdb_router.py` | ML model training/inference |
| `vuln_discovery_router.py` | ML-based vuln discovery |

### V9 — Air-Gapped Deployment: "Full offline on commodity hardware (<1 GB/year)"

| API | Air-gap capability |
|-----|------------------|
| `airgap_router.py` | Air-gap operations, offline sync, data bundles |
| `zero_gravity_router.py` | ZSTD compression, coreset selection, MinHash dedup |
| `single_agent_router.py` | Self-hosted LLM (no cloud calls) |
| `vllm_router.py` | vLLM local inference |

### V10 — CTEM with Crypto Proof: "Full Discover → Prioritize → Validate → Remediate → Measure loop"

| API | CTEM phase |
|-----|-----------|
| `audit_router.py` | Measure — audit trail, compliance logs |
| `evidence_router.py` | Measure — cryptographic evidence bundles |
| `compliance_engine_router.py` | Measure — framework assessments |
| `provenance_router.py` | Measure — artifact provenance |
| `material_change_router.py` | Measure — material change tracking |
| `inventory_router.py` | Discover — SBOM, license compliance |
| `reports_router.py` | Measure — executive/compliance/technical reports |
| `policies_router.py` | Prioritize — policy enforcement |
| `dtrack_router.py` | Discover — Dependency-Track SBOM |
| `exposure_case_router.py` | Prioritize — exposure case management |

---

## IV. Persona → API Mapping (25 Personas)

> Source: `tests/persona_validation_25.py` — validated against live API

| # | Persona | Role | Primary APIs Used | Workflow Space |
|---|---------|------|-------------------|----------------|
| P01 | **Sarah Chen** | CISO | `analytics` (dashboard, trends, top-risks, MTTR), `compliance-engine` (SOC2), `evidence` | Mission Control, Comply |
| P02 | **Marcus Johnson** | VP Engineering | `inventory` (applications), `remediation` (backlog, metrics), `analytics` (noise-reduction), `brain` (stats) | Mission Control, Remediate |
| P03 | **Alex Rivera** | SOC Analyst T1 | `analytics` (findings), `deduplication` (clusters), `nerve-center` (pulse, state), `copilot` (ask) | Mission Control, Discover |
| P04 | **Priya Sharma** | SOC Analyst T2 | `brain` (nodes), `attack-sim` (campaigns, MITRE heatmap), `mpte` (verify), `feeds` (NVD) | Discover, Validate |
| P05 | **James Wilson** | Security Engineer | `inputs/sarif`, `scanner-ingest` (supported), `autofix` (generate, stats), `self-learning` (feedback) | Discover, Remediate |
| P06 | **Emma Davis** | DevSecOps Engineer | `inputs/design`, `inputs/sbom`, `pipeline/run`, `policies`, `workflows`, `connectors` | Discover, Remediate |
| P07 | **Robert Kim** | Compliance Officer | `compliance-engine` (frameworks, assess, gaps, HIPAA, SOC2, PCI-DSS), `audit` (logs), `evidence` | Comply |
| P08 | **Lisa Zhang** | Penetration Tester | `attack-sim` (MITRE techniques, campaigns), `mpte` (verify, stats), `fail` (score) | Validate |
| P09 | **David Park** | Risk Manager | `fail` (top-risks, stats), `predictions` (risk-trajectory), `analytics` (risk-velocity, coverage) | Mission Control |
| P10 | **Maria Lopez** | IT Director | `system` (health, info, config), `teams`, `users`, `analytics` (summary) | Mission Control |
| P11 | **Tom Anderson** | AppSec Lead | `inventory` (applications), `remediation` (tasks, SLA), `analytics` (triage-funnel, noise-reduction) | Mission Control, Remediate |
| P12 | **Jennifer Wu** | Cloud Security Architect | `knowledge-graph` (status), `brain` (stats), `inventory` (assets, services), `code-to-cloud` | Discover |
| P13 | **Michael Brown** | Audit Manager | `audit` (logs, compliance/frameworks, decision-trail, policy-changes, user-activity, chain/verify) | Comply |
| P14 | **Karen Taylor** | Incident Response Lead | `nerve-center` (pulse, intelligence-map, playbooks, state), `cases` | Mission Control |
| P15 | **Chris Lee** | Security Data Scientist | `ml` (status, models, predict/anomaly), `self-learning` (weights, stats) | Discover |
| P16 | **Ryan Murphy** | Platform Engineer | `health`, `metrics`, `system` (config), `version`, `ready` | Mission Control |
| P17 | **Nina Patel** | Threat Intel Analyst | `feeds` (NVD, MITRE, EPSS, status), `fail` (CVE lookup) | Discover |
| P18 | **Olivia Martin** | GRC Analyst | `compliance-engine` (SOC2, PCI-DSS, gaps), `evidence`, `audit` (compliance/controls) | Comply |
| P19 | **Daniel Thompson** | SecOps Manager | `analytics` (dashboard), `remediation` (metrics), `teams`, `workflows`, `policies` | Mission Control, Remediate |
| P20 | **Emily Chang** | Developer (Security Champion) | `analytics` (findings), `autofix` (generate, fix-types, confidence-levels), `copilot` (ask) | Remediate |
| P21 | **Richard Adams** | Security Architect | `knowledge-graph` (analytics), `brain` (most-connected), `attack-sim` (health), `mcp` (tools), `predictions` | Discover, Validate |
| P22 | **Amanda Scott** | Supply Chain Security | `inputs/sbom`, `inventory` (assets), `provenance`, `graph`, `risk` | Discover, Comply |
| P23 | **Brian Hall** | QA Security Tester | `inputs/sarif`, `scanner-ingest` (stats), `deduplication` (stats), `remediation` (tasks), `self-learning` | Discover, Remediate |
| P24 | **Catherine Williams** | Board Member | `analytics` (dashboard, compliance-status, summary, ROI) | Mission Control |
| P25 | **Mark Roberts** | External Auditor | `audit` (logs, compliance/frameworks, chain/verify, retention), `evidence` | Comply |

---

## V. Workflow Space → API Mapping

> Source: `docs/CEO_VISION.md` Section V — "The 5-Space UI Vision"

### 🎯 Mission Control — "What needs my attention now?"

**Who uses it**: CISO, DevSecOps, SOC, VM Manager, Risk Manager, IT Director, SecOps Manager, Board Member

| API Group | Endpoints | What it powers in the UI |
|-----------|-----------|------------------------|
| `analytics` | dashboard/overview, trends, top-risks, MTTR, summary, risk-velocity, coverage, ROI, compliance-status | Executive dashboard, KPI cards, trend charts |
| `nerve-center` | pulse, state, intelligence-map, playbooks | Live threat feed, alert ticker, playbook launcher |
| `brain` | stats, most-connected | Pipeline health, knowledge graph overview |
| `fail` | top-risks, stats | FAIL risk ranking, chaos test results |
| `system` | health, info, config | System status panel |
| `teams` / `users` | CRUD | Team management sidebar |
| `health` / `metrics` / `ready` / `version` | probes | Platform status indicators |

### 🔍 Discover — "Find every risk in my environment"

**Who uses it**: AppSec, Cloud Security, Platform Engineers, SOC T2, Threat Intel, Data Scientists

| API Group | Endpoints | What it powers in the UI |
|-----------|-----------|------------------------|
| `analytics` | findings | Findings table, filter/sort |
| `scanner-ingest` | supported, stats | Scanner registry, ingestion dashboard |
| `inputs/*` | sarif, sbom, design | File upload for scan results |
| `inventory` | applications, assets, services, components | Asset inventory views |
| `feeds` | NVD, KEV, EPSS, MITRE, status | Threat intel feed panel |
| `deduplication` | clusters, stats | Dedup dashboard, noise reduction metrics |
| `knowledge-graph` | status, analytics | Graph visualization |
| `brain` | nodes | Finding detail drilldown |
| `code-to-cloud` | status | Lifecycle trace view |
| `ml` | status, models, predict | ML model status, anomaly detection |
| `attack-sim` | campaigns, MITRE heatmap/techniques | Attack surface map |

### ⚡ Validate — "Prove what's actually exploitable"

**Who uses it**: Red Team, Pen Testers, AppSec, SOC T2, Security Architects

| API Group | Endpoints | What it powers in the UI |
|-----------|-----------|------------------------|
| `mpte` | verify, stats | MPTE verification panel, results |
| `micro-pentest` | full engine | 19-phase pentest execution |
| `mpte-orchestrator` | campaigns | Multi-target campaign management |
| `attack-sim` | campaigns, health, MITRE | BAS engine, attack campaign viewer |
| `fail` | score, CVE lookup | FAIL scoring panel |
| `autofix-verify` | verification | Post-fix re-check |
| `postfix-verify` | re-verification | MPTE re-test after fix |
| `api-fuzzer` | fuzz | API fuzzing panel |
| `predictions` | risk-trajectory | Risk forecast charts |

### 🔧 Remediate — "Fix it, track it, close it"

**Who uses it**: Developers, DevSecOps, AppSec Lead, QA Testers, SecOps Manager

| API Group | Endpoints | What it powers in the UI |
|-----------|-----------|------------------------|
| `autofix` | generate, fix-types, confidence-levels, stats | AutoFix panel, one-click fix |
| `remediation` | tasks, backlog, metrics, SLA | Remediation task board |
| `copilot` | ask, sessions | AI Copilot sidebar |
| `bulk` | operations | Bulk action toolbar |
| `workflows` | management | Workflow designer |
| `policies` | CRUD, enforcement | Policy editor |
| `connectors` | types, test | Jira/GitHub ticket creation |
| `self-learning` | feedback | False-positive feedback loop |
| `pipeline` | run | Pipeline trigger |

### 🛡️ Comply — "Prove we're secure to auditors"

**Who uses it**: Compliance Officers, GRC Analysts, Audit Managers, External Auditors, CISO

| API Group | Endpoints | What it powers in the UI |
|-----------|-----------|------------------------|
| `compliance-engine` | frameworks, assess, gaps, SOC2/PCI-DSS/HIPAA status | Compliance dashboard |
| `audit` | logs, decision-trail, policy-changes, user-activity, chain/verify, retention | Audit log viewer |
| `evidence` | status, bundles, verification | Evidence vault |
| `provenance` | status | Artifact provenance panel |
| `reports` | generation | Report builder |
| `material-change` | tracking | Change log for SOX/SOC2 |
| `dtrack` | SBOM analysis | Dependency-Track integration |
| `inventory` | license compliance | License compliance view |

### 🤖 AI Copilot (Cross-cutting — available in every space)

| API Group | Endpoints | What it powers |
|-----------|-----------|---------------|
| `copilot` | ask, sessions, context | Persistent sidebar chat |
| `llm` | providers, models, consensus | LLM configuration |
| `llm-monitor` | injection detection | Prompt safety guard |
| `mcp` / `mcp-protocol` | tools, resources, prompts | MCP tool execution |
| `streaming` | SSE | Real-time pipeline progress |

---

## VI. Coverage & Gap Analysis

### Pillar Coverage Heatmap

| Pillar | # Real Routers | # Gap Stubs | Status | Notes |
|--------|---------------|------------|--------|-------|
| **V1** APP_ID-Centric | 9 | 2 (sbom_gap, findings_gap) | ✅ Strong | Inventory + DTrack + Brain graph cover it well |
| **V2** 10-Phase Lifecycle | 12 | 0 | ✅ Strong | All 10 phases have at least one real scanner/router |
| **V3** Decision Intelligence | 15 | 3 (copilot_gap, fail_gap, predictions_gap) | ✅ Strong | Brain pipeline + AutoFix + FAIL + dedup all real |
| **V4** Multi-LLM | 5 | 0 | ⚠️ Moderate | Real routers exist but engines are simplified stubs |
| **V5** MPTE Verification | 8 | 1 (attack_simulation_gap) | ✅ Strong | MPTE core + orchestrator + attack sim all functional |
| **V6** Quantum-Secure | 2 | 1 (evidence_gap) | ⚠️ Moderate | RSA-SHA256 works; ML-DSA is HMAC fallback (honest about it) |
| **V7** MCP-Native | 9 | 1 (integrations_gap) | ✅ Strong | MCP auto-discovery + protocol + 3 transports all work |
| **V8** Self-Learning | 5 | 1 (predictions_gap) | ⚠️ Moderate | Feedback loops work; MindsDB/Bayesian are stubs |
| **V9** Air-Gapped | 4 | 0 | ✅ Strong | Air-gap + Zero-Gravity + self-hosted LLM all present |
| **V10** CTEM + Crypto | 10 | 3 (compliance_gap, slsa_gap, compliance_status_gap) | ✅ Strong | Full loop: Discover→Prioritize→Validate→Remediate→Measure |

### Persona Coverage Summary

| Segment | Personas | # APIs hit | Validated? |
|---------|----------|-----------|-----------|
| **C-Suite** | P01, P02, P10, P24 | 12 | ✅ All pass |
| **Security Ops** | P03, P04, P09, P14, P19 | 18 | ✅ All pass |
| **Engineering** | P05, P06, P11, P16, P20 | 20 | ✅ All pass |
| **Offensive** | P08, P21 | 10 | ✅ All pass |
| **Compliance** | P07, P13, P18, P25 | 14 | ✅ All pass |
| **Specialized** | P12, P15, P17, P22, P23 | 16 | ✅ All pass |

### Top API Hotspots (most personas depend on)

| API | # Personas | Why it's critical |
|-----|-----------|-------------------|
| `analytics` | 12 | Dashboard is the front door for everyone |
| `audit` | 5 | Every compliance persona needs audit trail |
| `evidence` | 5 | Proof chain required for compliance |
| `brain` | 5 | Knowledge graph powers discovery + decisions |
| `autofix` | 4 | Developer-facing remediation |
| `remediation` | 5 | Task management for fix tracking |
| `compliance-engine` | 4 | Framework assessments |
| `nerve-center` | 3 | Incident response + SOC |
| `mpte` | 3 | Verification — the differentiator |

### Known Gaps (Things That Need Building)

| Gap | Impact | Priority | What's needed |
|-----|--------|----------|--------------|
| **26 gap routers are stubs** | UI works but returns mock data | P2 | Replace stubs with real engines as features mature |
| **V4 LLM engines are simplified** | Multi-LLM consensus is mocked | P2 | Wire real OpenAI/Anthropic providers when budget allows |
| **V6 ML-DSA is HMAC fallback** | No real post-quantum crypto | P3 | Integrate `pqcrypto` or `liboqs` when FIPS 204 finalizes |
| **V8 MindsDB integration is stub** | Self-learning is manual | P3 | Deploy MindsDB container for real ML training |
| **No real DAST engine** | DAST scanner is regex-based | P2 | Integrate ZAP/Nuclei via Docker service |
| **No real container scanner** | Container scan is basic | P2 | Integrate Trivy container scanning |

---

*Last updated: 2026-03-18 | Generated from full codebase re-audit of all 6 suites*
*Source of truth: `docs/CEO_VISION.md` (Vision), `tests/persona_validation_25.py` (Personas), `suite-api/apps/api/app.py` (Router mounts)*