# ALdeci / FixOps — Comprehensive Feature Audit

> Generated from source code analysis of all 6 suites.
> Every feature listed is backed by real router/implementation code.

---

## Table of Contents

1. [Risk Graph & Attack Path Visualization](#1-risk-graph--attack-path-visualization)
2. [NLP / Chat / AI Conversation](#2-nlp--chat--ai-conversation)
3. [Analytics, Dashboards & Reporting](#3-analytics-dashboards--reporting)
4. [Automation, Playbooks & Workflows](#4-automation-playbooks--workflows)
5. [Collaboration](#5-collaboration)
6. [Threat Intelligence Feeds](#6-threat-intelligence-feeds)
7. [Compliance, Evidence & Audit](#7-compliance-evidence--audit)
8. [MPTE / Penetration Testing](#8-mpte--penetration-testing)
9. [Integrations & Connectors](#9-integrations--connectors)
10. [ML, Self-Learning & Predictions](#10-ml-self-learning--predictions)
11. [Asset Management & Inventory](#11-asset-management--inventory)
12. [Policy Management](#12-policy-management)
13. [Remediation Tracking](#13-remediation-tracking)
14. [Deduplication & Exposure Cases](#14-deduplication--exposure-cases)
15. [Security Scanning Engines](#15-security-scanning-engines)
16. [Data Ingestion & Validation](#16-data-ingestion--validation)
17. [Platform Infrastructure](#17-platform-infrastructure)

---

## 1. Risk Graph & Attack Path Visualization

### 1a. Interactive Pipeline Risk Graph
- **What:** Transforms pipeline results into a node/edge graph: services → components → findings → CVEs. Enriches nodes with KEV status, EPSS scores, criticality, PII flags, internet-facing exposure.
- **File:** `suite-api/apps/api/app.py` (inline route)
- **Endpoints:** `GET /api/v1/graph`
- **Personas:** Security Analyst, CISO, Risk Manager

### 1b. Dependency & Supply-Chain Graph
- **What:** Builds a supply-chain dependency graph from SBOM + risk reports. Traces artifact lineage, detects KEV-affected components, flags version anomalies.
- **File:** `suite-evidence-risk/api/graph_router.py`
- **Endpoints:** `POST /graph/build`, `GET /graph/lineage/{artifact}`, `GET /graph/kev-affected`, `GET /graph/version-anomalies`
- **Personas:** AppSec Engineer, Supply-Chain Security Lead

### 1c. GNN Attack Path Prediction
- **What:** Graph Neural Network that predicts attack paths through infrastructure. Returns predicted paths with probability scores.
- **File:** `suite-core/api/algorithmic_router.py`
- **Endpoints:** `POST /api/v1/algorithms/gnn-attack-paths`
- **Personas:** Red Team Lead, Threat Modeler

### 1d. Markov Chain Attack Path Simulation
- **What:** Simulates attacker movement through MITRE ATT&CK kill-chain stages using Markov chains. Returns stage-by-stage probabilities and most-likely attack sequences.
- **File:** `suite-core/api/predictions_router.py`
- **Endpoints:** `POST /api/v1/predictions/attack-chain`, `POST /api/v1/predictions/attack-path`
- **Personas:** Threat Intelligence Analyst, SOC Manager

### 1e. Code-to-Cloud Traceability
- **What:** Traces a vulnerability from source code → git commit → container image → k8s deployment → cloud service → internet exposure. End-to-end lineage.
- **File:** `suite-core/api/code_to_cloud_router.py`
- **Endpoints:** `POST /api/v1/code-to-cloud/trace`
- **Personas:** Platform Engineer, DevSecOps Lead

### 1f. Knowledge Graph (Brain)
- **What:** Full CRUD knowledge graph for the security domain. Nodes (assets, vulns, services, policies), edges (affects, depends_on, mitigates), full-text search, graph traversal.
- **File:** `suite-core/api/brain_router.py`
- **Endpoints:** `POST /api/v1/brain/nodes`, `GET /api/v1/brain/nodes`, `POST /api/v1/brain/edges`, `GET /api/v1/brain/search`, `GET /api/v1/brain/traverse/{node_id}`
- **Personas:** Security Architect, Data Engineer

---

## 2. NLP / Chat / AI Conversation

### 2a. ALdeci Copilot Chat
- **What:** Conversational LLM interface with session management. Supports OpenAI GPT-4 + Anthropic Claude with auto-fallback. Session CRUD, message handling, context injection into Knowledge Brain, quick commands, AI suggestions, feeds integration.
- **File:** `suite-core/api/copilot_router.py` (~1140 lines)
- **Endpoints:** `POST /api/v1/copilot/sessions`, `POST /api/v1/copilot/sessions/{id}/messages`, `GET /api/v1/copilot/sessions/{id}/messages`, `POST /api/v1/copilot/quick-command`, `GET /api/v1/copilot/suggestions`
- **Personas:** Security Analyst, Developer, Auditor

### 2b. Specialized AI Agents
- **What:** 4 domain-specific AI agents with 28 endpoints total:
  - **Security Analyst Agent** — deep CVE analysis, EPSS/KEV enrichment, threat intel correlation
  - **Pentest Agent** — exploit validation, PoC generation, evidence collection (integrates MPTE + micro_pentest)
  - **Compliance Agent** — framework mapping (SOC2/PCI/HIPAA/GDPR), gap analysis, audit prep
  - **Remediation Agent** — AI fix generation, PR creation, dependency update planning
- **File:** `suite-core/api/agents_router.py` (~2958 lines)
- **Endpoints:** `POST /api/v1/copilot/agents/{type}/analyze`, `POST /api/v1/copilot/agents/{type}/actions`, `GET /api/v1/copilot/agents/{type}/status`, plus 25 more
- **Personas:** Security Analyst, Pen Tester, Compliance Officer, Developer

### 2c. LLM Provider Management
- **What:** Manage multi-LLM backend (OpenAI, Anthropic, Google Gemini). Check status/availability, configure providers, test connectivity, adjust settings (temperature, max_tokens, timeout).
- **File:** `suite-core/api/llm_router.py`
- **Endpoints:** `GET /api/v1/llm/status`, `GET /api/v1/llm/providers`, `POST /api/v1/llm/configure`, `POST /api/v1/llm/test`
- **Personas:** Platform Admin

### 2d. LLM Security Monitor
- **What:** Monitors LLM prompts/responses for jailbreak/injection attacks, PII leakage, and sensitive topic scanning.
- **File:** `suite-core/api/llm_monitor_router.py`
- **Endpoints:** `POST /api/v1/llm-monitor/analyze`
- **Personas:** AI Safety Engineer, Security Architect

### 2e. MCP Server (Model Context Protocol)
- **What:** Exposes FixOps as an MCP server for external AI agents (Copilot, Cursor, Windsurf, Zed). Tool/resource/prompt definitions, client management, configuration.
- **File:** `suite-integrations/api/mcp_router.py`
- **Endpoints:** `GET /api/v1/mcp/tools`, `GET /api/v1/mcp/resources`, `GET /api/v1/mcp/prompts`, `POST /api/v1/mcp/config`, `POST /api/v1/mcp/clients`
- **Personas:** Developer, AI Engineer

---

## 3. Analytics, Dashboards & Reporting

### 3a. Analytics Dashboard & Trends
- **What:** Dashboard with finding counts by severity, trend analysis with moving averages, anomaly detection via z-score, top risks, comparative metrics (period-over-period), severity heatmaps, risk-velocity scoring, CSV export.
- **File:** `suite-api/apps/api/analytics_router.py` (~796 lines)
- **Endpoints:** `GET /api/v1/analytics/overview`, `GET /api/v1/analytics/trends`, `GET /api/v1/analytics/anomalies`, `GET /api/v1/analytics/top-risks`, `GET /api/v1/analytics/heatmap`, `GET /api/v1/analytics/export`
- **Personas:** CISO, Security Manager, Risk Manager

### 3b. Pipeline Analytics Persistence
- **What:** Persists pipeline run analytics (forecasts, exploit snapshots, ticket metrics, feedback). Dashboard view across all runs.
- **File:** `suite-api/apps/api/app.py` (inline routes)
- **Endpoints:** `GET /analytics/dashboard`, `GET /analytics/runs/{run_id}`
- **Personas:** Security Operations Lead

### 3c. Report Generation Engine
- **What:** Real report generation from DB data. Multiple export formats: PDF, JSON, CSV, SARIF (2.1.0 compliant), HTML. Scheduled reports with cron-like scheduling, template-based customization, async processing.
- **File:** `suite-api/apps/api/reports_router.py` (~803 lines)
- **Endpoints:** `POST /api/v1/reports/generate`, `GET /api/v1/reports`, `GET /api/v1/reports/{id}`, `GET /api/v1/reports/{id}/download`, `POST /api/v1/reports/schedule`, `GET /api/v1/reports/templates`
- **Personas:** Auditor, CISO, Compliance Officer

### 3d. Global Search
- **What:** Universal full-text search across findings, CVEs, assets, and more. Returns typed results with severity and match context.
- **File:** `suite-api/apps/api/app.py` (inline route)
- **Endpoints:** `GET /api/v1/search?q=...`
- **Personas:** Any user

---

## 4. Automation, Playbooks & Workflows

### 4a. Workflow Orchestration Engine
- **What:** Step-by-step workflow execution engine with conditional branching (if/else), parallel step execution, SLA tracking with deadline monitoring, pause/resume, step retry with exponential backoff, execution timeline.
- **File:** `suite-api/apps/api/workflows_router.py` (~482 lines)
- **Endpoints:** `POST /api/v1/workflows`, `POST /api/v1/workflows/{id}/execute`, `POST /api/v1/workflows/{id}/pause`, `POST /api/v1/workflows/{id}/resume`, `GET /api/v1/workflows/{id}/timeline`
- **Personas:** Security Operations Lead, DevSecOps Engineer

### 4b. AI-Powered Auto-Fix
- **What:** LLM-generated code fixes for vulnerabilities. Single and bulk fix generation (up to 20), apply patches, create PRs, validate fixes, rollback. Full fix lifecycle tracking.
- **File:** `suite-core/api/autofix_router.py`
- **Endpoints:** `POST /api/v1/autofix/generate`, `POST /api/v1/autofix/bulk`, `POST /api/v1/autofix/{id}/apply`, `POST /api/v1/autofix/{id}/validate`, `POST /api/v1/autofix/{id}/rollback`
- **Personas:** Developer, AppSec Engineer

### 4c. Nerve Center (Central Orchestration)
- **What:** "The Intelligent Brain" — real-time composite threat pulse score (0-100), suite health monitoring, cross-suite intelligence linking, auto-remediation triggers (block/quarantine/patch/escalate/notify), pipeline throughput, decision engine status, compliance posture.
- **File:** `suite-core/api/nerve_center.py` (~846 lines)
- **Endpoints:** `GET /api/v1/nerve-center/pulse`, `GET /api/v1/nerve-center/health`, `POST /api/v1/nerve-center/auto-remediate`, `GET /api/v1/nerve-center/intelligence-links`, `GET /api/v1/nerve-center/compliance-posture`
- **Personas:** CISO, SOC Manager

### 4d. 12-Step Brain Pipeline
- **What:** Orchestrates the full ALdeci Brain Pipeline (12 stages): ingest → normalize → enrich → deduplicate → correlate → risk-score → prioritize → remediate → verify → evidence → comply → report. Sync & async modes. SOC2 evidence pack generation.
- **File:** `suite-core/api/pipeline_router.py`
- **Endpoints:** `POST /api/v1/brain/pipeline/run`, `POST /api/v1/brain/pipeline/run/async`, `GET /api/v1/brain/pipeline/runs`, `GET /api/v1/brain/pipeline/runs/{id}`
- **Personas:** DevSecOps Engineer, Platform Admin

### 4e. Unified Intelligent Security Engine
- **What:** Combines Micro-Pentest CVE validation + MPTE agentic testing + MindsDB ML predictions + multi-LLM consensus into a single engine. Attack plan generation, execution, MITRE mapping, compliance checks.
- **File:** `suite-core/api/intelligent_engine_routes.py` (~597 lines)
- **Endpoints:** `POST /intelligent-engine/plan`, `POST /intelligent-engine/execute`, `GET /intelligent-engine/results/{id}`, `GET /intelligent-engine/mitre-mapping`
- **Personas:** Security Architect, Red Team Lead

### 4f. Enterprise Bulk Operations
- **What:** Async bulk operations on findings: update status, assign, create tickets (Jira/GitHub/GitLab/ServiceNow/AzureDevOps), accept risk, export, delete. Job tracking with status lifecycle. Policy application in bulk.
- **File:** `suite-api/apps/api/bulk_router.py` (~1213 lines)
- **Endpoints:** `POST /api/v1/bulk/operations`, `GET /api/v1/bulk/operations/{id}`, `DELETE /api/v1/bulk/operations/{id}`, `POST /api/v1/bulk/policies/apply`
- **Personas:** Security Manager, SOC Analyst

---

## 5. Collaboration

### 5a. Threaded Comments
- **What:** Threaded commenting system on any entity (finding, case, remediation task). Supports parent/child nesting.
- **File:** `suite-api/apps/api/collaboration_router.py`
- **Endpoints:** `POST /api/v1/collaboration/comments`, `GET /api/v1/collaboration/comments`, `GET /api/v1/collaboration/comments/{id}`
- **Personas:** Security Analyst, Developer, Manager

### 5b. Entity Watchers
- **What:** Subscribe to changes on entities. Get notified when findings, cases, or tasks change status/assignment.
- **File:** `suite-api/apps/api/collaboration_router.py`
- **Endpoints:** `POST /api/v1/collaboration/watchers`, `GET /api/v1/collaboration/watchers`, `DELETE /api/v1/collaboration/watchers/{id}`
- **Personas:** Any user

### 5c. Activity Feed
- **What:** Chronological activity stream for entities, showing all changes, comments, and state transitions.
- **File:** `suite-api/apps/api/collaboration_router.py`
- **Endpoints:** `GET /api/v1/collaboration/activity`
- **Personas:** Security Manager, Team Lead

### 5d. Promote Comment to Evidence
- **What:** Promotes a collaboration comment directly into a signed compliance evidence bundle. Bridges conversation → audit trail.
- **File:** `suite-api/apps/api/collaboration_router.py`
- **Endpoints:** `POST /api/v1/collaboration/comments/{id}/promote-to-evidence`
- **Personas:** Compliance Officer, Auditor

### 5e. Slack Notifications
- **What:** Sends formatted Slack webhook notifications for entity events. SSRF-protected (blocks internal IPs).
- **File:** `suite-api/apps/api/collaboration_router.py`
- **Endpoints:** `POST /api/v1/collaboration/notify/slack`
- **Personas:** Team Lead, DevSecOps Engineer

### 5f. Team Management
- **What:** Team CRUD with member add/remove and role assignment.
- **File:** `suite-api/apps/api/teams_router.py`
- **Endpoints:** `POST /api/v1/teams`, `GET /api/v1/teams`, `POST /api/v1/teams/{id}/members`, `DELETE /api/v1/teams/{id}/members/{user_id}`
- **Personas:** Manager, Admin

### 5g. Feedback Capture
- **What:** Collects user feedback on platform outputs (findings, decisions, remediations) to improve ML models.
- **File:** `suite-api/apps/api/app.py` (inline route)
- **Endpoints:** `POST /feedback`
- **Personas:** Any user

---

## 6. Threat Intelligence Feeds

### 6a. Multi-Source Vulnerability Intelligence
- **What:** World-class feed aggregation across 8 categories with 30+ sources:
  1. **Global Authoritative** — NVD, CISA KEV, MITRE, CERT/CC
  2. **National CERTs** — NCSC (UK), BSI (Germany), ANSSI (France), JPCERT (Japan)
  3. **Exploit Intelligence** — Exploit-DB, Metasploit, Vulners
  4. **Threat Actor Intelligence** — MITRE ATT&CK groups, AlienVault OTX
  5. **Supply-Chain** — OSV, GitHub Advisory, Snyk, deps.dev
  6. **Cloud & Runtime** — AWS/Azure/GCP security bulletins, K8s CVEs
  7. **Zero-Day & Early-Signal** — emerging threat monitoring
  8. **Internal Enterprise** — SAST/DAST/SCA, IaC scan results
- **File:** `suite-feeds/api/feeds_router.py` (~1211 lines)
- **Endpoints:** `GET /api/v1/feeds/status`, `GET /api/v1/feeds/categories`
- **Personas:** Threat Intel Analyst, SOC Analyst

### 6b. EPSS Scoring
- **What:** First.org Exploit Prediction Scoring System integration. Get EPSS probability scores for CVEs.
- **File:** `suite-feeds/api/feeds_router.py`
- **Endpoints:** `GET /api/v1/feeds/epss/{cve_id}`, `POST /api/v1/feeds/epss/bulk`
- **Personas:** Vulnerability Manager, Risk Analyst

### 6c. CISA KEV Catalog
- **What:** Known Exploited Vulnerabilities lookup. Check if CVEs are in the CISA KEV catalog (mandated patching).
- **File:** `suite-feeds/api/feeds_router.py`
- **Endpoints:** `GET /api/v1/feeds/kev/{cve_id}`, `GET /api/v1/feeds/kev`
- **Personas:** Compliance Officer, Patch Manager

### 6d. Finding Enrichment
- **What:** Enriches raw findings with EPSS, KEV, exploitability data, threat actor associations, and geo-weighted risk scoring.
- **File:** `suite-feeds/api/feeds_router.py`
- **Endpoints:** `POST /api/v1/feeds/enrich`
- **Personas:** Security Analyst

### 6e. Threat Actor Intelligence
- **What:** Maps CVEs to known threat actors, APT groups, and MITRE ATT&CK techniques.
- **File:** `suite-feeds/api/feeds_router.py`
- **Endpoints:** `GET /api/v1/feeds/threat-actors/{cve_id}`
- **Personas:** Threat Intel Analyst

### 6f. Exploit Intelligence
- **What:** Checks availability of public exploits, PoCs, and Metasploit modules for a given CVE.
- **File:** `suite-feeds/api/feeds_router.py`
- **Endpoints:** `GET /api/v1/feeds/exploits/{cve_id}`
- **Personas:** Pen Tester, Red Team

### 6g. Supply-Chain Vulnerability Lookup
- **What:** Queries OSV, GitHub Advisory, and Snyk for package-level vulnerabilities across ecosystems (npm, PyPI, Maven, Go, etc.).
- **File:** `suite-feeds/api/feeds_router.py`
- **Endpoints:** `GET /api/v1/feeds/supply-chain/{package}`
- **Personas:** Developer, AppSec Engineer

---

## 7. Compliance, Evidence & Audit

### 7a. Tamper-Proof Audit Chain
- **What:** SHA-256 hash-linked audit trail. Every action (decision, policy change, user login) is logged with integrity verification. Detects tampering.
- **File:** `suite-api/apps/api/audit_router.py` (~470 lines)
- **Endpoints:** `GET /api/v1/audit/logs`, `GET /api/v1/audit/logs/{id}`, `POST /api/v1/audit/verify`, `GET /api/v1/audit/integrity-check`
- **Personas:** Auditor, CISO

### 7b. Compliance Report Generation
- **What:** Auto-generates compliance reports for GDPR, SOC2, ISO 27001, HIPAA frameworks. Maps findings and controls to framework requirements.
- **File:** `suite-api/apps/api/audit_router.py`
- **Endpoints:** `POST /api/v1/audit/compliance-report`, `GET /api/v1/audit/compliance-report/{framework}`
- **Personas:** Compliance Officer, Auditor

### 7c. Audit Log Export
- **What:** Exports audit logs in JSON, CSV, and SIEM-compatible CEF (Common Event Format) for integration with Splunk, QRadar, etc.
- **File:** `suite-api/apps/api/audit_router.py`
- **Endpoints:** `GET /api/v1/audit/export`
- **Personas:** SOC Analyst, SIEM Administrator

### 7d. Evidence Vault (WORM Storage)
- **What:** Immutable evidence bundles with RSA-SHA256 digital signatures. Write-Once-Read-Many storage. Signature verification, manifest download.
- **File:** `suite-evidence-risk/api/evidence_router.py`
- **Endpoints:** `GET /evidence/bundles`, `GET /evidence/bundles/{id}`, `GET /evidence/bundles/{id}/manifest`, `POST /evidence/bundles/{id}/verify`
- **Personas:** Auditor, Compliance Officer, Legal

### 7e. Risk Scoring Engine
- **What:** Per-component and per-CVE risk scoring. Summary risk reports with Knowledge Brain integration. Aggregates EPSS, KEV, business context, exposure.
- **File:** `suite-evidence-risk/api/risk_router.py`
- **Endpoints:** `GET /risk/summary`, `GET /risk/components/{name}`, `GET /risk/cves/{cve_id}`, `GET /risk/report`
- **Personas:** Risk Manager, CISO

### 7f. Provenance Attestations
- **What:** Supply-chain provenance verification. Lists and fetches SLSA-style attestations for build artifacts.
- **File:** `suite-evidence-risk/api/provenance_router.py`
- **Endpoints:** `GET /provenance/attestations`, `GET /provenance/attestations/{id}`
- **Personas:** Supply-Chain Security Lead, Platform Engineer

### 7g. Decision & Verification Engine
- **What:** Makes security decisions using multi-LLM consensus on findings + SBOM + threat model + business context. Generates evidence, confidence scores, SSDLC stage data.
- **File:** `suite-core/api/decisions.py`
- **Endpoints:** `POST /decisions/make`, `GET /decisions/status`, `GET /decisions/core-components`
- **Personas:** Security Architect, AppSec Engineer

---

## 8. MPTE / Penetration Testing

### 8a. Advanced MPTE Integration
- **What:** Full MPTE (Micro-Pentest Testing Engine) service integration. Configure test parameters, verify exploitability of CVEs, run penetration tests, manage test queue.
- **File:** `suite-attack/api/mpte_router.py` (~726 lines)
- **Endpoints:** `POST /api/v1/mpte/config`, `POST /api/v1/mpte/verify`, `POST /api/v1/mpte/run`, `GET /api/v1/mpte/results/{id}`, `GET /api/v1/mpte/queue`
- **Personas:** Pen Tester, Red Team Lead

### 8b. Enterprise Micro-Pentest
- **What:** 8-phase penetration testing: init → recon → threat modeling → vuln scanning → exploitation → compliance validation → risk scoring → attack path generation. MITRE ATT&CK-aligned. Compliance framework validation (SOC2, PCI-DSS, HIPAA, GDPR). Batch testing.
- **File:** `suite-attack/api/micro_pentest_router.py` (~1818 lines)
- **Endpoints:** `POST /api/v1/micro-pentest/scan`, `POST /api/v1/micro-pentest/batch`, `GET /api/v1/micro-pentest/results/{id}`, `GET /api/v1/micro-pentest/phases/{id}`, `GET /api/v1/micro-pentest/compliance/{id}`
- **Personas:** Pen Tester, Security Analyst, Compliance Officer

### 8c. Breach & Attack Simulation (BAS)
- **What:** Create/manage attack scenarios. AI-generate scenarios via LLM. Run attack campaigns across MITRE ATT&CK kill chain. Results include attack paths, MITRE heatmap, breach impact assessment.
- **File:** `suite-attack/api/attack_sim_router.py` (~393 lines)
- **Endpoints:** `POST /api/v1/attack-sim/scenarios`, `POST /api/v1/attack-sim/scenarios/generate`, `POST /api/v1/attack-sim/scenarios/{id}/run`, `GET /api/v1/attack-sim/scenarios/{id}/results`, `GET /api/v1/attack-sim/mitre-heatmap`
- **Personas:** Red Team Lead, SOC Manager

### 8d. PentAGI Unified API
- **What:** Unified gateway for PentAGI capabilities: threat intelligence, business impact analysis, attack simulation, remediation guidance, capability introspection. Bridges CLI and HTTP.
- **File:** `suite-attack/api/pentagi_router.py` (~670 lines)
- **Endpoints:** `POST /api/v1/pentagi/threat-intel`, `POST /api/v1/pentagi/impact-analysis`, `POST /api/v1/pentagi/attack-sim`, `POST /api/v1/pentagi/remediation`, `GET /api/v1/pentagi/capabilities`
- **Personas:** Pen Tester, Security Architect

### 8e. Vulnerability Discovery & CVE Contribution
- **What:** Report pentest-discovered vulnerabilities, submit to CVE/MITRE programs (MITRE, CISA, CERT, vendor), list internal pre-CVE vulns, retrain ML models from discovered vulns. Discovery sources: pentest, bug bounty, code review, fuzzing, research.
- **File:** `suite-attack/api/vuln_discovery_router.py` (~1128 lines)
- **Endpoints:** `POST /api/v1/vulns/report`, `POST /api/v1/vulns/submit-cve`, `GET /api/v1/vulns/internal`, `POST /api/v1/vulns/retrain`
- **Personas:** Security Researcher, Bug Bounty Hunter, Vuln Manager

---

## 9. Integrations & Connectors

### 9a. Integration Management Hub
- **What:** CRUD for integrations. 12 connector types: Jira, GitHub, GitLab, ServiceNow, AzureDevOps, Confluence, Slack, AWS Security Hub, Azure Security Center, Dependabot, Snyk, SonarQube. Test connectivity, trigger sync.
- **File:** `suite-integrations/api/integrations_router.py` (~482 lines)
- **Endpoints:** `POST /api/v1/integrations`, `GET /api/v1/integrations`, `POST /api/v1/integrations/{id}/test`, `POST /api/v1/integrations/{id}/sync`
- **Personas:** Platform Admin, DevSecOps Engineer

### 9b. Bidirectional Webhook Sync
- **What:** Real bidirectional sync with external systems. Inbound webhook receivers (Jira, ServiceNow, GitLab, Azure DevOps) with cryptographic signature verification. Integration mappings, drift detection/resolution, reliable outbox with retry logic.
- **File:** `suite-integrations/api/webhooks_router.py` (~1803 lines)
- **Endpoints:** `POST /api/v1/webhooks/jira`, `POST /api/v1/webhooks/servicenow`, `POST /api/v1/webhooks/gitlab`, `POST /api/v1/webhooks/azuredevops`, `GET /api/v1/webhooks/mappings`, `POST /api/v1/webhooks/drift/detect`, `POST /api/v1/webhooks/drift/resolve`
- **Personas:** Integration Engineer, Platform Admin

### 9c. IaC Scanning Integration
- **What:** Infrastructure-as-Code scanning with Checkov + tfsec. Findings management (create/list/resolve/remediate). Multi-provider: AWS/Azure/GCP/K8s. Scan HCL content.
- **File:** `suite-integrations/api/iac_router.py`
- **Endpoints:** `POST /api/v1/iac/scan`, `GET /api/v1/iac/findings`, `POST /api/v1/iac/findings/{id}/resolve`, `POST /api/v1/iac/findings/{id}/remediate`
- **Personas:** Platform Engineer, DevOps

### 9d. IDE Extension Support
- **What:** Real-time code analysis for IDE plugins. Pattern matching + AST parsing for Python/JavaScript/Java/Go/Ruby/PHP/C#. Security vulnerability detection, code quality metrics, intelligent suggestions, SARIF output.
- **File:** `suite-integrations/api/ide_router.py` (~981 lines)
- **Endpoints:** `POST /api/v1/ide/analyze`, `POST /api/v1/ide/scan`, `GET /api/v1/ide/suggestions`, `GET /api/v1/ide/metrics`
- **Personas:** Developer

### 9e. OSS Tools Integration
- **What:** Multi-tool scanning gateway: Trivy, Grype, Sigstore/Cosign signature verification, OPA policy evaluation.
- **File:** `suite-integrations/api/oss_tools.py`
- **Endpoints:** `POST /oss/trivy/scan`, `POST /oss/grype/scan`, `POST /oss/cosign/verify`, `POST /oss/opa/evaluate`
- **Personas:** DevSecOps Engineer

### 9f. SSO/SAML Configuration
- **What:** SSO/SAML configuration management supporting Okta, Azure AD, and other SAML providers. CRUD for SSO configs.
- **File:** `suite-api/apps/api/auth_router.py`
- **Endpoints:** `POST /api/v1/auth/sso`, `GET /api/v1/auth/sso`, `GET /api/v1/auth/sso/{id}`, `DELETE /api/v1/auth/sso/{id}`
- **Personas:** IT Admin, Platform Admin

### 9g. Marketplace
- **What:** Marketplace for remediation packs, policy templates, integration connectors, report templates. Built-in catalog, contributor system, enterprise module loading via importlib.
- **File:** `suite-api/apps/api/marketplace_router.py` (~706 lines)
- **Endpoints:** `GET /api/v1/marketplace/items`, `GET /api/v1/marketplace/items/{id}`, `POST /api/v1/marketplace/items/{id}/install`, `POST /api/v1/marketplace/contribute`, `GET /api/v1/marketplace/search`
- **Personas:** Platform Admin, Security Engineer

---

## 10. ML, Self-Learning & Predictions

### 10a. Local ML Training & Predictions
- **What:** Replaces MindsDB with locally-trained ML models. Anomaly detection, threat assessment, response time prediction, traffic analytics, API health scoring, threat indicator management.
- **File:** `suite-core/api/mindsdb_router.py` (~336 lines)
- **Endpoints:** `POST /api/v1/ml/train`, `POST /api/v1/ml/predict`, `GET /api/v1/ml/models`, `GET /api/v1/ml/anomalies`, `POST /api/v1/ml/threat-indicators`
- **Personas:** Data Scientist, Security Analyst

### 10b. Monte Carlo Risk Quantification (FAIR)
- **What:** FAIR-based Monte Carlo simulation for financial risk quantification. Outputs: Value-at-Risk (VaR), Expected Annual Loss (EAL), loss exceedance curves. CVE-specific and portfolio-level assessments.
- **File:** `suite-core/api/algorithmic_router.py`
- **Endpoints:** `POST /api/v1/algorithms/monte-carlo`, `POST /api/v1/algorithms/risk-quantify/{cve_id}`, `POST /api/v1/algorithms/portfolio-risk`
- **Personas:** Risk Manager, CISO, CFO

### 10c. Causal Inference (Root Cause Analysis)
- **What:** Statistical causal inference to determine root causes of security incidents. Separates correlation from causation.
- **File:** `suite-core/api/algorithmic_router.py`
- **Endpoints:** `POST /api/v1/algorithms/causal-inference`
- **Personas:** Incident Response Lead, Security Analyst

### 10d. SSVC Vulnerability Risk Assessment
- **What:** Stakeholder-Specific Vulnerability Categorization. Bayesian network assessing exploitation status, exposure level, utility, safety impact, mission impact to determine action priority (Track/Track*/Attend/Act).
- **File:** `suite-core/api/predictions_router.py`
- **Endpoints:** `POST /api/v1/predictions/ssvc-risk`
- **Personas:** Vulnerability Manager, CISO

### 10e. Risk Trajectory Prediction
- **What:** Predicts how risk levels will change over time based on historical trends, patching velocity, and threat landscape evolution.
- **File:** `suite-core/api/predictions_router.py`
- **Endpoints:** `POST /api/v1/predictions/risk-trajectory`
- **Personas:** Risk Manager

### 10f. Operator Feedback Loop
- **What:** Accepts operator feedback (merge_allowed/merge_blocked/split_cluster) to retrain deduplication ML models. Closes the human-in-the-loop learning cycle.
- **File:** `suite-core/api/deduplication_router.py`
- **Endpoints:** `POST /api/v1/deduplication/feedback`
- **Personas:** Security Analyst

---

## 11. Asset Management & Inventory

### 11a. Unified Asset Inventory
- **What:** Asset management across applications, services, and APIs. CRUD for assets, with dependency graph resolution (transitive dependencies).
- **File:** `suite-api/apps/api/inventory_router.py` (~585 lines)
- **Endpoints:** `POST /api/v1/inventory/assets`, `GET /api/v1/inventory/assets`, `GET /api/v1/inventory/assets/{id}`, `GET /api/v1/inventory/assets/{id}/dependencies`
- **Personas:** Platform Engineer, AppSec Lead

### 11b. License Compliance
- **What:** Checks component licenses against allowed/blocked lists (MIT, Apache-2.0, GPL, AGPL, etc.). Flags copyleft contamination.
- **File:** `suite-api/apps/api/inventory_router.py`
- **Endpoints:** `GET /api/v1/inventory/licenses`, `GET /api/v1/inventory/licenses/compliance`
- **Personas:** Legal, Compliance Officer

### 11c. SBOM Generation
- **What:** Generates Software Bill of Materials in CycloneDX and SPDX formats from inventoried assets.
- **File:** `suite-api/apps/api/inventory_router.py`
- **Endpoints:** `GET /api/v1/inventory/sbom`, `GET /api/v1/inventory/sbom/{format}`
- **Personas:** Supply-Chain Security Lead, Auditor

### 11d. Vulnerability-to-Asset Correlation
- **What:** Maps known CVEs to affected assets in inventory. Asset risk scoring based on aggregated vulnerability exposure.
- **File:** `suite-api/apps/api/inventory_router.py`
- **Endpoints:** `GET /api/v1/inventory/assets/{id}/vulnerabilities`, `GET /api/v1/inventory/risk-scores`
- **Personas:** Vulnerability Manager

### 11e. Fuzzy Asset Identity Resolution
- **What:** Resolves asset names across different scanners (e.g., "lodash" vs "lodash.js" vs "npm:lodash"). Canonical asset registry with alias management.
- **File:** `suite-core/api/fuzzy_identity_router.py`
- **Endpoints:** `POST /api/v1/identity/register`, `POST /api/v1/identity/alias`, `POST /api/v1/identity/resolve`, `POST /api/v1/identity/resolve/batch`, `GET /api/v1/identity/similar`
- **Personas:** AppSec Engineer, Data Engineer

---

## 12. Policy Management

### 12a. Policy-as-Code Engine
- **What:** OPA-style rule evaluation engine. Define policies with conditions (severity, threshold, pattern matching). Actions: block, warn, notify, auto_remediate, quarantine, escalate. Types: guardrail, compliance, custom.
- **File:** `suite-api/apps/api/policies_router.py` (~474 lines)
- **Endpoints:** `POST /api/v1/policies`, `GET /api/v1/policies`, `PUT /api/v1/policies/{id}`, `DELETE /api/v1/policies/{id}`
- **Personas:** Security Architect, Compliance Officer

### 12b. Policy Simulation (Dry-Run)
- **What:** Test policies against existing findings without enforcement. Preview which findings would be affected and what actions would trigger.
- **File:** `suite-api/apps/api/policies_router.py`
- **Endpoints:** `POST /api/v1/policies/{id}/simulate`
- **Personas:** Security Architect

### 12c. Policy Auto-Enforcement
- **What:** Automatically evaluates policies against new findings and triggers configured actions.
- **File:** `suite-api/apps/api/policies_router.py`
- **Endpoints:** `POST /api/v1/policies/enforce`
- **Personas:** Security Operations Lead

### 12d. Policy Conflict Detection
- **What:** Detects conflicts between policies (e.g., one blocks, another allows the same finding pattern).
- **File:** `suite-api/apps/api/policies_router.py`
- **Endpoints:** `GET /api/v1/policies/conflicts`
- **Personas:** Security Architect

---

## 13. Remediation Tracking

### 13a. Remediation Task Lifecycle
- **What:** Full lifecycle management for remediation tasks. Create, list, get, update status, assign to users. State machine with validated transitions. Verification evidence submission.
- **File:** `suite-api/apps/api/remediation_router.py` (~423 lines)
- **Endpoints:** `POST /api/v1/remediation/tasks`, `GET /api/v1/remediation/tasks`, `GET /api/v1/remediation/tasks/{id}`, `PATCH /api/v1/remediation/tasks/{id}/status`, `POST /api/v1/remediation/tasks/{id}/assign`
- **Personas:** Developer, Security Analyst, Manager

### 13b. Verification Evidence
- **What:** Submit evidence that a remediation was completed (screenshots, test results, scan outputs). Links evidence to the task.
- **File:** `suite-api/apps/api/remediation_router.py`
- **Endpoints:** `POST /api/v1/remediation/tasks/{id}/verify`
- **Personas:** Developer, Auditor

### 13c. External Ticket Linking
- **What:** Links remediation tasks to external tickets (Jira, ServiceNow, GitHub Issues). Bidirectional reference tracking.
- **File:** `suite-api/apps/api/remediation_router.py`
- **Endpoints:** `POST /api/v1/remediation/tasks/{id}/link-ticket`
- **Personas:** DevSecOps Engineer

---

## 14. Deduplication & Exposure Cases

### 14a. Finding Deduplication & Clustering
- **What:** Groups duplicate/related findings into clusters. Single and batch processing. Fuzzy matching across scanner outputs.
- **File:** `suite-core/api/deduplication_router.py` (~437 lines)
- **Endpoints:** `POST /api/v1/deduplication/process`, `POST /api/v1/deduplication/batch`, `GET /api/v1/deduplication/clusters`, `GET /api/v1/deduplication/clusters/{id}`
- **Personas:** Security Analyst

### 14b. Cluster Management
- **What:** Manage deduplication clusters: update status, assign ownership, merge clusters, split clusters, create correlation links.
- **File:** `suite-core/api/deduplication_router.py`
- **Endpoints:** `PATCH /api/v1/deduplication/clusters/{id}`, `POST /api/v1/deduplication/clusters/{id}/assign`, `POST /api/v1/deduplication/clusters/merge`, `POST /api/v1/deduplication/clusters/{id}/split`, `POST /api/v1/deduplication/correlations`
- **Personas:** Security Analyst, Team Lead

### 14c. Baseline Comparison
- **What:** Compares findings between runs to identify new, resolved, and persistent issues. Delta analysis for CI/CD gating.
- **File:** `suite-core/api/deduplication_router.py`
- **Endpoints:** `POST /api/v1/deduplication/baseline`
- **Personas:** DevSecOps Engineer

### 14d. Exposure Cases
- **What:** Collapses noisy findings into actionable Exposure Cases. Lifecycle: OPEN → TRIAGING → FIXING → RESOLVED → CLOSED. Priority management, cluster association, SLA tracking, playbook/autofix linking, risk scoring.
- **File:** `suite-core/api/exposure_case_router.py`
- **Endpoints:** `POST /api/v1/cases`, `GET /api/v1/cases`, `GET /api/v1/cases/{id}`, `PATCH /api/v1/cases/{id}`, `POST /api/v1/cases/{id}/link-cluster`
- **Personas:** Security Analyst, Vulnerability Manager

---

## 15. Security Scanning Engines

### 15a. SAST (Static Application Security Testing)
- **What:** Scan code snippets and files for security vulnerabilities. Rule-based detection with CWE mapping. Supports Python, JavaScript, Java, Go, Ruby, PHP, C#.
- **File:** `suite-attack/api/sast_router.py`
- **Endpoints:** `POST /api/v1/sast/scan`, `POST /api/v1/sast/scan/files`, `GET /api/v1/sast/rules`
- **Personas:** Developer, AppSec Engineer

### 15b. DAST (Dynamic Application Security Testing)
- **What:** Live target scanning with crawling and configurable depth.
- **File:** `suite-attack/api/dast_router.py`
- **Endpoints:** `POST /api/v1/dast/scan`
- **Personas:** Pen Tester, AppSec Engineer

### 15c. Container Security
- **What:** Dockerfile scanning, container image scanning (Trivy/Grype integration), base image vulnerability checks.
- **File:** `suite-attack/api/container_router.py`
- **Endpoints:** `POST /api/v1/container/scan/dockerfile`, `POST /api/v1/container/scan/image`, `GET /api/v1/container/base-images`
- **Personas:** Platform Engineer, DevOps

### 15d. CSPM (Cloud Security Posture Management)
- **What:** Terraform HCL and CloudFormation template scanning. Rules by cloud provider (AWS, Azure, GCP).
- **File:** `suite-attack/api/cspm_router.py`
- **Endpoints:** `POST /api/v1/cspm/scan/terraform`, `POST /api/v1/cspm/scan/cloudformation`, `GET /api/v1/cspm/rules/{provider}`
- **Personas:** Cloud Engineer, Platform Engineer

### 15e. API Fuzzing
- **What:** Discovers API endpoints from OpenAPI/Swagger specs, then fuzzes them for vulnerabilities.
- **File:** `suite-attack/api/api_fuzzer_router.py`
- **Endpoints:** `POST /api/v1/api-fuzzer/discover`, `POST /api/v1/api-fuzzer/fuzz`
- **Personas:** API Security Engineer, Pen Tester

### 15f. Malware Detection
- **What:** Scans file content for known malware signatures. Single and batch file scanning.
- **File:** `suite-attack/api/malware_router.py`
- **Endpoints:** `POST /api/v1/malware/scan`, `POST /api/v1/malware/scan/batch`, `GET /api/v1/malware/signatures`
- **Personas:** SOC Analyst, Incident Responder

### 15g. Secrets Detection
- **What:** Enterprise-grade secrets scanning with gitleaks and trufflehog integration. Repository scanning, findings management (create/list/resolve).
- **File:** `suite-attack/api/secrets_router.py`
- **Endpoints:** `GET /api/v1/secrets/findings`, `POST /api/v1/secrets/findings`, `POST /api/v1/secrets/findings/{id}/resolve`, `POST /api/v1/secrets/scan`
- **Personas:** Developer, AppSec Engineer

---

## 16. Data Ingestion & Validation

### 16a. Multi-Format Data Ingestion
- **What:** File upload endpoints for 7 data formats with content-type validation and size limiting:
  - **Design CSV** — component architecture/exposure data
  - **SBOM** — CycloneDX/SPDX JSON (supports gzip/zip)
  - **CVE feeds** — NVD-format JSON
  - **VEX** — Vulnerability Exploitability eXchange
  - **CNAPP** — Cloud-Native Application Protection findings
  - **SARIF** — Static analysis results (supports gzip/zip)
  - **Business Context** — YAML/JSON context overlays
- **File:** `suite-api/apps/api/app.py` (inline routes)
- **Endpoints:** `POST /inputs/design`, `POST /inputs/sbom`, `POST /inputs/cve`, `POST /inputs/vex`, `POST /inputs/cnapp`, `POST /inputs/sarif`, `POST /inputs/context`
- **Personas:** DevSecOps Engineer, CI/CD Pipeline

### 16b. Multipart & Chunked Upload
- **What:** Multipart ingest for combining multiple files in a single upload. Chunked upload support for large files.
- **File:** `suite-api/apps/api/app.py` (inline routes)
- **Endpoints:** `POST /api/v1/ingest/multipart`, `POST /api/v1/ingest/assets`, `POST /api/v1/ingest/formats`
- **Personas:** CI/CD Pipeline, Platform Engineer

### 16c. Dry-Run Validation
- **What:** Validates security tool output without processing it. Auto-detects format (SARIF, CycloneDX, SPDX, Snyk, Trivy, Grype, VEX, CNAPP, Checkov, SonarQube, ZAP). Schema drift detection and compatibility reports.
- **File:** `suite-api/apps/api/validation_router.py` (~492 lines)
- **Endpoints:** `POST /api/v1/validate/dry-run`, `POST /api/v1/validate/detect-format`, `POST /api/v1/validate/schema-drift`, `GET /api/v1/validate/compatibility`
- **Personas:** DevSecOps Engineer, Integration Engineer

### 16d. Business Context Integration
- **What:** Upload and manage business context (Jira projects, Confluence threat models). Enriches findings with business impact, data sensitivity, compliance requirements, stakeholder impact. Supports FixOps YAML and OTM formats. SSVC conversion.
- **File:** `suite-evidence-risk/api/business_context.py`, `suite-evidence-risk/api/business_context_enhanced.py`
- **Endpoints:** `POST /business-context/upload`, `POST /business-context/jira`, `POST /business-context/confluence`, `POST /business-context/enrich`, `POST /business-context/ssvc-convert`
- **Personas:** Product Owner, Security Architect

---

## 17. Platform Infrastructure

### 17a. Authentication & Authorization
- **What:** JWT authentication with bcrypt password hashing, RBAC, rate-limited login (5 attempts, 5-min lockout), session management, API key auth, audit-logged auth events.
- **File:** `suite-api/apps/api/users_router.py`
- **Endpoints:** `POST /api/v1/users/login`, `POST /api/v1/users/register`, `GET /api/v1/users/me`, `POST /api/v1/users/sessions`
- **Personas:** All users, Admin

### 17b. Real-Time Streaming (SSE)
- **What:** Server-Sent Events for real-time data push: pipeline progress, event bus live stream, scan status, copilot responses, live notifications.
- **File:** `suite-core/api/streaming_router.py`
- **Endpoints:** `GET /api/v1/stream/pipeline`, `GET /api/v1/stream/events`, `GET /api/v1/stream/scans`, `GET /api/v1/stream/copilot`, `GET /api/v1/stream/notifications`
- **Personas:** Any user (frontend consumption)

### 17c. Triage Inbox
- **What:** Transforms pipeline results into a triage inbox. Two views: individual findings ("events") or deduplicated cluster view. Enriched with exploitability, KEV, EPSS, compliance mapping.
- **File:** `suite-api/apps/api/app.py` (inline routes)
- **Endpoints:** `GET /api/v1/triage?view=events|clusters`, `GET /api/v1/triage/export`
- **Personas:** Security Analyst, SOC Analyst

### 17d. Health & Status
- **What:** Platform health check and authenticated status with version info.
- **File:** `suite-api/apps/api/app.py` (inline routes)
- **Endpoints:** `GET /health`, `GET /api/v1/status`
- **Personas:** Operations, Monitoring

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| Total Suites | 6 |
| Router Files | ~60 |
| Feature Categories | 17 |
| Distinct Features | 75+ |
| API Endpoints | ~250+ |
| Supported Languages (SAST) | 7 |
| Integration Connectors | 12+ |
| Compliance Frameworks | 5 (SOC2, PCI-DSS, HIPAA, GDPR, ISO 27001) |
| Feed Sources | 30+ |
| LLM Providers | 3 (OpenAI, Anthropic, Google) |
| Export Formats | 6 (PDF, JSON, CSV, SARIF, HTML, CEF) |

---

## Persona → Feature Mapping

| Persona | Key Feature Categories |
|---------|----------------------|
| **CISO** | Analytics (3a), Nerve Center (4c), Risk Quantification (10b), Risk Scoring (7e), Compliance Reports (7b) |
| **Security Analyst** | Triage (17c), Copilot Chat (2a), Agents (2b), Deduplication (14a), Exposure Cases (14d), Feeds (6a-g) |
| **Pen Tester / Red Team** | MPTE (8a), Micro-Pentest (8b), BAS (8c), PentAGI (8d), Vuln Discovery (8e), DAST (15b), API Fuzzing (15e) |
| **Developer** | Auto-Fix (4b), IDE Support (9d), SAST (15a), Secrets (15g), Remediation Tasks (13a) |
| **Compliance Officer / Auditor** | Audit Chain (7a), Evidence Vault (7d), Compliance Reports (7b), Provenance (7f), Policies (12a) |
| **DevSecOps Engineer** | Pipeline (4d), Workflows (4a), Data Ingestion (16a), Validation (16c), IaC (9c), Bulk Ops (4f) |
| **Platform Admin** | LLM Management (2c), Integrations (9a), SSO (9f), Marketplace (9g), Teams (5f) |
| **Risk Manager** | Monte Carlo FAIR (10b), SSVC (10d), Risk Trajectory (10e), Risk Graph (1a), Analytics (3a) |
| **Threat Intel Analyst** | Feeds (6a-g), EPSS (6b), KEV (6c), Threat Actors (6e), Exploit Intel (6f) |
| **Supply-Chain Security Lead** | SBOM Generation (11c), Dep Graph (1b), Provenance (7f), Supply-Chain Feeds (6g), License Compliance (11b) |

---

*Document generated from source-level audit of the ALdeci/FixOps codebase.*
