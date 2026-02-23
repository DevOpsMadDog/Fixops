<div align="center">

# ALdeci

### The Decision Layer Your Security Stack Is Missing

**Your scanners found 10,000 vulnerabilities. Which 5 actually matter?**

[![Status](https://img.shields.io/badge/status-work_in_progress-orange)]()
&nbsp;
[![Beta](https://img.shields.io/badge/beta-March_2026-brightgreen)]()
&nbsp;
[![GitHub stars](https://img.shields.io/github/stars/DevOpsMadDog/Fixops?style=social)](https://github.com/DevOpsMadDog/Fixops/stargazers)
&nbsp;
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/DevOpsMadDog/Fixops)
&nbsp;
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
&nbsp;
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
&nbsp;
[![License](https://img.shields.io/badge/license-proprietary-red)](LICENSE)
&nbsp;
[![Endpoints](https://img.shields.io/badge/API_endpoints-600+-blue)]()
&nbsp;
[![LLM Consensus](https://img.shields.io/badge/AI-Multi--LLM_Consensus-blueviolet)]()

> **⚠️ Work in Progress** — ALdeci is under active development. **Public beta planned for March 2026.** APIs may change. Star the repo to get notified when beta drops.

<br/>

*ALdeci ingests your security chaos — SBOM, SARIF, CVE, CNAPP — correlates it through an AI Knowledge Graph, produces auditable decisions via multi-LLM consensus, verifies exploitability with a built-in pentest engine, and generates cryptographically signed evidence your auditor will actually accept.*

<br/>

[Get Started](#-quick-start) · [Features (75+)](#-complete-feature-catalog) · [Architecture](#-architecture) · [API & CLI](#-api--cli) · [Deploy](#-deployment) · [Roadmap](#-roadmap) · [Docs](https://deepwiki.com/DevOpsMadDog/Fixops)

</div>

---

<br/>

## The Problem

Security teams are drowning:

- **Alert fatigue** — 10,000+ vulnerabilities per quarter, no way to prioritize
- **Tool sprawl** — separate scanners, GRC, BAS, SOAR, ticketing, evidence collection
- **Manual triage** — senior engineers spending 60% of time on spreadsheets
- **Audit pain** — weeks of screenshot collection before every SOC 2 / ISO 27001 cycle
- **No single source of truth** — findings scattered across 8+ tools with no correlation

> *"We have more security tools than engineers. None of them tell us what to actually do."*
> — Every CISO, probably

<br/>

## The Solution

ALdeci is a **Decision Intelligence Platform** for security teams. One platform that replaces the gap between your scanners and your decisions.

<table>
<tr>
<td width="50%">

### What Goes In
- SBOM / SARIF / VEX / CNAPP artifacts
- CVE feeds (NVD, KEV, EPSS, OSV, ExploitDB)
- Cloud security posture (AWS, Azure, GCP)
- Business context (asset criticality, ownership)
- Existing tool outputs (any scanner)

</td>
<td width="50%">

### What Comes Out
- **Prioritized action list** — not 10,000 findings, the 5 that matter
- **Signed evidence bundles** — auditor-ready, RSA-SHA256
- **Verified exploitability** — AI pentest proves it's real (or not)
- **Automated remediation** — playbooks that actually fix things
- **Compliance posture** — SOC 2, ISO 27001, NIST, HIPAA, PCI-DSS

</td>
</tr>
</table>

<br/>

## Why ALdeci

<table>
<tr>
<td align="center" width="33%">
<h3>🧠 Multi-LLM Consensus</h3>
<p>GPT-4 + Claude + Gemini vote on every decision. 85% agreement threshold. No single model hallucination. Every verdict is auditable.</p>
</td>
<td align="center" width="33%">
<h3>🔬 Built-in Pentest Engine</h3>
<p>19-phase vulnerability verification. Don't just flag it — <strong>prove it's exploitable</strong>. MITRE ATT&CK mapped. Professional reports with PoC commands.</p>
</td>
<td align="center" width="33%">
<h3>📋 Cryptographic Evidence</h3>
<p>RSA-SHA256 signed evidence bundles with SLSA v1 provenance. Your auditor accepts them as-is. Cut audit prep from 6 weeks to 3 days.</p>
</td>
</tr>
<tr>
<td align="center" width="33%">
<h3>🧬 Self-Learning Knowledge Graph</h3>
<p>Every finding, decision, and outcome feeds a per-customer knowledge graph. ALdeci gets smarter the more you use it. That's not a feature — it's a moat.</p>
</td>
<td align="center" width="33%">
<h3>⚡ Full Lifecycle in One Platform</h3>
<p>Ingest → Correlate → Prioritize → Verify → Remediate → Prove. No context switches. No tool-to-tool integrations. One pane of glass.</p>
</td>
<td align="center" width="33%">
<h3>🔌 Enterprise-Ready Integrations</h3>
<p>Jira, ServiceNow, Slack, GitHub, GitLab, Azure DevOps — all production-grade with full CRUD. Fits your workflow, not the other way around.</p>
</td>
</tr>
</table>

<br/>

## No One Else Does All of This

| Capability | ALdeci | Snyk | Wiz | Orca | Apiiro | Drata |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| Multi-LLM Consensus (3 providers) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Self-Learning Knowledge Graph | ✅ | ❌ | Partial | Partial | ✅ | ❌ |
| Built-in Pentest Engine (MPTE) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Cryptographically Signed Evidence | ✅ | ❌ | ❌ | ❌ | ❌ | Partial |
| 12-Stage Decision Pipeline | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Code-to-Cloud Tracing | ✅ | ❌ | ✅ | ✅ | Partial | ❌ |
| 5-Framework Compliance Automation | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| SAST + DAST + Container + IaC + API Fuzzing | ✅ | Partial | Partial | Partial | Partial | ❌ |
| Monte Carlo Risk Quantification (FAIR) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| MCP Server (AI Agent Protocol) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

<br/>

## By the Numbers

<div align="center">

| 600+ | 112+ | 75+ | 7 | 5 | 19 | 30+ | 12 |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| API Endpoints | CLI Commands | Features | Suites | Compliance Frameworks | Pentest Phases | Threat Feed Sources | Connectors |

</div>

<br/>

---

## 📋 Complete Feature Catalog

> Every feature below is **built and backed by real code** — verified via source-level audit ([FEATURE_AUDIT.md](docs/FEATURE_AUDIT.md)).

### 1. Risk Graph & Attack Path Visualization

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Interactive Pipeline Risk Graph** | Transforms pipeline results into node/edge graph: services → components → findings → CVEs. Enriched with KEV, EPSS, criticality, PII flags, internet exposure. | `GET /api/v1/graph` |
| **Dependency & Supply-Chain Graph** | Builds supply-chain dependency graph from SBOM + risk reports. Traces artifact lineage, detects KEV-affected components. | `POST /graph/build` · `GET /graph/lineage/{artifact}` · `GET /graph/kev-affected` |
| **GNN Attack Path Prediction** | Graph Neural Network that predicts attack paths through infrastructure with probability scores. | `POST /api/v1/algorithms/gnn-attack-paths` |
| **Markov Chain Attack Simulation** | Simulates attacker movement through MITRE ATT&CK kill-chain stages. Returns stage-by-stage probabilities. | `POST /api/v1/predictions/attack-chain` · `POST /api/v1/predictions/attack-path` |
| **Code-to-Cloud Traceability** | Traces a vuln from source code → git commit → container → K8s → cloud → internet. Full lineage. | `POST /api/v1/code-to-cloud/trace` |
| **Knowledge Graph (Brain)** | Full CRUD knowledge graph — nodes (assets, vulns, services, policies), edges, full-text search, graph traversal. | `POST /api/v1/brain/nodes` · `GET /api/v1/brain/search` · `GET /api/v1/brain/traverse/{id}` |

### 2. NLP, Chat & AI Agents

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **ALdeci Copilot Chat** | Conversational LLM interface with sessions, context injection into Knowledge Brain, quick commands, AI suggestions, feeds integration. GPT-4 + Claude with auto-fallback. | `POST /api/v1/copilot/sessions` · `POST /api/v1/copilot/sessions/{id}/messages` · `POST /api/v1/copilot/quick-command` |
| **4 Specialized AI Agents** | **Security Analyst** (CVE analysis, threat intel), **Pentest** (exploit validation, PoC generation), **Compliance** (5-framework gap analysis, audit prep), **Remediation** (AI fix generation, PR creation). 28 endpoints total. | `POST /api/v1/copilot/agents/{type}/analyze` · `POST /api/v1/copilot/agents/{type}/actions` |
| **LLM Provider Management** | Configure multi-LLM backend. Check status, test connectivity, adjust temperature/tokens/timeout per provider. | `GET /api/v1/llm/status` · `POST /api/v1/llm/configure` · `POST /api/v1/llm/test` |
| **LLM Security Monitor** | Monitors prompts/responses for jailbreak/injection attacks, PII leakage, sensitive topic scanning. | `POST /api/v1/llm-monitor/analyze` |
| **MCP Server** | Exposes ALdeci as an MCP server for external AI agents (Copilot, Cursor, Windsurf, Zed). Tool/resource/prompt definitions. | `GET /api/v1/mcp/tools` · `GET /api/v1/mcp/resources` · `GET /api/v1/mcp/prompts` |

### 3. Analytics, Dashboards & Reporting

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Analytics Dashboard** | Finding counts by severity, trend analysis with moving averages, anomaly detection (z-score), top risks, severity heatmaps, risk-velocity scoring, CSV export. | `GET /api/v1/analytics/overview` · `GET /api/v1/analytics/trends` · `GET /api/v1/analytics/anomalies` |
| **Report Generation Engine** | Real reports from DB data. PDF, JSON, CSV, SARIF 2.1.0, HTML. Scheduled reports with cron, template-based, async processing. | `POST /api/v1/reports/generate` · `GET /api/v1/reports/{id}/download` · `POST /api/v1/reports/schedule` |
| **Global Search** | Universal full-text search across findings, CVEs, assets. Typed results with severity and context. | `GET /api/v1/search?q=...` |
| **SLA & Performance Metrics** | MTTR, scan coverage, ROI calculations, noise reduction stats, scanner comparison, tool effectiveness. | `GET /api/v1/analytics/mttr` · `GET /api/v1/analytics/roi` · `GET /api/v1/analytics/scanner-comparison` |

### 4. Automation, Playbooks & Workflows

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Workflow Orchestration** | Step-by-step engine with conditional branching, parallel execution, SLA tracking, pause/resume, retry with backoff. | `POST /api/v1/workflows` · `POST /api/v1/workflows/{id}/execute` · `POST /api/v1/workflows/{id}/pause` |
| **AI-Powered Auto-Fix** | LLM-generated code fixes. Single and bulk (up to 20), apply patches, create PRs, validate, rollback. Full fix lifecycle. | `POST /api/v1/autofix/generate` · `POST /api/v1/autofix/bulk` · `POST /api/v1/autofix/{id}/apply` |
| **Nerve Center** | Central orchestration — real-time threat pulse score (0-100), suite health monitoring, auto-remediation triggers, compliance posture. | `GET /api/v1/nerve-center/pulse` · `POST /api/v1/nerve-center/auto-remediate` |
| **12-Stage Brain Pipeline** | Full pipeline: ingest → normalize → enrich → deduplicate → correlate → risk-score → prioritize → remediate → verify → evidence → comply → report. | `POST /api/v1/brain/pipeline/run` · `POST /api/v1/brain/pipeline/run/async` |
| **Enterprise Bulk Operations** | Async bulk ops: update status, assign, create tickets (Jira/GitHub/GitLab/ServiceNow/AzureDevOps), accept risk, export, delete. | `POST /api/v1/bulk/operations` · `POST /api/v1/bulk/policies/apply` |

### 5. Collaboration

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Threaded Comments** | Commenting on any entity (finding, case, task). Parent/child nesting. | `POST /api/v1/collaboration/comments` |
| **Entity Watchers** | Subscribe to entity changes. Notifications on status/assignment updates. | `POST /api/v1/collaboration/watchers` |
| **Activity Feed** | Chronological activity stream — changes, comments, state transitions. | `GET /api/v1/collaboration/activity` |
| **Promote Comment → Evidence** | Convert collaboration comments directly into signed compliance evidence bundles. | `POST /api/v1/collaboration/comments/{id}/promote-to-evidence` |
| **Team Management** | Team CRUD with member add/remove and role assignment. | `POST /api/v1/teams` · `POST /api/v1/teams/{id}/members` |
| **Feedback Capture** | Collects user feedback on outputs to improve ML models. Human-in-the-loop. | `POST /feedback` |

### 6. Threat Intelligence Feeds

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Multi-Source Feed Aggregation** | 30+ sources across 8 categories: Global (NVD, KEV, MITRE), National CERTs (NCSC, BSI, ANSSI, JPCERT), Exploits (ExploitDB, Metasploit, Vulners), Threat Actors (ATT&CK groups, OTX), Supply-Chain (OSV, GitHub Advisory, Snyk), Cloud (AWS/Azure/GCP bulletins), Zero-Day, Internal scanners. | `GET /api/v1/feeds/status` · `GET /api/v1/feeds/categories` |
| **EPSS Scoring** | FIRST.org Exploit Prediction Scoring. Per-CVE probability scores. Bulk lookup. | `GET /api/v1/feeds/epss/{cve_id}` · `POST /api/v1/feeds/epss/bulk` |
| **CISA KEV Catalog** | Known Exploited Vulnerabilities lookup. Mandated patching compliance. | `GET /api/v1/feeds/kev/{cve_id}` · `GET /api/v1/feeds/kev` |
| **Finding Enrichment** | Enriches raw findings with EPSS, KEV, exploitability, threat actors, geo-weighted risk. | `POST /api/v1/feeds/enrich` |
| **Threat Actor Intelligence** | Maps CVEs to APT groups and MITRE ATT&CK techniques. | `GET /api/v1/feeds/threat-actors/{cve_id}` |
| **Exploit Intelligence** | Checks public exploits, PoCs, Metasploit modules per CVE. | `GET /api/v1/feeds/exploits/{cve_id}` |
| **Supply-Chain Lookup** | OSV, GitHub Advisory, Snyk for package-level vulns (npm, PyPI, Maven, Go). | `GET /api/v1/feeds/supply-chain/{package}` |

### 7. Compliance, Evidence & Audit

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Tamper-Proof Audit Chain** | SHA-256 hash-linked audit trail. Integrity verification. Detects tampering. | `GET /api/v1/audit/logs` · `GET /api/v1/audit/hash-chain/verify` |
| **Compliance Report Generation** | Auto-generates reports for SOC 2, ISO 27001, HIPAA, GDPR, PCI-DSS. Maps findings to framework controls. | `POST /api/v1/audit/compliance-report` |
| **Audit Log Export** | JSON, CSV, SIEM-compatible CEF for Splunk/QRadar integration. | `GET /api/v1/audit/export` |
| **Evidence Vault (WORM)** | Immutable evidence bundles with RSA-SHA256 signatures. Write-Once-Read-Many. | `GET /evidence/bundles` · `POST /evidence/bundles/{id}/verify` |
| **Risk Scoring Engine** | Per-component and per-CVE risk scoring. Aggregates EPSS, KEV, business context, exposure. | `GET /risk/summary` · `GET /risk/cves/{cve_id}` |
| **Provenance Attestations** | SLSA-style supply-chain provenance verification for build artifacts. | `GET /provenance/attestations` |
| **Decision & Verification Engine** | Multi-LLM consensus decisions on findings + SBOM + threat model + business context. Evidence + confidence scores. | `POST /decisions/make` · `GET /decisions/status` |

### 8. Penetration Testing & Attack Simulation

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Advanced MPTE** | Full Micro-Pentest Testing Engine — configure, verify CVE exploitability, run pentests, manage test queue. | `POST /api/v1/mpte/verify` · `POST /api/v1/mpte/run` · `GET /api/v1/mpte/results/{id}` |
| **Enterprise Micro-Pentest** | 8-phase testing: init → recon → threat model → vuln scan → exploit → compliance → risk score → attack path. MITRE ATT&CK aligned. Batch testing. | `POST /api/v1/micro-pentest/scan` · `POST /api/v1/micro-pentest/batch` |
| **Breach & Attack Simulation** | Create/manage attack scenarios. AI-generate via LLM. MITRE ATT&CK heatmap. Breach impact assessment. | `POST /api/v1/attack-sim/scenarios` · `POST /api/v1/attack-sim/scenarios/generate` |
| **MPTE Orchestrator API** | Unified gateway for threat intel, business impact, attack simulation, remediation guidance. | `POST /api/v1/mpte-orchestrator/threat-intel` · `POST /api/v1/mpte-orchestrator/simulate` |
| **Vulnerability Discovery & CVE Contribution** | Report pentested vulns, submit to CVE/MITRE programs, retrain ML models from discoveries. | `POST /api/v1/vulns/report` · `POST /api/v1/vulns/submit-cve` · `POST /api/v1/vulns/retrain` |

### 9. Integrations & Connectors

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **12-Connector Integration Hub** | Jira, GitHub, GitLab, ServiceNow, Azure DevOps, Confluence, Slack, AWS Security Hub, Azure Security Center, Dependabot, Snyk, SonarQube. Test and sync. | `POST /api/v1/integrations` · `POST /api/v1/integrations/{id}/test` · `POST /api/v1/integrations/{id}/sync` |
| **Bidirectional Webhooks** | Inbound receivers (Jira, ServiceNow, GitLab, Azure DevOps) with HMAC signature verification. Drift detection and resolution. Reliable outbox with retry. | `POST /api/v1/webhooks/jira` · `POST /api/v1/webhooks/drift/detect` |
| **IaC Scanning** | Checkov + tfsec integration. AWS/Azure/GCP/K8s. Scan HCL content, manage findings. | `POST /api/v1/iac/scan` · `POST /api/v1/iac/findings/{id}/remediate` |
| **IDE Extension Support** | Real-time code analysis for IDE plugins. Pattern + AST parsing for 7 languages. SARIF output. | `POST /api/v1/ide/analyze` · `POST /api/v1/ide/scan` |
| **OSS Tool Gateway** | Trivy, Grype, Sigstore/Cosign verification, OPA policy evaluation. | `POST /oss/trivy/scan` · `POST /oss/grype/scan` · `POST /oss/cosign/verify` |
| **SSO/SAML** | Okta, Azure AD, SAML providers. SSO config CRUD. | `POST /api/v1/auth/sso` |
| **Marketplace** | Remediation packs, policy templates, connectors, report templates. Built-in catalog + contributor system. | `GET /api/v1/marketplace/items` · `POST /api/v1/marketplace/contribute` |

### 10. ML, Self-Learning & Predictions

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Local ML Training** | Anomaly detection, threat assessment, response time prediction, API health scoring. Replaces external ML services. | `POST /api/v1/ml/train` · `POST /api/v1/ml/predict` · `GET /api/v1/ml/anomalies` |
| **Monte Carlo Risk Quantification (FAIR)** | Financial risk via simulation — VaR, Expected Annual Loss, loss exceedance curves. CVE-specific and portfolio-level. | `POST /api/v1/algorithms/monte-carlo` · `POST /api/v1/algorithms/portfolio-risk` |
| **Causal Inference (Root Cause)** | Statistical causal inference to separate correlation from causation in incidents. | `POST /api/v1/algorithms/causal-inference` |
| **SSVC Assessment** | Stakeholder-Specific Vulnerability Categorization via Bayesian network — Track/Track*/Attend/Act priority. | `POST /api/v1/predictions/ssvc-risk` |
| **Risk Trajectory Prediction** | Predicts how risk evolves over time based on patching velocity and threat landscape. | `POST /api/v1/predictions/risk-trajectory` |
| **Operator Feedback Loop** | Accepts human feedback to retrain deduplication models. Closes the learning cycle. | `POST /api/v1/deduplication/feedback` |

### 11. Asset Management & Inventory

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Unified Asset Inventory** | Application, service, API asset management with dependency graph resolution (transitive deps). | `POST /api/v1/inventory/assets` · `GET /api/v1/inventory/assets/{id}/dependencies` |
| **License Compliance** | Checks against allowed/blocked lists (MIT, Apache, GPL, AGPL). Flags copyleft contamination. | `GET /api/v1/inventory/licenses/compliance` |
| **SBOM Generation** | Generates CycloneDX and SPDX BOMs from inventory. | `GET /api/v1/inventory/sbom/{format}` |
| **Vuln-to-Asset Correlation** | Maps CVEs to affected assets. Per-asset risk scoring from aggregated exposure. | `GET /api/v1/inventory/assets/{id}/vulnerabilities` · `GET /api/v1/inventory/risk-scores` |
| **Fuzzy Identity Resolution** | Resolves asset names across scanners ("lodash" vs "npm:lodash"). Canonical registry with aliases. | `POST /api/v1/identity/resolve` · `POST /api/v1/identity/resolve/batch` |

### 12. Policy Management

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Policy-as-Code Engine** | OPA-style rules — severity, threshold, pattern matching. Actions: block, warn, notify, auto-remediate, quarantine, escalate. | `POST /api/v1/policies` · `PUT /api/v1/policies/{id}` |
| **Policy Simulation (Dry-Run)** | Test policies against findings without enforcement. Preview impact. | `POST /api/v1/policies/{id}/simulate` |
| **Auto-Enforcement** | Automatically evaluates policies against new findings and triggers actions. | `POST /api/v1/policies/enforce` |
| **Conflict Detection** | Detects conflicting policies (one blocks, another allows same pattern). | `GET /api/v1/policies/conflicts` |

### 13. Remediation Tracking

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Task Lifecycle** | Full state machine with validated transitions. Create, assign, track, verify. | `POST /api/v1/remediation/tasks` · `PATCH /api/v1/remediation/tasks/{id}/status` |
| **Verification Evidence** | Submit evidence that remediation was completed (screenshots, scans, tests). | `POST /api/v1/remediation/tasks/{id}/verify` |
| **External Ticket Linking** | Links tasks to Jira, ServiceNow, GitHub Issues. Bidirectional references. | `POST /api/v1/remediation/tasks/{id}/link-ticket` |

### 14. Deduplication & Exposure Cases

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Finding Deduplication** | Groups duplicate/related findings into clusters. Single + batch. Fuzzy cross-scanner matching. | `POST /api/v1/deduplication/process` · `POST /api/v1/deduplication/batch` |
| **Cluster Management** | Merge, split, assign, correlate clusters. Full cluster lifecycle. | `POST /api/v1/deduplication/clusters/merge` · `POST /api/v1/deduplication/clusters/{id}/split` |
| **Baseline Comparison** | Delta analysis between runs — new, resolved, persistent. CI/CD gating ready. | `POST /api/v1/deduplication/baseline` |
| **Exposure Cases** | Collapses noise into actionable cases. Lifecycle: OPEN → TRIAGING → FIXING → RESOLVED → CLOSED. SLA + playbook linking. | `POST /api/v1/cases` · `PATCH /api/v1/cases/{id}` |

### 15. Security Scanning Engines

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **SAST** | Static analysis for 7 languages (Python, JS, Java, Go, Ruby, PHP, C#). CWE mapping. | `POST /api/v1/sast/scan` · `POST /api/v1/sast/scan/files` |
| **DAST** | Live target scanning with crawling and configurable depth. | `POST /api/v1/dast/scan` |
| **Container Security** | Dockerfile scanning, image scanning (Trivy/Grype), base image checks. | `POST /api/v1/container/scan/dockerfile` · `POST /api/v1/container/scan/image` |
| **CSPM** | Terraform HCL + CloudFormation scanning. AWS/Azure/GCP rules. | `POST /api/v1/cspm/scan/terraform` · `POST /api/v1/cspm/scan/cloudformation` |
| **API Fuzzing** | Discovers endpoints from OpenAPI/Swagger specs, then fuzzes for vulns. | `POST /api/v1/api-fuzzer/discover` · `POST /api/v1/api-fuzzer/fuzz` |
| **Malware Detection** | File content scanning against known signatures. Single + batch. | `POST /api/v1/malware/scan` · `POST /api/v1/malware/scan/batch` |
| **Secrets Detection** | Gitleaks + trufflehog integration. Repo scanning, findings management. | `POST /api/v1/secrets/scan` · `GET /api/v1/secrets/findings` |

### 16. Data Ingestion & Validation

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **7-Format Ingestion** | Design CSV, SBOM (CycloneDX/SPDX), CVE, VEX, CNAPP, SARIF, Business Context. Supports gzip/zip. | `POST /inputs/sbom` · `POST /inputs/sarif` · `POST /inputs/cnapp` · `POST /inputs/context` |
| **Chunked Upload** | Multipart + chunked upload for large files and combined uploads. | `POST /api/v1/ingest/multipart` |
| **Dry-Run Validation** | Validates any scanner output without processing. Auto-detects format (SARIF, CycloneDX, SPDX, Snyk, Trivy, Grype, Checkov, SonarQube, ZAP). Schema drift detection. | `POST /api/v1/validate/dry-run` · `POST /api/v1/validate/detect-format` |
| **Business Context Enrichment** | Jira project + Confluence threat model import. Enriches findings with impact, sensitivity, compliance reqs. SSVC conversion. | `POST /business-context/upload` · `POST /business-context/enrich` |

### 17. Platform Infrastructure

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Auth & RBAC** | JWT + bcrypt, rate-limited login (5 attempts, 5-min lockout), session management, API key auth, audit-logged. | `POST /api/v1/users/login` · `POST /api/v1/users/register` |
| **Real-Time Streaming (SSE)** | Server-Sent Events: pipeline progress, event bus, scan status, copilot responses, live notifications. | `GET /api/v1/stream/pipeline` · `GET /api/v1/stream/events` · `GET /api/v1/stream/notifications` |
| **Triage Inbox** | Two views: individual findings or deduplicated clusters. Enriched with exploitability, KEV, EPSS, compliance mapping. | `GET /api/v1/triage?view=events` · `GET /api/v1/triage?view=clusters` |
| **Health & Status** | Platform health check with version info and component status. | `GET /health` · `GET /api/v1/status` |

<br/>

---

## 🏗 Architecture

ALdeci runs as a **6-suite modular monolith** — one port (8000), zero message queues, enterprise-grade separation:

```
┌──────────────────────────────────────────────────────────────────┐
│                        ALdeci Platform                            │
│                         Port 8000                                 │
├──────────┬──────────┬──────────┬──────────┬───────────────────────┤
│ suite-api│suite-core│suite-    │suite-    │ suite-evidence-risk   │
│ ──────── │ ──────── │attack    │feeds     │ ────────────────────  │
│ FastAPI  │ Brain    │ ──────── │ ──────── │ 5 Compliance          │
│ 32       │ Knowledge│ MPTE     │ NVD 2.0  │   Frameworks          │
│ Routers  │ Graph    │ 19-phase │ CISA KEV │ Signed Evidence       │
│ Auth     │ Pipeline │ AI Orch  │ EPSS     │ Risk Scoring          │
│ Rate     │ Decisions│ BAS      │ ExploitDB│ FAIR Monte Carlo      │
│ Limits   │ Event Bus│ SAST/DAST│ OSV      │ Provenance            │
├──────────┴──────────┴──────────┴──────────┴───────────────────────┤
│                      suite-integrations                           │
│  Jira · ServiceNow · GitHub · GitLab · Azure DevOps · Slack      │
│  Confluence · AWS Security Hub · Trivy · Grype · OPA · Cosign    │
└──────────────────────────────────────────────────────────────────┘
```

### Micro-Pentest Engine (MPTE) — The Crown Jewel

Most platforms *flag* vulnerabilities. ALdeci **proves** them.

| Capability | Detail |
|---|---|
| **19-phase scan** | Headers, SSL/TLS, SQLi, XSS, SSTI, CORS, Host Injection, HTTP Smuggling, Cache Poisoning, and more |
| **4-state verdicts** | `VULNERABLE_VERIFIED` · `NOT_VULNERABLE_VERIFIED` · `NOT_APPLICABLE` · `UNVERIFIED` |
| **Multi-stage verification** | Product Detection → Version Fingerprint → Exploit Verification → Differential Confirmation |
| **Multi-AI orchestration** | GPT-4 (Strategy) + Claude (Exploits) + Gemini (Architecture) — consensus-driven |
| **Professional reports** | HTML reports with PoC commands, MITRE ATT&CK mapping, architecture intelligence |

### Multi-LLM Consensus Engine

No single model. No hallucination risk. Three providers vote on every decision:

| Role | Provider | Weight | Focus |
|------|----------|--------|-------|
| Architect | Gemini | 0.35 | Attack surface, business impact |
| Developer | Claude | 0.40 | Exploitability, payload design |
| Team Lead | GPT-4 | 0.25 | Strategy, risk assessment |

**85% consensus threshold** — if the models disagree, the decision falls back to deterministic rules. Every verdict includes reasoning from all three providers.

### 12-Stage Brain Pipeline

```
Ingest → Normalize → Enrich → Deduplicate → Correlate → Risk-Score
   → Prioritize → Remediate → Verify → Evidence → Comply → Report
```

<br/>

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/DevOpsMadDog/Fixops.git && cd Fixops

# Backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # Set FIXOPS_API_TOKEN (required), LLM keys (optional)
uvicorn apps.api.app:app --host 0.0.0.0 --port 8000
```

### Docker (Production)

```bash
# Standard
docker compose -f docker/docker-compose.yml up -d

# Enterprise (with ChromaDB vector store)
docker compose -f docker/docker-compose.enterprise.yml up -d

# Verify
curl http://localhost:8000/api/v1/health
```

<br/>

---

## 📡 API & CLI

**600+ REST endpoints** across 32 router modules. **112+ CLI commands** across 31 groups.

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Run AI-powered micropentest against a target
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_urls":["https://example.com"],"cve_ids":["CVE-2021-44228"]}' \
  http://localhost:8000/api/v1/micro-pentest/run

# Upload SBOM for analysis
curl -H "X-API-Key: $API_TOKEN" \
  -F "file=@sbom.json" http://localhost:8000/api/v1/inputs/sbom

# Trigger full 12-stage decision pipeline
curl -H "X-API-Key: $API_TOKEN" http://localhost:8000/api/v1/pipeline/run

# Query AI Copilot
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"Which critical CVEs in my environment have public exploits?"}' \
  http://localhost:8000/api/v1/copilot/sessions/{id}/messages

# Monte Carlo risk quantification
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2024-1234","simulations":10000}' \
  http://localhost:8000/api/v1/algorithms/monte-carlo

# Bulk operations (update 100 findings at once)
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"finding_ids":["f1","f2"],"action":"create_ticket","target":"jira"}' \
  http://localhost:8000/api/v1/bulk/operations
```

<br/>

---

## 🔌 Integrations

| Integration | Capability | Status |
|---|---|---|
| **Jira** | Bi-directional sync, auto-create issues, HMAC webhooks, SLA tracking | Production |
| **ServiceNow** | Incident creation, CMDB enrichment, change requests | Production |
| **GitHub** | Issue sync, PR security checks, advisory ingestion | Production |
| **GitLab** | Issue sync, pipeline integration, webhook receivers | Production |
| **Azure DevOps** | Work item sync, board integration | Production |
| **Slack** | Real-time alerts, decision notifications, weekly digests | Production |
| **Confluence** | Auto-generate compliance pages, evidence docs | Production |
| **AWS Security Hub** | Finding ingestion, posture sync | Production |
| **Trivy / Grype** | Container + SBOM scanning gateway | Production |
| **Sigstore / Cosign** | Artifact signature verification | Production |
| **OPA** | Policy evaluation gateway | Production |
| **SonarQube / Snyk** | Finding ingestion + format detection | Production |

<br/>

---

## ⚙️ Configuration

| Variable | Required | Description |
|----------|:--------:|-------------|
| `FIXOPS_API_TOKEN` | ✅ | API authentication token |
| `FIXOPS_MODE` | | `enterprise` (default) or `demo` |
| `OPENAI_API_KEY` | | GPT-4 for consensus engine |
| `ANTHROPIC_API_KEY` | | Claude for consensus engine |
| `GOOGLE_API_KEY` | | Gemini for consensus engine |
| `FIXOPS_JIRA_TOKEN` | | Jira integration |
| `FIXOPS_SLACK_WEBHOOK` | | Slack notifications |
| `FIXOPS_EVIDENCE_KEY` | | Evidence encryption (Fernet) |

> **Note:** LLM keys are optional. Without them, ALdeci falls back to deterministic decision rules — still functional, just without AI consensus.

<br/>

---

## 🛠 Technology

| Layer | Stack |
|---|---|
| **Backend** | Python 3.11 · FastAPI · uvicorn · SQLite WAL |
| **AI/ML** | OpenAI GPT-4 · Anthropic Claude · Google Gemini · scikit-learn · pgmpy · NetworkX |
| **Threat Intel** | NVD 2.0 · CISA KEV · FIRST EPSS · ExploitDB · OSV · GitHub Advisories · 30+ sources |
| **Integrations** | Jira · ServiceNow · Slack · GitHub · GitLab · Azure DevOps · Confluence · 12 connectors |
| **Scanning** | SAST (7 languages) · DAST · Container · IaC · API Fuzzing · Secrets · Malware |
| **Infrastructure** | Docker · docker-compose · Kubernetes · Air-gapped deployable |

<br/>

---

## 🗺 Roadmap

| Phase | Timeline | Features | Status |
|---|---|---|---|
| **v1 — Foundation** | Done | 600+ API endpoints, 12-stage pipeline, multi-LLM consensus, MPTE, evidence bundles, 12 integrations, 75+ features | ✅ Shipped |
| **v2 — Developer Experience** | Next | VS Code extension, GitHub App (PR comments), `aldeci fix CVE-XXXX` one-liner, JetBrains plugin | 🔄 Building |
| **v3 — Cloud Attack Paths** | Planned | AWS/GCP/Azure resource ingestion, visual attack path graph, blast radius calculation, code→cloud→internet chain | 📋 Planned |
| **v4 — AST AutoFix** | Planned | AST-based code transforms (not regex), test generation for fixes, fix confidence scoring, 4 language support | 📋 Planned |
| **v5 — Continuous Compliance** | Planned | SOC 2 Type II continuous monitoring, FedRAMP Moderate, PCI-DSS 4.0, control-to-evidence auto-mapping | 📋 Planned |

<br/>

---

## 📖 Documentation

| Resource | Description |
|----------|-------------|
| [Feature Audit (75+ features)](docs/FEATURE_AUDIT.md) | Complete source-verified feature catalog with endpoints |
| [Architecture Overview](docs/SUITE_ARCHITECTURE.md) | Suite design, data flow, component interactions |
| [API Reference](docs/API_REFERENCE.md) | Complete endpoint documentation |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | Contributing, testing, local setup |
| [Playbook Language](docs/PLAYBOOK_LANGUAGE_REFERENCE.md) | YAML playbook authoring reference |
| [Feature Roadmap](docs/research_next_features_to_build.md) | Strategic feature roadmap with competitor analysis |
| [DeepWiki](https://deepwiki.com/DevOpsMadDog/Fixops) | AI-indexed docs with semantic search |

<br/>

---

## 📂 Repository Structure

```
ALdeci/
├── suite-api/              API Gateway — FastAPI, 32 routers, auth, rate limiting
├── suite-core/             Core Engine — brain, pipeline, decisions, knowledge graph, ML
├── suite-attack/           Attack Suite — MPTE, 19-phase pentest, BAS, SAST, DAST, fuzzing
├── suite-feeds/            Threat Intel — NVD, KEV, EPSS, ExploitDB, OSV, 30+ sources
├── suite-evidence-risk/    Evidence & Risk — compliance, signed bundles, FAIR risk, provenance
├── suite-integrations/     Integrations — Jira, Slack, GitHub, ServiceNow, IaC, IDE, MCP
├── tests/                  Test suites — unit, e2e, integration, load
├── scripts/                Automation — seed, deploy, monitor, benchmark
├── docs/                   Documentation — architecture, API ref, feature audit, roadmap
├── docker/                 Docker + Kubernetes configs
└── data/                   Runtime data (SQLite DBs, feeds, evidence)
```

<br/>

---

<div align="center">

### If this project is useful, please consider giving it a ⭐

**ALdeci** — Stop triaging. Start deciding.

[Get Started](#-quick-start) · [Read the Docs](https://deepwiki.com/DevOpsMadDog/Fixops) · [Report an Issue](https://github.com/DevOpsMadDog/Fixops/issues)

*Proprietary — See [LICENSE](LICENSE) for details.*

</div>
