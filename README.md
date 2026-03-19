[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/DevOpsMadDog/Fixops)

<div align="center">

# ALdeci

### CTEM+ Decision Intelligence Platform with 8 Built-in Native Scanners

**Your scanners found 10,000 vulnerabilities. ALdeci tells you which 5 actually matter — and fixes them.**

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
[![Endpoints](https://img.shields.io/badge/API_endpoints-784-blue)]()
&nbsp;
[![Scanners](https://img.shields.io/badge/native_scanners-8-green)]()
&nbsp;
[![Parsers](https://img.shields.io/badge/scanner_parsers-25+-green)]()
&nbsp;
[![LLM Consensus](https://img.shields.io/badge/AI-Multi--LLM_Consensus-blueviolet)]()

> **⚠️ Work in Progress** — ALdeci is under active development. **Public beta planned for March 2026.** APIs may change. Star the repo to get notified when beta drops.

<br/>

*ALdeci is a **CTEM+ (Continuous Threat Exposure Management Plus)** platform with **784 API endpoints** that ingests your security chaos — SBOM, SARIF, CVE, CNAPP — normalizes it through 25+ scanner parsers, correlates via an AI Knowledge Graph, verifies exploitability with a 19-phase pentest engine, auto-fixes with 10 remediation types, and generates cryptographically signed evidence bundles. 8 built-in native scanners work fully air-gapped. All endpoints hardened with input validation, injection prevention, and SSRF guards.*

<br/>

[Get Started](#-quick-start) · [Features (75+)](#-complete-feature-catalog) · [Architecture](#-architecture) · [API & CLI](#-api--cli) · [Deploy](#-deployment) · [Roadmap](#-roadmap) · [Docs](#-documentation)

**[📖 Read "A Day in the Life" — How 25 real personas use ALdeci](docs/USER_STORY_APP_FLOW.md)**

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

ALdeci is a **CTEM+ Decision Intelligence Platform** for application security. It doesn't just aggregate findings — it scans, deduplicates, verifies exploitability, auto-fixes, and proves compliance with cryptographic evidence. Works with your existing tools (Switzerland model) AND ships 8 native scanners for air-gapped deployments.

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
<p>Jira, ServiceNow, Slack, GitHub, GitLab, Azure DevOps, ThreatMapper — all production-grade with full CRUD. Fits your workflow, not the other way around.</p>
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

| 784 | 22 | 75+ | 6 | 5 | 19 | 50+ | 13+ |
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
| **Multi-Source Feed Aggregation** | 50+ sources across 8 categories: Global (NVD, KEV, MITRE, CERT/CC), National CERTs (NCSC UK, BSI, ANSSI, JPCERT, CERT-In, ACSC, GovCERT SG, KISA), Exploits (ExploitDB, Metasploit, Vulners, Packet Storm, GreyNoise, Shodan, Censys), Threat Actors (Mandiant, CrowdStrike, Talos, Secureworks, Unit 42), Supply-Chain (OSV, GitHub Advisory, Snyk, Deps.dev, CycloneDX, SPDX), Cloud (AWS/Azure/GCP/K8s bulletins), Zero-Day (vendor blogs, GitHub commits), Internal scanners. | `GET /api/v1/feeds/status` · `GET /api/v1/feeds/categories` |
| **EPSS Scoring** | FIRST.org Exploit Prediction Scoring. Per-CVE probability scores. Bulk lookup. | `GET /api/v1/feeds/epss/{cve_id}` · `POST /api/v1/feeds/epss/bulk` |
| **CISA KEV Catalog** | Known Exploited Vulnerabilities lookup. Mandated patching compliance. | `GET /api/v1/feeds/kev/{cve_id}` · `GET /api/v1/feeds/kev` |
| **Finding Enrichment** | Enriches raw findings with EPSS, KEV, exploitability, threat actors, geo-weighted risk. | `POST /api/v1/feeds/enrich` |
| **Threat Actor Intelligence** | Maps CVEs to APT groups and MITRE ATT&CK techniques. | `GET /api/v1/feeds/threat-actors/{cve_id}` |
| **Exploit Intelligence** | Checks public exploits, PoCs, Metasploit modules per CVE. | `GET /api/v1/feeds/exploits/{cve_id}` |
| **Supply-Chain Lookup** | OSV, GitHub Advisory, Snyk for package-level vulns (npm, PyPI, Maven, Go). | `GET /api/v1/feeds/supply-chain/{package}` |
| **Geo-Weighted Risk Scoring** | Regional exploitation pattern analysis — risk differs by country/sector. | `GET /api/v1/feeds/geo-risk/{cve_id}` |
| **Exploit-Confidence Scoring** | Multi-factor confidence (not just CVSS): EPSS 25% + KEV 30% + exploit availability 25% + threat actor interest 20%. | `GET /api/v1/feeds/exploit-confidence/{cve_id}` |

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
| **13-Connector Integration Hub** | Jira, GitHub, GitLab, ServiceNow, Azure DevOps, Confluence, Slack, AWS Security Hub, Azure Security Center, Dependabot, Snyk, SonarQube, Deepfence ThreatMapper. Test and sync. | `POST /api/v1/integrations` · `POST /api/v1/integrations/{id}/test` · `POST /api/v1/integrations/{id}/sync` |
| **Extended CNAPP Connectors** | Wiz, Prisma Cloud, Orca Security, Lacework — cloud-native application protection platforms. | via `core/security_connectors.py` |
| **Bidirectional Webhooks** | Inbound receivers (Jira, ServiceNow, GitLab, Azure DevOps) with HMAC signature verification. Drift detection and resolution. Reliable outbox with retry. | `POST /api/v1/webhooks/jira` · `POST /api/v1/webhooks/drift/detect` |
| **IaC Scanning** | Checkov + tfsec integration. AWS/Azure/GCP/K8s. Scan HCL content, manage findings. | `POST /api/v1/iac/scan` · `POST /api/v1/iac/findings/{id}/remediate` |
| **IDE Extension Support** | Real-time code analysis for IDE plugins. Pattern + AST parsing for 7 languages. SARIF output. | `POST /api/v1/ide/analyze` · `POST /api/v1/ide/scan` |
| **OSS Tool Gateway** | Trivy, Grype, Sigstore/Cosign verification, OPA policy evaluation. | `POST /oss/trivy/scan` · `POST /oss/grype/scan` · `POST /oss/cosign/verify` |
| **SSO/SAML** | Okta, Azure AD, SAML providers. SSO config CRUD. | `POST /api/v1/auth/sso` |
| **Marketplace** | Remediation packs, policy templates, connectors, report templates. Built-in catalog + contributor system. | `GET /api/v1/marketplace/items` · `POST /api/v1/marketplace/contribute` |

### 10. ML, Self-Learning & Predictions

| Feature | What It Does | Key Endpoints |
|---|---|---|
| **Local ML Training** | Anomaly detection, threat assessment, response time prediction, API health scoring. Runs alongside your existing ML stack. | `POST /api/v1/ml/train` · `POST /api/v1/ml/predict` · `GET /api/v1/ml/anomalies` |
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
│ 51       │ Knowledge│ MPTE     │ NVD 2.0  │   Frameworks          │
│ Routers  │ Graph    │ 19-phase │ CISA KEV │ Signed Evidence       │
│ Auth     │ Pipeline │ AI Orch  │ EPSS     │ Risk Scoring          │
│ Rate     │ Decisions│ BAS      │ ExploitDB│ FAIR Monte Carlo      │
│ Limits   │ Event Bus│ SAST/DAST│ OSV + 45 │ Provenance            │
├──────────┴──────────┴──────────┴──────────┴───────────────────────┤
│                      suite-integrations                           │
│  Jira · ServiceNow · GitHub · GitLab · Azure DevOps · Slack      │
│  Confluence · AWS Security Hub · ThreatMapper · Trivy · OPA       │
│  Wiz · Prisma Cloud · Orca · Lacework · Cosign · Grype           │
└──────────────────────────────────────────────────────────────────┘
```

### Import Resolution — sitecustomize.py

All suites share a unified import system via [sitecustomize.py](sitecustomize.py) at the project root. Python auto-loads it at startup, prepending all suite directories to `sys.path`:

```python
# These imports Just Work from anywhere in the codebase:
from apps.api.app import create_app       # suite-api/apps/api/app.py
from core.connectors import JiraConnector  # suite-core/core/connectors.py
from risk.scoring import calculate_risk    # suite-evidence-risk/risk/scoring.py
```

> **Never manually manipulate `sys.path`.** `sitecustomize.py` handles it.

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

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **Python** | 3.11+ | 3.12, 3.13, 3.14 tested. [Download](https://www.python.org/downloads/) |
| **pip** | 22+ | Bundled with Python |
| **Git** | 2.x+ | [Download](https://git-scm.com/downloads) |
| **Docker** *(optional)* | 24+ | Only for container deployment. [Download](https://docs.docker.com/get-docker/) |
| **Docker Compose** *(optional)* | v2+ | Bundled with Docker Desktop |

### Option A: Local Development (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate    # Windows

# 3. Install dependencies
pip install --upgrade pip wheel
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — at minimum set FIXOPS_API_TOKEN

# 5. Start the API server
uvicorn apps.api.app:create_app --factory --host 0.0.0.0 --port 8000 --reload

# 6. Verify it's running
curl http://localhost:8000/health
# {"status":"healthy","version":"..."}
```

### Frontend (suite-ui/aldeci)

The official UI is a Vite + React application at `suite-ui/aldeci/`.

```bash
cd suite-ui/aldeci
npm install
npm run dev   # starts on http://localhost:5173
```

> **Note:** The legacy web/ micro-frontends are deprecated and archived at `archive/web_mfe_legacy/`. See [docs/legacy-ui.md](docs/legacy-ui.md) for migration details.

> **Or use `make bootstrap`** to create the venv and install everything in one command:
> ```bash
> make bootstrap
> source .venv/bin/activate
> uvicorn apps.api.app:create_app --factory --port 8000 --reload
> ```

### Option B: Docker

```bash
# Standard deployment
export FIXOPS_API_TOKEN=your-secret-token
docker compose -f docker/docker-compose.yml up -d

# Enterprise (with ChromaDB vector store for embeddings)
docker compose -f docker/docker-compose.enterprise.yml up -d

# With MPTE pentest engine
make up-mpte

# Verify
curl http://localhost:8000/health
```

### Option C: Docker Build from Source

```bash
# Build the image locally
docker build -t aldeci:local -f docker/Dockerfile docker/

# Run
docker run -d -p 8000:8000 \
  -e FIXOPS_API_TOKEN=your-token \
  -e FIXOPS_MODE=enterprise \
  -v $(pwd)/data:/app/data \
  aldeci:local

# Verify
curl http://localhost:8000/health
```

### First API Call

```bash
# Set your token
export API_TOKEN="your-token-from-.env"

# Health check (no auth required)
curl http://localhost:8000/health

# Get platform status (requires auth)
curl -H "X-API-Key: $API_TOKEN" http://localhost:8000/api/v1/status

# Upload an SBOM
curl -H "X-API-Key: $API_TOKEN" \
  -F "file=@sbom.json" \
  http://localhost:8000/api/v1/inputs/sbom

# Run the full 12-stage decision pipeline
curl -H "X-API-Key: $API_TOKEN" \
  http://localhost:8000/api/v1/pipeline/run

# Check EPSS score for a CVE
curl -H "X-API-Key: $API_TOKEN" \
  http://localhost:8000/api/v1/feeds/epss/CVE-2021-44228
```

<br/>

---

## ⚙️ Configuration

### Environment Variables

ALdeci is configured via environment variables. Copy [.env.example](.env.example) to `.env`:

```bash
cp .env.example .env
```

#### Core (Required)

| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_API_TOKEN` | — | **Required.** API authentication token. All authenticated endpoints require `X-API-Key` header. |
| `FIXOPS_ENVIRONMENT` | `demo` | Deployment mode: `demo`, `staging`, `production` |
| `FIXOPS_MODE` | `enterprise` | Runtime mode: `enterprise` (full features) or `demo` (sample data) |
| `SECRET_KEY` | — | Session management secret. **Change in production.** |

#### LLM Providers (Optional)

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | GPT-4 for consensus engine. [Get key](https://platform.openai.com/api-keys) |
| `ANTHROPIC_API_KEY` | Claude for consensus engine. [Get key](https://console.anthropic.com/settings/keys) |
| `GOOGLE_API_KEY` | Gemini for consensus engine. [Get key](https://aistudio.google.com/apikey) |
| `FIXOPS_ENABLE_OPENAI` | Enable/disable OpenAI provider (default: `true`) |
| `FIXOPS_ENABLE_ANTHROPIC` | Enable/disable Anthropic provider (default: `true`) |
| `FIXOPS_ENABLE_GEMINI` | Enable/disable Gemini provider (default: `true`) |

> **LLM keys are optional.** Without them, ALdeci falls back to deterministic decision rules — still fully functional, just without AI consensus.

#### Integration Tokens (Optional)

| Variable | Description |
|----------|-------------|
| `FIXOPS_JIRA_TOKEN` | Jira API token for bidirectional sync |
| `FIXOPS_CONFLUENCE_TOKEN` | Confluence API token |
| `FIXOPS_SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `THREATMAPPER_API_KEY` | Deepfence ThreatMapper console API key |

#### Security & Auth

| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_AUTH_DISABLED` | `false` | Disable authentication (**never in production**) |
| `FIXOPS_JWT_EXP_MINUTES` | `120` | JWT token expiration in minutes |
| `FIXOPS_RL_REQ_PER_MIN` | `60` | Rate limiting: requests per minute |
| `FIXOPS_RL_BURST_SIZE` | `10` | Rate limiting: burst size |
| `FIXOPS_EVIDENCE_KEY` | — | Fernet key for evidence encryption. Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

#### Infrastructure

| Variable | Default | Description |
|----------|---------|-------------|
| `UVICORN_WORKERS` | `4` | Number of API server workers |
| `FIXOPS_DISABLE_TELEMETRY` | `0` | Set to `1` to disable OpenTelemetry |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OpenTelemetry collector endpoint |
| `VECTOR_STORE_PROVIDER` | — | Set to `chromadb` for enterprise vector search |
| `VECTOR_STORE_PERSIST_DIR` | — | ChromaDB persistence directory |

<br/>

---

## 📡 API & CLI

**784 REST endpoints** across 73 router files in 6 suites. **22 CLI commands** for scripting and automation.

All authenticated endpoints require the `X-API-Key` header:

```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/api/v1/...
```

### Example API Calls

```bash
# Health & Status
curl http://localhost:8000/health
curl -H "X-API-Key: $API_TOKEN" http://localhost:8000/api/v1/status

# Upload SBOM (CycloneDX or SPDX)
curl -H "X-API-Key: $API_TOKEN" \
  -F "file=@sbom.json" http://localhost:8000/api/v1/inputs/sbom

# Upload SARIF scan results
curl -H "X-API-Key: $API_TOKEN" \
  -F "file=@results.sarif" http://localhost:8000/api/v1/inputs/sarif

# Run full 12-stage pipeline
curl -H "X-API-Key: $API_TOKEN" \
  http://localhost:8000/api/v1/pipeline/run

# EPSS score lookup
curl -H "X-API-Key: $API_TOKEN" \
  http://localhost:8000/api/v1/feeds/epss/CVE-2021-44228

# CISA KEV check
curl -H "X-API-Key: $API_TOKEN" \
  http://localhost:8000/api/v1/feeds/kev/CVE-2021-44228

# Enrich a finding with all threat intel
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2021-44228"}' \
  http://localhost:8000/api/v1/feeds/enrich

# Run AI-powered pentest against a target
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_urls":["https://example.com"],"cve_ids":["CVE-2021-44228"]}' \
  http://localhost:8000/api/v1/micro-pentest/run

# Create a copilot chat session
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Analysis"}' \
  http://localhost:8000/api/v1/copilot/sessions

# Monte Carlo risk simulation (FAIR model)
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2024-1234","simulations":10000}' \
  http://localhost:8000/api/v1/algorithms/monte-carlo

# Bulk create Jira tickets for findings
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"finding_ids":["f1","f2"],"action":"create_ticket","target":"jira"}' \
  http://localhost:8000/api/v1/bulk/operations

# Generate compliance report
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"framework":"soc2","format":"pdf"}' \
  http://localhost:8000/api/v1/audit/compliance-report

# Verify audit chain integrity
curl -H "X-API-Key: $API_TOKEN" \
  http://localhost:8000/api/v1/audit/hash-chain/verify
```

### Interactive API Docs

Once the server is running, visit:

| URL | Description |
|-----|-------------|
| http://localhost:8000/docs | Swagger UI — interactive API explorer |
| http://localhost:8000/redoc | ReDoc — alternative API documentation |
| http://localhost:8000/openapi.json | Raw OpenAPI 3.0 schema |

<br/>

---

## 🐳 Deployment

### Docker Compose Variants

All compose files are in the [docker/](docker/) directory:

| File | Use Case | Command |
|------|----------|---------|
| [docker-compose.yml](docker/docker-compose.yml) | Standard deployment with demo/smoke/feeds sidecars | `docker compose -f docker/docker-compose.yml up -d` |
| [docker-compose.enterprise.yml](docker/docker-compose.enterprise.yml) | Enterprise mode with ChromaDB vector store (4GB RAM) | `docker compose -f docker/docker-compose.enterprise.yml up -d` |
| [docker-compose.demo.yml](docker/docker-compose.demo.yml) | Client demo with dashboard | `docker compose -f docker/docker-compose.demo.yml up -d` |
| [docker-compose.mpte.yml](docker/docker-compose.mpte.yml) | MPTE pentest engine layer (overlay) | `make up-mpte` |

### Docker Compose Profiles

The standard `docker-compose.yml` includes optional sidecar services activated via profiles:

```bash
# Core API only (default)
docker compose -f docker/docker-compose.yml up -d

# With interactive demo sidecar
docker compose -f docker/docker-compose.yml --profile demo up -d

# With smoke tests
docker compose -f docker/docker-compose.yml --profile test up -d

# With continuous feed refresh (KEV + EPSS every hour)
docker compose -f docker/docker-compose.yml --profile feeds up -d

# With micro-pentest sidecar
docker compose -f docker/docker-compose.yml --profile pentest up -d

# With Risk Graph UI on port 3000
docker compose -f docker/docker-compose.yml --profile ui up -d

# Everything
docker compose -f docker/docker-compose.yml --profile demo --profile feeds --profile ui up -d
```

### MPTE Pentest Engine (Docker Layer)

MPTE can be layered on top of any compose file:

```bash
# Default (standard compose + MPTE)
make up-mpte

# Enterprise + MPTE
make up-mpte-enterprise

# Demo + MPTE
make up-mpte-demo

# Custom base
make up-mpte BASE_COMPOSE=docker/docker-compose.enterprise.yml

# Stop
make down-mpte

# View MPTE logs
make logs-mpte
```

### Build from Source

```bash
# Multi-stage build (Python 3.11-slim, ~500MB)
docker build -t aldeci:local -f docker/Dockerfile docker/

# Run with data persistence
docker run -d --name aldeci \
  -p 8000:8000 \
  -e FIXOPS_API_TOKEN=your-token \
  -e FIXOPS_MODE=enterprise \
  -v $(pwd)/data:/app/data \
  aldeci:local

# Health check
curl http://localhost:8000/health
```

### Production Checklist

- [ ] Set strong `FIXOPS_API_TOKEN` and `SECRET_KEY`
- [ ] Set `FIXOPS_ENVIRONMENT=production`
- [ ] Set `FIXOPS_AUTH_DISABLED=false` (default)
- [ ] Configure LLM API keys (or accept deterministic fallback)
- [ ] Set `UVICORN_WORKERS=4` (or higher for load)
- [ ] Mount persistent volume for `/app/data` (SQLite DBs, feeds, evidence)
- [ ] Generate `FIXOPS_EVIDENCE_KEY` for evidence encryption
- [ ] Configure integration tokens (Jira, Slack, etc.)
- [ ] Set up OpenTelemetry collector for observability
- [ ] Review rate limiting settings (`FIXOPS_RL_REQ_PER_MIN`)

<br/>

---

## 🔌 Integrations

### Production Connectors

All connectors inherit from `_BaseConnector` with circuit breaker, retry with exponential backoff, rate limiting, and health checks. Source: [suite-core/core/connectors.py](suite-core/core/connectors.py) and [suite-core/core/security_connectors.py](suite-core/core/security_connectors.py).

| Integration | Type | Capability | API/Version |
|---|---|---|---|
| **Jira** | Ticket Tracking | Bi-directional sync, auto-create issues, HMAC webhooks, SLA tracking | REST API v3 |
| **ServiceNow** | ITSM | Incident creation, CMDB enrichment, change requests | Table API |
| **GitHub** | DevOps | Issue sync, PR security checks, advisory ingestion | REST API (2022-11-28) |
| **GitLab** | DevOps | Issue sync, pipeline integration, webhook receivers | REST API v4 |
| **Azure DevOps** | DevOps | Work item sync, board integration | REST API v7.2 |
| **Confluence** | Documentation | Auto-generate compliance pages, evidence docs | REST API v2 |
| **Slack** | Notifications | Real-time alerts, decision notifications, weekly digests | Webhooks |
| **AWS Security Hub** | Cloud Security | Finding ingestion, posture sync | boto3 |
| **Azure Security Center** | Cloud Security | Defender for Cloud findings ingestion | REST API 2023-01-01 |
| **Snyk** | SCA/SAST | Project listing, vulnerability issue ingestion | REST API v1 |
| **SonarQube** | Code Quality | Issue ingestion, quality gate checks | Web API 10.x |
| **Dependabot** | SCA | Alert ingestion via GitHub GraphQL + REST | GitHub API |
| **Deepfence ThreatMapper** | Runtime CNAPP | Vulnerability, secret, malware, compliance scans; topology discovery; scan triggering | Console API v2 |

### Extended CNAPP Connectors

| Integration | Capability | Source |
|---|---|---|
| **Wiz** | GraphQL-based vuln, issue, cloud resource fetching | `security_connectors.py` |
| **Prisma Cloud** | Compliance + vulnerability data via Palo Alto REST API | `security_connectors.py` |
| **Orca Security** | Alert and vulnerability ingestion | `security_connectors.py` |
| **Lacework** | Security alerts + host/container vulnerability scans | `security_connectors.py` |

### OSS Tool Gateway

| Tool | Capability | Endpoint |
|---|---|---|
| **Trivy** | Container + SBOM vulnerability scanning | `POST /oss/trivy/scan` |
| **Grype** | Container image vulnerability scanning | `POST /oss/grype/scan` |
| **Sigstore / Cosign** | Artifact signature verification | `POST /oss/cosign/verify` |
| **OPA** | Policy evaluation gateway | `POST /oss/opa/evaluate` |

<br/>

---

## 🛠 Developer Guide

### Make Targets

```bash
make help                 # Show all available targets

# Setup
make bootstrap            # Create venv, install all deps + dev tools

# Code Quality
make fmt                  # Run isort + black formatters
make lint                 # Run flake8 lint checks

# Testing
make test                 # Run pytest with 60% coverage gate
pytest tests/test_integrations.py -v          # Single file
pytest -k "test_jira" -v                      # Pattern match
pytest -m unit -v                             # By marker

# Demo Pipeline
make demo-setup           # Create data directories
make demo-feeds           # Download real KEV + EPSS feeds
make demo-cves            # Generate 50k realistic CVE dataset
make demo-quick           # Quick demo (5k CVEs)
make demo-full            # Full demo (50k CVEs)
make demo-all             # Complete: setup + feeds + CVEs + full demo + tests
make demo-clean           # Clean demo artifacts (preserves feeds)

# Docker + MPTE
make up-mpte              # Start ALdeci + MPTE pentest engine
make up-mpte-enterprise   # Enterprise mode + MPTE
make up-mpte-demo         # Demo mode + MPTE
make down-mpte            # Stop all services
make logs-mpte            # View MPTE container logs

# Housekeeping
make inventory            # Rebuild file usage inventory
make clean                # Remove venv, caches, __pycache__
```

### Testing

Tests live in [tests/](tests/) and use pytest with markers defined in [pyproject.toml](pyproject.toml):

```bash
# Run all tests with coverage
pytest

# By marker
pytest -m unit             # Unit tests only
pytest -m integration      # Integration tests
pytest -m e2e              # End-to-end tests
pytest -m security         # Security tests
pytest -m performance      # Performance tests

# Coverage report
pytest --cov-report=html   # HTML report at htmlcov/index.html
```

Available markers: `unit`, `integration`, `performance`, `slow`, `security`, `regression`, `requires_network`, `requires_docker`, `requires_k8s`, `e2e`, `asyncio`.

Coverage gate: **60% minimum** (`--cov-fail-under=60`).

### Code Style

| Tool | Config | Command |
|---|---|---|
| **black** | [pyproject.toml](pyproject.toml) — line-length 88, target Python 3.11 | `make fmt` |
| **isort** | [pyproject.toml](pyproject.toml) — "black" profile | `make fmt` |
| **flake8** | `.flake8` | `make lint` |

> Files in `WIP/` are excluded from formatting and linting.

### Adding a New Router

1. Create `suite-api/apps/api/my_router.py` with `router = APIRouter(prefix="/api/v1/my-feature", tags=["my-feature"])`
2. Add `from apps.api.my_router import router as my_router` in [suite-api/apps/api/app.py](suite-api/apps/api/app.py)
3. Add `app.include_router(my_router, dependencies=[Depends(_verify_api_key)])` in `create_app()`

### Adding a New Connector

1. Create class in [suite-core/core/security_connectors.py](suite-core/core/security_connectors.py) inheriting from `_BaseConnector`
2. Implement `configured` property, `health_check()`, and data methods
3. Add to `IntegrationType` enum in [suite-core/core/integration_models.py](suite-core/core/integration_models.py)
4. Wire `test_integration()` and `trigger_sync()` in [suite-integrations/api/integrations_router.py](suite-integrations/api/integrations_router.py)
5. Add to `__all__` export list

<br/>

---

## 🛠 Technology

| Layer | Stack |
|---|---|
| **Backend** | Python 3.11+ · [FastAPI](https://fastapi.tiangolo.com) · [uvicorn](https://www.uvicorn.org) · SQLite WAL · [SQLAlchemy](https://www.sqlalchemy.org) |
| **AI/ML** | [OpenAI GPT-4](https://platform.openai.com) · [Anthropic Claude](https://console.anthropic.com) · [Google Gemini](https://ai.google.dev) · [scikit-learn](https://scikit-learn.org) · [pgmpy](https://pgmpy.org) (Bayesian) · [NetworkX](https://networkx.org) (graphs) |
| **Threat Intel** | [NVD 2.0](https://nvd.nist.gov/developers/vulnerabilities) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) · [ExploitDB](https://www.exploit-db.com) · [OSV](https://osv.dev) · [GitHub Advisories](https://github.com/advisories) · 50+ sources |
| **Integrations** | [Jira](https://developer.atlassian.com/cloud/jira/platform/rest/v3/) · [ServiceNow](https://www.servicenow.com/docs/bundle/zurich-api-reference/) · [Slack](https://api.slack.com) · [GitHub](https://docs.github.com/en/rest) · [GitLab](https://docs.gitlab.com/ee/api/rest/) · [Azure DevOps](https://learn.microsoft.com/en-us/rest/api/azure/devops/) · [ThreatMapper](https://threatmapper.org/) · 13+ connectors |
| **Scanning** | SAST (7 languages) · DAST · Container · IaC ([Checkov](https://www.checkov.io)/tfsec) · API Fuzzing · Secrets ([Gitleaks](https://gitleaks.io)) · Malware |
| **Crypto** | [RSA-SHA256](https://docs.python.org/3/library/hashlib.html) evidence signing · [Fernet](https://cryptography.io/en/latest/fernet/) encryption · [PyJWT](https://pyjwt.readthedocs.io) · [bcrypt](https://github.com/pyca/bcrypt) · [pyotp](https://pyauth.github.io/pyotp/) (TOTP/HOTP) |
| **Observability** | [OpenTelemetry](https://opentelemetry.io) · [structlog](https://www.structlog.org) · SSE streaming |
| **Standards** | [SARIF 2.1.0](https://sarifweb.azurewebsites.net) · [CycloneDX](https://cyclonedx.org) · [SPDX](https://spdx.dev) · [SSVC](https://www.cisa.gov/ssvc) · [FAIR](https://www.fairinstitute.org) · [SLSA](https://slsa.dev) · [MITRE ATT&CK](https://attack.mitre.org) |
| **Infrastructure** | [Docker](https://www.docker.com) · docker-compose · Kubernetes-ready · Air-gapped deployable |

### Key Dependencies

Pinned in [requirements.txt](requirements.txt):

```
fastapi>=0.115         uvicorn>=0.30.0       pydantic>=2.6
requests>=2.32         httpx>=0.27.0         cryptography>=46.0.3
scikit-learn>=1.3.0    pgmpy==0.1.24         networkx>=3.5
PyJWT>=2.8             bcrypt>=4.0.0         passlib[bcrypt]>=1.7.4
structlog>=25.4.0      PyYAML>=6.0.1         python-dotenv>=1.0.0
apscheduler>=3.10      tenacity>=8.2.0       sqlalchemy>=2.0.0
sarif-om>=1.0.4        ssvc>=1.2.0           cvss>=3.6
opentelemetry-sdk>=1.25                      pyotp>=2.9.0
```

Test dependencies in [requirements-test.txt](requirements-test.txt): pytest, pytest-cov, pytest-asyncio, httpx, responses, faker, freezegun, coverage.

<br/>

---

## 🗺 Roadmap

| Phase | Timeline | Features | Status |
|---|---|---|---|
| **v1 — Foundation** | Done | 784 API endpoints, 12-stage pipeline, multi-LLM consensus, MPTE, evidence bundles, 13 integrations, 75+ features | ✅ Shipped |
| **v2 — Developer Experience** | Next | VS Code extension, GitHub App (PR comments), `aldeci fix CVE-XXXX` one-liner, JetBrains plugin | 🔄 Building |
| **v3 — Cloud Attack Paths** | Planned | AWS/GCP/Azure resource ingestion, visual attack path graph, blast radius calculation, code-to-cloud-to-internet chain | 📋 Planned |
| **v4 — AST AutoFix** | Planned | AST-based code transforms (not regex), test generation for fixes, fix confidence scoring, 4 language support | 📋 Planned |
| **v5 — Continuous Compliance** | Planned | SOC 2 Type II continuous monitoring, FedRAMP Moderate, PCI-DSS 4.0, control-to-evidence auto-mapping | 📋 Planned |

<br/>

---

## 📖 Documentation

| Resource | Description |
|----------|-------------|
| [API Reference (784 endpoints)](docs/API_REFERENCE.md) | Complete endpoint documentation with curl examples, grouped by CTEM lifecycle |
| [User Guide](docs/USER_GUIDE.md) | 5-minute quickstart, scanner walkthroughs, troubleshooting |
| [Architecture](docs/ARCHITECTURE.md) | System overview with Mermaid diagrams, 6-suite architecture, data flow |
| [CTEM+ Identity](docs/CTEM_PLUS_IDENTITY.md) | Canonical platform identity — 8 scanners, 12-step pipeline, competitor matrix |
| [Investor Brief](docs/INVESTOR_BRIEF.md) | Technical product overview for investors and advisors |
| [CEO Vision](docs/CEO_VISION.md) | North-star vision document — 10 pillars, business model, roadmap |
| [Feature Audit (75+ features)](docs/FEATURE_AUDIT.md) | Complete source-verified feature catalog with endpoints |
| [A Day in the Life (25 personas)](docs/USER_STORY_APP_FLOW.md) | How 25 real personas use ALdeci — 28 chapters, 72 features |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | Contributing, testing, local setup |
| [Playbook Language](docs/PLAYBOOK_LANGUAGE_REFERENCE.md) | YAML playbook authoring reference |
| [PRD](docs/PRD.md) | Product Requirements Document |
| [Feature Roadmap](docs/research_next_features_to_build.md) | Strategic feature roadmap with competitor analysis |
| [Router Inventory](docs/ROUTER_ENDPOINT_INVENTORY.md) | Full router-by-router endpoint listing |
| [Comprehensive Analysis](docs/FIXOPS_COMPREHENSIVE_ANALYSIS.md) | Deep technical analysis of the platform |
| [DeepWiki (AI-indexed)](https://deepwiki.com/DevOpsMadDog/Fixops) | AI-indexed docs with semantic search |
| [.env.example](.env.example) | All environment variables with descriptions |
| [Makefile](Makefile) | All build/test/deploy targets |
| [pyproject.toml](pyproject.toml) | Python tooling config (black, isort, pytest) |

<br/>

---

## 📂 Repository Structure

```
ALdeci/
├── suite-api/                  API Gateway (FastAPI)
│   └── apps/api/
│       ├── app.py              Application factory, 27 include_router() calls
│       ├── dependencies.py     Auth (X-API-Key), rate limiting, org context
│       ├── *_router.py         73 router files across 6 suites
│       └── ...
├── suite-core/                 Core Engine
│   └── core/
│       ├── brain_pipeline.py   12-stage decision pipeline
│       ├── connectors.py       7 BaseConnector classes (Jira, GitHub, GitLab, etc.)
│       ├── security_connectors.py   9 security connectors (Snyk, Wiz, ThreatMapper, etc.)
│       ├── integration_models.py    IntegrationType enum, Integration dataclass
│       ├── llm_providers.py    Multi-LLM consensus (GPT-4, Claude, Gemini)
│       ├── event_bus.py        In-process event system (no external MQ)
│       ├── crypto.py           RSA-SHA256 signing, Fernet encryption
│       └── ...
├── suite-attack/               Attack Suite
│   ├── attack/
│   │   ├── micro_pentest.py    19-phase pentest engine
│   │   └── mpte_advanced.py    Multi-AI orchestration
│   └── api/
│       └── mpte_orchestrator_router.py
├── suite-feeds/                Threat Intelligence
│   ├── feeds_service.py        50+ feed sources, EPSS/KEV/NVD aggregation
│   └── api/
│       └── feeds_router.py     Feed endpoints, geo-weighted risk, exploit confidence
├── suite-evidence-risk/        Evidence & Risk
│   ├── risk/                   FAIR Monte Carlo, SSVC, risk scoring
│   └── evidence/               Signed bundles, SLSA provenance, WORM vault
├── suite-integrations/         Integrations
│   └── api/
│       └── integrations_router.py   Integration CRUD, test, sync
├── tests/                      Test suites (pytest)
│   ├── test_*.py               Unit, integration, e2e, security, performance
│   └── conftest.py             Shared fixtures
├── scripts/                    Automation scripts
│   ├── fetch_feeds.py          Download KEV + EPSS feeds
│   ├── generate_realistic_cves.py   Generate 50k CVE dataset
│   ├── demo_run.py             Demo pipeline runner
│   └── ...
├── docker/                     Container configs
│   ├── Dockerfile              Multi-stage build (Python 3.11-slim)
│   ├── Dockerfile.enterprise   Enterprise with ChromaDB
│   ├── docker-compose.yml      Standard deployment + sidecar profiles
│   ├── docker-compose.enterprise.yml   Enterprise deployment
│   ├── docker-compose.mpte.yml MPTE pentest overlay
│   └── kubernetes/             K8s manifests
├── docs/                       Documentation
├── data/                       Runtime data (SQLite DBs, feeds, evidence, artifacts)
├── sitecustomize.py            Auto-loads suite paths into sys.path
├── pyproject.toml              black, isort, pytest config
├── Makefile                    Build/test/deploy targets
├── requirements.txt            Production dependencies
├── requirements-test.txt       Test dependencies
├── .env.example                Environment variable template
└── LICENSE
```

<br/>

---

<div align="center">

### If this project is useful, please consider giving it a ⭐

**ALdeci** — Stop triaging. Start deciding.

[Get Started](#-quick-start) · [Read the Docs](https://deepwiki.com/DevOpsMadDog/Fixops) · [Report an Issue](https://github.com/DevOpsMadDog/Fixops/issues)

*Proprietary — See [LICENSE](LICENSE) for details.*

</div>
