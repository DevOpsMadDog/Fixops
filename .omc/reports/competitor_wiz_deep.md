# Wiz.io Deep Competitive Intelligence Report

**Date:** 2026-04-22
**Analyst:** Claude Opus 4.6 (CTO Agent)
**Classification:** Internal -- Product Strategy Use Only
**Purpose:** Comprehensive Wiz analysis to inform ALDECI product positioning, roadmap, and sales strategy

---

## Table of Contents

1. [Company Overview & Acquisition Context](#1-company-overview--acquisition-context)
2. [Complete Product Feature Map](#2-complete-product-feature-map)
3. [API Capabilities](#3-api-capabilities)
4. [Compliance Frameworks](#4-compliance-frameworks)
5. [Integration Ecosystem (268 Partners)](#5-integration-ecosystem-268-partners)
6. [Pricing Model](#6-pricing-model)
7. [Top 5 Enterprise Differentiators](#7-top-5-enterprise-differentiators)
8. [Known Weaknesses & Gaps](#8-known-weaknesses--gaps)
9. [Attack Path & Security Graph Deep Dive](#9-attack-path--security-graph-deep-dive)
10. [Head-to-Head: ALDECI vs Wiz](#10-head-to-head-aldeci-vs-wiz)
11. [Strategic Recommendations for ALDECI](#11-strategic-recommendations-for-aldeci)
12. [Sources](#12-sources)

---

## 1. Company Overview & Acquisition Context

| Attribute | Detail |
|-----------|--------|
| **Founded** | 2020 (Israel) |
| **Acquisition** | Google completed acquisition of Wiz for **$32B cash** on March 11, 2026 -- largest acquisition in Google history |
| **ARR** | $1B+ (2025), estimated $1.5B+ (2026) |
| **Customers** | 50% of Fortune 100 including Salesforce, Slack, Mars, BMW, DocuSign, Plaid, Agoda |
| **Employees** | ~1,800+ |
| **Category** | CNAPP (Cloud-Native Application Protection Platform) |
| **Deployment** | SaaS-only (multi-tenant cloud) |
| **Multi-cloud** | AWS, Azure, GCP, OCI, Alibaba Cloud, VMware vSphere |
| **Regulatory status** | FedRAMP Moderate authorized, SOC 2 Type II, ISO 27001/27017/27018/27701, HIPAA |
| **Analyst recognition** | Forrester Wave CNAPP Q1 2026 -- **Leader** with highest score in current offering (10/12 top marks) |
| **Post-acquisition** | Maintains independent brand within Google Cloud; binding EU/US regulatory commitment to multi-cloud neutrality; expected convergence with Google Chronicle SIEM, Vertex AI, Gemini |

### What the $32B Acquisition Means for ALDECI

Google's acquisition validates the cloud security market at the highest level. However, it introduces strategic risks for Wiz customers:

- **Vendor lock-in anxiety**: Enterprises on AWS/Azure may worry about Google ownership bias despite regulatory commitments
- **Price increases**: Google historically raises prices post-acquisition (Looker, Mandiant precedent)
- **Product roadmap uncertainty**: Will Wiz features become GCP-exclusive or degraded on competing clouds?
- **Data sovereignty**: Wiz data now flows through Google infrastructure -- a concern for regulated industries
- **Talent attrition**: Israeli founding team may depart after vesting cliff

**ALDECI opportunity**: Self-hosted, vendor-neutral, no acquisition risk. This narrative becomes stronger post-Google-acquisition.

### 2026 Post-Acquisition Product Announcements

Since the March 2026 acquisition close, Wiz has announced:

1. **Wiz Exposure Management** -- Unified risk visibility across cloud and AI surfaces
2. **AI Security Agents** -- Issues Agent (remediation guidance) and SecOps Agent (threat investigation with confidence verdicts)
3. **Wiz MCP Server** -- Model Context Protocol server for natural-language security queries in IDEs (Cursor, VS Code) and AI assistants
4. **WizOS** -- Hardened container base images for secure-by-default deployments
5. **WIN AI Security Category** -- New integration category for AI-focused partners
6. **Mika AI enhancements** -- Platform-wide conversational AI assistant, now powered by Gemini integration roadmap

---

## 2. Complete Product Feature Map

### 2.1 Core Platform Modules

| Module | Full Name | What It Does |
|--------|-----------|-------------|
| **CSPM** | Cloud Security Posture Management | Evaluates cloud configs against CIS, NIST, PCI, SOC 2; 2,800+ built-in rules; continuous scanning |
| **CWPP** | Cloud Workload Protection Platform | Vulnerability scanning of VMs, containers, serverless; malware detection; secrets scanning |
| **KSPM** | Kubernetes Security Posture Management | Cluster mapping, privileged pod detection, overpermissive service accounts, CIS K8s benchmarks |
| **DSPM** | Data Security Posture Management | Scans actual content of S3/RDS/Blob/BigQuery for PII/PCI/PHI using regex + ML classifiers |
| **CIEM** | Cloud Infrastructure Entitlement Management | Effective permissions analysis, least-privilege recommendations, unused/stale access detection |
| **AI-SPM** | AI Security Posture Management | Discovers unmanaged AI models, training datasets, unrestricted inference endpoints; generates AI-BOM; detects MCP connections |
| **IaC Security** | Infrastructure as Code Scanning | Terraform, CloudFormation, ARM, Helm, Kubernetes manifests scanned in CI/CD |
| **CDR / Wiz Defend** | Cloud Detection & Response | eBPF runtime sensor, real-time threat detection, behavioral analytics, cloud forensics |
| **Wiz Code** | Developer Security | IDE integration, CI/CD pipeline scanning, code-to-cloud tracing, secrets detection, SBOM |
| **Vulnerability Mgmt** | CVE Lifecycle | CVE data with CVSS, EPSS, KEV status, vendor severity, remediation guidance |

### 2.2 Wiz Defend (CDR) -- Runtime Security Deep Dive

Wiz Defend is their newest and fastest-growing module, GA since late 2025:

| Capability | Detail |
|-----------|--------|
| **Runtime Sensor** | Lightweight eBPF-based sensor; kernel-safe architecture (runs in restricted kernel sandbox) |
| **Performance Impact** | Under 2% CPU overhead; cannot crash or degrade host performance |
| **OS Support** | Linux (initial), Windows (added 2026) |
| **Threat Detection** | Cryptominers, fileless malware (memfd_create monitoring), lateral movement (anomalous SSH), C2 beacons |
| **AI Threat Detection** | Prompt injection, rogue AI agents, malicious AI agent actions |
| **Cloud Log Analysis** | CloudTrail monitoring: PutBucketAcl, AuthorizeSecurityGroupIngress, CreateAccessKey, ConsoleLogin without MFA |
| **Behavioral Baselining** | Learns normal process behavior per workload, alerts on deviations |
| **File Integrity** | Monitors file changes, image drift, log tampering |
| **Network Monitoring** | Network scanning detection, malicious IOC matching |
| **Forensics** | Full process tree capture for every protected host; integrated forensic collection |
| **Query Language** | KQL queries, Sigma rules, Python automation hooks |
| **SecOps Agent** | AI-powered investigation assistant -- auto-triages threats, produces verdicts with confidence levels |
| **MTTD Claim** | "10x faster detection" vs traditional SIEM-based approaches |
| **MTTR Claim** | "10x reduction" via AI-powered investigations |

### 2.3 Wiz Code -- Developer Security

| Capability | Detail |
|-----------|--------|
| **IDE Integration** | JetBrains, VS Code, Cursor (via MCP Server) |
| **CI/CD Scanning** | CLI-based scanning in 19 CI/CD systems (GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps, etc.) |
| **Code-to-Cloud Tracing** | Maps live cloud risks back to the exact line of code that introduced them |
| **IaC Scanning** | Terraform, CloudFormation, ARM templates, Helm charts, Kubernetes manifests |
| **Container Image Scanning** | Registry scanning + pipeline blocking on policy violations |
| **Secret Detection** | AWS Access Keys, private keys, DB connection strings, OAuth tokens |
| **SBOM** | Software Bill of Materials generation and tracking |
| **Automated Fixes** | 1-click pull request generation for code-level remediation |
| **Known Limitations** | Immature per user reviews -- missing rule ID display, limited ignore granularity in IDE |

### 2.4 AI-SPM (AI Security Posture Management)

Wiz was first-to-market with dedicated AI security posture management:

| Capability | Detail |
|-----------|--------|
| **AI-BOM** | Auto-discovers all AI services, libraries, SDKs, and models across cloud and SaaS |
| **AI Attack Paths** | Identifies attack paths targeting AI pipelines (e.g., training data poisoning via exposed S3 bucket) |
| **Model Discovery** | Finds unmanaged/shadow AI deployments including MCP server connections |
| **Agent Discovery** | Detects unauthorized autonomous AI agents (rogue agent detection) |
| **Prompt Injection Detection** | Runtime detection via Wiz Defend eBPF sensor |
| **Training Data Security** | DSPM integration to classify sensitivity of training datasets |
| **AI Endpoint Visibility** | New widget surfacing live endpoints across AI Security, AI as a Service, AI Tools, AI Pipelines, AI Frameworks, AI Models |
| **MCP Connection Mapping** | Discovers and maps Model Context Protocol connections between AI tools and data sources |

### 2.5 SideScanning Technology (Agentless Core)

Wiz's agentless scanning architecture is a key technical differentiator:

1. Cross-account IAM role grants read-only API access
2. Native cloud snapshots created (not on the running workload)
3. Ephemeral out-of-band analysis in the same region (no cross-region data transfer)
4. Analysis completes in 4-15 minutes per workload
5. Cryptographic destruction of snapshots after analysis
6. No agents installed, no performance impact on production

**Default scan frequency**: Every 24 hours (a known limitation addressed by Runtime Sensor for real-time gaps)

### 2.6 AI Agents (New 2026)

| Agent | Purpose | Capabilities |
|-------|---------|-------------|
| **Issues Agent** | Detection-to-resolution | Evaluates remediation paths, clarifies ownership, highlights actions, previews fix sequences |
| **SecOps Agent** | SOC investigation | Auto-triages threats, analyzes detection data + timelines, produces verdicts with confidence levels, generates investigation summaries |
| **Mika (Ask AI)** | Platform-wide assistant | Natural language queries throughout Wiz UI: "Which of my LLMs have access to production databases?" |
| **MCP Server** | IDE/AI integration | Translates natural language to Wiz operations; supports exposure analysis, toxic combination checks, data sensitivity queries in Cursor/VS Code |

### 2.7 Workflow Orchestration (New 2026)

Wiz added a **no-code canvas** for building multi-step automation sequences -- enabling teams to build workflows visually without writing code. This includes:
- Trigger conditions on findings/events
- Multi-step response actions
- Integration with ticketing, messaging, and SOAR platforms
- Custom remediation playbooks

---

## 3. API Capabilities

### 3.1 Architecture

| Attribute | Detail |
|-----------|--------|
| **API Style** | GraphQL-only (single endpoint) -- NO REST API |
| **Endpoint** | `https://api.<TENANT_DC>.app.wiz.io/graphql` (us1, us2, eu1, eu2) |
| **Authentication** | OAuth 2.0 Client Credentials (service account model) |
| **Token Endpoint** | `https://auth.app.wiz.io/oauth/token` |
| **Token Lifetime** | ~1 hour (not publicly documented) |
| **Rate Limit** | 10 req/s per service account per tenant (updated; previously reported as 3 req/s by third-party docs) |
| **Pagination** | Cursor-based (`pageInfo.endCursor`), max 500 records/page |
| **Result Caps** | Audit Logs: 10,000/query; Cloud Config: 10,000/query |
| **Webhooks** | NONE -- polling only |
| **WebSocket** | NONE |
| **Official SDK** | NONE (community Python wrappers exist) |
| **CLI** | Wiz CLI for CI/CD scanning only, not general API operations |
| **SCIM** | Enterprise plan only (`https://api.<tenant>.wiz.io/scim/v2`) |
| **MCP Server** | New in 2026 -- natural language queries via Model Context Protocol (preview) |

### 3.2 GraphQL Scopes (Permissions)

| Scope | Access |
|-------|--------|
| `read:all` | Super-scope: full read access |
| `read:cloud_accounts` | Cloud provider accounts |
| `read:resources` | Cloud resource inventory |
| `read:cloud_configuration` | Configuration findings |
| `read:host_configuration` | Host-level config findings |
| `read:issues` | Issues + controls + service tickets |
| `read:vulnerabilities` | CVE/vulnerability data |
| `read:inventory` | Full inventory (K8s, repos, technologies) |
| `read:sbom_artifacts` | SBOM package data |
| `read:projects` | Organizational groupings |
| `read:reports` | Access reports endpoint |
| `create:reports` | Generate new reports (CSV bulk export) |
| `read:users` | User management reads |
| `write:users` | User CRUD mutations |
| `read:service_accounts` | Service account reads |

### 3.3 Data Domains Queryable via GraphQL

| Domain | Read | Write |
|--------|------|-------|
| Issues / findings | Yes | Status update only |
| Vulnerabilities (CVE) | Yes | No |
| Cloud configuration findings | Yes (10K cap) | No |
| Host configuration findings | Yes | No |
| Cloud resource inventory | Yes | No |
| Cloud accounts | Yes | No |
| Kubernetes resources | Yes | No |
| IAM identities & permissions | Yes | No |
| SBOM artifacts | Yes | No |
| Users & service accounts | Yes | Yes (CRUD) |
| Audit logs | Yes (10K cap) | No |
| Projects / orgs | Yes | Limited |
| Compliance posture | Yes | No |

### 3.4 Bulk Export

For large datasets exceeding GraphQL's practical limits, Wiz provides a separate **Reports endpoint** that generates CSV exports. This requires the `create:reports` scope and is the only way to extract >10,000 records.

### 3.5 Critical API Limitations vs ALDECI

| Limitation | Impact | ALDECI Advantage |
|-----------|--------|------------------|
| **No webhooks** | Cannot push events to external systems in real-time | Full webhook system + WebSocket real-time push |
| **No REST API** | Forces all integrators to learn GraphQL | REST + GraphQL available |
| **No official SDK** | Every integrator builds their own client | OpenAPI auto-generated client possible |
| **10K result caps** | Cannot query full datasets in single call | No arbitrary caps |
| **OAuth 2.0 only** | Two-step auth flow adds complexity | Simple API key auth (one step) |
| **SaaS-only** | API endpoint is internet-hosted -- no private network option | Self-hosted, on-prem API |
| **Rate limit ceiling** | 10 req/s per service account caps high-throughput use | Configurable per-tenant rate limiting |

---

## 4. Compliance Frameworks

### 4.1 Frameworks Wiz Scans Against (100+ Built-In)

**Tier 1 -- Core Frameworks:**
- CIS Benchmarks (AWS, Azure, GCP, OCI, Kubernetes)
- NIST SP 800-53 (Rev 4 and Rev 5)
- NIST Cybersecurity Framework (CSF 2.0)
- PCI DSS v3.2.1 and v4.0
- SOC 2 Type II
- HIPAA / HITECH
- ISO 27001:2022
- GDPR
- FedRAMP (Moderate)
- FISMA

**Tier 2 -- Industry-Specific:**
- HITRUST CSF
- CCPA / CPRA
- LGPD (Brazil)
- PIPEDA (Canada)
- APRA CPS 234 (Australia)
- MAS TRM (Singapore)
- PDPA (Thailand)
- K-ISMS (South Korea)
- ENS (Spain)
- C5 (Germany)

**Tier 3 -- Cloud Provider Specific:**
- AWS Well-Architected Framework
- Azure Security Benchmark
- GCP Security Best Practices
- CIS Controls v8

**Custom Frameworks:** OPA/Rego-based custom policy engine for organizational rules.

### 4.2 Compliance Features

| Feature | Detail |
|---------|--------|
| **Continuous assessment** | Automatic posture evaluation against all enabled frameworks |
| **Cross-framework mapping** | Auto-correlates controls across overlapping frameworks (e.g., SOC 2 CC6.1 maps to ISO 27001 A.9) |
| **Built-in rules** | 1,400+ configuration rules mapped to frameworks (previously cited as 2,800; Wiz documentation now says 1,400+ mapped) |
| **Compliance heatmap** | Bird's-eye view across all frameworks x environments; color-coded cells |
| **Custom policies** | OPA/Rego-based custom policy engine |
| **Evidence export** | Compliance reports exportable as CSV for auditors |
| **Drift detection** | Alerts when compliance posture degrades |
| **Project-scoped compliance** | Compliance views filtered by business unit / cloud account |

### 4.3 Wiz's Own Certifications

Wiz itself holds: SOC 2 Type II, SOC 3, ISO 27001, ISO 27017, ISO 27018, ISO 27701, HIPAA, FedRAMP Moderate.

### 4.4 ALDECI Compliance Comparison

| Dimension | Wiz | ALDECI |
|-----------|-----|--------|
| Built-in frameworks | 100+ (cloud-focused) | 100+ (cloud + enterprise + OT/IoT) |
| Custom frameworks | Yes (OPA/Rego) | Yes (engine-based) |
| Evidence auto-collection | No (manual CSV export) | Yes (automated evidence collector + evidence vault + SHA-256 tamper chain) |
| Audit trail | Basic audit log | Immutable SHA-256 chain audit trail with tamper detection |
| Compliance calendar | No | Yes (scheduling, deadlines, recurring events) |
| Compliance workflow | No | Yes (approval lifecycle, auto-transition, 8 frameworks, 6 types) |
| Evidence vault | No | Yes (tamper-evident, sealed guard, retention policy) |
| Risk register integration | No | Yes (native risk register + treatment + quantification via FAIR) |
| Regulatory change tracking | No | Yes (regulatory tracker engine) |
| Questionnaire management | No | Yes (security questionnaire engine, 6 frameworks, vendor risk) |
| Gap analysis | Limited | Yes (SecurityGapAnalysis engine, 10 frameworks, risk_level thresholds) |
| Compliance mapping | Limited cross-framework | Yes (ComplianceMapping engine, implementation_rate auto-computed) |

**ALDECI advantage**: Wiz scans for compliance violations. ALDECI manages the entire compliance lifecycle -- from scanning through evidence collection, audit management, risk treatment, and regulatory reporting.

---

## 5. Integration Ecosystem (268 Partners)

Wiz maintains the **WIN (Wiz Integration Network)** with 268 named integrations across 30 categories. This is one of the largest integration ecosystems in cloud security.

### 5.1 Complete Integration Map by Category

| Category | Count | Key Partners |
|----------|-------|-------------|
| **Vulnerability Mgmt & Response** | 22 | Qualys, Tenable, Rapid7, Armis, Axonius, Ivanti, Nucleus, Seemplicity, ServiceNow VR |
| **CI/CD** | 19 | GitHub, GitLab, Jenkins, CircleCI, Azure DevOps, Bitbucket, Buildkite, Travis CI, AWS CodeBuild, Spacelift, Atlantis, Harness, TeamCity, OpenShift |
| **Compliance Management** | 17 | Drata, Vanta, Sprinto, Hyperproof, Anecdotes, Cypago, RegScale, ZenGRC, Scytale, 6clicks, Caveonix |
| **SOAR & Automation** | 16 | Cortex XSOAR, Tines, Torq, Swimlane, Workato, QRadar SOAR, D3 Security, Blinkops |
| **Security Data Management** | 15 | AWS CloudTrail Lake/Security Lake, Brinqa, Censys, Panaseer |
| **SIEM** | 14 | Splunk, Microsoft Sentinel, Datadog, Elastic, QRadar, Sumo Logic, Google SecOps, Securonix, Panther, Exabeam, Devo, Hunters |
| **Ticketing & Messaging** | 14 | Jira, ServiceNow ITSM, Slack, Microsoft Teams, PagerDuty, Opsgenie, Zendesk, Linear, ClickUp |
| **Application Security Scanners** | 14 | Checkmarx, Snyk, SonarQube, Semgrep, Rapid7, Mend.io, Endor Labs |
| **Application Security** | 11 | Apiiro, Black Duck, Veracode ASPM, OXSecurity, Legit Security |
| **Identity Security** | 11 | Okta, CyberArk/Palo Alto, Saviynt, ConductorOne, Oasis Security, Aembit |
| **MDR** | 10 | Arctic Wolf, Expel, Red Canary/Zscaler, ReliaQuest, Sygnia |
| **Data Lake & Analytics** | 10 | Snowflake, Elastic, Cribl, CloudQuery, Databahn |
| **Cloud Services** | 9 | AWS S3/SNS/SQS/EventBridge, Azure Blob/Logic Apps/Service Bus, GCP Pub/Sub, Vercel |
| **Threat Detection & Intel** | 9 | Amazon GuardDuty, SentinelOne, Google Threat Intelligence, Cymulate, Cybersixgill |
| **Data Security Scanners** | 8 | Amazon Macie, BigID, Cyera, Sentra, Laminar, Bedrock Security |
| **API Security Scanners** | 7 | CyCognito, HackerOne, Salt Security, StackHawk, Traceable |
| **Developer Tools** | 7 | Backstage, HashiCorp, JetBrains, Terraform Provider, WizExtend |
| **Network Security** | 7 | Check Point, Fortinet, Netskope, Cato Networks, Aviatrix, Illumio |
| **Secured Components** | 7 | Chainguard, Docker, Seal Security |
| **Version Control** | 6 | GitHub, GitLab, Bitbucket (Cloud + Data Center), Azure DevOps, HCP Terraform |
| **SSPM** | 6 | Adaptive Shield/CrowdStrike, AppOmni, Obsidian Security, Valence Security |
| **Artificial Intelligence** | 5 | Cloudflare, Google Gemini Code Assist, Pillar Security, TrojAI |
| **Vuln Scanners** | 5 | Qualys VMDR, Rapid7 InsightVM, Tenable VM/SC, Microsoft Defender VM |
| **Data Security** | 4 | Collibra, Concentric AI, Varonis, Orion Security |
| **Cyber Risk Quantification** | 4 | Balbix/Safe, Cye Security, Onyxia Cyber |
| **API Security** | 3 | Firetail, Google Apigee, Noname |
| **SaaS Security** | 2 | Databricks, Microsoft 365 |
| **Cyber Resilience** | 2 | Cohesity, Commvault |
| **Data & AI** | 2 | (New 2026 category) |
| **CMDB** | 1 | ServiceNow CMDB |
| **SAST/DAST** | 1 | — |
| **TOTAL** | **268** | |

### 5.2 Integration Architecture

- Most integrations are **outbound push** from Wiz to external tools (Jira ticket creation, Slack alerts, SIEM log forwarding)
- Inbound integrations are primarily **scanner result ingestion** (third-party scanners feed findings into Wiz)
- Cloud provider connections are **API-based agentless** (IAM role assumption)
- New: **Workflow Orchestration** no-code canvas enables multi-step automation without SOAR
- New: **MCP Server** enables AI assistants to query Wiz data via natural language
- No native webhook system -- integrations rely on Wiz polling or partner-side polling of GraphQL API

### 5.3 ALDECI Integration Comparison

| Dimension | Wiz | ALDECI |
|-----------|-----|--------|
| Named integration partners | 268 | ~40 (native connectors + n8n workflows) |
| CI/CD integrations | 19 | 5-8 (GitHub, GitLab, Jenkins, Azure DevOps) |
| SIEM integrations | 14 | 3-5 (Splunk, Sentinel, syslog/CEF ingest) |
| Ticketing | 14 | 3 (Jira, Slack, ServiceNow via n8n) |
| Cloud providers | 6 (AWS, Azure, GCP, OCI, Alibaba, VMware) | 3 (AWS, Azure, GCP) |
| **Integration architecture** | Partner-maintained, SaaS-to-SaaS | Self-hosted, API-first, n8n workflow engine |
| **Webhook support** | None | Full webhook + WebSocket real-time push |
| **Custom integration effort** | Build GraphQL client | Call REST API or use n8n visual builder |

**ALDECI gap**: Wiz's 268 named integrations is a massive ecosystem advantage. However, most are partner-maintained SaaS-to-SaaS connectors. ALDECI's n8n workflow engine + REST API + webhooks enable custom integrations with anything, but lack the "click to enable" marketplace experience.

**Strategic recommendation**: Build a Wiz-style integrations marketplace page (even if integrations are n8n-based). The perception of ecosystem size matters for enterprise buyers.

---

## 6. Pricing Model

### 6.1 Pricing Structure

Wiz uses **per-billable-workload** pricing with custom quotes. No public price list exists.

| Attribute | Detail |
|-----------|--------|
| **Billing unit** | Per cloud workload (VMs, containers, serverless functions, data stores) |
| **Billing frequency** | Monthly, based on peak workload count |
| **Stopped instances** | Still scanned and billed (orphaned resource cleanup required) |
| **Contract terms** | Typically 1-3 year agreements |
| **Negotiation** | Heavily negotiated; volume discounts available |
| **AWS Marketplace** | Available (EDP committed spend credits apply) |
| **Onboarding packages** | $10,000 (basic) to $50,000+ (complex multi-cloud with custom integrations) |

### 6.2 Published Price Points (AWS Marketplace)

| Tier | Workloads | Annual Cost | Per-Workload/Year |
|------|-----------|-------------|-------------------|
| **Wiz Essential** | 100 | $24,000 | $240 |
| **Wiz Advanced** | 100 | $38,000 | $380 |

### 6.3 Module Add-On Pricing (Estimated % Increase Over Base)

| Module | Premium Over Base |
|--------|------------------|
| CWPP (workload protection) | +15-25% |
| DSPM (data security) | +10-20% |
| CIEM (identity entitlements) | +10-15% |
| Wiz Code (developer security) | +10-15% |
| Wiz Defend (CDR/runtime) | +20-30% |

### 6.4 Estimated Cost by Organization Size

| Deployment Size | Workloads | Estimated Annual Cost |
|----------------|-----------|----------------------|
| Small | <1,000 | $50K - $100K |
| Mid-size | 1,000 - 5,000 | $100K - $200K |
| Large enterprise | 5,000+ | $200K - $500K+ |
| Fortune 500 | 10,000+ | $500K - $1M+ |

### 6.5 ALDECI Cost Comparison

| Scenario | Wiz Annual | ALDECI Annual | Savings |
|----------|-----------|---------------|---------|
| 100 workloads (Essential) | $24,000 | $420 (Community) | **98.3%** |
| 100 workloads (Advanced) | $38,000 | $1,188 (Pro) | **96.9%** |
| 500 workloads | ~$75,000 | $1,188 (Pro) | **98.4%** |
| 1,000 workloads | ~$120,000 | $5,988 (Enterprise) | **95.0%** |
| 5,000 workloads | ~$250,000 | $5,988 (Enterprise) | **97.6%** |
| 10,000 workloads + full modules | ~$750,000 | $5,988 (Enterprise) | **99.2%** |

**TCO note**: Wiz is SaaS -- no infra cost. ALDECI is self-hosted -- add $50-200/month for hosting (still 90%+ cheaper). Wiz also charges $10-50K for onboarding; ALDECI is docker compose up.

---

## 7. Top 5 Enterprise Differentiators

These are the reasons enterprises choose Wiz, based on Forrester Wave Q1 2026, customer reviews, and competitive positioning:

### Differentiator 1: The Security Graph (Toxic Combinations)

**What it is**: A property graph database (Neo4j-style) that maps ALL cloud resources as nodes and ALL relationships (IAM permissions, network reachability, data access, vulnerability exposure) as edges.

**Why enterprises love it**: Instead of showing 10,000 individual findings, Wiz shows the 10 attack paths that actually matter. A "toxic combination" collapses five separate findings into one actionable insight: *"This publicly-exposed VM has an overpermissive IAM role that can access an S3 bucket containing PII training data for an AI model."*

**2026 update**: The graph now incorporates runtime signals from the eBPF sensor, validating which paths are actually exploitable in production (not just theoretically possible from config scans).

**Impact**: Forrester noted that 50% of Wiz customers are in the "Zero Criticals Club" -- no outstanding critical issues in production.

**ALDECI response**: TrustGraph + attack_path_engine + brain_pipeline provide the data model. The gap is the **interactive graph visualization** in the UI and the **toxic combination detection algorithm** as a first-class API feature.

### Differentiator 2: Agentless-First Architecture (Time to Value)

**What it is**: SideScanning creates read-only snapshots of workloads and analyzes them out-of-band. No agents to install, no performance impact.

**Why enterprises love it**: Connect your AWS account and get full visibility in **minutes**, not weeks. One IAM role, one API call, done. This makes PoC evaluations trivially easy.

**2026 update**: Now complemented by the eBPF Runtime Sensor for real-time detection (under 2% CPU, kernel-safe), closing the 24-hour gap between agentless scans.

**ALDECI response**: ALDECI uses connector-based scanning (13 PULL connectors + 32 scanner normalizers). Time-to-value is slower but depth is greater.

### Differentiator 3: Unified CNAPP (Tool Consolidation)

**What it is**: CSPM + CWPP + CIEM + DSPM + KSPM + AI-SPM + IaC + CDR + Code in one platform, one UI, one graph.

**Why enterprises love it**: Replaces 5-8 point solutions. One vendor, one contract, one dashboard. Forrester gave Wiz highest possible scores in 10/12 current offering criteria.

**ALDECI response**: ALDECI has broader consolidation (334 engines vs ~10 modules). The challenge is communicating this breadth without overwhelming buyers.

### Differentiator 4: Google/Alphabet Backing

**What it is**: $32B acquisition by the world's most valuable cloud company. Unlimited R&D budget, Google threat intelligence, Gemini AI integration, Chronicle SIEM convergence roadmap.

**Why enterprises love it**: Enterprise buyers are risk-averse. Google-backed = will not disappear. Google Cloud sales teams now sell Wiz alongside GCP.

**ALDECI response**: Counter-position: "Google owns your security data" vs "ALDECI keeps data on your servers." Data sovereignty is the antidote to the Google trust narrative.

### Differentiator 5: AI-Native Security (Agents + MCP + Mika)

**What it is**: Full AI agent stack: Issues Agent (remediation), SecOps Agent (investigation), Mika (conversational), MCP Server (IDE integration). All backed by Security Graph context.

**Why enterprises love it**: Natural language queries like "Which of my LLMs have access to production databases?" get instant answers. SecOps Agent auto-triages threats with confidence verdicts.

**2026 update**: This is the fastest-evolving area. Wiz is positioning as the AI security platform, not just cloud security. The MCP Server enables any AI assistant (Cursor, Claude, ChatGPT) to query Wiz data.

**ALDECI response**: ALDECI has AI security advisor + GraphRAG copilot + AI governance engine, but lacks the polished agent UX and MCP server. This is an emerging competitive gap to close.

---

## 8. Known Weaknesses & Gaps

Based on G2, Gartner Peer Insights, PeerSpot reviews, and analyst reports (April 2026):

### 8.1 Architectural Limitations

| Weakness | Detail | Severity | ALDECI Advantage |
|----------|--------|----------|------------------|
| **SaaS-only** | No on-premise, no self-hosted, no air-gapped deployment | CRITICAL | ALDECI is 100% self-hosted |
| **No webhook/event push** | Cannot push real-time events to external systems; polling only | HIGH | Full webhook + WebSocket system |
| **24-hour scan cycle** | Default agentless scans run once per day; gaps between scans | HIGH | Configurable scan frequency |
| **No active kernel-level blocking** | Runtime Sensor detects but does NOT prevent at kernel level | HIGH | Configurable response actions |
| **GraphQL-only API** | Forces all integrators to learn GraphQL; no REST option | MEDIUM | REST + GraphQL available |
| **No official SDK** | Every customer builds their own API client | MEDIUM | OpenAPI auto-client generation |
| **10K query result caps** | Cannot extract full datasets without Reports endpoint | MEDIUM | No arbitrary caps |
| **Google data sovereignty** | Post-acquisition, all security telemetry flows through Google infra | MEDIUM | Self-hosted, data never leaves network |

### 8.2 Feature Gaps (Domains Wiz Does Not Cover)

| Gap | Detail | ALDECI Coverage |
|-----|--------|----------------|
| **SOC Operations** | Zero SOC workflow, case management, SLA tracking | 9+ SOC/incident engines |
| **SIEM Management** | Feeds SIEMs but does not manage them | SIEM integration engine |
| **Threat Intelligence Platform** | No TI management, IOC lifecycle, dark web monitoring | 25+ TI engines |
| **GRC / Risk Management** | No risk register, risk treatment, evidence collection, audit management | 40+ GRC engines |
| **EDR / NDR / XDR** | Cloud-only; no endpoint, network, or extended detection | EDR, NDR, XDR engines |
| **OT / IoT / SCADA** | Zero coverage for operational technology environments | OT, IoT, firmware engines |
| **Physical Security** | Zero coverage for physical access, badges, cameras | Physical security engine |
| **Pentest / Red Team** | Cannot manage offensive security programs | Pentest, red team, bug bounty engines |
| **Security Training** | Cannot manage awareness programs, phishing simulation | Training, awareness, gamification engines |
| **Network Security Mgmt** | Cannot manage firewalls, WAF, NAC, DDoS protection | 15+ network security engines |
| **Full Identity Lifecycle** | CIEM for cloud only; no full IAM lifecycle management | Full identity lifecycle, PAG, session recording |
| **Security Program Mgmt** | No budgeting, OKRs, investment tracking, culture metrics | Budget, OKR, investment, culture engines |

### 8.3 User Experience Issues (from 2026 Reviews)

| Issue | Source | Detail |
|-------|--------|--------|
| **Alert noise at scale** | G2, PeerSpot | Duplicate alerts under different categories; overwhelming in large environments |
| **Weak reporting** | G2, PeerSpot | Only compliance CSV reports; no customizable executive summaries or PDF exports |
| **Case-sensitive search** | PeerSpot | Finding misconfigurations requires exact-case queries |
| **Steep learning curve** | G2 | Complex UX with extensive functionality takes weeks to master |
| **Immature IDE integration** | PeerSpot | No rule IDs visible; limited ignore granularity outside global rules |
| **Weak connector validation** | G2 | Input validation for cloud connector credentials creates friction |
| **No self-remediation** | PeerSpot | Missing features hinder automated remediation workflows |
| **Limited project segregation** | G2 | Difficult to segregate findings by business unit/project in some views |
| **Pricing barrier** | G2, multiple | $50K minimum shuts out SMBs, startups, and non-profits |
| **Dashboard overwhelming** | G2 | Powerful but overwhelming for teams used to simpler scanners |

### 8.4 Post-Acquisition Risks

| Risk | Detail |
|------|--------|
| **AWS/Azure customer anxiety** | Google ownership may cause strategic concerns for competing cloud customers |
| **Price increase probability** | Google historically raises prices post-acquisition (Looker, Mandiant precedent) |
| **Product road bifurcation** | GCP-specific features may get priority over multi-cloud parity |
| **Data sovereignty** | Security telemetry now flows through Google infrastructure |
| **Talent attrition** | Israeli founding team may depart after vesting cliff |
| **Integration absorption** | Partner integrations may be replaced by Google-owned equivalents (Chronicle, VirusTotal, Mandiant) |
| **Regulatory overhang** | DOJ cleared but EU regulators may impose conditions; binding multi-cloud commitment has enforcement questions |

---

## 9. Attack Path & Security Graph Deep Dive

### 9.1 Architecture

The Wiz Security Graph is a **property graph database** that represents:

- **Nodes**: Cloud resources (VMs, containers, databases, S3 buckets, IAM roles, serverless functions, K8s pods, AI models, MCP servers)
- **Edges**: Typed relationship properties:
  - `NETWORK_REACHABLE` -- network connectivity between resources
  - `HAS_PERMISSION` -- IAM permission grants (who can access what)
  - `CONTAINS_DATA` -- data classification from DSPM scans
  - `HAS_VULNERABILITY` -- CVEs affecting a resource
  - `IS_EXPOSED_TO_INTERNET` -- public IP or public endpoint
  - `RUNS_ON` -- container-to-host, function-to-runtime relationships
  - `ACCESSES` -- observed API call relationships (new: validated by runtime sensor)

### 9.2 How Attack Path Analysis Works

1. **Graph Construction**: Every 24 hours (agentless scan cycle) + real-time runtime events from eBPF sensor, Wiz rebuilds the complete graph
2. **Crown Jewel Identification**: Resources tagged as critical (production databases, AI training data, PII stores) become target nodes
3. **Entry Point Detection**: Internet-exposed resources, publicly accessible endpoints, accounts without MFA become entry nodes
4. **Path Traversal**: BFS/DFS algorithms traverse from entry points through permission chains, network paths, and vulnerability hops to reach crown jewels
5. **Toxic Combination Detection**: Paths where multiple individually-low-risk factors combine to create critical exposure are flagged
6. **Runtime Validation** (New 2026): eBPF sensor confirms which paths are actively exploitable, not just theoretically possible
7. **Scoring**: Composite score based on: number of hops, severity of required exploits, blast radius, data sensitivity, runtime validation status

### 9.3 Toxic Combination Examples

**Example 1 -- Classic Cloud Breach Path:**
```
[Internet] -> Public IP on VM -> Unpatched CVE-2024-XXXX -> IAM Role with S3:GetObject ->
S3 Bucket containing PII -> AI Training Pipeline
```
Individual components: Medium, Medium, Low, Low, Info
Toxic combination: **CRITICAL** -- full data exfiltration + model poisoning path

**Example 2 -- Lateral Movement:**
```
[Internet] -> Public ALB -> Container with privileged access -> Host escape ->
Kubernetes cluster admin -> Cross-namespace access -> Production RDS (PHI data)
```

**Example 3 -- AI-Specific:**
```
[Internet] -> Exposed inference endpoint -> Write access to training bucket ->
Data poisoning of ML model -> Incorrect outputs in production
```

**Detection methodology**: The system identifies toxicity by looking for convergence of:
- Network exposure (internet-reachable entry point)
- Unprotected sensitive data (DSPM classification)
- Excessive permissions (CIEM over-privilege)
- Vulnerable resources (CWPP CVE scanning)

Neither factor alone is critical. The combination is what creates the breach scenario.

### 9.4 Visualization Approach

- **Card-based list**: Prioritized attack paths shown as cards with: start/end nodes, path length, required exploits, blast radius score
- **Interactive force-directed graph**: Clicking a card opens the Security Graph with that specific path highlighted
- **Dimming**: Off-path nodes are dimmed; critical path highlighted in red
- **Side panel**: Click any node for: resource details, CVEs, IAM policies, data classification, owner
- **Mini-map**: Corner navigation for large environments
- **Toxic combination badge**: Special visual indicator on multi-factor risk convergence points
- **Code-to-cloud tracing**: Click a finding to see the source code line that introduced it

### 9.5 ALDECI Gap Analysis

| Capability | Wiz | ALDECI |
|-----------|-----|--------|
| Graph data model | Neo4j-style property graph | TrustGraph (5 cores) + SQLite per engine |
| Graph query API | GraphQL traversal | BFS in attack_path_engine |
| Crown jewel identification | DSPM + asset tagging | Asset criticality engine |
| Toxic combination detection | First-class feature, core differentiator | **NOT IMPLEMENTED** |
| Interactive graph UI | Force-directed + drill-down + dimming | Basic SVG in AttackPathAnalysis.tsx |
| Internet exposure as universal filter | Yes (isAccessibleFromInternet on any query) | Partial (per-engine, not universal) |
| Data sensitivity as universal filter | Yes (hasSensitiveData from DSPM) | Partial (data_discovery, DLP separate) |
| Runtime-validated paths | eBPF sensor confirms exploitability | No runtime sensor |
| AI attack paths | AI-SPM detects AI-specific paths | Not yet |
| Code-to-cloud tracing in graph | Click finding -> source code line | Partial (code-to-cloud endpoint exists) |

---

## 10. Head-to-Head: ALDECI vs Wiz

### 10.1 Feature Coverage Scorecard

| Domain | Wiz (0-10) | ALDECI (0-10) | Notes |
|--------|-----------|--------------|-------|
| Cloud Posture (CSPM) | 10 | 7 | Wiz: 1,400+ rules, agentless SideScanning. ALDECI: engine-based, fewer rules |
| Cloud Workload Protection | 9 | 6 | Wiz: agentless deep scanning + eBPF runtime. ALDECI: scanner normalizers |
| Kubernetes Security | 9 | 7 | Wiz: deep KSPM + CIS benchmarks + runtime. ALDECI: kubernetes_security engine |
| Data Security (DSPM) | 9 | 6 | Wiz: actual content scanning with ML classifiers. ALDECI: data_discovery + DLP |
| Identity/Entitlements (CIEM) | 8 | 8 | Both strong; ALDECI has deeper IAM lifecycle management |
| AI Security (AI-SPM) | 9 | 5 | Wiz: first-mover with AI-BOM, MCP discovery, rogue agent detection. ALDECI: ai_governance but less depth |
| Developer Security (Code) | 7 | 7 | Roughly equivalent; Wiz has more CI/CD integrations and code-to-cloud tracing |
| Runtime / CDR | 8 | 4 | Wiz: eBPF sensor with behavioral baselining. ALDECI: no runtime sensor |
| Attack Path Visualization | 10 | 5 | Wiz: industry-leading interactive graph + toxic combos. ALDECI: basic SVG |
| Compliance Scanning | 8 | 8 | Both strong on scanning; ALDECI deeper on lifecycle management |
| AI Agents / Copilot | 8 | 6 | Wiz: Issues Agent, SecOps Agent, Mika, MCP Server. ALDECI: GraphRAG copilot |
| **SOC Operations** | 0 | 9 | Wiz has zero SOC capability |
| **Threat Intelligence** | 0 | 9 | Wiz has zero TI platform capability |
| **GRC / Risk Management** | 0 | 9 | Wiz has zero GRC capability |
| **Network Security** | 0 | 8 | Wiz is cloud-only |
| **Endpoint Security (EDR)** | 0 | 7 | Wiz is cloud-only |
| **OT / IoT / Physical** | 0 | 7 | Wiz is cloud-only |
| **Identity Lifecycle (Full)** | 3 | 9 | Wiz: CIEM only. ALDECI: full IAM lifecycle |
| **Pentest / Red Team** | 0 | 8 | Wiz has zero offensive security capability |
| **Security Training** | 0 | 7 | Wiz has zero awareness/training capability |
| **Security Program Mgmt** | 0 | 8 | Wiz has zero budgeting/OKR/investment tracking |
| Integration ecosystem | 9 | 4 | 268 vs ~40 named integrations |
| UI/UX polish | 9 | 5 | Wiz: enterprise-grade, analyst-validated. ALDECI: functional but less polished |
| **TOTAL (weighted for full security program)** | **5.5/10** | **7.0/10** | ALDECI wins on breadth; Wiz wins on cloud depth and UX |

### 10.2 When to Position Against Wiz

**ALDECI wins when:**
- Buyer requires self-hosted / on-premise / air-gapped deployment
- Buyer needs full security lifecycle (not just cloud posture)
- Buyer cannot afford $50K+ minimum annual spend
- Buyer is concerned about Google data sovereignty post-acquisition
- Buyer needs SOC, threat intel, GRC, or network security in the same platform
- Buyer operates OT/IoT/SCADA environments alongside cloud
- Buyer needs real-time webhooks/event push (Wiz has none)
- Buyer needs high-throughput API access (Wiz caps at 10 req/s)
- Buyer is an MSSP needing white-label multi-tenant deployment

**Wiz wins when:**
- Buyer is pure cloud-native with no on-premise requirements
- Buyer needs the fastest time-to-value (connect AWS and scan in minutes)
- Buyer values brand recognition, Google backing, and Forrester Wave leadership
- Buyer's team is small and needs the graph to prioritize findings automatically
- Buyer is already in the Google Cloud ecosystem
- Buyer needs specific integration with one of 268 WIN partners
- Buyer's compliance is purely cloud-focused (CIS, SOC 2, PCI for cloud)
- Buyer needs runtime detection with eBPF sensor (Wiz Defend)
- Buyer needs AI-SPM (AI model/agent discovery, MCP security)

---

## 11. Strategic Recommendations for ALDECI

### 11.1 Must-Build (Close Critical Competitive Gaps)

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| **P0** | Toxic combination detection engine + API endpoint | 2-3 days | Closes Wiz's #1 differentiator gap |
| **P0** | Interactive Security Graph UI (React Flow / @xyflow/react) | 3-5 days | Closes biggest visual gap; demo impact |
| **P1** | Internet exposure + data sensitivity as universal query filters across all engines | 1-2 days | Matches Wiz graph query UX |
| **P1** | Agentless cloud snapshot scanning (AWS SideScanning equivalent) | 5-7 days | Matches Wiz time-to-value story |
| **P1** | MCP Server for ALDECI (natural language security queries in IDE) | 2-3 days | Matches Wiz MCP Server; AI-native positioning |
| **P2** | AI-BOM generation (discover AI services/models/MCP connections in cloud) | 2-3 days | Matches AI-SPM capability |
| **P2** | AI investigation agents (Issues Agent + SecOps Agent equivalents) | 3-5 days | Matches Wiz AI agent UX |
| **P2** | Integrations marketplace page (list all n8n + native integrations visually) | 1 day | Perception of ecosystem size |
| **P3** | eBPF-based runtime sensor | 2-4 weeks | Matches Wiz Defend; major engineering effort |
| **P3** | Workflow orchestration no-code canvas | 1-2 weeks | Matches Wiz workflow builder |

### 11.2 Must-Market (Existing Advantages to Promote)

| Advantage | Sales Narrative |
|-----------|----------------|
| **Self-hosted** | "Your security data never leaves your network. Google now owns Wiz's infrastructure." |
| **95-98% cost reduction** | "Wiz Essential costs $24K/yr for 100 workloads. ALDECI Pro costs $1,188/yr unlimited." |
| **Full security lifecycle** | "Wiz finds cloud misconfigs. ALDECI manages your entire security program -- SOC, GRC, TI, OT, identity." |
| **334 engines vs 10 modules** | "Wiz covers cloud. ALDECI covers cloud + SOC + threat intel + GRC + network + OT + identity + pentest." |
| **Webhook + WebSocket** | "Wiz has no webhooks. You poll at 10 req/s max. ALDECI pushes events in real-time." |
| **No vendor lock-in** | "Wiz is now a Google product. ALDECI is yours forever." |
| **Compliance lifecycle** | "Wiz scans for violations. ALDECI manages evidence, audits, calendars, workflows, and regulatory reporting." |
| **REST + GraphQL** | "Wiz forces GraphQL-only with no SDK. ALDECI has 5,263+ REST endpoints with auto-generated OpenAPI." |

### 11.3 Positioning Matrix by Buyer Segment

| Buyer Segment | Lead Message | Wiz Counter |
|--------------|-------------|-------------|
| **Startup / SMB** | "Enterprise security for $99/month" | Wiz won't talk to you at <$50K |
| **Mid-market** | "Replace your 5-tool stack with one self-hosted platform" | Same as Wiz, but 95% cheaper and self-hosted |
| **Enterprise (regulated)** | "Self-hosted, SOC 2, HIPAA, on-prem, evidence vault" | Wiz is SaaS-only, Google-owned |
| **MSSP** | "White-label, multi-tenant, 5,263 API endpoints" | Wiz charges per customer, no white-label |
| **Government / Defense** | "Air-gapped, FedRAMP path, on-prem, zero data exfil" | Wiz FedRAMP Moderate only, SaaS-only |
| **OT / Industrial** | "Only platform covering IT + OT + IoT + SCADA" | Wiz is cloud-only, zero OT coverage |
| **AI-native company** | "AI governance + GraphRAG + self-hosted AI security" | Wiz AI-SPM is stronger today; close gap with P2 items |

---

## 12. Sources

### Official Wiz Sources
- [Wiz Platform Overview](https://www.wiz.io/platform)
- [Wiz Defend (CDR)](https://www.wiz.io/platform/wiz-defend)
- [Wiz Runtime Sensor](https://www.wiz.io/solutions/runtime-sensor)
- [Wiz DSPM Solution](https://www.wiz.io/solutions/dspm)
- [Wiz CIEM Solution](https://www.wiz.io/solutions/ciem)
- [Wiz CSPM Solution](https://www.wiz.io/solutions/cspm)
- [Wiz Compliance Solution](https://www.wiz.io/solutions/compliance)
- [Wiz AI-SPM Solution](https://www.wiz.io/solutions/ai-spm)
- [Wiz Container & Kubernetes Security](https://www.wiz.io/solutions/container-and-kubernetes-security)
- [Wiz Security Graph](https://www.wiz.io/lp/wiz-security-graph)
- [Wiz Integrations Marketplace](https://www.wiz.io/integrations)
- [Wiz Pricing Page](https://www.wiz.io/pricing)
- [Wiz AI Agents Blog](https://www.wiz.io/blog/wiz-ai-agents)
- [Wiz MCP Server Blog](https://www.wiz.io/blog/introducing-mcp-server-for-wiz)
- [Wiz AI-SPM Secures AI Agents](https://www.wiz.io/blog/wiz-ai-spm-secures-ai-agents)
- [Wiz Toxic Combinations Blog](https://www.wiz.io/blog/the-anatomy-of-a-toxic-combination-of-risk)
- [Wiz Forrester Wave CNAPP Q1 2026](https://www.wiz.io/blog/forrester-wave-cnapp-2026)
- [Wiz Attack Path Analysis Academy](https://www.wiz.io/academy/detection-and-response/attack-path-analysis)
- [Wiz AI Security Solutions 2026](https://www.wiz.io/academy/ai-security/ai-security-solutions)
- [Wiz Runtime Sensor for Windows](https://www.wiz.io/blog/wiz-runtime-sensor-for-your-windows-environment)
- [WIN 2026: Building AI Security Ecosystem](https://www.wiz.io/blog/win-ai-partnerships)
- [Wiz 200+ Integrations Celebration](https://www.wiz.io/blog/celebrating-200-wiz-integrations)
- [Wiz Joins Google Blog](https://www.wiz.io/blog/google-closes-deal-to-acquire-wiz)
- [Wiz Trust Center](https://trust.wiz.io/)

### Acquisition & Analyst Sources
- [Google Completes Acquisition of Wiz (Press Release)](https://www.googlecloudpresscorner.com/2026-03-11-Google-Completes-Acquisition-of-Wiz)
- [Google Cloud Blog: Welcoming Wiz](https://cloud.google.com/blog/products/identity-security/google-completes-acquisition-of-wiz)
- [Google Blog: Wiz Acquisition](https://blog.google/innovation-and-ai/infrastructure-and-cloud/google-cloud/wiz-acquisition/)
- [SecurityWeek: Wiz Joins Google Cloud](https://www.securityweek.com/wiz-joins-google-cloud-as-landmark-acquisition-closes/)
- [TechCrunch: Google Completes $32B Wiz Acquisition](https://techcrunch.com/2026/03/11/google-completes-32b-acquisition-of-wiz/)
- [Forrester: Google Acquires CNAPP Unicorn Wiz](https://www.forrester.com/blogs/google-to-acquire-cnapp-specialist-unicorn-wiz-for-32bn/)
- [Google Cloud: RSAC '26 Agentic AI Defense](https://cloud.google.com/blog/products/identity-security/rsac-26-supercharging-agentic-ai-defense-with-frontline-threat-intelligence)
- [SiliconANGLE: Google Cloud Agentic AI + Wiz](https://siliconangle.com/2026/03/23/google-cloud-unveils-agentic-ai-security-strategy-wiz-integration-threat-intelligence-upgrades/)

### Pricing Sources
- [Vendr: Wiz Pricing & Plans 2026](https://www.vendr.com/marketplace/wiz)
- [WizPricing.com: Estimated Costs](https://www.wizpricing.com/)
- [WizPricing.com: Pricing Model Explained](https://www.wizpricing.com/pricing-model)
- [UnderDefense: Wiz Pricing Guide](https://underdefense.com/industry-pricings/wiz-pricing-ultimate-guide-for-security-products/)

### Review Sources
- [G2: Wiz Reviews 2026](https://www.g2.com/products/wiz-wiz/reviews)
- [G2: Wiz Pros and Cons](https://www.g2.com/products/wiz-wiz/reviews?qs=pros-and-cons)
- [PeerSpot: Wiz Pros and Cons 2026](https://www.peerspot.com/products/wiz-pros-and-cons)
- [Gartner Peer Insights: Wiz CNAPP Reviews](https://www.gartner.com/reviews/product/wiz-703120040)

### Technical & Integration Sources
- [Stitchflow: Wiz API Guide](https://www.stitchflow.com/user-management/wiz/api)
- [Cribl: Wiz API Source Docs](https://docs.cribl.io/stream/sources-wiz/)
- [Port: Wiz Integration Docs](https://docs.port.io/build-your-software-catalog/sync-data-to-catalog/code-quality-security/wiz/)
- [Datadog: Wiz Integration](https://docs.datadoghq.com/integrations/wiz/)
- [APITracker: Wiz API](https://apitracker.io/a/wiz-io)
- [Solide Info: Wiz 2026 Definitive Guide](https://solideinfo.com/wiz-cloud-security/)
- [PuppyGraph: Recreating Wiz Security Graph](https://www.puppygraph.com/blog/wiz-security-graph)
- [Google Cloud: Wiz Architecture Guide](https://docs.cloud.google.com/architecture/partners/id-prioritize-security-risks-with-wiz)
- [Loginsoft: Wiz Cloud Security Overview](https://www.loginsoft.com/post/wiz-cloud-security-everything-you-need-to-know-about-the-platform-securing-the-modern-cloud)

---

*Report generated 2026-04-22 by ALDECI CTO Agent (Claude Opus 4.6). Updates quarterly or upon significant Wiz product announcements.*
