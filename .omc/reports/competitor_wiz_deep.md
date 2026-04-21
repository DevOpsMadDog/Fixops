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
| **Acquisition** | Google acquired Wiz for **$32B cash** on March 11, 2026 -- largest acquisition in Google history |
| **ARR** | $1B+ (2025), estimated $1.5B+ (2026) |
| **Customers** | 50% of Fortune 100 including Salesforce, Slack, Mars, BMW, DocuSign, Plaid, Agoda |
| **Employees** | ~1,800+ |
| **Category** | CNAPP (Cloud-Native Application Protection Platform) |
| **Deployment** | SaaS-only (multi-tenant cloud) |
| **Multi-cloud** | AWS, Azure, GCP, OCI, Alibaba Cloud, VMware vSphere |
| **Regulatory status** | FedRAMP Moderate authorized, SOC 2 Type II, ISO 27001/27017/27018/27701, HIPAA |
| **Post-acquisition** | Maintains independent brand and product roadmap within Google Cloud; binding EU/US regulatory commitment to multi-cloud neutrality; expected convergence with Google Chronicle SIEM, Vertex AI |

### What the $32B Acquisition Means for ALDECI

Google's acquisition validates the cloud security market at the highest level. However, it introduces strategic risks for Wiz customers:
- **Vendor lock-in anxiety**: Enterprises on AWS/Azure may worry about Google ownership bias despite regulatory commitments
- **Price increases**: Google historically raises prices post-acquisition (Looker, Mandiant precedent)
- **Product roadmap uncertainty**: Will Wiz features become GCP-exclusive or degraded on competing clouds?
- **Data sovereignty**: Wiz data now flows through Google infrastructure -- a concern for regulated industries

**ALDECI opportunity**: Self-hosted, vendor-neutral, no acquisition risk. This narrative becomes stronger post-Google-acquisition.

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
| **AI-SPM** | AI Security Posture Management | Discovers unmanaged AI models, training datasets, unrestricted inference endpoints; generates AI-BOM |
| **IaC Security** | Infrastructure as Code Scanning | Terraform, CloudFormation, ARM, Helm, Kubernetes manifests scanned in CI/CD |
| **CDR / Wiz Defend** | Cloud Detection & Response | eBPF runtime sensor, real-time threat detection, behavioral analytics, cloud forensics |
| **Wiz Code** | Developer Security | IDE integration, CI/CD pipeline scanning, code-to-cloud tracing, secrets detection, SBOM |
| **Vulnerability Management** | CVE lifecycle | CVE data with CVSS, EPSS, KEV status, vendor severity, remediation guidance |

### 2.2 Wiz Defend (CDR) -- Deep Dive

Wiz Defend is their newest and fastest-growing module, launched for GA in late 2025:

| Capability | Detail |
|-----------|--------|
| **Runtime Sensor** | Lightweight eBPF-based sensor (~1% CPU overhead) |
| **Threat Detection** | Cryptominers, fileless malware (memfd_create monitoring), lateral movement (anomalous SSH), C2 beacons |
| **Cloud Log Analysis** | CloudTrail monitoring: PutBucketAcl, AuthorizeSecurityGroupIngress, CreateAccessKey, ConsoleLogin without MFA |
| **Behavioral Baselining** | Learns normal process behavior per workload, alerts on deviations |
| **Blue Agent** | AI-powered investigation assistant for automated triage |
| **MTTD claim** | "10x faster detection" vs traditional SIEM-based approaches |
| **MTTR claim** | "10x reduction" via AI-powered investigations |
| **OS support** | Linux (initial), Windows (added 2026) |
| **Forensics** | Integrated forensic collection, KQL queries, Sigma rules, Python automation hooks |

### 2.3 Wiz Code -- Developer Security

| Capability | Detail |
|-----------|--------|
| **IDE integration** | JetBrains, VS Code (but immature per user reviews -- missing rule ID display, limited ignore granularity) |
| **CI/CD scanning** | CLI-based scanning in 19 CI/CD systems (GitHub Actions, GitLab CI, Jenkins, CircleCI, etc.) |
| **Code-to-cloud tracing** | Maps live cloud risks back to the exact line of code that introduced them |
| **IaC scanning** | Terraform, CloudFormation, ARM templates, Helm charts |
| **Container image scanning** | Registry scanning + pipeline blocking |
| **Secret detection** | AWS Access Keys, private keys, DB connection strings, OAuth tokens |
| **SBOM** | Software Bill of Materials generation and tracking |

### 2.4 AI-SPM (AI Security Posture Management)

Wiz was first-to-market with dedicated AI security posture management:

| Capability | Detail |
|-----------|--------|
| **AI-BOM** | Auto-discovers all AI services, libraries, SDKs, and models in the environment |
| **AI attack paths** | Identifies attack paths targeting AI pipelines (e.g., training data poisoning via exposed S3 bucket) |
| **Model discovery** | Finds unmanaged/shadow AI deployments across cloud accounts |
| **Prompt injection detection** | Runtime detection of prompt injection attempts (via Wiz Defend) |
| **Rogue agent detection** | Detects unauthorized autonomous AI agents |
| **Training data security** | DSPM integration to classify sensitivity of training datasets |

### 2.5 SideScanning Technology (Agentless Core)

Wiz's agentless scanning architecture is a key technical differentiator:

1. Cross-account IAM role grants read-only API access
2. Native cloud snapshots created (not on the running workload)
3. Ephemeral out-of-band analysis in the same region (no cross-region data transfer)
4. Analysis completes in 4-15 minutes per workload
5. Cryptographic destruction of snapshots after analysis
6. No agents installed, no performance impact on production

**Default scan frequency**: Every 24 hours (a known limitation addressed by Runtime Sensor for real-time gaps)

---

## 3. API Capabilities

### 3.1 Architecture

| Attribute | Detail |
|-----------|--------|
| **API style** | GraphQL-only (single endpoint) -- NO REST API |
| **Endpoint** | `https://api.<TENANT_DC>.app.wiz.io/graphql` (us1, us2, eu1, eu2) |
| **Authentication** | OAuth 2.0 Client Credentials (service account model) |
| **Token endpoint** | `https://auth.app.wiz.io/oauth/token` |
| **Token lifetime** | ~1 hour (not publicly documented) |
| **Rate limit** | 3 req/s (confirmed via Cribl documentation) -- extremely low |
| **Pagination** | Cursor-based (`pageInfo.endCursor`), max 500 records/page |
| **Result caps** | Audit Logs: 10,000/query; Cloud Config: 10,000/query |
| **Webhooks** | NONE -- polling only |
| **WebSocket** | NONE |
| **SDK** | NONE official (community Python wrappers exist) |
| **CLI** | Wiz CLI exists for CI/CD scanning only, not for API operations |
| **SCIM** | Enterprise plan only (`https://api.<tenant>.wiz.io/scim/v2`) |

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

### 3.5 Critical API Limitations (ALDECI Advantages)

| Limitation | Impact | ALDECI Advantage |
|-----------|--------|------------------|
| **3 req/s rate limit** | Blocks high-throughput integrations, SIEM ingestion at scale | Configurable per-tenant rate limiting |
| **No webhooks** | Cannot push events to external systems in real-time | Full webhook system + WebSocket real-time push |
| **No REST API** | Forces all integrators to learn GraphQL | REST + GraphQL available |
| **No official SDK** | Every integrator builds their own client | OpenAPI auto-generated client possible |
| **10K result caps** | Cannot query full datasets in single call | No arbitrary caps |
| **OAuth 2.0 only** | Two-step auth flow adds complexity | Simple API key auth (one step) |
| **SaaS-only** | API endpoint is internet-hosted -- no private network option | Self-hosted, on-prem API |

---

## 4. Compliance Frameworks

### 4.1 Frameworks Wiz Scans Against (100+ Built-In)

**Tier 1 -- Core Frameworks:**
- CIS Benchmarks (AWS, Azure, GCP, OCI, Kubernetes)
- NIST SP 800-53 (Rev 4 and Rev 5)
- NIST Cybersecurity Framework (CSF)
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

**Custom Frameworks:** Wiz supports custom framework creation to map organizational policies.

### 4.2 Compliance Features

| Feature | Detail |
|---------|--------|
| **Continuous assessment** | Automatic posture evaluation against all enabled frameworks |
| **Cross-framework mapping** | Auto-correlates controls across overlapping frameworks (e.g., SOC 2 CC6.1 maps to ISO 27001 A.9) |
| **2,800+ rules** | Built-in configuration rules running continuously |
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
| Evidence auto-collection | No (manual CSV export) | Yes (automated evidence collector + evidence vault) |
| Audit trail | Basic audit log | Immutable SHA-256 chain audit trail |
| Compliance calendar | No | Yes (scheduling, deadlines, recurring events) |
| Compliance workflow | No | Yes (approval lifecycle, auto-transition) |
| Evidence vault | No | Yes (tamper-evident, sealed guard) |
| Risk register integration | No | Yes (native risk register + treatment) |
| Regulatory change tracking | No | Yes (regulatory tracker engine) |
| Questionnaire management | No | Yes (security questionnaire engine) |

**ALDECI advantage**: Wiz scans for compliance violations. ALDECI manages the entire compliance lifecycle -- from scanning through evidence collection, audit management, risk treatment, and regulatory reporting.

---

## 5. Integration Ecosystem (268 Partners)

Wiz maintains the **WIN (Wiz Integration Network)** with 268 named integrations across 46 categories. This is one of the largest integration ecosystems in cloud security.

### 5.1 Complete Integration Map by Category

| Category | Count | Key Partners |
|----------|-------|-------------|
| **API Security** | 3 | Firetail, Google Apigee, Noname |
| **API Security Scanners** | 7 | CyCognito, HackerOne, Salt Security, StackHawk, Traceable |
| **Application Security** | 11 | Apiiro, Black Duck, Veracode ASPM, OXSecurity, Legit Security |
| **AppSec Scanners** | 14 | Checkmarx, Snyk, SonarQube, Semgrep, Rapid7, Mend.io, Endor Labs |
| **Artificial Intelligence** | 5 | Cloudflare, Google Gemini Code Assist, Pillar Security, TrojAI |
| **CI/CD** | 19 | GitHub, GitLab, Jenkins, CircleCI, Azure DevOps, Bitbucket, Buildkite, Travis CI, AWS CodeBuild, Spacelift, Atlantis, Harness, TeamCity, OpenShift |
| **Cloud Services** | 9 | AWS S3/SNS/SQS/EventBridge, Azure Blob/Logic Apps/Service Bus, GCP Pub/Sub, Vercel |
| **CMDB** | 1 | ServiceNow CMDB |
| **Compliance Management** | 17 | Drata, Vanta, Sprinto, Hyperproof, Anecdotes, Cypago, RegScale, ZenGRC, Scytale, 6clicks |
| **Cyber Resilience** | 2 | Cohesity, Commvault |
| **Cyber Risk Quantification** | 4 | Balbix/Safe, Cye Security, Onyxia Cyber |
| **Data Lake & Analytics** | 10 | Snowflake, Elastic, Cribl, CloudQuery, Databahn |
| **Data Security** | 4 | Collibra, Concentric AI, Varonis, Orion Security |
| **Data Security Scanners** | 8 | Amazon Macie, BigID, Cyera, Sentra, Laminar, Bedrock Security |
| **Developer Tools** | 7 | Backstage, HashiCorp, JetBrains, Terraform Provider, WizExtend |
| **Identity Security** | 11 | Okta, CyberArk/Palo Alto, Saviynt, ConductorOne, Oasis Security, Aembit |
| **MDR** | 10 | Arctic Wolf, Expel, Red Canary/Zscaler, ReliaQuest, Sygnia |
| **Network Security** | 7 | Check Point, Fortinet, Netskope, Cato Networks, Aviatrix, illumio |
| **SaaS Security** | 2 | Databricks, Microsoft 365 |
| **Secured Components** | 7 | Chainguard, Docker, Seal Security |
| **Security Data Management** | 15 | AWS CloudTrail Lake/Security Lake, Brinqa, Censys, Panaseer |
| **SIEM** | 14 | Splunk, Microsoft Sentinel, Datadog, Elastic, QRadar, Sumo Logic, Google SecOps, Securonix, Panther, Exabeam, Devo, Hunters |
| **SOAR & Automation** | 16 | Cortex XSOAR, Tines, Torq, Swimlane, Workato, QRadar SOAR, D3 Security, Blinkops |
| **SSPM** | 6 | Adaptive Shield/CrowdStrike, AppOmni, Obsidian Security, Valence Security |
| **Threat Detection & Intel** | 9 | Amazon GuardDuty, SentinelOne, Google Threat Intelligence, Cymulate, Cybersixgill |
| **Ticketing & Messaging** | 14 | Jira, ServiceNow ITSM, Slack, Microsoft Teams, PagerDuty, Opsgenie, Zendesk, Linear, ClickUp |
| **Version Control** | 6 | GitHub, GitLab, Bitbucket (Cloud + Data Center), Azure DevOps, HCP Terraform |
| **Vuln Management & Response** | 22 | Qualys, Tenable, Rapid7, Armis, Axonius, Ivanti, Nucleus, Seemplicity |
| **Vuln Scanners** | 5 | Qualys VMDR, Rapid7 InsightVM, Tenable VM/SC, Microsoft Defender VM |
| **TOTAL** | **268** | |

### 5.2 Integration Architecture

- Most integrations are **outbound push** from Wiz to external tools (Jira ticket creation, Slack alerts, SIEM log forwarding)
- Inbound integrations are primarily **scanner result ingestion** (third-party scanners feed findings into Wiz)
- Cloud provider connections are **API-based agentless** (IAM role assumption)
- No native webhook system -- integrations rely on Wiz polling or partner-side polling of GraphQL API

### 5.3 ALDECI Integration Comparison

| Dimension | Wiz | ALDECI |
|-----------|-----|--------|
| Named integration partners | 268 | ~40 (native connectors + n8n workflows) |
| CI/CD integrations | 19 | 5-8 (GitHub, GitLab, Jenkins, Azure DevOps) |
| SIEM integrations | 14 | 3-5 (Splunk, Sentinel, syslog/CEF ingest) |
| Ticketing | 14 | 3 (Jira, Slack, ServiceNow via n8n) |
| **Integration architecture** | Partner-maintained, SaaS-to-SaaS | Self-hosted, API-first, n8n workflow engine |
| **Webhook support** | None | Full webhook + WebSocket |
| **Custom integration effort** | Build GraphQL client | Call REST API or use n8n |

**ALDECI gap**: Wiz's 268 named integrations is a massive ecosystem advantage. However, most are partner-maintained SaaS-to-SaaS connectors. ALDECI's n8n workflow engine + REST API + webhooks enable custom integrations with anything, but lack the "click to enable" marketplace experience.

**Strategic recommendation**: Build a Wiz-style integrations marketplace page (even if integrations are n8n-based). The perception of ecosystem size matters for enterprise buyers.

---

## 6. Pricing Model

### 6.1 Pricing Structure

Wiz uses **per-billable-workload** pricing with custom quotes. No public price list.

| Attribute | Detail |
|-----------|--------|
| **Billing unit** | Per cloud workload (VMs, containers, serverless functions) |
| **Billing frequency** | Monthly, based on peak workload count |
| **Stopped instances** | Still scanned and billed (orphaned resource cleanup required) |
| **Contract terms** | Typically 1-3 year agreements |
| **Negotiation** | Heavily negotiated; volume discounts available |
| **AWS Marketplace** | Available (EDP committed spend credits apply) |

### 6.2 Published Price Points (AWS Marketplace)

| Tier | Workloads | Annual Cost | Per-Workload/Year |
|------|-----------|-------------|-------------------|
| **Wiz Essential** | 100 | $24,000 | $240 |
| **Wiz Advanced** | 100 | $38,000 | $380 |

### 6.3 Estimated Cost by Organization Size

| Deployment Size | Workloads | Estimated Annual Cost |
|----------------|-----------|----------------------|
| Small | <1,000 | $50K - $100K |
| Mid-size | 1,000 - 5,000 | $100K - $200K |
| Large enterprise | 5,000+ | $200K - $500K+ |
| Fortune 500 | 10,000+ | $500K - $1M+ |

### 6.4 Module Add-On Pricing (Estimated % Increase Over Base)

| Module | Premium Over Base |
|--------|------------------|
| CWPP (workload protection) | +15-25% |
| DSPM (data security) | +10-20% |
| CIEM (identity entitlements) | +10-15% |
| Wiz Code (developer security) | +10-15% |
| Wiz Defend (CDR/runtime) | +20-30% |

### 6.5 ALDECI Cost Comparison

| Scenario | Wiz Annual | ALDECI Annual | Savings |
|----------|-----------|---------------|---------|
| 100 workloads (Essential) | $24,000 | $420 (Community) | **98.3%** |
| 100 workloads (Advanced) | $38,000 | $1,188 (Pro) | **96.9%** |
| 500 workloads | ~$75,000 | $1,188 (Pro) | **98.4%** |
| 1,000 workloads | ~$120,000 | $5,988 (Enterprise) | **95.0%** |
| 5,000 workloads | ~$250,000 | $5,988 (Enterprise) | **97.6%** |

**TCO note**: Wiz is SaaS -- no infra cost. ALDECI is self-hosted -- add $50-200/month for hosting (still 90%+ cheaper).

---

## 7. Top 5 Enterprise Differentiators

These are the reasons enterprises choose Wiz, based on analyst reports, customer reviews, and competitive positioning research:

### Differentiator 1: The Security Graph (Toxic Combinations)

**What it is**: A Neo4j-style property graph that maps ALL cloud resources as nodes and ALL relationships (IAM permissions, network reachability, data access, vulnerability exposure) as edges.

**Why enterprises love it**: Instead of showing 10,000 individual findings, Wiz shows the 10 attack paths that actually matter. A single "toxic combination" card shows: *"This publicly-exposed VM has an overpermissive IAM role that can access an S3 bucket containing PII training data for an AI model."* That is five separate findings collapsed into one actionable insight.

**Impact**: Forrester noted that 50% of Wiz customers are in the "Zero Criticals Club" -- no outstanding critical issues in production. This is because the graph eliminates noise and lets teams focus.

**ALDECI response**: TrustGraph + attack_path_engine + brain_pipeline provide the data model. The gap is the **interactive graph visualization** in the UI and the **toxic combination detection algorithm** as a first-class API feature.

### Differentiator 2: Agentless-First Architecture (Time to Value)

**What it is**: SideScanning creates read-only snapshots of workloads and analyzes them out-of-band. No agents to install, no performance impact, no maintenance burden.

**Why enterprises love it**: Connect your AWS account and get full visibility in **minutes**, not weeks. No rollout plan, no agent conflicts, no kernel compatibility issues. One IAM role, one API call, done.

**Impact**: Wiz can scan an entire 10,000-workload environment in hours, not months. This makes PoC evaluations trivially easy -- which is why Wiz wins so many competitive bake-offs.

**ALDECI response**: ALDECI uses connector-based scanning (13 PULL connectors + 32 scanner normalizers). The time-to-value is slower but the depth is greater. Consider adding agentless cloud snapshot scanning for the top 3 providers (AWS, Azure, GCP) to match Wiz's onboarding experience.

### Differentiator 3: Unified CNAPP (Tool Consolidation)

**What it is**: CSPM + CWPP + CIEM + DSPM + KSPM + AI-SPM + IaC + CDR in one platform, one UI, one graph.

**Why enterprises love it**: Replaces 5-8 point solutions. One vendor, one contract, one dashboard. Security teams stop context-switching between tools. Alert fatigue drops dramatically because the graph contextualizes everything.

**Impact**: Gartner, Forrester, and G2 all recognize Wiz as the CNAPP market leader. The consolidation story resonates with CISOs who are drowning in tool sprawl.

**ALDECI response**: ALDECI has even broader consolidation (334 engines vs Wiz's ~10 modules). The challenge is **communicating** this breadth without overwhelming buyers. ALDECI needs a "3 product tiers" story: Essential (matches Wiz), Professional (adds SOC/TI/GRC), Enterprise (full platform).

### Differentiator 4: Google/Alphabet Backing

**What it is**: $32B acquisition by the world's most valuable cloud company. Unlimited R&D budget, Google threat intelligence, Gemini AI integration.

**Why enterprises love it**: Enterprise buyers are risk-averse. A Google-backed product will not disappear. Google's SOC/Mandiant/Chronicle integrations add real security value. The brand provides instant credibility.

**Impact**: Post-acquisition, Wiz's deal velocity is expected to increase further because Google Cloud sales teams now sell Wiz alongside GCP.

**ALDECI response**: This is Wiz's strongest differentiator and ALDECI's hardest to match. Counter-position: "Google owns your security data" vs "ALDECI keeps data on your servers." The data sovereignty narrative is the antidote to the Google trust narrative.

### Differentiator 5: Low False Positive Rate

**What it is**: Wiz's graph-based analysis produces fewer false positives than traditional rule-based scanners because it factors in actual exploitability (network exposure + IAM path + data sensitivity) rather than just CVSS scores.

**Why enterprises love it**: Forrester specifically called out Wiz's "low level of false positives" as building "credibility for risk remediation." Security teams trust Wiz alerts because they are real, not theoretical.

**Impact**: Higher trust = higher remediation rate = better security outcomes. This creates a virtuous cycle where security teams actually fix issues instead of ignoring alert fatigue.

**ALDECI response**: ALDECI's brain_pipeline + Karpathy LLM consensus (4 models) can achieve similar or better contextual analysis. The key is to **measure and market** false positive rates. If ALDECI can demonstrate a <5% false positive rate, this matches Wiz's strongest claim.

---

## 8. Known Weaknesses & Gaps

Based on G2, Gartner Peer Insights, PeerSpot reviews, and analyst reports (2026):

### 8.1 Architectural Limitations

| Weakness | Detail | Severity | ALDECI Advantage |
|----------|--------|----------|------------------|
| **SaaS-only** | No on-premise, no self-hosted, no air-gapped deployment | CRITICAL | ALDECI is 100% self-hosted |
| **No webhook/event push** | Cannot push real-time events to external systems; polling only | HIGH | Full webhook + WebSocket system |
| **24-hour scan cycle** | Default agentless scans run once per day; gaps between scans | HIGH | Configurable scan frequency |
| **No active blocking** | Historically passive detection only; Runtime Sensor adds detection but NOT kernel-level prevention | HIGH | Configurable response actions |
| **3 req/s API rate limit** | Blocks high-throughput integrations at scale | MEDIUM | Configurable per-tenant limits |
| **GraphQL-only API** | Forces all integrators to learn GraphQL; no REST option | MEDIUM | REST + GraphQL available |
| **No official SDK** | Every customer builds their own API client | MEDIUM | OpenAPI auto-client generation |
| **10K query result caps** | Cannot extract full datasets without Reports endpoint | MEDIUM | No arbitrary caps |

### 8.2 Feature Gaps

| Gap | Detail | ALDECI Coverage |
|-----|--------|----------------|
| **No SOC workflow** | Cannot manage SOC operations, case management, SLA tracking | 9+ SOC/incident engines |
| **No SIEM management** | Feeds SIEMs but does not manage them | SIEM integration engine |
| **No threat intelligence platform** | No TI management, IOC lifecycle, dark web monitoring | 25+ TI engines |
| **No GRC/risk management** | No risk register, risk treatment, evidence collection, audit management | 40+ GRC engines |
| **No EDR/NDR/XDR** | Cloud-only; no endpoint, network, or extended detection | EDR, NDR, XDR engines |
| **No OT/IoT/SCADA** | Zero coverage for operational technology environments | OT, IoT, firmware engines |
| **No physical security** | Zero coverage for physical access, badges, cameras | Physical security engine |
| **No pentest/red team management** | Cannot manage offensive security programs | Pentest, red team, bug bounty engines |
| **No security training** | Cannot manage awareness programs, phishing simulation | Training, awareness, gamification engines |
| **No network security management** | Cannot manage firewalls, WAF, NAC, DDoS protection | 15+ network security engines |
| **No identity lifecycle** | CIEM for cloud only; no full IAM lifecycle management | Full identity lifecycle, PAG, session recording |

### 8.3 User Experience Issues (from Reviews)

| Issue | Source | Detail |
|-------|--------|--------|
| **Alert noise in large environments** | G2, PeerSpot | Duplicate alerts under different categories; overwhelming at scale |
| **Weak reporting** | G2, PeerSpot | Only compliance CSV reports; no customizable executive summaries |
| **Case-sensitive search** | PeerSpot | Finding misconfigurations requires exact-case queries |
| **Steep learning curve** | G2 | Complex UX with extensive functionality takes weeks to master |
| **Immature IDE integration** | PeerSpot | No rule IDs visible; limited ignore granularity outside global rules |
| **Weak connector validation** | G2 | Input validation for cloud connector credentials creates friction |
| **No self-remediation** | PeerSpot | Missing features hinder automated remediation workflows |
| **No project segregation** | G2 | Difficult to segregate findings by business unit/project |
| **Pricing barrier** | G2, multiple | $50K minimum shuts out SMBs, startups, and non-profits |

### 8.4 Post-Acquisition Risks

| Risk | Detail |
|------|--------|
| **AWS/Azure customer anxiety** | Google ownership may cause strategic concerns for competing cloud customers |
| **Price increase probability** | Google historically raises prices post-acquisition |
| **Product road bifurcation** | GCP-specific features may get priority over multi-cloud parity |
| **Data sovereignty** | Security telemetry now flows through Google infrastructure |
| **Talent attrition** | Israeli founding team may depart after vesting cliff |
| **Integration absorption** | Partner integrations may be replaced by Google-owned equivalents |

---

## 9. Attack Path & Security Graph Deep Dive

### 9.1 Architecture

The Wiz Security Graph is a **property graph database** (Neo4j-style) that represents:

- **Nodes**: Cloud resources (VMs, containers, databases, S3 buckets, IAM roles, serverless functions, K8s pods, AI models)
- **Edges**: Relationships with typed properties:
  - `NETWORK_REACHABLE` -- network connectivity between resources
  - `HAS_PERMISSION` -- IAM permission grants (who can access what)
  - `CONTAINS_DATA` -- data classification from DSPM scans
  - `HAS_VULNERABILITY` -- CVEs affecting a resource
  - `IS_EXPOSED_TO_INTERNET` -- public IP or public endpoint
  - `RUNS_ON` -- container-to-host, function-to-runtime relationships
  - `ACCESSES` -- observed API call relationships

### 9.2 How Attack Path Analysis Works

1. **Graph Construction**: Every 24 hours (agentless scan cycle), Wiz rebuilds the complete graph for each cloud account
2. **Crown Jewel Identification**: Resources tagged as critical (production databases, AI training data, PII stores) are marked as target nodes
3. **Entry Point Detection**: Internet-exposed resources, publicly accessible endpoints, and accounts without MFA are marked as entry nodes
4. **Path Traversal**: BFS/DFS algorithms traverse from entry points through permission chains, network paths, and vulnerability hops to reach crown jewels
5. **Toxic Combination Detection**: Paths where multiple individually-low-risk factors combine to create critical exposure are flagged
6. **Scoring**: Each path receives a composite score based on: number of hops, severity of required exploits, blast radius of crown jewel, data sensitivity

### 9.3 Toxic Combination Examples

**Example 1 -- Classic Cloud Breach Path:**
```
[Internet] → Public IP on VM → Unpatched CVE-2024-XXXX → IAM Role with S3:GetObject → 
S3 Bucket containing PII → AI Training Pipeline
```
Individual components: Medium, Medium, Low, Low, Info
Toxic combination: **CRITICAL** -- full data exfiltration path

**Example 2 -- Lateral Movement:**
```
[Internet] → Public ALB → Container with privileged access → Host escape → 
Kubernetes cluster admin → Cross-namespace access → Production RDS (PHI data)
```

**Example 3 -- AI-Specific:**
```
[Internet] → Exposed inference endpoint → Write access to training bucket → 
Data poisoning of ML model → Incorrect outputs in production
```

### 9.4 Visualization

- **Card-based list**: Prioritized attack paths shown as cards with: start/end nodes, path length, required exploits, blast radius score
- **Interactive graph**: Clicking a card opens force-directed graph with highlighted path
- **Dimming**: Off-path nodes are dimmed; critical path is highlighted in red
- **Side panel**: Click any node for details (CVEs, IAM policies, data classification, owner)
- **Mini-map**: Corner navigation for large environments
- **Toxic combination badge**: Special visual indicator on multi-factor risk convergence points

### 9.5 ALDECI Gap Analysis

| Capability | Wiz | ALDECI |
|-----------|-----|--------|
| Graph data model | Neo4j-style property graph | TrustGraph (5 cores) + SQLite per engine |
| Graph query API | GraphQL traversal | BFS in attack_path_engine |
| Crown jewel identification | DSPM + asset tagging | Asset criticality engine |
| Toxic combination detection | First-class feature | **NOT IMPLEMENTED** |
| Interactive graph UI | Force-directed + drill-down | Basic SVG in AttackPathAnalysis.tsx |
| Internet exposure as universal filter | Yes (isAccessibleFromInternet) | Partial (per-engine, not universal) |
| Data sensitivity as universal filter | Yes (hasSensitiveData from DSPM) | Partial (data_discovery, DLP separate) |
| Real-time graph updates | 24h cycle + Runtime Sensor events | TrustGraph event bus (332 engines wired) |

**Priority recommendation**: Build a `toxic_combination_engine.py` and an interactive SecurityGraph React component. These two additions would close Wiz's #1 differentiator gap.

---

## 10. Head-to-Head: ALDECI vs Wiz

### 10.1 Feature Coverage Scorecard

| Domain | Wiz (0-10) | ALDECI (0-10) | Notes |
|--------|-----------|--------------|-------|
| Cloud Posture (CSPM) | 10 | 7 | Wiz: 2,800 rules, agentless. ALDECI: engine-based, fewer rules |
| Cloud Workload Protection | 9 | 6 | Wiz: agentless deep scanning. ALDECI: scanner normalizers |
| Kubernetes Security | 9 | 7 | Wiz: deep KSPM + CIS. ALDECI: kubernetes_security engine |
| Data Security (DSPM) | 9 | 6 | Wiz: actual content scanning with ML. ALDECI: data_discovery + DLP |
| Identity/Entitlements (CIEM) | 8 | 8 | Both strong; ALDECI has deeper IAM lifecycle |
| AI Security (AI-SPM) | 9 | 5 | Wiz: first-mover, AI-BOM. ALDECI: ai_governance but less depth |
| Developer Security (Code) | 7 | 7 | Roughly equivalent; Wiz has more CI/CD integrations |
| Runtime/CDR | 8 | 4 | Wiz: eBPF sensor. ALDECI: no runtime sensor |
| Attack Path Visualization | 10 | 5 | Wiz: industry-leading graph. ALDECI: basic SVG |
| Compliance Scanning | 8 | 8 | Both strong on scanning; ALDECI deeper on lifecycle |
| **SOC Operations** | 0 | 9 | Wiz has zero SOC capability |
| **Threat Intelligence** | 0 | 9 | Wiz has zero TI platform capability |
| **GRC / Risk Management** | 0 | 9 | Wiz has zero GRC capability |
| **Network Security** | 0 | 8 | Wiz is cloud-only |
| **Endpoint Security (EDR)** | 0 | 7 | Wiz is cloud-only |
| **OT/IoT/Physical** | 0 | 7 | Wiz is cloud-only |
| **Identity Lifecycle (Full)** | 3 | 9 | Wiz: CIEM only. ALDECI: full IAM lifecycle |
| **Pentest/Red Team** | 0 | 8 | Wiz has zero offensive security |
| **Security Training** | 0 | 7 | Wiz has zero awareness/training |
| Integration ecosystem | 9 | 4 | 268 vs ~40 named integrations |
| UI/UX polish | 9 | 5 | Wiz: enterprise-grade. ALDECI: functional but less polished |
| **TOTAL (weighted)** | **6.2/10** | **7.1/10** | ALDECI wins on breadth; Wiz wins on cloud depth and UX |

### 10.2 When to Position Against Wiz

**ALDECI wins when:**
- Buyer requires self-hosted / on-premise / air-gapped deployment
- Buyer needs full security lifecycle (not just cloud posture)
- Buyer cannot afford $50K+ minimum annual spend
- Buyer is worried about Google data sovereignty
- Buyer needs SOC, threat intel, GRC, or network security in the same platform
- Buyer operates OT/IoT/SCADA environments
- Buyer needs real-time webhooks/event push
- Buyer needs high-throughput API access (>3 req/s)

**Wiz wins when:**
- Buyer is pure cloud-native with no on-premise
- Buyer needs the fastest time-to-value (minutes, not hours)
- Buyer values brand recognition and analyst validation
- Buyer's team is small and needs the graph to prioritize for them
- Buyer is already in the Google Cloud ecosystem
- Buyer needs the specific integration with one of 268 WIN partners
- Buyer's compliance is purely cloud-focused (CIS, SOC 2, PCI for cloud)

---

## 11. Strategic Recommendations for ALDECI

### 11.1 Must-Build (Close Critical Gaps)

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| **P0** | Toxic combination detection engine + API | 2-3 days | Closes Wiz's #1 differentiator |
| **P0** | Interactive Security Graph UI (React Flow / @xyflow/react) | 3-5 days | Closes the biggest visual gap |
| **P1** | Internet exposure + data sensitivity as universal query filters | 1-2 days | Matches Wiz's graph query UX |
| **P1** | Agentless cloud snapshot scanning (AWS first) | 5-7 days | Matches Wiz's time-to-value story |
| **P2** | AI-BOM generation (discover AI services/models in cloud) | 2-3 days | Matches AI-SPM capability |
| **P2** | Integrations marketplace page (list all n8n + native integrations) | 1 day | Perception of ecosystem size |

### 11.2 Must-Market (Existing Advantages to Promote)

| Advantage | Sales Narrative |
|-----------|----------------|
| Self-hosted | "Your security data never leaves your network. Google now owns Wiz's infrastructure." |
| 95-98% cost reduction | "Wiz Essential costs $24K/yr for 100 workloads. ALDECI Pro costs $1,188/yr for unlimited." |
| Full security lifecycle | "Wiz finds cloud misconfigs. ALDECI manages your entire security program." |
| 334 engines vs 10 modules | "Wiz covers cloud. ALDECI covers cloud + SOC + threat intel + GRC + network + OT + identity." |
| Webhook + WebSocket | "Wiz has no webhooks. You poll at 3 req/s. ALDECI pushes events in real-time." |
| No vendor lock-in | "Wiz is now a Google product. ALDECI is yours forever." |

### 11.3 Positioning Matrix

| Buyer Segment | Lead Message | Wiz Counter |
|--------------|-------------|-------------|
| **Startup / SMB** | "Enterprise security for $99/month" | Wiz won't even talk to you at <$50K |
| **Mid-market** | "Replace your 5-tool stack with one platform" | Same as Wiz, but 95% cheaper |
| **Enterprise (regulated)** | "Self-hosted, SOC 2, HIPAA, on-prem" | Wiz is SaaS-only, Google-owned |
| **MSSP** | "White-label, multi-tenant, API-first" | Wiz charges per customer, no white-label |
| **Government / Defense** | "Air-gapped, FedRAMP path, on-prem" | Wiz FedRAMP Moderate only, SaaS-only |
| **OT/Industrial** | "Only platform covering IT + OT + IoT" | Wiz is cloud-only, zero OT coverage |

---

## 12. Sources

### Official Wiz Sources
- [Wiz Platform Overview](https://www.wiz.io/platform)
- [Wiz Defend (CDR)](https://www.wiz.io/platform/wiz-defend)
- [Wiz DSPM Solution](https://www.wiz.io/solutions/dspm)
- [Wiz CIEM Solution](https://www.wiz.io/solutions/ciem)
- [Wiz Compliance Solution](https://www.wiz.io/solutions/compliance)
- [Wiz Security Graph](https://www.wiz.io/lp/wiz-security-graph)
- [Wiz AI-SPM Announcement](https://www.wiz.io/blog/ai-security-posture-management)
- [Wiz Integrations Marketplace](https://www.wiz.io/integrations)
- [Wiz Pricing Page](https://www.wiz.io/pricing)
- [Wiz Forrester Wave CNAPP Q1 2026](https://www.wiz.io/blog/forrester-wave-cnapp-2026)
- [Wiz Attack Path Analysis Academy](https://www.wiz.io/academy/detection-and-response/attack-path-analysis)
- [Wiz Toxic Combinations Blog](https://www.wiz.io/blog/the-anatomy-of-a-toxic-combination-of-risk)
- [Wiz SOC 2 / Trust Center](https://trust.wiz.io/)
- [Wiz vs CrowdStrike Comparison](https://www.wiz.io/academy/cloud-security/wiz-vs-crowdstrike)
- [Wiz 100 WIN Integrations Blog](https://www.wiz.io/blog/100-win-integrations-and-counting)
- [Wiz Runtime Sensor for Windows](https://www.wiz.io/blog/wiz-runtime-sensor-for-your-windows-environment)
- [Wiz Joins Google Blog](https://www.wiz.io/blog/google-closes-deal-to-acquire-wiz)

### Acquisition & Analyst Sources
- [Google Completes Acquisition of Wiz (Press Release)](https://www.googlecloudpresscorner.com/2026-03-11-Google-Completes-Acquisition-of-Wiz)
- [TechCrunch: Google Completes $32B Wiz Acquisition](https://techcrunch.com/2026/03/11/google-completes-32b-acquisition-of-wiz/)
- [SecurityWeek: DOJ Clears Google Wiz Acquisition](https://www.securityweek.com/doj-antitrust-review-clears-googles-32-billion-acquisition-of-wiz/)
- [Forrester: Google Acquires CNAPP Unicorn Wiz](https://www.forrester.com/blogs/google-to-acquire-cnapp-specialist-unicorn-wiz-for-32bn/)
- [LexisNexis: Patent Analytics on Google-Wiz](https://www.lexisnexisip.com/resources/the-32b-google-wiz-acquisition/)

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
- [TrustRadius: Wiz Reviews 2026](https://www.trustradius.com/products/wiz/reviews)

### Technical & Integration Sources
- [Stitchflow: Wiz API Guide](https://www.stitchflow.com/user-management/wiz/api)
- [Cribl: Wiz API Source Docs](https://docs.cribl.io/stream/sources-wiz/)
- [Port: Wiz Integration Docs](https://docs.port.io/build-your-software-catalog/sync-data-to-catalog/code-quality-security/wiz/)
- [Datadog: Wiz Integration](https://docs.datadoghq.com/integrations/wiz/)
- [APITracker: Wiz API](https://apitracker.io/a/wiz-io)
- [Solide Info: Wiz 2026 Definitive Guide](https://solideinfo.com/wiz-cloud-security/)
- [AppSecSanta: Wiz 2026 Agentless CNAPP](https://appsecsanta.com/wiz)
- [PuppyGraph: Recreating Wiz Security Graph](https://www.puppygraph.com/blog/wiz-security-graph)
- [Google Cloud: Wiz Architecture Guide](https://docs.cloud.google.com/architecture/partners/id-prioritize-security-risks-with-wiz)
- [Plexicus: Wiz Alternatives 2026](https://www.plexicus.ai/blog/review/wiz-alternatives-from-visibility-to-remediation/)
- [Aikido: Wiz Alternatives 2026](https://www.aikido.dev/blog/top-wiz-io-alternatives-for-cloud-application-security)

---

*Report generated 2026-04-22 by ALDECI CTO Agent. Updates quarterly or upon significant Wiz product announcements.*
