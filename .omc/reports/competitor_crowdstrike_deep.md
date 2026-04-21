# CrowdStrike Falcon Deep Competitive Intelligence Report

**Date:** 2026-04-22 (Updated with RSAC 2026 + Spring '26 Release data)
**Analyst:** Claude Opus 4.6 (CTO Agent)
**Branch:** features/intermediate-stage
**Classification:** Internal — ALDECI Competitive Intelligence

---

## Table of Contents

1. [Platform Overview](#1-platform-overview)
2. [Complete Product Module Catalog](#2-complete-product-module-catalog)
3. [API Surface — All Endpoints & Service Collections](#3-api-surface--all-endpoints--service-collections)
4. [ASPM Capabilities Deep Dive](#4-aspm-capabilities-deep-dive)
5. [CTEM Capabilities Deep Dive](#5-ctem-capabilities-deep-dive)
6. [Real-Time Streaming / SSE Capabilities](#6-real-time-streaming--sse-capabilities)
7. [Compliance Frameworks](#7-compliance-frameworks)
8. [Pricing Model & Tiers](#8-pricing-model--tiers)
9. [Top 5 Enterprise Differentiators](#9-top-5-enterprise-differentiators)
10. [Known Weaknesses](#10-known-weaknesses)
11. [ALDECI vs CrowdStrike — Strategic Assessment](#11-aldeci-vs-crowdstrike--strategic-assessment)
12. [Sources](#12-sources)

---

## 1. Platform Overview

CrowdStrike Falcon is a **unified, cloud-native, AI-native security platform** built on the CrowdStrike Threat Graph (processing trillions of events per week). It operates on a **single lightweight agent** architecture — one kernel-level sensor deployed to endpoints that feeds telemetry into a cloud-native SaaS backend.

### Architecture Pillars

| Pillar | Description |
|--------|-------------|
| **Threat Graph** | Petabyte-scale graph database storing all telemetry — detections, events, entities, relationships — across endpoints, cloud, identity, SaaS. Up to 1 year of detection history. |
| **Charlotte AI** | Agentic AI layer embedded across every UI surface. Natural language queries, auto-triage, investigation co-pilot, dashboard generation. |
| **Charlotte AI AgentWorks** | No-code platform for customers to build, deploy, and orchestrate custom security AI agents. Industry first (announced 2025/2026). |
| **Single Agent** | One lightweight kernel sensor for Windows/macOS/Linux. ~25MB footprint. Handles EDR, NGAV, identity, cloud workload protection, vulnerability scanning, data protection. |
| **ExPRT.AI** | Proprietary exploitability prediction engine — combines CVSS, EPSS, adversary intelligence, and live telemetry to predict which vulnerabilities will be exploited next. |
| **Falcon Fusion SOAR** | Built-in SOAR automation — workflow builder for patching, isolation, ticketing, compensating controls. |

### Scale

- **106 API service collections** with **1,364 total API operations** (per FalconPy SDK)
- **30+ platform modules** spanning endpoint, cloud, identity, SIEM, exposure management, data protection, IoT/OT
- **281+ tracked adversary groups** with named profiles (BEAR, PANDA, KITTEN, SPIDER, etc.)
- **8.5M+ endpoints under management** (demonstrated during July 2024 incident)
- **99.99% guaranteed uptime SLA**
- Leader in **Gartner Magic Quadrant for Endpoint Protection** for 6 consecutive years
- Named **Customers' Choice in 2026 Gartner Peer Insights VOC for ASPM Tools**
- Named **Frost & Sullivan 2026 Company of the Year** for Cloud Workload Security (CWS) and 2025 Company of the Year for Global SSPM (second consecutive)

### Financial Scale (Fiscal Year 2026, ending Jan 31 2026)

| Metric | Value |
|--------|-------|
| **Total Revenue** | $4.81 billion (+22% YoY) |
| **Subscription Revenue** | $4.56 billion (+21% YoY) |
| **Ending ARR** | $5.25 billion (+24% YoY, first time crossing $5B) |
| **Record Net New ARR** | $331 million (+47% YoY) |
| **Falcon Flex ARR** | $1.69 billion (+120% YoY) |
| **Gross Retention** | 97% |
| **Cash & Equivalents** | $5.23 billion |
| **GAAP Subscription Gross Margin** | 78% |
| **Non-GAAP Subscription Gross Margin** | 81% |
| **Free Cash Flow (Q4)** | $376.4 million |
| **Target** | Advancing toward $10B ending ARR |

**Takeaway for ALDECI:** CrowdStrike has $5B ARR and $5B cash. They can outspend any startup on R&D, sales, and M&A. ALDECI's competitive moat must be structural (self-hosted, cost, compliance depth), not feature parity.

---

## 2. Complete Product Module Catalog

### 2.1 Confirmed Trial/Named Modules (15 modules)

| # | Module Name | Category | Description |
|---|------------|----------|-------------|
| 1 | **Falcon Prevent** | Endpoint | AI-powered next-gen antivirus (NGAV). ML-based malware prevention, behavioral IOA detection. |
| 2 | **Falcon Device Control** | Endpoint | USB and removable media policy enforcement. Block/allow by vendor, product, serial number. |
| 3 | **Falcon for Mobile** | Endpoint | Mobile threat defense for iOS/Android. App analysis, phishing protection, device posture. |
| 4 | **Falcon Insight XDR** | Detection & Response | Extended detection and response. Process tree visualization, Threat Graph explorer, cross-domain correlation. |
| 5 | **Falcon Spotlight** | Vulnerability Mgmt | Real-time vulnerability assessment via sensor. CVE detection without scans. ExPRT.AI risk scoring. EPSS + KEV integration. |
| 6 | **Falcon Identity Protection** | Identity Security | AD/Azure AD threat detection, lateral movement prevention, identity attack surface reduction. ITDR capabilities. |
| 7 | **Falcon Next-Gen SIEM** | SIEM/Log Mgmt | Cloud-native SIEM (formerly LogScale/Humio). Petabyte-scale log ingestion, real-time search, compliance dashboards. |
| 8 | **Falcon Data Protection** | Data Security | Endpoint DLP, content inspection, data classification. Integrated with the sensor. |
| 9 | **Falcon Cloud Security** | Cloud/CNAPP | Unified CSPM + CWP + ASPM + CIEM. AWS/Azure/GCP/OCI. Agentless + agent-based. |
| 10 | **Falcon FileVantage** | File Integrity | File integrity monitoring (FIM). Real-time change detection with process attribution. |
| 11 | **Falcon Sandbox** | Malware Analysis | Automated malware analysis. Detonation, behavioral profiling, IOC extraction. |
| 12 | **Falcon Discover** | Asset Discovery | IT hygiene — discover unmanaged assets, applications, accounts, and shadow IT. |
| 13 | **Falcon for IT** | IT Operations | Intelligent patching and IT remediation. Vulnerability-to-patch closed loop. |
| 14 | **Falcon ASPM** | Application Security | Application security posture management (acquired from Bionic). Service mapping, API discovery, SBOM, sensitive data flow detection. |
| 15 | **Falcon Firewall Management** | Network Security | Host-based firewall policy management. Centralized rule authoring and deployment. |

### 2.2 Additional Named Products (15+ additional modules)

| # | Module Name | Category | Description |
|---|------------|----------|-------------|
| 16 | **Falcon OverWatch** | Managed Hunting | 24/7 elite human threat hunting. Proactive detection of stealthy adversary activity. |
| 17 | **Falcon Complete (Next-Gen MDR)** | Managed Service | Fully managed detection, investigation, and response. Breach prevention warranty included. |
| 18 | **Falcon Adversary Intelligence** | Threat Intel | 245+ adversary profiles (BEAR/PANDA/KITTEN/SPIDER). TTPs, infrastructure, campaigns. Named actor tracking. |
| 19 | **Falcon Counter Adversary Operations** | Threat Intel | Digital risk protection — dark web monitoring, credential exposure, brand protection. |
| 20 | **Falcon Exposure Management** | CTEM | Continuous threat exposure management. ExPRT.AI + attack path analysis + external attack surface. |
| 21 | **Falcon Surface (EASM)** | Attack Surface | External attack surface management (acquired from Reposify). Internet-facing asset discovery. |
| 22 | **Falcon for XIoT** | IoT/OT | Extended IoT, OT, and medical device protection. Industrial control system visibility. |
| 23 | **Falcon Onum** | Telemetry | Telemetry control system — manage what data flows where and how much. Cost governance for log volumes. |
| 24 | **Falcon Flex** | Licensing | Credit-based consumption model. Annual credit pool for module swaps. 20-35% discount vs individual purchases. |
| 25 | **Charlotte AI** | AI Layer | Agentic AI — detection triage, investigation co-pilot, natural language queries, dashboard generation. |
| 26 | **Charlotte AI AgentWorks** | AI Platform | No-code platform for building and governing custom security AI agents at scale. |
| 27 | **Falcon Fusion SOAR** | Automation | Built-in SOAR — workflow automation for response, patching, ticketing, isolation. |
| 28 | **Falcon Real-Time Response (RTR)** | IR/Response | Live bi-directional command channel to endpoints. File I/O, script execution, memory forensics. |
| 29 | **Falcon Quick Scan** | Detection | Cloud hash lookup for rapid AV scanning. Near-instant verdicts. |
| 30 | **Flight Control (MSSP)** | Multi-Tenant | MSSP management plane. Child CID management, cross-tenant aggregation, delegated permissions. |

### 2.3 Recently Announced Capabilities (2025-2026)

| Capability | Description |
|-----------|-------------|
| **Shadow AI Visibility** | Detect and govern shadow AI usage — desktop AI apps, unauthorized AI services, data leakage to LLMs. |
| **Shadow SaaS Discovery** | Discover unauthorized SaaS applications and AI agents across the organization. |
| **Browser Extension Control** | Detect and block risky browser extensions. |
| **AI Data Flow Discovery** | Map data flows between applications and AI/ML services in cloud environments. |
| **AIDR (AI-Driven Response)** | Automated response covering desktop AI apps and containerized workloads. |
| **Timeline Explorer** | Cloud risk triage interface — visual timeline of cloud security events. |
| **Continuous Visibility** | Continuous cloud network asset scanning without periodic scan cycles. |
| **SOC Transformation Services** | Professional services for SOC modernization. |
| **Frontier AI Readiness Service** | Assessment service for AI security posture. |
| **SGNL Integration** | Continuous authorization and zero-standing-privilege enforcement. |

### 2.4 Spring '26 Release & RSAC 2026 Announcements (March-April 2026)

These are the most recent announcements and represent CrowdStrike's current strategic direction.

#### Falcon Data Security (NEW Product Launch)

| Capability | Details |
|-----------|---------|
| **Real-Time DLP** | Identifies, categorizes, and stops unauthorized movement of sensitive data in real time using adversary intelligence. |
| **Cross-Domain Coverage** | Monitors data across endpoints, SaaS, cloud, browsers, and AI workflows as data is created, transformed, and shared. |
| **Adversary-Informed** | Uses Falcon platform unified context and adversary intelligence to prioritize data theft risks. |

#### AI Security Expansion (RSAC 2026)

| Feature | Details |
|---------|---------|
| **EDR AI Runtime Protection** | Monitors AI application behavior on endpoints — commands, scripts, file activity, network connections. Can isolate compromised endpoints running AI workloads. |
| **Shadow AI Discovery for Endpoint** | Auto-discovers AI applications, agents, LLM runtimes, MCP servers, and AI development tools across devices. |
| **AIDR for Desktop** | Extends prompt-layer protections to desktop AI tools: ChatGPT, Gemini, Claude, DeepSeek, and Copilot variants. |
| **Shadow SaaS & AI Agent Discovery** | Discovers unauthorized SaaS applications and AI agent activity across Microsoft Copilot, Salesforce Agentforce, ChatGPT Enterprise. |
| **AIDR for Copilot Studio Agents** | Monitors prompts, data interactions, and runtime behavior to detect injection attacks and data leaks in low-code AI agents. |
| **Shadow AI Discovery for Cloud** | Identifies ungoverned AI services and sensitive data exposure across cloud infrastructure and applications. |
| **AIDR for Cloud and Kubernetes** | Runtime inspection for containerized AI workloads in Kubernetes environments. |
| **AI Data Flow Discovery for Cloud** | Tracks sensitive data movement through AI services in real time. |

#### Charlotte AI AgentWorks Ecosystem (Launched March 25, 2026)

Built in collaboration with Accenture, AWS, Anthropic, Deloitte, Kroll, NVIDIA, OpenAI, Salesforce, and Telefonica Tech.

| Agent | Function | Domain |
|-------|----------|--------|
| **Detection Triage Agent** | Classifies new detections and recommends next steps. >98% triage accuracy. | Detection & Response |
| **Response Agent** | Drives investigations with guiding questions and answers. | Detection & Response |
| **Malware Analysis Agent** | Analyzes files, maps malware families, builds YARA rules. | Threat Intelligence |
| **Hunt Agent** | Automates threat hunting and scans for emerging threats. | Threat Hunting |
| **Exposure Prioritization Agent** | Triages vulnerabilities and identifies exploitable risks. | Exposure Management |
| **Data Onboarding Agent** | Automates data pipeline creation for faster SIEM onboarding. | Next-Gen SIEM |
| **Search Analysis Agent** | Summarizes and interprets query results in seconds. | Next-Gen SIEM |
| **Correlation Rule Generation Agent** | Recommends and tunes detection rules for advanced threats. | Next-Gen SIEM |
| **Query Translation Agent** | Converts Splunk SPL queries into CrowdStrike Query Language (CQL). Eases SIEM migration. | Next-Gen SIEM |
| **Data Transformation Agent** | Normalizes and translates data across tools. | Agentic SOAR |
| **Workflow Generation Agent** | Converts natural language prompts into automated workflows. | Agentic SOAR |
| **Foundry App Creation Agent** | Builds security applications in CrowdStrike Falcon Foundry. | Platform |

**Performance claims:** >98% triage accuracy, 70% reduction in manual investigation work, 3X faster MTTR.

#### Charlotte Agentic SOAR (NEW)

Full orchestration layer providing mission-ready agents designed to offload common, time-intensive tasks ranging from triage to malware analysis, a workflow engine, and unified case management. Announced alongside AgentWorks.

#### Falcon Onum Integration (Acquisition Completed)

| Metric | Improvement |
|--------|------------|
| **Streaming Speed** | 5X faster data streaming |
| **Storage Costs** | 50% lower |
| **Incident Response** | 70% faster |
| **Ingestion Overhead** | 40% less through intelligent filtering and real-time in-pipeline detection |

Onum enriches, filters, and reshapes telemetry before delivering optimized copies to secondary destinations (data lakes, analytics tools, third-party systems). Replaces fragile legacy SIEM workflows with flexible hybrid pipelines.

#### SIEM Enhancements

| Feature | Details |
|---------|---------|
| **Microsoft Defender for Endpoint ingestion** | Native telemetry ingestion from MDE without additional sensors — positions CrowdStrike SIEM as a multi-vendor aggregation layer. |
| **Third-party indicator management** | External compromise data management in Next-Gen SIEM. |
| **Intel Partnership** | Falcon optimized for Intel-powered AI PCs — faster threat detection on endpoint with Intel hardware acceleration. |

---

## 3. API Surface — All Endpoints & Service Collections

### 3.1 Overview

| Dimension | Value |
|-----------|-------|
| API Base URL | `https://api.crowdstrike.com` |
| Auth Method | OAuth2 client credentials (Bearer token, 30-min TTL) |
| Total Service Collections | **106** |
| Total Operations | **1,364** (per FalconPy SDK) |
| Rate Limit | **6,000 requests/minute** per customer account |
| Rate Limit Headers | `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-RetryAfter` |
| Pagination | `offset` + `limit` pattern; max 500 items per call |
| Streaming | Event Streams API (SSE over HTTPS) |
| SDK Languages | Python (FalconPy), Go, PowerShell (PSFalcon), JavaScript, Rust, Ruby |
| OpenAPI Spec | Available at developer.crowdstrike.com (authenticated access) |
| On-Premise | **No** — SaaS only |

### 3.2 Complete Service Collection Catalog (106 Collections)

Organized by domain:

#### Detection & Response (6 collections)
| Collection | Key Operations |
|-----------|---------------|
| Detections | Query, get details, resolve, update status |
| Incidents | Query, get details, link detections to incidents |
| Alert Triage | Assign, update severity, bulk resolve |
| Real Time Response (RTR) | Execute commands on live endpoints, file upload/download, script execution |
| Real Time Response Admin | Manage RTR scripts, put-file management, admin command exec |
| Real Time Response Audit | Audit trail of RTR sessions |

#### Endpoint / Host Management (7 collections)
| Collection | Key Operations |
|-----------|---------------|
| Hosts | Query devices, get details, contain/lift containment, hide/unhide |
| Host Groups | CRUD group membership, assign prevention policies |
| Sensor Update Policies | Manage sensor versions, build targeting, policy assignment |
| Prevention Policies | CRUD AV/malware prevention rules |
| Device Control Policies | USB and removable media control |
| Response Policies | Endpoint response behavior policies |
| Content Update Policies | Manage rapid response content update deployment |

#### Firewall Management (2 collections)
| Collection | Key Operations |
|-----------|---------------|
| Firewall Management | Rule groups, policy rules, network location management |
| Firewall Policies | Assign firewall policy sets to host groups |

#### Threat Intelligence (4 collections)
| Collection | Key Operations |
|-----------|---------------|
| Intel | Query threat actors (245+), indicators (IOCs), reports, techniques |
| IOC Manager | Create/read/update/delete custom IOCs, bulk ingestion (500/call max) |
| MITRE ATT&CK | Query technique details, technique coverage mapping |
| Custom IOAs | Custom Indicators of Attack rules |

#### Vulnerability Management (2 collections)
| Collection | Key Operations |
|-----------|---------------|
| Spotlight Vulnerabilities | Query CVEs on endpoints, get vulnerability details, remediation paths |
| Spotlight Vulnerability Metadata | Query CVE evaluation logic |

#### Cloud Security — CSPM/CNAPP (11 collections)
| Collection | Key Operations |
|-----------|---------------|
| CSPM Registration | Register cloud accounts (AWS/Azure/GCP/OCI), delete registrations |
| Cloud Security (Horizon) | Query posture findings, get details, remediation guidance |
| Cloud Security Assets | Cloud asset inventory queries |
| Cloud Security Compliance | Cloud compliance benchmark results |
| Cloud Security Detections | Cloud runtime detection events |
| Cloud Snapshots | Cloud snapshot assessment |
| Cloud Connect AWS | AWS integration management |
| Cloud Policies | Cloud security policy CRUD |
| AWS Registration | AWS account registration |
| Azure Registration | Azure subscription registration |
| GCP Registration | GCP project registration |
| OCI Registration | OCI tenancy registration |

#### Container & Kubernetes (9 collections)
| Collection | Key Operations |
|-----------|---------------|
| Container Alerts | Query container-level alerts |
| Container Detections | Query container runtime detections |
| Container Images | Scan container images, get findings |
| Container Image Compliance | Image compliance checks |
| Container Packages | Query packages in containers for vulnerabilities |
| Container Vulnerabilities | Query CVEs affecting container images |
| Kubernetes Protection | Register clusters, query cluster findings |
| Kubernetes Container Compliance | K8s container compliance benchmarks |
| Unidentified Containers | Track containers without deployed agents |

#### Identity Security (3 collections)
| Collection | Key Operations |
|-----------|---------------|
| Identity Protection | Query identity-based detections, get identity entities |
| Zero Trust Assessment | ZTA scores per device/user, assessment details |
| User Management | CRUD users, roles, role assignments |

#### Asset Discovery (2 collections)
| Collection | Key Operations |
|-----------|---------------|
| Discover | Query discovered applications, hosts, accounts, logins |
| Asset Graph | Graph-based asset relationship queries |

#### Exposure Management (2 collections)
| Collection | Key Operations |
|-----------|---------------|
| Exposure Management | External attack surface queries, asset prioritization |
| ThreatGraph | Threat activity graph, adversary pattern queries |

#### Compliance & Configuration (2 collections)
| Collection | Key Operations |
|-----------|---------------|
| Compliance Assessments | CIS/NIST/PCI benchmark results per device |
| Configuration Assessment | Configuration drift detection |
| Image Assessment Policies | Container image assessment policies |
| Admission Control Policies | K8s admission control policies |

#### SOAR / Automation (3 collections)
| Collection | Key Operations |
|-----------|---------------|
| Falcon Fusion Workflows | CRUD automation workflows |
| Workflows | Trigger executions, query workflow run history |
| Correlation Rules | Cross-domain correlation rule management |

#### SIEM / Log Management (1 collection)
| Collection | Key Operations |
|-----------|---------------|
| Foundry LogScale | Ingest logs, query log data (NG-SIEM) |

#### Malware Analysis (3 collections)
| Collection | Key Operations |
|-----------|---------------|
| Sample Uploads | Upload malware samples to Falcon Sandbox |
| Sandbox | Submit samples for analysis, get analysis reports |
| Quick Scan | Rapid AV scan using cloud hash lookup |

#### Digital Risk Protection (1 collection)
| Collection | Key Operations |
|-----------|---------------|
| Recon | Dark web monitoring, credential exposure detection |

#### Infrastructure / Platform (7+ collections)
| Collection | Key Operations |
|-----------|---------------|
| OAuth2 | Generate/revoke access tokens |
| Event Streams | Establish streaming connection, refresh partition, get available topics |
| Message Center | Platform notices, support case management |
| Custom Storage | Custom data store within Falcon platform |
| Installation Tokens | Generate/revoke sensor installation tokens |
| Sensor Download | Download sensor installers (Windows/Linux/macOS) |
| Flight Control (MSSP) | Manage child CIDs, delegate permissions, aggregate across tenants |

#### Remaining Collections (~50+)
The remaining ~50 collections cover specialized areas including:
- Data protection policies
- FileVantage (FIM) operations
- Falcon for IT operations
- Foundry app management
- Report execution
- Scheduled reports
- Tailored intelligence
- Mobile enrollment
- Deployments & builds
- Certificate-based exclusions
- Machine learning exclusions
- Quarantined files
- Host migration
- And various internal/admin operations

### 3.3 Auth Flow

```
POST https://api.crowdstrike.com/oauth2/token
Content-Type: application/x-www-form-urlencoded

client_id=CLIENT_ID&client_secret=CLIENT_SECRET
```

Scopes are defined at API client creation time in the Falcon console (e.g., `detections:read`, `hosts:read:write`, `real-time-response:read:write:admin`). Cannot be changed per-request.

---

## 4. ASPM Capabilities Deep Dive

CrowdStrike's ASPM module (**Falcon ASPM**) was acquired via the **Bionic acquisition** (completed 2023, ~$350M) and is now integrated into Falcon Cloud Security.

### 4.1 Core ASPM Capabilities

| Capability | Details |
|-----------|---------|
| **Application Mapping** | Agentless discovery and mapping of all running applications, microservices, databases, and APIs. Graph-based topology showing service dependencies, data flows, and infrastructure connections. |
| **API Discovery** | Automatic discovery of all APIs (REST, gRPC, GraphQL). Identifies undocumented/shadow APIs. Maps API-to-service relationships. |
| **SBOM Generation** | Software Bill of Materials for every discovered application. Component-level vulnerability tracking. Supply chain risk identification. |
| **Runtime Behavior Analysis** | Monitors how applications actually execute (not just static analysis). Uncovers exploitable paths during runtime. Goes beyond static code scanning. |
| **Risk Prioritization** | Correlates runtime behavior + cloud exposure + asset criticality. Reduces up to **95% of vulnerability noise**. Prioritizes by business impact, not volume. |
| **Sensitive Data Flow Detection** | Automatically identifies PII, PCI, and PHI data flows in deployed applications. Maps where sensitive data traverses between services. |
| **AI Governance** | Monitors external AI service usage across applications. Detects shadow AI and ungoverned AI integrations. Identifies application-AI weakness combinations that form breach paths. |
| **Cloud-to-Application Context** | Maps application-to-cloud service relationships. Traces connections between apps, infrastructure, and AI models. Correlates cloud misconfigurations with application vulnerabilities. |
| **Language Support** | Java, Python, .NET, Node.js, Go (Golang support added 2025/2026), and other major frameworks. Expanding to cover all enterprise languages. |
| **Graph Technology** | Uses graph-based exploration to visualize relationships between application components, infrastructure assets, and AI models. |

### 4.3 DSPM & AI-SPM (Complementary Modules)

CrowdStrike positions DSPM and AI-SPM as integral parts of the CNAPP alongside ASPM:

| Module | Capabilities |
|--------|-------------|
| **DSPM (Data Security Posture Management)** | Powered by Flow Security (acquired). Scans AWS S3 buckets for PHI, PII, PCI data. Discovers, classifies, and protects data at rest and in motion across cloud and endpoints. |
| **AI-SPM (AI Security Posture Management)** | Monitors AI services and LLMs in cloud. Detects shadow AI and misconfigurations. Delivers visibility into AI model security posture. Ensures AI models remain compliant and resilient. |

Together, CrowdStrike Falcon Cloud Security is the only CNAPP claiming to deliver unified protection across cloud infrastructure (CSPM), applications (ASPM), data (DSPM), and AI models (AI-SPM) from a single console.

### 4.2 ASPM vs ALDECI Comparison

| Feature | CrowdStrike ASPM | ALDECI |
|---------|-----------------|--------|
| Application mapping | Agentless graph topology (Bionic tech) | `/api/v1/dependency-mapping` — BFS blast radius |
| API discovery | Automatic, including shadow APIs | `/api/v1/api-discovery` — endpoint discovery + risk scoring |
| API inventory | Via discovery engine | `/api/v1/api-inventory` — 6 API types, undocumented tracking |
| SBOM generation | Per-application via discovery | `/api/v1/sbom-export` — CycloneDX 1.4 + SPDX 2.3 |
| SCA | Via Falcon Cloud Security | `/api/v1/sca` — Log4Shell detection, license risk |
| Runtime analysis | Yes — live execution behavior | No — static/scan-based only |
| Sensitive data flows | Auto-detect PII/PCI/PHI | `/api/v1/data-discovery` — 7 datastore types |
| AI governance | Shadow AI, ungoverned AI | `/api/v1/ai-governance` — model lifecycle, bias/security assessments |
| Risk prioritization | ExPRT.AI + runtime + criticality | CVSS+EPSS+KEV+exposure composite scoring |
| Gartner ASPM recognition | Customers' Choice 2026 | Not yet evaluated |

**Key ALDECI gaps:** Runtime behavior analysis (requires agent/sidecar); Bionic's application topology mapping depth; ExPRT.AI proprietary scoring.

**Key ALDECI advantages:** Open SBOM export (CycloneDX+SPDX standard formats); broader API inventory management; AI governance with model lifecycle tracking; self-hosted (no data leaves customer infrastructure).

---

## 5. CTEM Capabilities Deep Dive

CrowdStrike's CTEM offering is branded as **Falcon Exposure Management** and maps to Gartner's 5-stage CTEM framework.

### 5.1 CTEM 5-Stage Coverage

| Stage | CrowdStrike Implementation | ALDECI Equivalent |
|-------|---------------------------|-------------------|
| **1. Scope** | Define assets, identities, SaaS, and external exposure aligned to business impact. Asset Criticality AI auto-classifies. | `/api/v1/asset-criticality` (weighted factors, BFS critical path), `/api/v1/asset-groups` |
| **2. Discover** | Single-agent + agentless cloud + EASM (Falcon Surface) + identity exposure + SaaS posture. Continuous, not periodic scans. | `/api/v1/api-discovery`, `/api/v1/data-discovery`, `/api/v1/cloud-inventory` (7 providers), `/api/v1/assets` |
| **3. Prioritize** | ExPRT.AI predicts exploitability. Exposure Prioritization Agent correlates live telemetry. Asset Criticality AI for business impact. | `/api/v1/vuln-prioritization` (CVSS+EPSS+KEV+exposure), `/api/v1/vuln-scoring` (criticality multipliers) |
| **4. Validate** | Attack path analysis + configuration drift detection + identity risk + network reachability + adversary intelligence correlation. Reduces false positives. | `/api/v1/attack-paths` (BFS lateral movement), `/api/v1/cloud-drift` (IaC baseline), `/api/v1/access-anomaly` |
| **5. Mobilize** | Falcon Fusion SOAR automation + Falcon for IT intelligent patching + closed-loop remediation tracking. | `/api/v1/autonomous-remediation`, `/api/v1/patch-management`, `/api/v1/vuln-remediation` |

### 5.2 CTEM-Specific Features

| Feature | Details |
|---------|---------|
| **Continuous Visibility** | Live monitoring across endpoint, cloud, identity, SaaS, and AI environments. No periodic scan dependency. |
| **ExPRT.AI** | Proprietary ML model predicting exploitability based on CrowdStrike's adversary intelligence + live telemetry + dark web activity. |
| **Exposure Prioritization Agent** | AI agent that correlates live Falcon telemetry to surface exposures attackers are most likely to target next. |
| **Asset Criticality AI** | Automatically classifies asset business impact without manual input. |
| **Attack Path Analysis** | Graph-based analysis showing how an attacker could move from initial access to critical assets. |
| **Configuration Drift Detection** | Continuous monitoring of cloud and endpoint configurations against baselines. |
| **Closed-Loop Remediation** | Falcon Fusion SOAR + Falcon for IT create automated patching/isolation/ticketing workflows with tracking. |
| **HCLTech CTEM Partnership** | AI-powered managed CTEM services (announced March 2026) — CrowdStrike + HCLTech joint offering for enterprise CTEM-as-a-service. Combines CrowdStrike platform with HCLTech professional services for end-to-end managed CTEM. |
| **Exposure Prioritization Agent** | Agentic AI that triages vulnerabilities and identifies exploitable risks. Part of the Charlotte AI AgentWorks ecosystem. Automates Stage 3 (Prioritize) of the CTEM lifecycle. |
| **Performance Claims** | 98% reduction in critical vulnerabilities (Intermex case study). 75% reduction in external attack surface risks with 24/7 internet monitoring. 2,100+ hours saved annually through automation. |

### 5.3 ALDECI CTEM Comparison

**ALDECI strengths vs CrowdStrike CTEM:**
- More granular vulnerability lifecycle (8-state machine with SLA tiers)
- Broader compliance mapping (7 frameworks vs CrowdStrike's CIS-focused approach)
- Risk quantification (FAIR methodology via `/api/v1/risk-quant`)
- Self-hosted — no telemetry leaves customer infrastructure
- 568 routers vs 106 service collections — deeper per-domain coverage

**ALDECI gaps vs CrowdStrike CTEM:**
- No endpoint agent for continuous visibility (scan-based, not real-time)
- No ExPRT.AI equivalent (proprietary ML trained on adversary telemetry)
- No integrated EASM (external attack surface management)
- No Asset Criticality AI (manual tagging in ALDECI)
- No closed-loop SOAR-to-patching pipeline in a single platform

---

## 6. Real-Time Streaming / SSE Capabilities

### 6.1 Event Streams API

| Dimension | Details |
|-----------|---------|
| Protocol | **Server-Sent Events (SSE)** over HTTPS — long-lived HTTP connection |
| Endpoint | `GET /sensors/entities/datafeed/v2` |
| Auth scope | `streaming:read` |
| Partitions | Multiple partitions for high-throughput consumers (horizontal scaling) |
| Offset management | **Yes** — resumable from saved offset. No events lost on reconnect. |
| Refresh required | Partition must be periodically refreshed to maintain connection |
| Event types | DetectionSummaryEvent, IncidentSummaryEvent, AuthActivityAuditEvent, UserActivityAuditEvent, IOAEvent, SensorLifecycleEvent, RemoteResponseSessionStartEvent |
| Non-sensor data only | Event Streams exports SaaS audit activity and detection summaries — not raw sensor telemetry |

### 6.2 Event Payload Example

```json
{
  "metadata": {
    "eventType": "DetectionSummaryEvent",
    "offset": 12345,
    "eventCreationTime": 1713456789000
  },
  "event": {
    "DetectId": "ldt:abc123:456",
    "Severity": 4,
    "SeverityName": "High",
    "FileName": "malware.exe",
    "CommandLine": "powershell -enc ...",
    "Tactic": "Execution",
    "Technique": "T1059.001",
    "ComputerName": "WORKSTATION-01",
    "UserName": "john.doe",
    "DetectDescription": "Process injection detected"
  }
}
```

### 6.3 SIEM Integration Partners

CrowdStrike provides official streaming integrations for:
- **Splunk** — Falcon Event Streams Technical Add-On (Splunkbase)
- **Cortex XSOAR** — CrowdStrike Falcon Streaming v2 integration
- **Panther** — Native CrowdStrike Event Streams log source
- **RunReveal** — Event Stream source connector
- **Stellar Cyber** — Streaming connector for hosts/events
- **Any SIEM** — Generic SSE consumer (standard HTTP client works)

### 6.4 ALDECI Streaming Comparison

| Feature | CrowdStrike | ALDECI |
|---------|-------------|--------|
| Protocol | SSE (Server-Sent Events) | WebSocket |
| Resumable offsets | **Yes** — resume from saved offset | **No** — fire-and-forget |
| Partition support | **Yes** — multi-partition for throughput | **No** — single stream |
| Event types | Detection, incident, audit, auth, IOA, sensor lifecycle | Alert, SOC events, threat intel updates |
| SIEM connectors | Official connectors for Splunk/XSOAR/Panther | No official connectors |
| Volume | All managed endpoint telemetry | Platform-level events only |

**Key gap for ALDECI:** Resumable offsets via Redis Streams (XREAD) would close the SSE gap. SSE is simpler for HTTP clients than WebSocket (no upgrade handshake). Official SIEM connectors are critical for enterprise adoption.

---

## 7. Compliance Frameworks

### 7.1 CrowdStrike Platform Compliance (What CrowdStrike Themselves Are Certified For)

| Framework | Status |
|-----------|--------|
| SOC 2 Type II | Certified |
| ISO 27001 | Certified |
| FedRAMP | Authorized (High) — Falcon modules authorized for government use |
| FISMA | Supported via FedRAMP |
| PCI DSS v4 | Validated by QSA — assists with PCI requirements |
| HIPAA | Independently validated for 8 key technical requirements |
| NIST SP 800-53 | Validated as suitable for system protection controls |
| NIST CSF | Supported |
| CSA CCM | Supported |
| UK Cyber Essentials | Supported |

### 7.2 Compliance Frameworks CrowdStrike Helps Customers Achieve

| Framework | How |
|-----------|-----|
| **CIS Benchmarks** | Via Compliance Assessments API — per-device CIS benchmark results |
| **NIST SP 800-53** | Falcon controls map to NIST requirements |
| **NIST SP 800-171** | DoD contractor compliance via endpoint monitoring |
| **PCI DSS v4** | Endpoint protection, log monitoring, file integrity (FileVantage) |
| **HIPAA** | Endpoint encryption, access logging, incident detection |
| **GDPR** | Data protection (Falcon Data Protection), breach detection/notification |
| **SOC 2** | Endpoint and cloud security controls for SOC 2 audits |
| **ISO 27001** | Security monitoring, incident management, access control |
| **FedRAMP** | Government-authorized modules |
| **MITRE ATT&CK** | Full technique coverage mapping via MITRE ATT&CK API |
| **CIS Controls** | Via CIS benchmark assessment per device |

### 7.3 Compliance Gaps

CrowdStrike does **NOT** provide:
- Automated compliance evidence collection
- Compliance workflow management (approve/reject lifecycle)
- Multi-framework compliance mapping and gap analysis
- Compliance calendar and deadline tracking
- Audit management and scheduling
- GDPR DSR (Data Subject Request) workflow
- Compliance automation (automated control testing with pass-rate)
- Evidence vault with tamper-evident chain of custody

**These are all areas where ALDECI has dedicated engines and routers** — this is one of ALDECI's strongest competitive differentiators.

---

## 8. Pricing Model & Tiers

### 8.1 Bundle Tiers

| Tier | Monthly/Device | Annual/Device | Key Modules Included | Target |
|------|---------------|---------------|---------------------|--------|
| **Falcon Go** | $7.99 | $59.99 | NGAV (Prevent), Device Control, Mobile, Express Support | SMB, max 100 devices |
| **Falcon Pro** | $14.99 | $99.99 | Go + Firewall Management | Mid-market |
| **Falcon Enterprise** | $19.99 | $184.99 | Pro + EDR (Insight XDR), Threat Intel, Hunting | Enterprise |
| **Falcon Elite** | Per-quote | Per-quote | Enterprise + Identity Protection | Large enterprise |
| **Falcon Complete MDR** | Per-quote | Per-quote | Fully managed D&R, breach warranty | All sizes |

### 8.2 Add-On Module Pricing

| Module | List Price | Negotiated (5K+ seats) |
|--------|-----------|----------------------|
| **Falcon Identity Protection** | $15-30/user/year | $12-20/user/year |
| **Falcon OverWatch** | $25-40/endpoint/year | $18-28/endpoint/year |
| **Falcon LogScale (SIEM)** | $2-6/GB/day | $1.50-2.50/GB/day (500+ GB commitment) |
| **Falcon Cloud Security** | Per-workload + per-account | Custom |
| **Falcon Spotlight** | Bundled in Enterprise+ | Standalone add-on for Pro |
| **Falcon Data Protection** | Per-endpoint add-on | Custom |
| **Falcon ASPM** | Per-application add-on | Custom |
| **Falcon Exposure Management** | Per-asset add-on | Custom |
| **Falcon for XIoT** | Per-device add-on | Custom |

### 8.3 Falcon Flex (Credit-Based)

- **Model:** Annual credit pool — swap modules on demand
- **Discount:** 20-35% vs individual module purchases
- **Risk:** Over-committed credits are use-it-or-lose-it
- **Target:** Large enterprises wanting full platform access

### 8.4 Enterprise Negotiated Pricing Benchmarks

| Scenario | Price Range |
|----------|------------|
| Falcon Enterprise, 2K-5K endpoints, 2-year | $120-145/endpoint/year |
| Falcon Enterprise, 5K-10K endpoints, 3-year | $95-125/endpoint/year |
| Full Falcon Flex platform, 5K+ endpoints | 20-35% off list |
| Multi-year commitment | Additional 15-25% discount |
| CrowdStrike Q4 (Nov-Jan, fiscal year end Jan 31) | Peak discount window |

### 8.5 Total Cost of Ownership — CrowdStrike vs ALDECI

| Scenario | CrowdStrike Annual Cost | ALDECI Annual Cost | Savings |
|----------|------------------------|-------------------|---------|
| 500 endpoints, Enterprise tier | $60,000 - $92,500 | $420 - $720 | **99%** |
| 2,000 endpoints + Identity + SIEM | $350,000 - $500,000+ | $420 - $720 | **99%+** |
| 5,000 endpoints, Falcon Flex | $500,000 - $800,000+ | $420 - $720 | **99%+** |

*Note: ALDECI is self-hosted ($35-60/month infrastructure), so cost scales with infrastructure, not seats. CrowdStrike is per-endpoint, so cost scales linearly with device count. SentinelOne is typically priced 35-50% below CrowdStrike.*

---

## 9. Top 5 Enterprise Differentiators

### Differentiator 1: Single Agent, Full Telemetry

CrowdStrike's single lightweight kernel-level sensor (~25MB) collects endpoint telemetry for NGAV, EDR, XDR, vulnerability scanning, identity protection, data protection, and file integrity — all from one agent. No other vendor achieves this breadth from a single sensor.

**Why it matters:** Enterprises deploying 5+ security agents per endpoint face performance impact, management overhead, and telemetry gaps. CrowdStrike eliminates this.

**ALDECI counter:** ALDECI is agentless — positions as the aggregation/analytics layer above deployed agents. Does not compete on endpoint telemetry depth.

### Differentiator 2: Threat Graph + 245+ Named Adversary Profiles

CrowdStrike's Threat Graph processes trillions of events per week and the Adversary Intelligence team maintains 245+ named threat actor profiles with TTPs, infrastructure maps, and campaign tracking. Named adversary groups (BEAR = Russia, PANDA = China, KITTEN = Iran, SPIDER = eCrime) are an industry standard reference.

**Why it matters:** SOC analysts can attribute attacks to specific nation-state or eCrime groups in real-time. No open-source threat feed provides this depth.

**ALDECI counter:** ALDECI's TrustGraph (332 engines wired) + threat attribution engine provides the structure, but lacks the curated adversary dataset. Mitigable via MISP/TAXII feed integration.

### Differentiator 3: Charlotte AI + AgentWorks

Charlotte AI is embedded in every UI surface — auto-triage (98%+ agreement with human experts, saves 40+ analyst hours/week), natural language investigation queries, auto-generated dashboards, investigation co-pilot. AgentWorks is the first no-code platform for building custom security AI agents.

**Why it matters:** Reduces SOC analyst fatigue and accelerates MTTD/MTTR. The "review and approve" queue model (vs "decide from scratch") is a paradigm shift.

**ALDECI counter:** ALDECI has AI-powered SOC engine, AI security advisor, and Karpathy LLM Consensus (4 models). Charlotte AI has more UI integration depth, but ALDECI's multi-model approach avoids single-vendor AI lock-in.

### Differentiator 4: ExPRT.AI Vulnerability Prioritization

ExPRT.AI combines CVSS, EPSS, KEV, CrowdStrike adversary intelligence, live endpoint telemetry, and dark web activity to predict which vulnerabilities will actually be exploited. Claims to reduce vulnerability noise by 95%.

**Why it matters:** Security teams are drowning in CVEs. Reducing 100,000 vulns to 5,000 actionable ones is transformative.

**ALDECI counter:** ALDECI's composite scoring (CVSS+EPSS+KEV+exposure+criticality multipliers) covers the open data sources but lacks CrowdStrike's proprietary adversary telemetry signal.

### Differentiator 5: Falcon Complete MDR with Breach Warranty

Falcon Complete is fully managed detection and response — CrowdStrike's SOC team handles investigation and response 24/7. Includes a **Breach Prevention Warranty** (financial coverage if a breach occurs while under Falcon Complete management).

**Why it matters:** For enterprises without mature SOC teams, this is a turnkey solution with financial backing. The breach warranty is unique in the industry.

**ALDECI counter:** ALDECI does not offer managed services or warranty. Positioned as self-hosted platform for teams that want to own their security stack. Different buyer persona.

---

## 10. Known Weaknesses

### 10.1 Critical: July 2024 Global Outage

On July 19, 2024, a faulty Falcon Sensor kernel driver update caused **8.5 million Windows systems to crash globally**. The root cause was a mismatch between the sensor expecting 20 input fields and the update providing 21, causing an out-of-bounds memory read at the kernel level. Estimated **$5.4 billion in financial losses** across the top 500 US companies.

**Impact on trust:**
- Exposed the inherent risk of kernel-level security agents
- Multiple enterprises now require **content update deployment governance** in contracts
- Competitors (SentinelOne, Microsoft) leveraged this aggressively in competitive positioning
- CrowdStrike stock (CRWD) dropped ~30% in the weeks following

**ALDECI advantage:** ALDECI's agentless, self-hosted architecture has zero kernel-level risk. A misconfiguration in ALDECI cannot crash customer endpoints.

### 10.2 Pricing — Expensive at Scale

- **$100-200+/endpoint/year** at list price; even negotiated rates of $95-145/endpoint/year are expensive for mid-market
- SentinelOne is consistently **35-50% cheaper** at comparable capability
- Add-on module creep: Identity ($15-30/user), OverWatch ($25-40/endpoint), LogScale ($2-6/GB/day) can double the per-endpoint cost
- Falcon Flex credits are use-it-or-lose-it
- Total cost for 5,000 endpoints can easily exceed **$500K-1M+/year**

### 10.3 SaaS-Only — No On-Premise Option

- All telemetry flows to CrowdStrike's cloud (US/EU data centers)
- No self-hosted or air-gapped deployment option
- Problematic for: defense/intelligence agencies, sovereign data requirements, GDPR strict interpretation, regulated industries with data residency mandates
- GovCloud (FedRAMP) partially mitigates but adds cost

### 10.4 Limited Compliance/GRC

- Compliance API covers **CIS benchmarks only** (per-device)
- No compliance automation, evidence collection, audit management, or GRC workflow
- Customers must use third-party GRC tools (Drata, Vanta, Tugboat Logic) alongside CrowdStrike
- No GDPR DSR workflow, no compliance calendar, no multi-framework mapping

### 10.5 Detection Delays in MITRE ATT&CK Evaluations

- Consistently shows detection delays in MITRE ATT&CK evaluations
- Fails to provide real-time visibility on certain attack steps
- These delays increase risk of lateral movement and data exfiltration before response
- Competitors (SentinelOne, Microsoft Defender) have matched or exceeded CrowdStrike in recent MITRE results

### 10.6 Dashboard/Reporting Limitations

- Dashboard and reporting functionalities require significant improvements (per Gartner/PeerSpot reviews)
- Limited customizable reporting — users rely on third-party tools (Splunk) for enhanced reporting
- Public dashboard lacks PDF export for reports
- Cloud-based UI can experience lag/slowness
- Visualization and correlation features need enhancement

### 10.7 DLP and Data Protection Gaps

- Falcon Data Protection is a relatively new module (not mature)
- Native DLP capabilities are limited compared to dedicated DLP vendors
- No data governance, data classification lifecycle, or data retention policy management

### 10.8 OT/IoT Limitations

- Falcon for XIoT is agent-based — many OT vendors have not certified the Falcon agent on their endpoints
- Slow progress in OT/ICS environments where agents cannot be deployed
- Medical device coverage requires vendor certification

### 10.9 Support Quality Degradation

- As CrowdStrike has scaled, support has become less personalized (per Capterra/PeerSpot reviews)
- Technical support relies on online articles rather than direct assistance
- Case resolution sometimes requires escalation
- Integration support is particularly weak

### 10.10 Complex Uninstallation

- Uninstalling the Falcon sensor requires API console token retrieval
- Problematic when hosts are disconnected
- Sensor upgrades on servers are time-consuming
- Kernel-level removal risks system instability

### 10.11 False Positive Rate

- AI/ML behavioral detection generates false positives requiring manual review
- Machine learning models require ongoing tuning per environment
- "Noisy" for environments with custom or proprietary applications

---

## 11. ALDECI vs CrowdStrike — Strategic Assessment

### 11.1 Where ALDECI Wins

| Domain | ALDECI Advantage |
|--------|-----------------|
| **Price** | $35-60/month vs $100K-1M+/year. 99%+ cost reduction for mid-market. |
| **Data Sovereignty** | Fully self-hosted. All data stays in customer infrastructure. Zero third-party telemetry exposure. |
| **Compliance/GRC** | 7 frameworks, automated evidence collection, compliance workflows, audit management, GDPR DSR, compliance calendar. CrowdStrike has CIS benchmarks only. |
| **API Surface** | 568 routers / 2,800+ operations vs 106 collections / 1,364 operations. 2x the API surface. |
| **Engine Depth** | 334 specialized engines vs ~30 modules. 10x the domain-specific coverage (quantum crypto, digital twin, security OKRs, tabletop exercises, etc.). |
| **No Kernel Risk** | Agentless — cannot crash customer endpoints. The July 2024 outage cannot happen with ALDECI. |
| **Multi-Model AI** | Karpathy LLM Consensus (4 models) vs Charlotte AI (single proprietary model). No AI vendor lock-in. |
| **Deployment Flexibility** | Docker, Kubernetes, bare metal, air-gapped. CrowdStrike is SaaS-only. |

### 11.2 Where CrowdStrike Wins

| Domain | CrowdStrike Advantage |
|--------|----------------------|
| **Endpoint Telemetry** | Single agent provides real-time process/network/file/registry telemetry. ALDECI has no endpoint agent. |
| **Real-Time Response** | Live bi-directional command channel to endpoints (RTR). Memory forensics, file I/O, script execution. |
| **Threat Intelligence** | 245+ named adversary profiles. Curated by elite threat intel team. Industry-standard naming convention. |
| **ExPRT.AI** | Proprietary ML trained on live adversary telemetry. No open-source equivalent. |
| **Charlotte AI** | Deeply integrated agentic AI across every UI surface. 98%+ triage accuracy. |
| **Managed Services** | Falcon Complete MDR with breach prevention warranty. Turnkey for enterprises without SOC teams. |
| **Market Position** | Gartner MQ Leader 6x consecutive. 8.5M+ managed endpoints. Enterprise trust/brand. |
| **Streaming** | SSE with resumable offsets and partitions. ALDECI WebSocket is fire-and-forget. |
| **SIEM** | Falcon LogScale (Humio) is a petabyte-scale SIEM. ALDECI has no equivalent log management engine. |

### 11.3 Strategic Positioning Recommendation

**ALDECI should NOT compete head-to-head with CrowdStrike on endpoint detection.**

Instead, position ALDECI as:

1. **The GRC/Compliance platform** that CrowdStrike cannot match (7 frameworks, automated evidence, audit management)
2. **The cost-effective ASPM+CSPM+CTEM layer** for mid-market ($35-60/month vs $100K+/year)
3. **The data sovereignty option** for regulated industries (defense, healthcare, finance, EU/GDPR)
4. **The aggregation layer above CrowdStrike** — ingest CrowdStrike telemetry via connector and add GRC, risk quantification, and multi-vendor correlation
5. **The self-hosted alternative** for organizations that cannot send telemetry to third-party SaaS

**Build a CrowdStrike connector** (via FalconPy SDK / Event Streams API) to position ALDECI as complementary rather than competitive. Turn CrowdStrike's endpoint moat into ALDECI's data source.

### 11.4 Threat Assessment: Spring 2026 Moves

CrowdStrike's Spring '26 release and RSAC 2026 announcements reveal three strategic moves that affect ALDECI's competitive position:

**1. Agentic AI Dominance Play**
Charlotte AI AgentWorks (12 named agents, no-code builder, multi-model support via Anthropic/OpenAI/NVIDIA) is the most aggressive AI investment in cybersecurity. The >98% triage accuracy and 70% manual reduction claims, if sustained, make it hard for smaller platforms to compete on SOC productivity. ALDECI's multi-model consensus approach is architecturally different (4 models vote, not single-agent workflow), which is a genuine differentiator for buyers wary of AI hallucination risk.

**2. Data Security Expansion (Falcon Data Security + DSPM + AI-SPM)**
CrowdStrike is closing the DLP/data protection gap that was a known weakness. Falcon Data Security now covers endpoints, SaaS, cloud, browsers, and AI workflows. ALDECI's DLP, data classification, data governance, and data discovery engines remain more granular (7 datastore types, retention policies, GDPR DSR), but the gap is narrowing.

**3. SIEM as Multi-Vendor Aggregation Layer**
By ingesting Microsoft Defender for Endpoint telemetry natively (no additional sensors), CrowdStrike is positioning Falcon Next-Gen SIEM as the aggregation layer for multi-vendor environments. This is the same strategic position ALDECI targets — being the intelligence layer above deployed tools. The Onum acquisition (5X faster streaming, 50% lower storage) strengthens this further.

**ALDECI Response Priorities:**
1. **Accelerate CrowdStrike connector** — ingest Falcon Event Streams + Detections API into ALDECI's TrustGraph. Position as "CrowdStrike + compliance + risk quantification."
2. **Emphasize compliance moat** — CrowdStrike has no compliance automation, evidence collection, audit management, or GRC workflow. This remains ALDECI's strongest differentiator against CrowdStrike specifically.
3. **Counter agentic AI narrative** — Position ALDECI's multi-model consensus as "AI safety for security decisions" vs CrowdStrike's single-vendor agent model. Emphasize auditability and explainability.
4. **Target CrowdStrike cost refugees** — At $5B ARR, CrowdStrike is raising prices. Organizations spending $200K+/year on Falcon modules are the ideal ALDECI prospect for the self-hosted cost reduction story.
5. **Differentiate on data sovereignty** — CrowdStrike's AI security features (Shadow AI discovery, AIDR) all require cloud telemetry. ALDECI's self-hosted architecture means zero telemetry exposure, critical for regulated industries.

---

## 12. Sources

### Official CrowdStrike
- [CrowdStrike Falcon Platform](https://www.crowdstrike.com/en-us/platform/)
- [CrowdStrike Pricing Page](https://www.crowdstrike.com/en-us/pricing/)
- [Falcon Trial Modules](https://www.crowdstrike.com/en-us/free-trial-guide/falcon-trial-modules/)
- [Falcon ASPM](https://www.crowdstrike.com/en-us/platform/cloud-security/aspm/)
- [Falcon CSPM](https://www.crowdstrike.com/en-us/platform/cloud-security/cspm/)
- [Falcon CTEM / Exposure Management](https://www.crowdstrike.com/en-us/platform/exposure-management/continuous-threat-exposure-management-ctem/)
- [Quarterly Platform Release Highlights](https://www.crowdstrike.com/en-us/platform/quarterly-falcon-platform-release-highlights/)
- [CrowdStrike Developer Center](https://developer.crowdstrike.com/)
- [CrowdStrike Compliance Certifications](https://www.crowdstrike.com/en-us/why-crowdstrike/crowdstrike-compliance-certification/)
- [Falcon and NIST Compliance](https://www.crowdstrike.com/en-us/resources/reports/crowdstrike-falcon-nist-compliance/)
- [Falcon and PCI DSS Compliance](https://www.crowdstrike.com/en-us/resources/reports/crowdstrike-falcon-and-pci-dss-compliance/)
- [Falcon Next-Gen SIEM Compliance](https://www.crowdstrike.com/en-us/platform/next-gen-siem/compliance/)
- [Charlotte AI Detection Triage](https://www.crowdstrike.com/en-us/blog/agentic-ai-innovation-in-cybersecurity-charlotte-ai-detection-triage/)
- [Falcon Platform Agentic Security Era](https://www.crowdstrike.com/en-us/blog/crowdstrike-falcon-platform-evolves-to-lead-agentic-security-era/)
- [Falcon Update for Windows Hosts Technical Details (July 2024)](https://www.crowdstrike.com/en-us/blog/falcon-update-for-windows-hosts-technical-details/)

### FalconPy SDK / API Documentation
- [FalconPy — The CrowdStrike Falcon SDK for Python](https://www.falconpy.io/)
- [FalconPy Operations Overview (1,364 operations)](https://www.falconpy.io/Operations/Operations-Overview.html)
- [FalconPy All Operations](https://www.falconpy.io/Operations/All-Operations.html)
- [FalconPy Event Streams](https://falconpy.io/Service-Collections/Event-Streams.html)
- [GitHub CrowdStrike/falconpy](https://github.com/CrowdStrike/falconpy)

### Pricing & Licensing
- [CrowdStrike Falcon Licensing Guide 2026 — Redress Compliance](https://redresscompliance.com/crowdstrike-falcon-licensing-guide.html)
- [Complete Guide to CrowdStrike Falcon Pricing 2026 — CyCognito](https://www.cycognito.com/learn/attack-surface/crowdstrike-falcon-pricing/)

### Reviews & Weaknesses
- [CrowdStrike Falcon Pros and Cons 2026 — PeerSpot](https://www.peerspot.com/products/crowdstrike-falcon-pros-and-cons)
- [CrowdStrike Reviews — Capterra](https://www.capterra.com/p/147662/CrowdStrike-Falcon/reviews/)
- [CrowdStrike Falcon Components, Pros/Cons — Exabeam](https://www.exabeam.com/explainers/crowdstrike/crowdstrike-falcon-components-pros-cons-and-top-5-alternatives/)
- [CrowdStrike Falcon Review 2026 — Work Management](https://work-management.org/antivirus/crowdstrike-review/)

### CTEM & Market
- [CrowdStrike + HCLTech CTEM Partnership (March 2026)](https://www.businesswire.com/news/home/20260330641539/en/CrowdStrike-and-HCLTech-Expand-Strategic-Partnership-with-AI-Powered-Continuous-Threat-Exposure-Management-Services)
- [CrowdStrike Named Gartner Customers' Choice for ASPM 2026](https://www.businesswire.com/news/home/20260202380434/en/CrowdStrike-Named-a-Customers-Choice-in-the-2026-Gartner-Peer-Insights-Voice-of-the-Customer-for-Application-Security-Posture-Management-ASPM-Tools-Report)

### July 2024 Outage
- [2024 CrowdStrike-Related IT Outages — Wikipedia](https://en.wikipedia.org/wiki/2024_CrowdStrike-related_IT_outages)
- [CrowdStrike Outage Explained — HBR](https://hbr.org/2025/01/what-the-2024-crowdstrike-glitch-can-teach-us-about-cyber-risk)
- [CrowdStrike Outage Lasting Impact — Tufin](https://www.tufin.com/blog/lasting-impact-of-crowdstrike-update-outage)
- [Channel File 291 RCA — CrowdStrike](https://www.crowdstrike.com/en-us/blog/channel-file-291-rca-available/)

### Streaming Integrations
- [CrowdStrike Falcon Streaming v2 — Cortex XSOAR](https://xsoar.pan.dev/docs/reference/integrations/crowd-strike-falcon-streaming-v2)
- [CrowdStrike Falcon Event Streams Add-on — Splunkbase](https://splunkbase.splunk.com/app/5082)

### Spring '26 Release & RSAC 2026
- [Introducing the Falcon Platform Spring '26 Release — CrowdCast](https://www.crowdstrike.com/en-us/resources/crowdcasts/introducing-the-falcon-platform-spring-2026-release/)
- [CrowdStrike Targets AI Security Gap at RSAC 2026 — SiliconANGLE](https://siliconangle.com/2026/03/23/crowdstrike-targets-ai-security-gap-falcon-platform-expansion-rsac-conference/)
- [CrowdStrike Expands Falcon with Threat-Informed Cloud Risk — SiliconANGLE](https://siliconangle.com/2026/03/24/crowdstrike-expands-falcon-platform-threat-informed-cloud-risk-data-security-tools/)
- [CrowdStrike Introduces Falcon Data Security](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-introduces-falcon-data-security-to-stop-data-theft-across-the-agentic-enterprise/)
- [Charlotte AI AgentWorks Launch](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-launches-charlotte-ai-agentworks-ecosystem-for-building-secure-agents/)
- [Charlotte AI AgentWorks — Agentic Ecosystem Blog](https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/)
- [Charlotte Agentic SOAR Orchestration](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-unveils-charlotte-agentic-soar/)
- [Charlotte AI Agentic Security Workforce](https://www.crowdstrike.com/en-us/platform/charlotte-ai/agentic-security-workforce/)
- [CrowdStrike Falcon Onum](https://www.crowdstrike.com/en-us/platform/next-gen-siem/falcon-onum/)
- [CrowdStrike to Acquire Onum](https://www.crowdstrike.com/en-us/blog/crowdstrike-to-acquire-onum/)
- [Falcon Next-Gen SIEM for Microsoft Defender](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-unveils-falcon-next-gen-siem-support-for-microsoft-defender-for-endpoint/)
- [CrowdStrike + Intel AI PC Partnership](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-intel-partner-secure-ai-pcs-falcon-platform/)
- [Agentic SOC Telemetry Gap at RSAC 2026 — VentureBeat](https://venturebeat.com/security/rsac-2026-agentic-soc-agent-telemetry-security-gap)

### Financial Performance
- [CrowdStrike Q4 FY2026 Earnings](https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-reports-fourth-quarter-and-fiscal-year-2026/)
- [CrowdStrike Q3 FY2026 Results](https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-reports-third-quarter-fiscal-year-2026-financial)
- [CrowdStrike Q2 FY2026 — Record ARR](https://www.investing.com/news/company-news/crowdstrike-q2-fy2026-slides-record-arr-and-platform-growth-fuel-21-revenue-increase-93CH-4213362)
- [CrowdStrike Q4 FY2026 Revenue Hits $1.31B](https://bayelsawatch.com/crowdstrike-q4-fiscal-year-2026-earnings/)

### Cloud Security — DSPM & AI-SPM
- [CrowdStrike Unveils AI-SPM and DSPM](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-unveils-falcon-cloud-security-innovations/)
- [Falcon AI-SPM Product Page](https://www.crowdstrike.com/en-us/platform/cloud-security/ai-spm/)
- [Fal.Con 2024 Cloud Security Innovations Blog](https://www.crowdstrike.com/en-us/blog/cloud-security-unified-cnapp-innovations-fal-con-2024/)

### Differentiators & Competitor Analysis
- [CrowdStrike Compare Page](https://www.crowdstrike.com/en-us/compare/)
- [CrowdStrike Pros, Cons, Features — Teramind](https://www.teramind.co/blog/crowdstrike-pros-and-cons/)
- [CrowdStrike Competitive Landscape — MatrixBCG](https://matrixbcg.com/blogs/competitors/crowdstrike)
