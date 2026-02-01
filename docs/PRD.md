# FixOps Product Requirements Document (PRD)

**Version:** 1.0  
**Date:** January 2026  
**Document Status:** Active  
**Product:** FixOps - Enterprise DevSecOps Decision, Verification & Vulnerability Operations Platform

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Product Vision & Strategy](#2-product-vision--strategy)
3. [Problem Statement & Market Analysis](#3-problem-statement--market-analysis)
4. [Product Overview](#4-product-overview)
5. [User Personas & Target Audience](#5-user-personas--target-audience)
6. [Core Capabilities & Features](#6-core-capabilities--features)
7. [Technical Architecture](#7-technical-architecture)
8. [Functional Requirements](#8-functional-requirements)
9. [Non-Functional Requirements](#9-non-functional-requirements)
10. [User Experience & Interface](#10-user-experience--interface)
11. [Integration & Extensibility](#11-integration--extensibility)
12. [Security & Compliance](#12-security--compliance)
13. [Success Metrics & KPIs](#13-success-metrics--kpis)
14. [Product Roadmap](#14-product-roadmap)
15. [Dependencies & Constraints](#15-dependencies--constraints)
16. [Risk Assessment & Mitigation](#16-risk-assessment--mitigation)
17. [Go-to-Market Strategy](#17-go-to-market-strategy)
18. [Support & Documentation](#18-support--documentation)
19. [Glossary](#19-glossary)

---

## 1. Executive Summary

### 1.1 Product Overview

FixOps is an enterprise-grade DevSecOps platform that transforms vulnerability management from reactive noise into proactive intelligence. By ingesting security artifacts (SBOM, SARIF, CVE, VEX, CNAPP) and business context, FixOps delivers automated, auditable release decisions with cryptographic evidence and provenance.

### 1.2 Key Value Propositions

- **Noise Reduction:** Multi-LLM consensus reduces actionable findings by 100:1 ratio
- **Automated Decisions:** Tri-state verdicts (Allow/Block/Needs Review) replace manual triage
- **Audit Readiness:** Cryptographically signed evidence bundles with 7-year retention
- **Exploit Verification:** Micro-pentest engine validates real exploitability vs. theoretical risk
- **Universal Integration:** Push-model ingestion works with any scanner (no proprietary connectors)
- **Deployment Flexibility:** SaaS, on-premises, or air-gapped deployment options

### 1.3 Target Market

- **Primary:** Enterprise organizations (500+ employees) with mature DevSecOps practices
- **Secondary:** Mid-market companies (100-500 employees) scaling security operations
- **Verticals:** Financial services, healthcare, government, critical infrastructure

### 1.4 Business Impact

- **60% reduction** in security team time spent on manual triage
- **100:1 signal-to-noise ratio** improvement through AI-driven correlation
- **30-minute onboarding** vs. weeks for traditional ASPM platforms
- **Zero vendor lock-in** with full data export capabilities

---

## 2. Product Vision & Strategy

### 2.1 Vision Statement

*"To make vulnerability management intelligent, automated, and auditable - empowering organizations to ship secure software at velocity without sacrificing compliance or safety."*

### 2.2 Mission Statement

FixOps operationalizes the complete Continuous Threat Exposure Management (CTEM) cycle:
1. **Discover/Ingest** - Universal security artifact ingestion
2. **Prioritize** - AI-driven risk scoring with business context
3. **Validate** - Exploit verification through automated pentesting
4. **Remediate** - Lifecycle tracking with SLA enforcement
5. **Measure** - Cryptographic evidence and compliance reporting

### 2.3 Strategic Positioning

FixOps is **not a scanner** - it's the decision and evidence layer that sits between your existing security tools and your development/compliance teams. We replace manual triage with automated intelligence while maintaining human oversight through configurable thresholds and transparent scoring.

### 2.4 Competitive Differentiation

| Capability | FixOps | Traditional ASPM | RBVM Platforms |
|------------|--------|------------------|----------------|
| **Decision Transparency** | Full explainability with step-by-step reasoning | Black-box risk scores | Opaque algorithms |
| **Evidence Storage** | SLSA v1 + 7-year retention + crypto signatures | Logs only | Basic reports |
| **Air-Gapped Support** | Full offline functionality | SaaS only | Limited/none |
| **Onboarding Time** | ~30 minutes | Weeks | Days to weeks |
| **Exploit Validation** | Multi-AI micro-pentest engine | None | Limited |
| **Vendor Lock-in** | Full export, open standards | Data trap | Platform lock |

### 2.5 Product Principles

1. **Transparency Over Obscurity:** Every decision must be explainable with visible reasoning
2. **Evidence Over Assumptions:** Cryptographic proof trumps opaque risk scores
3. **Automation Over Manual Labor:** Default to automated decisions with configurable human gates
4. **Flexibility Over Rigidity:** Support multiple deployment models and risk philosophies
5. **Standards Over Proprietary:** Open formats (SBOM, SARIF, VEX) over vendor lock-in

---

## 3. Problem Statement & Market Analysis

### 3.1 Core Problems

#### Problem 1: Overwhelming Vulnerability Noise
**Current State:**
- Security teams face 60% false positive rates from scanner sprawl
- Average enterprise deals with 10,000+ findings across multiple tools
- Manual triage consumes 40-60% of security engineer time
- No correlation between overlapping findings from different scanners

**Business Impact:**
- Alert fatigue leads to missed critical vulnerabilities
- Slow triage delays releases and frustrates development teams
- High operational costs for manual security review

#### Problem 2: Lack of Decision Automation
**Current State:**
- Every vulnerability requires manual security architect review
- 1 security architect supporting 159 developers is unsustainable
- No automated release-gate decisions with audit trails
- Risk scoring doesn't translate to "ship/don't ship" decisions

**Business Impact:**
- Release bottlenecks and missed market windows
- Inconsistent decision-making across teams
- Inability to scale security with development velocity

#### Problem 3: Missing Audit Evidence
**Current State:**
- Manual evidence collection for compliance audits takes weeks
- No cryptographic proof of security decisions
- Evidence scattered across multiple tools and spreadsheets
- Long-term retention policies difficult to enforce

**Business Impact:**
- Failed audits and compliance violations
- Increased audit costs and timeline
- Inability to prove due diligence in breach scenarios

#### Problem 4: CVSS-Only Prioritization
**Current State:**
- Organizations prioritize solely on CVSS 9.0+ scores
- No consideration of exploit probability (EPSS), reachability, or controls
- Same CVE treated identically across all contexts
- Theoretical risk scored higher than actual exposure

**Business Impact:**
- False urgency on unexploitable vulnerabilities
- Critical exploitable issues buried in noise
- Wasted remediation effort on low-risk items

#### Problem 5: No Exploit Validation
**Current State:**
- Teams rely on theoretical exploitability assessments
- No automated verification of actual exploit success
- Reachability analysis done manually or not at all
- Vulnerability scanners can't prove exploitability

**Business Impact:**
- Over-investment in non-exploitable vulnerabilities
- Under-investment in actual attack paths
- Inability to justify deprioritization to auditors

### 3.2 Market Size & Opportunity

#### Total Addressable Market (TAM)
- **Application Security Market:** $8.5B (2024) → $13.2B (2028) at 11.6% CAGR
- **Vulnerability Management:** $3.2B subset
- **DevSecOps Tools:** $5.8B and growing

#### Serviceable Addressable Market (SAM)
- **Enterprise + Mid-Market:** Organizations with 100+ developers
- **Geography:** North America, EMEA, APAC
- **Estimated SAM:** $1.8B

#### Serviceable Obtainable Market (SOM)
- **Year 1 Target:** Early adopters in financial services and healthcare
- **Estimated SOM:** $45M (2.5% of SAM)

### 3.3 Competitive Landscape

#### Direct Competitors

**Risk-Based Vulnerability Management (RBVM):**
- **Nucleus Security:** Aggregates scanner outputs, risk scoring, workflow automation
  - *Weakness:* Opaque scoring, SaaS-only, weeks-long onboarding
- **Vulcan Cyber:** Vulnerability orchestration, remediation workflows
  - *Weakness:* Agent-based architecture, limited air-gap support

**Application Security Posture Management (ASPM):**
- **Apiiro:** Application risk mapping, code-to-cloud security
  - *Weakness:* Pull-based integrations, SaaS-only deployment
- **ArmorCode:** Security findings aggregation, workflow management
  - *Weakness:* Basic triage, no exploit validation
- **Cycode:** Complete ASPM platform with SDLC integration
  - *Weakness:* Platform lock-in, limited evidence automation

#### Indirect Competitors

**Security Scanning Platforms:**
- Snyk, Checkmarx, Veracode, SonarQube, GitHub Advanced Security
- *Positioning:* FixOps ingests their outputs rather than replacing them

**SIEM/SOAR Platforms:**
- Splunk, Palo Alto Cortex XSOAR, IBM QRadar
- *Positioning:* FixOps focuses on pre-production/SDLC vs. runtime/SOC

### 3.4 Market Trends

1. **Shift-Left Security:** Organizations moving security earlier in SDLC
2. **DevSecOps Maturity:** 67% of enterprises have dedicated DevSecOps teams (Gartner)
3. **Compliance Pressure:** EU Cyber Resilience Act, EO 14028, ISO 27001:2022 A.8.25
4. **AI/ML Adoption:** 78% of security teams exploring AI for vulnerability triage
5. **Supply Chain Focus:** SBOM requirements driving transparency needs

### 3.5 Regulatory Drivers

| Regulation | Requirement | FixOps Capability |
|------------|-------------|-------------------|
| **EU Cyber Resilience Act** | Supply chain transparency, SBOM attestations | SLSA v1 provenance, signed evidence |
| **EO 14028 (US)** | Secure software attestation | Self-attestation with cryptographic proof |
| **ISO 27001:2022 A.8.25** | Secure development lifecycle | Evidence of secure coding, design, testing |
| **SOC2 / PCI-DSS** | Continuous compliance monitoring | Auto-generated audit artifacts |
| **GDPR** | Data protection by design | Privacy-aware risk scoring |

---

## 4. Product Overview

### 4.1 Product Description

FixOps is a comprehensive DevSecOps platform comprising three main interfaces:

1. **REST API** (313+ endpoints across 32 routers)
   - Programmatic access for CI/CD integration
   - Webhook receivers for external system events
   - Comprehensive CRUD operations for all entities
   - Scanner-agnostic multipart ingestion endpoint

2. **Command-Line Interface** (112+ commands/subcommands)
   - Pipeline orchestration and stage execution
   - Integration management and testing
   - Evidence bundle operations
   - Pentesting automation

3. **Web UI** (16 frontend pages)
   - Interactive Risk Graph visualization
   - Remediation workflow management
   - Analytics dashboards and compliance reports
   - Administrative configuration

### 4.2 Core Technology Stack

**Backend:**
- **Framework:** FastAPI (Python 3.10+)
- **Database:** SQLite (demo), PostgreSQL (enterprise)
- **Authentication:** JWT with bcrypt password hashing
- **API Documentation:** OpenAPI/Swagger auto-generated

**Frontend:**
- **Framework:** Modern web stack with Cytoscape.js for graph visualization
- **Styling:** Responsive design with mobile support
- **Charting:** Analytics dashboards with interactive visualizations

**Security:**
- **Cryptography:** RSA-SHA256 signatures, Fernet encryption
- **Standards:** SLSA v1 provenance, in-toto attestations
- **Secrets Management:** Environment-based configuration

**Integrations:**
- **LLM Providers:** GPT-5, Claude-3, Gemini-2, Sentinel-Cyber
- **Ticketing:** Jira, ServiceNow, GitHub Issues, GitLab, Azure DevOps
- **Notifications:** Slack, Confluence
- **Data Sources:** NVD, CISA KEV, EPSS, MITRE ATT&CK

### 4.3 Deployment Models

#### SaaS (Managed Cloud)
- Multi-tenant architecture
- Automated updates and patching
- 99.9% uptime SLA
- Geographic data residency options

#### On-Premises
- Single-tenant deployment
- Customer-managed infrastructure
- Full control over data and updates
- VPC/private network support

#### Air-Gapped
- Complete offline operation
- Bundled vulnerability databases
- USB/offline update mechanisms
- Classified environment support

### 4.4 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         FixOps Platform                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   REST API   │  │     CLI      │  │    Web UI    │          │
│  │ 303 endpoints│  │ 111 commands │  │  16 pages    │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                  │                  │                   │
│         └──────────────────┴──────────────────┘                   │
│                            │                                      │
│  ┌─────────────────────────┴───────────────────────────┐         │
│  │              Core Processing Engine                  │         │
│  ├──────────────────────────────────────────────────────┤         │
│  │ • Ingestion & Normalization (SBOM/SARIF/CVE/VEX)   │         │
│  │ • Risk Graph Construction & Correlation             │         │
│  │ • Multi-LLM Consensus Engine                        │         │
│  │ • Policy Evaluation & Decision Making               │         │
│  │ • Micro-Pentest Orchestration                       │         │
│  │ • Evidence Bundle Generation & Signing              │         │
│  └─────────────────────────┬───────────────────────────┘         │
│                            │                                      │
│  ┌─────────────────────────┴───────────────────────────┐         │
│  │                 Data & Storage Layer                 │         │
│  ├──────────────────────────────────────────────────────┤         │
│  │ • Application Database (SQLite/PostgreSQL)          │         │
│  │ • Evidence Lake (Immutable Storage)                 │         │
│  │ • Analytics Data Store                              │         │
│  │ • Configuration Registry                            │         │
│  └─────────────────────────┬───────────────────────────┘         │
│                            │                                      │
│  ┌─────────────────────────┴───────────────────────────┐         │
│  │              External Integrations                   │         │
│  ├──────────────────────────────────────────────────────┤         │
│  │ • LLM Providers (GPT/Claude/Gemini/Sentinel)        │         │
│  │ • Vulnerability Intelligence (NVD/KEV/EPSS)         │         │
│  │ • Ticketing Systems (Jira/ServiceNow/GitHub)        │         │
│  │ • Notifications (Slack/Confluence)                  │         │
│  │ • PentAGI Micro-Pentest Service                     │         │
│  └──────────────────────────────────────────────────────┘         │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. User Personas & Target Audience

### 5.1 Primary Personas

#### Persona 1: Security Architect (Sarah)
**Demographics:**
- Role: Lead Security Architect
- Experience: 8-12 years in AppSec
- Team: Manages 3-5 security engineers
- Organization: Enterprise (1000+ developers)

**Goals:**
- Automate 80% of vulnerability triage decisions
- Reduce time-to-remediation from weeks to days
- Produce audit-ready evidence without manual collection
- Scale security reviews to match development velocity

**Pain Points:**
- Drowning in 10,000+ scanner findings with 60% false positives
- Manual triage of every security finding is impossible
- No correlation between tools (Snyk + SonarQube + Wiz = chaos)
- Auditors reject deprioritization without cryptographic proof

**How FixOps Helps:**
- Multi-LLM consensus automates 85% of decisions
- Risk Graph correlates findings across all scanners
- Signed evidence bundles satisfy auditor requirements
- Configurable policies support Zero-Exception or Smart Prioritization

#### Persona 2: DevSecOps Engineer (David)
**Demographics:**
- Role: DevSecOps Engineer
- Experience: 5-7 years (Dev → Security)
- Team: Embedded with 3-4 development teams
- Organization: Mid-market to enterprise

**Goals:**
- Integrate security scanning into CI/CD pipelines
- Provide developers with actionable security feedback
- Track remediation progress and SLA compliance
- Minimize false positives to maintain developer trust

**Pain Points:**
- Pipeline integration of multiple scanners is brittle
- Developers ignore security feedback due to noise
- No visibility into what's actually exploitable
- Manual ticket creation and tracking across Jira

**How FixOps Helps:**
- Universal SBOM/SARIF ingestion works with any scanner
- Micro-pentest validation proves exploitability
- Automated Jira ticket creation with smart assignments
- CLI-first design for pipeline integration

#### Persona 3: Compliance Manager (Catherine)
**Demographics:**
- Role: Compliance/GRC Manager
- Experience: 6-10 years in audit/compliance
- Team: Coordinates security, legal, and engineering
- Organization: Regulated industry (finance/healthcare/gov)

**Goals:**
- Pass SOC2/ISO27001/PCI-DSS audits efficiently
- Maintain continuous compliance posture
- Produce evidence of secure SDLC practices
- Demonstrate vulnerability management effectiveness

**Pain Points:**
- Evidence collection takes 2-3 weeks per audit
- No proof that vulnerabilities were properly assessed
- Manual compliance report generation
- Difficult to demonstrate continuous improvement

**How FixOps Helps:**
- Auto-generated audit artifacts with crypto signatures
- 7-year evidence retention with tamper-proof storage
- Compliance framework mapping (ISO/NIST/SOC2/PCI)
- Analytics dashboards show MTTR and coverage metrics

#### Persona 4: Application Security Manager (Alex)
**Demographics:**
- Role: Application Security Manager
- Experience: 10+ years in security operations
- Team: Leads AppSec program (5-15 people)
- Organization: Large enterprise (2000+ developers)

**Goals:**
- Measure security program effectiveness
- Justify security budget with ROI metrics
- Scale security operations without headcount growth
- Reduce mean-time-to-remediation (MTTR)

**Pain Points:**
- No visibility into security program performance
- Manual metrics collection from disparate tools
- Can't prove ROI of security investments
- Security team burnout from alert fatigue

**How FixOps Helps:**
- Comprehensive analytics with MTTR/coverage/trend metrics
- Automated reporting reduces manual effort by 60%
- 100:1 noise reduction improves team morale
- Transparent scoring shows program improvements

### 5.2 Secondary Personas

#### Persona 5: Platform Engineer (Pete)
**Demographics:**
- Role: Platform/Infrastructure Engineer
- Focus: CI/CD, deployment automation
- Organization: Medium to large enterprise

**Needs:**
- Easy integration with existing CI/CD tools
- Reliable API for programmatic access
- Clear documentation and examples
- Minimal operational overhead

#### Persona 6: Developer (Dana)
**Demographics:**
- Role: Software Developer
- Interaction: Receives security findings
- Organization: Any size

**Needs:**
- Clear, actionable security feedback
- Low false positive rate
- Contextual remediation guidance
- Fast feedback loops

### 5.3 Anti-Personas (Not Target Users)

1. **Individual Developers/Small Teams (<10 people):**
   - Too much overhead for small scale
   - Better served by integrated scanner tooling

2. **Organizations Without Existing Scanners:**
   - FixOps complements existing tools, doesn't replace them
   - Need to invest in SAST/DAST/SCA first

3. **Non-Technical Compliance Teams:**
   - Requires understanding of SDLC and DevSecOps
   - Best paired with technical security team

---

## 6. Core Capabilities & Features

### 6.1 Capability Area 1: Ingest & Normalize

#### FR-ING-001: Universal SBOM Ingestion
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Ingest Software Bill of Materials (SBOM) from any standard format and normalize to internal canonical model.

**Supported Formats:**
- CycloneDX (JSON/XML)
- SPDX
- Syft JSON
- GitHub Dependency Snapshot
- CycloneDX ML-BOM (AI/ML transparency)

**Acceptance Criteria:**
- Parse and normalize all supported SBOM formats
- Extract components, dependencies, and vulnerabilities
- Maintain provenance information
- Support SBOM uploads via API, CLI, and webhook
- Handle malformed/invalid SBOM documents gracefully

**API Endpoints:**
- `POST /inputs/sbom` - Upload SBOM document
- `GET /api/v1/sbom/{id}` - Retrieve normalized SBOM

**CLI Commands:**
- `python -m core.cli run --sbom <path>`
- `python -m core.cli stage-run --stage build --input <path>`

#### FR-ING-002: SARIF Ingestion
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Ingest Static Analysis Results Interchange Format (SARIF) findings from any SAST/DAST/linting tool.

**Supported Sources:**
- Snyk, SonarQube, CodeQL, Semgrep, Checkmarx, Veracode
- Any tool producing SARIF 2.1.0+ output

**Acceptance Criteria:**
- Parse SARIF documents with full rule metadata
- Extract findings with location, severity, and CWE mapping
- Support multiple SARIF runs in single document
- Correlate SARIF findings with SBOM components
- Handle large SARIF files (10,000+ findings)

**API Endpoints:**
- `POST /inputs/sarif` - Upload SARIF document

**CLI Commands:**
- `python -m core.cli run --sarif <path>`

#### FR-ING-003: CVE/VEX Feed Processing
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Ingest CVE feeds and Vulnerability Exploitability eXchange (VEX) documents for enrichment.

**Sources:**
- NVD (National Vulnerability Database)
- CISA KEV (Known Exploited Vulnerabilities)
- VEX documents (CycloneDX VEX, CSAF)

**Acceptance Criteria:**
- Automatic CVE enrichment with CVSS, EPSS, KEV status
- VEX document processing for exploitability overrides
- Scheduled CVE feed updates
- Air-gapped mode with bundled feeds

**API Endpoints:**
- `POST /inputs/cve` - Upload CVE feed
- `POST /inputs/vex` - Upload VEX document

#### FR-ING-004: CNAPP Integration
**Priority:** P1 (High)
**Status:** ✅ Implemented

**Description:**
Ingest findings from Cloud-Native Application Protection Platform (CNAPP) tools.

**Supported Types:**
- IaC misconfigurations (Terraform, CloudFormation)
- Secrets scanning results
- Container image vulnerabilities
- Runtime security alerts

**Acceptance Criteria:**
- Normalize CNAPP findings to common schema
- Map to MITRE ATT&CK techniques
- Correlate with SBOM/SARIF findings
- Support Wiz, Prisma Cloud, Lacework formats

**API Endpoints:**
- `POST /inputs/cnapp` - Upload CNAPP findings

#### FR-ING-005: Scanner-Agnostic Multipart Ingestion
**Priority:** P0 (Critical)
**Status:** ✅ Implemented (January 2026)

**Description:**
Universal scanner-agnostic ingestion endpoint that auto-detects and normalizes security findings from any supported format with dynamic asset inventory.

**Supported Formats:**
- SARIF 2.1+ (with schema drift handling for 2.1 → 2.2)
- CycloneDX SBOM
- SPDX SBOM
- VEX (Vulnerability Exploitability eXchange)
- CNAPP findings
- Trivy container/filesystem scanner output
- Grype container vulnerability scanner output
- Semgrep SAST scanner output
- Dependabot GitHub dependency alerts
- Dark web intelligence feeds

**Acceptance Criteria:**
- Auto-detect format from file content with 99% accuracy
- Handle 10,000+ findings in under 2 minutes
- 99% parse success rate on drifted/variant formats
- Dynamic asset inventory with stable deduplication keys
- Plugin registry for custom format handlers via YAML config
- Lenient Pydantic parsing for schema evolution

**API Endpoints:**
- `POST /api/v1/ingest/multipart` - Upload multiple files with auto-detection
- `GET /api/v1/ingest/assets` - Retrieve dynamic asset inventory
- `GET /api/v1/ingest/formats` - List available normalizers and plugins

**CLI Commands:**
- `python -m core.cli ingest-file --file <path> [--format <format>]`
- `POST /api/v1/iac/scan/*` - IaC scanning endpoints
- `POST /api/v1/secrets/scan/*` - Secrets scanning endpoints

#### FR-ING-005: Business Context Enrichment
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Ingest business context (criticality, data classification, exposure) to weight risk scores.

**Context Types:**
- Application criticality (critical/high/medium/low)
- Data classification (PII/financial/internal/public)
- Network exposure (internet-facing/internal/isolated)
- Regulatory requirements (PCI/HIPAA/SOX)

**Acceptance Criteria:**
- Support CSV and JSON import formats
- API for programmatic context updates
- Automatic context inheritance for components
- Historical context tracking with versioning

**API Endpoints:**
- `POST /inputs/context` - Upload business context
- `POST /api/v1/inventory/services` - Register services
- `PUT /api/v1/inventory/services/{id}` - Update context

**CLI Commands:**
- `python -m core.cli inventory add --service <name> --criticality <level>`
- `python -m core.cli inventory import --csv <path>`

### 6.2 Capability Area 2: Correlate & Deduplicate

#### FR-COR-001: Risk Graph Construction
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Build application-centric Risk Graph modeling relationships between services, components, and vulnerabilities.

**Graph Structure:**
```
Services → Components → CVEs/Findings
         ↓              ↓
    Business Context  KEV/EPSS Enrichment
```

**Acceptance Criteria:**
- Construct graph from ingested SBOM/SARIF/CVE data
- Track dependency relationships
- Support graph traversal for reachability analysis
- Persist graph in database with efficient querying

**API Endpoints:**
- `GET /api/v1/risk-graph` - Retrieve full graph
- `GET /api/v1/risk-graph/services/{id}` - Service subgraph
- `POST /api/v1/risk-graph/query` - Custom graph queries

#### FR-COR-002: Finding Deduplication
**Priority:** P0 (Critical)
**Status:** ✅ Implemented (5 strategies)

**Description:**
Intelligent deduplication of findings from multiple scanners using correlation strategies.

**Correlation Strategies:**
1. **Fingerprint:** CVE ID + component name + version
2. **Location:** File path + line number + CWE
3. **Pattern:** Code pattern signature (hash-based)
4. **Root-Cause:** Same underlying vulnerability, different manifestations
5. **Vulnerability Taxonomy:** CWE hierarchy mapping

**Acceptance Criteria:**
- Automatically detect duplicate findings
- Present single unified finding with multi-tool evidence
- Track source tools for each finding
- Allow manual merge/split operations
- Maintain audit trail of deduplication decisions

**API Endpoints:**
- `GET /api/v1/findings/duplicates` - List duplicate groups
- `POST /api/v1/findings/merge` - Manually merge findings
- `POST /api/v1/findings/split` - Separate incorrectly merged findings

#### FR-COR-003: Vulnerability Enrichment
**Priority:** P0 (Critical)
**Status:** ✅ Implemented (8 intelligence sources)

**Description:**
Enrich CVEs with intelligence from global vulnerability databases and threat feeds.

**Intelligence Sources:**
1. **Global Authoritative:** NVD, CVE Program, MITRE, CISA KEV, CERT/CC
2. **National CERTs:** NCSC UK, BSI Germany, ANSSI France, JPCERT, others
3. **Exploit Intelligence:** Exploit-DB, Metasploit, Packet Storm, Vulners
4. **Threat Actors:** MITRE ATT&CK, AlienVault OTX, abuse.ch
5. **Supply-Chain:** OSV, GitHub Advisory, Snyk, deps.dev
6. **Cloud/Runtime:** AWS/Azure/GCP Security Bulletins, Kubernetes CVEs
7. **Zero-Day Signals:** MSRC, Apple Security, Cisco PSIRT
8. **Internal Signals:** SAST/DAST findings, exposure data

**Enrichment Data:**
- CVSS v2/v3/v4 scores
- EPSS (Exploit Prediction Scoring System)
- KEV (Known Exploited Vulnerabilities) status
- CWE (Common Weakness Enumeration) mapping
- MITRE ATT&CK technique mapping
- Threat actor attribution
- Exploit availability status
- Patch availability and timeline

**Acceptance Criteria:**
- Automatic enrichment on CVE ingestion
- Scheduled updates from all intelligence sources
- Offline mode with bundled intelligence databases
- API access to enrichment data

### 6.3 Capability Area 3: Decide with Transparency

#### FR-DEC-001: Tri-State Decision Verdicts
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Produce actionable release-gate decisions with three outcomes: Allow, Block, or Needs Review.

**Decision Logic:**
- **Allow:** Vulnerability not exploitable in current context → Proceed with deployment
- **Block:** Exploitable vulnerability detected → Stop deployment, create remediation ticket
- **Needs Review:** Insufficient confidence or edge case → Escalate to human review

**Acceptance Criteria:**
- Deterministic decision based on configurable thresholds
- Support fail-closed (Block by default) or fail-open (Allow by default) modes
- Natural language explanation for each decision
- Audit trail with all decision factors

**API Endpoints:**
- `POST /api/v1/enhanced/analysis` - Analyze findings and produce decision
- `GET /pipeline/run` - Execute full pipeline with decision

**CLI Commands:**
- `python -m core.cli make-decision` - Execute decision as exit code
- `python -m core.cli run` - Full pipeline execution

#### FR-DEC-002: Multi-LLM Consensus Engine
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Leverage multiple AI providers with weighted voting to reduce hallucinations and improve decision quality.

**LLM Providers:**
1. **GPT-5** (weight: 1.0) - Strategic analysis, MITRE ATT&CK mapping
2. **Claude-3** (weight: 0.95) - Compliance analysis, guardrail evaluation
3. **Gemini-2** (weight: 0.9) - Exploit signals, CNAPP correlation
4. **Sentinel-Cyber** (weight: 0.85) - Threat intelligence, security heuristics

**Consensus Configuration:**
- Default threshold: 85% agreement
- Configurable via `FIXOPS_CONSENSUS_THRESHOLD` environment variable
- Retry logic with exponential backoff
- Graceful degradation to deterministic mode if LLMs unavailable

**Acceptance Criteria:**
- Query all LLM providers in parallel
- Calculate weighted consensus score
- Fall back to subset if some providers fail
- Log step-by-step reasoning from each LLM
- Support A/B testing of different provider configurations

**API Endpoints:**
- `POST /api/v1/llm/consensus` - Execute multi-LLM consensus
- `GET /api/v1/llm/providers` - List configured providers
- `PUT /api/v1/llm/config` - Update LLM configuration

#### FR-DEC-003: Policy Evaluation Engine
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Evaluate findings against configurable security policies with transparent rule execution.

**Policy Types:**
- **Severity-based:** Block all critical/high findings
- **Context-aware:** Apply different thresholds based on criticality/exposure
- **Compliance-driven:** Enforce regulatory requirements (PCI/HIPAA/SOX)
- **Exception-based:** Allow specific CVEs with documented justification

**Policy Configuration:**
Via `config/fixops.overlay.yml`:
```yaml
risk_models:
  weighted_scoring_v1:
    allow_threshold: 0.6
    block_threshold: 0.85
    criticality_weights:
      critical: 1.0
      high: 0.8
      medium: 0.5
      low: 0.2
```

**Acceptance Criteria:**
- Load policies from YAML overlay configuration
- Support multiple policy models (Zero-Exception, Smart Prioritization)
- Transparent rule evaluation with visible decision tree
- Policy versioning and audit trail
- API for policy CRUD operations

**API Endpoints:**
- `GET /api/v1/policies` - List policies
- `POST /api/v1/policies` - Create policy
- `PUT /api/v1/policies/{id}` - Update policy
- `POST /api/v1/policies/{id}/evaluate` - Test policy

**CLI Commands:**
- `python -m core.cli policies create --name <name> --config <yaml>`
- `python -m core.cli policies evaluate --policy <id> --findings <json>`

#### FR-DEC-004: Probabilistic Risk Forecasting
**Priority:** P1 (High)
**Status:** ✅ Implemented

**Description:**
Apply statistical models to predict vulnerability severity trends and exploitation probability.

**Models:**
1. **Bayesian Posterior Probability** - EPSS-based exploit likelihood
2. **5-State Markov Chain** - Severity trend prediction
3. **BN-LR Hybrid Model** - Calibrated risk scores

**Forecasting Capabilities:**
- Predict probability of exploitation within 30/60/90 days
- Forecast severity escalation (e.g., CVSS 7.5 → 9.0)
- Model A/B testing in production
- Calibration with historical incident data

**Acceptance Criteria:**
- Train models with historical vulnerability data
- Generate probabilistic forecasts per finding
- Support model calibration with organization-specific incidents
- Export forecast parameters for audit

**CLI Commands:**
- `python -m core.cli train-forecast --incidents <json> --output <config>`

#### FR-DEC-005: Explainable Scoring
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Provide transparent risk scores with visible contributing factors and weights.

**Score Components:**
- **Severity:** CVSS score (weight: 0.4)
- **Exploitability:** EPSS + KEV status (weight: 0.3)
- **Business Context:** Criticality + data classification (weight: 0.2)
- **Exposure:** Internet-facing + reachability (weight: 0.1)

**Transparency Features:**
- Show formula: `RiskScore = (Severity × W1) + (Exploitability × W2) + ...`
- Display each factor's contribution
- Natural language narrative: "Risk is HIGH because CVE is KEV-listed, EPSS is 0.92, and service is internet-facing"
- Audit trail of score calculation

**Acceptance Criteria:**
- Calculate risk score with configurable weights
- Return detailed breakdown with each API response
- Support custom scoring formulas via overlay
- Historical score tracking to show trends

### 6.4 Capability Area 4: Verify Exploitability

#### FR-VER-001: Micro-Pentest Engine
**Priority:** P1 (High)
**Status:** ✅ Implemented

**Description:**
Automated vulnerability verification through targeted exploit simulation.

**Attack Vector Types:**
- SQL Injection
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- Remote Code Execution (RCE)
- Path Traversal
- JNDI Injection
- Buffer Overflow

**Pentest Execution:**
1. Select CVEs from Risk Graph
2. Generate exploit payloads per CVE/attack-vector
3. Execute tests in isolated environment
4. Collect evidence (request/response, exit codes)
5. Calculate confidence score (0-100%)
6. Update finding with exploitability verdict

**Multi-AI Orchestration:**
- Use LLM consensus to generate exploit strategies
- Validate results across multiple AI providers
- Reduce false positives through cross-validation

**Acceptance Criteria:**
- Support batch testing of multiple CVEs
- Return confidence score per test
- Collect cryptographic evidence of exploit success/failure
- Integrate with PentAGI service for advanced testing
- Right-click execution from Risk Graph UI

**API Endpoints:**
- `POST /api/v1/micro-pentest/execute` - Execute micro-pentest
- `GET /api/v1/micro-pentest/results/{id}` - Get results
- `POST /api/v1/micro-pentest/batch` - Batch test multiple CVEs

**CLI Commands:**
- `python -m core.cli advanced-pentest run --finding-id <id>`
- `python -m core.cli micro-pentest run --cve-ids <csv-list>`

#### FR-VER-002: Reachability Analysis
**Priority:** P1 (High)
**Status:** ✅ Implemented

**Description:**
Determine if vulnerabilities are reachable from external attack surfaces.

**Analysis Approach:**
1. Map attack paths: Internet → Gateway → Service → Component → CVE
2. Check network exposure (internet-facing vs. internal)
3. Validate authentication requirements
4. Assess lateral movement potential
5. Calculate reachability confidence score

**Verdicts:**
- **Reachable:** Direct path from internet to vulnerable component
- **Not Reachable:** Isolated/air-gapped, requires insider access
- **Conditional:** Reachable only after authentication/authorization bypass

**Acceptance Criteria:**
- Analyze reachability for individual CVEs or bulk lists
- Return attack path visualization
- Combine with EPSS/KEV for final risk score
- Support what-if scenarios (e.g., "if DMZ is breached")

**API Endpoints:**
- `POST /api/v1/reachability/analyze` - Analyze CVE reachability
- `POST /api/v1/reachability/batch` - Batch analysis

#### FR-VER-003: PentAGI Integration
**Priority:** P2 (Medium)
**Status:** ✅ Implemented

**Description:**
Integration with PentAGI automated pentesting service for advanced exploit validation.

**Capabilities:**
- Create pentest requests for findings
- Track pentest execution status
- Retrieve detailed results with exploitability verdict
- Manage Pentagi configuration

**Acceptance Criteria:**
- Submit pentest requests via API/CLI
- Poll for completion or receive webhooks
- Parse exploitability results (confirmed/likely/unexploitable)
- Update finding status based on Pentagi verdict

**API Endpoints:**
- `POST /api/v1/pentagi/requests` - Create pentest request
- `GET /api/v1/pentagi/requests/{id}` - Get request status
- `POST /api/v1/pentagi/requests/{id}/start` - Start execution
- `GET /api/v1/pentagi/results` - List results

**CLI Commands:**
- `python -m core.cli pentagi create-request --finding-id <id>`
- `python -m core.cli pentagi list-requests`
- `python -m core.cli pentagi get-request <id>`

### 6.5 Capability Area 5: Operationalize Remediation

#### FR-REM-001: Remediation Lifecycle Management
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Track vulnerabilities through full remediation lifecycle with SLA enforcement.

**Lifecycle States:**
1. **Open:** Newly discovered vulnerability
2. **Triaged:** Assigned to owner with priority
3. **In Progress:** Actively being remediated
4. **Pending Verification:** Fix deployed, awaiting validation
5. **Verified:** Fix confirmed effective
6. **Closed:** Remediation complete
7. **Deferred:** Accepted risk with documented justification

**SLA Tracking:**
- Critical: 7 days
- High: 30 days
- Medium: 90 days
- Low: 180 days

**Acceptance Criteria:**
- Automatic state transitions based on events
- SLA countdown with breach notifications
- Bulk state updates for multiple findings
- Historical state audit trail
- Remediation metrics (MTTR, breach rate)

**API Endpoints:**
- `POST /api/v1/remediation/tasks` - Create remediation task
- `PUT /api/v1/remediation/tasks/{id}` - Update task status
- `GET /api/v1/remediation/tasks` - List tasks with filters
- `POST /api/v1/remediation/bulk-update` - Bulk operations

**CLI Commands:**
- `python -m core.cli remediation create --finding-id <id>`
- `python -m core.cli remediation update --task-id <id> --status <status>`

#### FR-REM-002: Jira/Ticketing Integration
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Bidirectional integration with ticketing systems for automated remediation workflow.

**Supported Systems:**
- Jira (full bidirectional sync)
- ServiceNow (incident creation + updates)
- GitHub Issues
- GitLab Issues
- Azure DevOps Work Items

**Outbound Operations:**
- Create tickets for Block/Needs Review findings
- Update ticket status on remediation progress
- Add comments with new evidence or analysis
- Transition tickets through workflow states

**Inbound Operations (Webhooks):**
- Receive status updates from external system
- Sync comments back to FixOps
- Detect drift (ticket state ≠ FixOps state)
- Trigger re-verification on ticket closure

**Acceptance Criteria:**
- Configure integrations via overlay YAML
- Test connectivity with health check endpoint
- Automatic ticket creation on decision = Block
- Webhook receiver for bidirectional sync
- Outbox pattern for reliable delivery
- Retry logic with exponential backoff

**API Endpoints:**
- `POST /api/v1/integrations` - Configure integration
- `POST /api/v1/integrations/{id}/test` - Test connection
- `POST /api/v1/integrations/{id}/sync` - Manual sync
- `POST /api/v1/webhooks/jira` - Jira webhook receiver
- `POST /api/v1/webhooks/servicenow` - ServiceNow webhook

**CLI Commands:**
- `python -m core.cli integrations configure --type jira --url <url> --token <token>`
- `python -m core.cli integrations test --id <id>`
- `python -m core.cli integrations sync --id <id>`

#### FR-REM-003: Collaboration & Comments
**Priority:** P2 (Medium)
**Status:** ✅ Implemented

**Description:**
Team collaboration features for discussing findings and coordinating remediation.

**Features:**
- Threaded comments on findings
- @mention notifications
- Attachment uploads (screenshots, logs)
- Activity timeline
- Comment reactions (upvote/important/resolved)

**Acceptance Criteria:**
- Add/edit/delete comments via API
- Real-time updates via WebSocket or polling
- Email notifications on mentions
- Search within comments
- Comment export for audit

**API Endpoints:**
- `POST /api/v1/findings/{id}/comments` - Add comment
- `GET /api/v1/findings/{id}/comments` - List comments
- `PUT /api/v1/findings/{id}/comments/{cid}` - Edit comment
- `DELETE /api/v1/findings/{id}/comments/{cid}` - Delete comment

#### FR-REM-004: Bulk Operations
**Priority:** P1 (High)
**Status:** ✅ Implemented

**Description:**
Perform actions on multiple findings simultaneously for efficiency.

**Bulk Operations:**
- Assign to owner
- Update status
- Apply tags/labels
- Set SLA deadlines
- Create Jira tickets
- Mark as false positive
- Accept risk (defer)
- Trigger micro-pentests

**Acceptance Criteria:**
- Support selection of findings by filter criteria
- Preview bulk operation impact before execution
- Atomic transactions (all succeed or all fail)
- Background job processing for large batches
- Progress tracking with status API

**API Endpoints:**
- `POST /api/v1/remediation/bulk-assign` - Bulk assign
- `POST /api/v1/remediation/bulk-update` - Bulk status update
- `POST /api/v1/remediation/bulk-tag` - Bulk tagging

### 6.6 Capability Area 6: Prove & Retain

#### FR-EVD-001: Signed Evidence Bundles
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Generate cryptographically signed evidence bundles for tamper-proof audit trails.

**Bundle Contents:**
- Stage outputs (requirements, design, build, test, deploy, operate, decision)
- Manifest with SHA256 checksums
- RSA-SHA256 signature
- SLSA v1 provenance metadata
- in-toto attestation (DSSE envelope)

**Signing Process:**
1. Collect all stage outputs
2. Generate manifest with checksums
3. Create SLSA provenance document
4. Sign manifest with RSA private key
5. Package as `.zip` bundle
6. Store in immutable evidence lake

**Acceptance Criteria:**
- Sign bundles with configurable key (RSA 2048/4096)
- Support optional Fernet encryption for sensitive data
- Verify signatures via API endpoint
- Export bundles in multiple formats (ZIP, tar.gz)
- Maintain signature validity for 7+ years

**API Endpoints:**
- `POST /api/v1/evidence/bundles` - Create evidence bundle
- `GET /api/v1/evidence/bundles/{id}` - Download bundle
- `POST /api/v1/evidence/verify` - Verify bundle signature
- `GET /api/v1/evidence/bundles` - List all bundles

**CLI Commands:**
- `python -m core.cli get-evidence --result <json> --destination <dir>`
- `python -m core.cli copy-evidence --bundle-id <id> --output <path>`

#### FR-EVD-002: Immutable Evidence Lake
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Store evidence bundles in immutable storage with configurable retention policies.

**Storage Backends:**
- **Local Filesystem:** Standard filesystem with integrity checks
- **S3 Object Lock:** AWS S3 with WORM (Write Once Read Many) mode
- **Azure Immutable Blob:** Azure Blob Storage with immutability policy

**Retention Policies:**
- Configurable retention periods per evidence type
- Minimum: 1 year (compliance baseline)
- Maximum: 10 years (long-term regulatory)
- Default: 7 years (most compliance frameworks)

**Integrity Verification:**
- Periodic checksum validation
- Alert on tampering detection
- Automatic re-signing on migration

**Acceptance Criteria:**
- Support multiple storage backends
- Enforce retention policies (no deletion before expiration)
- Audit log of all evidence access
- Compression (gzip) for storage efficiency
- Export capability for offline archive

#### FR-EVD-003: SLSA Provenance
**Priority:** P1 (High)
**Status:** ✅ Implemented

**Description:**
Generate SLSA (Supply-chain Levels for Software Artifacts) v1 provenance for all decisions.

**Provenance Contents:**
- Build/pipeline metadata (runner, timestamp, version)
- Input artifacts (SBOM/SARIF checksums)
- Output artifacts (decision, evidence bundle)
- Dependencies and tools used
- Signing certificate chain

**SLSA Levels:**
- **Level 1:** Documentation of build process ✅
- **Level 2:** Tamper-proof build service (in progress)
- **Level 3:** Hardened build platform (planned)
- **Level 4:** Two-party review (future)

**Acceptance Criteria:**
- Generate provenance per SLSA v1 specification
- Use in-toto attestation format (DSSE envelope)
- Include in evidence bundles
- Validate provenance on ingestion
- Support external provenance verification tools

#### FR-EVD-004: Compliance Report Generation
**Priority:** P1 (High)
**Status:** ✅ Implemented

**Description:**
Auto-generate compliance reports mapped to regulatory frameworks.

**Supported Frameworks:**
- ISO 27001:2022 A.8.25 (Secure Development Lifecycle)
- NIST SSDF / EO 14028 (Secure Software Development Framework)
- SOC2 (Trust Services Criteria)
- PCI-DSS (Payment Card Industry)
- GDPR (Data Protection)
- OWASP ASVS (Application Security Verification Standard)

**Report Types:**
- **Attestation Report:** Self-attestation of secure practices
- **Evidence Summary:** Aggregated evidence for audit period
- **Gap Analysis:** Compliance gaps with remediation status
- **Metrics Dashboard:** KPIs (MTTR, coverage, trend)

**Acceptance Criteria:**
- Generate reports on-demand or scheduled
- Export formats: PDF, JSON, SARIF
- Include evidence bundle references
- Support date range filtering
- Compliance status: Compliant/Non-Compliant/Partial

**API Endpoints:**
- `GET /api/v1/compliance/frameworks` - List supported frameworks
- `POST /api/v1/compliance/reports` - Generate report
- `GET /api/v1/compliance/reports/{id}` - Download report
- `GET /api/v1/compliance/status` - Current compliance posture

**CLI Commands:**
- `python -m core.cli compliance report --framework iso27001 --output <path>`
- `python -m core.cli compliance status`

### 6.7 Capability Area 7: Automate & Extend

#### FR-AUT-001: YAML Overlay Configuration
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

**Description:**
Declarative configuration of all platform behavior via YAML overlay files.

**Configurable Aspects:**
- Risk models and scoring weights
- Policy thresholds (allow/block)
- LLM provider configuration
- Integration credentials
- Feature toggles
- Retention policies

**Configuration File:** `config/fixops.overlay.yml`

**Acceptance Criteria:**
- Load configuration from YAML file
- Support environment variable substitution
- Validate configuration schema on load
- Hot-reload without restart (for non-security settings)
- Version control friendly (no secrets in plain text)

**CLI Commands:**
- `python -m core.cli show-overlay --overlay <path> --pretty`
- `python -m core.cli health --overlay <path>` (validate config)

#### FR-AUT-002: YAML Playbook Scripting
**Priority:** P2 (Medium)
**Status:** ✅ Implemented (21 pre-approved actions)

**Description:**
Automate complex workflows with YAML-based playbook language.

**Pre-Approved Actions:**
1. `create_jira_ticket`
2. `update_finding_status`
3. `assign_to_owner`
4. `add_comment`
5. `send_slack_notification`
6. `trigger_micro_pentest`
7. `create_confluence_page`
8. `bulk_assign`
9. `defer_finding`
10. `escalate_priority`
11. ... (11 more)

**Playbook Example:**
```yaml
name: auto-remediate-critical
trigger: finding_created
conditions:
  - severity: critical
  - kev_listed: true
actions:
  - create_jira_ticket:
      project: SEC
      priority: highest
  - send_slack_notification:
      channel: "#security-alerts"
  - assign_to_owner: security-team
```

**Acceptance Criteria:**
- Parse and execute YAML playbooks
- Support conditional logic
- Error handling and rollback
- Dry-run mode for testing
- Audit log of playbook executions

**API Endpoints:**
- `POST /api/v1/playbooks` - Create playbook
- `GET /api/v1/playbooks/{id}` - Get playbook
- `POST /api/v1/playbooks/{id}/execute` - Execute playbook
- `GET /api/v1/playbooks/executions` - List execution history

#### FR-AUT-003: Compliance Marketplace
**Priority:** P2 (Medium)
**Status:** ✅ Implemented (concept)

**Description:**
Marketplace of pre-built compliance packs for rapid regulatory alignment.

**Available Packs:**
- PCI-DSS v4.0 Compliance Pack
- HIPAA Security Rule Pack
- SOC2 Type II Pack
- ISO 27001:2022 Pack
- GDPR Data Protection Pack

**Pack Contents:**
- Pre-configured policies
- Compliance-specific playbooks
- Report templates
- Evidence collection rules
- Risk model tuning

**Acceptance Criteria:**
- Install marketplace packs via CLI/API
- Preview pack contents before installation
- Support custom pack creation
- Version and update packs independently
- Export organization-specific customizations

**CLI Commands:**
- `python -m core.cli marketplace list`
- `python -m core.cli marketplace install --pack pci-dss`

#### FR-AUT-004: Scheduled Jobs & Background Workers
**Priority:** P1 (High)
**Status:** ✅ Implemented

**Description:**
Background job processing for long-running operations and scheduled tasks.

**Scheduled Tasks:**
- CVE feed updates (daily)
- Compliance report generation (weekly/monthly)
- Evidence bundle compression (nightly)
- Integration health checks (hourly)
- Outbox processing (every 5 minutes)

**Background Jobs:**
- Bulk operations
- Large SBOM/SARIF processing
- Multi-CVE micro-pentests
- Analytics aggregation

**Acceptance Criteria:**
- Job scheduling with cron-like syntax
- Job queue with priority support
- Progress tracking and status API
- Job cancellation capability
- Automatic retry on failure (exponential backoff)

**API Endpoints:**
- `GET /api/v1/jobs` - List scheduled jobs
- `POST /api/v1/jobs` - Create job
- `GET /api/v1/jobs/{id}` - Get job status
- `POST /api/v1/jobs/{id}/cancel` - Cancel job

### 6.8 Capability Area 8: Visualize & Analyze

#### FR-VIZ-001: Interactive Risk Graph
**Priority:** P1 (High)
**Status:** ✅ Implemented

**Description:**
Cytoscape.js-powered visualization of services, components, and vulnerabilities.

**Graph Features:**
- **Node Types:** Services (blue), Components (green), CVEs (red/orange/yellow)
- **Relationships:** Service → Component → CVE with dependency lines
- **Highlighting:** KEV-listed CVEs in red, internet-facing services in bold
- **Filtering:** By severity, KEV status, EPSS score, reachability
- **Multi-Select:** Bulk select CVEs for batch micro-pentest

**Interaction:**
- Click node for details panel
- Right-click CVE for context menu (micro-pentest, Jira ticket, defer)
- Drag nodes for layout customization
- Zoom and pan for navigation
- Export as PNG/SVG

**Acceptance Criteria:**
- Render graph with 1000+ nodes performantly (<2s load)
- Real-time filtering without full re-render
- Responsive design (desktop and tablet)
- Keyboard navigation support
- Accessibility (screen reader compatible)

**UI Route:**
- `/risk-graph` - Main Risk Graph page

#### FR-VIZ-002: Analytics Dashboards
**Priority:** P1 (High)
**Status:** ✅ Implemented

**Description:**
Comprehensive analytics and metrics visualization.

**Dashboard Types:**
1. **Executive Dashboard:** High-level KPIs, trend charts
2. **Security Metrics:** MTTR, vulnerability counts, severity distribution
3. **Remediation Progress:** SLA compliance, ticket aging
4. **Coverage Analysis:** SBOM completeness, scan frequency
5. **Compliance Status:** Framework compliance percentages

**Key Metrics:**
- Mean Time to Remediate (MTTR)
- Mean Time to Detect (MTTD)
- Vulnerability trend (new vs. resolved)
- SLA breach rate
- False positive rate
- Decision distribution (Allow/Block/Review)

**Visualization Types:**
- Time series line charts
- Severity distribution pie charts
- Remediation funnel
- Heat maps for risk concentration
- Trend arrows (↑↓→)

**Acceptance Criteria:**
- Render dashboards with date range filtering
- Export charts as PNG or data as CSV
- Real-time updates (WebSocket or auto-refresh)
- Drill-down from chart to detailed findings
- Responsive design

**UI Routes:**
- `/analytics` - Main analytics hub
- `/analytics/security` - Security metrics
- `/analytics/remediation` - Remediation tracking
- `/analytics/compliance` - Compliance status

**API Endpoints:**
- `GET /api/v1/analytics/metrics` - Get current metrics
- `GET /api/v1/analytics/trends` - Time series data
- `GET /api/v1/analytics/summary` - Executive summary

**CLI Commands:**
- `python -m core.cli analytics dashboard`
- `python -m core.cli analytics export --format csv`

---

## 7. Technical Architecture

### 7.1 System Architecture

**Architecture Style:** Modular monolith with optional microservices decomposition

**Core Components:**
1. **API Gateway Layer:** FastAPI with OpenAPI documentation
2. **Business Logic Layer:** Core processing engine (Python modules)
3. **Data Access Layer:** Database adapters with ORM (SQLAlchemy/SQLite/PostgreSQL)
4. **Integration Layer:** External system connectors and webhooks
5. **Storage Layer:** Evidence lake, database, file storage

**Architecture Diagram:**
```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Layer                             │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐     │
│  │ Web UI  │    │  CLI    │    │ CI/CD   │    │ External│     │
│  │ Browser │    │ Terminal│    │ Pipeline│    │ Systems │     │
│  └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘     │
└───────┼──────────────┼──────────────┼──────────────┼───────────┘
        │              │              │              │
        └──────────────┴──────────────┴──────────────┘
                       │
        ┌──────────────┴──────────────┐
        │       Load Balancer         │ (Optional)
        └──────────────┬──────────────┘
                       │
┌──────────────────────┴──────────────────────────────────────────┐
│                      API Gateway Layer                           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  FastAPI Application (apps/api/app.py)                     │ │
│  │  - 303 REST API endpoints across 32 routers                │ │
│  │  - OpenAPI/Swagger documentation                           │ │
│  │  - JWT authentication & authorization                      │ │
│  │  - Rate limiting & request validation                      │ │
│  └────────────────────┬───────────────────────────────────────┘ │
└───────────────────────┼─────────────────────────────────────────┘
                        │
┌───────────────────────┼─────────────────────────────────────────┐
│               Business Logic Layer (core/)                       │
│  ┌───────────────────┴──────────────────────────────────────┐  │
│  │                                                            │  │
│  │  ┌──────────────────┐  ┌──────────────────┐             │  │
│  │  │ Ingestion Engine │  │ Correlation Eng. │             │  │
│  │  │ - SBOM/SARIF     │  │ - Deduplication  │             │  │
│  │  │ - CVE/VEX        │  │ - Risk Graph     │             │  │
│  │  └──────────────────┘  └──────────────────┘             │  │
│  │                                                            │  │
│  │  ┌──────────────────┐  ┌──────────────────┐             │  │
│  │  │  Decision Engine │  │  Verification    │             │  │
│  │  │ - LLM Consensus  │  │ - Micro-Pentest  │             │  │
│  │  │ - Policy Eval    │  │ - Reachability   │             │  │
│  │  └──────────────────┘  └──────────────────┘             │  │
│  │                                                            │  │
│  │  ┌──────────────────┐  ┌──────────────────┐             │  │
│  │  │ Remediation Mgr  │  │  Evidence Engine │             │  │
│  │  │ - Lifecycle      │  │ - Signing        │             │  │
│  │  │ - SLA Tracking   │  │ - SLSA Prov.     │             │  │
│  │  └──────────────────┘  └──────────────────┘             │  │
│  │                                                            │  │
│  └───────────────────┬──────────────────────────────────────┘  │
└───────────────────────┼─────────────────────────────────────────┘
                        │
┌───────────────────────┼─────────────────────────────────────────┐
│                  Data Access Layer                               │
│  └───────────────────────────────────────────────────────────┘  │
└───────────────────────┼─────────────────────────────────────────┘
                        │
┌───────────────────────┼─────────────────────────────────────────┐
│                  Storage & Integration Layers                    │
└─────────────────────────────────────────────────────────────────┘
```

*For complete technical architecture details, data models, and remaining sections 8-19, please refer to the mind map in PRD_MIND_MAP.md which provides the full structural outline.*

---

## Summary

This PRD document provides comprehensive product requirements for FixOps, covering:
- **Executive vision** and market positioning
- **Core capabilities** across 8 functional areas (40+ requirements)
- **Technical architecture** and system design
- **Non-functional requirements** for performance, security, and scalability
- **Product roadmap** through 2027+
- **Go-to-market strategy** and pricing model
- **Success metrics** and KPIs for measuring impact

For the complete detailed expansion of sections 8-19, refer to:
- **PRD_MIND_MAP.md**: Comprehensive mind map with all sections expanded
- **docs/FIXOPS_PRODUCT_STATUS.md**: Current implementation status
- **CLI_API_INVENTORY.md**: Complete API and CLI reference
- **README.md**: Product overview and capabilities

---

**Document Status:** Core sections complete. This is a living document updated quarterly.
**Version:** 1.0  
**Last Updated:** January 2026
**Next Review:** April 2026

---

**END OF PRD**
