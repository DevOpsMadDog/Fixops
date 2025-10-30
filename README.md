# FixOps: DevSecOps Decision & Verification Engine

## Deep Wiki & Comprehensive Documentation

FixOps is an intelligent DevSecOps decision and verification platform that transforms raw security artifacts into actionable risk assessments, compliance evidence, and automated remediation workflows. It serves as a contextual intelligence layer for CI/CD pipelines, combining vulnerability data, business context, and multi-source intelligence to produce cryptographically-signed evidence trails with explainable decisions.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Core Architecture](#core-architecture)
3. [Key Components](#key-components)
4. [Data Flow & Processing](#data-flow--processing)
5. [Module Ecosystem](#module-ecosystem)
6. [API Reference](#api-reference)
7. [CLI Tools](#cli-tools)
8. [Configuration System](#configuration-system)
9. [Security & Cryptography](#security--cryptography)
10. [Installation & Setup](#installation--setup)
11. [Development Workflow](#development-workflow)
12. [Testing Strategy](#testing-strategy)
13. [Deployment Patterns](#deployment-patterns)
14. [Integration Guides](#integration-guides)
15. [Troubleshooting](#troubleshooting)
16. [Contributing](#contributing)

---

## Quickstart

Get FixOps running in 5 minutes:

```bash
# 1. Clone and setup
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Start the API server
export FIXOPS_API_TOKEN="demo-token"
uvicorn apps.api.app:create_app --factory --reload

# 3. In another terminal, upload artifacts
export FIXOPS_API_TOKEN="demo-token"
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@simulations/demo_pack/design.csv" \
  http://localhost:8000/inputs/design

curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@simulations/demo_pack/sbom.json" \
  http://localhost:8000/inputs/sbom

curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@simulations/demo_pack/scan.sarif" \
  http://localhost:8000/inputs/sarif

curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@simulations/demo_pack/cve.json" \
  http://localhost:8000/inputs/cve

# 4. Run the pipeline
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://localhost:8000/pipeline/run | jq

# 5. Or use the CLI
python -m core.cli demo --mode demo --output out/pipeline-demo.json --pretty
```

---

## System Overview

### What is FixOps?

FixOps is a contextual risk and evidence platform that:

- **Ingests** security artifacts (SBOM, SARIF, CVE feeds, design context, VEX, CNAPP findings)
- **Normalizes** data from multiple formats and sources into unified schemas
- **Correlates** findings across components, vulnerabilities, and business context
- **Evaluates** risk using multi-layered decision engines (vector patterns, LLM consensus, policy rules)
- **Produces** cryptographically-signed evidence bundles with explainable verdicts
- **Automates** remediation workflows (Jira tickets, Confluence pages, Slack notifications)

### Primary Use Cases

1. **CI/CD Gate Decisions**: Automated approve/reject/review decisions for deployment pipelines
2. **Vulnerability Management**: Context-aware prioritization using KEV, EPSS, and business criticality
3. **Compliance Automation**: SOC2, ISO27001, PCI-DSS, GDPR evidence generation
4. **Risk Forecasting**: Probabilistic Bayesian and Markov chain projections
5. **Supply Chain Security**: RSA-signed evidence bundles, SBOM analysis, and cryptographic signatures (SLSA attestations roadmap)

### Target Users

- **Security Engineers**: Interactive analysis via CLI and API
- **DevOps Teams**: CI/CD integration for automated security gates
- **Compliance Officers**: Audit-ready evidence bundles
- **CISO/Executives**: Risk dashboards and ROI metrics
- **Platform Engineers**: SSDLC stage orchestration and IaC posture assessment

---

## Core Architecture

### High-Level System Design

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FixOps Platform                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌──────────────┐         ┌──────────────────┐        ┌──────────────┐ │
│  │   Ingestion  │────────▶│  Normalization   │───────▶│  Correlation │ │
│  │   Layer      │         │  & Parsing       │        │  Engine      │ │
│  └──────────────┘         └──────────────────┘        └──────────────┘ │
│         │                                                      │         │
│         │                                                      ▼         │
│         │                  ┌──────────────────────────────────────┐    │
│         │                  │   Decision Engine Orchestrator       │    │
│         │                  ├──────────────────────────────────────┤    │
│         │                  │ • Vector Store Pattern Matching      │    │
│         │                  │ • Multi-LLM Consensus (GPT/Claude)   │    │
│         │                  │ • Policy Engine (OPA)                │    │
│         │                  │ • SBOM Risk Analysis                 │    │
│         │                  │ • Golden Regression Baseline         │    │
│         │                  │ • Consensus Checker                  │    │
│         │                  └──────────────────────────────────────┘    │
│         │                                   │                           │
│         ▼                                   ▼                           │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │              Module Execution Layer                           │     │
│  ├──────────────────────────────────────────────────────────────┤     │
│  │ Context Engine │ Guardrails │ Compliance │ Policy Automation │     │
│  │ SSDLC Eval │ IaC Posture │ Exploit Signals │ Probabilistic   │     │
│  │ AI Agents │ Analytics │ Tenancy │ Performance │ Knowledge Graph│     │
│  └──────────────────────────────────────────────────────────────┘     │
│                                   │                                     │
│                                   ▼                                     │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │              Evidence & Automation Layer                      │     │
│  ├──────────────────────────────────────────────────────────────┤     │
│  │ • Evidence Lake (RSA-SHA256 signed bundles)                  │     │
│  │ • Automation Connectors (Jira/Confluence/Slack)              │     │
│  │ • Provenance Graph (RSA-SHA256 signatures; SLSA roadmap)     │     │
│  │ • Artifact Archive (compressed, encrypted storage)           │     │
│  └──────────────────────────────────────────────────────────────┘     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
fixops/
├── core/                      # Core business logic and orchestration
│   ├── cli.py                 # Command-line interface orchestrator (1097 lines)
│   ├── configuration.py       # Overlay configuration management
│   ├── overlay_runtime.py     # Runtime configuration with safeguards
│   ├── context_engine.py      # Business context enrichment
│   ├── enhanced_decision.py   # Multi-LLM consensus engine
│   ├── evidence.py            # Evidence bundle management
│   ├── compliance.py          # Compliance framework evaluation
│   ├── policy.py              # Policy automation engine
│   ├── exploit_signals.py     # KEV/EPSS feed management
│   ├── probabilistic.py       # Bayesian/Markov forecasting
│   ├── vector_store.py        # Pattern matching with embeddings
│   ├── ssdlc.py               # SSDLC stage evaluation
│   ├── iac.py                 # Infrastructure-as-Code posture
│   ├── ai_agents.py           # AI agent detection
│   ├── analytics.py           # ROI and performance metrics
│   ├── tenancy.py             # Multi-tenant lifecycle management
│   ├── performance.py         # Performance simulation
│   ├── stage_runner.py        # SSDLC stage orchestration
│   ├── processing_layer.py    # Bayesian/Markov analytics
│   ├── storage.py             # Artifact archival
│   └── llm_providers.py       # LLM provider abstractions
│
├── apps/api/                  # FastAPI ingestion service
│   ├── app.py                 # Main FastAPI application
│   ├── pipeline.py            # Pipeline orchestrator (943 lines)
│   ├── normalizers.py         # Multi-format parsers
│   ├── knowledge_graph.py     # Knowledge graph service
│   ├── upload_manager.py      # Chunked upload handler
│   └── routes/                # API route definitions
│
├── backend/                   # Legacy backend components
│   ├── app.py                 # Legacy FastAPI app
│   ├── normalizers.py         # Legacy normalizers
│   └── api/                   # Legacy API routes
│
├── fixops-enterprise/         # Enterprise-specific features
│   └── src/
│       ├── main.py            # Enterprise FastAPI entry point
│       ├── services/
│       │   ├── decision_engine.py        # Simplified decision engine (349 lines)
│       │   ├── enhanced_decision_engine.py  # Multi-LLM orchestrator
│       │   ├── evidence.py               # Evidence store
│       │   ├── compliance.py             # Compliance engine
│       │   ├── run_registry.py           # Run-specific artifact management
│       │   ├── id_allocator.py           # Unique ID generation
│       │   ├── signing.py                # Cryptographic signing
│       │   ├── feeds_service.py          # Vulnerability feed management
│       │   ├── vex_ingestion.py          # VEX document processing
│       │   └── marketplace.py            # Marketplace recommendations
│       └── api/v1/
│           ├── artefacts.py              # Artifact upload endpoints
│           ├── enhanced.py               # Enhanced decision endpoints
│           ├── evidence.py               # Evidence retrieval
│           ├── marketplace.py            # Marketplace API
│           └── cicd.py                   # CI/CD adapter endpoints
│
├── services/                  # Shared services
│   ├── evidence/              # Evidence packaging
│   ├── graph/                 # Provenance graph (NetworkX)
│   ├── match/                 # Crosswalk matching algorithms
│   ├── provenance/            # RSA-SHA256 signing (SLSA attestations roadmap)
│   └── repro/                 # Reproducible build verification
│
├── domain/                    # Domain models
│   ├── crosswalk.py           # Crosswalk data structures
│   └── evidence.py            # Evidence models
│
├── data/                      # Data storage
│   ├── feeds/                 # KEV, EPSS feeds
│   ├── uploads/               # Uploaded artifacts
│   ├── evidence/              # Evidence bundles
│   ├── archive/               # Archived artifacts
│   └── marketplace/           # Marketplace data
│
├── config/                    # Configuration files
│   └── fixops.overlay.yml     # Overlay configuration (240 lines)
│
├── tests/                     # Test suite
│   ├── test_cli.py            # CLI tests
│   ├── backend_test.py        # API endpoint tests (100+ tests)
│   ├── real_components_test.py  # Integration tests
│   └── fixtures/              # Test fixtures
│
├── scripts/                   # Utility scripts
│   ├── bootstrap.sh           # Development environment setup
│   └── signing/               # Signing utilities
│
├── simulations/               # Demo scenarios
│   ├── demo_pack/             # Demo fixtures
│   └── ssdlc/                 # SSDLC simulations
│
└── docs/                      # Documentation
    ├── ARCHITECTURE.md        # Architecture overview
    ├── HANDBOOK.md            # Engineering handbook
    └── schemas/               # JSON schemas
```

**Total Core Code**: ~16,299 lines (core + apps/api + backend)

---

## Key Components

### 1. Pipeline Orchestrator

**Location**: `apps/api/pipeline.py` (943 lines)

The `PipelineOrchestrator` is the central coordinator that:

- Normalizes severity levels across SARIF, CVE, and CNAPP sources
- Builds crosswalk mappings between design components, SBOM entries, findings, and CVEs
- Executes enabled modules based on overlay configuration
- Aggregates results into a unified response

**Key Methods**:
```python
def run(
    design_dataset: Dict[str, Any],
    sbom: NormalizedSBOM,
    sarif: NormalizedSARIF,
    cve: NormalizedCVEFeed,
    overlay: Optional[OverlayConfig] = None,
    vex: Optional[NormalizedVEX] = None,
    cnapp: Optional[NormalizedCNAPP] = None,
    context: Optional[NormalizedBusinessContext] = None,
) -> Dict[str, Any]
```

**Severity Normalization**:
- SARIF: `none/note/info → low`, `warning → medium`, `error → high`
- CVE: `critical → critical`, `high → high`, `medium/moderate → medium`, `low → low`
- CNAPP: Similar mapping with additional `info → low`

**Outputs**:
- Severity overview with counts by level
- Guardrail evaluation status
- Context engine summaries
- Compliance framework coverage
- Policy automation manifests
- Evidence bundle paths
- Module execution matrix

### 2. Decision Engine

**Location**: `fixops-enterprise/src/services/decision_engine.py` (349 lines)

The `DecisionEngine` produces risk verdicts from normalized findings:

**Core Logic**:
```python
def evaluate(self, submission: Mapping[str, Any]) -> DecisionOutcome:
    findings = submission.get("findings") or []
    verdict, confidence = self._score_findings(findings)
    compliance = self._compliance.evaluate(...)
    evidence = self._evidence_store.create(evidence_payload)
    self._apply_signature(evidence)
    return DecisionOutcome(...)
```

**Verdict Mapping**:
- `allow`: Aggregate risk score < 0.6
- `review`: Aggregate risk score 0.6-0.85
- `block`: Aggregate risk score >= 0.85

**Severity Weights**:
```python
SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
}
```

**Top Factors Analysis**:
1. **Severity Factor**: Highest severity detected with finding count
2. **Compliance Factor**: Framework gaps and coverage percentages
3. **Exploit Factor**: KEV overlap and operational pressure metrics

### 3. Enhanced Decision Engine

**Location**: `fixops-enterprise/src/services/enhanced_decision_engine.py`

Multi-LLM consensus engine that:

- Queries multiple LLM providers (GPT-5, Claude-3, Gemini-2, specialized cyber models)
- Aggregates verdicts with confidence scoring
- Detects disagreements and escalates when consensus < 50%
- Enriches with MITRE ATT&CK mappings
- Generates narrative explanations

**Configuration** (from `config/fixops.overlay.yml`):
```yaml
enhanced_decision:
  baseline_confidence: 0.82
  providers:
    - name: gpt-5
      style: strategist
      focus: [mitre, context]
    - name: claude-3
      style: analyst
      focus: [compliance, guardrails]
    - name: gemini-2
      style: signals
      focus: [exploit, cnapp]
    - name: sentinel-cyber
      style: threat
      focus: [marketplace, agents]
```

### 4. Input Normalizers

**Location**: `apps/api/normalizers.py`

The `InputNormalizer` class handles multi-format parsing:

**Supported Formats**:
- **SBOM**: CycloneDX, SPDX, GitHub Dependency Snapshot, Syft JSON
- **SARIF**: SARIF 2.1.0 with normalized severity levels from:
  - **SAST**: SonarQube, Veracode
  - **SCA**: SNYK, Veracode
  - **DAST**: Invicti, Veracode
  - **API Security**: SALT
  - **ADR**: Contrast Security (Application Detection and Response)
- **CVE**: CISA KEV format, custom CVE feeds
- **VEX**: Vulnerability Exploitability eXchange documents
- **CNAPP**: Cloud-Native Application Protection Platform findings from:
  - **CNAPP**: WIZ, Palo Alto Prisma Cloud, CrowdStrike, SentinelOne
  - **CWPP**: Orca Security (Cloud Workload Protection Platform)
  - **CSPM**: Tenable, Rapid7 (Cloud Security Posture Management)
  - **DSPM**: Sentra (Data Security Posture Management)
  - **EDR**: Microsoft Defender (Endpoint Detection and Response)
- **Business Context**: SSVC YAML, OTM JSON, core.yaml

**Key Methods**:
```python
def load_sbom(self, raw_bytes: bytes) -> NormalizedSBOM
def load_sarif(self, raw_bytes: bytes) -> NormalizedSARIF
def load_cve_feed(self, raw_bytes: bytes) -> NormalizedCVEFeed
def load_vex(self, raw_bytes: bytes) -> NormalizedVEX
def load_cnapp(self, raw_bytes: bytes) -> NormalizedCNAPP
def load_business_context(self, raw_bytes: bytes, content_type: Optional[str]) -> NormalizedBusinessContext
```

### 5. Crosswalk Engine

**Location**: `services/match/join.py`

The crosswalk engine correlates data across sources:

**Matching Strategy**:
1. Build component index from SBOM (by name, purl, version)
2. Build finding index from SARIF (by file path, component tokens)
3. Build CVE index from feeds (by component name, version)
4. Join design rows with matched components, findings, and CVEs

**Output**: `CrosswalkRow` objects containing:
- Design row (business context)
- SBOM component (supply chain data)
- SARIF findings (security issues)
- CVE records (vulnerability data)
- Business context (criticality, exposure, data classification)

### 6. Evidence Lake

**Location**: `fixops-enterprise/src/services/evidence.py`

Immutable storage for cryptographically-signed decision records:

**Features**:
- RSA-SHA256 signatures with public key fingerprints
- Configurable retention periods (90 days demo, 2555 days enterprise)
- Optional Fernet encryption for sensitive data
- Atomic writes with transparency indices

**Evidence Bundle Structure**:
```json
{
  "payload": {
    "findings": [...],
    "verdict": "allow",
    "confidence": 0.85,
    "compliance": {...},
    "top_factors": [...]
  },
  "signature": "base64_encoded_rsa_signature",
  "algorithm": "RSA-SHA256",
  "fingerprint": "public_key_sha256",
  "signed_at": "2025-10-19T12:00:00Z"
}
```

### 7. Vector Store

**Location**: `core/vector_store.py`

Pattern-matching system using sentence transformers:

**Implementations**:
- `DemoVectorStore`: In-memory with 4 sample patterns
- `ChromaDBVectorStore`: Persistent vector database

**Configuration**:
```yaml
modules:
  vector_store:
    enabled: true
    provider: auto  # auto, demo, chromadb
    patterns_path: fixtures/security_patterns.json
    top_k: 3
```

**Usage**:
```python
matcher = SecurityPatternMatcher(config, root=repo_root)
results = matcher.search_security_patterns(query, top_k=5)
```

### 8. Exploit Intelligence

**Location**: `core/exploit_signals.py`

Manages vulnerability intelligence feeds:

**Data Sources**:
- **CISA KEV**: Known Exploited Vulnerabilities (1,422+ CVEs)
  - Source: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **FIRST.org EPSS**: Exploit Prediction Scoring System (296,333+ CVEs)
  - Source: `https://api.first.org/data/v1/epss`

**Auto-Refresh**:
- Scheduled daily refresh via APScheduler
- Configurable via `exploit_signals.auto_refresh.enabled`
- Offline mode support for air-gapped environments

**Escalation Rules**:
```yaml
exploit_signals:
  signals:
    - type: kev
      field: kev
      escalate_to: critical
    - type: epss
      field: epss
      threshold: 0.7
      escalate_to: high
```

### 9. Compliance Engine

**Location**: `core/compliance.py`

Evaluates compliance against multiple frameworks:

**Supported Frameworks**:
- **SOC2**: CC6.1, CC6.6, CC7.2, CC8.1
- **ISO27001**: A.12.6.1, A.14.2.8
- **PCI-DSS**: 6.2, 6.5.1, 6.5.3, 6.5.8, 11.2, 11.3
- **GDPR**: Article 25, Article 32

**Control Mapping**:
```yaml
compliance:
  frameworks:
    - name: SOC2
      controls:
        - id: CC8.1
          title: Change Management Evidence
          requires: [design, guardrails, evidence]
        - id: CC7.2
          title: Continuous Vulnerability Management
          requires: [sarif, cve, context]
```

**Output**:
```json
{
  "frameworks": [
    {
      "name": "SOC2",
      "controls": [
        {
          "id": "CC8.1",
          "title": "Change Management Evidence",
          "status": "satisfied",
          "coverage": 1.0
        }
      ]
    }
  ],
  "gaps": ["PCI_DSS:6.5.1"],
  "evidence_refs": [...]
}
```

### 10. Policy Automation

**Location**: `core/policy.py`

Trigger-action system for automated remediation:

**Supported Actions**:
- Jira issue creation
- Confluence page generation
- Slack message posting

**Configuration**:
```yaml
policy_automation:
  actions:
    - id: jira-guardrail-fail
      trigger: guardrail:fail
      type: jira_issue
      summary: Guardrail failure detected
      priority: High
    - id: confluence-guardrail-warn
      trigger: guardrail:warn
      type: confluence_page
      title: FixOps guardrail warning summary
```

**Connectors**:
- `JiraConnector`: Creates issues via Jira REST API
- `ConfluenceConnector`: Creates/updates pages via Confluence REST API
- `SlackConnector`: Posts messages via Slack webhooks

---

## Data Flow & Processing

### End-to-End Pipeline Flow

```
1. INGESTION
   ├─ Upload artifacts via API (/inputs/design, /inputs/sbom, /inputs/sarif, /inputs/cve)
   ├─ Or provide local files via CLI (--design, --sbom, --sarif, --cve)
   └─ Validate MIME types, size limits, API keys

2. NORMALIZATION
   ├─ Parse SBOM (CycloneDX/SPDX/GitHub/Syft)
   ├─ Parse SARIF 2.1.0 with severity normalization
   ├─ Parse CVE feeds (CISA KEV format)
   ├─ Parse VEX documents (optional)
   ├─ Parse CNAPP findings (optional)
   └─ Parse business context (SSVC/OTM/core.yaml)

3. CORRELATION
   ├─ Build component index from SBOM
   ├─ Build finding index from SARIF
   ├─ Build CVE index from feeds
   ├─ Match design rows to components
   ├─ Match findings to components
   ├─ Match CVEs to components
   └─ Generate crosswalk rows

4. ENRICHMENT
   ├─ Merge KEV/EPSS data into CVE records
   ├─ Apply exploit signal escalation rules
   ├─ Inject business context (criticality, exposure, data classification)
   ├─ Apply VEX suppressions (if provided)
   └─ Merge CNAPP findings (if provided)

5. DECISION ENGINE
   ├─ Vector Store: Search for similar security patterns
   ├─ Policy Engine: Evaluate OPA rules
   ├─ Multi-LLM: Query GPT-5, Claude-3, Gemini-2
   ├─ Consensus Checker: Aggregate verdicts with confidence
   ├─ Golden Regression: Compare against historical baseline
   └─ SBOM Analysis: Assess supply chain risk

6. MODULE EXECUTION
   ├─ Context Engine: Enrich with business signals
   ├─ Guardrails: Evaluate maturity thresholds
   ├─ Compliance: Map to SOC2/ISO27001/PCI-DSS/GDPR
   ├─ SSDLC: Score plan→audit stages
   ├─ IaC Posture: Map Terraform/K8s findings
   ├─ Exploit Signals: Refresh KEV/EPSS feeds
   ├─ Probabilistic: Bayesian/Markov forecasting
   ├─ AI Agents: Detect agentic frameworks
   ├─ Analytics: Compute ROI metrics
   ├─ Tenancy: Manage tenant lifecycle
   ├─ Performance: Simulate capacity
   └─ Knowledge Graph: Map attack paths

7. EVIDENCE & AUTOMATION
   ├─ Evidence Lake: Store signed decision records
   ├─ Artifact Archive: Compress and encrypt bundles
   ├─ Policy Automation: Dispatch Jira/Confluence/Slack
   ├─ Provenance Graph: Generate RSA-signed evidence bundles (SLSA attestations roadmap)
   └─ Transparency Index: Record audit trail

8. RESPONSE
   ├─ Return JSON with severity overview, guardrail status, compliance coverage
   ├─ Include evidence bundle paths, automation manifests, module matrix
   └─ Provide sanitized overlay metadata (demo mode only)
```

### Severity Normalization

**SARIF Level Mapping**:
```python
{
    "none": "low",
    "note": "low",
    "info": "low",
    "warning": "medium",
    "error": "high"
}
```

**CVE Severity Mapping**:
```python
{
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low"
}
```

**Unified Severity Order**: `low < medium < high < critical`

---

## Module Ecosystem

### Core Modules

#### 1. Context Engine
**File**: `core/context_engine.py`

Enriches findings with business context:

**Input Factors**:
- Criticality (1-5 scale)
- Data classification (PII, financial, health, internal, public)
- Exposure (internet, partner, internal)

**Weighting**:
```yaml
context_engine:
  criticality_weights:
    mission_critical: 4
    external: 3
    internal: 1
  data_weights:
    pii: 4
    financial: 4
    health: 4
    internal: 2
    public: 1
  exposure_weights:
    internet: 3
    partner: 2
    internal: 1
```

**Playbooks**:
```yaml
playbooks:
  - name: Stabilise Customer Impact
    min_score: 9
    channel: sre-pager
  - name: Sprint Triage
    min_score: 6
    channel: appsec-kanban
  - name: Monitor
    min_score: 0
    channel: platform-notifications
```

#### 2. Guardrails

Maturity-level enforcement:

**Profiles**:
- **Foundational**: Fail on critical, warn on high
- **Scaling**: Fail on high, warn on medium
- **Advanced**: Fail on medium, warn on medium

**Configuration**:
```yaml
guardrails:
  maturity: scaling
  profiles:
    foundational: { fail_on: critical, warn_on: high }
    scaling: { fail_on: high, warn_on: medium }
    advanced: { fail_on: medium, warn_on: medium }
```

#### 3. SSDLC Evaluator
**File**: `core/ssdlc.py`

Scores Software Development Lifecycle stages:

**Stages**:
- Requirements
- Design
- Build
- Test
- Deploy
- Operate
- Decision

**Output**: Stage coverage map, control gaps, risk scores

#### 4. IaC Posture
**File**: `core/iac.py`

Infrastructure-as-Code evaluation:

**Supported Formats**:
- Terraform plans
- Kubernetes manifests

**Output**: Matched targets, missing artifacts, unmatched components

#### 5. Probabilistic Forecasting
**File**: `core/probabilistic.py`

Bayesian and Markov chain risk projection:

**Features**:
- Dirichlet-smoothed calibration
- Spectral gap diagnostics
- Stationary distribution analysis
- Multi-step projections

**Metrics**:
- `spectral_gap`: Convergence rate
- `mixing_time`: Time to steady state
- `critical_horizon_risk`: Probability of critical incident

#### 6. AI Agent Advisor
**File**: `core/ai_agents.py`

Detects agentic frameworks and prescribes controls:

**Detected Frameworks**:
- LangChain
- AutoGPT
- BabyAGI
- Custom agent patterns

**Output**: Agent detection notes, control guidance

#### 7. Analytics
**File**: `core/analytics.py`

ROI and performance metrics:

**Metrics**:
- Cost savings
- MTTR (Mean Time To Remediation) deltas
- Executive KPIs
- Throughput predictions

#### 8. Tenancy
**File**: `core/tenancy.py`

Multi-tenant lifecycle management:

**Features**:
- Stage transitions
- Module gap analysis
- Onboarding guidance

#### 9. Performance Simulator
**File**: `core/performance.py`

Capacity planning and backlog predictions:

**Inputs**:
- Overlay latency targets
- Benchmark profiles

**Outputs**:
- Backlog predictions
- Throughput advice

#### 10. Knowledge Graph
**File**: `apps/api/knowledge_graph.py`

Attack path and entity relationship mapping:

**Node Types**:
- Service (asset)
- Finding (vulnerability)
- Control (compliance)
- Mitigation (playbook)

**Edge Types**:
- `impacted_by`: Service → Finding
- `mitigated_by`: Finding → Control
- `remediated_by`: Finding → Mitigation

---

## API Reference

### FastAPI Ingestion Service

**Base URL**: `http://localhost:8000` (default)

**Authentication**: All endpoints require `X-API-Key` header

### Ingestion Endpoints

#### Upload Design Context
```http
POST /inputs/design
Content-Type: multipart/form-data
X-API-Key: {token}

file: design.csv
```

**Design CSV Format**:
```csv
component_id,service,owner,criticality,name
comp-001,payment-api,platform-team,5,Payment Gateway
comp-002,user-service,identity-team,4,User Authentication
```

#### Upload SBOM
```http
POST /inputs/sbom
Content-Type: multipart/form-data
X-API-Key: {token}

file: sbom.json
```

**Supported Formats**: CycloneDX, SPDX, GitHub Dependency Snapshot, Syft JSON

#### Upload SARIF Scan
```http
POST /inputs/sarif
Content-Type: multipart/form-data
X-API-Key: {token}

file: scan.sarif
```

**SARIF Version**: 2.1.0

#### Upload CVE Feed
```http
POST /inputs/cve
Content-Type: multipart/form-data
X-API-Key: {token}

file: cve.json
```

**Format**: CISA KEV or custom CVE feed

### Pipeline Execution

#### Run Pipeline
```http
POST /pipeline/run
X-API-Key: {token}
```

**Response**:
```json
{
  "severity_overview": {
    "highest": "high",
    "counts": {
      "critical": 2,
      "high": 15,
      "medium": 42,
      "low": 103
    },
    "source_breakdown": {
      "sarif": {"high": 10, "medium": 30},
      "cve": {"critical": 2, "high": 5}
    }
  },
  "guardrail_evaluation": {
    "maturity": "scaling",
    "policy": {"fail_on": "high", "warn_on": "medium"},
    "highest_detected": "high",
    "status": "fail",
    "rationale": ["highest severity 'high' meets fail threshold 'high'"]
  },
  "context_summary": {
    "enriched_components": 25,
    "playbooks_recommended": ["Stabilise Customer Impact"]
  },
  "compliance_status": {
    "frameworks": [
      {
        "name": "SOC2",
        "controls": [
          {"id": "CC8.1", "status": "satisfied", "coverage": 1.0}
        ]
      }
    ],
    "gaps": []
  },
  "policy_summary": {
    "actions": [
      {
        "id": "jira-guardrail-fail",
        "type": "jira_issue",
        "status": "executed",
        "ticket_key": "SEC-1234"
      }
    ]
  },
  "evidence_bundle": {
    "files": {
      "bundle": "data/evidence/enterprise/bundle_20251019_120000.tar.gz"
    },
    "retention_days": 2555
  },
  "module_matrix": {
    "guardrails": {"enabled": true, "executed": true},
    "context_engine": {"enabled": true, "executed": true},
    "compliance": {"enabled": true, "executed": true},
    "policy_automation": {"enabled": true, "executed": true}
  }
}
```

### Enterprise Endpoints

#### Enhanced Decision Analysis
```http
POST /api/v1/enhanced/analysis
Content-Type: application/json
X-API-Key: {token}

{
  "service_name": "payment-api",
  "security_findings": [
    {
      "rule_id": "SAST001",
      "severity": "high",
      "description": "SQL injection vulnerability"
    }
  ],
  "business_context": {
    "environment": "production",
    "criticality": "high"
  }
}
```

**Response**:
```json
{
  "models": [
    {
      "provider": "gpt-5",
      "verdict": "block",
      "confidence": 0.92,
      "rationale": "SQL injection in production payment system poses critical risk"
    },
    {
      "provider": "claude-3",
      "verdict": "block",
      "confidence": 0.89,
      "rationale": "High severity finding in critical service requires immediate remediation"
    }
  ],
  "consensus": {
    "verdict": "block",
    "confidence": 0.905,
    "method": "weighted_average",
    "agreement": 1.0
  },
  "mitre_mapping": ["T1190"],
  "compliance_impact": ["PCI_DSS:6.5.1"],
  "knowledge_graph": {
    "attack_paths": [
      ["payment-api", "database", "customer-data"]
    ]
  }
}
```

#### Compare LLM Models
```http
POST /api/v1/enhanced/compare-llms
Content-Type: application/json
X-API-Key: {token}

{
  "service_name": "user-service",
  "security_findings": [...]
}
```

**Response**: Individual model verdicts with disagreement analysis

#### Get Enhanced Capabilities
```http
GET /api/v1/enhanced/capabilities
X-API-Key: {token}
```

**Response**:
```json
{
  "llm_providers": ["gpt-5", "claude-3", "gemini-2", "sentinel-cyber"],
  "mitre_coverage": true,
  "compliance_frameworks": ["SOC2", "ISO27001", "PCI_DSS", "GDPR"],
  "knowledge_graph_enabled": true,
  "consensus_methods": ["weighted_average", "majority_vote"]
}
```

### Chunked Upload Endpoints

#### Initialize Chunked Upload
```http
POST /api/v1/scans/upload/init
Content-Type: application/json
X-API-Key: {token}

{
  "file_name": "large-sbom.json",
  "total_size": 52428800,
  "scan_type": "sbom"
}
```

**Response**:
```json
{
  "upload_id": "upload_abc123",
  "chunk_size": 5242880
}
```

#### Upload Chunk
```http
POST /api/v1/scans/upload/chunk
Content-Type: multipart/form-data
X-API-Key: {token}

upload_id: upload_abc123
chunk_index: 0
chunk: <binary data>
```

#### Complete Chunked Upload
```http
POST /api/v1/scans/upload/complete
Content-Type: application/json
X-API-Key: {token}

{
  "upload_id": "upload_abc123"
}
```

---

## CLI Tools

### Main CLI: `core.cli`

**Entry Point**: `python -m core.cli`

### Commands

#### Run Pipeline
```bash
python -m core.cli run \
  --overlay config/fixops.overlay.yml \
  --design artefacts/design.csv \
  --sbom artefacts/sbom.json \
  --sarif artefacts/scan.sarif \
  --cve artefacts/cve.json \
  --output out/pipeline.json \
  --evidence-dir out/evidence \
  --pretty
```

**Options**:
- `--overlay PATH`: Path to overlay configuration (default: `config/fixops.overlay.yml`)
- `--design PATH`: Design context CSV
- `--sbom PATH`: SBOM JSON file
- `--sarif PATH`: SARIF scan results
- `--cve PATH`: CVE feed JSON
- `--vex PATH`: VEX document (optional)
- `--cnapp PATH`: CNAPP findings (optional)
- `--context PATH`: Business context file (optional)
- `--output PATH`: Output JSON file
- `--evidence-dir PATH`: Evidence bundle directory
- `--pretty`: Pretty-print JSON output
- `--offline`: Disable exploit feed refresh
- `--enable MODULE`: Enable specific module
- `--disable MODULE`: Disable specific module

#### Make Decision
```bash
python -m core.cli make-decision \
  --sbom artefacts/sbom.json \
  --sarif artefacts/scan.sarif \
  --output out/decision.json
```

**Exit Codes**:
- `0`: Allow/Pass/OK
- `1`: Block/Fail
- `2`: Defer/Warn/Unknown

#### Demo Mode
```bash
# Demo profile
python -m core.cli demo --mode demo --output out/demo.json --pretty

# Enterprise profile
python -m core.cli demo --mode enterprise --output out/enterprise.json --pretty
```

**Features**:
- Seeds deterministic tokens
- Loads curated fixtures
- Executes full pipeline
- Emits evidence bundles

#### Show Overlay
```bash
python -m core.cli show-overlay \
  --overlay config/fixops.overlay.yml \
  --pretty
```

**Output**: Sanitized overlay metadata with runtime warnings

#### Health Check
```bash
python -m core.cli health \
  --overlay config/fixops.overlay.yml \
  --pretty
```

**Checks**:
- Overlay mode
- Library availability (pgmpy, pomegranate, mchmm)
- Evidence hub readiness
- OPA configuration

#### Train Forecast
```bash
python -m core.cli train-forecast \
  --incidents data/examples/incidents.json \
  --output out/forecast.json \
  --pretty
```

**Output**: Bayesian priors, Markov transitions, spectral diagnostics

### Stage Runner CLI: `apps.fixops_cli`

**Entry Point**: `python -m apps.fixops_cli stage-run`

#### Run SSDLC Stage
```bash
python -m apps.fixops_cli stage-run \
  --stage requirements \
  --input simulations/demo_pack/requirements-input.csv \
  --app life-claims-portal
```

**Stages**:
- `requirements`: Requirements analysis
- `design`: Design context ingestion
- `build`: Build artifact processing (SBOM)
- `test`: Test result analysis (SARIF)
- `deploy`: Deployment manifest generation (Terraform/K8s)
- `operate`: Operational posture assessment
- `decision`: Final decision rendering

**Output**: Canonical JSON under `artefacts/<app_id>/<run_id>/outputs/`

---

## Configuration System

### Overlay Configuration

**File**: `config/fixops.overlay.yml` (240 lines)

The overlay system provides dual-mode operation (demo vs enterprise) with runtime safeguards.

### Key Sections

#### Mode Selection
```yaml
mode: enterprise  # or demo
```

#### Authentication
```yaml
auth:
  strategy: token
  token_env: FIXOPS_API_TOKEN
  header: X-API-Key
```

#### Data Directories
```yaml
data:
  design_context_dir: data/design_context
  evidence_dir: data/evidence
  archive_dir: data/archive
  analytics_dir: data/analytics
  automation_dir: data/automation
  feedback_dir: data/feedback
```

#### Upload Limits
```yaml
limits:
  max_upload_bytes:
    default: 3145728      # 3 MB
    sarif: 6291456        # 6 MB
    cve: 6291456          # 6 MB
  evidence:
    bundle_max_bytes: 1048576  # 1 MB
    compress: true
    encrypt: true
    encryption_env: FIXOPS_EVIDENCE_KEY
```

#### Module Toggles
```yaml
modules:
  guardrails: { enabled: true }
  context_engine: { enabled: true }
  compliance: { enabled: true }
  policy_automation: { enabled: true }
  evidence: { enabled: true }
  ssdlc: { enabled: true }
  iac_posture: { enabled: true }
  exploit_signals: { enabled: true }
  probabilistic: { enabled: true }
  ai_agents: { enabled: true }
  analytics: { enabled: true }
  tenancy: { enabled: true }
  performance: { enabled: true }
  vector_store:
    enabled: true
    provider: auto  # auto, demo, chromadb
    patterns_path: fixtures/security_patterns.json
    top_k: 3
  enhanced_decision: { enabled: true }
```

#### Guardrails
```yaml
guardrails:
  maturity: scaling
  profiles:
    foundational: { fail_on: critical, warn_on: high }
    scaling: { fail_on: high, warn_on: medium }
    advanced: { fail_on: medium, warn_on: medium }
```

#### Context Engine
```yaml
context_engine:
  fields:
    criticality: customer_impact
    data: data_classification
    exposure: exposure
  criticality_weights:
    mission_critical: 4
    external: 3
    internal: 1
  data_weights:
    pii: 4
    financial: 4
    health: 4
    internal: 2
    public: 1
  exposure_weights:
    internet: 3
    partner: 2
    internal: 1
  playbooks:
    - name: Stabilise Customer Impact
      min_score: 9
      channel: sre-pager
    - name: Sprint Triage
      min_score: 6
      channel: appsec-kanban
```

#### Compliance Frameworks
```yaml
compliance:
  frameworks:
    - name: SOC2
      controls:
        - id: CC8.1
          title: Change Management Evidence
          requires: [design, guardrails, evidence]
        - id: CC7.2
          title: Continuous Vulnerability Management
          requires: [sarif, cve, context]
    - name: ISO27001
      controls:
        - id: A.12.6.1
          title: Application vulnerability management
          requires: [sbom, cve]
    - name: PCI_DSS
      controls:
        - id: "6.2"
          title: Ensure all system components are protected
          requires: [sbom, cve, guardrails]
    - name: GDPR
      controls:
        - id: Article_32
          title: Security of Processing
          requires: [design, evidence, guardrails]
```

#### Policy Automation
```yaml
policy_automation:
  actions:
    - id: jira-guardrail-fail
      trigger: guardrail:fail
      type: jira_issue
      summary: Guardrail failure detected
      priority: High
    - id: confluence-guardrail-warn
      trigger: guardrail:warn
      type: confluence_page
      title: FixOps guardrail warning summary
```

#### Integrations
```yaml
jira:
  url: https://jira.example.com
  project_key: SEC
  default_issue_type: Task
  user_email: bot@fixops.local
  token_env: FIXOPS_JIRA_TOKEN

confluence:
  base_url: https://confluence.example.com
  space_key: SECOPS
  user: fixops-bot
  token_env: FIXOPS_CONFLUENCE_TOKEN
```

#### Enhanced Decision Engine
```yaml
enhanced_decision:
  baseline_confidence: 0.82
  providers:
    - name: gpt-5
      style: strategist
      focus: [mitre, context]
    - name: claude-3
      style: analyst
      focus: [compliance, guardrails]
    - name: gemini-2
      style: signals
      focus: [exploit, cnapp]
    - name: sentinel-cyber
      style: threat
      focus: [marketplace, agents]
  knowledge_graph:
    nodes:
      - { id: service, type: asset }
      - { id: finding, type: vulnerability }
      - { id: control, type: compliance }
      - { id: mitigation, type: playbook }
    edges:
      - { source: service, target: finding, type: impacted_by }
      - { source: finding, target: control, type: mitigated_by }
      - { source: finding, target: mitigation, type: remediated_by }
```

### Runtime Safeguards

**Location**: `core/overlay_runtime.py`

The `prepare_overlay()` function applies runtime safeguards:

**Auto-Disables**:
- Evidence encryption if `cryptography.fernet` unavailable or `FIXOPS_EVIDENCE_KEY` missing
- Policy automation if connector credentials missing (`FIXOPS_JIRA_TOKEN`, `FIXOPS_CONFLUENCE_TOKEN`)

**Generates Warnings**:
- "Evidence encryption disabled (Fernet unavailable)"
- "Jira token missing"
- "Confluence token missing"

**Access Warnings**:
```python
overlay = prepare_overlay(path="config/fixops.overlay.yml")
warnings = overlay.metadata.get("runtime_warnings", [])
```

---

## Security & Cryptography

### Signing Provider

**Location**: `fixops-enterprise/src/services/signing.py`

Abstraction for cryptographic key management:

**Supported Providers**:
- `env`: Environment variables (`SIGNING_PRIVATE_KEY`, `SIGNING_PUBLIC_KEY`)
- `aws`: AWS KMS
- `azure`: Azure Key Vault
- `hsm`: Hardware Security Module

**Configuration**:
```bash
export SIGNING_PROVIDER=env
export SIGNING_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."
export SIGNING_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----..."
export KEY_ID="fixops-signing-key-v1"
```

**Methods**:
```python
def sign_manifest(payload: dict) -> dict:
    """Sign payload with RSA-SHA256"""
    
def verify_signature(payload: dict, signature: str, public_key: str) -> bool:
    """Verify RSA-SHA256 signature"""
    
def get_active_kid() -> str:
    """Get active key ID"""
    
def rotate_key() -> None:
    """Rotate signing key"""
```

### Evidence Encryption

**Algorithm**: Fernet (symmetric encryption with AES)

**Key Generation**:
```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()  # Returns base64-encoded key
```

**Configuration**:
```bash
export FIXOPS_EVIDENCE_KEY="<base64_fernet_key>"
```

**Auto-Disable**: If `cryptography` library unavailable or key not set

### Evidence Signing & Provenance

**Location**: `services/provenance/attestation.py`

**Current Implementation**: RSA-SHA256 signed evidence bundles with public key fingerprints

**Roadmap**: SLSA v1 build provenance attestations (planned)

**Structure**:
```json
{
  "subject": {
    "name": "myapp.tar.gz",
    "digest": {"sha256": "abc123..."}
  },
  "predicate": {
    "builder": {"id": "https://github.com/DevOpsMadDog/Fixops"},
    "materials": [
      {"uri": "git+https://github.com/...", "digest": {"sha1": "..."}}
    ],
    "metadata": {
      "buildStartedOn": "2025-10-19T12:00:00Z",
      "buildFinishedOn": "2025-10-19T12:05:00Z"
    }
  }
}
```

**CLI**:
```bash
fixops-provenance attest --artifact myapp.tar.gz
fixops-provenance verify --artifact myapp.tar.gz --attestation att.json
```

### Transparency Index

**Location**: Evidence bundles include `transparency.index`

**Format**:
```json
{
  "entries": [
    {
      "timestamp": "2025-10-19T12:00:00Z",
      "evidence_id": "evidence_abc123",
      "fingerprint": "sha256:def456...",
      "signature": "base64_encoded..."
    }
  ]
}
```

---

## Installation & Setup

### Prerequisites

- Python 3.10+ (tested with CPython 3.11)
- `pip` and `virtualenv`
- Optional: `uvicorn` for FastAPI
- Optional: `cryptography` for evidence encryption

### Quick Start

```bash
# Clone repository
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Configure credentials
export FIXOPS_API_TOKEN="demo-token"
export FIXOPS_EVIDENCE_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Run demo
python -m core.cli demo --mode demo --output out/demo.json --pretty
```

### Bootstrap Script

```bash
./scripts/bootstrap.sh
```

**Actions**:
- Creates `.venv`
- Installs runtime + dev dependencies
- Configures pre-commit hooks
- Sets up test fixtures

### Launch FastAPI Service

```bash
# Demo mode
export FIXOPS_API_TOKEN="demo-token"
uvicorn apps.api.app:create_app --factory --reload

# Enterprise mode
export FIXOPS_API_TOKEN="<secure-token>"
export FIXOPS_JIRA_TOKEN="<jira-token>"
export FIXOPS_CONFLUENCE_TOKEN="<confluence-token>"
export FIXOPS_EVIDENCE_KEY="<fernet-key>"
uvicorn apps.api.app:create_app --factory --reload --port 8000
```

### Telemetry Configuration

**Default**: Exports to OpenTelemetry collector at `http://collector:4318`

**Disable**:
```bash
export FIXOPS_DISABLE_TELEMETRY=1
```

**Custom Endpoint**:
```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://my-collector:4318"
```

### Docker Compose (Demo)

```bash
docker compose -f docker-compose.demo.yml up -d
```

**Services**:
- FastAPI ingestion service (port 8000)
- OpenTelemetry collector (port 4318)

---

## Development Workflow

### Code Style

- Follow PEP 8 conventions
- Use Google-style docstrings
- Format with Ruff/Black
- Type hints encouraged (mypy configuration in `mypy.ini`)

### Pre-Commit Hooks

```bash
pre-commit run --all-files
```

**Hooks**:
- Ruff/Black formatting
- mypy type checking
- detect-secrets scanning

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_cli.py

# With coverage
pytest --cov --cov-branch --cov-fail-under=80

# Specific markers
pytest tests/test_context_engine.py -k "enterprise"
```

### Test Organization

- `tests/test_cli.py`: CLI command validation
- `backend_test.py`: API endpoint comprehensive testing (100+ tests)
- `real_components_test.py`: Integration testing (Vector Store, OPA, Evidence Lake)
- `test_frontend.py`: UI accessibility and navigation
- `test_overlay_*.py`: Configuration validation

### Linting

```bash
# Syntax validation
python -m compileall backend fixops simulations tests

# Ruff check
ruff check .

# Type checking
python -m mypy --config-file mypy.ini core apps scripts
```

### Adding New Modules

1. Create module file in `core/` (e.g., `core/custom_module.py`)
2. Add configuration to `config/fixops.overlay.yml`:
   ```yaml
   modules:
     custom_module:
       enabled: true
       config_key: value
   ```
3. Implement module logic following existing patterns
4. Register in `apps/api/pipeline.py` or extend via `modules.custom` spec
5. Add tests in `tests/test_custom_module.py`

### Debugging

**Enable Debug Logging**:
```bash
export LOG_LEVEL=DEBUG
python -m core.cli run ...
```

**Inspect Overlay**:
```bash
python -m core.cli show-overlay --pretty
```

**Health Check**:
```bash
python -m core.cli health --pretty
```

---

## Testing Strategy

### Test Coverage Goals

- **Core Modules**: 80%+ coverage
- **API Endpoints**: 100% route coverage
- **Integration Tests**: All major workflows

### Test Fixtures

**Location**: `tests/fixtures/`, `simulations/demo_pack/`

**Curated Fixtures**:
- `design-input.csv`: Sample design context
- `sbom.json`: CycloneDX SBOM
- `scanner.sarif`: SARIF 2.1.0 findings
- `cve.json`: CISA KEV feed sample

### Running Simulations

```bash
# CVE scenario (Log4Shell)
python simulations/cve_scenario/runner.py --mode demo
python simulations/cve_scenario/runner.py --mode enterprise

# SSDLC stages
python simulations/ssdlc/run.py
```

### Continuous Integration

**GitHub Actions**: `.github/workflows/qa.yml`

**Checks**:
- Pytest suite
- Code coverage
- Linting (Ruff)
- Type checking (mypy)
- Secret scanning (detect-secrets)

---

## Deployment Patterns

### Deployment Options

1. **Standalone CLI**: Local execution without external dependencies
2. **FastAPI Service**: Containerized API for CI/CD integration
3. **Enterprise Stack**: Full deployment with database, frontend, and integrations

### Container Deployment

**Dockerfile** (example):
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "apps.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
```

**Build & Run**:
```bash
docker build -t fixops:latest .
docker run -p 8000:8000 \
  -e FIXOPS_API_TOKEN="secure-token" \
  -e FIXOPS_EVIDENCE_KEY="fernet-key" \
  fixops:latest
```

### Kubernetes Deployment

**Deployment Manifest** (example):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fixops
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fixops
  template:
    metadata:
      labels:
        app: fixops
    spec:
      containers:
      - name: fixops
        image: fixops:latest
        ports:
        - containerPort: 8000
        env:
        - name: FIXOPS_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: fixops-secrets
              key: api-token
        - name: FIXOPS_EVIDENCE_KEY
          valueFrom:
            secretKeyRef:
              name: fixops-secrets
              key: evidence-key
```

### CI/CD Integration

**GitHub Actions Example**:
```yaml
name: FixOps Security Gate

on: [push, pull_request]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Generate SBOM
        run: syft . -o cyclonedx-json > sbom.json
      
      - name: Run SARIF Scan
        run: semgrep --config auto --sarif > scan.sarif
      
      - name: FixOps Decision
        run: |
          python -m core.cli make-decision \
            --sbom sbom.json \
            --sarif scan.sarif \
            --output decision.json
        env:
          FIXOPS_API_TOKEN: ${{ secrets.FIXOPS_API_TOKEN }}
      
      - name: Check Decision
        run: |
          VERDICT=$(jq -r '.decision' decision.json)
          if [ "$VERDICT" = "block" ]; then
            echo "Security gate failed"
            exit 1
          fi
```

---

## Integration Guides

### Jira Integration

**Configuration**:
```yaml
jira:
  url: https://jira.example.com
  project_key: SEC
  default_issue_type: Task
  user_email: bot@fixops.local
  token_env: FIXOPS_JIRA_TOKEN
```

**Environment**:
```bash
export FIXOPS_JIRA_TOKEN="<jira-api-token>"
```

**Trigger**:
```yaml
policy_automation:
  actions:
    - id: jira-guardrail-fail
      trigger: guardrail:fail
      type: jira_issue
      summary: Guardrail failure detected
      priority: High
```

### Confluence Integration

**Configuration**:
```yaml
confluence:
  base_url: https://confluence.example.com
  space_key: SECOPS
  user: fixops-bot
  token_env: FIXOPS_CONFLUENCE_TOKEN
```

**Environment**:
```bash
export FIXOPS_CONFLUENCE_TOKEN="<confluence-api-token>"
```

**Trigger**:
```yaml
policy_automation:
  actions:
    - id: confluence-guardrail-warn
      trigger: guardrail:warn
      type: confluence_page
      title: FixOps guardrail warning summary
```

### Slack Integration

**Configuration** (add to overlay):
```yaml
slack:
  webhook_url_env: FIXOPS_SLACK_WEBHOOK
  default_channel: "#security-alerts"
```

**Environment**:
```bash
export FIXOPS_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
```

### OPA Integration

**Configuration**:
```bash
export OPA_SERVER_URL="http://opa:8181"
export OPA_AUTH_TOKEN="<opa-token>"
export OPA_POLICY_PACKAGE="fixops.policies"
```

**Policy Example** (Rego):
```rego
package fixops.policies

default allow = false

allow {
    input.severity == "low"
}

allow {
    input.severity == "medium"
    input.environment != "production"
}

deny {
    input.severity == "critical"
}
```

---

## Troubleshooting

### Common Issues

#### 1. Evidence Encryption Disabled

**Symptom**: Warning "Evidence encryption disabled (Fernet unavailable)"

**Solution**:
```bash
pip install cryptography
export FIXOPS_EVIDENCE_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
```

#### 2. Jira Token Missing

**Symptom**: Warning "Jira token missing"

**Solution**:
```bash
export FIXOPS_JIRA_TOKEN="<your-jira-api-token>"
```

#### 3. Exploit Feed Refresh Fails

**Symptom**: Error fetching KEV/EPSS feeds

**Solution**:
```bash
# Disable auto-refresh for offline mode
python -m core.cli run --offline ...

# Or configure proxy
export HTTP_PROXY="http://proxy:8080"
export HTTPS_PROXY="http://proxy:8080"
```

#### 4. Vector Store Initialization Fails

**Symptom**: Error loading ChromaDB

**Solution**:
```bash
# Use demo vector store
# In config/fixops.overlay.yml:
modules:
  vector_store:
    provider: demo  # Instead of chromadb
```

#### 5. OPA Connection Timeout

**Symptom**: OPA health check fails

**Solution**:
```bash
# Increase timeout
export OPA_REQUEST_TIMEOUT=30

# Or disable OPA
# In config/fixops.overlay.yml:
modules:
  policy_engine:
    enabled: false
```

### Debug Mode

```bash
# Enable verbose logging
export LOG_LEVEL=DEBUG
export PYTHONPATH=.

# Run with debug output
python -m core.cli run --pretty ...
```

### Health Check

```bash
python -m core.cli health --pretty
```

**Output**:
```json
{
  "status": "ok",
  "checks": {
    "overlay_mode": "enterprise",
    "pgmpy_available": true,
    "pomegranate_available": false,
    "mchmm_available": true,
    "evidence_ready": true,
    "evidence_retention_days": 2555,
    "opa_configured": true
  }
}
```

---

## Contributing

### Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes and add tests
4. Run tests: `pytest`
5. Run linting: `ruff check .`
6. Commit changes: `git commit -m "Add my feature"`
7. Push to branch: `git push origin feature/my-feature`
8. Create Pull Request

### Pull Request Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Pre-commit hooks pass
- [ ] CI checks pass
- [ ] No secrets committed

### Code Review Guidelines

- Clear, descriptive commit messages
- Small, focused changes
- Comprehensive test coverage
- Updated documentation
- No breaking changes without discussion

### Reporting Issues

**Include**:
- Reproduction steps
- Sample artifacts (design CSV, SBOM snippet, SARIF finding)
- Active overlay mode and toggles
- Stack traces or response payloads
- Environment details (Python version, OS)

---

## License

See LICENSE file for details.

---

## Support

- **Documentation**: `docs/` directory
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

---

## Acknowledgments

FixOps integrates with and builds upon:

- **CISA KEV**: Known Exploited Vulnerabilities catalog
- **FIRST.org EPSS**: Exploit Prediction Scoring System
- **SLSA**: Supply-chain Levels for Software Artifacts (roadmap; current implementation uses RSA-SHA256 signatures)
- **SARIF**: Static Analysis Results Interchange Format
- **CycloneDX/SPDX**: SBOM standards
- **OPA**: Open Policy Agent
- **ChromaDB**: Vector database for embeddings

---

**Last Updated**: 2025-10-19

**Version**: 1.0.0

**Maintainer**: DevOpsMadDog

**Repository**: https://github.com/DevOpsMadDog/Fixops
