[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/DevOpsMadDog/Fixops)

# FixOps

**Enterprise DevSecOps Decision, Verification & Vulnerability Operations Platform**

*FixOps turns noisy security outputs into provable release decisions and verified remediation.*

FixOps is a comprehensive DevSecOps platform that operationalizes vulnerability management end-to-end. It ingests and normalizes security artifacts (SBOM, SARIF, CVE, VEX, CNAPP) plus business context, correlates and deduplicates findings into an application-centric **Risk Graph** (services → components → CVEs/findings with KEV/EPSS enrichment), and produces release-gate outcomes (Allow/Block/Needs Review) via policy evaluation, multi-LLM consensus, probabilistic forecasting, and explainable risk scoring. FixOps then verifies exploitability through reachability analysis and micro-pentest validation, operationalizes remediation with lifecycle/SLA tracking and bulk actions, and produces tamper-evident evidence and provenance (signed bundles, integrity-verified evidence lake, SLSA attestations) for audit and long-term retention.

**Core Capability Areas:**

| Category | What It Does |
|----------|--------------|
| **Ingest & Normalize** | SBOM/SARIF/CVE/VEX/CNAPP ingestion with business context enrichment |
| **Correlate & Deduplicate** | Risk Graph modeling, 5 correlation strategies (fingerprint, location, pattern, root-cause, vulnerability taxonomy), intelligent finding clustering |
| **Decide with Transparency** | Policy evaluation, multi-LLM consensus (4 providers), probabilistic forecasting, explainable verdicts with natural-language narratives, MITRE ATT&CK mapping (35+ techniques), transparent scoring with visible weights |
| **Verify Exploitability** | **Micro-Pentest Engine** (automated exploit validation, attack vector simulation, confidence scoring) + reachability analysis with attack path mapping |
| **Operationalize Remediation** | Remediation lifecycle with SLA tracking, bulk operations, team collaboration, decision regression validation |
| **Prove & Retain** | RSA-SHA256 signed evidence bundles, immutable evidence lake with integrity verification, SLSA v1 provenance/attestations, configurable multi-year retention |
| **Automate & Extend** | YAML overlay configuration, YAML playbook scripting (21 pre-approved actions), compliance marketplace, Jira/Confluence/Slack/GitHub integrations |

**Platform Interfaces:** REST API (303 endpoints across 32 router modules), CLI (111 commands/subcommands across 31 command groups), and modular UI (16 frontend pages) - deployable on-prem or air-gapped as needed.

**Documentation:** See [Product Status & Technical Mapping](docs/FIXOPS_PRODUCT_STATUS.md) for detailed capability maps, workflow diagrams, and code references.

---

## The Problem We Solve

Enterprise vulnerability management is broken. Security teams face an impossible task:

- **1 Security Architect : 159 Developers** - Manual review of every security finding is functionally impossible at modern development velocity.

- **60% False Positive Rate** - Scanner sprawl creates massive alert noise. Teams drown in overlapping findings with zero business context.

- **No Design-to-Runtime Link** - Zero correlation between architecture decisions, code vulnerabilities, and runtime controls. Risk assessment is blind to actual operational reality.

- **40-60% Wasted Team Time** - Manual evidence collection for audits paralyzes velocity. Engineers hate it, auditors demand it, and nobody wins.

- **CVSS-Only Prioritization Creates False Urgency** - Prioritizing by CVSS 9.0+ ignores exploit prediction (EPSS), reachability analysis, and control validation.

- **Aggregation Is Not Intelligence** - "Single pane of glass" dashboards that aggregate 10k findings from Snyk, Wiz, and Tenable into one place still leave you with 10k findings to manually triage.

**Business Impact:** Shipping delays, compliance risk, and compounding security debt.

---

## How FixOps Solves This

| Problem | FixOps Solution |
|---------|-----------------|
| Scanner noise | Multi-LLM consensus with 85% agreement threshold reduces actionable findings by 100:1 ratio |
| Manual triage | Tri-state verdicts (Allow/Block/Needs Review) with automated policy enforcement |
| Missing context | Business context engine weighs criticality, data classification, and exposure |
| Audit drag | Evidence-as-Code with cryptographically signed bundles and configurable retention |
| CVSS-only scoring | EPSS + KEV + CVSS enrichment with Bayesian/Markov probabilistic forecasting |
| Tool sprawl | Push-model ingestion works with any SBOM/SARIF source - zero proprietary connectors |

---

## Competitor Comparison

FixOps is not a vulnerability scanner. It's the decision and evidence layer that works with your existing scanners.

| Capability | FixOps | Nucleus | Apiiro | ArmorCode | Cycode | Vulcan |
|------------|--------|---------|--------|-----------|--------|--------|
| **Signed Evidence Storage** | SLSA v1 + 7-year retention | Logs only | SLA only | Reports | Basic | Basic |
| **Compliance Automation** | Auto-generated audit artifacts | - | Reports | Reports | Basic | Basic |
| **Explainable Decisions** | Transparent "Why" + audit trail | Score only | Black box | Risk score | Priority | Risk score |
| **Push-Model Integration** | Universal SBOM/SARIF support | Connectors | Pull-based | Scanner | Hard-wired | Agent+API |
| **On-Prem / Air-Gapped** | Full functionality offline | Ltd SaaS | SaaS only | SaaS only | SaaS+Priv | SaaS+VPC |
| **CTEM Loop** | Full (prioritize→validate→remediate→measure) | Partial | Partial | Partial | Limited | Partial |
| **Micro-Pentest Validation** | Multi-AI exploit verification | - | - | - | - | - |
| **Onboarding Time** | ~30 minutes | Weeks | Weeks | Days | Days | Weeks |
| **Vendor Lock-in** | Full export (JSON/SARIF) | Data trap | SaaS silo | Platform | Platform | Platform |

### Why FixOps Over Alternatives

**vs. Snyk/Checkmarx/Veracode**: These are scanning platforms. FixOps ingests their outputs (SARIF/SBOM) and adds the intelligence layer for automated, auditable decisions. We don't replace your scanners - we make them actionable.

**vs. RBVM Platforms (Nucleus, Vulcan)**: Traditional RBVM tools hide decisions behind opaque "risk scores." FixOps produces cryptographically signed artifacts proving WHY a vulnerability is or isn't exploitable in your context.

**vs. ASPM Platforms (Apiiro, ArmorCode, Cycode)**: ASPM tools aggregate findings but still require manual triage. FixOps adds evidence automation and supports on-prem/air-gapped environments that SaaS-only platforms can't serve.

**vs. CTEM (Continuous Threat Exposure Management)**: Most platforms cover only parts of the CTEM loop. FixOps delivers the complete cycle:

| CTEM Phase | What It Means | How FixOps Delivers |
|------------|---------------|---------------------|
| **Discover/Ingest** | Identify all exposure sources | Universal SBOM/SARIF/CVE/VEX/CNAPP ingestion from any scanner |
| **Prioritize** | Rank by real risk, not just CVSS | Multi-LLM consensus + EPSS/KEV enrichment + business context weighting |
| **Validate** | Confirm exploitability | Micro-Pentest Engine + reachability analysis with attack path mapping |
| **Remediate** | Fix with tracking | Remediation lifecycle, SLA tracking, Jira/Slack integration, bulk operations |
| **Measure** | Prove progress | Signed evidence bundles, compliance dashboards, MTTR/coverage analytics |

Competitors typically stop at Prioritize (RBVM) or Discover+Prioritize (ASPM). FixOps closes the loop with Validate, Remediate, and Measure - all with cryptographic proof.

### Risk-Based + Evidence-Based Philosophy

Moving beyond opaque risk scores to auditable, cryptographically signed decisions.

**The Industry Critique:** Traditional RBVM tools hide critical vulnerabilities behind opaque "risk scores." Auditors reject deprioritization without proof. The "fix everything" approach creates 60% noise and alert fatigue. Risk scores often ignore architecture context (air-gapped, internal-only), leading to false urgency.

**FixOps Approach:** We don't just "deprioritize" - we produce a cryptographically signed artifact proving WHY a vulnerability is not exploitable in your context. Policy flexibility supports Zero-Exception (Block all) OR Smart Prioritization via policy overlay. You control the dial, we provide the evidence.

**Safety Guardrails:** 85% Multi-LLM Consensus threshold, fail-closed defaults, step-by-step reasoning transparency.

### Closing the Compliance Gap

New regulations demand evidence, not just scans. Traditional ASPM tools leave you exposed to audit failure.

| Regulation | Requirement | How FixOps Helps |
|------------|-------------|------------------|
| **ISO 27001:2022 A.8.25** | Secure Development Cycle | Evidence of secure coding, design security, and testing milestones |
| **NIST SSDF / EO 14028** | Secure Software Attestation | Self-attestation of secure practices with signed evidence |
| **EU Cyber Resilience Act** | Supply Chain Transparency | SLSA v1 provenance, SBOM attestations, tamper-evident audit trails |
| **SOC2 / PCI-DSS** | Continuous Compliance | Auto-generated audit artifacts, compliance pack marketplace |

---

## Key Capabilities

### Tri-State Decision Verdicts
Moving beyond vague risk scores to actionable outcomes:
- **Allow (Not Exploitable)** - Proceed with deployment
- **Block (Exploitable)** - Stop deployment, create remediation ticket
- **Needs Review** - Human review required with full context

### Multi-LLM Consensus Engine
Four AI providers with weighted voting, hallucination guards, and real LLM integration:
- **GPT-5** (weight: 1.0) - Strategic analysis, MITRE ATT&CK mapping
- **Claude-3** (weight: 0.95) - Compliance analysis, guardrail evaluation
- **Gemini-2** (weight: 0.9) - Exploit signals, CNAPP correlation
- **Sentinel-Cyber** (weight: 0.85) - Threat intelligence, security heuristics

Configurable consensus threshold via `FIXOPS_CONSENSUS_THRESHOLD` (default: 85%) with step-by-step reasoning transparency. Includes retry logic with exponential backoff and graceful fallback to deterministic responses when providers are unavailable.

### Probabilistic Risk Forecasting
- **Bayesian posterior probability** with EPSS priors
- **5-state Markov chain** for severity trend prediction
- **BN-LR hybrid model** for calibrated risk scores
- Supports model A/B testing in production

### Evidence-as-Code
Every decision produces a cryptographically signed bundle:
- RSA-SHA256 signatures for integrity verification via `POST /api/v1/evidence/verify`
- SLSA v1 provenance with in-toto attestation format (DSSE envelope)
- Optional Fernet encryption for sensitive data
- Configurable retention policies with WORM-compliant storage options
- **Enterprise Storage Backends**: Local filesystem, S3 Object Lock, Azure Immutable Blob
- Audit-ready anytime, even offline

### World-Class Vulnerability Intelligence (8 Categories)
FixOps ingests the largest vulnerability and exploit intelligence surface in the world:

**1. Global Authoritative Sources (Ground Truth)**
- NVD, CVE Program, MITRE, CISA KEV, CERT/CC, US-CERT, ICS-CERT

**2. National CERTs (Geo-specific Exploit Reality)**
- NCSC UK, BSI Germany, ANSSI France, JPCERT Japan, CERT-In, ACSC Australia, SingCERT, KISA Korea
- Geo-weighted risk scoring (exploitation differs by country/region)

**3. Exploit & Weaponization Intelligence**
- Exploit-DB, Metasploit, Packet Storm, Vulners, GreyNoise, Shodan, Censys, Nuclei Templates
- Exploit-confidence scoring (not CVSS fear-score)

**4. Threat Actor & Campaign Intelligence**
- MITRE ATT&CK, AlienVault OTX, abuse.ch, Feodo Tracker, Ransomware Live
- CVE → Threat Actor → Sector targeting mapping

**5. Supply-Chain & SBOM Intelligence**
- OSV, GitHub Advisory Database, Snyk, deps.dev, NPM/PyPI/RustSec advisories
- Reachable dependency analysis (exploitability based on actual reachability)

**6. Cloud & Runtime Vulnerability Feeds**
- AWS, Azure, GCP Security Bulletins, Kubernetes CVEs, Red Hat, Ubuntu, Debian, Alpine

**7. Zero-Day & Early-Signal Feeds**
- Microsoft MSRC, Apple Security, Cisco PSIRT, Palo Alto, Fortinet
- GitHub security commits, Full-Disclosure, OSS-Security mailing lists
- Pre-CVE risk alerts

**8. Internal Enterprise Signals**
- SAST/DAST/SCA findings, IaC misconfigurations, runtime detections
- Exposure graph (internet-facing? auth bypass?), business criticality metadata

**Key Differentiators:**
- **Exploit-Confidence Score** - Based on actual exploitation evidence, not CVSS fear-scoring
- **Geo-Weighted Risk** - Regional exploitation patterns from national CERTs
- **Threat Actor Mapping** - Know which APT groups are using which CVEs
- **Reachable Dependency Analysis** - Same CVE ≠ same risk

### Compliance Framework Mapping
Native support for regulatory requirements:
- **ISO 27001:2022 A.8.25** - Secure Development Lifecycle
- **NIST SSDF / EO 14028** - Secure Software Development Framework
- **SOC2** - Trust Services Criteria
- **PCI-DSS** - Payment Card Industry standards
- **GDPR** - Data protection requirements
- **OWASP** - Application security standards

### Push-Model Integration
Works with your existing tools - no proprietary connectors:
- Any SBOM format (CycloneDX, SPDX)
- Any SARIF output (Snyk, SonarQube, CodeQL, Semgrep)
- CVE feeds (NVD, CISA KEV)
- VEX documents
- CNAPP findings

### Deployment Flexibility
- **SaaS** - Managed cloud deployment
- **On-Premises** - Full functionality in your data center
- **Air-Gapped** - Complete offline operation for classified environments
- **Quick Setup** - Target deployment time ~30 minutes with setup wizard

---

## Advanced Capabilities

### Interactive Risk Graph
Cytoscape.js-powered visualization that maps your entire security posture:
- **Service → Component → CVE/Finding relationships** with real-time filtering
- **KEV highlighting** - Known Exploited Vulnerabilities visually distinguished
- **EPSS enrichment** - Exploit probability scores displayed per node
- **Internet-facing indicators** - Identify exposed attack surfaces
- **Multi-select CVEs** for batch micro-pentest execution
- **Severity-based coloring** with configurable thresholds
- Filter by KEV-only, internet-facing, severity level, or EPSS score

### Micro-Pentest Engine
Automated vulnerability verification with multi-AI orchestration:
- **Targeted exploit validation** - Verify if CVEs are actually exploitable in your environment
- **Attack vector simulation** - JNDI injection, SQL injection, XSS, buffer overflow, path traversal
- **Confidence scoring** - Each test returns exploitability confidence (0-100%)
- **Evidence collection** - Captures proof of exploitability for audit
- **Risk score calculation** - Combines severity, KEV status, EPSS, and exposure
- **Remediation prioritization** - Auto-assigns critical/high/medium/low priority
- **Right-click from Risk Graph** - Select CVEs and launch micro-pentests directly

### Reachability Analysis
Determine if vulnerabilities are actually reachable from attack surfaces:
- **Attack path mapping** - Traces Internet → Gateway → Service → Component → CVE
- **Reachable vs. Not Reachable verdicts** with confidence scores
- **Business impact assessment** - High/Medium/Low impact classification
- **Bulk CVE analysis** - Analyze multiple CVEs in a single request
- **EPSS + KEV correlation** - Combines reachability with exploit intelligence

### YAML-Based Vulnerability Management (Overlay Configuration)
All platform behavior is controlled via `config/fixops.overlay.yml`:
```yaml
risk_models:
  weighted_scoring_v1:
    allow_threshold: 0.6      # Below this = Allow
    block_threshold: 0.85     # Above this = Block
    criticality_weights:
      critical: 1.0
      high: 0.8
      medium: 0.5
      low: 0.2
    data_weights:
      pii: 1.0
      financial: 0.9
      internal: 0.5
    exposure_weights:
      internet: 1.0
      internal: 0.5
      isolated: 0.2
```

### Customizable Risk Parameters & Scoring Transparency
Full control over how risk scores are calculated:
- **Configurable thresholds** - Set your own allow/block boundaries
- **Weighted scoring factors** - Adjust weights for criticality, data classification, exposure
- **Transparent calculations** - Every score shows contributing factors and weights
- **A/B testing support** - Test different risk models in production
- **Audit trail** - Full history of scoring parameter changes

### Overlay-Driven Feature Matrix
Toggle features on/off via configuration without code changes:
```yaml
modules:
  guardrails: true
  compliance: true
  ssdlc: true
  probabilistic: true
  policy_automation: true
  reachability: false      # Enterprise feature
  marketplace: false       # Enterprise feature
  enhanced_pentagi: false  # Enterprise feature
```

### Multi-Year Evidence Retention
Configurable retention policies for compliance requirements:
- **Retention periods** - Configure days/months/years per evidence type
- **Compression** - Gzip compression for storage efficiency
- **Encryption** - Optional Fernet encryption for sensitive bundles
- **Export formats** - JSON, SARIF for portability
- **Audit-ready** - Evidence accessible offline for auditors

---

## 16 Frontend Pages

| Page | Description |
|------|-------------|
| **ArchitectDashboard** | Architecture-focused security overview |
| **ArchitectureCenter** | Architecture management and visualization |
| **ArchitecturePage** | Architecture details and analysis |
| **CISODashboard** | Executive security metrics for CISOs |
| **CommandCenter** | Centralized security operations |
| **ComplianceRollup** | Compliance status aggregation |
| **DeveloperDashboard** | Developer-focused security view |
| **DeveloperOps** | Developer operations and workflows |
| **EnhancedDashboard** | Advanced dashboard with multi-LLM insights |
| **EvidenceTimeline** | Evidence bundle timeline view |
| **ExecutiveBriefing** | Executive summary and briefings |
| **InstallPage** | Installation and setup wizard |
| **RiskExplorer** | Risk exploration and analysis |
| **RiskGraph** | Interactive Cytoscape.js dependency visualization |
| **TriageInbox** | Vulnerability triage inbox |
| **TriageQueue** | Triage queue management |

---

## Platform Architecture

```
+-----------------------------------------------------------------------------------+
|                              FixOps Decision Engine                                |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  INGESTION LAYER              DECISION ENGINE              EVIDENCE SYSTEM        |
|  +------------------+         +------------------+         +------------------+   |
|  | SBOM (CycloneDX) |         | Multi-LLM        |         | RSA-SHA256       |   |
|  | SARIF            |  --->   |   Consensus      |  --->   |   Signing        |   |
|  | CVE/KEV/EPSS     |         | Policy Engine    |         | Fernet           |   |
|  | VEX              |         | Guardrails       |         |   Encryption     |   |
|  | CNAPP            |         | Risk Models      |         | Compliance       |   |
|  | Business Context |         |   (BN-LR)        |         |   Mapping        |   |
|  +------------------+         +------------------+         +------------------+   |
|                                                                                   |
|  INTEGRATIONS                 ANALYTICS                    FRONTEND               |
|  +------------------+         +------------------+         +------------------+   |
|  | Jira             |         | ROI Dashboard    |         | 16 Frontend Pages|   |
|  | Confluence       |         | MTTR/MTTD        |         | React + Vite     |   |
|  | Slack            |         | Trend Analysis   |         | Tailwind CSS     |   |
|  | GitHub           |         | Forecasting      |         |                  |   |
|  +------------------+         +------------------+         +------------------+   |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## API & CLI Coverage

### 303 API Endpoints (32 Router Modules)

| Router | Endpoints | Description |
|--------|-----------|-------------|
| Ingestion | 15 | SBOM, SARIF, CVE, VEX, CNAPP, context uploads |
| Pipeline | 4 | Pipeline execution, analytics, feedback |
| Enhanced Decision | 4 | Multi-LLM analysis, consensus, capabilities |
| Analytics | 16 | Dashboard, trends, MTTR, ROI, forecasting |
| Audit | 10 | Logs, decision trails, compliance status |
| Reports | 9 | Generation, scheduling, export |
| Teams | 8 | Team management, membership |
| Users | 6 | User management, authentication |
| Policies | 8 | Policy CRUD, validation, testing |
| Integrations | 8 | Jira, Confluence, Slack configuration |
| Workflows | 7 | Workflow automation, execution history |
| Inventory | 15 | Applications, services, components |
| PentAGI | 14 | Pen test requests, results, configs |
| Enhanced PentAGI | 19 | Verification, monitoring, comprehensive scans |
| Micro-Pentest | 3 | Automated vulnerability verification |
| IaC | 5 | Infrastructure-as-Code findings |
| Secrets | 5 | Secrets scanning findings |
| Health | 5 | Health checks, readiness, metrics |
| IDE | 3 | IDE plugin integration |
| Bulk | 12 | Bulk operations, async job framework |
| Marketplace | 12 | Compliance packs, contributions |
| Evidence | 4 | Bundles, manifests, verification |
| Graph/Risk | 4 | Dependency visualization, reachability |
| Deduplication | 17 | Cluster management, correlation linking, baseline comparison |
| Remediation | 13 | Task lifecycle, SLA tracking, verification evidence |
| Collaboration | 21 | Comments, watchers, activity feeds, notifications |
| Webhooks | 20 | Jira/ServiceNow/GitLab/Azure DevOps sync, outbox |
| Feeds | 20 | Threat intelligence, EPSS, KEV, exploit feeds |

### ~90 CLI Commands (30 Command Groups)

| Command Group | Commands | Description |
|---------------|----------|-------------|
| Pipeline | `run`, `make-decision`, `ingest`, `analyze` | Core pipeline execution |
| Stage | `stage-run design/build/test/deploy/decision` | Single SDLC stage execution |
| Evidence | `get-evidence`, `copy-evidence` | Evidence bundle management |
| Config | `show-overlay`, `health` | Configuration and health |
| Demo | `demo` | Demo mode execution |
| Forecasting | `train-forecast` | Probabilistic model training |
| Compliance | `compliance frameworks/status/gaps/report` | Compliance management |
| Reports | `reports list/generate/export/schedules` | Report generation |
| Inventory | `inventory apps/add/get/services/search` | Asset inventory |
| Policies | `policies list/get/create/validate/test` | Policy management |
| Integrations | `integrations list/configure/test/sync` | Integration management |
| Analytics | `analytics dashboard/mttr/coverage/roi/export` | Security analytics |
| Audit | `audit logs/decisions/export` | Audit trails |
| Workflows | `workflows list/get/create/execute/history` | Workflow automation |
| Teams/Users | `teams`, `users` | Team and user management |
| PentAGI | `pentagi list/create/status` | Pen testing |
| Advanced | `advanced-pentest run/threat-intel/simulate` | Advanced pen testing |
| Reachability | `reachability analyze/bulk/status` | Vulnerability reachability |

---

## Installation Guide

This section covers installation for local development, customer implementations, and production deployments.

### Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.10+ (3.11 recommended) | Core runtime |
| pip + virtualenv | Latest | Package management |
| Docker + Docker Compose | 20.10+ / v2 | Container deployment |
| Node.js | 18+ | Frontend development (optional) |
| Git | 2.30+ | Version control |

**System Requirements:**
- 8GB RAM minimum (16GB recommended for full stack with PentAGI)
- 20GB disk space
- macOS, Linux, or Windows with WSL2

### Option 1: Local Laptop Setup (Development/Testing)

Best for developers and evaluators who want to test all FixOps features locally.

```bash
# 1. Clone the repository
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# 2. Run the setup wizard (recommended)
./scripts/setup-wizard.sh

# Or manual setup
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env

# Edit .env and set required values:
#   FIXOPS_API_TOKEN=your-secure-token
#   FIXOPS_MODE=demo  # or 'enterprise' for full features

# 4. (Optional) Configure LLM providers for multi-AI consensus
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GOOGLE_API_KEY="..."

# 5. Start the API server
uvicorn apps.api.app:create_app --factory --reload --host 0.0.0.0 --port 8000

# 6. Verify installation
curl http://localhost:8000/health
```

### Option 2: Docker Compose (Recommended for Customers)

Best for customer implementations and production-like environments.

```bash
# 1. Clone the repository
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# 2. Configure environment
cp .env.example .env
# Edit .env with your settings

# 3. Choose your deployment variant:

# Development/Demo
docker compose up -d

# Enterprise with ChromaDB
docker compose -f docker-compose.enterprise.yml up -d

# Demo with telemetry
docker compose -f docker-compose.demo.yml up -d

# Production deployment
docker compose -f deployment-packs/docker/docker-compose.yml up -d

# 4. Verify services
curl http://localhost:8000/health
```

### Option 3: Full Stack with PentAGI (Micro-Pentest Capabilities)

Best for security teams who want automated vulnerability verification.

```bash
# 1. Clone and configure
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops
cp .env.example .env
cp env.pentagi.example .env.pentagi

# 2. Configure LLM API keys in .env.pentagi (at least one required)
# Edit .env.pentagi:
#   OPENAI_API_KEY=sk-...
#   ANTHROPIC_API_KEY=sk-ant-...

# 3. Start FixOps with PentAGI
make up-pentagi

# Or for enterprise mode:
make up-pentagi-enterprise

# 4. Verify all services
curl http://localhost:8000/health          # FixOps API
curl -k https://localhost:8443/health      # PentAGI (self-signed SSL)

# 5. (Optional) Use air-gapped fork without VXControl Cloud SDK
export PENTAGI_IMAGE=ghcr.io/devopsmaddog/pentagi_fork:latest
make down-pentagi && make up-pentagi
```

See [PentAGI Integration Guide](docs/PENTAGI_INTEGRATION.md) for detailed configuration.

---

## Quick Start: Test All Features

After installation, use these commands to verify all FixOps capabilities are working.

### 1. Run the Demo Pipeline
```bash
# Quick demo (no external dependencies)
python -m core.cli demo --mode demo

# Enterprise demo (full features)
python -m core.cli demo --mode enterprise --output results.json --pretty
```

### 2. Test API Endpoints
```bash
export FIXOPS_API_TOKEN="demo-token"  # Or your configured token

# Upload security artifacts
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@simulations/demo_pack/sbom.json" http://localhost:8000/inputs/sbom

curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@simulations/demo_pack/scanner.sarif" http://localhost:8000/inputs/sarif

curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@simulations/demo_pack/cve-feed.json" http://localhost:8000/inputs/cve

# Execute pipeline and get decision
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/pipeline/run | jq

# Check capabilities
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/api/v1/enhanced/capabilities | jq
```

### 3. Test Multi-LLM Consensus
```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"service_name":"test-app","security_findings":[{"rule_id":"SAST001","severity":"high","description":"SQL injection"}],"business_context":{"environment":"production","criticality":"high"}}' \
  http://localhost:8000/api/v1/enhanced/compare-llms | jq
```

### 4. Interactive Demo Runner
```bash
# Animated demo with all 7 capability areas
./scripts/aldeci-demo-runner.sh

# Interactive API tester (303 endpoints)
./scripts/fixops-interactive.sh

# Or via Docker
docker build -f Dockerfile.interactive -t fixops-demo .
docker run -it fixops-demo demo
```

### 5. Test PentAGI Integration (if installed)
```bash
# Verify PentAGI is running
curl -k https://localhost:8443/health

# Trigger a micro-pentest via FixOps
curl -H "X-API-Key: $FIXOPS_API_TOKEN" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://example.com","cve":"CVE-2021-44228","scope":"verify"}' \
  http://localhost:8000/api/v1/pentagi/micro-pentest | jq
```

### 6. Run Test Suite
```bash
# All tests
pytest

# With coverage
pytest --cov=core --cov=apps

# E2E tests
./scripts/run_e2e_tests.sh
```

---

## Feature Verification Checklist

Use this checklist to verify all FixOps features are working in your installation:

| Feature | Test Command | Expected Result |
|---------|--------------|-----------------|
| API Health | `curl http://localhost:8000/health` | `{"status":"healthy"}` |
| SBOM Ingestion | `curl -F "file=@simulations/demo_pack/sbom.json" .../inputs/sbom` | 200 OK |
| SARIF Ingestion | `curl -F "file=@simulations/demo_pack/scanner.sarif" .../inputs/sarif` | 200 OK |
| Pipeline Execution | `curl .../pipeline/run` | JSON with decision |
| CLI Demo | `python -m core.cli demo --mode demo` | Pipeline output |
| Multi-LLM Consensus | `curl -X POST .../compare-llms` | Consensus result |
| Evidence Bundles | Check `data/evidence/` directory | Signed bundles |
| PentAGI (optional) | `curl -k https://localhost:8443/health` | `{"status":"ok"}` |

---

## CLI Reference

### Core Commands
```bash
# Pipeline execution
python -m core.cli run --design design.csv --sbom sbom.json --sarif scan.sarif

# Demo modes
python -m core.cli demo --mode demo
python -m core.cli demo --mode enterprise

# Show configuration
python -m core.cli show-overlay --overlay config/fixops.overlay.yml

# Offline mode (no exploit feed refresh)
python -m core.cli run --offline

# Copy evidence for audits
python -m core.cli copy-evidence --run results.json --target ./audit-handoff
```

### CLI Command Categories

---

## Operating Modes

### Demo Mode
Quick demonstration with simplified settings. No external integrations required.
```bash
python -m core.cli demo --mode demo
```

### Enterprise Mode
Full feature set with compliance, governance, and integrations.
```bash
python -m core.cli demo --mode enterprise
```

### Multi-LLM Mode (Default)
Consensus across 4 AI providers for high-confidence decisions.
```bash
export FIXOPS_ENABLE_OPENAI=true
export FIXOPS_ENABLE_ANTHROPIC=true
export FIXOPS_ENABLE_GEMINI=true
export FIXOPS_ENABLE_SENTINEL=true
```

### Single-LLM Mode
Use one provider for cost optimization.
```bash
export FIXOPS_ENABLE_OPENAI=true
export FIXOPS_ENABLE_ANTHROPIC=false
export FIXOPS_ENABLE_GEMINI=false
export FIXOPS_ENABLE_SENTINEL=false
```

### Deterministic Mode
Risk-based decisions without LLM dependencies.
```bash
export FIXOPS_ENABLE_OPENAI=false
export FIXOPS_ENABLE_ANTHROPIC=false
export FIXOPS_ENABLE_GEMINI=false
export FIXOPS_ENABLE_SENTINEL=false
```

---

## OSS Fallback Analysis

When proprietary scanners aren't available, FixOps integrates with open-source tools:

| Language | OSS Tools |
|----------|-----------|
| Python | Semgrep, Bandit |
| JavaScript/TypeScript | Semgrep, ESLint |
| Java | Semgrep, SpotBugs |
| Go | Gosec, Semgrep |
| Rust | Clippy, Semgrep |
| C/C++ | Cppcheck, Semgrep |
| Ruby | Brakeman |
| PHP | PHPStan |
| .NET | SonarQube |

### IaC Analysis
- **Terraform**: Checkov, Terrascan, TFLint
- **CloudFormation**: cfn-lint, Checkov
- **Kubernetes**: Kubesec, Checkov
- **Dockerfile**: Hadolint, Trivy

### Container Security
- Trivy, Clair, Grype

### Cloud Security (CSPM)
- Prowler (AWS), Scout-Suite, CloudSploit

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FIXOPS_API_TOKEN` | Yes | - | API authentication token |
| `FIXOPS_MODE` | No | enterprise | Operating mode (demo/enterprise) |
| `FIXOPS_ENABLE_OPENAI` | No | true | Enable OpenAI GPT provider |
| `FIXOPS_ENABLE_ANTHROPIC` | No | true | Enable Anthropic Claude provider |
| `FIXOPS_ENABLE_GEMINI` | No | true | Enable Google Gemini provider |
| `FIXOPS_ENABLE_SENTINEL` | No | true | Enable Sentinel Cyber provider |
| `OPENAI_API_KEY` | No | - | OpenAI API key |
| `ANTHROPIC_API_KEY` | No | - | Anthropic API key |
| `GOOGLE_API_KEY` | No | - | Google API key |
| `FIXOPS_JIRA_TOKEN` | No | - | Jira integration token |
| `FIXOPS_CONFLUENCE_TOKEN` | No | - | Confluence integration token |
| `FIXOPS_EVIDENCE_KEY` | No | - | Evidence encryption key |
| `FIXOPS_DISABLE_TELEMETRY` | No | false | Disable OpenTelemetry |

---

## Production Deployment

### Docker (Recommended for Local Development)

All Docker configurations use **port 8000** for the API by default.

**Quick Start:**
```bash
# Option 1: Use the setup wizard (generates .env and starts services)
./scripts/setup-wizard.sh

# Option 2: Manual setup with main docker-compose
docker compose up -d

# Verify it's running
curl http://localhost:8000/health

# Run the pipeline
export FIXOPS_API_TOKEN="demo-token"
curl -H "X-API-Key: $FIXOPS_API_TOKEN" -F "file=@simulations/demo_pack/sbom.json" http://localhost:8000/inputs/sbom
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/pipeline/run | jq
```

**Available Docker Configurations:**

| File | Purpose | Token |
|------|---------|-------|
| `docker-compose.yml` | Main dev stack with sidecars | `demo-token` |
| `docker-compose.demo.yml` | Demo with OpenTelemetry | (env var) |
| `docker-compose.enterprise.yml` | Enterprise with ChromaDB | `enterprise-token` |
| `docker-compose.vc-demo.yml` | VC demonstrations | `demo-token` |
| `deployment-packs/docker/docker-compose.yml` | Production template | (env var) |

For detailed Docker documentation, see [Docker Guide](docs/DOCKER.md).

### Cloud Deployment Scripts

### AWS
```bash
# AWS deployment
./scripts/deploy-aws.sh

# GCP deployment
./scripts/deploy-gcp.sh
```

### Makefile Targets Reference

| Target | Description |
|--------|-------------|
| `make help` | Show all available targets |
| `make demo` | Run demo pipeline |
| `make demo-enterprise` | Run enterprise pipeline |
| `make up-pentagi` | Start FixOps + PentAGI (default compose) |
| `make up-pentagi-enterprise` | Start FixOps Enterprise + PentAGI |
| `make up-pentagi-demo` | Start FixOps Demo + PentAGI |
| `make up-pentagi-deployment` | Start Deployment Pack + PentAGI |
| `make down-pentagi` | Stop FixOps + PentAGI |
| `make logs-pentagi` | View PentAGI logs |
| `make clean` | Remove cached artifacts |

---

### Air-Gapped / Offline Deployment

For environments without internet access, choose one of the following options:

**Option A: Using Official Images**

The official PentAGI images work offline but include VXControl Cloud SDK (which will fail gracefully without connectivity).

```bash
# 1. Pre-pull all required images on a connected machine
docker pull vxcontrol/pentagi:latest
docker pull vxcontrol/pgvector:latest
docker pull vxcontrol/scraper:latest

# 2. Save images to tar files
docker save vxcontrol/pentagi:latest > pentagi.tar
docker save vxcontrol/pgvector:latest > pgvector.tar
docker save vxcontrol/scraper:latest > scraper.tar

# 3. Transfer tar files to air-gapped environment

# 4. Load images on air-gapped machine
docker load < pentagi.tar
docker load < pgvector.tar
docker load < scraper.tar

# 5. Start FixOps with PentAGI
make up-pentagi
```

**Option B: Using Fork Images (No Cloud SDK)**

The [DevOpsMadDog/pentagi_fork](https://github.com/DevOpsMadDog/pentagi_fork) has VXControl Cloud SDK completely removed for fully offline operation with no phone-home behavior.

```bash
# 1. Pre-pull fork image on a connected machine
docker pull ghcr.io/devopsmaddog/pentagi_fork:latest
docker pull vxcontrol/pgvector:latest
docker pull vxcontrol/scraper:latest

# 2. Save images to tar files
docker save ghcr.io/devopsmaddog/pentagi_fork:latest > pentagi-fork.tar
docker save vxcontrol/pgvector:latest > pgvector.tar
docker save vxcontrol/scraper:latest > scraper.tar

# 3. Transfer tar files to air-gapped environment

# 4. Load images on air-gapped machine
docker load < pentagi-fork.tar
docker load < pgvector.tar
docker load < scraper.tar

# 5. Start FixOps with fork image
export PENTAGI_IMAGE=ghcr.io/devopsmaddog/pentagi_fork:latest
make up-pentagi
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Product Status & Technical Mapping](docs/FIXOPS_PRODUCT_STATUS.md) | Master document with capability maps, workflow diagrams, program flows, and code references |
| [Docker Guide](docs/DOCKER.md) | Complete Docker and docker-compose documentation |
| [API/CLI Reference](docs/API_CLI_REFERENCE.md) | Complete API to CLI mapping |
| [Complete API Mapping](docs/COMPLETE_API_CLI_MAPPING.md) | Full endpoint list by router |
| [PentAGI Integration](docs/PENTAGI_INTEGRATION.md) | Micro-pentest deployment and configuration guide |
| [CLI/API Inventory](CLI_API_INVENTORY.md) | CLI commands and API endpoints inventory |
| [Configuration Guide](config/fixops.overlay.yml) | Overlay configuration options |
| [DeepWiki](https://deepwiki.com/DevOpsMadDog/Fixops) | AI-indexed documentation with search |

---

## What's Included vs. Optional

### Core Features (Always Available)
- Pipeline ingestion (SBOM, SARIF, CVE, VEX, CNAPP)
- Multi-LLM consensus engine (or deterministic mode)
- Guardrails and policy automation
- Evidence bundle generation
- Compliance framework mapping
- CLI and API access

### Enterprise Features (Conditional)
- Reachability analysis
- Marketplace compliance packs
- Enhanced PentAGI
- IDE integration APIs
- SSO/OAuth configuration
- **Deduplication & Correlation Engine** - Two-layer system with cluster management, correlation linking, and 35% noise reduction targeting
- **Remediation Lifecycle Management** - State machine with SLA tracking (Critical=24h, High=72h, Medium=168h, Low=720h), verification evidence, and MTTR metrics
- **Enterprise Bulk Operations** - Async job framework with per-item outcomes, partial failure handling, and job status tracking
- **Team Collaboration** - Append-only comment threads, watchers, activity feeds, mention tracking, and evidence promotion

### Enterprise Plug-and-Play Readiness

For enterprise deployments via Docker images, the following integration status applies:

| Integration | Status | Notes |
|-------------|--------|-------|
| **Jira** | Partial | Create tickets works; update/transition/comment pending |
| **Confluence** | Outbound Only | Create page works |
| **Slack** | Ready | Webhook notifications working |
| **ServiceNow** | Inbound Only | Webhook receiver only |
| **GitLab** | Inbound Only | Webhook receiver only |
| **Azure DevOps** | Inbound Only | Webhook receiver only |
| **GitHub** | Not Ready | Connector not implemented |

See [Enterprise Plug-and-Play Readiness](docs/FIXOPS_PRODUCT_STATUS.md#enterprise-plug-and-play-readiness) for detailed status, API/CLI mappings, and roadmap.

### Optional Integrations
- Jira (requires `FIXOPS_JIRA_TOKEN`)
- Confluence (requires `FIXOPS_CONFLUENCE_TOKEN`)
- Slack (requires webhook configuration)
- GitHub (requires token configuration)

---

## License

Proprietary - See LICENSE file for details.

---

## Support

- [Documentation](docs/API_CLI_REFERENCE.md)
- [DeepWiki](https://deepwiki.com/DevOpsMadDog/Fixops)
- [Issues](https://github.com/DevOpsMadDog/Fixops/issues)
