[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/DevOpsMadDog/Fixops)

# FixOps

**Enterprise DevSecOps Decision & Verification Engine**

*Automate Trust. Prove Security.*

FixOps transforms scanner chaos into auditable decisions. It's the intelligence layer that sits between your security scanners and your CI/CD pipeline, providing automated allow/block/defer verdicts backed by multi-LLM consensus, probabilistic risk models, and cryptographically-signed evidence bundles.

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
| **Signed Evidence Storage** | SLSA-style provenance | Logs only | SLA only | Reports | Basic | Basic |
| **Compliance Automation** | Auto-generated audit artifacts | - | Reports | Reports | Basic | Basic |
| **Explainable Decisions** | Transparent reasoning + audit trail | Score only | Black box | Risk score | Priority | Risk score |
| **Push-Model Integration** | Universal SBOM/SARIF support | Connectors | Pull-based | Scanner | Hard-wired | Agent+API |
| **On-Prem / Air-Gapped** | Full functionality offline | Ltd SaaS | SaaS only | SaaS only | SaaS+Priv | SaaS+VPC |
| **Onboarding Time** | ~30 minutes | Weeks | Weeks | Days | Days | Weeks |
| **Vendor Lock-in** | Full export (JSON/SARIF) | Data trap | SaaS silo | Platform | Platform | Platform |

### Why FixOps Over Alternatives

**vs. Snyk/Checkmarx/Veracode**: These are scanning platforms. FixOps ingests their outputs (SARIF/SBOM) and adds the intelligence layer for automated, auditable decisions. We don't replace your scanners - we make them actionable.

**vs. RBVM Platforms (Nucleus, Vulcan)**: Traditional RBVM tools hide decisions behind opaque "risk scores." FixOps produces cryptographically signed artifacts proving WHY a vulnerability is or isn't exploitable in your context.

**vs. ASPM Platforms (Apiiro, ArmorCode, Cycode)**: ASPM tools aggregate findings but still require manual triage. FixOps adds evidence automation and supports on-prem/air-gapped environments that SaaS-only platforms can't serve.

---

## Key Capabilities

### Tri-State Decision Verdicts
Moving beyond vague risk scores to actionable outcomes:
- **Allow (Not Exploitable)** - Proceed with deployment
- **Block (Exploitable)** - Stop deployment, create remediation ticket
- **Needs Review** - Human review required with full context

### Multi-LLM Consensus Engine
Four AI providers with weighted voting and hallucination guards:
- **GPT-5** (weight: 1.0) - Strategic analysis, MITRE ATT&CK mapping
- **Claude-3** (weight: 0.95) - Compliance analysis, guardrail evaluation
- **Gemini-2** (weight: 0.9) - Exploit signals, CNAPP correlation
- **Sentinel-Cyber** (weight: 0.85) - Threat intelligence, security heuristics

Configurable 85% consensus threshold with step-by-step reasoning transparency.

### Probabilistic Risk Forecasting
- **Bayesian posterior probability** with EPSS priors
- **5-state Markov chain** for severity trend prediction
- **BN-LR hybrid model** for calibrated risk scores
- Supports model A/B testing in production

### Evidence-as-Code
Every decision produces a cryptographically signed bundle:
- RSA-SHA256 signatures for integrity verification
- Optional Fernet encryption for sensitive data
- Configurable retention policies
- Audit-ready anytime, even offline

### Exploit Intelligence Enrichment
Real-time threat data integration:
- **CISA KEV** - Known Exploited Vulnerabilities catalog
- **EPSS** - Exploit Prediction Scoring System
- **CVSS/CWE** - Standard vulnerability metrics
- Automatic severity promotion for actively exploited CVEs

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
|  | Jira             |         | ROI Dashboard    |         | 27 MFE Apps      |   |
|  | Confluence       |         | MTTR/MTTD        |         | React + Vite     |   |
|  | Slack            |         | Trend Analysis   |         | Tailwind CSS     |   |
|  | GitHub           |         | Forecasting      |         | Turborepo        |   |
|  +------------------+         +------------------+         +------------------+   |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## API & CLI Coverage

### 243+ API Endpoints (22 Router Modules)

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
| IaC | 5 | Infrastructure-as-Code findings |
| Secrets | 5 | Secrets scanning findings |
| Health | 5 | Health checks, readiness, metrics |
| IDE | 3 | IDE plugin integration |
| Bulk | 5 | Bulk operations |
| Marketplace | 12 | Compliance packs, contributions |
| Evidence | 17 | Bundles, manifests, verification |
| Graph/Risk | 7 | Dependency visualization, reachability |

### 67 CLI Commands

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

## Quick Start

### Prerequisites
- Python 3.10+ (tested with CPython 3.11)
- pip and virtualenv
- Optional: Node.js 18+ for frontend development

### 1. Setup
```bash
# Run the setup wizard
./scripts/setup-wizard.sh

# Or manual setup
./scripts/bootstrap.sh
```

### 2. Configure Environment
```bash
cp .env.example .env

# Required
export FIXOPS_API_TOKEN="your-api-token"

# Optional LLM providers (all enabled by default)
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GOOGLE_API_KEY="..."

# Optional integrations
export FIXOPS_JIRA_TOKEN="..."
export FIXOPS_CONFLUENCE_TOKEN="..."
```

### 3. Start the API
```bash
uvicorn apps.api.app:create_app --factory --reload
```

### 4. Run Your First Pipeline
```bash
# Upload artifacts
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@samples/sbom.json" http://localhost:8000/inputs/sbom

curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@samples/scan.sarif" http://localhost:8000/inputs/sarif

# Execute pipeline
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/pipeline/run | jq
```

### 5. CLI Demo
```bash
# Demo mode (quick demonstration)
python -m core.cli demo --mode demo

# Enterprise mode (full features)
python -m core.cli demo --mode enterprise --output results.json
```

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

## Deployment

### AWS
```bash
./scripts/deploy-aws.sh
```

### GCP
```bash
./scripts/deploy-gcp.sh
```

### Docker Compose
```bash
cp .env.example .env
docker-compose -f deployment-packs/docker/docker-compose.yml up -d
```

---

## Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=core --cov=apps

# E2E tests
./scripts/run_e2e_tests.sh
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [API/CLI Reference](docs/API_CLI_REFERENCE.md) | Complete API to CLI mapping (243+ endpoints) |
| [Complete API Mapping](docs/COMPLETE_API_CLI_MAPPING.md) | Full endpoint list by router |
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

- [Documentation](https://docs.devin.ai)
- [DeepWiki](https://deepwiki.com/DevOpsMadDog/Fixops)
- [Issues](https://github.com/DevOpsMadDog/Fixops/issues)
