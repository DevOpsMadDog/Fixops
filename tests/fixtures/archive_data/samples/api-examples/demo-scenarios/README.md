# ALDECI Multi-Application Demo Scenarios

This directory contains comprehensive, correlated sample data for demonstrating FixOps across **14 applications** spanning the entire ALM-to-Runtime lifecycle, covering all **7 Core Capability Areas**.

## 7 Core Capability Areas

| Category | What It Does |
|----------|--------------|
| **Ingest & Normalize** | SBOM/SARIF/CVE/VEX/CNAPP ingestion with business context enrichment |
| **Correlate & Deduplicate** | Risk Graph modeling, 5 correlation strategies, intelligent finding clustering |
| **Decide with Transparency** | Multi-LLM consensus (4 providers), MITRE ATT&CK mapping (35+ techniques), explainable verdicts |
| **Verify Exploitability** | Micro-Pentest Engine (automated exploit validation) + reachability analysis with attack path mapping |
| **Operationalize Remediation** | Remediation lifecycle with SLA tracking, bulk operations, team collaboration |
| **Prove & Retain** | RSA-SHA256 signed evidence bundles, SLSA v1 provenance/attestations, multi-year retention |
| **Automate & Extend** | YAML playbook scripting (25+ pre-approved actions), Jira/Confluence/Slack/GitHub integrations |

## 14 Applications Across Different Portfolios

| Application | Tech Stack | Architecture | Portfolio | Primary Compliance |
|-------------|------------|--------------|-----------|-------------------|
| `payment-gateway` | Java/Spring Boot | Microservices | Fintech | PCI-DSS 4.0 |
| `user-identity-service` | Node.js/Express | Microservices | IAM | SOC2, GDPR |
| `healthcare-api` | Python/FastAPI | Microservices | Healthcare | HIPAA, GDPR |
| `supply-chain-portal` | Ruby on Rails | Monolith | Logistics | SOC2, ISO27001 |
| `trading-engine` | Rust/Actix | Bare-metal | Capital Markets | PCI-DSS, SOC2 |
| `iot-device-hub` | Go/Gin | Edge-distributed | Industrial IoT | ISO27001, IEC62443 |
| `ml-inference-service` | Python/TensorFlow | Serverless-hybrid | AI/ML | SOC2, GDPR, CCPA |
| `mobile-banking-bff` | Kotlin/Ktor | Cloud-native | Consumer Banking | PCI-DSS, SOC2, GDPR |
| `legacy-mainframe-adapter` | C#/.NET/COBOL | Hybrid | Core Banking | SOC2, PCI-DSS, SOX |
| `realtime-analytics` | Scala/Spark | Streaming | Data Platform | GDPR, CCPA, SOC2 |
| `gaming-matchmaker` | C++/gRPC | Multi-cloud | Gaming | GDPR, CCPA, COPPA |
| `media-transcoder` | Go/FFmpeg | Serverless-batch | Media | SOC2, DMCA |
| `blockchain-bridge` | Solidity/Node.js | Distributed-consensus | Web3 | SOC2, Travel Rule |
| `edge-cdn-service` | Rust/Workers | Global-edge | Infrastructure | SOC2, ISO27001, PCI-DSS |

## Major CVEs Covered

| CVE | Name | Severity | Applications Affected |
|-----|------|----------|----------------------|
| CVE-2021-44228 | Log4Shell | Critical (10.0) | realtime-analytics, legacy-mainframe-adapter |
| CVE-2022-22965 | Spring4Shell | Critical (9.8) | payment-gateway, mobile-banking-bff |
| CVE-2014-0160 | Heartbleed | Critical (9.8) | gaming-matchmaker, edge-cdn-service |
| CVE-2023-44487 | HTTP/2 Rapid Reset | High (7.5) | edge-cdn-service, mobile-banking-bff, trading-engine |
| CVE-2023-50164 | Apache Struts RCE | Critical (9.8) | legacy-mainframe-adapter |
| CVE-2024-21626 | Leaky Vessels (runc) | Critical (8.6) | iot-device-hub, ml-inference-service, media-transcoder |
| CVE-2023-4863 | libwebp Heap Overflow | Critical (9.8) | media-transcoder, ml-inference-service |

## Tools Coverage (ALM to Runtime)

### Application Lifecycle Management (ALM)
- Jira (Issue Tracking)
- Confluence (Documentation)
- ServiceNow (ITSM)

### Source Code Management (SCM)
- GitHub
- GitLab

### CI/CD Pipeline
- GitHub Actions
- Jenkins
- ArgoCD

### Static Application Security Testing (SAST)
- SonarQube
- Checkmarx
- Semgrep

### Dynamic Application Security Testing (DAST)
- OWASP ZAP
- Burp Suite

### Software Composition Analysis (SCA)
- Snyk
- Dependabot
- Trivy

### Container Security
- Trivy
- Grype
- Prisma Cloud

### Cloud Security (CNAPP)
- AWS Security Hub
- Wiz
- Orca Security

### Runtime Security
- Falco
- Sysdig
- Datadog Security

## Compliance Frameworks

1. **PCI-DSS 4.0** - Payment Card Industry Data Security Standard
2. **SOC2 Type II** - Service Organization Control 2
3. **HIPAA** - Health Insurance Portability and Accountability Act
4. **GDPR** - General Data Protection Regulation

## Data Correlation

All sample data is interconnected:
- Vulnerabilities found by SAST tools correlate with SCA findings
- CVEs in dependencies link to container scan results
- Compliance gaps map to specific vulnerabilities
- Remediation tasks track fixes across all tools
- Audit logs show complete lifecycle of findings

## Directory Structure

```
demo-scenarios/
├── applications/           # 14 Application definitions
│   ├── payment-gateway.json
│   ├── user-identity-service.json
│   ├── healthcare-api.json
│   ├── supply-chain-portal.json
│   ├── trading-engine.json
│   ├── iot-device-hub.json
│   ├── ml-inference-service.json
│   ├── mobile-banking-bff.json
│   ├── legacy-mainframe-adapter.json
│   ├── realtime-analytics.json
│   ├── gaming-matchmaker.json
│   ├── media-transcoder.json
│   ├── blockchain-bridge.json
│   └── edge-cdn-service.json
├── scans/                  # Security scan results
│   ├── sast/              # SAST findings + Major CVEs
│   ├── dast/              # DAST findings (ZAP, Burp)
│   ├── sca/               # SCA findings (Snyk, Dependabot, Trivy)
│   ├── container/         # Container scans (Trivy, Grype, Prisma)
│   └── cloud/             # Cloud security (AWS, Wiz, Orca)
├── pentest/               # Micro-Pentest Engine results
│   ├── micro-pentest-results.json
│   └── reachability-analysis.json
├── decisions/             # AI-powered decisions
│   └── multi-llm-consensus.json
├── evidence/              # Evidence bundles
│   └── evidence-bundles.json
├── automation/            # YAML playbooks
│   └── yaml-playbooks.json
├── compliance/            # Compliance assessments
│   ├── pci-dss/
│   ├── soc2/
│   ├── hipaa/
│   └── gdpr/
├── integrations/          # Tool integrations (Jira, Slack)
├── remediation/           # Remediation tracking
├── runtime/               # Runtime security events (Falco, Sysdig)
└── REALTIME-GENERATION.md # Guide for generating data at customer sites
```

## Quick Start

### Run the Demo

```bash
# Option 1: Use the super classy animated ALDECI demo runner
./scripts/aldeci-demo-runner.sh

# Option 2: Use the interactive API tester
./scripts/fixops-interactive.sh

# Option 3: Docker
docker build -f Dockerfile.interactive -t aldeci-demo .
docker run -it aldeci-demo
```

### Demo Features

The ALDECI demo runner includes:
- **Super classy animations** - Matrix rain, neon glow effects, cyberpunk visuals
- **Animated Micro-Pentest Engine** - Step-by-step exploit validation with typewriter effects
- **Animated Reachability Analysis** - Visual attack path mapping with ASCII art
- **Multi-LLM Consensus** - Real-time querying of 4 AI providers (GPT-4, Claude-3, Gemini-Pro, Llama-3)
- **8 Demo Phases** - Ingestion, Analysis, Micro-Pentest, Reachability, Decisions, Integrations, Remediation, Compliance

### Customize for Customer

1. **Change application names**: Edit files in `applications/` directory
2. **Change compliance frameworks**: Modify `compliance/` assessments
3. **Change tools**: Update scan files in `scans/` subdirectories
4. **Change tech stacks**: Modify application definitions

## Real-Time Data Generation

For generating fresh data at customer sites using their actual tools, see:
- **[REALTIME-GENERATION.md](./REALTIME-GENERATION.md)** - Complete guide with commands for all tools

Quick examples:

```bash
# SAST with Semgrep
semgrep --config=auto --json -o scan.json .

# SCA with Snyk
snyk test --json > snyk-scan.json

# Container with Trivy
trivy image --format json -o scan.json $IMAGE

# DAST with ZAP
zap-cli quick-scan --self-contained -o json $URL
```

## Correlation IDs

All findings across tools are linked using correlation IDs (format: `CORR-*`):

| Correlation ID | Description | Tools |
|---------------|-------------|-------|
| CORR-LOG4J-001 | Log4Shell vulnerability | Snyk, Trivy, Wiz |
| CORR-SQL-001 | SQL Injection in payment-gateway | SonarQube, Checkmarx, ZAP |
| CORR-IDOR-001 | IDOR in healthcare-api | Checkmarx, Burp |
| CORR-CRED-002 | Hardcoded JWT secret | Semgrep, Orca |

## Sample Files Summary

| Category | Files | Description |
|----------|-------|-------------|
| Applications | 14 | Application definitions with metadata |
| SAST | 5 | SonarQube, Checkmarx, Semgrep, Bandit, Major CVEs |
| DAST | 2 | OWASP ZAP, Burp Suite |
| SCA | 4 | Snyk, Dependabot, Trivy, Safety |
| Container | 3 | Trivy, Grype, Prisma Cloud |
| Cloud | 3 | AWS Security Hub, Wiz, Orca |
| Runtime | 2 | Falco, Sysdig |
| Pentest | 2 | Micro-Pentest Results, Reachability Analysis |
| Decisions | 1 | Multi-LLM Consensus Verdicts |
| Evidence | 1 | RSA-SHA256 Signed Evidence Bundles |
| Automation | 1 | YAML Playbooks (25+ actions) |
| Compliance | 4 | PCI-DSS, SOC2, HIPAA, GDPR |
| Integrations | 2 | Jira tickets, Slack notifications |
| Remediation | 1 | Remediation tracker |

## Demo Scripts

### aldeci-demo-runner.sh

Super classy animated end-to-end demo with:
- Neon glow effects and cyberpunk-style visuals
- Matrix rain and gradient text animations
- Animated Micro-Pentest Engine with step-by-step exploit validation
- Animated Reachability Analysis with ASCII attack path visualization
- Multi-LLM Consensus with real-time provider querying
- Customer customization (14 applications, 8 compliance frameworks)
- 8-phase demo flow covering all capabilities

### fixops-interactive.sh

Interactive API/CLI tester with:
- 300+ API endpoints
- 67 CLI commands
- Sample data generation
- Real-time API testing
- File upload support
