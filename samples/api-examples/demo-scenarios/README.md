# FixOps Multi-Application Demo Scenarios

This directory contains comprehensive, correlated sample data for demonstrating FixOps across 4 applications spanning the entire ALM-to-Runtime lifecycle.

## Applications

| Application | Domain | Criticality | Primary Compliance |
|-------------|--------|-------------|-------------------|
| `payment-gateway` | Financial Services | Critical | PCI-DSS 4.0 |
| `user-identity-service` | Identity & Access | Critical | SOC2, GDPR |
| `healthcare-api` | Healthcare | Critical | HIPAA, GDPR |
| `supply-chain-portal` | Supply Chain | High | SOC2, ISO27001 |

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
├── applications/           # Application definitions
│   ├── payment-gateway.json
│   ├── user-identity-service.json
│   ├── healthcare-api.json
│   └── supply-chain-portal.json
├── scans/                  # Security scan results
│   ├── sast/              # SAST findings (SonarQube, Checkmarx, Semgrep)
│   ├── dast/              # DAST findings (ZAP, Burp)
│   ├── sca/               # SCA findings (Snyk, Dependabot, Trivy)
│   ├── container/         # Container scans (Trivy, Grype, Prisma)
│   └── cloud/             # Cloud security (AWS, Wiz, Orca)
├── compliance/            # Compliance assessments
│   ├── pci-dss/
│   ├── soc2/
│   ├── hipaa/
│   └── gdpr/
├── integrations/          # Tool integrations (Jira, Slack)
├── workflows/             # Automated workflows
├── remediation/           # Remediation tracking
├── runtime/               # Runtime security events (Falco, Sysdig)
└── REALTIME-GENERATION.md # Guide for generating data at customer sites
```

## Quick Start

### Run the Demo

```bash
# Option 1: Use the fancy animated demo runner
./scripts/fixops-demo-runner.sh

# Option 2: Use the interactive API tester
./scripts/fixops-interactive.sh

# Option 3: Docker
docker build -f Dockerfile.interactive -t fixops-demo .
docker run -it fixops-demo
```

### Customize for Customer

1. **Change application names**: Edit files in `applications/` directory
2. **Change compliance frameworks**: Modify `compliance/` assessments
3. **Change tools**: Update scan files in `scans/` subdirectories

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
| Applications | 4 | Application definitions with metadata |
| SAST | 5 | SonarQube, Checkmarx, Semgrep, Bandit |
| DAST | 2 | OWASP ZAP, Burp Suite |
| SCA | 4 | Snyk, Dependabot, Trivy, Safety |
| Container | 3 | Trivy, Grype, Prisma Cloud |
| Cloud | 3 | AWS Security Hub, Wiz, Orca |
| Runtime | 2 | Falco, Sysdig |
| Compliance | 4 | PCI-DSS, SOC2, HIPAA, GDPR |
| Integrations | 2 | Jira tickets, Slack notifications |
| Remediation | 1 | Remediation tracker |

## Demo Scripts

### fixops-demo-runner.sh

Fancy animated end-to-end demo with:
- Matrix rain effects
- Rainbow/gradient text
- Progress animations
- Customer customization (applications, frameworks)
- Phase-by-phase demo flow

### fixops-interactive.sh

Interactive API/CLI tester with:
- 300+ API endpoints
- 67 CLI commands
- Sample data generation
- Real-time API testing
- File upload support
