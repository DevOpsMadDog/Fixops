# FixOps Comprehensive End-to-End Test Suite

## Overview

This test suite provides a complete simulation of FixOps/ALDECI deployment across 3 enterprise customers with 14 applications, covering all 291 API endpoints with realistic security tool data.

## Test Modes (Commercial Deployment)

The test suite supports three modes for different deployment scenarios:

### 1. Platform Readiness (`--mode platform-readiness`)

**Use for: Fresh deployments, CI/CD validation, platform health checks**

```bash
python comprehensive_e2e_test.py --mode platform-readiness
```

- Validates that the API is up, authentication works, and endpoints respond correctly
- Empty responses (no data) are counted as **PASS** since no data exists yet
- Focus: API availability, auth, endpoint contracts
- **Expected pass rate: 90%+** on a fresh install

### 2. Onboarding Validation (`--mode onboarding-validation`)

**Use for: After customer data ingestion + pipeline run**

```bash
python comprehensive_e2e_test.py --mode onboarding-validation
```

- Validates that data exists after the onboarding process
- Empty responses are counted as **GAP** (data should exist)
- Focus: Data completeness, integration verification
- **Run after:** `POST /inputs/sbom`, `POST /inputs/sarif`, `POST /pipeline/run`

### 3. Full Analysis (`--mode full`) [DEFAULT]

**Use for: Development, debugging, comprehensive analysis**

```bash
python comprehensive_e2e_test.py --mode full
```

- Full test with detailed classification of all results
- NEEDS-SEEDING is reported separately for visibility
- Provides complete breakdown of all result categories

## Commercial Onboarding Process

At a client site, follow this process:

1. **Deploy & Configure**
   ```bash
   # Deploy FixOps
   docker pull devopsaico/fixops:latest
   docker run -d -p 8002:8002 devopsaico/fixops:latest
   
   # Verify platform is ready
   python comprehensive_e2e_test.py --mode platform-readiness
   ```

2. **Ingest Customer Data**
   ```bash
   # Upload SBOM from their security tools (Trivy, Syft, etc.)
   curl -F "file=@sbom.json" http://localhost:8002/inputs/sbom
   
   # Upload SARIF from their scanners (SonarQube, Checkmarx, etc.)
   curl -F "file=@scan.sarif" http://localhost:8002/inputs/sarif
   
   # Upload CVE feed
   curl -F "file=@cve.json" http://localhost:8002/inputs/cve
   ```

3. **Run Pipeline**
   ```bash
   curl http://localhost:8002/pipeline/run
   ```

4. **Validate Onboarding**
   ```bash
   python comprehensive_e2e_test.py --mode onboarding-validation
   ```

## Test Philosophy

**Goal: Find bugs and gaps, not just pass tests.**

Results are classified as:
- **PASS**: Valid response with expected data
- **BUG**: Unexpected error or incorrect behavior (server errors, validation failures)
- **GAP**: Missing feature, permission issue, or incomplete implementation
- **NEEDS-SEEDING**: Empty response expected for unseeded data (only in `full` mode)
- **NOT-APPLICABLE**: Endpoint not relevant for current scenario (file uploads, disabled features)

## Customer Scenarios

### Customer 1: Acme Financial Services (AWS)
- **Industry**: Financial Services
- **Cloud**: AWS (EKS, Lambda, RDS)
- **Compliance**: PCI-DSS, SOX, GLBA
- **Apps**: 5 applications

### Customer 2: MedTech Healthcare (Azure)
- **Industry**: Healthcare
- **Cloud**: Azure (AKS, Functions, CosmosDB)
- **Compliance**: HIPAA, SOC2, HITRUST
- **Apps**: 4 applications

### Customer 3: GameZone Entertainment (GCP)
- **Industry**: Gaming/Media
- **Cloud**: GCP (GKE, Cloud Run, BigQuery)
- **Compliance**: SOC2, GDPR, CCPA
- **Apps**: 5 applications

## 14 Applications

| App | Tech Stack | Cloud | Runtime | Security Tools |
|-----|------------|-------|---------|----------------|
| payment-gateway | Java 17/Spring Boot 3.x | AWS EKS | Kubernetes | SonarQube, Checkmarx, Trivy |
| mobile-banking-bff | Kotlin/Ktor | AWS Lambda | Serverless | Detekt, Snyk, OWASP ZAP |
| user-identity-service | Node.js 20/Express | AWS ECS | Container | ESLint Security, npm audit, Burp |
| edge-cdn-service | Rust/Actix | AWS CloudFront | Edge | cargo-audit, Semgrep |
| inventory-service | Go 1.21/Gin | AWS EKS | Kubernetes | gosec, Trivy, Falco |
| healthcare-api | Python 3.12/FastAPI | Azure AKS | Kubernetes | Bandit, Safety, OWASP ZAP |
| ml-inference-engine | Python/TensorFlow | Azure ML | Container | Bandit, pip-audit, Snyk |
| data-pipeline | Scala 3/Spark | Azure Databricks | Spark | SpotBugs, Snyk, Trivy |
| legacy-mainframe-adapter | COBOL/Java Bridge | Azure VMs | VM | Fortify, Checkmarx |
| gaming-matchmaker | C++17/gRPC | GCP GKE | Kubernetes | Coverity, cppcheck, Falco |
| customer-portal | TypeScript/Next.js 14 | GCP Cloud Run | Serverless | ESLint, Snyk, Nuclei |
| media-transcoder | Go/FFmpeg | GCP GKE | Kubernetes | gosec, Trivy, Falco |
| realtime-analytics | Scala/Kafka Streams | GCP Dataproc | Spark | SpotBugs, Snyk |
| blockchain-bridge | Solidity/Node.js | GCP GKE | Kubernetes | Slither, Mythril, npm audit |

## Mac M5 Silicon Setup Instructions

### Prerequisites

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.12
brew install python@3.12

# Install Docker Desktop for Mac (Apple Silicon)
brew install --cask docker

# Install jq for JSON processing
brew install jq

# Install git (usually pre-installed)
brew install git
```

### Clone and Setup

```bash
# Clone the repository
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Set required environment variables
export FIXOPS_API_TOKEN="demo-token"
export FIXOPS_MODE="demo"
export FIXOPS_DISABLE_TELEMETRY=1
```

### Start the API Server

```bash
# Start the API server
uvicorn apps.api.app:app --port 8002 --host 0.0.0.0

# In a new terminal, verify it's running
curl http://localhost:8002/health
```

### Run the Comprehensive Tests

```bash
# Navigate to test directory
cd /path/to/fixops_comprehensive_test

# Run the full test suite
python3 comprehensive_e2e_test.py

# View results
open results/comprehensive_report.html
```

## Test Phases

### Phase 1: Infrastructure Setup
- Register all 14 applications
- Create teams and users
- Configure integrations
- Set up policies and workflows

### Phase 2: Data Ingestion (per app)
- Upload SARIF (SAST findings)
- Upload SBOM (component inventory)
- Upload CVE feed (vulnerability data)
- Upload CNAPP findings (cloud security)
- Upload design artifacts (threat models)

### Phase 3: Pipeline Execution
- Run security pipeline
- Generate findings and decisions
- Create evidence bundles

### Phase 4: Analysis & Reporting
- Query analytics endpoints
- Generate compliance reports
- Check reachability analysis
- Run micro-pentests

### Phase 5: API Surface Coverage
- Test all 291 endpoints
- Include negative tests
- Verify cross-endpoint consistency

## Sample Data Sources

All sample data is based on real tool output formats:

- **SARIF**: Based on SonarQube, Checkmarx, Semgrep output schemas
- **SBOM**: CycloneDX 1.5 and SPDX 2.3 formats from Trivy/Syft
- **CVE**: NVD JSON 5.0 format
- **CNAPP**: AWS Security Hub, Azure Defender, GCP SCC formats

## Output Files

After running tests:
- `results/comprehensive_report.html` - Visual HTML report
- `results/test_results.json` - Full JSON results
- `results/bugs_and_gaps.md` - Summary of issues found
- `results/coverage_matrix.csv` - API coverage matrix
- `results/consistency_checks.json` - Cross-endpoint validation results

## Troubleshooting

### Common Issues on Mac M5

1. **Docker not starting**: Ensure Docker Desktop is running and has Rosetta enabled for x86 emulation if needed.

2. **Port 8002 in use**: Kill existing process: `lsof -ti:8002 | xargs kill -9`

3. **Python version mismatch**: Ensure you're using Python 3.12: `python3 --version`

4. **Virtual environment issues**: Delete and recreate: `rm -rf .venv && python3.12 -m venv .venv`

## License

MIT License - See LICENSE file in repository root.
