# FixOps Feature-to-Code Mapping

> **Total Codebase: ~270K LOC** | **303 API Endpoints** | **111 CLI Commands** | **16 UI Pages**

This document maps every FixOps feature to its exact code paths, API endpoints, CLI commands, and execution flows.

---

## Deployment & Usage Guide

> **For complete runnable examples of all 303 API endpoints and 111 CLI commands, see [Docker Showcase Guide](DOCKER_SHOWCASE_GUIDE.md)**

### Running Inside Docker (Recommended for Production)

FixOps is distributed as Docker images for easy deployment at customer sites. The main image exposes port 8000 for the API.

**Option 1: Quick Start with Docker Compose**

```bash
# Clone the repo (or use pre-built image)
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# Start the API server
docker compose up -d

# Verify it's running
curl http://localhost:8000/health
```

**Option 2: Run Pre-built Image Directly**

```bash
# Pull and run the image
docker run -d \
  --name fixops-api \
  -p 8000:8000 \
  -e FIXOPS_API_TOKEN=your-secure-token \
  -e FIXOPS_DISABLE_TELEMETRY=1 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  devopsaico/fixops:latest

# Check health
curl http://localhost:8000/health
```

**Docker Container Modes**

The container supports multiple modes via the entrypoint:

| Mode | Command | Description |
|------|---------|-------------|
| `api-only` | `docker run fixops api-only` | Start only the API server (default) |
| `interactive` | `docker run -it fixops interactive` | Interactive API tester shell |
| `demo` | `docker run -it fixops demo` | Run animated ALDECI demo |
| `cli <args>` | `docker run fixops cli teams list` | Run any CLI command |
| `shell` | `docker run -it fixops shell` | Start bash shell |
| `test-all` | `docker run fixops test-all` | Run all API tests |

**Example: Run CLI Commands Inside Docker**

```bash
# List teams
docker run devopsaico/fixops:latest cli teams list

# Run demo pipeline
docker run devopsaico/fixops:latest cli demo --mode demo --pretty

# Run compliance check
docker run devopsaico/fixops:latest cli compliance status --framework PCI-DSS

# Interactive shell for exploration
docker run -it devopsaico/fixops:latest shell
```

**Example: Upload Files to Running Container**

```bash
# Start container
docker run -d --name fixops -p 8000:8000 devopsaico/fixops:latest

# Upload SBOM
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@my-sbom.json;type=application/json" \
  http://localhost:8000/inputs/sbom

# Run pipeline
curl -H "X-API-Key: demo-token-12345" http://localhost:8000/pipeline/run | jq
```

**Available Docker Compose Configurations**

| File | Purpose | Default Token |
|------|---------|---------------|
| `docker-compose.yml` | Main dev stack with sidecars | `demo-token` |
| `docker-compose.demo.yml` | Demo with OpenTelemetry | (env var) |
| `docker-compose.enterprise.yml` | Enterprise with ChromaDB | `enterprise-token` |
| `docker-compose.mpte.yml` | With MPTE pentest service | (env var) |
| `deployment-packs/docker/docker-compose.yml` | Production template | (env var) |

---

### Running Outside Docker (Local Development)

For development or when you need direct access to the codebase.

**Prerequisites**

- Python 3.10+ (tested with 3.11)
- pip and virtualenv
- Optional: `jq` for JSON formatting

**Setup**

```bash
# Clone and setup
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FIXOPS_API_TOKEN="demo-token"
export FIXOPS_DISABLE_TELEMETRY=1
```

**Start the API Server**

```bash
# Development mode with auto-reload
uvicorn apps.api.app:app --reload --port 8000

# Production mode
uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --workers 4
```

**Run CLI Commands Directly**

```bash
# All CLI commands use: python -m core.cli <command> [options]
python -m core.cli --help                    # Show all commands
python -m core.cli demo --mode demo --pretty # Run demo pipeline
python -m core.cli teams list                # List teams
python -m core.cli compliance status         # Check compliance
```

---

## CLI Command Reference

All CLI command groups with their purpose and usage. Run `python -m core.cli <command> --help` for full options.

| Command Group | Purpose | Why You Need It | Example |
|---------------|---------|-----------------|---------|
| `demo` | Run pipeline with bundled fixtures | Quick validation without external data | `python -m core.cli demo --mode demo --pretty` |
| `run` | Execute full FixOps pipeline | Production pipeline execution with overlays | `python -m core.cli run --overlay config/fixops.overlay.yml` |
| `ingest` | Normalize security artifacts | Import SBOM/SARIF/CVE files into FixOps | `python -m core.cli ingest --sbom sbom.json --sarif scan.sarif` |
| `stage-run` | Run single pipeline stage | Debug specific stages (build, test, deploy) | `python -m core.cli stage-run --stage build --input design.csv` |
| `make-decision` | Get remediation decision | Automated accept/reject based on policy | `python -m core.cli make-decision --input findings.json` |
| `analyze` | Analyze findings and output verdict | Quick security assessment | `python -m core.cli analyze --input findings.json` |
| `health` | Check integration readiness | Verify connectors before pipeline run | `python -m core.cli health` |
| `get-evidence` | Copy evidence bundle | Extract signed evidence for audits | `python -m core.cli get-evidence --run pipeline.json --target ./audit` |
| `show-overlay` | Print overlay configuration | Debug configuration without secrets | `python -m core.cli show-overlay --overlay config/fixops.overlay.yml` |
| `train-forecast` | Train severity forecast model | Calibrate risk predictions with history | `python -m core.cli train-forecast --data incidents.csv` |
| `train-bn-lr` | Train Bayesian Network model | Advanced risk modeling | `python -m core.cli train-bn-lr --data training.csv` |
| `predict-bn-lr` | Predict exploitation risk | Score CVEs using trained model | `python -m core.cli predict-bn-lr --input cves.json` |
| `backtest-bn-lr` | Backtest trained model | Validate model accuracy | `python -m core.cli backtest-bn-lr --model model.pkl --test test.csv` |
| `teams` | Manage teams | Create/list/delete security teams | `python -m core.cli teams list` |
| `users` | Manage users | User administration | `python -m core.cli users list` |
| `groups` | Manage finding groups | Cluster related findings | `python -m core.cli groups list` |
| `mpte` | Manage MPTE testing | Basic pentest job management | `python -m core.cli mpte list` |
| `micro-pentest` | Run micro penetration tests | Quick CVE-specific pentest | `python -m core.cli micro-pentest run --cve-ids CVE-2024-1234` |
| `advanced-pentest` | AI-powered pentest | Multi-LLM consensus pentest | `python -m core.cli advanced-pentest run --target https://app.com` |
| `compliance` | Manage compliance | Framework status and reports | `python -m core.cli compliance status --framework PCI-DSS` |
| `reports` | Generate reports | Security reports in various formats | `python -m core.cli reports generate --format pdf` |
| `inventory` | Manage app inventory | Track applications and services | `python -m core.cli inventory list` |
| `policies` | Manage security policies | CRUD for decision policies | `python -m core.cli policies list` |
| `integrations` | Manage connectors | Configure Jira, Slack, etc. | `python -m core.cli integrations list` |
| `analytics` | View security metrics | Dashboard and MTTR stats | `python -m core.cli analytics dashboard` |
| `audit` | View audit logs | Compliance audit trail | `python -m core.cli audit list --days 30` |
| `workflows` | Manage automation | Workflow definitions | `python -m core.cli workflows list` |
| `remediation` | Manage remediation tasks | Track fix progress | `python -m core.cli remediation list --status open` |
| `reachability` | Analyze vulnerability reach | Check if CVE is reachable in code | `python -m core.cli reachability analyze --cve CVE-2024-1234` |
| `correlation` | Manage deduplication | Find duplicate findings | `python -m core.cli correlation analyze` |
| `notifications` | Notification queue | Manage alert delivery | `python -m core.cli notifications list` |

---

## API Router Reference

All 30 API routers with their purpose. Access OpenAPI docs at `http://localhost:8000/docs` when running.

| Router | Endpoints | Purpose | Why You Need It | Base Path |
|--------|-----------|---------|-----------------|-----------|
| Main App | 45 | Core pipeline operations | Upload artifacts, run pipeline, health checks | `/inputs/*`, `/pipeline/*`, `/health` |
| Enhanced | 4 | Multi-LLM decisions | Compare GPT/Claude/Gemini recommendations | `/api/v1/enhanced/*` |
| Feeds | 15 | Threat intelligence | EPSS, KEV, NVD, OSV feed access | `/api/v1/feeds/*` |
| Policies | 6 | Decision policies | CRUD for security policies | `/api/v1/policies/*` |
| Validation | 3 | Input validation | Validate SBOM/SARIF before processing | `/api/v1/validate/*` |
| MPTE | 14 | Basic pentest | Job management for MPTE | `/api/v1/mpte/*` |
| MPTE Enhanced | 19 | Advanced pentest | Playbooks, campaigns, reporting | `/api/v1/mpte/enhanced/*` |
| Micro Pentest | 3 | Quick pentest | CVE-specific micro tests | `/api/v1/micro-pentest/*` |
| Compliance | 12 | Compliance management | Frameworks, assessments, evidence | `/api/v1/compliance/*` |
| Reports | 8 | Report generation | PDF/HTML/JSON security reports | `/api/v1/reports/*` |
| Inventory | 10 | Asset inventory | Applications, services, dependencies | `/api/v1/inventory/*` |
| Analytics | 12 | Security metrics | Dashboard, trends, MTTR | `/api/v1/analytics/*` |
| Audit | 6 | Audit logging | Compliance audit trail | `/api/v1/audit/*` |
| Workflows | 10 | Automation | Workflow definitions and execution | `/api/v1/workflows/*` |
| Remediation | 14 | Fix tracking | Task management, SLA tracking | `/api/v1/remediation/*` |
| Teams | 8 | Team management | CRUD for security teams | `/api/v1/teams/*` |
| Users | 10 | User management | User administration | `/api/v1/users/*` |
| Groups | 6 | Finding groups | Cluster management | `/api/v1/groups/*` |
| Correlation | 8 | Deduplication | Finding correlation | `/api/v1/correlation/*` |
| Notifications | 6 | Alerts | Notification delivery | `/api/v1/notifications/*` |
| Webhooks | 18 | Inbound webhooks | Receive from Jira, GitHub, etc. | `/api/v1/webhooks/*` |
| Integrations | 12 | Connector config | Configure external systems | `/api/v1/integrations/*` |
| Marketplace | 8 | Extensions | Plugin marketplace | `/api/v1/marketplace/*` |
| Evidence | 6 | Evidence bundles | Cryptographic evidence | `/api/v1/evidence/*` |
| SSDLC | 8 | Secure SDLC | Pipeline security gates | `/api/v1/ssdlc/*` |
| Bulk | 6 | Bulk operations | Mass updates, imports | `/api/v1/bulk/*` |
| Comments | 4 | Collaboration | Finding comments | `/api/v1/comments/*` |
| Attachments | 4 | File attachments | Evidence files | `/api/v1/attachments/*` |
| Provenance | 4 | Supply chain | SLSA provenance | `/api/v1/provenance/*` |
| Backend Routes | 18 | Legacy backend | Additional backend endpoints | `/api/v1/*` |

---

## Quick Start Examples

Real commands you can run immediately. See [detailed feature sections](#feature-1-vulnerability-intake--normalization) below for full API/CLI reference.

### 1. Run Demo Pipeline (No External Services Required)

```bash
# Demo mode - generates pipeline output and evidence bundles
python -m core.cli demo --mode demo --output out/pipeline-demo.json --pretty

# Enterprise mode - with encryption enabled
python -m core.cli demo --mode enterprise --output out/pipeline-enterprise.json --pretty
```

### 2. Start API Server & Upload Scan Results

```bash
# Terminal 1: Start the API server
export FIXOPS_API_TOKEN="demo-token"
export FIXOPS_DISABLE_TELEMETRY=1
uvicorn apps.api.app:app --reload --port 8000

# Terminal 2: Upload security artifacts
curl -H "X-API-Key: demo-token" \
  -F "file=@simulations/demo_pack/sbom.json;type=application/json" \
  http://127.0.0.1:8000/inputs/sbom

curl -H "X-API-Key: demo-token" \
  -F "file=@simulations/demo_pack/scan.sarif;type=application/json" \
  http://127.0.0.1:8000/inputs/sarif

# Run the pipeline
curl -H "X-API-Key: demo-token" http://127.0.0.1:8000/pipeline/run | jq
```

### 3. CLI Commands by Feature

```bash
# Intake & Normalization
python -m core.cli ingest --sbom artifacts/sbom.json --sarif artifacts/scan.sarif

# Risk Scoring
python -m core.cli reachability analyze --cve CVE-2024-1234

# Decision Engine
python -m core.cli run --overlay config/fixops.overlay.yml --output out/decision.json

# Compliance & Evidence
python -m core.cli compliance status --framework PCI-DSS
python -m core.cli compliance report --format pdf --output out/compliance.pdf

# Team Management
python -m core.cli teams list
python -m core.cli users list

# Analytics
python -m core.cli analytics dashboard
python -m core.cli analytics mttr --days 90

# Remediation Workflow
python -m core.cli remediation list --status open
python -m core.cli workflows list
```

### 4. API Endpoints by Feature

```bash
# Health Check
curl http://127.0.0.1:8000/health

# Get LLM Capabilities
curl -H "X-API-Key: demo-token" \
  http://127.0.0.1:8000/api/v1/enhanced/capabilities | jq

# Compare LLM Recommendations
curl -H "X-API-Key: demo-token" -X POST \
  -H "Content-Type: application/json" \
  -d '{"service_name":"demo-app","security_findings":[{"rule_id":"SAST001","severity":"high","description":"SQL injection"}],"business_context":{"environment":"demo","criticality":"high"}}' \
  http://127.0.0.1:8000/api/v1/enhanced/compare-llms | jq

# List Threat Feeds
curl -H "X-API-Key: demo-token" \
  http://127.0.0.1:8000/api/v1/feeds/status | jq

# Get EPSS Score for a CVE
curl -H "X-API-Key: demo-token" \
  http://127.0.0.1:8000/api/v1/feeds/epss/CVE-2024-1234 | jq

# Check if CVE is in KEV
curl -H "X-API-Key: demo-token" \
  http://127.0.0.1:8000/api/v1/feeds/kev/check/CVE-2024-1234 | jq

# Analytics Dashboard
curl -H "X-API-Key: demo-token" \
  http://127.0.0.1:8000/api/v1/analytics/dashboard | jq

# List Remediation Tasks
curl -H "X-API-Key: demo-token" \
  http://127.0.0.1:8000/api/v1/remediation/tasks | jq
```

### 5. Micro Penetration Testing (Requires MPTE Service)

```bash
# CLI: Run micro pentest
python -m core.cli micro-pentest run \
  --cve-ids CVE-2024-1234 \
  --target-urls https://example.com \
  --context "Production web application"

# API: Run micro pentest
curl -H "X-API-Key: demo-token" -X POST \
  -H "Content-Type: application/json" \
  -d '{"cve_ids":["CVE-2024-1234"],"target_urls":["https://example.com"],"context":"Production web app"}' \
  http://127.0.0.1:8000/api/v1/micro-pentest/run | jq
```

### 6. Run Tests

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/test_api_smoke.py           # API endpoints
pytest tests/test_micro_pentest_core.py  # Micro pentest
pytest tests/risk/test_scoring.py        # Risk scoring
pytest tests/test_crypto.py              # Evidence signing
```

---

## Table of Contents

- [Feature 1: Vulnerability Intake & Normalization](#feature-1-vulnerability-intake--normalization)
- [Feature 2: Risk Scoring & Prioritization](#feature-2-risk-scoring--prioritization)
- [Feature 3: Automated Decision Engine](#feature-3-automated-decision-engine)
- [Feature 4: Penetration Testing](#feature-4-penetration-testing)
- [Feature 5: Remediation Workflow](#feature-5-remediation-workflow)
- [Feature 6: Compliance & Evidence](#feature-6-compliance--evidence)
- [Feature 7: Integrations & Connectors](#feature-7-integrations--connectors)
- [Feature 8: Security Scanning](#feature-8-security-scanning)
- [Feature 9: Deduplication & Correlation](#feature-9-deduplication--correlation)
- [Feature 10: Analytics & Dashboards](#feature-10-analytics--dashboards)
- [Feature 11: Team & User Management](#feature-11-team--user-management)
- [Feature 12: Marketplace](#feature-12-marketplace)
- [Feature 13: Bulk Operations](#feature-13-bulk-operations)
- [Feature 14: Collaboration](#feature-14-collaboration)
- [Feature 15: Frontend UI](#feature-15-frontend-ui)

---

## Feature 1: Vulnerability Intake & Normalization

**Purpose:** Ingest security scan results from any tool (SARIF, SBOM, CVE, VEX, CNAPP, dark web intel, and more) and normalize to a unified finding model with dynamic asset inventory.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Main API App | `apps/api/app.py` | 1,747 | `upload_sbom()`, `upload_sarif()`, `upload_cve()`, `upload_vex()` |
| **Ingestion Module** | `apps/api/ingestion.py` | 2,099 | `NormalizerRegistry`, `IngestionService`, `UnifiedFinding`, format normalizers |
| **Registry Config** | `config/normalizers/registry.yaml` | 150 | YAML plugin configuration for normalizers |
| Normalizers | `apps/api/normalizers.py` | 1,838 | `normalize_sarif()`, `normalize_sbom()`, `normalize_cve()` |
| Format Adapters | `core/adapters.py` | 1,148 | `SARIFAdapter`, `SBOMAdapter`, `CVEAdapter`, `VEXAdapter` |
| Validation Router | `apps/api/validation_router.py` | 491 | `validate_sbom()`, `validate_sarif()` |
| SARIF Canonicalization | `core/sarif_canon.py` | 264 | `canonicalize_sarif()` |
| SBOM Library | `lib4sbom/` | 699 | SBOM parsing utilities |
| CLI Handler | `core/cli.py:403-417` | 15 | `_handle_ingest()`, `_handle_ingest_file()` |
| Stage Runner | `core/stage_runner.py` | 1,149 | `run_stage()`, `StageRunner` |

### Supported Formats (Scanner-Agnostic)

| Format | Normalizer Class | Auto-Detection | Notes |
|--------|------------------|----------------|-------|
| SARIF 2.1+ | `SARIFNormalizer` | Yes | Supports schema drift (2.1 → 2.2) |
| CycloneDX | `CycloneDXNormalizer` | Yes | SBOM format |
| SPDX | `SPDXNormalizer` | Yes | SBOM format |
| VEX | `VEXNormalizer` | Yes | Vulnerability Exploitability eXchange |
| CNAPP | `CNAPPNormalizer` | Yes | Cloud-Native Application Protection |
| Trivy | `TrivyNormalizer` | Yes | Container/filesystem scanner |
| Grype | `GrypeNormalizer` | Yes | Container vulnerability scanner |
| Semgrep | `SemgrepNormalizer` | Yes | SAST scanner |
| Dependabot | `DependabotNormalizer` | Yes | GitHub dependency alerts |
| Dark Web Intel | `DarkWebIntelNormalizer` | Yes | Threat intelligence feeds |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| POST | `/inputs/sbom` | `upload_sbom` | `apps/api/app.py:850-890` |
| POST | `/inputs/sarif` | `upload_sarif` | `apps/api/app.py:892-932` |
| POST | `/inputs/cve` | `upload_cve` | `apps/api/app.py:934-974` |
| POST | `/inputs/vex` | `upload_vex` | `apps/api/app.py:976-1016` |
| POST | `/inputs/design` | `upload_design` | `apps/api/app.py:808-848` |
| POST | `/inputs/cnapp` | `upload_cnapp` | `apps/api/app.py:1018-1033` |
| **POST** | **`/api/v1/ingest/multipart`** | `ingest_multipart` | `apps/api/ingestion.py` |
| **GET** | **`/api/v1/ingest/assets`** | `get_asset_inventory` | `apps/api/ingestion.py` |
| **GET** | **`/api/v1/ingest/formats`** | `list_formats` | `apps/api/ingestion.py` |
| POST | `/api/v1/validate/input` | `validate_input` | `apps/api/validation_router.py:225-380` |
| POST | `/api/v1/validate/batch` | `validate_batch` | `apps/api/validation_router.py:381-423` |
| GET | `/api/v1/validate/supported-formats` | `get_supported_formats` | `apps/api/validation_router.py:424-491` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `ingest --sbom FILE` | `_handle_ingest()` | `core/cli.py:403-417` |
| `ingest --sarif FILE` | `_handle_ingest()` | `core/cli.py:403-417` |
| **`ingest-file --file FILE [--format FORMAT]`** | `_handle_ingest_file()` | `core/cli.py` |
| `stage-run --stage build` | `_handle_stage_run()` | `core/cli.py:622-678` |
| `stage-run --stage test` | `_handle_stage_run()` | `core/cli.py:622-678` |

### Code Flow

```
User Upload (API/CLI)
    |
    v
[apps/api/app.py:upload_sbom()] or [core/cli.py:_handle_ingest()]
    |
    v
[apps/api/normalizers.py:normalize_sbom()]
    |-- Detect format (CycloneDX, SPDX, etc.)
    |-- Parse components
    |-- Extract vulnerabilities
    |
    v
[core/adapters.py:SBOMAdapter.adapt()]
    |-- Map to internal schema
    |-- Enrich with metadata
    |
    v
[core/storage.py:store_findings()]
    |
    v
Normalized findings in data/findings.db
```

### Tests

| Test File | LOC | Coverage |
|-----------|-----|----------|
| `tests/test_api_smoke.py` | 632 | Ingestion endpoints |
| `tests/test_normalizers.py` | 450 | All normalizers |
| `tests/test_adapters.py` | 380 | Format adapters |

---

## Feature 2: Risk Scoring & Prioritization

**Purpose:** Score vulnerabilities using CVSS + EPSS + KEV + reachability analysis to prioritize what matters.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Risk Scoring | `risk/scoring.py` | 467 | `calculate_risk_score()`, `RiskScorer` |
| EPSS Feed | `risk/feeds/epss.py` | 146 | `EPSSFeed`, `get_epss_score()` |
| KEV Feed | `risk/feeds/kev.py` | 135 | `KEVFeed`, `is_in_kev()` |
| NVD Feed | `risk/feeds/nvd.py` | 233 | `NVDFeed`, `get_cvss()` |
| OSV Feed | `risk/feeds/osv.py` | 223 | `OSVFeed`, `query_osv()` |
| Feed Orchestrator | `risk/feeds/orchestrator.py` | 378 | `FeedOrchestrator`, `refresh_all()` |
| Reachability Analyzer | `risk/reachability/analyzer.py` | 809 | `ReachabilityAnalyzer`, `analyze()` |
| Proprietary Analyzer | `risk/reachability/proprietary_analyzer.py` | 964 | `ProprietaryAnalyzer` |
| Code Analysis | `risk/reachability/code_analysis.py` | 553 | `analyze_code_paths()` |
| Call Graph | `risk/reachability/call_graph.py` | 213 | `build_call_graph()` |
| Feeds Router | `apps/api/feeds_router.py` | 660 | Feed API endpoints |
| Probabilistic | `core/probabilistic.py` | 692 | `BayesianRiskModel` |
| Forecasting | `risk/forecasting.py` | 285 | `forecast_risk()` |
| Severity Promotion | `core/severity_promotion.py` | 302 | `promote_severity()` |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| GET | `/api/v1/feeds/epss` | `get_epss` | `apps/api/feeds_router.py:45-80` |
| GET | `/api/v1/feeds/epss/{cve_id}` | `get_epss_score` | `apps/api/feeds_router.py:82-110` |
| GET | `/api/v1/feeds/kev` | `get_kev` | `apps/api/feeds_router.py:112-145` |
| GET | `/api/v1/feeds/kev/check/{cve_id}` | `check_kev` | `apps/api/feeds_router.py:147-175` |
| GET | `/api/v1/feeds/nvd/{cve_id}` | `get_nvd` | `apps/api/feeds_router.py:177-210` |
| POST | `/api/v1/feeds/refresh` | `refresh_feeds` | `apps/api/feeds_router.py:212-250` |
| GET | `/api/v1/feeds/status` | `get_feed_status` | `apps/api/feeds_router.py:252-280` |
| POST | `/api/v1/reachability/analyze` | `analyze_reachability` | `apps/api/feeds_router.py:400-450` |
| GET | `/api/v1/reachability/results/{id}` | `get_results` | `apps/api/feeds_router.py:452-490` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `reachability analyze --cve CVE-ID` | `_handle_reachability()` | `core/cli.py:3335-3403` |
| `reachability bulk --file cves.txt` | `_handle_reachability()` | `core/cli.py:3335-3403` |
| `train-forecast --data FILE` | `_handle_train_forecast()` | `core/cli.py:933-964` |
| `predict-bn-lr --input FILE` | `_handle_predict_bn_lr()` | `core/cli.py:1029-1077` |

### Code Flow

```
CVE Input
    |
    v
[risk/scoring.py:calculate_risk_score()]
    |
    +---> [risk/feeds/epss.py:get_epss_score()] --> EPSS probability
    |
    +---> [risk/feeds/kev.py:is_in_kev()] --> KEV status (boolean)
    |
    +---> [risk/feeds/nvd.py:get_cvss()] --> CVSS base score
    |
    +---> [risk/reachability/analyzer.py:analyze()]
    |         |
    |         +---> [risk/reachability/code_analysis.py:analyze_code_paths()]
    |         |
    |         +---> [risk/reachability/call_graph.py:build_call_graph()]
    |         |
    |         v
    |     Reachability score (0-1)
    |
    v
Combined Risk Score = f(CVSS, EPSS, KEV, Reachability)
    |
    v
[core/severity_promotion.py:promote_severity()] --> Final priority
```

### Tests

| Test File | LOC | Coverage |
|-----------|-----|----------|
| `tests/risk/test_scoring.py` | 631 | Scoring algorithms |
| `tests/risk/reachability/test_analyzer_core.py` | 611 | Reachability |
| `tests/test_threat_intelligence_feeds.py` | 658 | All feeds |
| `tests/test_threat_intelligence_comprehensive_coverage.py` | 2,441 | Full coverage |

---

## Feature 3: Automated Decision Engine

**Purpose:** Multi-LLM consensus for remediation decisions using GPT, Claude, Gemini with hallucination guards.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Enhanced Decision | `core/enhanced_decision.py` | 1,279 | `EnhancedDecisionEngine`, `compare_llms()`, `get_consensus()` |
| LLM Providers | `core/llm_providers.py` | 659 | `GPTProvider`, `ClaudeProvider`, `GeminiProvider`, `SentinelProvider` |
| Decision Tree | `core/decision_tree.py` | 329 | `DecisionTree`, `evaluate()` |
| Decision Policy | `core/decision_policy.py` | 328 | `PolicyEngine`, `apply_policy()` |
| Hallucination Guards | `core/hallucination_guards.py` | 324 | `HallucinationGuard`, `validate_response()` |
| Policy Models | `core/policy_models.py` | 46 | `Policy`, `PolicyRule` |
| Policies Router | `apps/api/policies_router.py` | 182 | Policy CRUD endpoints |
| Enhanced Routes | `apps/api/routes/enhanced.py` | 110 | Enhanced decision endpoints |
| Enterprise Decision | `fixops-enterprise/src/services/decision_engine.py` | 436 | `EnterpriseDecisionEngine` |
| Enhanced Enterprise | `fixops-enterprise/src/services/enhanced_decision_engine.py` | 134 | Enterprise enhancements |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| POST | `/api/v1/enhanced/analysis` | `run_enhanced_analysis` | `apps/api/routes/enhanced.py:40-68` |
| POST | `/api/v1/enhanced/compare-llms` | `compare_llms` | `apps/api/routes/enhanced.py:69-91` |
| GET | `/api/v1/enhanced/capabilities` | `enhanced_capabilities` | `apps/api/routes/enhanced.py:92-102` |
| GET | `/api/v1/enhanced/signals` | `enhanced_signals` | `apps/api/routes/enhanced.py:103-110` |
| GET | `/api/v1/policies` | `list_policies` | `apps/api/policies_router.py:30-55` |
| POST | `/api/v1/policies` | `create_policy` | `apps/api/policies_router.py:57-95` |
| GET | `/api/v1/policies/{id}` | `get_policy` | `apps/api/policies_router.py:97-120` |
| PUT | `/api/v1/policies/{id}` | `update_policy` | `apps/api/policies_router.py:122-155` |
| DELETE | `/api/v1/policies/{id}` | `delete_policy` | `apps/api/policies_router.py:157-182` |
| POST | `/api/v1/policies/{id}/test` | `test_policy` | `apps/api/policies_router.py:184-220` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `make-decision --input FILE` | `_handle_make_decision()` | `core/cli.py:455-474` |
| `run --overlay config.yml` | `_handle_run()` | `core/cli.py:903-915` |
| `policies list` | `_handle_policies()` | `core/cli.py:2225-2414` |
| `policies create --name NAME` | `_handle_policies()` | `core/cli.py:2225-2414` |
| `policies test --id ID` | `_handle_policies()` | `core/cli.py:2225-2414` |

### Code Flow

```
Security Findings Input
    |
    v
[core/enhanced_decision.py:EnhancedDecisionEngine.decide()]
    |
    +---> [core/llm_providers.py:GPTProvider.analyze()]
    |         |
    |         v
    |     GPT-4 recommendation
    |
    +---> [core/llm_providers.py:ClaudeProvider.analyze()]
    |         |
    |         v
    |     Claude recommendation
    |
    +---> [core/llm_providers.py:GeminiProvider.analyze()]
    |         |
    |         v
    |     Gemini recommendation
    |
    v
[core/enhanced_decision.py:get_consensus()]
    |
    +---> [core/hallucination_guards.py:validate_response()]
    |         |-- Check for hallucinations
    |         |-- Verify CVE references
    |         |-- Validate remediation steps
    |
    v
[core/decision_policy.py:apply_policy()]
    |-- Apply organization policies
    |-- Check SLA requirements
    |-- Apply risk thresholds
    |
    v
Final Decision (accept/reject/defer/escalate)
```

### Tests

| Test File | LOC | Coverage |
|-----------|-----|----------|
| `tests/test_decision_tree_e2e.py` | 574 | Decision trees |
| `tests/e2e/test_critical_decision_policy.py` | 1,008 | Policy engine |

---

## Feature 4: Penetration Testing

**Purpose:** Automated and micro penetration testing via MPTE integration.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Micro Pentest Core | `core/micro_pentest.py` | 445 | `run_micro_pentest()`, `MicroPentestConfig`, `BatchTestConfig` |
| Advanced Pentest | `core/mpte_advanced.py` | 1,093 | `AdvancedPentestEngine`, `run_advanced_pentest()` |
| MPTE DB | `core/mpte_db.py` | 507 | `MPTEDB`, job storage |
| MPTE Client | `integrations/mpte_client.py` | 388 | `MPTEClient`, API client |
| MPTE Service | `integrations/mpte_service.py` | 470 | `MPTEService` |
| Decision Integration | `integrations/mpte_decision_integration.py` | 277 | Integration layer |
| Basic Router | `apps/api/mpte_router.py` | 290 | 14 basic endpoints |
| Enhanced Router | `apps/api/mpte_router.py` | 619 | 19 advanced endpoints |
| Micro Router | `apps/api/micro_pentest_router.py` | 222 | 3 micro endpoints |
| Enterprise Engine | `fixops-enterprise/src/services/advanced_pentest_engine.py` | 2,292 | Enterprise pentest |
| Automated Pentest | `fixops-enterprise/src/services/automated_pentest.py` | 1,430 | Automation |
| Playbook Executor | `fixops-enterprise/src/services/playbook_executor.py` | 916 | Playbook execution |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| POST | `/api/v1/mpte/requests` | `create_request` | `apps/api/mpte_router.py:45-90` |
| GET | `/api/v1/mpte/requests` | `list_requests` | `apps/api/mpte_router.py:92-120` |
| GET | `/api/v1/mpte/requests/{id}` | `get_request` | `apps/api/mpte_router.py:122-150` |
| GET | `/api/v1/mpte/requests/{id}/status` | `get_status` | `apps/api/mpte_router.py:152-180` |
| GET | `/api/v1/mpte/requests/{id}/results` | `get_results` | `apps/api/mpte_router.py:182-220` |
| POST | `/api/v1/micro-pentest/run` | `run_pentest` | `apps/api/micro_pentest_router.py:98-140` |
| GET | `/api/v1/micro-pentest/status/{flow_id}` | `get_pentest_status` | `apps/api/micro_pentest_router.py:143-164` |
| POST | `/api/v1/micro-pentest/batch` | `run_batch_pentests` | `apps/api/micro_pentest_router.py:167-219` |
| POST | `/api/v1/advanced-pentest/run` | `run_advanced` | `apps/api/mpte_router.py:80-150` |
| POST | `/api/v1/advanced-pentest/threat-intel` | `get_threat_intel` | `apps/api/mpte_router.py:152-200` |
| POST | `/api/v1/advanced-pentest/simulate` | `simulate_attack` | `apps/api/mpte_router.py:202-280` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `mpte create --target APP --cve CVE` | `_handle_mpte()` | `core/cli.py:1346-1443` |
| `mpte list` | `_handle_mpte()` | `core/cli.py:1346-1443` |
| `mpte status --id ID` | `_handle_mpte()` | `core/cli.py:1346-1443` |
| `micro-pentest run --cve-ids CVE --target-urls URL` | `_handle_micro_pentest()` | `core/cli.py:1451-1581` |
| `micro-pentest status FLOW_ID` | `_handle_micro_pentest()` | `core/cli.py:1451-1581` |
| `micro-pentest batch CONFIG.json` | `_handle_micro_pentest()` | `core/cli.py:1451-1581` |
| `advanced-pentest run --target APP` | `_handle_advanced_pentest()` | `core/cli.py:3091-3327` |
| `advanced-pentest simulate --cve CVE` | `_handle_advanced_pentest()` | `core/cli.py:3091-3327` |

### Code Flow

```
Pentest Request (CVE + Target)
    |
    v
[apps/api/micro_pentest_router.py:run_pentest()]
    |
    v
[core/micro_pentest.py:run_micro_pentest()]
    |-- Validate CVE ID format (CVE-YYYY-NNNNN)
    |-- Validate target URL (no SSRF)
    |-- Sanitize context (size limit)
    |
    v
[integrations/mpte_client.py:MPTEClient.create_flow()]
    |-- POST to MPTE service
    |-- Get flow_id
    |
    v
[core/mpte_db.py:store_job()]
    |-- Store job metadata
    |-- Track status
    |
    v
MPTE executes pentest asynchronously
    |
    v
[apps/api/micro_pentest_router.py:get_pentest_status()]
    |
    v
[core/micro_pentest.py:get_micro_pentest_status()]
    |
    v
[integrations/mpte_client.py:get_flow_status()]
    |
    v
Return findings + recommendations
```

### Tests

| Test File | LOC | Coverage |
|-----------|-----|----------|
| `tests/test_micro_pentest_core.py` | 694 | Core functions |
| `tests/test_micro_pentest_cli.py` | 698 | CLI commands |
| `tests/test_micro_pentest_router.py` | 440 | API endpoints |

---

## Feature 5: Remediation Workflow

**Purpose:** Track, assign, verify, and close vulnerability remediation tasks.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Auto Remediation | `core/automated_remediation.py` | 649 | `AutoRemediator`, `generate_fix()` |
| Workflow DB | `core/workflow_db.py` | 265 | `WorkflowDB`, workflow storage |
| Workflow Models | `core/workflow_models.py` | 87 | `Workflow`, `WorkflowStep` |
| Remediation Router | `apps/api/remediation_router.py` | 268 | 13 remediation endpoints |
| Workflows Router | `apps/api/workflows_router.py` | 189 | 7 workflow endpoints |
| Playbook Executor | `fixops-enterprise/src/services/playbook_executor.py` | 916 | `PlaybookExecutor` |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| GET | `/api/v1/remediation/tasks` | `list_tasks` | `apps/api/remediation_router.py:35-70` |
| POST | `/api/v1/remediation/tasks` | `create_task` | `apps/api/remediation_router.py:72-115` |
| GET | `/api/v1/remediation/tasks/{id}` | `get_task` | `apps/api/remediation_router.py:117-145` |
| PUT | `/api/v1/remediation/tasks/{id}/assign` | `assign_task` | `apps/api/remediation_router.py:147-180` |
| PUT | `/api/v1/remediation/tasks/{id}/transition` | `transition_task` | `apps/api/remediation_router.py:182-220` |
| POST | `/api/v1/remediation/tasks/{id}/verify` | `verify_task` | `apps/api/remediation_router.py:222-268` |
| GET | `/api/v1/workflows` | `list_workflows` | `apps/api/workflows_router.py:30-55` |
| POST | `/api/v1/workflows` | `create_workflow` | `apps/api/workflows_router.py:57-100` |
| POST | `/api/v1/workflows/{id}/execute` | `execute_workflow` | `apps/api/workflows_router.py:140-189` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `remediation list --status open` | `_handle_remediation_cli()` | `core/cli.py:3581-3732` |
| `remediation assign --task-id ID --user EMAIL` | `_handle_remediation_cli()` | `core/cli.py:3581-3732` |
| `remediation transition --task-id ID --status fixed` | `_handle_remediation_cli()` | `core/cli.py:3581-3732` |
| `workflows list` | `_handle_workflows()` | `core/cli.py:2866-3083` |
| `workflows execute --id ID` | `_handle_workflows()` | `core/cli.py:2866-3083` |

### Code Flow

```
New Finding
    |
    v
[apps/api/remediation_router.py:create_task()]
    |
    v
[core/workflow_db.py:create_task()]
    |-- Create task record
    |-- Set initial status (open)
    |-- Calculate SLA deadline
    |
    v
[core/automated_remediation.py:generate_fix()]
    |-- Analyze vulnerability
    |-- Generate fix suggestion
    |-- Create PR template (if applicable)
    |
    v
Task assigned to developer
    |
    v
[apps/api/remediation_router.py:transition_task()]
    |-- Update status (in_progress -> fixed)
    |
    v
[apps/api/remediation_router.py:verify_task()]
    |-- Re-scan to verify fix
    |-- Update status (verified/reopened)
    |
    v
Task closed
```

### Tests

| Test File | LOC | Coverage |
|-----------|-----|----------|
| `tests/test_remediation.py` | 450 | Remediation workflow |
| `tests/test_workflows.py` | 380 | Workflow engine |

---

## Feature 6: Compliance & Evidence

**Purpose:** Generate audit evidence, compliance reports, SLSA attestations.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Evidence Core | `core/evidence.py` | 436 | `EvidenceBundle`, `create_bundle()` |
| Evidence Indexer | `core/evidence_indexer.py` | 279 | `EvidenceIndexer` |
| Crypto | `core/crypto.py` | 570 | `sign_evidence()`, `encrypt_bundle()` |
| Compliance | `core/compliance.py` | 133 | `check_compliance()` |
| Attestation | `services/provenance/attestation.py` | 694 | `create_attestation()`, SLSA |
| Audit Router | `apps/api/audit_router.py` | 209 | 10 audit endpoints |
| Reports Router | `apps/api/reports_router.py` | 263 | 10 report endpoints |
| Evidence Router | `backend/api/evidence/router.py` | 330 | 4 evidence endpoints |
| Provenance Router | `backend/api/provenance/router.py` | 51 | 2 provenance endpoints |
| MITRE Analyzer | `fixops-enterprise/src/services/mitre_compliance_analyzer.py` | 764 | MITRE ATT&CK mapping |
| Enterprise Crypto | `fixops-enterprise/src/utils/crypto.py` | 723 | HSM support |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| GET | `/api/v1/audit/logs` | `get_logs` | `apps/api/audit_router.py:35-75` |
| GET | `/api/v1/audit/decisions` | `get_decisions` | `apps/api/audit_router.py:77-115` |
| POST | `/api/v1/audit/export` | `export_audit` | `apps/api/audit_router.py:160-209` |
| GET | `/api/v1/reports` | `list_reports` | `apps/api/reports_router.py:35-65` |
| POST | `/api/v1/reports/generate` | `generate_report` | `apps/api/reports_router.py:67-130` |
| GET | `/api/v1/reports/{id}` | `get_report` | `apps/api/reports_router.py:132-165` |
| POST | `/api/v1/reports/{id}/export` | `export_report` | `apps/api/reports_router.py:200-263` |
| GET | `/api/v1/evidence/{id}` | `get_evidence` | `backend/api/evidence/router.py:45-100` |
| POST | `/api/v1/evidence/bundle` | `create_bundle` | `backend/api/evidence/router.py:102-180` |
| POST | `/api/v1/provenance/attest` | `create_attestation` | `backend/api/provenance/router.py:25-51` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `compliance status --framework PCI-DSS` | `_handle_compliance()` | `core/cli.py:1589-1842` |
| `compliance frameworks` | `_handle_compliance()` | `core/cli.py:1589-1842` |
| `compliance report --format pdf` | `_handle_compliance()` | `core/cli.py:1589-1842` |
| `get-evidence --run-id ID` | `_handle_get_evidence()` | `core/cli.py:586-619` |
| `copy-evidence --run ID --target DIR` | `_copy_evidence()` | `core/cli.py:204-238` |
| `audit logs --days 30` | `_handle_audit()` | `core/cli.py:2704-2858` |
| `reports generate --type executive` | `_handle_reports()` | `core/cli.py:1850-2062` |

### Code Flow

```
Pipeline Run Complete
    |
    v
[core/evidence.py:create_bundle()]
    |-- Collect all artifacts
    |-- Include decision logs
    |-- Include scan results
    |
    v
[core/crypto.py:sign_evidence()]
    |-- RSA signature
    |-- Timestamp
    |
    v
[services/provenance/attestation.py:create_attestation()]
    |-- SLSA provenance
    |-- In-toto format
    |
    v
Evidence bundle stored in data/evidence/
    |
    v
[apps/api/reports_router.py:generate_report()]
    |-- Compliance mapping
    |-- Executive summary
    |-- Technical details
    |
    v
PDF/HTML/JSON report
```

### Tests

| Test File | LOC | Coverage |
|-----------|-----|----------|
| `tests/test_crypto.py` | 847 | Signing/encryption |
| `tests/services/provenance/test_attestation.py` | 116 | SLSA attestation |

---

## Feature 7: Integrations & Connectors

**Purpose:** Jira, Confluence, Slack, GitHub, GitLab, ServiceNow, Azure DevOps bidirectional integrations with full CRUD operations.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Connectors | `core/connectors.py` | 2,885 | `JiraConnector`, `ConfluenceConnector`, `SlackConnector`, `ServiceNowConnector`, `GitLabConnector`, `AzureDevOpsConnector`, `GitHubConnector` |
| Integration DB | `core/integration_db.py` | 167 | `IntegrationDB` |
| Integration Models | `core/integration_models.py` | 65 | `Integration`, `WebhookConfig` |
| Webhooks Router | `apps/api/webhooks_router.py` | 1,805 | 21 webhook + outbox endpoints |
| Integrations Router | `apps/api/integrations_router.py` | 338 | 8 integration endpoints |
| API Dependencies | `apps/api/dependencies.py` | 83 | `get_org_id`, `get_org_id_required`, `get_correlation_id` |
| Integrations Module | `apps/api/integrations.py` | 417 | Integration helpers |
| GitHub Adapter | `integrations/github/adapter.py` | 105 | `GitHubAdapter` |
| Jenkins Adapter | `integrations/jenkins/adapter.py` | 82 | `JenkinsAdapter` |
| SonarQube Adapter | `integrations/sonarqube/adapter.py` | 49 | `SonarQubeAdapter` |

### Enterprise Connector Operations

| Connector | Operations | Status |
|-----------|------------|--------|
| **Jira** | `create_issue()`, `update_issue()`, `transition_issue()`, `add_comment()` | Full CRUD |
| **ServiceNow** | `create_incident()`, `update_incident()`, `add_work_note()` | Full CRUD |
| **GitLab** | `create_issue()`, `update_issue()`, `add_comment()` | Full CRUD |
| **Azure DevOps** | `create_work_item()`, `update_work_item()`, `add_comment()` | Full CRUD |
| **GitHub** | `create_issue()`, `update_issue()`, `add_comment()` | Full CRUD |
| **Confluence** | `create_page()`, `update_page()` | Bidirectional |
| **Slack** | `post_message()` | Outbound only |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| POST | `/api/v1/webhooks/jira` | `handle_jira_webhook` | `apps/api/webhooks_router.py:100-250` |
| POST | `/api/v1/webhooks/github` | `handle_github_webhook` | `apps/api/webhooks_router.py:252-400` |
| POST | `/api/v1/webhooks/gitlab` | `handle_gitlab_webhook` | `apps/api/webhooks_router.py:402-550` |
| POST | `/api/v1/webhooks/servicenow` | `handle_servicenow_webhook` | `apps/api/webhooks_router.py:552-650` |
| POST | `/api/v1/webhooks/azure-devops` | `handle_azure_devops_webhook` | `apps/api/webhooks_router.py:652-750` |
| GET | `/api/v1/webhooks/outbox` | `list_outbox` | `apps/api/webhooks_router.py:752-800` |
| GET | `/api/v1/webhooks/outbox/{id}` | `get_outbox_item` | `apps/api/webhooks_router.py:802-850` |
| POST | `/api/v1/webhooks/outbox/{id}/execute` | `execute_outbox_item` | `apps/api/webhooks_router.py:852-950` |
| POST | `/api/v1/webhooks/outbox/process-pending` | `process_pending_outbox` | `apps/api/webhooks_router.py:952-1050` |
| GET | `/api/v1/integrations` | `list_integrations` | `apps/api/integrations_router.py:35-65` |
| POST | `/api/v1/integrations/configure` | `configure_integration` | `apps/api/integrations_router.py:67-130` |
| POST | `/api/v1/integrations/{id}/test` | `test_integration` | `apps/api/integrations_router.py:132-180` |
| POST | `/api/v1/integrations/{id}/sync` | `sync_integration` | `apps/api/integrations_router.py:182-253` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `integrations list` | `_handle_integrations()` | `core/cli.py:2422-2575` |
| `integrations configure --type jira --url URL` | `_handle_integrations()` | `core/cli.py:2422-2575` |
| `integrations test --id ID` | `_handle_integrations()` | `core/cli.py:2422-2575` |
| `integrations sync --id ID` | `_handle_integrations()` | `core/cli.py:2422-2575` |

### Code Flow

```
Jira Webhook (issue updated)
    |
    v
[apps/api/webhooks_router.py:handle_jira_webhook()]
    |-- Verify HMAC signature
    |-- Parse event type
    |
    v
[core/connectors.py:JiraConnector.process_event()]
    |-- Map Jira status to FixOps status
    |-- Update remediation task
    |
    v
[core/workflow_db.py:update_task()]
    |
    v
Task status synced

---

FixOps creates Jira issue
    |
    v
[core/connectors.py:JiraConnector.create_issue()]
    |-- Map finding to Jira fields
    |-- Set priority, labels
    |
    v
POST to Jira API
    |
    v
Store Jira issue key in task
```

### Tests

| Test File | LOC | Coverage |
|-----------|-----|----------|
| `tests/test_comprehensive_cicd_alm_integrations.py` | 761 | CI/CD integrations |
| `tests/test_comprehensive_tool_integrations.py` | 813 | Tool integrations |

---

## Feature 8: Security Scanning

**Purpose:** IaC scanning (Terraform, CloudFormation), secrets detection, SBOM generation.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| IaC Scanner | `core/iac_scanner.py` | 672 | `IaCScanner`, `scan_terraform()`, `scan_cloudformation()` |
| IaC DB | `core/iac_db.py` | 176 | `IaCDB` |
| IaC Models | `core/iac_models.py` | 93 | `IaCFinding`, `IaCScanResult` |
| Secrets Scanner | `core/secrets_scanner.py` | 736 | `SecretsScanner`, `scan_for_secrets()` |
| Secrets DB | `core/secrets_db.py` | 169 | `SecretsDB` |
| Secrets Models | `core/secrets_models.py` | 90 | `SecretFinding` |
| Safe Path Ops | `core/safe_path_ops.py` | 528 | Path traversal protection |
| IaC Router | `apps/api/iac_router.py` | 230 | 6 IaC endpoints |
| Secrets Router | `apps/api/secrets_router.py` | 226 | 6 secrets endpoints |
| Terraform Analysis | `risk/iac/terraform.py` | 262 | `TerraformAnalyzer` |
| SBOM Generator | `risk/sbom/generator.py` | 424 | `SBOMGenerator` |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| POST | `/api/v1/iac/scan` | `scan_iac` | `apps/api/iac_router.py:45-100` |
| GET | `/api/v1/iac/results/{id}` | `get_results` | `apps/api/iac_router.py:102-140` |
| GET | `/api/v1/iac/findings` | `list_findings` | `apps/api/iac_router.py:142-180` |
| POST | `/api/v1/secrets/scan` | `scan_secrets` | `apps/api/secrets_router.py:45-100` |
| GET | `/api/v1/secrets/findings` | `list_findings` | `apps/api/secrets_router.py:102-150` |
| POST | `/api/v1/secrets/allowlist` | `add_allowlist` | `apps/api/secrets_router.py:152-200` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `stage-run --stage deploy --input terraform/` | `_handle_stage_run()` | `core/cli.py:622-678` |

### Code Flow

```
IaC Files (Terraform/CloudFormation)
    |
    v
[apps/api/iac_router.py:scan_iac()]
    |
    v
[core/iac_scanner.py:IaCScanner.scan()]
    |
    +---> [core/iac_scanner.py:scan_terraform()]
    |         |-- Parse HCL
    |         |-- Check security rules
    |         |-- Detect misconfigurations
    |
    +---> [core/iac_scanner.py:scan_cloudformation()]
    |         |-- Parse YAML/JSON
    |         |-- Check security rules
    |
    v
[core/iac_db.py:store_findings()]
    |
    v
IaC findings with remediation suggestions

---

Source Code
    |
    v
[apps/api/secrets_router.py:scan_secrets()]
    |
    v
[core/secrets_scanner.py:SecretsScanner.scan()]
    |-- Regex patterns for API keys
    |-- Entropy analysis
    |-- Known secret formats
    |
    v
[core/secrets_db.py:store_findings()]
    |
    v
Secret findings with locations
```

### Tests

| Test File | LOC | Coverage |
|-----------|-----|----------|
| `tests/test_iac_scanner.py` | 1,231 | IaC scanning |
| `tests/test_iac_api.py` | 125 | IaC API |
| `tests/test_secrets_scanner.py` | 1,416 | Secrets detection |
| `tests/test_secrets_api.py` | 136 | Secrets API |
| `tests/test_safe_path_ops.py` | 707 | Path safety |

---

## Feature 9: Deduplication & Correlation

**Purpose:** Deduplicate findings across tools, correlate related issues, group for bulk remediation.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Deduplication Router | `apps/api/deduplication_router.py` | 417 | 17 dedup endpoints |
| Correlation Engine | `fixops-enterprise/src/services/correlation_engine.py` | 495 | `CorrelationEngine` |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| POST | `/api/v1/deduplication/analyze` | `analyze_duplicates` | `apps/api/deduplication_router.py:45-100` |
| GET | `/api/v1/deduplication/groups` | `list_groups` | `apps/api/deduplication_router.py:102-140` |
| POST | `/api/v1/deduplication/merge` | `merge_findings` | `apps/api/deduplication_router.py:142-200` |
| POST | `/api/v1/deduplication/split` | `split_group` | `apps/api/deduplication_router.py:202-250` |
| GET | `/api/v1/deduplication/strategies` | `list_strategies` | `apps/api/deduplication_router.py:252-290` |
| POST | `/api/v1/deduplication/feedback` | `submit_feedback` | `apps/api/deduplication_router.py:350-417` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `correlation analyze --findings FILE` | `_handle_correlation()` | `core/cli.py:3406-3482` |
| `correlation stats` | `_handle_correlation()` | `core/cli.py:3406-3482` |
| `groups list` | `_handle_groups()` | `core/cli.py:3485-3578` |
| `groups merge --ids 1,2,3` | `_handle_groups()` | `core/cli.py:3485-3578` |

### Code Flow

```
Multiple scan results
    |
    v
[apps/api/deduplication_router.py:analyze_duplicates()]
    |
    v
[fixops-enterprise/src/services/correlation_engine.py:correlate()]
    |-- Fuzzy matching on description
    |-- CVE ID matching
    |-- File path matching
    |-- Component matching
    |
    v
Grouped findings
    |
    v
[apps/api/deduplication_router.py:merge_findings()]
    |-- Create canonical finding
    |-- Link duplicates
    |
    v
Single remediation task for group
```

---

## Feature 10: Analytics & Dashboards

**Purpose:** MTTR, ROI, trends, coverage metrics, executive dashboards.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Analytics Core | `core/analytics.py` | 775 | `AnalyticsEngine`, `calculate_mttr()`, `calculate_roi()` |
| Analytics DB | `core/analytics_db.py` | 413 | `AnalyticsDB` |
| Analytics Models | `core/analytics_models.py` | 133 | `MetricSnapshot`, `TrendData` |
| Analytics Router | `apps/api/analytics_router.py` | 436 | 16 analytics endpoints |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| GET | `/api/v1/analytics/dashboard` | `get_dashboard` | `apps/api/analytics_router.py:45-100` |
| GET | `/api/v1/analytics/mttr` | `get_mttr` | `apps/api/analytics_router.py:102-150` |
| GET | `/api/v1/analytics/roi` | `get_roi` | `apps/api/analytics_router.py:152-200` |
| GET | `/api/v1/analytics/trends` | `get_trends` | `apps/api/analytics_router.py:202-260` |
| GET | `/api/v1/analytics/coverage` | `get_coverage` | `apps/api/analytics_router.py:262-310` |
| POST | `/api/v1/analytics/export` | `export_analytics` | `apps/api/analytics_router.py:380-436` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `analytics dashboard` | `_handle_analytics()` | `core/cli.py:2583-2696` |
| `analytics mttr --days 90` | `_handle_analytics()` | `core/cli.py:2583-2696` |
| `analytics roi` | `_handle_analytics()` | `core/cli.py:2583-2696` |
| `analytics coverage` | `_handle_analytics()` | `core/cli.py:2583-2696` |
| `analytics export --format csv` | `_handle_analytics()` | `core/cli.py:2583-2696` |

### UI Pages

| Page | File Path | LOC | Purpose |
|------|-----------|-----|---------|
| Enhanced Dashboard | `frontend/src/pages/EnhancedDashboard.jsx` | 943 | Main dashboard |
| CISO Dashboard | `frontend/src/pages/CISODashboard.jsx` | 428 | Executive view |
| Executive Briefing | `frontend/src/pages/ExecutiveBriefing.jsx` | 570 | Board reports |
| Developer Dashboard | `frontend/src/pages/DeveloperDashboard.jsx` | 643 | Dev metrics |
| Architect Dashboard | `frontend/src/pages/ArchitectDashboard.jsx` | 566 | Architecture view |

---

## Feature 11: Team & User Management

**Purpose:** Teams, users, roles, RBAC, SSO/OIDC authentication.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| User DB | `core/user_db.py` | 337 | `UserDB`, `create_user()`, `assign_role()` |
| Auth DB | `core/auth_db.py` | 163 | `AuthDB`, `validate_token()` |
| User Models | `core/user_models.py` | 101 | `User`, `Team`, `Role` |
| Auth Models | `core/auth_models.py` | 76 | `Token`, `Session` |
| Teams Router | `apps/api/teams_router.py` | 150 | 8 team endpoints |
| Users Router | `apps/api/users_router.py` | 184 | 6 user endpoints |
| Auth Router | `apps/api/auth_router.py` | 124 | 4 auth endpoints |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| GET | `/api/v1/teams` | `list_teams` | `apps/api/teams_router.py:30-55` |
| POST | `/api/v1/teams` | `create_team` | `apps/api/teams_router.py:57-90` |
| GET | `/api/v1/teams/{id}` | `get_team` | `apps/api/teams_router.py:92-115` |
| DELETE | `/api/v1/teams/{id}` | `delete_team` | `apps/api/teams_router.py:117-150` |
| GET | `/api/v1/users` | `list_users` | `apps/api/users_router.py:30-55` |
| POST | `/api/v1/users` | `create_user` | `apps/api/users_router.py:57-100` |
| POST | `/api/v1/auth/login` | `login` | `apps/api/auth_router.py:30-70` |
| POST | `/api/v1/auth/logout` | `logout` | `apps/api/auth_router.py:72-95` |

### CLI Commands

| Command | Handler Function | File:Line |
|---------|-----------------|-----------|
| `teams list` | `_handle_teams()` | `core/cli.py:1141-1213` |
| `teams create --name NAME` | `_handle_teams()` | `core/cli.py:1141-1213` |
| `users list` | `_handle_users()` | `core/cli.py:1252-1343` |
| `users create --email EMAIL` | `_handle_users()` | `core/cli.py:1252-1343` |

---

## Feature 12: Marketplace

**Purpose:** Policy marketplace, integration templates, community sharing.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Marketplace Router | `apps/api/marketplace_router.py` | 702 | 12 marketplace endpoints |
| Marketplace Service | `fixops-enterprise/src/services/marketplace_service.py` | 781 | `MarketplaceService` |
| Marketplace API | `fixops-enterprise/src/api/v1/marketplace.py` | 328 | Enterprise marketplace |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| GET | `/api/v1/marketplace/items` | `list_items` | `apps/api/marketplace_router.py:45-100` |
| GET | `/api/v1/marketplace/items/{id}` | `get_item` | `apps/api/marketplace_router.py:102-140` |
| POST | `/api/v1/marketplace/items/{id}/install` | `install_item` | `apps/api/marketplace_router.py:142-220` |
| POST | `/api/v1/marketplace/items/{id}/rate` | `rate_item` | `apps/api/marketplace_router.py:222-270` |
| GET | `/api/v1/marketplace/categories` | `list_categories` | `apps/api/marketplace_router.py:272-310` |

---

## Feature 13: Bulk Operations

**Purpose:** Batch processing, bulk updates, async job management.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Bulk Router | `apps/api/bulk_router.py` | 684 | 12 bulk endpoints |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| POST | `/api/v1/bulk/validate` | `validate_batch` | `apps/api/bulk_router.py:45-120` |
| POST | `/api/v1/bulk/execute` | `execute_batch` | `apps/api/bulk_router.py:122-250` |
| GET | `/api/v1/bulk/jobs` | `list_jobs` | `apps/api/bulk_router.py:252-300` |
| GET | `/api/v1/bulk/jobs/{id}` | `get_job` | `apps/api/bulk_router.py:302-350` |
| DELETE | `/api/v1/bulk/jobs/{id}` | `cancel_job` | `apps/api/bulk_router.py:352-400` |

---

## Feature 14: Collaboration

**Purpose:** Comments, mentions, notifications, sharing, team communication.

### Code Paths

| Component | File Path | LOC | Key Functions/Classes |
|-----------|-----------|-----|----------------------|
| Collaboration Router | `apps/api/collaboration_router.py` | 583 | 21 collaboration endpoints |

### API Endpoints

| Method | Endpoint | Handler | File:Line |
|--------|----------|---------|-----------|
| POST | `/api/v1/collaboration/comments` | `add_comment` | `apps/api/collaboration_router.py:45-100` |
| GET | `/api/v1/collaboration/comments/{finding_id}` | `get_comments` | `apps/api/collaboration_router.py:102-140` |
| POST | `/api/v1/collaboration/share` | `share_finding` | `apps/api/collaboration_router.py:142-200` |
| GET | `/api/v1/collaboration/mentions` | `get_mentions` | `apps/api/collaboration_router.py:202-250` |
| POST | `/api/v1/collaboration/notify` | `send_notification` | `apps/api/collaboration_router.py:252-310` |

---

## Feature 15: Frontend UI

**Purpose:** React-based dashboards, triage workflows, visualizations.

### UI Pages

| Page | File Path | LOC | Purpose | API Dependencies |
|------|-----------|-----|---------|------------------|
| Triage Inbox | `frontend/src/pages/TriageInbox.jsx` | 1,383 | Vulnerability triage | `/api/v1/findings`, `/api/v1/remediation` |
| Risk Graph | `frontend/src/pages/RiskGraph.jsx` | 992 | Risk visualization | `/api/v1/graph`, `/api/v1/risk` |
| Enhanced Dashboard | `frontend/src/pages/EnhancedDashboard.jsx` | 943 | Main dashboard | `/api/v1/analytics` |
| Component Drawer | `frontend/src/components/ComponentDrawer.jsx` | 672 | Component details | `/api/v1/inventory` |
| Compliance Rollup | `frontend/src/pages/ComplianceRollup.jsx` | 619 | Compliance status | `/api/v1/compliance` |
| Command Center | `frontend/src/pages/CommandCenter.jsx` | 613 | Operations | `/api/v1/workflows` |
| Triage Queue | `frontend/src/pages/TriageQueue.jsx` | 604 | Triage workflow | `/api/v1/remediation` |
| Executive Briefing | `frontend/src/pages/ExecutiveBriefing.jsx` | 570 | Executive view | `/api/v1/reports` |
| Evidence Timeline | `frontend/src/pages/EvidenceTimeline.jsx` | 566 | Audit timeline | `/api/v1/evidence` |
| Architect Dashboard | `frontend/src/pages/ArchitectDashboard.jsx` | 566 | Architecture | `/api/v1/inventory` |
| Architecture Center | `frontend/src/pages/ArchitectureCenter.jsx` | 561 | Architecture center | `/api/v1/inventory` |
| Developer Ops | `frontend/src/pages/DeveloperOps.jsx` | 456 | Developer ops | `/api/v1/analytics` |
| CISO Dashboard | `frontend/src/pages/CISODashboard.jsx` | 428 | CISO view | `/api/v1/analytics` |
| Risk Explorer | `frontend/src/pages/RiskExplorer.jsx` | 371 | Risk explorer | `/api/v1/risk` |
| Architecture Page | `frontend/src/pages/ArchitecturePage.jsx` | 168 | Architecture | `/api/v1/inventory` |
| Install Page | `frontend/src/pages/InstallPage.jsx` | 164 | Installation | `/api/v1/health` |

### Shared Components

| Component | File Path | LOC | Purpose |
|-----------|-----------|-----|---------|
| Attack Path Explorer | `frontend/src/components/AttackPathExplorer.jsx` | 555 | Attack visualization |
| Risk Graph Explorer | `frontend/src/components/RiskGraphExplorer.jsx` | 499 | Graph navigation |
| Security Layout | `frontend/src/components/SecurityLayout.jsx` | 357 | Page layout |
| Auth Context | `frontend/src/contexts/AuthContext.jsx` | 258 | Authentication |
| Layout | `frontend/src/components/Layout.jsx` | 250 | Main layout |
| Mode Toggle | `frontend/src/components/ModeToggle.jsx` | 147 | Theme toggle |

### Utilities

| Utility | File Path | LOC | Purpose |
|---------|-----------|-----|---------|
| Graph Adapter | `frontend/src/utils/graphAdapter.js` | 298 | Graph data |
| Triage Adapter | `frontend/src/utils/triageAdapter.js` | 259 | Triage data |
| API Client | `frontend/src/utils/api.js` | 185 | API calls |
| Theme | `frontend/src/theme/aldeci.js` | 106 | Theming |

---

## Feature 16: Playbook DSL (YAML-Based Automation)

**Purpose:** Declarative YAML-based Domain-Specific Language for automating vulnerability management, compliance validation, and security remediation workflows without writing code.

**Key Capabilities:**
- 25+ pre-approved action types (Jira, Confluence, Slack, OPA, compliance, etc.)
- Template variable resolution with `{{ }}` syntax
- Conditional execution with `when`, `unless`, and `depends_on`
- Error handling with retry and continue-on-failure
- Sandboxed execution (only pre-approved adapters, no arbitrary code)
- Integration with enterprise connectors

### Core Files

| File | LOC | Purpose |
|------|-----|---------|
| `core/playbook_runner.py` | 1,100 | Production playbook execution engine |
| `config/playbook-schema.yaml` | 369 | JSON Schema for playbook validation |
| `config/playbooks/soc2-access-control-validation.yaml` | 280 | Example SOC2 compliance playbook |

### CLI Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `playbook run` | Execute a playbook | `python -m core.cli playbook run --playbook config/playbooks/soc2-access-control-validation.yaml` |
| `playbook validate` | Validate playbook syntax | `python -m core.cli playbook validate --playbook config/playbooks/my-playbook.yaml` |
| `playbook list` | List available playbooks | `python -m core.cli playbook list --dir config/playbooks` |

### Playbook Actions

| Action | Category | Description | Connector |
|--------|----------|-------------|-----------|
| `opa.evaluate` | Policy | Evaluate OPA policy | OPA Client |
| `opa.assert` | Policy | Assert policy passes | OPA Client |
| `evidence.collect` | Evidence | Collect compliance evidence | EvidenceHub |
| `evidence.sign` | Evidence | Sign evidence bundle | EvidenceHub |
| `evidence.assert` | Evidence | Assert evidence requirements | EvidenceHub |
| `compliance.check_control` | Compliance | Check compliance control | ComplianceEngine |
| `compliance.map_finding` | Compliance | Map finding to controls | ComplianceEngine |
| `compliance.generate_report` | Compliance | Generate compliance report | ComplianceEngine |
| `pentest.request` | Security | Request penetration test | MicroPentestEngine |
| `pentest.validate_exploitability` | Security | Validate exploitability | MicroPentestEngine |
| `scanner.run` | Security | Run security scanner | Scanner |
| `jira.create_issue` | Issue Tracking | Create Jira issue | JiraConnector |
| `jira.update_issue` | Issue Tracking | Update Jira issue | JiraConnector |
| `jira.add_comment` | Issue Tracking | Add Jira comment | JiraConnector |
| `confluence.create_page` | Documentation | Create Confluence page | ConfluenceConnector |
| `confluence.update_page` | Documentation | Update Confluence page | ConfluenceConnector |
| `notify.slack` | Notifications | Send Slack notification | SlackConnector |
| `notify.email` | Notifications | Send email notification | EmailConnector |
| `notify.pagerduty` | Notifications | Create PagerDuty incident | PagerDutyConnector |
| `workflow.approve` | Workflow | Approve workflow item | WorkflowEngine |
| `workflow.reject` | Workflow | Reject workflow item | WorkflowEngine |
| `workflow.escalate` | Workflow | Escalate workflow item | WorkflowEngine |
| `data.filter` | Data | Filter dataset | Internal |
| `data.aggregate` | Data | Aggregate data | Internal |
| `data.transform` | Data | Transform data | Internal |

### Code Flow

```
Playbook YAML → PlaybookRunner.load_playbook()
    → _parse_playbook() → Playbook object
    → validate_playbook() → ValidationError[]
    → execute() → PlaybookExecutionContext
        → For each step:
            → _check_step_condition() (when/unless/depends_on)
            → _resolve_params() (template variables)
            → _action_handlers[action]() → Connector call
            → StepResult (success/failed/skipped)
        → Return execution context with all results
```

### Example Playbook Structure

```yaml
apiVersion: fixops.io/v1
kind: CompliancePack
metadata:
  name: soc2-access-control-validation
  version: "1.0.0"
spec:
  inputs:
    findings:
      type: sarif
      required: true
    severity_threshold:
      type: string
      default: "high"
  steps:
    - name: evaluate-policy
      action: opa.evaluate
      params:
        policy: "soc2/access-control.rego"
        input: "{{ inputs.findings }}"
    - name: create-ticket
      action: jira.create_issue
      condition:
        when: "steps.evaluate-policy.status == 'failed'"
      params:
        project: "SEC"
        summary: "SOC2 compliance gap detected"
  outputs:
    compliance_status:
      from: "steps.evaluate-policy.output"
  triggers:
    - event: schedule.cron
      filter:
        expression: "0 0 * * 1"
```

### Related Documentation

- [Playbook Language Reference](PLAYBOOK_LANGUAGE_REFERENCE.md) - Complete syntax documentation
- [Docker Showcase Guide](DOCKER_SHOWCASE_GUIDE.md#29-playbook---execute-fixops-playbooks-yaml-dsl) - Docker examples

---

## Summary Table

| Feature | Python LOC | JS LOC | APIs | CLIs | UI Pages | Tests LOC |
|---------|------------|--------|------|------|----------|-----------|
| Intake & Normalization | 5,700 | 0 | 21 | 4 | 1 | 1,500 |
| Risk Scoring | 6,200 | 0 | 20 | 4 | 2 | 4,000 |
| Decision Engine | 3,500 | 0 | 12 | 5 | 1 | 1,600 |
| Penetration Testing | 6,100 | 0 | 36 | 8 | 0 | 1,900 |
| Remediation Workflow | 1,400 | 0 | 20 | 5 | 2 | 900 |
| Compliance & Evidence | 3,200 | 0 | 24 | 7 | 2 | 1,000 |
| Integrations | 2,500 | 0 | 25 | 4 | 0 | 1,600 |
| Security Scanning | 2,700 | 0 | 12 | 1 | 0 | 3,600 |
| Deduplication | 900 | 0 | 17 | 4 | 0 | 500 |
| Analytics | 1,800 | 0 | 16 | 5 | 5 | 600 |
| Team Management | 1,100 | 0 | 18 | 4 | 0 | 400 |
| Marketplace | 1,800 | 0 | 12 | 0 | 0 | 300 |
| Bulk Operations | 700 | 0 | 12 | 0 | 0 | 200 |
| Collaboration | 600 | 0 | 21 | 0 | 0 | 200 |
| Playbook DSL | 1,100 | 0 | 0 | 3 | 0 | 0 |
| Frontend UI | 0 | 13,600 | - | - | 16 | 0 |
| **Subtotal (Features)** | **39,300** | **13,600** | **303** | **54** | **16** | **18,300** |
| Core Infrastructure | 40,000 | 0 | - | - | - | 20,000 |
| Enterprise Features | 15,600 | 0 | - | - | - | 5,000 |
| Other JS/Config | 0 | 44,000 | - | - | - | 0 |
| Other Tests | 0 | 0 | - | - | - | 23,500 |
| **TOTAL** | **~168K** | **~58K** | **303** | **111** | **16** | **~67K** |

---

*Document generated from code analysis. Line numbers are approximate and may shift with code changes.*
