# FixOps: DevSecOps Pipeline & Decision Engine

FixOps is a DevSecOps pipeline orchestration and decision engine that ingests security artifacts (SBOM, SARIF, CVE feeds, design context), normalizes and correlates findings across sources, evaluates risk using configurable modules, and produces cryptographically-signed evidence bundles with automated remediation workflows.

## What's in This Repository

This repository contains:
- **CLI tools** for local pipeline execution and decision-making
- **FastAPI ingestion service** for artifact upload and pipeline orchestration
- **Core processing modules** for risk assessment, compliance mapping, and evidence generation

**What's NOT included:**
- No Docker Compose configuration
- No Terraform infrastructure code
- No bundled web UI (frontend is in a separate repository)

## Prerequisites

- Python 3.10+ (tested with Python 3.12)
- pip and virtualenv
- Optional: uvicorn (for API server), jq (for JSON formatting)

## Installation

1. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start - CLI

### Demo Mode (Bundled Fixtures)

Run the pipeline with bundled demo fixtures:
```bash
python -m core.cli demo --mode demo --output out/pipeline-demo.json --pretty
```

This uses fixtures from `simulations/demo_pack/` and produces a complete pipeline response.

### Local Artifacts

Run the pipeline with your own artifacts:
```bash
python -m core.cli run \
  --sbom artefacts/sbom.cdx.json \
  --sarif artefacts/snyk.sarif \
  --cve artefacts/cve.json \
  --design artefacts/design.csv \
  --output out/pipeline.json \
  --pretty
```

**Required inputs:**
- `--sbom`: SBOM file (CycloneDX or SPDX JSON)
- `--sarif`: SARIF 2.1.0 scan results
- `--cve`: CVE/KEV feed JSON

**Optional inputs:**
- `--design`: Design CSV with component metadata
- `--vex`: VEX document for vulnerability status
- `--cnapp`: CNAPP findings for cloud security
- `--context`: Business context (FixOps.yaml, OTM.json, or SSVC YAML)

### Decision-Based Exit Codes

Use the pipeline decision as a CI/CD gate:
```bash
python -m core.cli make-decision \
  --sbom artefacts/sbom.cdx.json \
  --sarif artefacts/snyk.sarif \
  --cve artefacts/cve.json
```

**Exit codes:**
- `0`: allow/pass (safe to deploy)
- `1`: block/fail (deployment blocked)
- `2`: defer/warn (manual review required)

### Health Check

Verify local environment readiness:
```bash
python -m core.cli health
```

### CLI Reference

View all available commands:
```bash
python -m core.cli --help
```

Available subcommands:
- `demo` - Run with bundled fixtures
- `run` - Execute pipeline with local artifacts
- `make-decision` - Run pipeline and use decision as exit code
- `health` - Check integration readiness
- `get-evidence` - Copy evidence bundle from pipeline result
- `show-overlay` - Print sanitized overlay configuration
- `train-forecast` - Calibrate probabilistic forecast engine
- `stage-run` - Normalize a single stage input

For detailed help on any subcommand:
```bash
python -m core.cli <subcommand> --help
```

## Quick Start - API

### Starting the API Server

Set required environment variables and start the server:
```bash
export FIXOPS_API_TOKEN="demo-token"
export FIXOPS_MODE="demo"
uvicorn apps.api.app:create_app --factory --reload
```

The API will be available at `http://127.0.0.1:8000`.

**Note:** In demo mode, a JWT secret is automatically generated. For production, set `FIXOPS_JWT_SECRET` instead of `FIXOPS_MODE`.

### Ingesting Artifacts

Upload artifacts to the API:

```bash
# Upload design context
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@artefacts/design.csv;type=text/csv" \
  http://127.0.0.1:8000/inputs/design

# Upload SBOM
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@artefacts/sbom.cdx.json;type=application/json" \
  http://127.0.0.1:8000/inputs/sbom

# Upload CVE feed
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@artefacts/cve.json;type=application/json" \
  http://127.0.0.1:8000/inputs/cve

# Upload SARIF scan results
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@artefacts/snyk.sarif;type=application/json" \
  http://127.0.0.1:8000/inputs/sarif
```

### Running the Pipeline

Execute the pipeline with uploaded artifacts:
```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://127.0.0.1:8000/pipeline/run | jq
```

### Analytics Dashboard

View aggregated analytics:
```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://127.0.0.1:8000/analytics/dashboard | jq
```

### API Endpoints

**Ingestion endpoints:**
- `POST /inputs/design` - Upload design CSV
- `POST /inputs/sbom` - Upload SBOM (CycloneDX/SPDX)
- `POST /inputs/sarif` - Upload SARIF 2.1.0 results
- `POST /inputs/cve` - Upload CVE/KEV feed
- `POST /inputs/vex` - Upload VEX document
- `POST /inputs/cnapp` - Upload CNAPP findings
- `POST /inputs/context` - Upload business context

**Pipeline endpoints:**
- `POST /pipeline/run` - Execute pipeline with uploaded artifacts
- `GET /pipeline/run` - Get last pipeline execution result

**Analytics endpoints:**
- `GET /analytics/dashboard` - Aggregated analytics dashboard
- `GET /analytics/runs/{run_id}` - Specific run details

**Health endpoints:**
- `GET /health` - API health check
- `GET /ready` - Readiness probe

## Supported Input Formats

### SBOM
- **Formats:** CycloneDX JSON, SPDX JSON, GitHub Dependency Snapshot, Syft JSON
- **Compression:** Raw JSON, gzip (.json.gz), or zip archive
- **Content-Type:** `application/json`, `application/gzip`, `application/zip`

### SARIF
- **Format:** SARIF 2.1.0
- **Compression:** Raw JSON or zip archive containing scan.sarif
- **Severity mapping:** 
  - `none/note/info` → low
  - `warning` → medium
  - `error` → high

### CVE/KEV Feed
- **Format:** CISA KEV format or custom CVE feed JSON
- **Compression:** Raw JSON or zip archive containing kev.json
- **Fields:** cveID, title, severity, knownExploited (optional)

### Design Context
- **Format:** CSV with columns: component, owner, criticality, notes
- **Purpose:** Maps business context to technical components

### VEX (Vulnerability Exploitability eXchange)
- **Format:** CycloneDX VEX JSON
- **Purpose:** Noise reduction via vulnerability status declarations

### CNAPP (Cloud-Native Application Protection)
- **Format:** Custom JSON with cloud security findings
- **Purpose:** Threat path enrichment for cloud workloads

### Business Context
- **Formats:** FixOps.yaml, OTM JSON, SSVC YAML
- **Purpose:** Business criticality, data classification, exposure metadata

## Configuration

### Environment Variables

**Required for API:**
- `FIXOPS_API_TOKEN` - API authentication token (used with X-API-Key header)
- `FIXOPS_MODE` - Set to "demo" for demo mode, or set `FIXOPS_JWT_SECRET` for production

**Optional:**
- `FIXOPS_JWT_SECRET` - JWT signing secret (required in non-demo mode)
- `FIXOPS_OVERLAY_PATH` - Path to custom overlay configuration file
- `FIXOPS_ALLOWED_ORIGINS` - Comma-separated CORS origins
- `FIXOPS_DISABLE_TELEMETRY` - Set to "1" to disable OpenTelemetry
- `OTEL_EXPORTER_OTLP_ENDPOINT` - OpenTelemetry collector endpoint (default: http://collector:4318)

### Overlay Configuration

The overlay configuration file controls module enablement, thresholds, and behavior. Default location: `config/fixops.overlay.yml`

View the active overlay configuration:
```bash
python -m core.cli show-overlay
```

Override the overlay file:
```bash
python -m core.cli run --overlay /path/to/custom-overlay.yml ...
```

Or via environment variable:
```bash
export FIXOPS_OVERLAY_PATH=/path/to/custom-overlay.yml
```

### Authentication

**Token-based (default):**
```bash
export FIXOPS_API_TOKEN="your-secret-token"
# Use X-API-Key header in requests
curl -H "X-API-Key: $FIXOPS_API_TOKEN" ...
```

**JWT-based:**
Set `auth.strategy: "jwt"` in overlay configuration and provide `FIXOPS_JWT_SECRET`:
```bash
export FIXOPS_JWT_SECRET="your-jwt-secret"
# Use Authorization: Bearer <token> header
```

## Testing

### Comprehensive E2E Test Suite ✅

FixOps includes a comprehensive end-to-end test suite with **67 tests** that validate all functionality using real subprocess calls and HTTP requests (no mocks).

**Run the full E2E test suite:**
```bash
python -m pytest tests/e2e/ -v
```

**Expected results:** 67 passed in ~4 minutes

**What's tested:**
- ✅ **API Golden Path** (15 tests) - Upload endpoints, pipeline execution, authentication, large files, error handling
- ✅ **CLI Golden Path** (15 tests) - Demo mode, enterprise mode, module flags, offline mode, evidence generation
- ✅ **Branding & Namespace** (11 tests) - Product rebranding, namespace aliasing (fixops → aldeci), configuration
- ✅ **Feature Flag Wiring** (10 tests) - Module flags, risk model selection, encryption, retention, connectors
- ✅ **Evidence Generation** (13 tests) - Bundle creation, structure validation, encryption, branding, extraction
- ✅ **Provider Fallback** (7 tests) - LaunchDarkly fallback chain, local overlay, registry defaults

**Test Status:** All 67 tests passing (100% pass rate) ✅

**Documentation:**
- `docs/E2E_TESTING_CHEAT_SHEET.md` - Complete test coverage and risk assessment
- `docs/RUTHLESS_E2E_FINDINGS.md` - Detailed findings from ruthless testing
- `docs/RUTHLESS_E2E_TESTING_PLAN.md` - Testing strategy and future phases

### Run Legacy End-to-End Tests

```bash
python -m pytest tests/test_end_to_end.py -v
```

These legacy tests verify:
- API ingestion endpoints (design, sbom, sarif, cve)
- Pipeline orchestration
- Analytics endpoints
- Authentication and authorization
- Compressed file uploads (gzip, zip)
- Large file streaming

### Run All Tests

```bash
python -m pytest -v
```

### Integration Tests

Integration tests require external services and are skipped by default. To run them:
```bash
export RUN_FIXOPS_INTEGRATION_TESTS=1
python -m pytest backend_test.py -v
```

## Architecture Overview

### Pipeline Flow

```
Inputs → Normalization → Crosswalk → Modules → Evidence
  ↓           ↓              ↓          ↓          ↓
Design    Parsers      Correlation  Analysis   Bundles
SBOM      Validators   Mapping      Decisions  Signatures
SARIF                  Enrichment   Compliance Automation
CVE/KEV
VEX
CNAPP
Context
```

### Core Components

**Pipeline Orchestrator** (`apps/api/pipeline.py`)
- Coordinates end-to-end analysis workflow
- Builds crosswalk mappings between design, SBOM, findings, and CVEs
- Executes enabled modules based on overlay configuration
- Aggregates results into unified response

**Input Normalizers** (`apps/api/normalizers.py`)
- Parse and validate multiple artifact formats
- Handle compression (gzip, zip)
- Normalize severity levels across sources
- Extract metadata and relationships

**Decision Engine** (`fixops-blended-enterprise/src/services/decision_engine.py`)
- Weighted severity scoring
- Verdict thresholds: allow (<0.6), review (0.6-0.85), block (≥0.85)
- Compliance gap analysis
- Evidence bundle generation with RSA-SHA256 signatures

**Enhanced Decision Engine** (`fixops-blended-enterprise/src/services/enhanced_decision_engine.py`)
- Multi-LLM consensus (GPT-5, Claude-3, Gemini-2, specialized models)
- MITRE ATT&CK mapping
- Narrative explanations
- Confidence scoring and disagreement detection

**Evidence Lake** (`core/evidence.py`, `fixops-blended-enterprise/src/services/evidence.py`)
- Immutable storage with RSA-SHA256 signatures
- Configurable retention (90 days demo, 2555 days enterprise)
- Optional Fernet encryption
- Transparency index for audit trails

### Processing Modules

Modules can be enabled/disabled via overlay configuration:

- **Guardrails** - Maturity-based thresholds (foundational/scaling/advanced)
- **Compliance** - Framework mapping (SOC2, ISO27001, PCI-DSS, GDPR)
- **Context Engine** - Business context enrichment
- **Exploit Signals** - KEV/EPSS feed integration
- **Probabilistic Forecasting** - Bayesian/Markov severity projections
- **SSDLC Assessment** - Secure SDLC stage evaluation
- **IaC Posture** - Infrastructure-as-Code security analysis
- **AI Agents** - AI agent detection in components
- **Policy Automation** - Jira/Confluence/Slack integration
- **Analytics** - ROI metrics and performance tracking
- **Tenancy** - Multi-tenant lifecycle management

## Troubleshooting

### 401 Unauthorized

**Problem:** API returns 401 status code

**Solution:** Ensure `FIXOPS_API_TOKEN` is set and `X-API-Key` header is included:
```bash
export FIXOPS_API_TOKEN="demo-token"
curl -H "X-API-Key: $FIXOPS_API_TOKEN" ...
```

### 413 Payload Too Large

**Problem:** Upload fails with 413 status code

**Solution:** File exceeds configured upload limit. Reduce file size or adjust overlay configuration:
```yaml
limits:
  max_upload_bytes:
    default: 16777216  # 16 MB
    sbom: 16777216
    sarif: 16777216
```

### Normalizer Errors

**Problem:** Failed to parse SBOM/SARIF/CVE

**Solution:** 
- Verify file is valid JSON
- Check format matches expected schema (CycloneDX, SPDX, SARIF 2.1.0)
- Try compressing with gzip or zip if file is large
- Review error message for specific validation failures

### JWT Secret Error

**Problem:** `ValueError: FIXOPS_JWT_SECRET environment variable must be set`

**Solution:** Either set `FIXOPS_MODE=demo` for demo mode, or generate and set a JWT secret:
```bash
# Demo mode
export FIXOPS_MODE="demo"

# Production mode
export FIXOPS_JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')
```

### Telemetry Errors

**Problem:** Telemetry configuration warnings or errors

**Solution:** Disable telemetry if no collector is available:
```bash
export FIXOPS_DISABLE_TELEMETRY=1
```

Or configure a custom endpoint:
```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://your-collector:4318"
```

## Sample Data

The repository includes sample data for testing:

**artefacts/** - Minimal test fixtures:
- `design.csv` - Component design context
- `sbom.cdx.json` - CycloneDX SBOM
- `cve.json` - CVE feed
- `snyk.sarif` - SARIF scan results
- `vex.cdx.json` - VEX document
- `cnapp.json` - CNAPP findings

**simulations/demo_pack/** - Demo scenario fixtures:
- `sbom.json` - Demo SBOM
- `scanner.sarif` - Demo SARIF
- `requirements-input.csv` - Demo design CSV
- Additional demo artifacts

**samples/** - Vendor-specific samples:
- AWS Security Hub, Snyk, Veracode, SonarQube, Wiz, Prisma, Rapid7, Tenable, Invicti

## Development

### Project Structure

```
fixops/
├── apps/api/          # FastAPI application
├── core/              # Core business logic
├── backend/           # Legacy backend (being phased out)
├── fixops-blended-enterprise/  # Enterprise features
├── services/          # Shared services
├── domain/            # Domain models
├── data/              # Data storage
├── config/            # Configuration files
├── tests/             # Test suite
├── simulations/       # Demo scenarios
├── artefacts/         # Test fixtures
└── samples/           # Vendor samples
```

### Running in Development Mode

```bash
# CLI with auto-reload (not supported, use pytest for iteration)
python -m core.cli demo --mode demo

# API with auto-reload
export FIXOPS_API_TOKEN="demo-token"
export FIXOPS_MODE="demo"
uvicorn apps.api.app:create_app --factory --reload
```

### Code Quality

Run linting and type checking (if configured):
```bash
# Check for syntax errors
python -m compileall apps core tests

# Run tests with coverage
python -m pytest --cov=apps --cov=core --cov=backend
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines, coding standards, and pull request process.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed architecture overview
- [HANDBOOK.md](HANDBOOK.md) - Engineering handbook and best practices
- [CHANGELOG.md](CHANGELOG.md) - Version history and changes
- [DEPRECATIONS.md](DEPRECATIONS.md) - Deprecated features and migration guides

## License

See [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or contributions, please open an issue on GitHub
