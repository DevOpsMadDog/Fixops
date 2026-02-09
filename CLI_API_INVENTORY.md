# FixOps CLI and API Inventory

## CLI Commands (core/cli.py)

### 1. stage-run
**Purpose:** Normalize a single stage input and materialize canonical outputs
**Entry Point:** `core/cli.py:_handle_stage_run()`
**Arguments:**
- `--stage` (required): requirements, design, build, test, deploy, operate, decision
- `--input`: Path to stage input artifact
- `--app`: Application identifier
- `--output`: Optional path to copy canonical output
- `--mode`: demo or enterprise
- `--sign`: Sign canonical outputs
- `--verify`: Verify signatures
- `--verbose`: Print verbose information

**Flow:** CLI → StageRunner.run_stage() → Output files in registry

### 2. run
**Purpose:** Execute the FixOps pipeline locally
**Entry Point:** `core/cli.py:_handle_run()`
**Arguments:** (via _configure_pipeline_parser)
- Design, SBOM, SARIF, CVE inputs
- `--overlay`: Path to overlay file
- `--quiet`: Suppress summary

**Flow:** CLI → PipelineOrchestrator.run() → Evidence bundle + decision

### 3. ingest
**Purpose:** Normalize artifacts and print pipeline response
**Entry Point:** `core/cli.py:_handle_ingest()`
**Arguments:** Same as run
**Flow:** CLI → PipelineOrchestrator.run() → JSON output

### 4. make-decision
**Purpose:** Execute pipeline and use decision as exit code
**Entry Point:** `core/cli.py:_handle_make_decision()`
**Arguments:** Same as run
**Flow:** CLI → PipelineOrchestrator.run() → Exit code based on decision

### 5. health
**Purpose:** Check integration readiness for local runs
**Entry Point:** `core/cli.py:_handle_health()`
**Arguments:**
- `--overlay`: Path to overlay file
- `--pretty`: Pretty-print JSON

**Flow:** CLI → Check integrations → Health status JSON

### 6. get-evidence
**Purpose:** Copy evidence bundle from pipeline result
**Entry Point:** `core/cli.py:_handle_get_evidence()`
**Arguments:**
- `--result` (required): Path to pipeline result JSON
- `--destination`: Directory to copy bundle
- `--pretty`: Pretty-print JSON

**Flow:** CLI → Read result → Copy evidence bundle

### 7. show-overlay
**Purpose:** Print sanitized overlay configuration
**Entry Point:** `core/cli.py:_handle_show_overlay()`
**Arguments:**
- `--overlay`: Path to overlay file
- `--env`: Set environment variables
- `--pretty`: Pretty-print JSON

**Flow:** CLI → Load overlay → Print config

### 8. train-forecast
**Purpose:** Calibrate probabilistic severity forecast engine
**Entry Point:** `core/cli.py:_handle_train_forecast()`
**Arguments:**
- `--incidents` (required): Historical incident records JSON
- `--config`: Base forecast configuration
- `--output`: File to write calibrated priors
- `--pretty`: Pretty-print JSON
- `--enforce-validation`: Fail if matrix doesn't validate
- `--quiet`: Suppress summary

**Flow:** CLI → Train forecast model → Save calibrated config

### 9. demo
**Purpose:** Run pipeline with bundled demo/enterprise fixtures
**Entry Point:** `core/cli.py:_handle_demo()`
**Arguments:**
- `--mode`: demo or enterprise
- `--output`: Path to write pipeline response
- `--pretty`: Pretty-print JSON
- `--quiet`: Suppress summary

**Flow:** CLI → Load fixtures → PipelineOrchestrator.run() → Output

### 10. mpte
**Purpose:** Manage MPTE pen testing integration
**Entry Point:** `core/cli.py:_handle_mpte()`

#### 10.1 mpte list-requests
```bash
python -m core.cli mpte list-requests [--finding-id ID] [--status STATUS] [--limit N] [--offset N] [--format table|json]
```
- Lists pen test requests with optional filtering
- Status choices: pending, running, completed, failed, cancelled
- Default format: table
- Returns exit code 0 on success

#### 10.2 mpte create-request
```bash
python -m core.cli mpte create-request \
  --finding-id "finding-123" \
  --target-url "https://test.example.com/api" \
  --vuln-type "sql_injection" \
  --test-case "Test SQL injection via username parameter" \
  --priority critical|high|medium|low
```
- Creates new pen test request for a finding
- Priority defaults to medium
- Returns request ID and JSON on success
- Returns exit code 0 on success

#### 10.3 mpte get-request
```bash
python -m core.cli mpte get-request <request_id>
```
- Gets pen test request details by ID
- Returns JSON with full request details
- Returns exit code 0 if found, 1 if not found

#### 10.4 mpte list-results
```bash
python -m core.cli mpte list-results [--finding-id ID] [--exploitability LEVEL] [--limit N] [--offset N] [--format table|json]
```
- Lists pen test results with optional filtering
- Exploitability choices: confirmed_exploitable, likely_exploitable, unexploitable, blocked, inconclusive
- Default format: table
- Returns exit code 0 on success

#### 10.5 mpte list-configs
```bash
python -m core.cli mpte list-configs [--limit N] [--offset N] [--format table|json]
```
- Lists MPTE configuration instances
- Default format: table
- Returns exit code 0 on success

#### 10.6 mpte create-config
```bash
python -m core.cli mpte create-config \
  --name "Production MPTE" \
  --url "https://mpte.example.com" \
  [--api-key "secret-key"] \
  [--disabled]
```
- Creates new MPTE configuration
- Config is enabled by default unless --disabled flag is used
- API key is optional
- Returns config ID and JSON on success
- Returns exit code 0 on success

**Flow:** CLI → MPTEDB operations → Output results

## API Endpoints (apps/api/app.py)

### Phase 6: MPTE Integration (12 endpoints) ✅

#### Pen Test Request Management (apps/api/mpte_router.py)
- `GET /api/v1/mpte/requests` - List pen test requests with filtering
- `POST /api/v1/mpte/requests` - Create pen test request
- `GET /api/v1/mpte/requests/{id}` - Get pen test request details
- `PUT /api/v1/mpte/requests/{id}` - Update pen test request
- `POST /api/v1/mpte/requests/{id}/start` - Start pen test execution
- `POST /api/v1/mpte/requests/{id}/cancel` - Cancel running pen test

#### Pen Test Results (apps/api/mpte_router.py)
- `GET /api/v1/mpte/results` - List pen test results with filtering
- `POST /api/v1/mpte/results` - Create pen test result
- `GET /api/v1/mpte/results/by-request/{request_id}` - Get result by request ID

#### MPTE Configuration (apps/api/mpte_router.py)
- `GET /api/v1/mpte/configs` - List MPTE configurations
- `POST /api/v1/mpte/configs` - Create MPTE configuration
- `GET /api/v1/mpte/configs/{id}` - Get configuration details
- `PUT /api/v1/mpte/configs/{id}` - Update configuration
- `DELETE /api/v1/mpte/configs/{id}` - Delete configuration

**Total API Surface: 137 endpoints** (125 from Phases 1-5 + 12 from Phase 6)

---

## Enterprise Plug-and-Play Integration Endpoints

### Integration Management (apps/api/integrations_router.py)

| Endpoint | Method | CLI Command | Status |
|----------|--------|-------------|--------|
| `/api/v1/integrations` | GET | `integrations list` | Working |
| `/api/v1/integrations` | POST | `integrations configure` | Working |
| `/api/v1/integrations/{id}` | GET | N/A | Working |
| `/api/v1/integrations/{id}` | PUT | N/A | Working |
| `/api/v1/integrations/{id}` | DELETE | N/A | Working |
| `/api/v1/integrations/{id}/test` | POST | `integrations test` | Working |
| `/api/v1/integrations/{id}/sync-status` | GET | N/A | Working |
| `/api/v1/integrations/{id}/sync` | POST | `integrations sync` | **NO-OP** |

### Webhook Receivers (apps/api/webhooks_router.py)

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `/api/v1/webhooks/jira` | POST | Receive Jira webhook events | Working |
| `/api/v1/webhooks/servicenow` | POST | Receive ServiceNow webhook events | Working |
| `/api/v1/webhooks/gitlab` | POST | Receive GitLab webhook events | Working |
| `/api/v1/webhooks/azure-devops` | POST | Receive Azure DevOps webhook events | Working |

### Outbox Management (apps/api/webhooks_router.py)

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `/api/v1/webhooks/outbox` | GET | List outbox items | Working |
| `/api/v1/webhooks/outbox/{id}` | GET | Get outbox item details | Working |
| `/api/v1/webhooks/outbox/{id}/execute` | POST | Execute outbox item via connector | Working |
| `/api/v1/webhooks/outbox/process-pending` | POST | Process all pending outbox items | Working |

### Connector Status Summary

| Connector | Outbound Operations | Inbound (Webhook) | Background Worker | Bidirectional Sync |
|-----------|---------------------|-------------------|-------------------|-------------------|
| **Jira** | `create_issue()`, `update_issue()`, `transition_issue()`, `add_comment()` | Yes | Outbox execute | Drift detection |
| **Confluence** | `create_page()` only | No | No | No |
| **Slack** | `post_message()` only | No | No | No |
| **ServiceNow** | `create_incident()`, `update_incident()`, `add_work_note()` | Yes | Outbox execute | No |
| **GitLab** | `create_issue()`, `update_issue()`, `add_comment()` | Yes | Outbox execute | No |
| **Azure DevOps** | `create_work_item()`, `update_work_item()`, `add_comment()` | Yes | Outbox execute | No |
| **GitHub** | `create_issue()`, `update_issue()`, `add_comment()` | No | Outbox execute | No |

See [Enterprise Plug-and-Play Readiness](docs/FIXOPS_PRODUCT_STATUS.md#enterprise-plug-and-play-readiness) for detailed analysis and roadmap.

---

## Supported Input Formats (apps/api/normalizers.py)

### SBOM Formats
| Format | Description | Parser | Status |
|--------|-------------|--------|--------|
| **CycloneDX** | OWASP CycloneDX JSON/XML | `lib4sbom`, `_parse_cyclonedx_json()` | Wired |
| **SPDX** | Linux Foundation SPDX | `lib4sbom` | Wired |
| **Syft JSON** | Anchore Syft native format | `_parse_syft_json()` | Wired |
| **GitHub Dependency Snapshot** | GitHub dependency graph export | `_parse_github_dependency_snapshot()` | Wired |

### AI/ML-BOM Formats (CycloneDX v1.5+)
| Format | Description | Parser | Status |
|--------|-------------|--------|--------|
| **CycloneDX ML-BOM** | Machine Learning Bill of Materials for AI/ML model transparency | `load_sbom()` | Wired |

The CycloneDX ML-BOM format (introduced in CycloneDX v1.5) enables transparency in AI and machine learning systems by representing critical information about models, datasets, and their dependencies. This includes the provenance of datasets, training methodologies, and the configuration of AI frameworks. FixOps normalizes ML-BOM documents through the same SBOM ingestion pipeline, extracting model components, training data references, and AI framework dependencies for security analysis.

### Other Input Formats
| Format | Description | Parser | API Endpoint | Status |
|--------|-------------|--------|--------------|--------|
| **SARIF** | Static Analysis Results Interchange Format | `load_sarif()` | `POST /inputs/sarif` | Wired |
| **CVE Feed** | CVE/KEV vulnerability feeds | `load_cve_feed()` | `POST /inputs/cve` | Wired |
| **VEX** | Vulnerability Exploitability eXchange | `load_vex()` | `POST /inputs/vex` | Wired |
| **CNAPP** | Cloud-Native Application Protection Platform findings | `load_cnapp()` | `POST /inputs/cnapp` | Wired |
| **Business Context** | FixOps/OTM/SSVC context documents | `load_business_context()` | `POST /inputs/context` | Wired |

---

## Output Files

### Stage Outputs
- requirements.json
- design.manifest.json
- build.report.json
- test.report.json
- deploy.manifest.json
- operate.snapshot.json
- decision.json
- manifest.json (checksums of all stage outputs)

### Evidence Bundle
- evidence_bundle.zip (contains all stage outputs + manifest)

## Code Flow

### Stage Processing
1. CLI/API receives input
2. StageRunner.run_stage() called with stage name and input
3. Stage-specific processor (_process_requirements, _process_design, etc.)
4. Output written to RunRegistry directory
5. Evidence bundle created with all outputs
6. Manifest with checksums generated

### Pipeline Processing
1. CLI/API receives design, SBOM, SARIF, CVE inputs
2. PipelineOrchestrator.run() orchestrates all stages
3. Each stage processes its input
4. Decision engine evaluates all outputs
5. Evidence bundle created
6. Pipeline result returned with all summaries
