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

### 10. train-bn-lr
**Purpose:** Train Bayesian Network + Logistic Regression hybrid model
**Entry Point:** `core/cli.py:_handle_train_bn_lr()`
**Arguments:**
- `--data` (required): Path to CSV training data
- `--output`: Path to write trained model
- `--pretty`: Pretty-print JSON
- `--quiet`: Suppress training summary

**Flow:** CLI → Train BN-LR model → Save model file

### 11. predict-bn-lr
**Purpose:** Make predictions using trained BN-LR model
**Entry Point:** `core/cli.py:_handle_predict_bn_lr()`
**Arguments:**
- `--model` (required): Path to trained model
- `--data` (required): Path to CSV test data
- `--output`: Path to write predictions
- `--pretty`: Pretty-print JSON
- `--quiet`: Suppress prediction summary

**Flow:** CLI → Load model → Make predictions → Output results

### 12. backtest-bn-lr
**Purpose:** Backtest BN-LR model performance
**Entry Point:** `core/cli.py:_handle_backtest_bn_lr()`
**Arguments:**
- `--model` (required): Path to trained model
- `--data` (required): Path to CSV test data
- `--output`: Path to write metrics
- `--pretty`: Pretty-print JSON
- `--thresholds`: Comma-separated decision thresholds
- `--allow-skew`: Allow BN CPD hash mismatch
- `--quiet`: Suppress backtest summary

**Flow:** CLI → Load model → Evaluate on test data → Output metrics

### 13. inventory
**Purpose:** Manage application and service inventory
**Entry Point:** `core/cli.py:_handle_inventory()`

#### 13.1 inventory list
```bash
fixops inventory list [--limit N] [--offset N] [--format table|json]
```
- Lists all applications with pagination
- Default format: table
- Returns exit code 0 on success

#### 13.2 inventory create
```bash
fixops inventory create \
  --name "App Name" \
  --description "Description" \
  --criticality critical|high|medium|low \
  [--environment production] \
  [--owner-team "Team Name"] \
  [--repo-url "https://..."]
```
- Creates new application
- Prints application ID and JSON on success
- Returns exit code 0 on success, 1 on failure

#### 13.3 inventory get
```bash
fixops inventory get <id> [--format table|json]
```
- Gets application details by ID
- Default format: json
- Returns exit code 0 if found, 1 if not found

#### 13.4 inventory update
```bash
fixops inventory update <id> \
  [--name "New Name"] \
  [--description "New Description"] \
  [--criticality critical|high|medium|low] \
  [--status active|deprecated|archived]
```
- Updates application fields
- Only specified fields are updated
- Returns exit code 0 on success

#### 13.5 inventory delete
```bash
fixops inventory delete <id> --confirm
```
- Deletes application (requires --confirm flag)
- Returns exit code 0 on success, 1 on failure

#### 13.6 inventory search
```bash
fixops inventory search <query> [--limit N]
```
- Searches across all inventory types
- Returns JSON with results
- Returns exit code 0 on success

**Flow:** CLI → InventoryDB operations → Output results

## API Endpoints

### Core API (apps/api/app.py)
- `GET /health` - Health check endpoint
- `GET /api/v1/status` - Authenticated status endpoint
- `POST /inputs/design` - Upload design CSV
- `POST /inputs/sbom` - Upload SBOM JSON
- `POST /inputs/cve` - Upload CVE JSON
- `POST /inputs/vex` - Upload VEX document
- `POST /inputs/cnapp` - Upload CNAPP findings
- `POST /inputs/sarif` - Upload SARIF scan results
- `POST /inputs/context` - Upload business context
- `POST /api/v1/uploads/init` - Initialize chunked upload
- `POST /api/v1/uploads/{upload_id}/chunk` - Upload chunk
- `POST /api/v1/uploads/{upload_id}/complete` - Complete upload
- `GET /api/v1/uploads/{upload_id}/status` - Get upload status
- `POST /pipeline/run` - Execute pipeline
- `GET /analytics/dashboard` - Get analytics dashboard
- `GET /analytics/run/{run_id}` - Get analytics for specific run
- `POST /feedback` - Submit feedback

### Inventory API (apps/api/inventory_router.py) - Phase 1
- `GET /api/v1/inventory/applications` - List applications
- `POST /api/v1/inventory/applications` - Create application
- `GET /api/v1/inventory/applications/{id}` - Get application
- `PUT /api/v1/inventory/applications/{id}` - Update application
- `DELETE /api/v1/inventory/applications/{id}` - Delete application
- `GET /api/v1/inventory/applications/{id}/components` - List components
- `GET /api/v1/inventory/applications/{id}/apis` - List APIs
- `GET /api/v1/inventory/applications/{id}/dependencies` - Get dependencies
- `GET /api/v1/inventory/services` - List services
- `POST /api/v1/inventory/services` - Create service
- `GET /api/v1/inventory/services/{id}` - Get service
- `GET /api/v1/inventory/apis` - List API endpoints
- `POST /api/v1/inventory/apis` - Create API endpoint
- `GET /api/v1/inventory/apis/{id}/security` - Get API security
- `GET /api/v1/inventory/search` - Search inventory

### Backend API Routers
- Provenance API (backend/api/provenance/router.py)
- Risk API (backend/api/risk/router.py)
- Graph API (backend/api/graph/router.py)
- Evidence API (backend/api/evidence/router.py)

**Total Endpoints**: ~55 (40 existing + 15 new inventory endpoints)
**Planned**: 80+ additional endpoints across Phases 2-4

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
