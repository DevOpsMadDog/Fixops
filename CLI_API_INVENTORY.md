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

## API Endpoints (apps/api/app.py)

TODO: Inventory all FastAPI endpoints

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
