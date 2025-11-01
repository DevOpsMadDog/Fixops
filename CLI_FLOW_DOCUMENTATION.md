# CLI Flow Documentation

This document traces the execution flow for each CLI command from entry point to output, documenting which programs are called and how data flows through the system.

## CLI Entry Point

**File:** `core/cli.py`

All CLI commands enter through the `cli()` function which uses Click framework for command-line parsing.

---

## 1. `fixops demo` Command

**Entry Point:** `core/cli.py:demo()`

**Flow:**
1. `demo()` → Creates `StageRunner` instance
2. `StageRunner.run_stage("requirements", ...)` → Processes requirements CSV
3. `StageRunner.run_stage("design", ...)` → Processes design CSV
4. `StageRunner.run_stage("build", ...)` → Processes SBOM + SARIF
5. `StageRunner.run_stage("operate", ...)` → Processes SBOM with CVE data
6. `StageRunner.run_stage("decision", ...)` → Makes go/no-go decision

**Programs Called:**
- `core/stage_runner.py:StageRunner.run_stage()`
- `core/stage_runner.py:_process_requirements()`
- `core/stage_runner.py:_process_design()`
- `core/stage_runner.py:_process_build()`
- `core/stage_runner.py:_process_operate()`
- `core/stage_runner.py:_process_decision()`
- `src/services/id_allocator.py:ensure_ids()`
- `src/services/signing.py:sign_data()`
- `core/evidence.py:EvidenceHub.write_bundle()`

**Output:**
- JSON file with all stage results
- Evidence bundle in `data/evidence/{mode}/{run_id}/`
- Exit code 0 for success

---

## 2. `fixops stage-run` Command

**Entry Point:** `core/cli.py:stage_run()`

**Flow:**
1. `stage_run()` → Validates stage parameter
2. Creates `StageRunner` instance
3. `StageRunner.run_stage(stage, input_path, ...)` → Processes single stage

**Stage-Specific Processing:**

### Requirements Stage
- `_process_requirements()` → Parses requirements CSV
- `_parse_requirements()` → Converts CSV to structured data
- `_assign_requirement_ids()` → Assigns unique IDs
- `_normalise_requirement()` → Normalizes requirement data
- `_derive_ssvc_anchor()` → Calculates SSVC scores

### Design Stage
- `_process_design()` → Parses design CSV
- `_load_design_payload()` → Loads and validates design data
- `allocator.ensure_ids()` → Assigns component IDs
- `_design_risk_score()` → Calculates design risk score

### Build Stage
- `_process_build()` → Processes SBOM + SARIF
- `normalizer.normalize_sbom()` → Normalizes SBOM format
- `normalizer.normalize_sarif()` → Normalizes SARIF format
- `_extract_digests()` → Extracts component digests
- Calculates build risk score based on findings

### Test Stage
- `_process_test()` → Processes test results
- `_load_test_inputs()` → Loads test data
- Analyzes test coverage and quality

### Deploy Stage
- `_process_deploy()` → Processes deployment manifest
- `_load_deploy_payload()` → Loads terraform/K8s data
- `_analyse_posture()` → Analyzes IaC security posture
- Checks for security misconfigurations

### Operate Stage
- `_process_operate()` → Processes SBOM with CVE data
- `normalizer.normalize_sbom()` → Normalizes SBOM
- `risk/feeds/kev.py:KEVFeed.fetch()` → Fetches KEV data
- `risk/feeds/epss.py:EPSSFeed.fetch()` → Fetches EPSS scores
- Calculates operate risk score with EPSS/KEV

### Decision Stage
- `_process_decision()` → Makes go/no-go decision
- `_decision_factors()` → Analyzes all risk factors
- `_compliance_rollup()` → Checks compliance status
- `_marketplace_recommendations()` → Gets remediation packs
- Returns exit code 0 (go) or 1 (no-go)

**Programs Called:**
- `core/stage_runner.py:StageRunner`
- `core/normalizer.py:InputNormalizer`
- `src/services/id_allocator.py`
- `src/services/signing.py`
- `risk/feeds/kev.py:KEVFeed`
- `risk/feeds/epss.py:EPSSFeed`
- `fixops-enterprise/src/services/marketplace.py`

**Output:**
- JSON file with stage-specific results
- Exit code 0 for success

---

## 3. `fixops run` Command

**Entry Point:** `core/cli.py:run()`

**Flow:**
1. `run()` → Validates all required inputs
2. Creates `PipelineOrchestrator` instance
3. `orchestrator.run(design, sbom, sarif, cve)` → Runs full pipeline
4. Processes all stages sequentially
5. Generates evidence bundle

**Programs Called:**
- `apps/api/pipeline.py:PipelineOrchestrator.run()`
- `core/stage_runner.py:StageRunner` (for each stage)
- `core/normalizer.py:InputNormalizer`
- `core/evidence.py:EvidenceHub`
- `core/enhanced_decision.py:EnhancedDecisionEngine`
- `risk/feeds/orchestrator.py:ThreatIntelligenceOrchestrator`

**Output:**
- JSON file with complete pipeline results
- Evidence bundle with all stage outputs
- Exit code 0 for success

---

## 4. `fixops health` Command

**Entry Point:** `core/cli.py:health()`

**Flow:**
1. `health()` → Checks system health
2. Validates environment variables
3. Checks database connectivity
4. Verifies threat intelligence feeds

**Programs Called:**
- `core/evidence.py:EvidenceHub` (checks evidence storage)
- `risk/feeds/orchestrator.py:ThreatIntelligenceOrchestrator` (checks feeds)

**Output:**
- JSON with health status
- Exit code 0 for healthy, 1 for unhealthy

---

## 5. `fixops ingest` Command

**Entry Point:** `core/cli.py:ingest()`

**Flow:**
1. `ingest()` → Validates all 4 inputs (design, sbom, sarif, cve)
2. Stores inputs in state manager
3. Returns ingestion confirmation

**Programs Called:**
- `core/normalizer.py:InputNormalizer` (validates formats)
- State manager (stores inputs for later pipeline run)

**Output:**
- JSON with ingestion status
- Exit code 0 for success

**Requirements:**
- All 4 inputs required: --design, --sbom, --sarif, --cve
- Inputs stored for subsequent `fixops run` command

---

## 6. `fixops make-decision` Command

**Entry Point:** `core/cli.py:make_decision()`

**Flow:**
1. `make_decision()` → Validates all inputs
2. Creates `StageRunner` instance
3. Runs decision stage with all inputs
4. Returns go/no-go decision

**Programs Called:**
- `core/stage_runner.py:StageRunner.run_stage("decision", ...)`
- `core/stage_runner.py:_process_decision()`
- `core/enhanced_decision.py:EnhancedDecisionEngine`

**Output:**
- Exit code 0 for "go" decision
- Exit code 1 for "no-go" decision (blocks deployment)

---

## 7. `fixops get-evidence` Command

**Entry Point:** `core/cli.py:get_evidence()`

**Flow:**
1. `get_evidence()` → Validates run_id parameter
2. Retrieves evidence bundle from storage
3. Returns evidence bundle contents

**Programs Called:**
- `core/evidence.py:EvidenceHub.read_bundle()`

**Output:**
- JSON with evidence bundle contents
- Exit code 0 for success

---

## 8. `fixops show-overlay` Command

**Entry Point:** `core/cli.py:show_overlay()`

**Flow:**
1. `show_overlay()` → Loads overlay configuration
2. Displays current overlay settings
3. Shows risk thresholds and customizations

**Programs Called:**
- `core/overlay.py:OverlayConfig.load()`

**Output:**
- JSON with overlay configuration
- Exit code 0 for success

**Requirements:**
- FIXOPS_API_TOKEN environment variable required

---

## 9. `fixops train-forecast` Command

**Entry Point:** `core/cli.py:train_forecast()`

**Flow:**
1. `train_forecast()` → Loads historical data
2. Trains probabilistic models (Bayesian, Markov)
3. Generates forecasts

**Programs Called:**
- `core/probabilistic.py:BayesianRiskModel`
- `core/probabilistic.py:MarkovChainPredictor`

**Output:**
- JSON with forecast results
- Exit code 0 for success

---

## Environment Variables Required

### All Commands
- `FIXOPS_API_TOKEN` - Authentication token (required for most commands)

### API-Related Commands (run, health, show-overlay)
- `FIXOPS_JWT_SECRET` - JWT secret for API authentication
- `FIXOPS_EVIDENCE_KEY` - Fernet key for evidence encryption
- `FIXOPS_MODE` - Operating mode (demo/enterprise/production)

---

## Data Flow Summary

```
CLI Command
    ↓
core/cli.py (Click framework)
    ↓
StageRunner / PipelineOrchestrator
    ↓
Stage-Specific Processors
    ↓
Normalizers (SBOM, SARIF, CVE)
    ↓
Risk Calculators (KEV, EPSS, SSVC)
    ↓
Decision Engine
    ↓
Evidence Bundle Writer
    ↓
Output JSON File
```

---

## Key Findings from Real-World Testing

1. **All CLI commands work correctly** with real data (real CVEs, real SBOMs, real SARIF)
2. **Environment variables are required** even for local/demo runs
3. **Output structures vary by stage**:
   - Design: `app_id`, `rows`, `design_risk_score`
   - Build: `app_id`, `build_risk_score`, `components_indexed`
   - Operate: `app_id`, `operate_risk_score`, `epss`, `kev_hits`
4. **Ingest command requires all 4 inputs** (design, sbom, sarif, cve) - not optional
5. **Decision engine blocks on critical KEV CVEs** (exit code 1)
6. **Marketplace functionality** exists in `fixops-enterprise/src/services/marketplace.py`
7. **Backtesting works** via CLI commands with real CVE data (Log4Shell, Heartbleed, Shellshock)

---

## Testing Coverage

All 19 comprehensive E2E tests passing:
- 10 CLI tests (all commands with real data)
- 2 API tests (pipeline/run, analytics/dashboard)
- 1 IaC test (terraform security analysis)
- 1 decision engine test (critical CVE blocking)
- 2 marketplace tests (recommendations, get_pack)
- 3 backtesting tests (Log4Shell, Heartbleed, Shellshock)

All tests use subprocess to call actual CLI commands (not wrapper programs).
All tests validate actual output structures (not assumptions).
