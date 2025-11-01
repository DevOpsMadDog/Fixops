# FixOps Comprehensive E2E Audit - Entry Points Inventory

**Generated:** 2025-11-01  
**Purpose:** Systematic inventory of all CLI commands and API endpoints for comprehensive E2E testing with real data

## CLI Commands (core/cli.py)

### Main Commands

1. **run** - Execute full pipeline with local artifacts
   - Entry: `core/cli.py:_handle_run()`
   - Flow: CLI → InputNormalizer → PipelineOrchestrator → Evidence
   - Inputs: --design, --sbom, --sarif, --cve, --vex, --cnapp, --context
   - Outputs: Pipeline JSON, evidence bundles
   - Real Data Test: ✓ Required

2. **demo** - Run demo/enterprise walkthrough with bundled fixtures
   - Entry: `core/cli.py:_handle_demo()`
   - Flow: CLI → demo_runner → PipelineOrchestrator
   - Modes: --mode demo|enterprise
   - Real Data Test: ✓ Required (enterprise mode only)

3. **make-decision** - Decision-based exit code for CI/CD
   - Entry: `core/cli.py:_handle_make_decision()`
   - Flow: CLI → DecisionEngine → Exit code
   - Real Data Test: ✓ Required

4. **health** - Check system health and dependencies
   - Entry: `core/cli.py:_handle_health()`
   - Flow: CLI → Health checks → Status report
   - Real Data Test: ✓ Required

5. **show-overlay** - Display overlay configuration
   - Entry: `core/cli.py:_handle_show_overlay()`
   - Flow: CLI → OverlayConfig → Display
   - Real Data Test: ✓ Required

6. **train-forecast** - Train probabilistic forecast models
   - Entry: `core/cli.py:_handle_train_forecast()`
   - Flow: CLI → ProbabilisticForecastEngine → Model training
   - Real Data Test: ✓ Required

7. **copy-evidence** - Copy evidence bundles to target directory
   - Entry: `core/cli.py:_copy_evidence()`
   - Flow: CLI → File operations
   - Real Data Test: ✓ Required

8. **stage-run** - Execute specific pipeline stage
   - Entry: `core/cli.py:_handle_stage_run()`
   - Flow: CLI → StageRunner → Stage execution
   - Real Data Test: ✓ Required

9. **ingest** - Ingest artifacts without running pipeline
   - Entry: `core/cli.py:_handle_ingest()`
   - Flow: CLI → ArtefactArchive → Storage
   - Real Data Test: ✓ Required

10. **get-evidence** - Retrieve evidence bundle by run ID
    - Entry: `core/cli.py:_handle_get_evidence()`
    - Flow: CLI → EvidenceHub → Evidence retrieval
    - Real Data Test: ✓ Required

## API Endpoints (apps/api/app.py)

### Authentication
- All endpoints require: `X-API-Key` header with `FIXOPS_API_TOKEN`

### Input Ingestion Endpoints

1. **POST /inputs/design**
   - Handler: `apps/api/app.py:ingest_design()`
   - Flow: API → _process_design() → ArtefactArchive
   - Input: CSV file (design context)
   - Real Data Test: ✓ Required

2. **POST /inputs/sbom**
   - Handler: `apps/api/app.py:ingest_sbom()`
   - Flow: API → _process_sbom() → InputNormalizer.load_sbom()
   - Input: JSON (CycloneDX or SPDX)
   - Real Data Test: ✓ Required (both formats)

3. **POST /inputs/cve**
   - Handler: `apps/api/app.py:ingest_cve()`
   - Flow: API → _process_cve() → InputNormalizer.load_cve_feed()
   - Input: JSON (CVE/KEV feed)
   - Real Data Test: ✓ Required (real KEV data)

4. **POST /inputs/vex**
   - Handler: `apps/api/app.py:ingest_vex()`
   - Flow: API → _process_vex() → InputNormalizer.load_vex()
   - Input: JSON (VEX document)
   - Real Data Test: ✓ Required

5. **POST /inputs/cnapp**
   - Handler: `apps/api/app.py:ingest_cnapp()`
   - Flow: API → _process_cnapp() → InputNormalizer.load_cnapp()
   - Input: JSON (CNAPP findings)
   - Real Data Test: ✓ Required

6. **POST /inputs/sarif**
   - Handler: `apps/api/app.py:ingest_sarif()`
   - Flow: API → _process_sarif() → InputNormalizer.load_sarif()
   - Input: JSON (SARIF 2.1.0)
   - Real Data Test: ✓ Required (Semgrep, CodeQL, Bandit)

7. **POST /inputs/context**
   - Handler: `apps/api/app.py:ingest_context()`
   - Flow: API → _process_context() → Business context storage
   - Input: JSON (business context)
   - Real Data Test: ✓ Required

### Chunked Upload Endpoints

8. **POST /upload/init**
   - Handler: `apps/api/app.py:initialise_chunk_upload()`
   - Flow: API → ChunkUploadManager.init_session()
   - Real Data Test: ✓ Required

9. **POST /upload/chunk**
   - Handler: `apps/api/app.py:upload_chunk()`
   - Flow: API → ChunkUploadManager.append_chunk()
   - Real Data Test: ✓ Required

10. **POST /upload/complete**
    - Handler: `apps/api/app.py:complete_upload()`
    - Flow: API → ChunkUploadManager.finalise() → Processing
    - Real Data Test: ✓ Required

11. **GET /upload/status/{session_id}**
    - Handler: `apps/api/app.py:upload_status()`
    - Flow: API → ChunkUploadManager.get_status()
    - Real Data Test: ✓ Required

### Pipeline Execution

12. **POST /pipeline/run**
    - Handler: `apps/api/app.py:run_pipeline()`
    - Flow: API → PipelineOrchestrator.run() → All modules → Evidence
    - Real Data Test: ✓ CRITICAL - Main workflow

### Analytics & Feedback

13. **GET /analytics/dashboard**
    - Handler: `apps/api/app.py:analytics_dashboard()`
    - Flow: API → AnalyticsStore.get_dashboard()
    - Real Data Test: ✓ Required

14. **GET /analytics/run/{run_id}**
    - Handler: `apps/api/app.py:analytics_run()`
    - Flow: API → AnalyticsStore.get_run()
    - Real Data Test: ✓ Required

15. **POST /feedback**
    - Handler: `apps/api/app.py:submit_feedback()`
    - Flow: API → FeedbackRecorder.record()
    - Real Data Test: ✓ Required

### Health & Status

16. **GET /api/v1/health** (from health_router)
    - Handler: `apps/api/health.py`
    - Flow: API → Health checks
    - Real Data Test: ✓ Required

17. **GET /api/v1/ready** (from health_router)
    - Handler: `apps/api/health.py`
    - Flow: API → Readiness checks
    - Real Data Test: ✓ Required

### Enhanced Decision Engine

18. **POST /api/v1/enhanced/compare-llms** (from enhanced_router)
    - Handler: `apps/api/routes/enhanced.py`
    - Flow: API → EnhancedDecisionEngine.evaluate()
    - Real Data Test: ✓ CRITICAL - Multi-LLM consensus

19. **GET /api/v1/enhanced/capabilities** (from enhanced_router)
    - Handler: `apps/api/routes/enhanced.py`
    - Flow: API → Capabilities report
    - Real Data Test: ✓ Required

### Evidence Management (from evidence_router)

20. **GET /api/v1/evidence/{run_id}** (from evidence_router)
    - Handler: `backend/api/evidence.py`
    - Flow: API → EvidenceHub → Evidence retrieval
    - Real Data Test: ✓ Required

### Risk Analysis (from risk_router)

21. **POST /api/v1/risk/assess** (from risk_router)
    - Handler: `backend/api/risk.py`
    - Flow: API → Risk assessment
    - Real Data Test: ✓ Required

### Provenance (from provenance_router)

22. **GET /api/v1/provenance/{artifact_id}** (from provenance_router)
    - Handler: `backend/api/provenance.py`
    - Flow: API → Provenance tracking
    - Real Data Test: ✓ Required

### Knowledge Graph (from graph_router)

23. **GET /api/v1/graph/query** (from graph_router)
    - Handler: `backend/api/graph.py`
    - Flow: API → Knowledge graph query
    - Real Data Test: ✓ Required

## Pipeline Modules (apps/api/pipeline.py)

### Core Orchestration
- **PipelineOrchestrator.run()** - Main orchestration
  - Entry: `apps/api/pipeline.py:PipelineOrchestrator.run()`
  - Flow: Crosswalk → Modules → Evidence
  - Real Data Test: ✓ CRITICAL

### Module Execution Flow
1. Guardrails module
2. Context engine module
3. Compliance module
4. SSDLC module
5. IaC posture module
6. Exploit signals module
7. Probabilistic forecasting module
8. Policy automation module
9. Evidence generation module

## Decision Engines

### Simple Decision Engine
- **DecisionEngine** - `fixops-blended-enterprise/src/services/decision_engine.py`
  - Entry: `DecisionEngine.evaluate()`
  - Flow: Scoring → SSVC → KEV/EPSS → Verdict
  - Real Data Test: ✓ CRITICAL

### Enhanced Decision Engine
- **EnhancedDecisionEngine** - `core/enhanced_decision.py`
  - Entry: `EnhancedDecisionEngine.evaluate()`
  - Flow: Multi-LLM → Consensus → Hallucination guards → Verdict
  - Real Data Test: ✓ CRITICAL (requires LLM credentials)

## External Data Feeds

### KEV Feed
- Source: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Local: `data/feeds/kev.json`
- Real Data Test: ✓ CRITICAL - Must use live data

### EPSS Feed
- Source: `https://api.first.org/data/v1/epss`
- Local: `data/feeds/epss.json`
- Real Data Test: ✓ CRITICAL - Must use live data

## External Connectors (Enterprise Mode)

### Jira Connector
- Module: `core/policy.py:JiraConnector`
- Config: `config/fixops.overlay.yml:jira`
- Real Data Test: ✓ Required (if credentials available)

### Confluence Connector
- Module: `core/policy.py:ConfluenceConnector`
- Config: `config/fixops.overlay.yml:confluence`
- Real Data Test: ✓ Required (if credentials available)

### Slack Connector
- Module: `core/policy.py:SlackConnector`
- Real Data Test: ✓ Required (if credentials available)

## Test Data Requirements

### Real CVE Data
- [ ] KEV CVEs (actively exploited)
- [ ] High EPSS CVEs (≥0.7)
- [ ] Low EPSS CVEs (<0.3)
- [ ] CVEs with CWE mappings
- [ ] CVEs without patches

### Real SBOM Data
- [ ] CycloneDX format (real OSS project)
- [ ] SPDX format (real OSS project)
- [ ] Large SBOM (>1000 components)
- [ ] SBOM with vulnerabilities

### Real SARIF Data
- [ ] Semgrep output (real scan)
- [ ] CodeQL output (real scan)
- [ ] Bandit output (real scan)
- [ ] Mixed severity findings

### Real Business Context
- [ ] Mission-critical service
- [ ] PII data classification
- [ ] Internet exposure

## Testing Strategy

### Phase 1: Entry Point Validation
- Test each CLI command with real data
- Test each API endpoint with real data
- Document actual flow: entry → programs → output
- Capture file:line references for each stage

### Phase 2: Module Integration
- Test each pipeline module independently
- Test full pipeline with all modules enabled
- Test module interactions and dependencies

### Phase 3: External Services
- Test KEV/EPSS feed refresh
- Test Jira/Confluence/Slack connectors
- Test LLM providers (if credentials available)

### Phase 4: Decision Engine Backtesting
- Run KEV dataset through decision engine
- Verify all KEV CVEs trigger appropriate actions
- Run EPSS dataset through decision engine
- Verify EPSS thresholds work correctly

### Phase 5: Evidence & Compliance
- Test evidence encryption and signatures
- Test evidence retrieval and verification
- Test compliance mapping accuracy

### Phase 6: Stress & Edge Cases
- Large file uploads
- Malformed inputs
- Missing credentials
- Concurrent requests
- Network failures

## Documentation Deliverables

1. **Flow Diagrams** - Visual representation of each workflow
2. **Program Flow Documentation** - file:line references for each stage
3. **Bug Report** - All real bugs found during testing
4. **Dead Code Report** - Unused code identified via coverage
5. **IaC Fixes** - Corrected infrastructure as code
6. **Architecture Review** - Recommendations for improvements

## Status

- [x] Inventory created
- [ ] Real data harness created
- [ ] CLI commands tested
- [ ] API endpoints tested
- [ ] Decision engine backtested
- [ ] External services tested
- [ ] Evidence management tested
- [ ] Flow documentation completed
- [ ] Bug report completed
- [ ] IaC fixes completed
