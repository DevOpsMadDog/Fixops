# Data Scientist Persistent Memory

## Key Patterns
- **Import mechanism**: `sitecustomize.py` auto-prepends suite paths. Use `from core.ml.risk_scorer import ...`
- **Golden dataset**: `data/golden_regression_cases.json` — 75 real CVE cases, 7 categories (v3.0.0)
- **ML models dir**: `.claude/team-state/data-science/models/`
- **Brain pipeline Step 2**: ParserQualityValidator wired into `_step_normalize()` — quality metrics in step output
- **Brain pipeline Step 5**: GNN attack-path analysis wired into `_step_build_graph()` — attention hotspots in output
- **Brain pipeline Step 6**: Uses ThreatEnricher (real EPSS/KEV) — NOT fake formula
- **Brain pipeline Step 7**: ML scorer integrated + SHAP explanations at `suite-core/core/brain_pipeline.py`
- **Feature importance**: asset_criticality (59.4%) >> epss_score (31.5%) >> network_exposure (3.2%)
- **Consensus weights**: claude=0.329, gpt4=0.330, gemini=0.340 (F1=0.9081, updated 2026-03-02)
- **Risk model version**: v2.1.0 — GBT with 200 estimators, max_depth=4, lr=0.05, trained on 75 cases
- **Priority thresholds (v2.1.0)**: P0>=82, P1>=56, P2>=30, P3>=8, P4>=5, FP<5
- **AutoFix confidence model**: v1.0.0 — Random Forest, 200 trees, 10 features, 83.7% accuracy
- **AutoFix ML wired**: `_compute_confidence()` in autofix_engine.py uses ML model -> fallback rule-based
- **CWE mapping**: `_cwe_to_category()` covers 20+ CWEs -> 14 categories; fix-type fallback for unknown CWEs
- **EventBus integration**: ML handlers auto-register via `register_all_subscribers()` in event_subscribers.py
- **Online learning**: Wired to DECISION_MADE + REMEDIATION_COMPLETED events → feedback buffer → retrain

## ML Module Index (10 modules, 7,325 LOC)
| Module | LOC | Purpose |
|--------|-----|---------|
| `risk_scorer.py` | 1,211 | GBT risk scoring + SHAP explanations (Step 7) |
| `online_learning.py` | 1,176 | User feedback → model retraining pipeline |
| `attack_path_gnn.py` | 923 | 2-layer GAT for attack-path analysis (Step 5) |
| `autofix_confidence.py` | 734 | AutoFix quality prediction |
| `anomaly_detector.py` | 709 | Isolation Forest + scan drift detection |
| `parser_quality.py` | 693 | Scanner parser data quality validator |
| `threat_enricher.py` | 602 | Real EPSS/KEV/CVSS enrichment (Step 6) |
| `consensus_calibrator.py` | 560 | Multi-LLM weight calibration (Step 9) |
| `daily_intel.py` | 423 | Daily threat intelligence collector |
| `eventbus_integration.py` | 294 | EventBus wiring for ML alerts |

## API Endpoints for Feeds
- EPSS: `https://api.first.org/data/v1/epss` — supports batch: `?cve=CVE-1,CVE-2` (max 30/batch)
- NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0` (live, sometimes slow ~10s)
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (1,529 entries)
- All three fetched successfully on 2026-03-03

## Test Patterns
- ML tests: `test_ml_risk_scorer.py` (42), `test_ml_anomaly_detector.py` (21), `test_ml_consensus_calibrator.py` (24), `test_ml_threat_enricher.py` (29), `test_ml_autofix_confidence.py` (38), `test_ml_shap_explanations.py` (36), `test_ml_drift_detection.py` (21), `test_ml_parser_quality.py` (16), `test_ml_eventbus_integration.py` (30), `test_ml_online_learning.py` (47), `test_ml_attack_path_gnn.py` (38)
- MCP demo tests: `test_mcp_gateway_demo.py` (22)
- Autofix engine tests: `test_autofix_engine_unit.py` (54, incl. 17 ML integration + CWE mapping)
- Brain pipeline tests: `test_brain_pipeline.py` (73)
- **ML-only tests: 365 PASS**
- **Total incl. MCP+autofix+brain: 514 tests, ALL PASS**
- Use `tempfile.mkdtemp()` for model_dir in tests to avoid side effects
- Brain pipeline tests expect real KEV behavior (synthetic CVEs -> in_kev=False)
- Golden dataset assertions use `>=50` (not `==50`) since dataset grows
- **Priority threshold tests**: Must match risk_scorer.py thresholds — update BOTH when changing
- **EventBus tests**: Reset both EventBus singleton AND ML handler state before each test
- **Online learning tests**: Use `reset_pipeline()` before/after to avoid singleton leaks

## Priority Threshold Calibration (CRITICAL LESSON)
- **v1.0.0 -> v2.1.0**: P0: 85->82, P1: 60->56, P2: 35->30, P3: 15->8
- Priority mismatches are usually threshold issues, NOT model accuracy problems
- When recalibrating: find boundary scores, pick thresholds between adjacent priorities

## EventBus Integration (2026-03-03)
- `eventbus_integration.py` registers on SCAN_COMPLETED: anomaly detection + parser quality
- `online_learning.py` registers on DECISION_MADE + REMEDIATION_COMPLETED: feedback → retrain
- 4 ML event types: SCAN_ANOMALY_DETECTED, SCAN_DRIFT_DETECTED, MODEL_RETRAINED, PARSER_QUALITY_FAILED
- Per-org scan history for drift detection (bounded at 50 scans per org)
- `register_ml_handlers(bus)` is idempotent — safe to call multiple times
- `register_online_learning_handlers(bus)` is idempotent — safe to call multiple times
- Both wired into `register_all_subscribers()` in `core/event_subscribers.py`
- **Anomaly detector auto-fitted with synthetic baseline** — real scans may trigger anomaly against synthetic baseline (expected behavior)

## Online Learning Pipeline (2026-03-03)
- FeedbackConverter: maps 4 feedback types (decision_outcome, false_positive, mpte_result, remediation_success)
- FeedbackBuffer: thread-safe deque with configurable min_for_retrain and max_size
- IncrementalTrainer: warm-start GBT with golden regression gate (95% pass threshold)
- Safety: MAE increase guard (max 5%), score drift guard (max 20 points), atomic model swap
- Rate limiting: 10 min between retrains (configurable via FIXOPS_ONLINE_LEARN_INTERVAL)
- Retrain log persisted to `.claude/team-state/data-science/online-learning-log.json`
- Env vars: FIXOPS_ONLINE_LEARN_MIN_SAMPLES, FIXOPS_ONLINE_LEARN_MAX_BUFFER, FIXOPS_ONLINE_LEARN_INTERVAL

## Attack-Path GNN (2026-03-03)
- Architecture: 2-layer GAT (12→32×4→16), pure numpy (V9 air-gap)
- Node features: 12-dim (10 type one-hot + severity + criticality)
- GATLayer: attention mechanism from Velickovic et al. (2018), multi-head
- Path scoring: aggregated attention-weighted node embeddings × propagation factor
- Risk propagation: BFS with attention-weighted decay, configurable max_depth and decay factor
- Hotspot detection: nodes receiving most incoming attention
- Helper: `build_gnn_from_knowledge_graph(kg)` — fits GNN from KnowledgeGraphEngine instance
- Wired into brain pipeline Step 5: defensive try/except, adds gnn_fitted/gnn_coverage/gnn_hotspots

## Brain Pipeline StepResult API
- `StepResult.output` is `Dict[str, Any]` — NOT `.result`
- `PipelineResult.steps` is list of `StepResult` (NOT `.step_results`)
- Step 2 output: `{"normalized_count", "parser_quality_score", "parser_quality_passes", "parser_quality_errors", "parser_quality_warnings"}`
- Step 5 output: `{"nodes_added", "edges_added", "total_nodes", "total_edges", "gnn_fitted", "gnn_coverage", "gnn_hotspots"}`
- Step 7 output: `{"avg_risk_score", "critical_count", "scored", "model", "avg_confidence_width"}`
- Context findings NOT exposed via to_dict() — SHAP data is in pipeline internal context only

## Architecture Decisions
- GBT over LogisticRegression: need 0-100 continuous regression, not binary classification
- Bootstrap ensemble (20 models) for confidence intervals, not parametric CI
- Isolation Forest over DBSCAN: more robust for unknown distributions, no eps tuning
- Interventional SHAP over shap library: V9 air-gap compatible, no heavy dependencies
- Parser quality: per-category baselines from industry data, not per-scanner
- EventBus ML handlers: defensive/non-blocking — failures logged but don't crash pipeline
- GNN: pure numpy GAT over PyTorch Geometric: V9 compliance, <10K node graphs, deterministic
- Online learning: warm-start GBT over full retrain: preserves existing knowledge, faster convergence

## MCP Gateway (DEMO-009)
- **757 tools** auto-discovered via `suite-api/apps/api/mcp_router.py` (977 LOC)
- MCP auto-discovery is at `/api/v1/mcp/tools`, NOT `suite-integrations/api/mcp_router.py`
- **Rate limiter**: Set `FIXOPS_DISABLE_RATE_LIMIT=1` in tests
- Demo script: `scripts/mcp_gateway_demo.py` — supports `--self-contained` and `--json` modes
- **7 demo steps**: init → discover → scan → pipeline → results → ML showcase → schema export
- Step 6 (ML Intelligence Showcase): risk scoring with SHAP, anomaly detection, consensus F1
- MCP demo result saved to `.claude/team-state/data-science/mcp-gateway-demo-result.json`
- ML dashboard data at `.claude/team-state/data-science/ml-dashboard.json`

## Daily Intel API
- Use `collect_daily_intel()` from `core.ml.daily_intel` (NOT `DailyIntelCollector` class)
- Module exports: `collect_daily_intel`, `fetch_epss_intel`, `fetch_nvd_intel`, `fetch_kev_intel`
- Output at `.claude/team-state/data-science/daily-intel.json`
- Summary keys: epss_high_count, epss_weaponized_count, nvd_critical_count, etc.

## Consensus Calibrator API
- `CalibrationResult` has `.model_evaluations` (NOT `.model_performance`)
- Use `.to_dict()` for serialization to JSON

## Year 1 Roadmap (ALL DONE)
1. ~~Wire autofix_confidence into AutoFixEngine~~ DONE (2026-03-02)
2. ~~SHAP explanations for feature contributions~~ DONE (2026-03-02)
3. ~~Scan drift detection~~ DONE (2026-03-02)
4. ~~Scanner parser data quality validation~~ DONE (2026-03-02)
5. ~~Wire anomaly detection alerts to EventBus~~ DONE (2026-03-02)
6. ~~Wire parser quality validator to Brain Pipeline Step 2~~ DONE (2026-03-02)
7. ~~GNN for attack-path analysis (Step 5 enhancement)~~ DONE (2026-03-03)
8. ~~Online learning pipeline for model weight updates~~ DONE (2026-03-03)
