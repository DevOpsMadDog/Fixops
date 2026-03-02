# Data Scientist Persistent Memory

## Key Patterns
- **Import mechanism**: `sitecustomize.py` auto-prepends suite paths. Use `from core.ml.risk_scorer import ...`
- **Golden dataset**: `data/golden_regression_cases.json` — 85 real CVE cases, 7 categories (v3.1.0)
- **ML models dir**: `.claude/team-state/data-science/models/`
- **Brain pipeline Step 2**: ParserQualityValidator wired into `_step_normalize()` — quality metrics in step output
- **Brain pipeline Step 5**: GNN attack-path analysis wired into `_step_build_graph()` — attention hotspots in output
- **Brain pipeline Step 6**: Uses ThreatEnricher (real EPSS/KEV) — NOT fake formula
- **Brain pipeline Step 7**: ML scorer integrated + SHAP explanations at `suite-core/core/brain_pipeline.py`
- **Brain pipeline _emit_event**: Feeds results to trend analyzer automatically (since 2026-03-03)
- **Feature importance (v2.2.0)**: asset_criticality (78.5%) >> epss_score (14.1%) >> network_exposure (3.3%)
- **Consensus weights**: claude=0.329, gpt4=0.330, gemini=0.340 (F1=0.9081, stable since 2026-03-02)
- **Risk model version**: v2.2.0 — GBT with 200 estimators, max_depth=4, lr=0.05, trained on 85 cases
- **Priority thresholds (v2.2.0)**: P0>=82, P1>=56, P2>=30, P3>=8, P4>=5, FP<5
- **AutoFix confidence model**: v1.0.0 — Random Forest, 200 trees, 10 features, 83.7% accuracy
- **AutoFix ML wired**: `_compute_confidence()` in autofix_engine.py uses ML model -> fallback rule-based
- **CWE mapping**: `_cwe_to_category()` covers 20+ CWEs -> 14 categories; fix-type fallback for unknown CWEs
- **EventBus integration**: ML handlers auto-register via `register_all_subscribers()` in event_subscribers.py
- **Online learning**: Wired to DECISION_MADE + REMEDIATION_COMPLETED events → feedback buffer → retrain

## ML Module Index (12 modules, 8,058 LOC)
| Module | LOC | Purpose |
|--------|-----|---------|
| `risk_scorer.py` | 1,211 | GBT risk scoring + SHAP explanations (Step 7) |
| `online_learning.py` | 1,174 | User feedback → model retraining pipeline |
| `attack_path_gnn.py` | 922 | 2-layer GAT for attack-path analysis (Step 5) |
| `autofix_confidence.py` | 734 | AutoFix quality prediction |
| `anomaly_detector.py` | 709 | Isolation Forest + scan drift detection |
| `trend_analyzer.py` | 703 | Trend detection + posture scoring (NEW 2026-03-03) |
| `parser_quality.py` | 693 | Scanner parser data quality validator |
| `threat_enricher.py` | 602 | Real EPSS/KEV/CVSS enrichment (Step 6) |
| `consensus_calibrator.py` | 560 | Multi-LLM weight calibration (Step 9) |
| `daily_intel.py` | 423 | Daily threat intelligence collector |
| `eventbus_integration.py` | 294 | EventBus wiring for ML alerts |
| `__init__.py` | 33 | Module exports |

## Risk Model API
- Class: `RiskScoringModel` (NOT `RiskScorer`)
- Train: `scorer.train_from_golden_dataset('path/to/golden.json')` — takes PATH not list
- Predict: `scorer.predict(vuln_dict)` → `PredictionResult`
- Feature importance: `scorer.get_feature_importance()` (NOT `feature_importance()`)
- Metrics: `ModelMetrics` — has `.mae`, `.r2`, `.within_range_pct`, `.f1_by_priority`, `.cv_scores`
- No `mean_confidence_width` on ModelMetrics — get CI width from individual PredictionResult

## Trend Analyzer (NEW 2026-03-03)
- 4 detectors: severity_drift, cwe_emergence, recurrence, volume
- Posture scoring: 0-100 with trend direction (improving/degrading/stable)
- ScanHistoryStore: bounded in-memory store with optional JSON persistence
- API endpoint: `/api/v1/brain/trends` (GET, optional org_id/app_id query params)
- Wired to brain pipeline `_emit_event()` — auto-feeds scan results
- Zero-std edge case: ratio-based spike/drop detection when all previous scans identical

## API Endpoints for Feeds
- EPSS: `https://api.first.org/data/v1/epss` — supports batch: `?cve=CVE-1,CVE-2` (max 30/batch)
- NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0` (live, sometimes slow ~10s)
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (1,529 entries)
- All three fetched successfully on 2026-03-03

## Test Patterns
- ML tests: risk_scorer(42), anomaly_detector(21), consensus_calibrator(24), threat_enricher(29), autofix_confidence(38), shap(36), drift(21), parser_quality(16), eventbus(30), online_learning(47), attack_path_gnn(38), **trend_analyzer(33)**
- MCP demo: 22, autofix engine: 54, brain pipeline: 73
- **ML-only tests: 375 PASS** (was 365, +33 trend_analyzer)
- **Total incl. MCP+autofix+brain: 547 tests, ALL PASS** (was 514, +33)
- Use `tempfile.mkdtemp()` for model_dir in tests to avoid side effects
- Golden dataset assertions use `>=50` (not `==50`) since dataset grows
- **Priority threshold tests**: Must match risk_scorer.py thresholds — update BOTH when changing
- **EventBus tests**: Reset both EventBus singleton AND ML handler state before each test
- **Online learning tests**: Use `reset_pipeline()` before/after to avoid singleton leaks
- **Trend analyzer tests**: Reset `_default_analyzer = None` to avoid singleton leaks

## Priority Threshold Calibration (CRITICAL LESSON)
- **v1.0.0 -> v2.2.0**: P0: 85->82, P1: 60->56, P2: 35->30, P3: 15->8
- Priority mismatches are usually threshold issues, NOT model accuracy problems
- When recalibrating: find boundary scores, pick thresholds between adjacent priorities
- **P4/FP boundary lesson**: Score ~5 boundary is narrow. Low-criticality vulns with no exploit → model correctly classifies as FP even if CVSS is high

## Architecture Decisions
- GBT over LogisticRegression: need 0-100 continuous regression, not binary classification
- Bootstrap ensemble (20 models) for confidence intervals, not parametric CI
- Isolation Forest over DBSCAN: more robust for unknown distributions, no eps tuning
- Interventional SHAP over shap library: V9 air-gap compatible, no heavy dependencies
- Parser quality: per-category baselines from industry data, not per-scanner
- EventBus ML handlers: defensive/non-blocking — failures logged but don't crash pipeline
- GNN: pure numpy GAT over PyTorch Geometric: V9 compliance, <10K node graphs, deterministic
- Online learning: warm-start GBT over full retrain: preserves existing knowledge, faster convergence
- Trend analyzer: pure numpy linear regression + z-score — no heavy time-series libraries needed

## MCP Gateway (DEMO-009)
- **757 tools** auto-discovered via `suite-api/apps/api/mcp_router.py` (977 LOC)
- **Rate limiter**: Set `FIXOPS_DISABLE_RATE_LIMIT=1` in tests
- Demo script: `scripts/mcp_gateway_demo.py` — supports `--self-contained` and `--json` modes

## Consensus Calibrator API
- `CalibrationResult` has `.model_evaluations` (NOT `.model_performance`)
- `calibrate_from_golden_dataset('path')` — takes PATH not list
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
9. ~~Vulnerability trend analysis + posture scoring~~ DONE (2026-03-03)
