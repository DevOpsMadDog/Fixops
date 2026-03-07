# Data Scientist Persistent Memory

## Key Patterns
- **Import mechanism**: `sitecustomize.py` auto-prepends suite paths. Use `from core.ml.risk_scorer import ...`
- **Golden dataset**: `data/golden_regression_cases.json` — 93 real CVE cases, 7 categories (v3.2.1)
- **ML models dir**: `.claude/team-state/data-science/models/`
- **Brain pipeline Step 2**: ParserQualityValidator wired into `_step_normalize()`
- **Brain pipeline Step 5**: GNN attack-path analysis wired into `_step_build_graph()`
- **Brain pipeline Step 6**: Uses ThreatEnricher (real EPSS/KEV) — NOT fake formula
- **Brain pipeline Step 7**: ML scorer integrated + SHAP explanations
- **Brain pipeline _emit_event**: Feeds results to trend analyzer automatically
- **Feature importance (v2.3.0)**: asset_criticality (68.3%) >> exploit_maturity (10.6%) >> network_exposure (7.7%)
- **Consensus weights**: claude=0.330, gpt4=0.336, gemini=0.335 (F1=0.8467, updated 2026-03-07)
- **Risk model version**: v2.3.0 — GBT with 200 estimators, max_depth=4, lr=0.05, trained on 93 cases
- **Priority thresholds**: P0>=82, P1>=56, P2>=30, P3>=8, P4>=5, FP<5
- **AutoFix confidence model**: v1.0.0 — Random Forest, 200 trees, 10 features, 83.7% accuracy
- **AutoFix ML wired**: `_compute_confidence()` in autofix_engine.py uses ML model -> fallback
- **EventBus integration**: ML handlers auto-register via `register_all_subscribers()`
- **Online learning**: Wired to DECISION_MADE + REMEDIATION_COMPLETED events

## ML Module Index (13 modules, 8,791 LOC)
| Module | LOC | Purpose |
|--------|-----|---------|
| `risk_scorer.py` | 1,211 | GBT risk scoring + SHAP (Step 7) |
| `online_learning.py` | 1,174 | User feedback → model retraining |
| `attack_path_gnn.py` | 922 | 2-layer GAT (Step 5) |
| `predictive_scorer.py` | 733 | Pre-CVE risk prediction (Year 3) |
| `autofix_confidence.py` | 734 | AutoFix quality prediction |
| `anomaly_detector.py` | 709 | Isolation Forest + drift |
| `trend_analyzer.py` | 703 | Trend detection + posture |
| `parser_quality.py` | 693 | Parser data quality |
| `threat_enricher.py` | 602 | Real EPSS/KEV/CVSS (Step 6) |
| `consensus_calibrator.py` | 560 | Multi-LLM calibration (Step 9) |
| `daily_intel.py` | 423 | EPSS/NVD/KEV feeds |
| `eventbus_integration.py` | 294 | EventBus wiring |
| `__init__.py` | 33 | Module exports |

## Risk Model API
- Class: `RiskScoringModel` (NOT `RiskScorer`)
- Train: `scorer.train_from_golden_dataset('path/to/golden.json')` — takes PATH not list
- Predict: `scorer.predict(vuln_dict)` → `PredictionResult`
- Feature importance: `scorer.get_feature_importance()` (NOT `feature_importance()`)
- Metrics: `ModelMetrics` — `.mae`, `.r2`, `.within_range_pct`, `.f1_by_priority`, `.cv_scores`
- Version constant: `MODEL_VERSION` — must be updated when retraining

## Predictive Scorer API (NEW 2026-03-07)
- Class: `PredictiveScorer` — fits from golden dataset, predicts code pattern risk
- `predict_code_risk(pattern_dict)` → `PredictiveResult` (risk_score, exploit_prob, CI, similar_cves)
- `score_dependency_risk(dep_dict)` → `DependencyRiskResult`
- `compute_temporal_decay(initial_risk, days, ...)` → `TemporalDecay`
- `compute_similarity(vuln_a, vuln_b)` → float (0-1)
- 28 CWE profiles in `CWE_EXPLOIT_PROFILES` dict
- Singleton: `get_predictive_scorer()` — reset `_default_scorer = None` in tests

## API Endpoints for Feeds
- EPSS: `https://api.first.org/data/v1/epss` — batch: `?cve=CVE-1,CVE-2` (max 30/batch)
- NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0` — use pubStartDate/pubEndDate for recent
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (1,536 entries)
- All three fetched successfully on 2026-03-07

## Test Patterns
- ML tests: risk_scorer(42), anomaly_detector(21), consensus_calibrator(24), threat_enricher(29), autofix_confidence(38), shap(36), drift(21), parser_quality(16), eventbus(30), online_learning(47), attack_path_gnn(38), trend_analyzer(33), **predictive_scorer(59)**
- **ML-only tests: 457 PASS** (was 398, +59 predictive_scorer)
- Use `tempfile.mkdtemp()` for model_dir in tests
- Golden dataset assertions use `>=50` (not `==50`) since dataset grows
- **Singleton resets**: `_default_scorer = None` for predictive_scorer, trend_analyzer
- **SHAP test lesson**: Don't assert EPSS is 2nd strongest — feature importance shifts with EPSS updates

## EPSS Drift (CRITICAL LESSON 2026-03-07)
- Live EPSS scores can drift significantly from stored values
- CVE-2023-35078: 0.21→0.94 (350% drift!) — was never exploited, now high EPSS
- CVE-2023-38408: 0.06→0.67 (1014% drift!) — OpenSSH agent forwarding
- Run `?cve=CVE-X,CVE-Y` batch query to check multiple at once
- Always update golden dataset with live EPSS before retraining
- Feature importance WILL shift — don't hardcode expected SHAP contributions

## Architecture Decisions
- GBT over LogisticRegression: need 0-100 continuous regression
- Bootstrap ensemble (20 models) for confidence intervals
- Interventional SHAP over shap library: V9 air-gap compatible
- Predictive scorer: pure numpy, CWE profile database, no external ML dependencies
- Temporal decay: exponential model, zero decay for KEV/actively exploited

## MCP Gateway (DEMO-009)
- **759 tools** auto-discovered via `suite-api/apps/api/mcp_router.py` (977 LOC)
- **Rate limiter**: Set `FIXOPS_DISABLE_RATE_LIMIT=1` in tests
- Demo script: `scripts/mcp_gateway_demo.py` — `--self-contained` and `--json` modes
- Now includes predictive scoring showcase in Step 6

## Consensus Calibrator API
- `CalibrationResult` has `.model_evaluations` (NOT `.model_performance`)
- `.model_evaluations[name]` is `ModelEvaluation` dataclass (has `.f1`, `.precision`, `.recall`)
- `calibrate_from_golden_dataset('path')` — takes PATH not list
- Use `.to_dict()` for serialization

## Year 1 Roadmap (ALL DONE)
All 9 items completed by 2026-03-03.

## Year 3 Preview (DONE 2026-03-07)
- Predictive vulnerability scoring module LIVE (733 LOC, 59 tests)
