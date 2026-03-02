# Data Scientist Persistent Memory

## Key Patterns
- **Import mechanism**: `sitecustomize.py` auto-prepends suite paths. Use `from core.ml.risk_scorer import ...`
- **Golden dataset**: `data/golden_regression_cases.json` — 75 real CVE cases, 7 categories (v3.0.0)
- **ML models dir**: `.claude/team-state/data-science/models/`
- **Brain pipeline Step 6**: Uses ThreatEnricher (real EPSS/KEV) — NOT fake formula
- **Brain pipeline Step 7**: ML scorer integrated + SHAP explanations at `suite-core/core/brain_pipeline.py`
- **Feature importance**: asset_criticality (59.4%) >> epss_score (31.5%) >> network_exposure (3.2%)
- **Consensus weights**: claude=0.329, gpt4=0.330, gemini=0.340 (F1=0.9081, updated 2026-03-02)
- **Risk model version**: v2.1.0 — GBT with 200 estimators, max_depth=4, lr=0.05, trained on 75 cases
- **Priority thresholds (v2.1.0)**: P0≥82, P1≥56, P2≥30, P3≥8, P4≥5, FP<5
- **AutoFix confidence model**: v1.0.0 — Random Forest, 200 trees, 10 features, 83.7% accuracy
- **AutoFix ML wired**: `_compute_confidence()` in autofix_engine.py uses ML model → fallback rule-based
- **CWE mapping**: `_cwe_to_category()` covers 20+ CWEs → 14 categories; fix-type fallback for unknown CWEs

## ML Module Index (7 modules, 4,932 LOC)
| Module | LOC | Purpose |
|--------|-----|---------|
| `risk_scorer.py` | 1,211 | GBT risk scoring + SHAP explanations (Step 7) |
| `anomaly_detector.py` | 709 | Isolation Forest + scan drift detection |
| `consensus_calibrator.py` | 560 | Multi-LLM weight calibration (Step 9) |
| `threat_enricher.py` | 602 | Real EPSS/KEV/CVSS enrichment (Step 6) |
| `autofix_confidence.py` | 734 | AutoFix quality prediction |
| `daily_intel.py` | 423 | Daily threat intelligence collector |
| `parser_quality.py` | 693 | Scanner parser data quality validator |

## API Endpoints for Feeds
- EPSS: `https://api.first.org/data/v1/epss` — supports batch: `?cve=CVE-1,CVE-2` (max 30/batch)
- NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0` (live, sometimes slow ~10s)
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (1,529 entries)
- All three fetched successfully on 2026-03-02

## Test Patterns
- ML tests: `test_ml_risk_scorer.py` (42), `test_ml_anomaly_detector.py` (21), `test_ml_consensus_calibrator.py` (24), `test_ml_threat_enricher.py` (29), `test_ml_autofix_confidence.py` (38), `test_ml_shap_explanations.py` (36), `test_ml_drift_detection.py` (21), `test_ml_parser_quality.py` (16)
- Autofix engine tests: `test_autofix_engine_unit.py` (54, incl. 17 ML integration + CWE mapping)
- **Total: 227 ML tests + 73 brain pipeline + 54 autofix = 354 tests, ALL PASS in ~60s**
- Use `tempfile.mkdtemp()` for model_dir in tests to avoid side effects
- Brain pipeline tests expect real KEV behavior (synthetic CVEs → in_kev=False)
- Golden dataset assertions use `>=50` (not `==50`) since dataset grows
- **Priority threshold tests**: Must match risk_scorer.py thresholds — update BOTH when changing

## Priority Threshold Calibration (CRITICAL LESSON)
- **v1.0.0 → v2.1.0**: P0: 85→82, P1: 60→56, P2: 35→30, P3: 15→8
- Priority mismatches are usually threshold issues, NOT model accuracy problems
- When recalibrating: find boundary scores, pick thresholds between adjacent priorities

## SHAP Explanations (2026-03-02 — NEW)
- `explain_prediction(vuln)` → `ExplanationResult` with per-feature contributions
- `predict()` now uses interventional contributions (not naive features[i]*importance[i])
- Interventional method: replace each feature with mean (0 in scaled space), measure prediction change
- NOT exact SHAP (no shap library) but equivalent to TreeSHAP interventional for GBT
- Brain pipeline Step 7 attaches `risk_explanation` (narrative + top_drivers) and `risk_feature_contributions` to findings
- `_generate_feature_explanation()`: use `_fmt_float()` helper — raw_value may be str, bool, or float
- 36 tests in test_ml_shap_explanations.py

## Scan Drift Detection (2026-03-02 — NEW)
- `detect_drift(current_findings, previous_findings)` → `DriftResult`
- Identity-based diff: cve_id|location or title|location|severity
- Detects: regression, improvement, stable, shift
- Tracks: new_findings_count, resolved_findings_count, severity_changes, feature_deltas
- 21 tests in test_ml_drift_detection.py

## Parser Quality Validator (2026-03-02 — NEW)
- `ParserQualityValidator.validate_findings(findings, scanner_type)` → `ParserQualityResult`
- 6 checks: required fields, severity values, distribution baselines, CVE/CWE format, completeness, dedup readiness
- Scanner categories: sast (bandit, checkmarx, sonarqube, fortify, veracode), dast (zap, burp, nikto, nuclei), sca (snyk), infrastructure (nessus, openvas, nmap, prowler, checkov)
- Quality score 0-100: -10 per error, -3 per warning, +10 completeness bonus, +5 CVE, +5 CWE
- 16 tests in test_ml_parser_quality.py

## Brain Pipeline StepResult API
- `StepResult.output` is `Dict[str, Any]` — NOT `.result`
- `PipelineResult.steps` is list of `StepResult` (NOT `.step_results`)
- Step 7 output: `{"avg_risk_score", "critical_count", "scored", "model", "avg_confidence_width"}`
- Context findings NOT exposed via to_dict() — SHAP data is in pipeline internal context only

## Architecture Decisions
- GBT over LogisticRegression: need 0-100 continuous regression, not binary classification
- Bootstrap ensemble (20 models) for confidence intervals, not parametric CI
- Isolation Forest over DBSCAN: more robust for unknown distributions, no eps tuning
- Interventional SHAP over shap library: V9 air-gap compatible, no heavy dependencies
- Parser quality: per-category baselines from industry data, not per-scanner

## MCP Gateway (DEMO-009)
- **705 tools** auto-discovered via `suite-api/apps/api/mcp_router.py` (977 LOC)
- MCP auto-discovery is at `/api/v1/mcp/tools`, NOT `suite-integrations/api/mcp_router.py`
- **Rate limiter**: Set `FIXOPS_DISABLE_RATE_LIMIT=1` in tests
- Demo script: `scripts/mcp_gateway_demo.py` — supports `--self-contained` and `--json` modes

## Year 1 Roadmap (Next Steps)
1. ~~Wire autofix_confidence into AutoFixEngine~~ DONE (2026-03-02)
2. ~~SHAP explanations for feature contributions~~ DONE (2026-03-02)
3. ~~Scan drift detection~~ DONE (2026-03-02)
4. ~~Scanner parser data quality validation~~ DONE (2026-03-02)
5. GNN for attack-path analysis (Step 7 enhancement)
6. Online learning pipeline for model weight updates from user feedback
7. Wire anomaly detection alerts to EventBus
8. Wire parser quality validator to Brain Pipeline Step 2 (normalize)
