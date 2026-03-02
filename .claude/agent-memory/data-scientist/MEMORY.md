# Data Scientist Persistent Memory

## Key Patterns
- **Import mechanism**: `sitecustomize.py` auto-prepends suite paths. Use `from core.ml.risk_scorer import ...`
- **Golden dataset**: `data/golden_regression_cases.json` — 65 real CVE cases, 7 categories (v2.0.0)
- **ML models dir**: `.claude/team-state/data-science/models/`
- **Brain pipeline Step 6**: Uses ThreatEnricher (real EPSS/KEV) — NOT fake formula
- **Brain pipeline Step 7**: ML scorer integrated at `suite-core/core/brain_pipeline.py`
- **Feature importance**: asset_criticality (62.5%) >> epss_score (25.3%) >> network_exposure (6.4%) >> in_kev (2.3%)
- **Consensus weights**: claude=0.329, gpt4=0.334, gemini=0.338 (F1-weighted, updated 2026-03-02)
- **Risk model version**: v2.0.0 — GBT with 200 estimators, max_depth=4, lr=0.05, trained on 65 cases
- **AutoFix confidence model**: v1.0.0 — Random Forest, 200 trees, 10 features, 83.7% accuracy
- **AutoFix ML wired**: `_compute_confidence()` in autofix_engine.py uses ML model → fallback rule-based
- **CWE mapping**: `_cwe_to_category()` covers 20+ CWEs → 14 categories; fix-type fallback for unknown CWEs

## ML Module Index (6 modules, 3,233 LOC)
| Module | LOC | Purpose |
|--------|-----|---------|
| `risk_scorer.py` | 885 | GBT risk scoring (Step 7) |
| `anomaly_detector.py` | 486 | Isolation Forest scan anomaly detection |
| `consensus_calibrator.py` | 562 | Multi-LLM weight calibration (Step 9) |
| `threat_enricher.py` | 345 | Real EPSS/KEV/CVSS enrichment (Step 6) |
| `autofix_confidence.py` | 530 | AutoFix quality prediction |
| `daily_intel.py` | 425 | Daily threat intelligence collector |

## API Endpoints for Feeds
- EPSS: `https://api.first.org/data/v1/epss` — supports batch: `?cve=CVE-1,CVE-2` (max 30/batch)
- NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0` (live, sometimes slow ~10s)
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (1,529 entries)
- All three fetched successfully on 2026-03-02

## Test Patterns
- ML tests: `test_ml_risk_scorer.py` (42), `test_ml_anomaly_detector.py` (21), `test_ml_consensus_calibrator.py` (24), `test_ml_threat_enricher.py` (29), `test_ml_autofix_confidence.py` (38)
- Autofix engine tests: `test_autofix_engine_unit.py` (54, incl. 17 ML integration + CWE mapping)
- **Total: 154 ML tests + 73 brain pipeline + 54 autofix engine = 281 tests, ALL PASS in ~55s**
- Use `tempfile.mkdtemp()` for model_dir in tests to avoid side effects
- Brain pipeline tests expect real KEV behavior (synthetic CVEs → in_kev=False)
- Golden dataset assertions use `>=50` (not `==50`) since dataset grows

## EPSS Calibration (CRITICAL)
- **Old formula was WRONG**: `epss = min(cvss/10*0.6, 0.97)` massively overestimates
- **Correct medians** (from FIRST.org research): critical=0.25, high=0.10, medium=0.03, low=0.01
- EPSS and CVSS are only WEAKLY correlated — don't derive one from the other
- ThreatEnricher._estimate_epss_from_severity() uses calibrated medians as fallback

## Architecture Decisions
- GBT over LogisticRegression: need 0-100 continuous regression, not binary classification
- Bootstrap ensemble (20 models) for confidence intervals, not parametric CI
- Isolation Forest over DBSCAN: more robust for unknown distributions, no eps tuning
- F1-weighted calibration over grid search: faster, good enough for initial weights
- AutoFix confidence: Random Forest (not GBT) — fast, interpretable, works well for 10 features

## MCP Gateway (DEMO-009)
- **705 tools** auto-discovered via `suite-api/apps/api/mcp_router.py` (977 LOC)
- MCP auto-discovery is at `/api/v1/mcp/tools`, NOT `suite-integrations/api/mcp_router.py`
- **Rate limiter**: Set `FIXOPS_DISABLE_RATE_LIMIT=1` in tests
- Demo script: `scripts/mcp_gateway_demo.py` — supports `--self-contained` and `--json` modes

## Year 1 Roadmap (Next Steps)
1. ~~Wire autofix_confidence into AutoFixEngine~~ ✅ DONE (2026-03-02)
2. SHAP explanations for feature contributions (replace simple multiplication)
3. GNN for attack-path analysis (Step 7 enhancement)
4. Online learning pipeline for model weight updates from user feedback
5. Wire anomaly detection alerts to EventBus
