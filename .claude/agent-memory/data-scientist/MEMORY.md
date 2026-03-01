# Data Scientist Persistent Memory

## Key Patterns
- **Import mechanism**: `sitecustomize.py` auto-prepends suite paths. Use `from core.ml.risk_scorer import ...`
- **Golden dataset**: `data/golden_regression_cases.json` — 50 real CVE cases, 7 categories
- **ML models dir**: `.claude/team-state/data-science/models/`
- **Brain pipeline Step 7**: ML scorer integrated at `suite-core/core/brain_pipeline.py:544`
- **Feature importance**: asset_criticality (57.2%) >> epss_score (18.7%) >> network_exposure (14.4%) >> cvss_score (0.9%)
- **Consensus weights**: gpt4=0.339, gemini=0.334, claude=0.328 (F1-weighted calibration)
- **Model version**: 1.0.0 — GBT with 200 estimators, max_depth=4, lr=0.05

## API Endpoints for Feeds
- EPSS: `https://api.first.org/data/v1/epss` (live, fast)
- NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0` (live, slow ~10s)
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (live)
- All three fetched successfully on 2026-02-27

## Test Patterns
- ML tests: `tests/test_ml_risk_scorer.py` (42), `test_ml_anomaly_detector.py` (21), `test_ml_consensus_calibrator.py` (24)
- All 87 tests pass in ~19s
- Use `tempfile.mkdtemp()` for model_dir in tests to avoid side effects

## Architecture Decisions
- GBT over LogisticRegression: need 0-100 continuous regression, not binary classification
- Bootstrap ensemble (20 models) for confidence intervals, not parametric CI
- Isolation Forest over DBSCAN: more robust for unknown distributions, no eps tuning
- F1-weighted calibration over grid search: faster, good enough for initial weights

## MCP Gateway (DEMO-009)
- **705 tools** auto-discovered via `suite-api/apps/api/mcp_router.py` (977 LOC)
- Auto-discovery router introspects ALL FastAPI routes at startup (~21ms)
- Categories: 320 query, 279 action, 106 analysis; 72 unique tags
- MCP auto-discovery is at `/api/v1/mcp/tools`, NOT `suite-integrations/api/mcp_router.py` (that's legacy 8 tools)
- **Rate limiter**: Set `FIXOPS_DISABLE_RATE_LIMIT=1` in tests, or tests hit 429 after ~15 requests
- **TestClient + startup**: Use `with TestClient(app) as c:` context manager to trigger startup events
- Demo script: `scripts/mcp_gateway_demo.py` — supports `--self-contained` (TestClient) and `--json` modes
- Tests: `tests/test_mcp_gateway_demo.py` — 22 tests covering discovery, JSON-RPC, execution, schemas, E2E
- Brain pipeline via MCP: execute "run_pipeline" tool with findings + assets → 9/12 steps run (3 optional)

## Year 1 Roadmap (Next Steps)
1. GNN for attack-path analysis (Step 7 enhancement)
2. Live threat feed wiring (Step 6 enhancement)
3. AutoFix confidence estimator
4. Online learning for model updates
5. SHAP explanations for feature contributions
