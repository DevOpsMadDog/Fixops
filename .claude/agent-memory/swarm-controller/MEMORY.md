# Swarm Controller Memory

## Key Patterns

### Task Decomposition
- Senior agent status files are sparse — extract work from `decisions.log` instead
- Read-only tasks (tests, lint, audit) are CHEAPER to run directly than spawning juniors
- 8 tasks per wave is optimal for this codebase (avoids resource contention)
- Lint auto-fixes (ruff --fix) should ALWAYS be done by controller directly — no judgment needed
- E2E test fixes require understanding test expectations — juniors fail at this (1/1 failure)
- CLI test fixes are CONTROLLER work — juniors can diagnose but can't fix cross-module issues
- Analysis tasks (coverage, security audit, code debt) work GREAT for juniors — they write detailed reports

### Junior Worker Effectiveness
- **Good for**: Test runs, lint fixes, coverage analysis, security audits, code debt audits, report generation
- **Bad for**: Complex test failure analysis, extremely slow tests (API smoke), copilot bugs, cross-module fixes
- **Haiku model**: 100% success rate for test runs (29/29 in v5-v8). CHEAPEST option for all tasks.
- **Sonnet model**: 90% success rate (20/22 cumulative). Good for scoped tasks requiring more judgment.
- **Cost**: ~$0.06/task (haiku), ~$0.12/task (sonnet). 89% savings vs opus.
- **Kill threshold**: If junior shows no output after 5 min on test runs, kill immediately
- **Best pattern**: Dispatch all 8 juniors simultaneously with `run_in_background: true`
- **Coverage analysis juniors**: Excellent at finding root causes (swarm-514 found 15 stale paths in v6)
- **v8 achievement**: 100% junior completion rate (13/13) — no stuck juniors when avoiding coverage/large-exec tasks

### Test Performance (Updated 2026-03-03 v8)
- Brain pipeline + AutoFix (4 files): 534 tests, ~36s (up from 23s — test_brain_pipeline_optimization new)
- Compliance + Analytics + MicroPentest-Deep (3 files): 246 tests, ~19s
- Crypto (3 files): test_crypto_signing.py, test_crypto_unit.py, test_crypto.py (~2s)
- FAIL engine (3 files) + scanner_parsers (2 files): 516 tests, ~5s
- MPTE + MCP + Self-learning (6 files): 308 tests, ~19s
- Security connectors + Connectors (2 files): 202 tests, ~5s
- SBOM + risk (7 files): 268 tests, ~4.5s
- Config + EventBus + Webhooks + Feedback (5 files): 279 tests, ~19s
- CLI + Crypto (5 files): 187 tests, ~36s (was 53s in v7 — improved!)
- Security analyst persona (1 file): 109 tests (2 skip), ~75s
- LLM Consensus + Hardening (2 files): 71 tests, ~12s
- New tests (autofix-deep, jwt, brain-opt, sec-headers, hardening-0303): 232 tests, ~19s
- ML (GNN, online-learning, micro-pentest-deep): 249 tests, ~32s
- API smoke: STILL extremely slow — DO NOT assign to juniors
- **FULL SUITE v8**: 3,201 tests verified across 13 juniors in 2 waves
- **Total collected**: 13,862 tests, 353 test files, 183.8K test LOC

### Known Issues (Updated 2026-03-03 v8)
- `core.cspm_analyzer` doesn't exist — correct module is `core.cspm_engine`
- Coverage at ~19.22% (gate: 25%, gap: 5.78pp) — ROOT CAUSE: 15 stale --cov paths in pyproject.toml
- Docker: POSTGRES_PASSWORD hardcoded in aldeci-complete.yml (non-prod, known)
- MPTE /verify endpoint times out at 30s (performance issue, not code bug)
- test_evidence_lifecycle.py does NOT exist — juniors will skip it silently
- Coverage juniors get STUCK on full pytest --cov (>2min) — do NOT assign
- 4 test files referenced in Wave 2 group 2 don't exist: test_llm_consensus_deep, test_knowledge_graph_unit, test_hardening_comprehensive, test_hardening_unit
- **FIXED in v8**: test_brain_pipeline_deep.py dedup assertions (skipped → local_fallback)
- **FIXED in v7**: CORS production guard (ENVIRONMENT=production requires FIXOPS_ALLOWED_ORIGINS)
- **FIXED in v6**: test_scanner_parsers.py sandbox router count 7→8
- **FIXED in v6**: brain_pipeline.py autofix observability when engine unavailable
- **FIXED in v5**: id_allocator hash() → hashlib.md5 (cross-process determinism)
- **FIXED in v5**: copilot_router.py mitre_techniques TypeError (List[Dict] join)

### Lint Status (Updated 2026-03-03 v8)
- **Total: 140 remaining** (133 E402 structural + 6 E741 ambiguous var + 1 F401 false positive)
- v8 fixed 44 errors (30 F401 + 9 F541 + 6 F841 via --unsafe-fixes)
- v7 fixed 27 additional errors (22 F401 + 5 F841 from new test files)
- v6 run 2 fixed 529 errors
- The 133 E402 are ALL from sitecustomize.py sys.path injection — cannot be auto-fixed
- New test files regularly add F401/F841 — run ruff --fix at start of each session

### Security Audit (Updated v8)
- 0 HIGH bandit findings across 163K LOC (up from 161K in v7)
- 67 MEDIUM: B608 SQL formatting (34), B310 URL schemes (14), B108 temp files (11), B104 bind-all (5), others (3)
- CORS production guard now enforced

### API Surface (Updated v8)
- 781 routes (up from 768 in v7)
- 21 key demo endpoints: ALL return 200 (verified with TestClient + FIXOPS_API_TOKEN)

### UI (Updated v8)
- 101 TS/TSX files, 43,477 LOC (up from 99/41.8K in v7)
- TypeScript: 0 errors, Vite build: 2.32s, 209.28 KB index bundle (63.98 KB gzipped)

### Test File Naming (Correct Names — Updated 2026-03-03 v8)
- test_brain_pipeline.py, test_brain_pipeline_deep.py, test_brain_pipeline_optimization.py (NEW)
- test_autofix_engine.py, test_autofix_engine_unit.py, test_autofix_engine_deep.py (NEW)
- test_self_learning_unit.py, test_self_learning_demo.py
- test_mcp_server_unit.py, test_mcp_autodiscovery.py
- test_micro_pentest_core.py, test_mpte_advanced_unit.py, test_micro_pentest_deep.py (NEW)
- test_feedback.py, test_event_bus_unit.py
- test_compliance_engine_unit.py
- test_fail_engine.py, test_fail_engine_unit.py, test_fail_engine_comprehensive.py
- test_risk_scoring_unit.py, test_risk_scoring.py
- test_webhooks_router_unit.py, test_webhooks_router_outbox.py
- test_scanner_parsers_unit.py, test_scanner_parsers.py
- test_sbom_deterministic.py, test_sbom_generator_unit.py, test_sbom_quality.py
- test_comprehensive_sbom_generation.py, test_comprehensive_supply_chain_risk.py
- test_configuration_unit.py, test_analytics_comprehensive.py
- test_crypto_signing.py, test_crypto_unit.py, test_crypto.py
- test_security_connectors_unit.py, test_connectors_comprehensive.py
- test_security_analyst_persona.py
- test_jwt_hardening.py, test_security_headers.py, test_hardening_2026_03_03.py (ALL NEW v8)
- test_ml_attack_path_gnn.py, test_ml_online_learning.py (NEW)
- test_llm_consensus_unit.py, test_security_hardening_v2.py
- NON-EXISTENT (confirmed v8): test_llm_consensus_deep, test_knowledge_graph_unit, test_hardening_comprehensive, test_hardening_unit + all from v6 list

### Cumulative Stats (v1-v8)
- Total runs: 8
- Total juniors dispatched: 121
- Total tests verified: 21,795
- Total bugs fixed: 22
- Total lint errors fixed: 675
- Junior overall success rate: ~95%
