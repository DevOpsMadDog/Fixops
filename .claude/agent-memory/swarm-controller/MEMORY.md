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
- **Haiku model**: 100% success rate for test runs (16/16 in v5+v6). CHEAPEST option for all tasks.
- **Sonnet model**: 90% success rate (20/22 cumulative). Good for scoped tasks requiring more judgment.
- **Cost**: ~$0.06/task (haiku), ~$0.12/task (sonnet). 89% savings vs opus.
- **Kill threshold**: If junior shows no output after 5 min on test runs, kill immediately
- **Best pattern**: Dispatch all 8 juniors simultaneously with `run_in_background: true`
- **Coverage analysis juniors**: Excellent at finding root causes (swarm-514 found 15 stale paths in v6)

### Test Performance (Updated 2026-03-03 v7)
- Brain pipeline + AutoFix (4 files): 534 tests, ~23s
- Compliance + Analytics (3 files): 102 tests, ~6s
- Crypto (3 files): test_crypto_signing.py, test_crypto_unit.py, test_crypto.py (~2s)
- FAIL engine (3 files) + scanner_parsers (2 files): 516 tests, ~4s
- MPTE + MCP + Self-learning (6 files): 308 tests, ~9s
- Security connectors + Connectors (2 files): 202 tests, ~3s
- SBOM + risk (7 files): 268 tests, ~2s
- Config + EventBus + Webhooks + Feedback (5 files): 279 tests, ~11s
- CLI + Crypto (5 files): 187 tests, ~53s
- Security analyst persona (1 file): 109 tests (2 skip), ~66s (down from 122s!)
- LLM Consensus (2 files): 50 tests, ~3s
- KG + Hardening (4 files): 77 tests, ~13s
- API smoke: STILL extremely slow — DO NOT assign to juniors
- **FULL CORE SUITE**: 2,632 tests verified in v7 across 11 waves
- **Total collected**: 13,614 tests (up 393 from Day 2), 347 test files

### Known Issues (Updated 2026-03-03 v7)
- `core.cspm_analyzer` doesn't exist — correct module is `core.cspm_engine`
- Coverage at ~19.23% (gate: 25%, gap: 5.77pp) — ROOT CAUSE: 15 stale --cov paths in pyproject.toml
- Docker: POSTGRES_PASSWORD hardcoded in aldeci-complete.yml (non-prod, known)
- MPTE /verify endpoint times out at 30s (performance issue, not code bug)
- autofix_engine.py coverage only 55.80% — patch gen + fix application untested
- test_evidence_lifecycle.py does NOT exist — juniors will skip it silently
- Coverage juniors get STUCK on full pytest --cov (>2min) — do NOT assign
- 128 recently modified test files — too many for single junior exec loop
- **FIXED in v7**: CORS production guard (ENVIRONMENT=production requires FIXOPS_ALLOWED_ORIGINS)
- **FIXED in v6**: test_scanner_parsers.py sandbox router count 7→8
- **FIXED in v6**: brain_pipeline.py autofix observability when engine unavailable
- **FIXED in v5**: id_allocator hash() → hashlib.md5 (cross-process determinism)
- **FIXED in v5**: copilot_router.py mitre_techniques TypeError (List[Dict] join)
- **FIXED in v4**: ExploitabilityLevel.UNKNOWN (added to enum)
- **FIXED in v4**: CLI demo→showcase, load_overlay→prepare_overlay

### Coverage Deep Analysis (v6)
- brain_pipeline.py: 94.54% (excellent)
- fail_engine.py: 99.75% (outstanding)
- autofix_engine.py: 55.80% (needs work — patch gen + fix application untested)
- pyproject.toml has 15 NON-EXISTENT --cov paths (core, risk, automation, cli, etc.)
- These are pre-suite-fication package names that don't resolve
- Actual code is in suite-*/core, suite-*/api, etc.
- Removing stale paths would show true coverage (~5%) but gate needs adjustment

### Lint Status (Updated 2026-03-03 v7)
- **Total: 140 remaining** (133 E402 structural + 6 E741 ambiguous var + 1 F401 false positive)
- v7 fixed 27 additional errors (22 F401 + 5 F841 from new test files)
- v6 run 2 fixed 529 errors: 443 (ruff --fix) + 53 (tests --unsafe-fixes) + 33 (scripts --unsafe-fixes) + 6 (E702 manual) + 1 (E731 manual)
- The 133 E402 are ALL from sitecustomize.py sys.path injection — cannot be auto-fixed
- The 6 E741 are all `l` variable names in scripts/tools/tests — low priority
- The 1 F401 is `from cvss import CVSS3` used for availability check — false positive
- New test files regularly add F401/F841 — run ruff --fix at start of each session

### Security Audit (Updated v7)
- 0 HIGH bandit findings across 161K LOC (was 111K in v6 — scope expanded)
- 67 MEDIUM: B608 SQL formatting (8), B110 try-except-pass (296 — large increase)
- 471 LOW: informational (B105 hardcoded strings mostly FP, B603 subprocess safe)
- CORS production guard now enforced (ENVIRONMENT=production requires FIXOPS_ALLOWED_ORIGINS)

### API Surface
- 759 endpoints (7th consecutive stable scan)
- 21 key demo endpoints: ALL return 200 (verified with TestClient + FIXOPS_API_TOKEN)

### UI (Updated v7)
- 99 TS/TSX files, 41,806 LOC (up from 95/37K)
- TypeScript: 0 errors, Vite build: 2.11s, 204.81 KB index bundle (62.84 KB gzipped)

### Test File Naming (Correct Names — Updated 2026-03-02 v6)
- test_brain_pipeline.py, test_brain_pipeline_deep.py (NOT test_brain_pipeline_comprehensive.py)
- test_autofix_engine.py, test_autofix_engine_unit.py (NOT test_autofix_comprehensive.py)
- test_self_learning_unit.py, test_self_learning_demo.py (NOT test_self_learning.py)
- test_mcp_server_unit.py, test_mcp_autodiscovery.py (NOT test_mcp_server.py)
- test_micro_pentest_core.py, test_mpte_advanced_unit.py (NOT test_mpte_core.py)
- test_feedback.py (NOT test_feedback_loops.py)
- test_event_bus_unit.py (NOT test_event_bus.py)
- test_compliance_engine_unit.py (NOT test_compliance_engine.py or test_compliance_comprehensive.py)
- test_fail_engine.py, test_fail_engine_unit.py, test_fail_engine_comprehensive.py
- test_risk_scoring_unit.py, test_risk_scoring.py (NOT test_risk_scoring_ml_unit.py)
- test_webhooks_router_unit.py, test_webhooks_router_outbox.py (NOT test_webhooks.py)
- test_scanner_parsers_unit.py, test_scanner_parsers.py
- test_sbom_deterministic.py, test_sbom_generator_unit.py, test_sbom_quality.py
- test_comprehensive_sbom_generation.py, test_comprehensive_supply_chain_risk.py
- test_configuration_unit.py (NOT test_configuration.py)
- test_analytics_comprehensive.py (single file, 41 tests)
- test_crypto_signing.py, test_crypto_unit.py, test_crypto.py (NOT test_crypto_attestation.py)
- test_security_connectors_unit.py (NOT test_security_connectors.py)
- test_connectors_comprehensive.py (single file, includes all connector tests)
- test_security_analyst_persona.py (single file, 288+ tests with crypto)
- NON-EXISTENT (confirmed v6): test_branding_namespace.py, test_e2e_comprehensive.py, test_e2e_four_apps.py, test_integration_layer.py, test_compliance_comprehensive.py, test_brain_pipeline_comprehensive.py, test_autofix_comprehensive.py, test_crypto_attestation.py, test_ml_models_unit.py, test_sbom_api.py, test_scanner_integration.py, test_scanner_normalizer_unit.py, test_micro_pentest_cli_unit.py
