# Swarm Controller Memory

## Key Patterns

### Task Decomposition
- Senior agent status files are sparse — extract work from `decisions.log` instead
- Read-only tasks (tests, lint, audit) are CHEAPER to run directly than spawning juniors
- 8 tasks per wave is optimal for this codebase (avoids resource contention)
- Lint auto-fixes (ruff --fix) should ALWAYS be done by controller directly — no judgment needed
- E2E test fixes require understanding test expectations — juniors fail at this (1/1 failure)
- CLI test fixes are CONTROLLER work — juniors can diagnose but can't fix cross-module issues

### Junior Worker Effectiveness
- **Good for**: Test runs, lint fixes requiring judgment, import path fixes, mock path fixes
- **Bad for**: Complex test failure analysis, extremely slow tests (API smoke), copilot bugs, cross-module fixes
- **Haiku model**: 100% success rate for test runs (8/8 in v5). CHEAPEST option for verification tasks.
- **Sonnet model**: 90% success rate (20/22 cumulative). Good for scoped tasks requiring more judgment.
- **Cost**: ~$0.06/task (haiku), ~$0.12/task (sonnet). 88% savings vs opus for test runs.
- **Kill threshold**: If junior shows no output after 5 min on test runs, kill immediately
- **Best pattern**: Dispatch all 8 juniors simultaneously with `run_in_background: true`

### Test Performance (Updated 2026-03-02 v5)
- Brain pipeline + AutoFix: 377 tests, ~13s
- Compliance engine: 42+ tests, ~11s (file: test_compliance_*.py, NOT test_compliance_comprehensive.py)
- Crypto: test_crypto_signing.py, test_crypto_unit.py, test_crypto.py (NOT test_crypto_attestation.py)
- FAIL engine (3 files): 516 tests, ~0.64s (extremely fast)
- MPTE + MCP + Self-learning: 308 tests, ~5.2s
- Scanner parsers (2 files): 142 tests included in FAIL count
- Security connectors + Connectors: 202 tests, ~0.5s
- Analytics: 41 tests, ~2.88s (NOT 124 — was overcounting)
- SBOM + risk (7 files): 268 tests, ~0.76s
- Config + EventBus + Webhooks + Feedback: 279 tests, ~5.31s
- Security analyst persona: 109 tests (2 skip), ~89s (needs 120s timeout)
- CLI: 4/4 pass, ~12s (test count reduced from 12)
- CLI stage-run: 4/4 pass, ~1.5s (ALL PASS after v5 fix!)
- API smoke: STILL extremely slow — DO NOT assign to juniors

### Known Issues (Updated 2026-03-02 v5)
- `core.cspm_analyzer` doesn't exist — correct module is `core.cspm_engine`
- Coverage at ~19.25% (gate: 25%, gap: 5.75pp) — config issue, DEMO-006
- Docker: POSTGRES_PASSWORD hardcoded in aldeci-complete.yml (non-prod, known)
- MPTE /verify endpoint times out at 30s (performance issue, not code bug)
- **FIXED in v5**: id_allocator hash() → hashlib.md5 (cross-process determinism)
- **FIXED in v5**: copilot_router.py mitre_techniques TypeError (List[Dict] join)
- **FIXED in v4**: ExploitabilityLevel.UNKNOWN (added to enum)
- **FIXED in v4**: CLI demo→showcase, load_overlay→prepare_overlay

### Lint Status (Updated 2026-03-02 v3)
- **Total: 93 remaining** (ALL are E402 = structural, can't auto-fix)

### API Surface
- 766 routes, 77 `/api/v1/` prefixes, 683 OpenAPI paths
- Top: copilot (46), feeds (31), brain (31), webhooks (25)

### UI
- 81 TSX files, 5 TS files, 30,581 LOC, 59 pages, 19 components
- TypeScript: 0 errors, Vite build: 1.63s, 534 KB bundle

### Test File Naming (Correct Names — Updated 2026-03-02 v5)
- test_self_learning_unit.py, test_self_learning_demo.py (NOT test_self_learning.py)
- test_mcp_server_unit.py, test_mcp_autodiscovery.py (NOT test_mcp_server.py)
- test_micro_pentest_core.py, test_mpte_advanced_unit.py (NOT test_mpte_core.py)
- test_feedback.py (NOT test_feedback_loops.py)
- test_event_bus_unit.py (NOT test_event_bus.py)
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
- NON-EXISTENT (confirmed v5): test_e2e_comprehensive.py, test_e2e_four_apps.py, test_integration_layer.py, test_compliance_comprehensive.py, test_crypto_attestation.py, test_ml_models_unit.py, test_sbom_api.py, test_scanner_integration.py, test_scanner_normalizer_unit.py, test_micro_pentest_cli_unit.py

### Enterprise Service Modules (Updated 2026-03-02 v5)
- `id_allocator.py` — ensure_ids(), allocate_run_id(), allocate_app_id() — NOW uses hashlib.md5
- `signing.py` — sign_manifest(), verify_manifest(), is_available()
- `run_registry.py` — RunRegistry with APP-ID/LATEST directory structure
- Continuation stages (build, test, deploy, operate, decision) reuse latest run for same APP-ID
- New-run stages: requirements, design
- CRITICAL: Python hash() is NOT deterministic across processes — always use hashlib
