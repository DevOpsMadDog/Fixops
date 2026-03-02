# Swarm Controller Memory

## Key Patterns

### Task Decomposition
- Senior agent status files are sparse — extract work from `decisions.log` instead
- Read-only tasks (tests, lint, audit) are CHEAPER to run directly than spawning juniors
- 8 tasks per wave is optimal for this codebase (avoids resource contention)
- Lint auto-fixes (ruff --fix) should ALWAYS be done by controller directly — no judgment needed
- E2E test fixes require understanding test expectations — juniors fail at this (1/1 failure)

### Junior Worker Effectiveness
- **Good for**: Lint fixes requiring judgment (F841, E721), import path fixes, test runs
- **Bad for**: Complex test failure analysis (E2E failures), extremely slow tests (API smoke)
- **Sonnet model**: 75% success rate (6/8). Good for scoped, well-defined tasks.
- **Cost**: ~$0.06 per junior task (sonnet). 80% savings vs opus for simple tasks.
- **Kill threshold**: If junior shows no output after 5 min on test runs, kill immediately

### Test Performance (Updated 2026-03-02)
- Brain pipeline: 73 tests, ~25s (improved from 68s)
- AutoFix engine: 54 tests (was 37), ~9s
- Compliance engine: 42 tests, ~11s
- Crypto: 45 tests, ~5s
- Attestation: 24 tests, ~1.5s (fast)
- E2E comprehensive: 24 tests, ~33s (all pass after fixes)
- FAIL engine: 608 tests total (42+566), ~9s (extremely fast per test)
- MPTE all suites: 355 tests, ~50s
- MCP all suites: 135 tests, ~21s
- Self-learning: 73 tests, ~3s
- Scanner parsers: 38 tests, ~0.15s (lightning fast)
- API smoke: STILL extremely slow — DO NOT assign to juniors

### Known Issues (Updated 2026-03-02)
- `core.cspm_analyzer` doesn't exist — correct module is `core.cspm_engine`
- pyproject.toml coverage still at 19.11% (gate: 25%). Need QA to target uncovered suites.
- E2E edge-case failures: ALL FIXED (chunked=accept 400, size=accept 422, CLI=showcase, key=accept 200)
- Docker: POSTGRES_PASSWORD hardcoded in aldeci-complete.yml (non-prod, known)
- Postman collections use mixed URL variables: `{{apiBase}}` (81%) vs `{{base_url}}` (18%)
- MPTE /verify endpoint times out at 30s (performance issue, not code bug)
- test_cicd_signature.py: FIXED — created suite-core/api/v1/cicd.py

### Lint Status (Updated 2026-03-02)
- suite-core: 24 errors (was 99 — reduced 76%)
  - Remaining: 16 E402, 4 E701, 4 F401
- suite-api: 62 errors (was 76 — reduced 18%)
  - Remaining: 61 E402, 1 F401
- suite-attack: 1 error (was 3 — reduced 67%)
- suite-evidence-risk: 7 errors (was 9)
- suite-integrations: 10 errors (unchanged)
- **Total: 104 remaining** (77 are E402 = structural, can't auto-fix)

### API Surface
- 766 routes, 77 `/api/v1/` prefixes, 683 OpenAPI paths
- Top: copilot (46), feeds (31), brain (31), webhooks (25)
- V3=54, V5=42, V7=68 endpoints for active pillars

### UI
- 81 TSX files, 5 TS files, 30,581 LOC, 59 pages, 19 components
- TypeScript: 0 errors
- Vite build: 1.63s, 534 KB bundle

### Test File Naming (Correct Names)
- test_self_learning_unit.py, test_self_learning_demo.py (NOT test_self_learning.py)
- test_mcp_server_unit.py, test_mcp_autodiscovery.py (NOT test_mcp_server.py, test_mcp_e2e.py)
- test_micro_pentest_core.py, test_mpte_advanced_unit.py (NOT test_mpte_core.py)
- test_feedback.py (NOT test_feedback_loops.py)
