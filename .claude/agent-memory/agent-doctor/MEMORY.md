# Agent-Doctor Persistent Memory

## Critical Patterns

### macOS Agent Launch (9 Root Causes — ALL RESOLVED as of run19)
When launching claude CLI as child processes on macOS:
1. **gtimeout not timeout** — macOS lacks GNU timeout. Use `brew install coreutils` → `gtimeout`
2. **stdin must be /dev/null** — Background claude gets SIGTTIN if stdin→terminal → STOPPED → killed by watchdog → 0-byte output. Fix: Perl setsid wrapper with `POSIX::setsid()` + `open(STDIN, "<", "/dev/null")`
3. **unset CLAUDECODE** — If run from inside Claude Code, `CLAUDECODE=1` blocks child invocations. Unset in self_heal + every subshell
4. **--agent flag required** — Without `--agent "$name"`, claude CLI ignores .md frontmatter (model, maxTurns, permissions)
5. **Prompt size cap** — SCP context + retries accumulate. Cap at 50KB. Clean stale `.prompt.tmp` files
6. **False failure detection (RC6)** — `claude --agent` mode works via tool calls (Read/Write/Edit/Bash) producing 0-byte stdout. Script must use multi-signal detection: exit code + status file recency + git changes. Fixed at line 3901+.

### Script Locations
- Swarm script: `scripts/run-ctem-swarm.sh` (6,499 LOC)
- Agent configs: `.claude/agents/{name}.md` (17 files including vision-agent)
- State: `.claude/team-state/`
- Logs: `logs/ai-team/`

### Sprint 2 Pre-Flight (run24→run35, 2026-03-01→03)
- Enterprise demo in 3 days (2026-03-06). Sprint 2: 11/12 done (91.7%), 1 P0 blocker (DEMO-003 UI wiring).
- **Run35 (latest)**: 16/17 Grade A, 1 Grade C (sales-engineer rate-limited). 19/19 engines (21,000 LOC). 4/4 MOATs. 56/56 DBs integrity OK. 321 core tests (32.97s). 13,816 total (+142 since run34). GREEN.
- **Run35**: 7 WAL files (9.5MB) checkpointed via TRUNCATE + cleaned. fixops_brain.db HEALTHY (612 pages, 4 tables) — no corruption since run34 recovery.
- **Run34 CLEANUP**: QA directory 971MB → 228MB (freed 743MB). Team state 998MB → 255MB.
- **fixops_brain.db**: Corruption was RECURRING (run28, run31+, run33, run34) but STABLE since run34 recovery. suite-api/data/fixops_brain.db is now EMPTY (2 pages, 0 tables) — NOT a viable backup anymore. Primary at data/fixops_brain.db is the only copy (612 pages).
- Lock files: jarvis.pid, jarvis.lock, controller-watchdog.pid — ALWAYS check if PIDs alive before cleaning
- SA-001: .env secrets rotation CRITICAL (7 days open, .gitignore fix applied, key rotation pending)
- SA-002: Docker hardening PARTIALLY RESOLVED (credentials fixed, socket mount accepted risk)

### CTEM+ Engine Inventory (verified 2026-03-03 run34)
- 6 scanner engines: sast (1622), dast (633), secrets (848), container (445), iac (713), cspm (609) = 4,870 LOC
- Brain pipeline: `brain_pipeline.py` (1,663 LOC, 12 steps via _step_* methods, has `run()` method) — growing since run15
- MPTE: mpte_advanced.py (1,089, AdvancedMPTEClient), mpte_db.py (536, MPTEDB), mpte_models.py (141, PenTestConfig/Request/Result), micro_pentest.py (2,054, run_micro_pentest) = 3,820 LOC
- AutoFix: `autofix_engine.py` (1,515 LOC, AutoFixEngine, 8 public methods)
- FAIL Engine: `fail_engine.py` (711 LOC, FAILEngine, 8 public methods)
- Connectors: `connectors.py` (3,005 LOC, AutomationConnectors) + `universal_connector.py` (1,637 LOC)
- MCP: `mcp_server.py` (979 LOC, MCPProtocolHandler NOT MCPServer) + `mcp_router.py` (468 in suite-integrations)
- 6 vision engines: falkordb_client (835, KnowledgeGraphEngine), single_agent (818, SingleAgentEngine), quantum_crypto (664, HybridQuantumSigner), mcp_server (978, MCPProtocolHandler), self_learning (1359, SelfLearningEngine), zero_gravity (855, ZeroGravityEngine) = 5,509 LOC
- **Module names (NOT _engine suffix)**: `core.single_agent`, `core.self_learning`, `core.zero_gravity` — NOT `core.single_agent_engine` etc.
- Crypto: `crypto.py` (582 LOC, RSAKeyManager/RSASigner/RSAVerifier — NOT CryptoEngine)
- Total 19 engines verified importable: 6 scanner + 6 vision + 7 core = 21,000 LOC (was 18,160 at Sprint 1 end)
- CTEM_PLUS_IDENTITY.md says `cspm_analyzer.py` but actual is `cspm_engine.py`

### Test-Code Drift Pattern (RC7 — resolved run9)
- `micro_pentest.py` was refactored to fall back to built-in scanner on MPTE errors
- 5 tests in `test_micro_pentest_core.py` still expected old error behavior
- Fix: mock `_run_builtin_vulnerability_scan` in tests that expect error paths
- Also: default URL changed from `http://` to `https://mpte:8443`
- Lesson: after any engine refactor, check corresponding test expectations

### Broken Test Files (RC8 — resolved run11)
- `tests/test_micro_pentest_engine.py` imported from `core.services.enterprise.micro_pentest_engine` which doesn't exist. Stale fixops-enterprise code.
- Fix: renamed to `.broken` suffix (run11). Eliminated collection error, +198 tests collected.
- NOTE: `FAILEngine` is the class name (not `FAILScorer`). `micro_pentest` uses functions (`run_micro_pentest`, `run_batch_micro_pentests`) not a class.

### Agent Config Rules
- All 17 agents must have: name, model, maxTurns in YAML frontmatter
- All must reference CTEM and CTEM_PLUS_IDENTITY
- Scanner-facing agents (backend-hardener, security-analyst, qa-engineer, threat-architect) must reference scanner engines
- Never downgrade model tier. Never delete agent files.

### Claude Usage Quota Failures (RC11 — identified run31)
- When Claude usage cap is hit, agents get: "You're out of extra usage · resets 7pm (Australia/Sydney)"
- Produces 59-byte log files. Status shows "Failed (3 attempts exhausted)".
- This is NOT a config failure — diagnosis: "rate-limited", grade C (not F).
- Fix: auto-recovers when usage resets. No config change needed.
- Differentiate from real failures by reading log content (usage message vs error stack)
- Run31: affected context-engineer + vision-agent. Both had successful earlier runs same day.

### Watchdog Behavior
- SIGCONT only — never kill working agents
- Check for stopped processes (state T) and resume them
- Located in controller_start_watchdog() around line 2240

### Lock Files
- `.claude/team-state/jarvis.lock` + `jarvis.pid` — check if PID alive before cleaning
- `.claude/team-state/.controller-watchdog.pid` — active if swarm running

### Worktrees
- Empty worktrees (0 changes) should be cleaned with `git worktree remove --force` + `git branch -D`
- Each worktree ~54MB. 4 worktrees = 217MB wasted if unused.
- Path: `.claude/worktrees/agent-{hash}/`

### Status File Staleness
- Status files reference specific run IDs (e.g., `swarm-2026-02-27_13-02-15`)
- If current run is different, old status files are STALE — F grades don't mean current failure
- Always compare status file run ID against current active run before diagnosing

### Shell Compatibility
- Use `bash -c '...'` wrapper for scripts with `[[ ]]` syntax — zsh parses `[[ ! ]]` differently
- Or use `[ ]` (POSIX) instead of `[[ ]]` (bash)

### Sprint Artifacts (as of 2026-03-03 run35)
- Sprint 1 ARCHIVED: 21/23 done (91.3%)
- Sprint 2 ACTIVE: 11/12 done (91.7%). 1 P0 blocker: DEMO-003 (UI wiring). 3 days to demo.
- 13,816 tests collected (+142 since run34), 321 core tests passing (32.97s, 6 files)
- Coverage: 19.23% (gate: 25% — FAILING, not demo blocker)
- 21,000 LOC across 19 engines (+2,840 from Sprint 1)
- WAL trend: 2.5GB (run28) → 0KB (run33-34) → 9.5MB (run35, cleaned) — STABLE
- SA-001: .env secrets rotation CRITICAL (7 days open, .gitignore fix applied, key rotation pending)
- SA-002: Docker hardening PARTIALLY RESOLVED (1 day old)

### Core Test Files (verified run v6 — 948 tests, ~68s)
- test_brain_pipeline.py (159 tests)
- test_autofix_engine_unit.py (64 tests)
- test_fail_engine.py + test_fail_engine_unit.py + test_fail_engine_comprehensive.py (183 tests)
- test_micro_pentest_core.py + test_micro_pentest_core_unit.py (67 tests)
- test_iac_scanner.py (189 tests)
- test_secrets_scanner.py (59 tests)
- test_event_bus_unit.py (38 tests) — NEW run v6
- test_mpte_models_unit.py (37 tests) — NEW run v6
- test_decision_policy_unit.py (33 tests) — NEW run v6
- test_context_engine_unit.py (40 tests) — NEW run v6
- test_llm_providers_unit.py (42 tests) — NEW run v6
- test_exposure_case_unit.py (37 tests) — NEW run v6

### Scanner Module Export Names (verified run17)
- container_scanner.py exports `ContainerImageScanner` not `ContainerScanner`
- sast_engine.py: class `SASTEngine` exists but check actual exports with `dir()`
- mcp_server.py: exports `MCPProtocolHandler`, `MCPToolRegistry`, `MCPSessionManager` — NOT `MCPServer`
- crypto.py: exports `RSAKeyManager`, `RSASigner`, `RSAVerifier` — NOT `CryptoEngine`
- mpte_advanced.py: exports `AdvancedMPTEClient`, `MultiAIOrchestrator` — NOT `AdvancedMPTE`
- mpte_models.py: exports `PenTestConfig`, `PenTestRequest`, `PenTestResult` — NOT `MPTETarget`
- Always use `import core.module_name` pattern, not `from core.module_name import ClassName`

### Healthy Agents (verified run35 — 2026-03-03)
- 16/17 Grade A, 1 Grade C (sales-engineer rate-limited). Health: GREEN.
- Run35: 19/19 engines (21,000 LOC). 4/4 MOATs. 56/56 DBs integrity OK. 321 core tests (32.97s). 13,816 total.
- Run35: 7 WAL (9.5MB) checkpointed+cleaned. fixops_brain.db HEALTHY (612 pages, no corruption).
- IMPORTANT: suite-api/data/fixops_brain.db is now EMPTY (2 pages, 0 tables) — no longer usable as backup.
- Crypto MOAT4: RSASigner.sign(data) returns (bytes, str) tuple = (512-byte signature, SHA256 fingerprint). RSAKeyManager has NO generate_keys method — keys auto-generated on init.

### Coverage Acceleration Strategy (updated run v8)
- **v6 strategy** (suite-core modules): diminishing returns — tests hit already-covered code
- **v8 strategy** (suite-evidence-risk): BREAKTHROUGH — 0% baseline meant every test adds coverage
- Best ROI: target suites with 0% baseline coverage and high LOC
- v8 targets: risk/scoring.py (466 LOC, 55 tests, 91.8% file coverage), compliance_engine.py (829 LOC, 49 tests), cloud.py (864 LOC, 24 tests)
- 2,159 LOC covered by 128 tests = 16.9 LOC/test ratio
- Next targets: suite-evidence-risk/risk/reachability/ (2,100+ LOC), suite-feeds/feeds_service.py (3,042 LOC), suite-integrations/api/ (2,000+ LOC)
- Coverage trend: v1: 16.99%, v4: 17.15%, v5: 17.47%, v6-v10: 17.99% (PLATEAU confirmed by context-engineer, prior 19.27% was narrower scope)
- **Key insight**: Target uncovered SUITES not uncovered MODULES within covered suites
- v10 targets: feeds_service.py (3,042 LOC, 77 tests), code_analysis.py (553 LOC, 26 tests)
- **Coverage measurement note**: context-engineer v18 authoritatively corrected 19.27% → 17.99% (agent-doctor was using narrower --cov scope). Always use full `--cov=.` for official numbers.

### FeedsService Dataclass Field Names (learned run v10)
- SupplyChainVuln: `vuln_id` (NOT cve_id), `ecosystem`, `package_name`, `affected_versions` (NOT package_version), `patched_versions` (NOT fixed_version)
- CloudSecurityBulletin: `remediation` (NOT mitigation), `url` (NOT advisory_url)
- EarlySignal: `signal_type` positional, `cve_id` (optional), `severity_estimate` (NOT severity), `confidence` is string not float
- NationalCERTAdvisory: requires `country` field, `url` (NOT advisory_url)
- GeoWeightedRisk: `base_score` (NOT base_risk), `geo_scores` dict, `cert_mentions` dict (NOT weighted_risk/region/factors)
- FeedRefreshResult: `records_updated` (NOT records_added), `error` (NOT error_message), NO duration_seconds field

### PenTestConfig Constructor (learned run21)
- PenTestConfig requires `id` and `name` positional args: `PenTestConfig(id="...", name="...", mpte_url="...")`
- Other fields have defaults: api_key=None, enabled=True, max_concurrent_tests=5, timeout_seconds=300

### mpte_advanced.py Fallback Behavior (learned run21)
- When `_call_llm` fails and `fallback_enabled=True`, it returns valid JSON with fallback data
- Calling methods (get_architect_decision, compose_consensus) parse this JSON normally
- The fallback is NOT detected by `metadata.fallback` in the AIDecision — it flows through normal path
- To detect fallback: check `confidence == 0.5` and `reasoning` contains "Fallback"

### Coverage Measurement Note (run16, updated run35)
- Agent-doctor's full `pytest --cov=.` measures 19.23% as of run35 (stable since run34)
- Previous: 17.99% (v6), 19.15% (run33), 19.23% (run34-35) — plateaued
- Context-engineer reported 19.25% at v30 — close match (different scope/timing)
- Always use agent-doctor's `--cov=.` measurement for official coverage metric
- `stat -f '%m'` on macOS: use `date -r FILE` instead — avoids zsh parsing issues

### WAL File Accumulation Pattern (run19, updated run28)
- SQLite WAL files grow during pytest runs — each test that creates/writes DB produces WAL
- Run15: 5 WAL (13.1MB), Run16: 9 WAL (29MB), Run17: 2 WAL (0 bytes), Run18: 0 WAL, Run19: 3 WAL (8.1MB), Run v6: 5 WAL (0 bytes)
- **Run28: 12 WAL (2.55GB!!!) — fixops_brain.db had 2.5GB WAL causing CORRUPTION (malformed disk image)**
- **CRITICAL LESSON**: Large WAL files can corrupt the parent DB. fixops_brain.db had to be recreated.
- Safe to clean: `rm -f` on WAL + SHM files. DB files remain intact IF not already corrupted.
- Pattern RECURRING: WAL accumulate between runs. Always check and clean. Check DB integrity after cleaning large WALs.

### PersistentDict Resource Leak (RC9 — resolved run19)
- `persistent_store.py` `_conn()` method created NEW `sqlite3.connect()` on every call
- `with self._conn() as conn:` auto-commits but does NOT close the connection (Python SQLite context manager behavior)
- Every `__setitem__`, `_load_all`, `_init_table`, `clear`, `persist_all` leaked a connection
- **First attempt FAILED**: Single `self._connection` broke thread safety (SQLite connections can't cross threads)
- **Correct fix**: Use `threading.local()` for per-thread connection caching + `close()` + `__del__`
- 55/55 PersistentDict tests pass (including TestThreadSafety::test_concurrent_writes_no_crash)
- PersistentDict used in 14 files across the codebase — fix has wide impact
- Lesson: ALWAYS run related test files after modifying shared code (not just core tests)

### SQLite Connection Leak Pattern (RC10 — AUDIT COMPLETE 2026-03-01 run v3)
- Original 3 classes fixed in RC10: `fuzzy_identity.py`, `exposure_case.py`, `knowledge_brain.py`
- Run v3 fix: `graph.py` (ProvenanceGraph) — added `__del__` with try/except pattern
- Full audit of 31 files: 8 now have `__del__`, 23 use safe per-call `_get_connection()` with try/finally/close
- `api_learning_store.py` uses `with self._get_conn() as conn:` — context manager auto-commits but doesn't close. Relies on CPython ref counting. Acceptable risk.
- **All `*_db.py` files are SAFE** — they use per-call `_get_connection()` pattern where callers always close. No `__del__` needed.
- feeds_service.py: 28 `sqlite3.connect` calls, ALL properly closed (try/finally/conn.close())
- RC10 is now CLOSED — no remaining action needed

## See Also
- [debugging.md](debugging.md) — Detailed root cause analysis patterns
