# Context Engineer Memory

## Key Codebase Facts (Verified 2026-03-02 v23.0)
- **Python**: 865 files, 355,805 LOC. **Tests**: 339 files, 149,793 LOC, 10,141 collected (0 errors)
- **Coverage**: 19.35% (gate: 25%) -- FAILING. Root cause: pyproject.toml only measures 5 modules. DEMO-006 will fix. Expect 30%+.
- **Endpoints**: 704 (634 @router + 47 non-standard + 23 @app) across 64 router files + 8 non-standard, 34 mounts
- **Connectors**: 17 total (7 integration in connectors.py + 10 security tool in security_connectors.py)
- **Entry point**: `suite-api/apps/api/app.py` (2,737 LOC) -- single FastAPI process, port 8000
- **Import mechanism**: `sitecustomize.py` adds all suite dirs to sys.path
- **SQLite databases**: 55 .db files across data/, .fixops_data/, suite-api/data/
- **DB duplication**: Many DBs duplicated between data/ and suite-api/data/ (runtime copies)
- **Test collection time**: 13.89s (non-deterministic, varies 11-16s per run)
- **Sprint**: 2 -- Enterprise Demo (2026-03-06). 12 items, 0/12 done (Day 1).

## Naming Corrections
- CSPM file is `cspm_engine.py` NOT `cspm_analyzer.py` (agent def is wrong)
- `suite-ui/aldeci-ui-new/` does NOT EXIST (directory itself is missing, not just empty)
- compliance_engine.py exists in TWO locations: suite-evidence-risk/compliance/ (829 LOC) and suite-core/core/services/enterprise/ (125 LOC)
- Legacy UI has 85 TS/TSX files in src/ + 8 outside (vite.config, playwright.config, etc.) = 93 total, 26,219 LOC
- node_modules adds ~4,031 .ts/.d.ts files -- NEVER count these
- health.py is at `suite-api/apps/api/health.py` (162 LOC) NOT `suite-core/core/health.py`
- routes/enhanced.py is at `suite-api/apps/api/routes/enhanced.py` (109 LOC) NOT suite-core
- reachability/api.py is at `suite-evidence-risk/risk/reachability/api.py` NOT suite-core

## Connector Inventory (CORRECTED v11.0, verified v23.0)
- **connectors.py** (3,005 LOC): 7 integration connectors -- Jira, Confluence, Slack, ServiceNow, GitLab, AzureDevOps, GitHub
- **security_connectors.py** (1,335 LOC): 10 security tool connectors -- Snyk, SonarQube, Dependabot, AWS SecurityHub, Azure Defender, Wiz, Prisma Cloud, Orca, Lacework, ThreatMapper
- **Total**: 17 production connectors + universal REST/MCP ingest
- All inherit from `_BaseConnector` with retry, circuit-breaker, rate-limiting
- v10.0 moat correction to "7 connectors" was WRONG -- it only examined connectors.py
- Frozen UI "17 connectors" claim in Integrations.tsx:381 is CORRECT

## Honesty Corrections (P0 MOAT MISSION) -- Updated v23.0
- SAST is regex-based (16 rules), NOT AST-based. Position as "lightweight, air-gapped scanner"
- AutoFix is LLM-powered (10 fix types), NOT AST-based. Actually STRONGER positioning
- **Connectors: 17 IS CORRECT** (7 integration + 10 security tool). v10.0 correction was over-aggressive.
- Secrets scanner: gitleaks/trufflehog wrapper with air-gapped fallback, NOT "20+ entropy patterns"
- Integration math: 17 connectors + 8 native scanners + 665 MCP tools = 690 integration points
- NOTE: ide_router.py and reachability/call_graph.py DO genuinely use Python `ast` module (different from SAST engine)
- NOTE: docs/FIXOPS_COMPREHENSIVE_ANALYSIS.md ProprietaryAnalyzer "AST-based" is CORRECT (uses Python ast module)
- NOTE: docs/SUITE_API_DEEP_ANALYSIS.md ide_router "AST-based" is CORRECT (uses Python ast module)
- **STATUS**: ALL claims verified accurate. Zero violations remaining in active materials. 17th consecutive clean scan.
- README.md:960 "v4 -- AST AutoFix" is correctly labeled "Planned" -- future roadmap, not current claim.

## Scan Commands That Work
- `find . -name "*.py" -not -path "./.venv/*" | wc -l` -- file count
- Per-router grep for endpoints: `grep -cE '@router\.(get|post|put|delete|patch)' file`
- `python -m pytest tests/ --co -q --timeout=10 2>&1 | tail -10` -- test collection + coverage
- macOS: no `-P` flag for grep (use ripgrep/Grep tool instead)
- `find . -name "*.db" -not -path "./.venv/*"` -- catches ALL DBs
- **TS files**: MUST use `\( -name "*.ts" -o -name "*.tsx" \)` with parens on macOS

## Endpoint Counting (v23.0 -- verified, unchanged since v13.0)
- Scan ALL *_router.py files with @router decorators -> 634 endpoints across 64 files
- Non-standard endpoint files (8 total, 47 endpoints):
  - Always mounted: health.py(4), routes/enhanced.py(4), reachability/api.py(7), oss_tools.py(8) = 23
  - Conditionally mounted: decisions.py(6), nerve_center.py(9), business_context_enhanced.py(6), business_context.py(3) = 24
- @app direct endpoints in app.py -> 23
- Total = router(634) + non-standard(47) + app.direct(23) = 704
- NOTE: `find` returns 65 *_router.py files -- 1 is tests/test_micro_pentest_router.py (NOT a router)

## Suite LOC (v23.0 -- stable since v13.0, 11th consecutive)
- suite-api: 42 files, 22,060 LOC
- suite-core: 304 files, 127,498 LOC (+7 from v22)
- suite-attack: 13 files, 5,926 LOC
- suite-feeds: 3 files, 4,347 LOC
- suite-evidence-risk: 71 files, 19,651 LOC
- suite-integrations: 23 files, 6,697 LOC

## Vision Engine LOC (v23.0 -- all stable since v13.0)
- brain_pipeline: 1,000 | autofix: 1,259 | micro_pentest: 2,054 | mpte_advanced: 1,089
- fail_engine: 713 | exposure_case: 646 | connectors: 3,005 | security_connectors: 1,335
- mcp_server: 979 | falkordb: 835 | single_agent: 819 | quantum_crypto: 666
- self_learning: 832 | zero_gravity: 857 | enhanced_decision: 1,279 | crypto: 570 | cli: 5,911
- scanner_parsers: 1,088 | sandbox_verifier: 1,029
- mpte_router: 1,063 | scanner_ingest_router: 370 | mcp_protocol_router: 204
- oss_tools: 205 | health: 162 | enhanced: 109

## Scanner Inventory (8 engines, all verified v23.0)
SAST(465), DAST(533), Secrets(775), Container(410), CSPM(586), API Fuzzer(3 eps), Malware(4 eps), LLM Monitor(4 eps)

## Suite Hub Pattern
- suite-core is the hub -- ALL other suites import from it
- suite-core also imports from apps.api.normalizers (suite-api)
- suite-api is the gateway -- imports routers from ALL suites, mounts on single app
- suite-attack imports from core.* (suite-core)
- suite-feeds imports from apps.api.dependencies (suite-api)
- suite-evidence-risk imports from apps.api.normalizers (suite-api), core.* (suite-core)
- suite-integrations imports from core.connectors, core.enhanced_decision (suite-core) + apps.api.dependencies
- Cross-suite imports work via sitecustomize.py (fragile but functional)

## Transient Scan Issues (LESSONS)
- LESSON 1: ALWAYS re-run test collection before flagging regression
- LESSON 2: ALWAYS re-run file/LOC counts before flagging shrinkage
- LESSON 3: Verify ANY metric change >5% with a second run before reporting
- LESSON 4: Never flag a P0 CRITICAL without verification
- LESSON 5: ALWAYS exclude node_modules from TS/TSX file counts
- LESSON 6: ALWAYS verify subtotals by re-summing, never trust hand-calculation
- LESSON 7: Use \( parens \) in find -o patterns on macOS -- without them results vary
- LESSON 8: Check files actually exist on disk before reporting them as "deleted"
- LESSON 9: Non-standard endpoint files may be in DIFFERENT suites than expected
- LESSON 10: ALWAYS search the FULL codebase for related files before correcting claims
- LESSON 11: Verify LOC changes by checking -newer flag first; small LOC deltas may be measurement variance
- LESSON 12 (v13.0): metrics.json may have stale sub-values even when header is updated
- LESSON 13 (v14.0): When coverage finally changes after a long plateau, cross-reference agent-doctor's activity
- LESSON 14 (v15.0): Test collection time can improve even with more tests
- LESSON 15 (v16.0): Verify coverage gains >0.5pp by checking new test files
- LESSON 16 (v17.0): Coverage can plateau even with hundreds of new tests if they target already-covered modules
- LESSON 17 (v18.0): Different --cov scopes give different numbers. agent-doctor narrower, CE uses --cov=.
- LESSON 18 (v18.0): Production suite LOC can be stable for many versions. Don't force-report changes.
- LESSON 19-21: Test collection time and testFiles counts can vary. Trust fresh `find` over stale metrics.
- LESSON 22-23: Collection time is non-deterministic (11-16s range). Not a regression signal.
- LESSON 24 (v23.0): Coverage scope matters: pyproject.toml default (19.35%) vs --cov=. (17.99%). Align with other agents on scope.
- LESSON 25 (v23.0): When UI LOC decreases and frontend-craftsman has active work (DEMO-003), it's expected refactoring, not regression.

## Output Versioning
- Use `version: "23.0"` for current outputs. Increment on each full refresh.
- History: v23.0 (00:30 2026-03-02), v22.0 (23:30 2026-03-01), v21.0 (21:00), v20.0 (17:00), v19.0 (14:35), v18.0 (23:45), v17.0 (22:00), v16.0 (01:00), v15.0 (23:30), v14.0 (21:00), v13.0 (15:30), v12.0 (10:00), v11.0 (09:00), v10.0 (23:59 2026-02-28)

## Coverage Trend (v23.0)
- v3.0: ~17% -> v4.0: 17.52% -> v5.0: 16.89% -> v6.0: 16.80% -> v7-v13: 16.99% (x7) -> v14: 17.21% -> v15: 17.31% -> v16: 17.99% -> v17-v22: 17.99% (x6) -> v23: 19.35% (scope change)
- The 17.99%→19.35% jump is NOT code improvement, it's measurement scope difference (pyproject.toml defaults vs --cov=.)
- Root cause: pyproject.toml only measures 5 modules. DEMO-006 will add all 6 suites.
- 0 collection errors. Test collection time: 13.89s.
- 1 failing e2e test: test_combined_provider.py (10s timeout, since v17)

## Agent Coordination
- I produce: codebase-map.json, dependency-graph.json, architecture-context.md, briefing-{date}.md, CLAUDE.md
- ALL agents read my codebase-map.json and briefing
- enterprise-architect + scrum-master review my work
- 3 MCP routers exist (suite-api, suite-integrations, suite-core)
