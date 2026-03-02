# Context Engineer Memory

## Key Codebase Facts (Verified 2026-03-02 v26.0)
- **Python**: 900 files, 389,587 LOC. **Tests**: 360 files, 171,214 LOC, 12,565 collected (0 errors)
- **Coverage**: 19.22% (gate: 25%) -- FAILING. DEMO-006 config fix applied but still below gate.
- **Endpoints**: 759 (687 @router + 47 non-standard + 25 @app) across 64 router files + 8 non-standard, 34 mounts
- **Connectors**: 17 total (7 integration in connectors.py + 10 security tool in security_connectors.py)
- **Entry point**: `suite-api/apps/api/app.py` (2,742 LOC) -- single FastAPI process, port 8000
- **Import mechanism**: `sitecustomize.py` adds all suite dirs to sys.path
- **SQLite databases**: 56 .db files across data/, .fixops_data/, suite-api/data/
- **DB duplication**: Many DBs duplicated between data/ and suite-api/data/ (runtime copies)
- **Test collection time**: 19.21s (growth from 12,565 tests, was 14s at 10,356)
- **Sprint**: 2 -- Enterprise Demo (2026-03-06). 12 items, 11/12 done (Day 2). 1 P0 blocker (DEMO-003).
- **Stability**: v25→v26 all suite/engine/test metrics unchanged. Codebase has stabilized.

## Naming Corrections
- CSPM file is `cspm_engine.py` NOT `cspm_analyzer.py` (agent def is wrong)
- `suite-ui/aldeci-ui-new/` does NOT EXIST (directory itself is missing, not just empty)
- compliance_engine.py exists in TWO locations: suite-evidence-risk/compliance/ (829 LOC) and suite-core/core/services/enterprise/ (125 LOC)
- Legacy UI has 89 TS/TSX files in src/ + 2 outside (vite.config, playwright.config) = 91 total, 36,055 src LOC
- node_modules adds ~4,031 .ts/.d.ts files -- NEVER count these
- health.py is at `suite-api/apps/api/health.py` (162 LOC) NOT `suite-core/core/health.py`
- routes/enhanced.py is at `suite-api/apps/api/routes/enhanced.py` (109 LOC) NOT suite-core
- reachability/api.py is at `suite-evidence-risk/risk/reachability/api.py` NOT suite-core

## Connector Inventory (CORRECTED v11.0, verified v25.0)
- **connectors.py** (3,005 LOC): 7 integration connectors -- Jira, Confluence, Slack, ServiceNow, GitLab, AzureDevOps, GitHub
- **security_connectors.py** (1,335 LOC): 10 security tool connectors -- Snyk, SonarQube, Dependabot, AWS SecurityHub, Azure Defender, Wiz, Prisma Cloud, Orca, Lacework, ThreatMapper
- **Total**: 17 production connectors + universal REST/MCP ingest
- All inherit from `_BaseConnector` with retry, circuit-breaker, rate-limiting

## Honesty Corrections (P0 MOAT MISSION) -- Updated v26.0
- SAST is regex-based, NOT AST-based. 1,577 LOC (tripled from 465).
- AutoFix is LLM-powered (10 fix types), NOT AST-based. Actually STRONGER positioning
- **Connectors: 17 IS CORRECT** (7 integration + 10 security tool).
- Secrets scanner: gitleaks/trufflehog wrapper with air-gapped fallback, NOT "20+ entropy patterns"
- Integration math: 17 connectors + 8 native scanners + 665 MCP tools = 690 integration points
- **STATUS**: ALL claims verified accurate. Zero violations remaining. 20th consecutive clean scan.
- README.md:964 "v4 -- AST AutoFix" is correctly labeled "Planned" -- future roadmap, not current claim.

## Scan Commands That Work
- `find . -name "*.py" -not -path "./.venv/*" | wc -l` -- file count
- Per-router grep for endpoints: `grep -cE '@router\.(get|post|put|delete|patch)' file`
- `python -m pytest tests/ --co -q --timeout=10 2>&1 | tail -10` -- test collection + coverage
- macOS: no `-P` flag for grep (use ripgrep/Grep tool instead)
- `find . -name "*.db" -not -path "./.venv/*"` -- catches ALL DBs
- **TS files**: MUST use `\( -name "*.ts" -o -name "*.tsx" \)` with parens on macOS
- For @app vs @router: `grep -cE '@app\.(get|post|put|delete|patch)'` (separate counts!)

## Endpoint Counting (v25.0 -- stable from v24.1)
- Scan ALL *_router.py files with @router decorators -> 687 endpoints across 64 files
- Per-suite: suite-api 229, suite-core 233, suite-attack 106, suite-feeds 31, suite-evidence-risk 37, suite-integrations 51
- Non-standard endpoint files (8 total, 47 endpoints):
  - Always mounted: health.py(4), routes/enhanced.py(4), reachability/api.py(7), oss_tools.py(8) = 23
  - Conditionally mounted: decisions.py(6), nerve_center.py(9), business_context_enhanced.py(6), business_context.py(3) = 24
- @app direct endpoints in app.py -> **25** (NOT 27 -- v24.0 over-counted)
- Total = router(687) + non-standard(47) + app.direct(25) = **759**
- NOTE: `find` returns 65 *_router.py files -- 1 is tests/test_micro_pentest_router.py (NOT a router)

## Suite LOC (v25.0)
- suite-api: 42 files, 22,190 LOC (+66 from v24.1)
- suite-core: 308 files, 132,278 LOC (+2,097 from v24.1, +4 files)
- suite-attack: 13 files, 6,300 LOC (-2 from v24.1, formatting)
- suite-feeds: 3 files, 4,353 LOC (unchanged)
- suite-evidence-risk: 71 files, 20,275 LOC (unchanged)
- suite-integrations: 23 files, 6,709 LOC (unchanged)

## Vision Engine LOC (v25.0 -- significant changes from v24.1)
- brain_pipeline: **1,354** (+193!) | autofix: **1,416** (+157!) | micro_pentest: 2,054 | mpte_advanced: 1,089
- fail_engine: 711 | exposure_case: 646 | connectors: 3,005 | security_connectors: 1,335
- mcp_server: 978 | falkordb: 835 | single_agent: 818 | quantum_crypto: 664
- self_learning: 1,359 | zero_gravity: 855 | enhanced_decision: 1,279 | crypto: 582 | cli: 5,911
- scanner_parsers: **1,206** (+118!) | sandbox_verifier: **1,073** (+37)
- sast_engine: 1,577 | secrets_scanner: 850 | dast_engine: **629** (+96!) | container_scanner: **445** (+35)
- cspm_engine: 593

## Scanner Inventory (8 engines, verified v25.0)
SAST(1,577), DAST(**629** +96), Secrets(850), Container(**445** +35), CSPM(593), API Fuzzer(3 eps), Malware(4 eps), LLM Monitor(4 eps)

## Suite Hub Pattern
- suite-core is the hub -- ALL other suites import from it
- suite-api is the gateway -- imports routers from ALL suites, mounts on single app
- Cross-suite imports work via sitecustomize.py (fragile but functional)

## Transient Scan Issues (LESSONS)
- LESSON 1: ALWAYS re-run test collection before flagging regression
- LESSON 2: ALWAYS re-run file/LOC counts before flagging shrinkage
- LESSON 3: Verify ANY metric change >5% with a second run before reporting
- LESSON 4: Never flag a P0 CRITICAL without verification
- LESSON 5: ALWAYS exclude node_modules from TS/TSX file counts
- LESSON 6: ALWAYS verify subtotals by re-summing, never trust hand-calculation
- LESSON 7: Use \( parens \) in find -o patterns on macOS
- LESSON 8: Check files actually exist on disk before reporting them
- LESSON 9: Non-standard endpoint files may be in DIFFERENT suites than expected
- LESSON 10: ALWAYS search the FULL codebase for related files before correcting claims
- LESSON 11-25: Various measurement scope and transient lessons (see v13-v23 notes)
- LESSON 26 (v24.0): `cd` in Bash tool PERSISTS. Always use absolute paths.
- LESSON 27 (v24.0): When LOC jumps >5K, verify with git diff not just find/wc.
- LESSON 28 (v24.0): Agent metrics.json entries may be updated by other agents. Always re-read before editing.
- LESSON 29 (v24.1): ALWAYS separately count @app vs @router in app.py. The combined regex over-counts.
- LESSON 30 (v24.1): Agent "drift" claims from vision-agent may be stale. Cross-reference metrics.json lastRun dates.
- LESSON 31 (v24.1): Sprint board status ('todo') doesn't mean agent didn't run -- it means the task wasn't completed/verified.
- LESSON 32 (v25.0): vision-agent may update metrics.json between context-engineer runs. Always re-read before partial edit.
- LESSON 33 (v26.0): architecture-context.md data flow diagram has LOC values that may go stale across versions. Always verify diagram LOCs match codebase-map.json.

## Output Versioning
- Use `version: "26.0"` for current outputs. Increment on each full refresh.
- History: v26.0 (19:30), v25.0 (16:00), v24.1 (12:30), v24.0 (09:00 2026-03-02), v23.0 (00:30), v22.0 (23:30 2026-03-01)

## Coverage Trend (v26.0)
- v3-v6: ~17% -> v7-v13: 16.99% (x7) -> v14: 17.21% -> v15: 17.31% -> v16-v22: 17.99% (x7) -> v23: 19.35% (scope) -> v24: 19.19% -> v25-v26: 19.22% (stable)
- v25→v26: NO CHANGE (0pp). Codebase stabilized. Coverage plateau at 19.22%.
- 0 collection errors. Test collection time: 19.21s (up from 18.49s).

## Agent Coordination
- I produce: codebase-map.json, dependency-graph.json, architecture-context.md, briefing-{date}.md, CLAUDE.md
- ALL agents read my codebase-map.json and briefing
- Other agents may modify my outputs (vision-agent, agent-doctor). Re-read before writing.
- 3 MCP routers exist (suite-api, suite-integrations, suite-core)
