# Context Engineer Memory

## Key Codebase Facts (Verified 2026-03-07 v33.0)
- **Python**: 939 files, 428,173 LOC. **Tests**: 392 files, 192,265 LOC, 13,949 collected (0 errors)
- **Coverage**: 19.21% (gate: 25%) -- FAILING. Gap: 5.79pp. Stable ~19.2% since v26.
- **Endpoints**: 771 (699 @router + 47 non-standard + 25 @app) across 64 router files + 8 non-standard, 34 mounts
- **Connectors**: 17 total (7 integration in connectors.py + 10 security tool in security_connectors.py)
- **Entry point**: `suite-api/apps/api/app.py` (2,893 LOC) -- single FastAPI process, port 8000
- **Import mechanism**: `sitecustomize.py` adds all suite dirs to sys.path
- **SQLite databases**: 56 .db files across data/, .fixops_data/, suite-api/data/
- **DB duplication**: Many DBs duplicated between data/ and suite-api/data/ (runtime copies)
- **Test collection time**: Varies by run environment (7.91s to 19.27s observed). Use whatever value you measure.
- **Sprint**: 2 -- Enterprise Demo (2026-03-06). 11/12 done (Post-Demo Day 1). DEMO-003 carries to Sprint 3.
- **Growth v32→v33**: +4 files, +3,935 LOC, +3 endpoints, +87 tests, +1 UI file, +2,350 UI LOC.
- **Engine changes**: brain_pipeline +50 LOC (→1,878), connectors +6 LOC (→3,011), app.py +40 LOC (→2,893).
- **Git**: No commits since 2026-03-03. All v32→v33 changes are uncommitted working directory.

## Naming Corrections
- CSPM file is `cspm_engine.py` NOT `cspm_analyzer.py` (agent def is wrong)
- `suite-ui/aldeci-ui-new/` does NOT EXIST (directory itself is missing, not just empty)
- compliance_engine.py exists in TWO locations: suite-evidence-risk/compliance/ (829 LOC) and suite-core/core/services/enterprise/ (125 LOC)
- Legacy UI has 101 TS/TSX files in src/ + 3 outside (vite.config, playwright.config, smoke.spec.ts) = 104 total, 45,332 src LOC
- node_modules adds ~4,031 .ts/.d.ts files -- NEVER count these
- health.py is at `suite-api/apps/api/health.py` (162 LOC) NOT `suite-core/core/health.py`
- routes/enhanced.py is at `suite-api/apps/api/routes/enhanced.py` (109 LOC) NOT suite-core
- reachability/api.py is at `suite-evidence-risk/risk/reachability/api.py` NOT suite-core
- enhanced_decision.py (1,279 LOC) at `suite-core/core/` AND enhanced_decision_engine.py (686 LOC) at `suite-core/core/services/enterprise/` -- TWO SEPARATE FILES
- falkordb file is `falkordb_client.py` (835 LOC), NOT `falkordb_integration.py`

## Connector Inventory (CORRECTED v11.0, verified v33.0)
- **connectors.py** (3,011 LOC): 7 integration connectors -- Jira, Confluence, Slack, ServiceNow, GitLab, AzureDevOps, GitHub
- **security_connectors.py** (1,335 LOC): 10 security tool connectors -- Snyk, SonarQube, Dependabot, AWS SecurityHub, Azure Defender, Wiz, Prisma Cloud, Orca, Lacework, ThreatMapper
- **Total**: 17 production connectors + universal REST/MCP ingest
- All inherit from `_BaseConnector` with retry, circuit-breaker, rate-limiting

## Honesty Corrections (P0 MOAT MISSION) -- Updated v33.0
- SAST is regex-based, NOT AST-based. 1,622 LOC (grew from 465→1,577→1,622).
- AutoFix is LLM-powered (10 fix types), NOT AST-based. Actually STRONGER positioning
- **Connectors: 17 IS CORRECT** (7 integration + 10 security tool).
- Secrets scanner: gitleaks/trufflehog wrapper with air-gapped fallback, NOT "20+ entropy patterns"
- Integration math: 17 connectors + 8 native scanners + 665 MCP tools = 690 integration points
- **STATUS**: ALL claims verified accurate. Zero violations remaining. **27th consecutive clean scan.**
- README.md:964 "v4 -- AST AutoFix" is correctly labeled "Planned" -- future roadmap, not current claim.
- SUITE_API_DEEP_ANALYSIS.md:553 "AST-based code analysis" describes ide_router purpose (analysis doc, not product claim).
- FIXOPS_COMPREHENSIVE_ANALYSIS.md:974 "ProprietaryAnalyzer" is planned architecture, not shipping claim.
- Zero inflated claims found in any .py source files.

## Scan Commands That Work
- `find . -name "*.py" -not -path "./.venv/*" | wc -l` -- file count
- Per-router grep for endpoints: `grep -cE '@router\.(get|post|put|delete|patch)' file`
- `python -m pytest tests/ --co -q --timeout=10 2>&1 | tail -15` -- test collection + coverage
- macOS: no `-P` flag for grep (use ripgrep/Grep tool instead)
- `find . -name "*.db" -not -path "./.venv/*"` -- catches ALL DBs
- **TS files**: MUST use `\( -name "*.ts" -o -name "*.tsx" \)` with parens on macOS
- For @app vs @router: `grep -cE '@app\.(get|post|put|delete|patch)'` (separate counts!)
- Per-suite endpoint count: iterate files with for loop, not find -exec

## Endpoint Counting (v33.0 -- +3 from v32)
- Scan ALL *_router.py files with @router decorators -> 699 endpoints across 64 files
- Per-suite: suite-api 230, suite-core 241 (+3), suite-attack 106, suite-feeds 31, suite-evidence-risk 40, suite-integrations 51
- Changed routers (v32→v33): brain_router 23→24, mcp_protocol_router 9→10, self_learning_router 19→20
- Non-standard endpoint files (8 total, 47 endpoints): unchanged
- @app direct endpoints in app.py -> **25**: unchanged
- Total = router(699) + non-standard(47) + app.direct(25) = **771**
- NOTE: `find` returns 65 *_router.py files -- 1 is tests/test_micro_pentest_router.py (NOT a router)

## Suite LOC (v33.0)
- suite-api: 42 files, 22,606 LOC (+49)
- suite-core: 316 files, 138,015 LOC (+1 file, +848)
- suite-attack: 13 files, 6,708 LOC (+199)
- suite-feeds: 3 files, 4,353 LOC (unchanged)
- suite-evidence-risk: 71 files, 20,313 LOC (unchanged)
- suite-integrations: 23 files, 6,768 LOC (+59)

## Vision Engine LOC (v33.0)
- brain_pipeline: **1,878** (+50) | autofix: **1,534** | micro_pentest: 2,054 | mpte_advanced: 1,089
- fail_engine: 711 | exposure_case: 646 | connectors: **3,011** (+6) | security_connectors: 1,335
- mcp_server: 978 | falkordb_client: 835 | single_agent: 818 | quantum_crypto: 666
- self_learning: 1,359 | zero_gravity: 855 | enhanced_decision: 1,279 | crypto: 582 | cli: 5,911
- enhanced_decision_engine (services/enterprise/): 686 -- separate file from enhanced_decision.py
- scanner_parsers: 1,238 | sandbox_verifier: 1,178
- sast_engine: 1,622 | secrets_scanner: 848 | dast_engine: 633 | container_scanner: 445
- cspm_engine: 609 | event_subscribers: 211 | playbook_runner: 1,273
- app.py: **2,893** (+40)

## ML Module LOC (v33.0)
- attack_path_gnn: 922 | online_learning: 1,174 | trend_analyzer: 703 | __init__: 33

## Scanner Inventory (8 engines, verified v33.0)
SAST(1,622), DAST(633), Secrets(848), Container(445), CSPM(609), API Fuzzer(3 eps), Malware(4 eps), LLM Monitor(4 eps)

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
- LESSON 11-40: See v13-v32 notes. Key: always use absolute paths, re-read before editing, verify diagrams match map.
- LESSON 41 (v33.0): Coverage can vary by ~0.07pp between runs (agent-doctor got 19.28%, I got 19.21%). Report what you measure, note discrepancy.
- LESSON 42 (v33.0): UI outside-src files can grow (smoke.spec.ts added). Check all 3 outside files not just 2.

## Output Versioning
- Use `version: "33.0"` for current outputs. Increment on each full refresh.
- History: v33.0 (22:00 2026-03-07), v32.0 (21:30 2026-03-03), v31.0 (20:00 2026-03-03), v30.0 (23:30 2026-03-02), v29.1, v29.0, v28.0, v27.0, v26.0, v25.0, v24.1, v24.0

## Coverage Trend (v33.0)
- v3-v6: ~17% -> v7-v13: 16.99% -> v14: 17.21% -> v15: 17.31% -> v16-v22: 17.99% -> v23: 19.35% -> v24: 19.19% -> v25-v26: 19.22% -> v27-v32: 19.23% -> v33: 19.21%
- v32→v33: stable. Tests +87 (13,862→13,949). New test files +2.
- 0 collection errors. Test collection time varies by environment (7.91s to 19.27s).

## Agent Coordination
- I produce: codebase-map.json, dependency-graph.json, architecture-context.md, briefing-{date}.md, CLAUDE.md
- ALL agents read my codebase-map.json and briefing
- Other agents may modify my outputs (vision-agent, agent-doctor). Re-read before writing.
- 3 MCP routers exist (suite-api, suite-integrations, suite-core)
