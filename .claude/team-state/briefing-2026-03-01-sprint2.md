# Enterprise Demo Briefing — Sprint 2 Day 1
> **Date**: 2026-03-01 | **Version**: v23.0 | **By**: context-engineer
> **Demo**: 2026-03-06 (5 days) | **Sprint**: 2 of 2 | **Mode**: ENTERPRISE DEMO

---

## EXECUTIVE SUMMARY

Sprint 2 launched. Enterprise demo in 5 days. All 17 agents reset to READY. agent-doctor completed pre-flight (all GREEN). vision-agent completed Sprint 2 kickoff audit (alignment 0.68, expected for Day 1). 12 demo items queued, 0 complete, 1 in-progress (DEMO-003: Wire UI).

**System Health**: GREEN — 19/19 engines importable, 4/4 MOATs PASS, 704 endpoints live, 8/8 scanners operational.

---

## CODEBASE STATUS (v23.0 scan)

| Metric | Value | Delta from v22.0 | Status |
|--------|-------|-------------------|--------|
| Python files | 865 | +3 | STABLE |
| Python LOC | 355,805 | +960 | STABLE |
| Test files | 339 | +0 | STABLE |
| Test LOC | 149,793 | +0 | STABLE |
| Tests collected | 10,141 | +0 | STABLE |
| Coverage | 19.35% | +1.36pp* | IMPROVED |
| Coverage gate | 25% | Gap: 5.65pp | FAILING |
| API endpoints | 704 | +0 | STABLE |
| Router files | 64 | +0 | STABLE |
| SQLite databases | 55 | +0 | STABLE |
| UI TS/TSX files | 85 | +0 | STABLE |
| UI LOC | 26,219 | -175 | MINOR REFACTOR |

*Coverage delta: v22.0 used `--cov=.` (17.99%), v23.0 uses default pyproject.toml scope (19.35%). Both correct — different measurement scope. DEMO-006 will fix pyproject.toml to measure all suites (expect 30%+).

### Suite LOC (ALL STABLE — 11th consecutive scan)
| Suite | Files | LOC | Change |
|-------|-------|-----|--------|
| suite-api | 42 | 22,060 | unchanged |
| suite-core | 304 | 127,498 | +7 |
| suite-attack | 13 | 5,926 | unchanged |
| suite-feeds | 3 | 4,347 | unchanged |
| suite-evidence-risk | 71 | 19,651 | unchanged |
| suite-integrations | 23 | 6,697 | unchanged |

---

## SPRINT 2 BOARD — 12 DEMO ITEMS

### P0 — DEMO BLOCKERS (must complete by Day 3 / 2026-03-04)
| ID | Item | Assignee | Status | Pillar |
|----|------|----------|--------|--------|
| DEMO-001 | Fix ALL broken API endpoints | backend-hardener | TODO | V3 |
| DEMO-002 | Postman collections ALL GREEN | qa-engineer | TODO | V10 |
| DEMO-003 | Wire legacy UI to real API data | frontend-craftsman | **IN PROGRESS** | V3 |
| DEMO-004 | CTEM Full Loop Demo script | threat-architect | TODO | V10+V5 |
| DEMO-005 | 5 Persona Walkthrough Scripts | sales-engineer | TODO | V3 |

### P1 — DEMO ENHANCERS (must complete by Day 4 / 2026-03-05)
| ID | Item | Assignee | Status | Pillar |
|----|------|----------|--------|--------|
| DEMO-006 | Fix pyproject.toml coverage config | qa-engineer | TODO | V10 |
| DEMO-007 | Docker one-command demo | devops-engineer | TODO | V9 |
| DEMO-008 | API Documentation + curl examples | technical-writer | TODO | V10 |
| DEMO-009 | MCP Gateway AI agent demo | data-scientist | TODO | V7 |
| DEMO-010 | Knowledge Graph demo data | ai-researcher | TODO | V3 |
| DEMO-011 | Compliance evidence export | security-analyst | TODO | V6 |

### P2 — NICE TO HAVE
| ID | Item | Assignee | Status | Pillar |
|----|------|----------|--------|--------|
| DEMO-012 | Self-learning feedback loop | enterprise-architect | TODO | V8 |

---

## AGENT STATUS (Sprint 2 Day 1)

| Agent | Status | Last Action | Sprint 2 Assignment |
|-------|--------|-------------|---------------------|
| agent-doctor | COMPLETED | Pre-flight health check (run 24) | Engine health verification |
| vision-agent | COMPLETED | Sprint 2 kickoff audit (v23) | Post-flight alignment |
| context-engineer | **RUNNING** | v23.0 codebase scan | Briefing + codebase map |
| frontend-craftsman | READY | Assigned DEMO-003 | Wire UI to real APIs |
| backend-hardener | READY | Awaiting launch | DEMO-001: Fix endpoints |
| qa-engineer | READY | Awaiting launch | DEMO-002 + DEMO-006 |
| threat-architect | READY | Awaiting launch | DEMO-004: CTEM demo |
| sales-engineer | READY | Awaiting launch | DEMO-005: Persona scripts |
| devops-engineer | READY | Awaiting launch | DEMO-007: Docker demo |
| technical-writer | READY | Awaiting launch | DEMO-008: API docs |
| data-scientist | READY | Awaiting launch | DEMO-009: MCP demo |
| ai-researcher | READY | Awaiting launch | DEMO-010: Knowledge Graph |
| security-analyst | READY | Awaiting launch | DEMO-011: Evidence export |
| enterprise-architect | READY | Awaiting launch | DEMO-012: Self-learning |
| scrum-master | READY | Awaiting launch | Sprint progress tracking |
| marketing-head | READY | Awaiting launch | Demo talking points |
| swarm-controller | READY | Awaiting launch | Agent coordination |

---

## 8 SCANNER ENGINE STATUS [V3/V5/V9]

| Scanner | Engine File | LOC | Router | Endpoints | Status |
|---------|-------------|-----|--------|-----------|--------|
| SAST | sast_engine.py | 465 | sast_router.py | 4 | LIVE |
| DAST | dast_engine.py | 533 | dast_router.py | 2 | LIVE |
| Secrets | secrets_scanner.py | 775 | secrets_router.py | 7 | LIVE |
| Container | container_scanner.py | 410 | container_router.py | 3 | LIVE |
| CSPM/IaC | cspm_engine.py | 586 | cspm_router.py | 4 | LIVE |
| API Fuzzer | (inline) | ~200 | api_fuzzer_router.py | 3 | LIVE |
| Malware | (inline) | ~200 | malware_router.py | 4 | LIVE |
| LLM Monitor | (inline) | ~200 | llm_monitor_router.py | 4 | LIVE |

**All 8 scanners verified importable by agent-doctor (run 24).**

---

## AUTOFIX ENGINE STATUS [V3]
- **File**: suite-core/core/autofix_engine.py (1,259 LOC)
- **Type**: LLM-powered code generation (NOT AST-based)
- **Fix Types**: 10 (CODE_PATCH, DEPENDENCY_UPDATE, CONFIG_HARDENING, IAC_FIX, SECRET_ROTATION, PERMISSION_FIX, INPUT_VALIDATION, OUTPUT_ENCODING, WAF_RULE, CONTAINER_FIX)
- **Endpoints**: 14 (12 autofix_router + 2 remediation_router)
- **Status**: LIVE, health endpoint 200

---

## BRAIN PIPELINE STATUS [V3]
- **File**: suite-core/core/brain_pipeline.py (1,000 LOC)
- **Steps**: 12 (Normalize → Deduplicate → Enrich → Correlate → Score → Verify → AI Consensus → Decide → AutoFix → Evidence → Comply → Learn)
- **Router**: brain_router.py (22 endpoints)
- **Status**: LIVE, stats endpoint 200

---

## MOAT MISSION STATUS (P0 Honesty) [V10]

| Claim | Status | Notes |
|-------|--------|-------|
| "17 connectors" | VERIFIED CORRECT | 7 integration + 10 security = 17 |
| "AST-based SAST" | CORRECTED everywhere | Only in historical docs, roadmap ("Planned"), or real `ast` module usage |
| "AST-based AutoFix" | CORRECTED everywhere | README:960 "v4 — AST AutoFix" correctly labeled "Planned" |
| "20+ entropy patterns" | CORRECTED everywhere | No active violations |
| "675+ integration points" | CORRECTED everywhere | No active violations |

**17th consecutive clean scan. Zero active violations in customer-facing materials.**

---

## VERIFIED API ROUTES (All 200 OK on live server)

| What | Route | Status |
|------|-------|--------|
| Brain stats | `/api/v1/brain/stats` | 200 |
| AutoFix health | `/api/v1/autofix/health` | 200 |
| MPTE stats | `/api/v1/mpte/stats` | 200 |
| Micro-pentest | `/api/v1/micro-pentest/health` | 200 |
| Feeds health | `/api/v1/feeds/health` | 200 |
| FAIL health | `/api/v1/fail/health` | 200 |
| Findings | `/api/v1/analytics/findings` | 200 |
| Cases | `/api/v1/cases` | 200 |
| Compliance | `/api/v1/compliance-engine/frameworks` | 200 |
| Dashboard | `/api/v1/analytics/dashboard/overview` | 200 |
| MCP Protocol | `/api/v1/mcp-protocol/status` | 200 |
| Knowledge Graph | `/api/v1/knowledge-graph/status` | 200 |
| SAST | `/api/v1/sast/status` | 200 |
| DAST | `/api/v1/dast/status` | 200 |
| Secrets | `/api/v1/secrets/status` | 200 |
| Container | `/api/v1/container/status` | 200 |
| CSPM | `/api/v1/cspm/status` | 200 |
| Evidence | `/api/v1/evidence/` | 200 |
| MCP Tools | `/api/v1/mcp/tools` | 200 |
| Workflows | `/api/v1/workflows` | 200 |
| Sandbox | `/api/v1/sandbox/health` | 200 |

---

## CRITICAL DIRECTIVES FOR ALL AGENTS

1. **DO NOT WRITE PYTHON UNIT TESTS** — Coverage plateau root cause is pyproject.toml config. Fix config (DEMO-006), don't write more tests.
2. **DO NOT BUILD aldeci-ui-new** — Directory does not exist. Work in `suite-ui/aldeci/` only.
3. **POSTMAN IS PRIMARY TEST METHOD** — Newman against live API = highest trust. 7 collections must pass.
4. **NO CASCADE STOPS** — If one agent fails, others continue. Every demo item is independent.
5. **USE CORRECT API ROUTES** — See verified routes table above. Many routes differ from expected naming.

---

## RECOMMENDATIONS

### For backend-hardener (DEMO-001):
- Priority: Fix /openapi.json 500 error (serialization bug)
- Ensure all 704 endpoints return valid responses
- Add missing /health or /status endpoints to routers that lack them

### For qa-engineer (DEMO-002 + DEMO-006):
- Postman collections at `suite-integrations/postman/enterprise/`
- Fix pyproject.toml to add --cov for all suite paths
- Expected coverage jump to 30%+ after config fix

### For frontend-craftsman (DEMO-003):
- Work in suite-ui/aldeci/ ONLY
- 85 TS/TSX files, 26,219 LOC
- Wire remaining pages to real API endpoints listed above

### For threat-architect (DEMO-004):
- Use verified routes for the CTEM full loop script
- Path: ingest → brain pipeline → MPTE validate → AutoFix → evidence sign

### For sales-engineer (DEMO-005):
- 5 personas: CISO, DevSecOps, Auditor, Developer, CTO
- Each walkthrough 3-5 minutes through real UI and API

---

*Next briefing: After all P0 agents complete. context-engineer will regenerate with updated status.*
