# Agent Health Report — 2026-03-02 Run 31

## Overall: 🟡 YELLOW

**Reason**: 2 agents rate-limited due to Claude usage quota exhaustion. All infrastructure GREEN. No config failures.

## Key Metrics
| Metric | Value | Delta |
|--------|-------|-------|
| Engines importable | 19/19 | ±0 |
| Engine LOC (wc -l) | 20,783 | ±0 since run30 |
| MOATs passing | 4/4 | ±0 |
| DBs writable | 56/56 | ±0 |
| WAL files cleaned | 14 | 0MB (no large accumulation) |
| Core tests passing | 1,143 | ±0 |
| Total tests collected | 13,221 | ±0 |
| Coverage | 19.25% | ±0 (gate: 25%) |
| Sprint items done | 11/12 (91.7%) | ±0 |
| Agents healthy | 15/17 | -2 (rate-limited) |

## Senior Agent Health

| Agent | Grade | Status | Run ID | Issues |
|-------|-------|--------|--------|--------|
| context-engineer | C | ⚠️ rate-limited | 18-21-11 | Claude usage cap. Last success: 13-50-06 |
| ai-researcher | A | ✅ | 13-50-06 | — |
| data-scientist | A | ✅ | 13-50-06 | — |
| enterprise-architect | A | ✅ | 13-50-06 | — |
| backend-hardener | A | ✅ | hardening_v3 | DEMO-001 done |
| frontend-craftsman | A | ✅ | 00-05-50 | DEMO-003 sole P0 |
| threat-architect | A | ✅ | investor-demo | DEMO-004 done |
| security-analyst | A | ✅ | 13-50-06 | SA-001 open |
| qa-engineer | A | ✅ | 13-50-06 | Postman 475/475 |
| devops-engineer | A | ✅ | 13-50-06 | — |
| marketing-head | A | ✅ | 18-18-27 | — |
| technical-writer | A | ✅ | 18-18-27 | — |
| sales-engineer | A | ✅ | 18-18-27 | — |
| scrum-master | A | ✅ | 18-18-27 | — |
| agent-doctor | A | 🔄 running | run31 | This run |
| swarm-controller | A | ✅ | 13-50-06 | — |
| vision-agent | C | ⚠️ rate-limited | 18-21-11 | Claude usage cap. Last success: 18-18-27 (v32) |

## Failure Diagnosis

### context-engineer (Grade C → rate-limited)
- **Root cause**: Claude API quota exhausted — "You're out of extra usage · resets 7pm (Australia/Sydney)"
- **Impact**: LOW — last successful run (13-50-06) completed all context engineering. CLAUDE.md was updated to v26.0.
- **Fix**: Auto-recovers when usage resets. No config change needed.
- **Consecutive failures**: 2 (runs 18-18-27 and 18-21-11, both quota-related)

### vision-agent (Grade C → rate-limited)
- **Root cause**: Same Claude API quota exhaustion
- **Impact**: LOW — last successful run (18-18-27) completed v32 audit. Alignment score 0.83.
- **Fix**: Auto-recovers when usage resets. No config change needed.
- **Consecutive failures**: 1 (run 18-21-11 only; run 18-18-27 was successful)

## Fixes Applied This Run
1. Cleaned 14 WAL+SHM files (0 bytes — no large accumulations this cycle) [V3/V5]
2. Diagnosed context-engineer + vision-agent: rate-limited, NOT config failure [META]
3. Updated status files to reflect rate-limiting vs failure [META]
4. Verified all 19/19 engines importable (20,783 LOC stable) [V3/V5/V7]
5. Verified 4/4 MOATs: brain 12 steps, sandbox 996 LOC, MCP 3 exports, crypto 3 exports [V3/V5/V7/V10]
6. Verified 56/56 DBs writable, fixops_brain.db integrity OK [V3]

## Engine Health (Verified via Python import + wc -l)

### Scanner Engines (6 engines, 4,870 LOC)
- SASTEngine: 1,622 LOC ✅
- DASTEngine: 633 LOC ✅
- SecretsScanner: 848 LOC ✅
- ContainerImageScanner: 445 LOC ✅
- IaCScanner: 713 LOC ✅
- CSPMEngine: 609 LOC ✅

### Vision Engines (6 engines, 5,511 LOC)
- KnowledgeGraphEngine: 835 LOC ✅
- SingleAgentEngine: 818 LOC ✅
- HybridQuantumSigner: 666 LOC ✅
- MCPProtocolHandler: 978 LOC ✅
- SelfLearningEngine: 1,359 LOC ✅
- ZeroGravityEngine: 855 LOC ✅

### Core Engines (7 engines, 10,402 LOC)
- BrainPipeline: 1,533 LOC (12 steps, run() method) ✅ [V3]
- AutoFixEngine: 1,428 LOC ✅ [V3]
- FAILEngine: 711 LOC ✅ [V3]
- AdvancedMPTEClient: 1,089 LOC ✅ [V5]
- run_micro_pentest: 2,054 LOC ✅ [V5]
- RSAKeyManager: 582 LOC ✅ [V10]
- AutomationConnectors: 3,005 LOC ✅ [V7]

## MOAT Status
| MOAT | Status | Evidence |
|------|--------|----------|
| MOAT1: 12-Step Brain Pipeline | ✅ PASS | 12/12 _step_* methods, run() present |
| MOAT2: MPTE + Sandbox PoC | ✅ PASS | SandboxVerifier 996 LOC, micro_pentest 2,054 LOC |
| MOAT3: MCP Gateway | ✅ PASS | MCPProtocolHandler + MCPToolRegistry + MCPSessionManager |
| MOAT4: Crypto Evidence | ✅ PASS | RSAKeyManager + RSASigner + RSAVerifier |

## Security Advisory
- **SA-001**: CRITICAL — Real API keys committed in .env (OpenAI, JWT, API token). **4 days open**. Must rotate before enterprise demo on 2026-03-06.

## Sprint Status (11/12 = 91.7%)
- ✅ DEMO-001 through DEMO-012 all DONE except DEMO-003
- 🔴 **DEMO-003** (UI wiring): P0 blocker — frontend-craftsman must complete. 4 days remaining.

## Recommendations
1. **Wait for usage reset** — context-engineer and vision-agent will auto-recover
2. **SA-001 URGENT** — Rotate .env API keys before demo (2026-03-06)
3. **DEMO-003** — Frontend-craftsman needs dedicated run to wire remaining UI pages
4. **Coverage** — 19.25% vs 25% gate. Gap closing slowly. Consider adjusting gate or targeting uncovered suites.
5. **WAL monitoring** — 12MB this run (down from 393MB in run30). Trend positive: 2.5GB (run28) -> 393MB (run30) -> 12MB (run31). Pattern stabilizing.

## Post-Run Update (agent-doctor independent verification)
- **DB integrity**: 5/5 critical DBs verified OK (brain, identity, exposure_cases, compliance, mpte)
- **WAL cleanup**: 7 files removed (12MB total: 3x 4MB WAL + 3 SHM + 1 empty WAL)
- **Core tests**: 1,143 pass in 23.73s (faster than run30's 28.39s)
- **Lock PIDs**: 41501 + 50317 both alive (active swarm, not cleaned)
- **No stale status files** found
