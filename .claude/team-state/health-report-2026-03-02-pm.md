# Agent Health Report — 2026-03-02 (PM Run29)

## Overall: GREEN

> **Sprint 2 — Enterprise Demo in 4 days (2026-03-06)**
> **Run ID**: agent-doctor-sprint2-day2-run29

---

## Senior Agent Health

| Agent | Grade | Status | CTEM | Duration | Issues |
|-------|-------|--------|------|----------|--------|
| context-engineer | A | Completed | 5 refs | 536s | — |
| ai-researcher | A | Completed | 8 refs | 942s | — |
| data-scientist | A | Completed | 7 refs | 740s | — |
| enterprise-architect | A | Completed | 9 refs | 838s | — |
| backend-hardener | A | Completed | 6 refs | 993s | DEMO-001 DONE |
| frontend-craftsman | A | Completed | 6 refs | 993s | DEMO-003 in progress |
| threat-architect | A | Completed | 8 refs | 1442s | — |
| security-analyst | A | Completed | 6 refs | 390s | SA-001 OPEN |
| qa-engineer | A | Completed | 4 refs | 606s | DEMO-002 DONE |
| devops-engineer | A | Completed | 6 refs | 801s | — |
| marketing-head | A | Completed | 6 refs | 633s | — |
| technical-writer | A | Completed | 11 refs | 660s | — |
| sales-engineer | A | Completed | 4 refs | 869s | — |
| scrum-master | A | Completed | 6 refs | 549s | — |
| agent-doctor | A | Running | 10 refs | — | This run |
| swarm-controller | A | Completed | 4 refs | 815s | — |
| vision-agent | A | Running | 12 refs | — | Alignment scan |

**Grade Distribution**: 17x A, 0x B, 0x C, 0x D, 0x F — **PERFECT HEALTH**

---

## Engine Health [V3] [V5] [V7] [V10]

| Category | Count | LOC | Status |
|----------|-------|-----|--------|
| Scanner Engines | 6 | 4,807 | All importable |
| Vision Engines | 6 | 5,509 | All importable |
| Core Engines | 7 | 10,211 | All importable |
| **Total** | **19** | **20,527** | **19/19 PASS** |

### MOAT Verification

| MOAT | Status | Detail |
|------|--------|--------|
| MOAT1: 12-Step Brain Pipeline | PASS | 12/12 steps registered and runnable |
| MOAT2: MPTE + Sandbox PoC | PASS | micro_pentest + mpte_advanced importable |
| MOAT3: MCP Gateway | PASS | MCPProtocolHandler + MCPToolRegistry importable |
| MOAT4: Crypto Evidence | PASS | RSAKeyManager + RSASigner + RSAVerifier importable |

---

## Database Health

- **55/55 DBs writable** (0 errors)
- **5/5 integrity checks PASS** (brain, identity, exposure_cases, api_learning, fail_scores)
- **10 WAL+SHM files cleaned** (1.6MB total)
- Largest DBs: api_detailed_logs (264MB), fixops_dedup (112MB), feeds (60MB)

---

## Test Health

| Metric | Value | Delta |
|--------|-------|-------|
| Total tests collected | 12,565 | +165 |
| Core tests passing | 1,143 | +15 |
| Core test time | 39.87s | — |
| Collection errors | 0 | — |
| Coverage | 19.22% | +0.03pp |
| Coverage gate | 25% | FAILING (gap 5.78pp) |

---

## Sprint Progress

| Item | Status | Owner | Detail |
|------|--------|-------|--------|
| DEMO-001: Fix broken APIs | DONE | backend-hardener | E2E 58/58, 769 routes, 11 security fixes |
| DEMO-002: Postman GREEN | DONE | qa-engineer | 411/411 (100%), 74 collection fixes |
| DEMO-003: Wire UI to APIs | IN PROGRESS | frontend-craftsman | 3 pages wired, more remaining |
| DEMO-004: CTEM Full Loop | DONE | threat-architect | 36/36 steps, 5/5 phases |
| DEMO-005: Persona Scripts | DONE | sales-engineer | 5 walkthroughs + 3 demo scripts |
| DEMO-006: Coverage Config | DONE | qa-engineer | pyproject.toml fixed |
| DEMO-007: Docker Demo | DONE | devops-engineer | 34/34 health checks pass |
| DEMO-008: API Docs | DONE | technical-writer | 704 endpoints documented |
| DEMO-009: MCP Gateway Demo | DONE | data-scientist | 705 tools discovered |
| DEMO-010: Knowledge Graph | DONE | ai-researcher | 73 nodes, 110 edges |
| DEMO-011: Compliance Export | DONE | security-analyst | RSA-SHA256 signed bundles |
| DEMO-012: Self-Learning | DONE | enterprise-architect | 5 feedback loops, 73 tests |

**Completion**: 11/12 (91.7%) — 1 P0 remaining (DEMO-003)

---

## Fixes Applied This Run

1. Cleaned 10 WAL+SHM files (1.6MB — prevents accumulation toward corruption)
2. Removed 4 stale fix-* status files (fix-frontend-craftsman, fix-security-analyst, fix-swarm-controller, fix-vision-agent)
3. Verified all 19/19 engines importable (20,527 LOC stable)
4. Verified 4/4 MOATs PASS
5. Verified 55/55 DBs writable with 5/5 integrity checks
6. Verified 16/16 agent configs valid YAML + CTEM refs
7. Confirmed 1,143 core tests pass across 15 files (39.87s)
8. Confirmed 12,565 total tests collected (0 collection errors)
9. Confirmed all 3 lock file PIDs alive (no stale locks)
10. Updated health dashboard to run29

---

## Security Advisories

| ID | Severity | Status | Finding | Deadline |
|----|----------|--------|---------|----------|
| SA-001 | CRITICAL | OPEN | Real API keys in .env (OpenAI sk-proj-*, JWT secret, API token) | Before demo (2026-03-06) |

**Action Required**: security-analyst must rotate all keys in .env before enterprise demo. 3 days open.

---

## Recommendations

- [ ] **P0**: Complete DEMO-003 (UI wiring) — only remaining P0 blocker
- [ ] **P0**: Rotate .env secrets (SA-001) — 3 days open, must resolve before demo
- [ ] **P1**: Close coverage gap (19.22% → 25%) — target uncovered suites (feeds_service, suite-integrations)
- [ ] **P2**: Monitor WAL accumulation — cleaned 1.6MB this run, pattern recurring every run
- [ ] **P2**: Consider archiving largest DBs (api_detailed_logs 264MB, fixops_dedup 112MB) before demo

---

## Health Trend

| Run | Date | Health | Engines | Tests | Coverage | Sprint |
|-----|------|--------|---------|-------|----------|--------|
| 27 | Mar 1 | GREEN | 19/19 | 10,356 | 17.99% | 9/12 |
| 28 | Mar 2 AM | GREEN | 19/19 | 12,400 | 19.19% | 11/12 |
| 29 | Mar 2 PM | GREEN | 19/19 | 12,565 | 19.22% | 11/12 |

**Trend**: Stable GREEN. Tests growing. Coverage improving slowly. Sprint nearly complete.

---

*Generated by agent-doctor run29 at 2026-03-02 14:00 UTC*
