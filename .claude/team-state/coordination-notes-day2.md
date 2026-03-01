# Coordination Notes — Day 2 (2026-03-02)

> **Written by**: scrum-master
> **Sprint**: 2 — Enterprise Demo | **Day**: 2/5
> **Status**: 9/12 DONE, 3 P0 REMAINING

---

## DAY 2 PRIORITIES (In Order)

### PRIORITY 1: DEMO-001 — Fix ALL Broken API Endpoints [V3]
**Assignee**: backend-hardener
**Status**: todo → MUST START AND COMPLETE TODAY
**Why Critical**: This blocks DEMO-002 (Postman) and DEMO-003 (UI wiring).

**Specific Tasks**:
1. Fix `/openapi.json` 500 error — serialization bug in `apps/api/app.py`
2. Add `/health`, `/status`, `/stats` aliases to ALL routers (so any naming works)
3. Fix `/api/v1/search` 500 error
4. Verify: Run `python scripts/enterprise_e2e_test.py` → 100% pass

**Known Route Corrections** (from coordination-notes.md):
- brain: `/api/v1/brain/stats` (add /status, /health aliases)
- autofix: `/api/v1/autofix/health` (add /status, /stats aliases)
- mpte: `/api/v1/mpte/stats` (add /status, /health aliases)
- feeds: `/api/v1/feeds/health` (add /status, /stats aliases)
- fail: `/api/v1/fail/health` (add /status, /stats aliases)
- knowledge-graph: `/api/v1/knowledge-graph/status` (add /stats, /health aliases)
- micro-pentest: `/api/v1/micro-pentest/health` (add /status, /stats aliases)

### PRIORITY 2: DEMO-003 — Wire Legacy UI to Real API Data [V3]
**Assignee**: frontend-craftsman
**Status**: in-progress

**Remaining Pages**:
- Dashboard.tsx → `/api/v1/analytics/dashboard/overview`
- EvidenceBundles.tsx → `/api/v1/evidence/*`
- Remediation.tsx → `/api/v1/remediation/tasks`
- Reports.tsx → `/api/v1/reports` (response key: `data?.items`)
- AuditLogs.tsx → `/api/v1/audit/logs`
- Workflows.tsx → `/api/v1/workflows`

**Pattern**: `const items = data?.items || data?.results || [];`
**WARNING**: Do NOT build aldeci-ui-new — it doesn't exist. Work in `suite-ui/aldeci/`.

### PRIORITY 3: DEMO-002 — Postman 84.7% → 100% [V10]
**Assignee**: qa-engineer
**Status**: in-progress (84.7%, 404/477 passing)

**Remaining Failures (73)**:
- 20 null-ID 404s → Add pre-request seed data scripts
- 30 complex validation 422s → Fix request body payloads
- 2 search 500s → Depends on DEMO-001 (/api/v1/search fix)
- 21 other → Investigate individually

**Dependency**: DEMO-001 must fix search 500 before QA can achieve 100%.

---

## SECURITY ADVISORY — IMMEDIATE ACTION REQUIRED

### SEC-ADV-001: Real API Keys in .env (CRITICAL)
**CEO Action**: Rotate OpenAI API key at https://platform.openai.com/account/api-keys — IMMEDIATELY
**devops-engineer**: Add `.env` to `.gitignore` and create `.env.example` with placeholders
**backend-hardener**: Generate strong JWT secret (32+ bytes random) to replace `demo-secret`

---

## AGENT INSTRUCTIONS FOR DAY 2

| Agent | Day 2 Task | Priority |
|-------|-----------|----------|
| **backend-hardener** | DEMO-001: Fix ALL broken endpoints (P0 BLOCKER) | 🔴 CRITICAL |
| **frontend-craftsman** | DEMO-003: Wire remaining UI pages to API | 🔴 HIGH |
| **qa-engineer** | DEMO-002: Push Postman to 100% (after DEMO-001) | 🔴 HIGH |
| devops-engineer | Fix .env security advisory | 🟡 MEDIUM |
| agent-doctor | Post-Day-2 health check | 🟢 LOW |
| context-engineer | Track Day 2 code changes | 🟢 LOW |
| vision-agent | Post-Day-2 alignment check | 🟢 LOW |
| swarm-controller | Coordinate Day 2 builder agents | 🟢 LOW |
| scrum-master | Day 2 standup and demo report | 🟢 LOW |
| All others | DONE — support as needed | ✅ COMPLETE |

---

## DATA FLOW FOR DAY 2

- backend-hardener produces: Fixed endpoints → qa-engineer tests with Postman → frontend-craftsman wires UI
- This is a sequential dependency: DEMO-001 → DEMO-002 → DEMO-003
- If DEMO-001 completes early, qa-engineer and frontend-craftsman can work in parallel

---

## DEMO READINESS CHECKLIST

| # | Criteria | Day 1 Status | Day 2 Target |
|---|----------|-------------|--------------|
| 1 | Zero API 404s/500s | ❌ (search 500, openapi 500) | ✅ |
| 2 | Postman all green | 🟡 84.7% (404/477) | 🟡 95%+ |
| 3 | UI shows real data | 🟡 3/9 pages wired | 🟡 6/9 pages |
| 4 | CTEM full loop works | ✅ 36/36 steps | ✅ |
| 5 | 5 personas scripted | ✅ | ✅ |
| 6 | Docker works | ✅ 34/34 health | ✅ |
| 7 | Coverage ≥25% | ❌ 19.35% (config fixed) | 🟡 Verify |

---

*Written by scrum-master • Day 2 instructions • 2026-03-02*
