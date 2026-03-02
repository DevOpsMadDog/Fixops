# Coordination Notes — Day 3 (2026-03-03)
# Enterprise Demo Sprint | 3 Days Remaining | 10/12 Done

> **Updated by**: scrum-master (Day 2 afternoon, 2026-03-02 10:23)
> **Sprint board**: sprint-board.json (source of truth)
> **Previous notes**: coordination-notes.md (Sprint 2 master), coordination-notes-day2.md

## STATUS: 10/12 DONE — 2 P0 ITEMS REMAIN

### REMAINING ITEMS (Day 3 Priority)

| Item | Agent | Status | Day 3 Action |
|------|-------|--------|--------------|
| **DEMO-002** | qa-engineer | 84.7% (404/477) | **ITERATE**: /search FIXED (200). Run Newman again. Target 95%+. Fix remaining 73 failures. |
| **DEMO-003** | frontend-craftsman | BLOCKED (OAuth) | **RESTART**: Root cause is OAuth token expiry, NOT code bug. Get fresh token, restart agent. Wire remaining pages. |

### COMPLETED ITEMS (No further action needed)
DEMO-001 ✅, DEMO-004 ✅, DEMO-005 ✅, DEMO-006 ✅, DEMO-007 ✅, DEMO-008 ✅, DEMO-009 ✅, DEMO-010 ✅, DEMO-011 ✅, DEMO-012 ✅

---

## CRITICAL DIRECTIVES (Unchanged)

### 1. DO NOT WRITE PYTHON UNIT TESTS
Coverage config is fixed (DEMO-006). The 73 Postman failures are the priority, not pytest.

### 2. DO NOT BUILD aldeci-ui-new
`suite-ui/aldeci-ui-new/` does NOT EXIST. Work in `suite-ui/aldeci/`.

### 3. POSTMAN IS THE PRIMARY TEST METHOD
Newman runs against live API = highest trust.

### 4. NO CASCADE STOPS
Every demo item is independent. If one agent fails, others continue.

---

## DAY 3 AGENT ASSIGNMENTS

### P0 — Must Complete Day 3
| Agent | Task | Details |
|-------|------|---------|
| **qa-engineer** | DEMO-002: Push Postman to 95%+ | /search NOW returns 200 (was 500). Run Newman. Fix remaining 73 failures: 20 null-ID 404s (add seed data), 30 validation 422s (fix request bodies), 23 other. Use `suite-integrations/postman/enterprise/` collections. |
| **frontend-craftsman** | DEMO-003: Wire remaining UI pages | Get fresh OAuth token first. Wire: Dashboard pages, Evidence pages, Remediation pages, Settings pages. Use `suite-ui/aldeci/src/lib/api.ts` exports. Fix response key mismatches (backend returns `{items:[]}` but UI expects array). Previous build is intact (0 TS errors, 1.75s). |

### P1 — Available for Support / Enhancement
| Agent | Task | Details |
|-------|------|---------|
| **backend-hardener** | Support DEMO-002/003 | Fix any remaining 500 endpoints found by QA. Generate strong JWT secret (SEC-ADV-001). Available as fallback for API fixes. |
| **devops-engineer** | Infrastructure support | Fix OAuth token infrastructure for frontend-craftsman. Verify Docker compose still works after Day 2 changes. |
| **threat-architect** | MOAT hardening | If time permits, enhance CTEM regression tests. Security advisory threat model support. |
| **enterprise-architect** | Tech debt | Address top items from tech debt tracker. Brain pipeline memory leak follow-up. |
| **data-scientist** | ML refinement | Keep threat intel fresh. Model maintenance. |
| **security-analyst** | Security hardening | Run bandit scan to reduce 194 warnings. Verify compliance endpoints. Follow up on SEC-ADV-001. |

### Support — Monitoring
| Agent | Task | Details |
|-------|------|---------|
| **agent-doctor** | Pre-flight Day 3 | Health check all engines. Clear WAL files. Verify 4 MOATs. |
| **context-engineer** | Codebase scan | Refresh codebase-map if changes detected. |
| **vision-agent** | Post-flight | Verify alignment score. Track DEMO-002/003 completion. |
| **swarm-controller** | Orchestrate Day 3 | Dispatch agents. No cascade stops. Priority: qa-engineer + frontend-craftsman. |
| **marketing-head** | Demo rehearsal support | Refine talking points based on what's demo-ready. |
| **sales-engineer** | Demo rehearsal | Rehearse persona walkthroughs against live API. |
| **technical-writer** | Docs polish | Update API docs if endpoint counts change. |
| **scrum-master** | Track Day 3 | Standup, demo report, sprint board. |

---

## VERIFIED API ENDPOINTS (2026-03-02 10:23)

All tested with auth token (`X-API-Key: $TOKEN`):

| Endpoint | Status | Previously |
|----------|--------|-----------|
| `/api/v1/brain/stats` | 200 ✅ | 200 |
| `/api/v1/autofix/health` | 200 ✅ | 200 |
| `/api/v1/mpte/stats` | 200 ✅ | 200 |
| `/api/v1/micro-pentest/health` | 200 ✅ | 200 |
| `/api/v1/mcp/tools` | 200 ✅ | 200 |
| `/api/v1/knowledge-graph/status` | 200 ✅ | 200 |
| `/api/v1/sast/status` | 200 ✅ | 200 |
| `/api/v1/search` | **200 ✅** | **500 ❌** |
| `/api/v1/compliance-engine/frameworks` | 200 ✅ | 200 |
| `/api/v1/evidence/` | 200 ✅ | 200 |
| `/api/v1/cases` | 200 ✅ | 200 |
| `/openapi.json` | 200 ✅ | 200 |

---

## SECURITY ADVISORY STATUS (SEC-ADV-001)

| Action | Status | Owner |
|--------|--------|-------|
| .gitignore updated | ✅ | agent-doctor |
| .env untracked | ✅ | agent-doctor |
| .env.example created | ✅ | devops-engineer |
| Docker safe defaults | ✅ | devops-engineer |
| CI placeholder tokens | ✅ | devops-engineer |
| Dockerfile non-root | ✅ | devops-engineer |
| Random token generation | ✅ | devops-engineer |
| mpte_router placeholder removed | ✅ | agent-doctor |
| **OpenAI key rotation** | ⚠️ PENDING | **CEO** |
| **Strong JWT secret** | ⚠️ PENDING | **backend-hardener** |
| Pre-commit hook | ⏰ Sprint 3 | devops-engineer |

**Risk**: MEDIUM (keys removed from git index, exist only in history)

---

## DATA-FLOW REMINDER

- context-engineer produces: codebase-map.json, briefing, architecture-context.md
- vision-agent produces: vision-alignment, vision-preflight
- agent-doctor produces: health-dashboard.json, health-report
- qa-engineer produces: quality-gate.json, iteration verdicts, failure analysis
- scrum-master produces: standup, daily-demo, demo script, debate-summary, metrics, coordination-notes
- All agents READ: sprint-board.json, coordination-notes.md, this file

---

## SUCCESS CRITERIA FOR DAY 3

1. **DEMO-002**: Postman pass rate ≥ 95% (currently 84.7%)
2. **DEMO-003**: At least Dashboard + Remediation pages wired to real API data
3. **No regressions**: All 10 completed DEMO items still pass
4. **Sprint board**: 11/12 or 12/12 done

If both DEMO-002 and DEMO-003 complete Day 3:
- Day 4 = Polish + dress rehearsal
- Day 5 = Final rehearsal + backup plans
- Day 6 (2026-03-06) = ENTERPRISE DEMO

---
*Coordination notes by scrum-master | 2026-03-02 10:23 | Pillars: [V3] [V5] [V7] [V10]*
