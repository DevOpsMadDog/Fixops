# Coordination Notes — Day 4 (2026-03-04)
# Enterprise Demo Sprint | 2 Days Remaining | 11/12 Done (91.7%)

> **Updated by**: scrum-master (Run 6, Day 3 FINAL)
> **Sprint board**: sprint-board.json (source of truth)
> **Quality gate**: PASS (Newman 475/475, 10th consecutive green, moat 95.60%)

## HEADLINE: FINISH DEMO-003 + SIDEBAR + POLISH — 2 DAYS LEFT

DEMO-003 (UI wiring + sidebar restructure) is the ONLY remaining sprint item. All 11 other items DONE.
If DEMO-003 completes today, Day 5 is pure polish.

## Verified Working Endpoints (31/32 confirmed HTTP 200, 2026-03-03 Run 6)

### All Green (31)
health, brain/stats, autofix/health, mpte/stats, micro-pentest/health, feeds/health, fail/health, analytics/findings, cases, compliance-engine/frameworks, analytics/dashboard/overview, mcp-protocol/status, knowledge-graph/status, sast/status, dast/status, secrets/status, container/status, cspm/status, evidence/, mcp/tools, workflows, policies, reports, audit/logs, remediation/tasks, self-learning/health, zero-gravity/health, quantum-crypto/status, sandbox/health, scanner-ingest/health, ai-agent/status

### Still 404 (1)
self-learning/stats — assigned to backend-hardener (P1)

---

## Day 4 Agent Assignments

### P0 — MUST Complete Day 4

| Agent | Task | Details |
|-------|------|---------|
| **frontend-craftsman** | DEMO-003: Wire 6 remaining UI pages | AttackLab, Copilot, DataFabric, IntelligenceHub, RemediationCenter, Settings. Use api.ts exports. Work in suite-ui/aldeci/ ONLY. |
| **frontend-craftsman** | SIDEBAR RESTRUCTURE (P0) | Rewrite MainLayout.tsx NavSection[] from 8 Technical Suites to 5 Workflow Spaces. See coordination-notes-day3.md for full mapping. Icons: Target, Search, Zap, Wrench, Shield (lucide-react). Do NOT change route URLs. Build must succeed. |
| **frontend-craftsman** | Remove Math.random() fallback | EvidenceBundles.tsx uses DEMO_BUNDLES with Math.random() on error. Replace with proper error state. |

### P1 — Demo Polish

| Agent | Task | Details |
|-------|------|---------|
| **backend-hardener** | Fix self-learning/stats 404 | Only remaining broken endpoint. Add /stats endpoint to self-learning router. Also continue security hardening. |
| **qa-engineer** | Newman run 10 + DEMO-003 verification | Maintain Newman streak. Once frontend-craftsman wires pages, verify they load real data. Push toward 25% coverage. |
| **threat-architect** | Final demo rehearsal | Run ctem-investor-demo.sh and mpte-sandbox-demo.sh. Verify all 191+ steps still pass. |
| **security-analyst** | Final security sweep | Bandit scan, pip-audit, SEC-ADV-001 status check. Last security gate before demo. |
| **devops-engineer** | Docker validation + demo-start.sh | Verify all compose files. Run demo-start.sh --check. Air-gapped test. |
| **data-scientist** | ML validation + threat intel | SHAP regression, golden test (75 cases), EPSS/KEV/NVD refresh. |

### P2 — Support

| Agent | Task |
|-------|------|
| **enterprise-architect** | Final ADR review, tech debt assessment, architecture accuracy |
| **marketing-head** | Demo talking points v6 with Day 3 metrics, investor one-pager refresh |
| **sales-engineer** | Persona script rehearsal against live API (verify all endpoints still work) |
| **technical-writer** | API docs accuracy check (verify curl examples against live server) |
| **ai-researcher** | Daily Pulse, CVE/KEV/EPSS fetch, KG data freshness |
| **context-engineer** | v31 codebase scan, CLAUDE.md metrics update, contradiction check |
| **agent-doctor** | Health check, DB/WAL maintenance, fix swarm startup failures |
| **swarm-controller** | Investigate 6 agent startup failures from Day 2 late swarm. Fix and re-run. |
| **vision-agent** | Post-flight alignment check. Verify sidebar restructure against 5-Space vision. |

---

## Swarm Infrastructure Issue (ACTION NEEDED)

6 agents failed in the Day 2 late swarm run (all 34-37s duration, 3 attempts each):
- qa-engineer, security-analyst, devops-engineer, marketing-head, sales-engineer, technical-writer

**Root cause**: Likely swarm startup infrastructure issue (all failed in identical pattern). None of these are code failures.

**Action**: swarm-controller and agent-doctor must investigate and fix before Day 4 swarm run. Check:
1. Is the startup script properly initializing agent environments?
2. Are there resource limits causing early termination?
3. Is there a rate-limiting issue with the swarm orchestrator?

---

## DEMO-003 Page-to-Endpoint Mapping (for frontend-craftsman)

| UI Page | Primary API Endpoint | Response Shape |
|---------|---------------------|---------------|
| AttackLab | /api/v1/mpte/stats, /api/v1/fail/health | JSON objects |
| Copilot | /api/v1/mcp/tools, /api/v1/mcp-protocol/status | Array of tools, status object |
| DataFabric | /api/v1/knowledge-graph/status, /api/v1/feeds/health | Status objects |
| IntelligenceHub | /api/v1/analytics/dashboard/overview, /api/v1/feeds/health | Dashboard object |
| RemediationCenter | /api/v1/remediation/tasks, /api/v1/autofix/health | Tasks array, health object |
| Settings | /api/v1/users, /api/v1/teams | User/team arrays |

**Important**: Check response shape carefully. Backend often returns `{items: [...]}` but UI might expect a flat array. Use api.ts helper functions for consistent handling.

---

## Quality Metrics Snapshot (2026-03-03 Run 6 — FINAL)
- Newman: 475/475 (10th consecutive green, 0 regressions)
- Tests: 13,614+ collected
- Coverage: ~21% (moat: 95.60% — all 19/19 above 80%, 6 at 100%)
- Endpoints: 31/32 verified 200 (only self-learning/stats 404)
- Bandit: 0 HIGH findings
- Security score: 95 (SecurityHeadersMiddleware added)
- TS errors: 0
- Build: passing
- Docker: 10/11 compose files valid
- Customer sims: 8/8 PASS
- Vision alignment: 0.85 (STABLE)

## Critical Rules (Unchanged)
1. DO NOT build aldeci-ui-new — it does NOT exist
2. DO NOT write Python unit tests for coverage — use Postman/Newman
3. Work in suite-ui/aldeci/ for all UI work
4. Use FIXOPS_API_TOKEN from .env for auth
5. If you change an API endpoint, update Postman collections immediately

## SEC-ADV-001: MEDIUM — All infra done. CEO must rotate OpenAI key.
## DEBATE-001: RESOLVED — Defer SQLite to PostgreSQL to Sprint 3+.
