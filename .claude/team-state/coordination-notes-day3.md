# Coordination Notes — Day 3 (2026-03-03)
# Enterprise Demo Sprint | 3 Days Remaining | 11/12 Done (91.7%)

> **Updated by**: scrum-master (Run 4, 2026-03-02)
> **Sprint board**: sprint-board.json (source of truth)
> **Quality gate**: PASS (Newman 475/475, moat 88.95%)

## HEADLINE: 1 ITEM LEFT — FINISH DEMO-003 + POLISH EVERYTHING

DEMO-003 (UI wiring) is the ONLY remaining sprint item. 6 UI pages need mock-to-real API wiring.
All other 11 items DONE. Day 3 priority: complete DEMO-003 and polish the entire demo.

---

## Day 3 Agent Assignments

### P0 — Must Complete Day 3

| Agent | Task | Details |
|-------|------|---------|
| **frontend-craftsman** | DEMO-003: Wire 6 remaining UI pages | AttackLab, Copilot, DataFabric, IntelligenceHub, RemediationCenter, Settings. Use api.ts exports. Work in suite-ui/aldeci/ ONLY. Do NOT reference aldeci-ui-new. |

### P1 — Demo Polish

| Agent | Task | Details |
|-------|------|---------|
| **backend-hardener** | Fix 3 minor 404s + hardening | self-learning/stats, self-learning/health, zero-gravity/health. Add status/health endpoints. Continue security pass. |
| **qa-engineer** | Coverage push + Newman run 9 | Push toward 25% gate. Maintain Newman streak. Verify DEMO-003 pages once wired. |
| **threat-architect** | Demo script rehearsal | Verify ctem-investor-demo.sh and mpte-sandbox-demo.sh against live API. |
| **devops-engineer** | Docker final validation | All compose files, demo-start.sh, air-gapped test. |
| **security-analyst** | Final security sweep | Bandit, pip-audit, compliance matrix, SEC-ADV-001 monitoring. |
| **data-scientist** | ML final validation | SHAP in brain pipeline, golden regression (75 cases), threat intel refresh. |

### P2 — Support

| Agent | Task |
|-------|------|
| **enterprise-architect** | Tech debt review, ADR updates, architecture doc accuracy |
| **marketing-head** | Demo talking points final polish, LOC verification |
| **sales-engineer** | Persona script rehearsal against current API routes |
| **technical-writer** | API docs accuracy check against live endpoints |
| **ai-researcher** | Daily Pulse, KG data refresh, CVE/KEV/EPSS fetch |
| **context-engineer** | v27 codebase scan, CLAUDE.md metrics update |
| **agent-doctor** | Health check, DB maintenance, WAL cleanup |
| **swarm-controller** | Available for ad-hoc lint fixes, test runs |

---

## Verified Working Endpoints (21 confirmed HTTP 200)
brain/stats, autofix/health, mpte/stats, feeds/health, mcp/tools, analytics/dashboard/overview, compliance-engine/frameworks, evidence/, sast/status, dast/status, secrets/status, container/status, cspm/status, knowledge-graph/status, mcp-protocol/status, micro-pentest/health, sandbox/health, self-learning/status, health, openapi.json, fail/health.

## Known 404s (non-critical, assigned to backend-hardener Day 3)
self-learning/stats, self-learning/health, zero-gravity/health

## Critical Rules
1. DO NOT build aldeci-ui-new — it does NOT exist
2. DO NOT write Python unit tests for coverage — use Postman/Newman
3. Work in suite-ui/aldeci/ for all UI
4. Use FIXOPS_API_TOKEN from .env for auth

## SEC-ADV-001: MEDIUM — All infra done. CEO must rotate OpenAI key.
## DEBATE-001: RESOLVED — Defer SQLite to PostgreSQL to Sprint 3+.
