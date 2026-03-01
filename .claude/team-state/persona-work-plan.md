# Persona-Based Agent Work Plan — ALdeci CTEM+

> **Created**: 2026-02-27 | **Model**: Claude Opus 4.6 (fast mode)
> **Goal**: Each agent owns specific personas. Fix API/CLI + test + UI/UX for each persona. Run multiple times. Achieve A grade before moving to next.
> **Reference**: [docs/CHANGE_IMPACT_REPORT.md](../../docs/CHANGE_IMPACT_REPORT.md) | [docs/USER_STORY_APP_FLOW.md](../../docs/USER_STORY_APP_FLOW.md)

---

## Current State

- **Enterprise Demo**: 264/267 = 99% (3 remaining = curl SSE timeouts, not bugs)
- **Agent Health**: 5/17 completed, 12 failed (all D grade — 35%)
- **Root Cause**: Agents produce empty/fake output, no real API/CLI work

---

## Execution Strategy

1. **One agent at a time** — fix, test, verify A grade, then move to next
2. **Each agent owns specific personas** — mapped to real API endpoints, CLI commands, and UI pages
3. **A-grade criteria**: Real API calls return 200, real data flows, no stubs, tests pass
4. **Run 3x minimum** — until stable A grade per agent

---

## Priority Order (P0 → P3)

| Priority | Agent | Personas Owned | Why First |
|----------|-------|----------------|-----------|
| **P0** | backend-hardener | Ethan, Hasan | Core API fixes enable all other agents |
| **P0** | qa-engineer | — (tests all) | Test infrastructure = foundation |
| **P1** | threat-architect | Jake, Sana | MPTE + FAIL = key differentiators (V5) |
| **P1** | security-analyst | Raj, Nina, Anika, Tom | Core security workflow (V3) |
| **P1** | frontend-craftsman | Mike, Alex, Lisa | Developer experience + UI (V2) |
| **P2** | enterprise-architect | Sarah, David | CISO/VP views + architecture (V1) |
| **P2** | data-scientist | Chen, Farid, Maya, Ravi | AI/ML pipeline (V4, V8) |
| **P2** | ai-researcher | — (research) | Market intel feeds into V3 |
| **P2** | devops-engineer | Lisa, Hasan | Infrastructure (V9) |
| **P3** | context-engineer | — (meta) | Codebase knowledge graph |
| **P3** | sales-engineer | Priya, Karen | Demo/sales materials (V3, V7) |
| **P3** | marketing-head | — (GTM) | Positioning + content |
| **P3** | technical-writer | Diana | Documentation |
| **P3** | scrum-master | Derek, Olivia | Sprint coordination |
| **P3** | vision-agent | — (meta) | Vision alignment audit |
| **P3** | agent-doctor | — (meta) | Agent health monitoring |
| **P3** | swarm-controller | — (meta) | Parallel task orchestration |

---

## Detailed Agent ↔ Persona ↔ API/CLI/UI Mapping

### 1. backend-hardener (P0)
**Personas**: Ethan (Security Engineer), Hasan (Platform Admin)
**Pillars**: V2, V3, V5, V9

| Persona | API Endpoints to Verify | CLI Commands | UI Pages |
|---------|------------------------|--------------|----------|
| Ethan | `POST /api/v1/connectors/register` | `aldeci connectors list` | Connector Config |
| Ethan | `GET /api/v1/integrations` | `aldeci integrations status` | Integration Dashboard |
| Ethan | `POST /api/v1/webhooks/mappings` | `aldeci webhooks list` | Webhook Manager |
| Hasan | `GET /api/v1/admin/users` | `aldeci admin users` | Users.tsx |
| Hasan | `POST /api/v1/admin/teams` | `aldeci admin teams` | Teams.tsx |
| Hasan | `GET /api/v1/system/health` | `aldeci system health` | SystemHealth.tsx |

**A-Grade Criteria**:
- [ ] All 6 endpoints return 200 with real data
- [ ] No SQLite IntegrityError 500s (all → 409)
- [ ] Connector health_check works for all 8 connector types
- [ ] CLI commands produce formatted output
- [ ] 3 consecutive runs with 0 failures

---

### 2. qa-engineer (P0)
**Personas**: All (test infrastructure)
**Pillars**: V2, V3, V5, V10

| Task | API Endpoints | CLI | Test Files |
|------|--------------|-----|------------|
| Test coverage gate | All 267 demo endpoints | `pytest tests/` | `tests/test_*.py` |
| Postman/Newman | All router endpoints | `newman run` | `suite-integrations/postman/` |
| Regression tests | Brain, MPTE, AutoFix | `make test` | `tests/test_brain_pipeline.py` |

**A-Grade Criteria**:
- [ ] Test coverage ≥ 40% (currently 17.52%)
- [ ] All 267 demo endpoints pass (264/267 achieved + 3 SSE known)
- [ ] No new regressions introduced
- [ ] Postman collections pass against live API
- [ ] 3 consecutive `make test` runs with 0 failures

---

### 3. threat-architect (P1)
**Personas**: Jake (Red Team Lead), Sana (Threat Analyst)
**Pillars**: V1, V2, V3, V5, V10

| Persona | API Endpoints | CLI | UI Pages |
|---------|--------------|-----|----------|
| Jake | `POST /api/v1/mpte/campaigns` | `aldeci mpte run` | MPTE Console |
| Jake | `POST /api/v1/micro-pentest/assessments` | `aldeci pentest start` | Attack Simulation |
| Jake | `GET /api/v1/fail-engine/scenarios` | `aldeci fail list` | FAIL Engine |
| Jake | `POST /api/v1/attack-sim/simulate` | `aldeci attack sim` | Playbooks |
| Sana | `GET /api/v1/feeds/nvd` | `aldeci feeds nvd` | ThreatFeeds.tsx |
| Sana | `GET /api/v1/feeds/kev` | `aldeci feeds kev` | Threat Intel |
| Sana | `GET /api/v1/feeds/epss` | `aldeci feeds epss` | Daily Brief |

**A-Grade Criteria**:
- [ ] MPTE campaign creation + execution returns real results
- [ ] Micro-pentest assessment produces exploitability proof
- [ ] FAIL engine scores vulnerabilities with real FAIL metrics
- [ ] All 7 threat feed endpoints return fresh data
- [ ] TTP correlation works end-to-end
- [ ] 3 consecutive runs: all endpoints 200

---

### 4. security-analyst (P1)
**Personas**: Raj (AppSec Lead), Nina (AppSec Engineer), Anika (VM Analyst), Tom (Security Analyst)
**Pillars**: V2, V5, V6, V10

| Persona | API Endpoints | CLI | UI Pages |
|---------|--------------|-----|----------|
| Raj | `POST /api/v1/brain/ingest` | `aldeci brain ingest` | Finding Explorer |
| Raj | `GET /api/v1/brain/graph/statistics` | `aldeci brain stats` | Command Dashboard |
| Raj | `POST /api/v1/copilot/sessions` | `aldeci copilot ask` | AI Copilot |
| Nina | `GET /api/v1/sast/scan` | `aldeci sast scan` | Code Scanning |
| Nina | `POST /api/v1/autofix/suggest` | `aldeci autofix` | AutoFix |
| Anika | `GET /api/v1/findings` | `aldeci findings list` | Finding Explorer |
| Anika | `POST /api/v1/findings/deduplicate` | `aldeci dedup` | SBOM |
| Tom | `GET /api/v1/analytics/summary` | `aldeci analytics` | Risk Overview |
| Tom | `GET /api/v1/analytics/trends` | `aldeci trends` | Live Feed |

**A-Grade Criteria**:
- [ ] Brain pipeline ingests, deduplicates, and builds knowledge graph
- [ ] SAST scanner returns real findings (not stubs)
- [ ] AutoFix engine suggests code patches with confidence levels
- [ ] Copilot sessions create and respond
- [ ] Analytics endpoint returns computed metrics
- [ ] 3 consecutive runs: all endpoints 200

---

### 5. frontend-craftsman (P1)
**Personas**: Mike (Senior Dev), Alex (Junior Dev), Lisa (DevOps Lead)
**Pillars**: V2, V3, V7

| Persona | UI Pages | Components | API Dependencies |
|---------|----------|------------|-----------------|
| Mike | Remediation Center | AutoFix widget | `/api/v1/autofix/*` |
| Mike | Bulk Operations | Batch action buttons | `/api/v1/findings/bulk` |
| Alex | Finding Detail | Security Guide panel | `/api/v1/findings/{id}` |
| Alex | Collaboration | Comments, activity feed | `/api/v1/collaboration/*` |
| Lisa | IaC Scanning | Cloud miscconfig cards | `/api/v1/cspm/*` |
| Lisa | Container Security | Image scan results | `/api/v1/container/*` |

**A-Grade Criteria**:
- [ ] All 15 stub pages rebuilt with real components (not placeholder text)
- [ ] 5 Workflow Spaces navigation works (Mission Control → Discover → Validate → Remediate → Comply)
- [ ] All API calls from UI return real data
- [ ] Apple HIG design: clean typography, generous whitespace
- [ ] Responsive layout works on 1280px and 1920px
- [ ] 3 consecutive `npm run build` with 0 errors

---

### 6. enterprise-architect (P2)
**Personas**: Sarah (VP Eng), David (CISO)
**Pillars**: V1, V2, V3, V7, V9

| Persona | API Endpoints | UI Pages |
|---------|--------------|----------|
| Sarah | `GET /api/v1/reports/executive` | Executive View |
| Sarah | `GET /api/v1/analytics/roi` | SLA Dashboard |
| David | `GET /api/v1/risk/register` | Risk Overview |
| David | `POST /api/v1/policies` | Policies.tsx |
| David | `GET /api/v1/analytics/mttr` | CISO Dashboard |

**A-Grade Criteria**:
- [ ] Executive report generates real PDF/HTML
- [ ] ROI metrics compute actual savings
- [ ] Risk register shows ranked vulnerabilities with owner
- [ ] Policy engine enforces rules (block/alert/log)
- [ ] 3 consecutive runs: all endpoints 200

---

### 7. data-scientist (P2)
**Personas**: Chen (Data Scientist), Farid (LLM Analyst), Maya (Context Engineer), Ravi (Data Engineer)
**Pillars**: V3, V4, V8

| Persona | API Endpoints | CLI |
|---------|--------------|-----|
| Chen | `GET /api/v1/analytics/predictions` | `aldeci predict` |
| Chen | `GET /api/v1/self-learning/feedback` | `aldeci feedback` |
| Farid | `POST /api/v1/llm/consensus` | `aldeci llm query` |
| Farid | `GET /api/v1/llm/providers` | `aldeci llm status` |
| Maya | `GET /api/v1/brain/graph/statistics` | `aldeci context` |
| Ravi | `GET /api/v1/feeds/status` | `aldeci feeds status` |

**A-Grade Criteria**:
- [ ] ML prediction models return scored results
- [ ] LLM consensus endpoint works with ≥1 provider
- [ ] Self-learning feedback loop records and learns from outcomes
- [ ] Feed parser handles all 6 formats without error
- [ ] 3 consecutive runs: all endpoints 200

---

### 8. devops-engineer (P2)
**Personas**: Lisa (DevOps Lead), Hasan (Platform Admin)
**Pillars**: V7, V9, V10

| Task | Deliverables |
|------|-------------|
| Docker build | `docker compose up` succeeds for all tiers |
| Air-gapped packaging | All 8 native scanners work offline |
| Health monitoring | `/api/v1/system/health` returns all subsystem statuses |
| CI/CD pipeline | GitHub Actions YAML with test + build + deploy |

**A-Grade Criteria**:
- [ ] `docker compose up` boots successfully
- [ ] All 8 scanners work without internet
- [ ] Health endpoint reports per-subsystem status
- [ ] 3 consecutive builds pass

---

### 9. sales-engineer (P2)
**Personas**: Priya (CFO), Karen (Compliance Manager)
**Pillars**: V3, V5, V7, V9

| Persona | API Endpoints | UI Pages |
|---------|--------------|----------|
| Priya | `GET /api/v1/analytics/roi` | ROI Dashboard |
| Priya | `GET /api/v1/analytics/cost` | Cost Analysis |
| Karen | `GET /api/v1/compliance/status` | Compliance Dashboard |
| Karen | `POST /api/v1/evidence/bundles` | Evidence Vault |
| Karen | `GET /api/v1/evidence/export` | Evidence Export |

**A-Grade Criteria**:
- [ ] ROI metrics show real savings calculations
- [ ] Compliance status maps to HIPAA/PCI-DSS/SOC2 controls
- [ ] Evidence bundle generation produces signed, exportable packages
- [ ] 3 consecutive runs: all endpoints 200

---

### 10-17. Support Agents (P3)

| Agent | Focus | A-Grade Criteria |
|-------|-------|-----------------|
| **context-engineer** | Codebase map + CLAUDE.md accuracy | Map matches real file structure, <5% error |
| **ai-researcher** | Market intelligence briefs | 5+ actionable research items per run |
| **marketing-head** | Positioning documents | Battlecard + pitch deck + 3 blog drafts |
| **technical-writer** | API docs + user guides | API_REFERENCE.md matches actual endpoints |
| **scrum-master** | Sprint coordination | Sprint board accurate, daily demo report produced |
| **vision-agent** | Vision alignment audit | All work tagged V1-V10, no drift detected |
| **agent-doctor** | Agent health monitoring | Diagnose + fix 3+ agent failures per run |
| **swarm-controller** | Junior worker orchestration | Successfully spawn and collect 5+ parallel tasks |

---

## Execution Checklist

```
RUN ORDER:
  1. [ ] backend-hardener  → run 3x → verify A grade
  2. [ ] qa-engineer       → run 3x → verify A grade
  3. [ ] threat-architect  → run 3x → verify A grade
  4. [ ] security-analyst  → run 3x → verify A grade
  5. [ ] frontend-craftsman → run 3x → verify A grade
  6. [ ] enterprise-architect → run 3x → verify A grade
  7. [ ] data-scientist    → run 3x → verify A grade
  8. [ ] devops-engineer   → run 3x → verify A grade
  9. [ ] sales-engineer    → run 3x → verify A grade
  10. [ ] context-engineer → run 3x → verify A grade
  11. [ ] ai-researcher    → run 3x → verify A grade
  12. [ ] marketing-head   → run 3x → verify A grade
  13. [ ] technical-writer → run 3x → verify A grade
  14. [ ] scrum-master     → run 3x → verify A grade
  15. [ ] vision-agent     → run 3x → verify A grade
  16. [ ] agent-doctor     → run 3x → verify A grade
  17. [ ] swarm-controller → run 3x → verify A grade
```

---

## Grading Scale

| Grade | Score | Criteria |
|-------|-------|----------|
| **A** | 90-100% | All API endpoints 200, real data, tests pass, no stubs |
| **B** | 75-89% | Most endpoints work, minor issues |
| **C** | 60-74% | Some endpoints fail, output needs review |
| **D** | 40-59% | Significant failures, stubs present |
| **F** | <40% | Empty output, crashes, no real work |

---

## Critical Blockers to Fix Before Agent Runs

1. **run-ctem-swarm.sh env vars** — Lines 2053, 2077, 2226, 5125 spawn `uvicorn` without `FIXOPS_API_TOKEN` etc. This steals port 8000 and causes cascading failures.
2. **CLAUDECODE nested session** — Agents sometimes hit "cannot launch inside another Claude Code session". Self-healing exists but add pre-emptive `unset CLAUDECODE` in agent bootstrap.
3. **Prompt bloat** — >50KB prompts cause 0-byte output. The 50KB cap is set but SCP context accumulates on retries.

---

*Generated by Claude Opus 4.6 (fast mode) — 2026-02-27*
