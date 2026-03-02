# Coordination Notes — Day 3 (2026-03-03)
# Enterprise Demo Sprint | 3 Days Remaining | 11/12 Done (91.7%)

> **Updated by**: CEO / Team Lead (2026-03-03 strategic review)
> **Sprint board**: sprint-board.json (source of truth)
> **Quality gate**: PASS (Newman 475/475, moat 88.95%)

## HEADLINE: 1 ITEM LEFT — FINISH DEMO-003 + SIDEBAR RESTRUCTURE + POLISH

DEMO-003 (UI wiring) is the ONLY remaining sprint item. 6 UI pages need mock-to-real API wiring.
All other 11 items DONE. 

**NEW P0 DIRECTIVE**: Sidebar must be restructured from 8 Technical Suites → 5 Workflow Spaces (Mission Control, Discover, Validate, Remediate, Comply) per VISION_TO_ACCOMPLISH.MD Section 4.2. This is a demo-blocking visual issue.

**NEW AGENT**: ux-architect created (`.claude/agents/ux-architect.md`). Phase 2.5 — audits UI information architecture BEFORE frontend-craftsman builds. Deploy after demo.

**CONTRADICTIONS FIXED (2026-03-03)**:
- `.github/copilot-instructions.md` — 12 corrections applied (aldeci-ui-new refs removed, counts updated, startup command fixed, coverage gate fixed)
- `.claude/agents/backend-hardener.md` — CSPM filename, brain_pipeline LOC, autofix LOC
- `.claude/agents/enterprise-architect.md` — connector count 7→17
- `.claude/agents/qa-engineer.md` — aldeci-ui-new reference removed
- `.claude/agents/context-engineer.md` — aldeci-ui-new/package.json reference removed

---

## Day 3 Agent Assignments

### P0 — Must Complete Day 3

| Agent | Task | Details |
|-------|------|---------|
| **frontend-craftsman** | DEMO-003: Wire 6 remaining UI pages | AttackLab, Copilot, DataFabric, IntelligenceHub, RemediationCenter, Settings. Use api.ts exports. Work in suite-ui/aldeci/ ONLY. Do NOT reference aldeci-ui-new. |
| **frontend-craftsman** | **SIDEBAR RESTRUCTURE** (P0 — pre-demo) | Rewrite `MainLayout.tsx` NavSection[] from 8 Technical Suites → 5 Workflow Spaces. See mapping below. |

#### Sidebar Restructure Mapping (MainLayout.tsx lines 74-186)

**CURRENT** (WRONG — organizes by what product can do):
```
Core (7 items) → Code Suite (6) → Cloud Suite (5) → Attack Suite (7) → 
Protect Suite (6) → AI Engine (5) → Evidence (7) → Feeds Suite (2) = 45 items in 8 groups
```

**TARGET** (CORRECT — organizes by what people need to do):
```
🎯 MISSION CONTROL — "What needs attention now?"
  ├── Command Dashboard (/) 
  ├── Executive View (/executive)
  ├── Nerve Center (/nerve-center)
  ├── Brain Pipeline (/brain-pipeline)
  ├── Exposure Cases (/exposure-cases)
  └── Live Feed (/live-feed)

🔍 DISCOVER — "What risks exist?"
  ├── Finding Explorer (/findings)
  ├── Code Scanning (/code/scanning)
  ├── Secrets Detection (/code/secrets)
  ├── IaC Scanning (/code/iac)
  ├── Container Scanning (/code/containers)
  ├── Cloud Posture (/cloud/posture)
  ├── SBOM & Inventory (/code/inventory)
  ├── Knowledge Graph (/knowledge-graph)
  ├── Threat Feeds (/cloud/threat-feeds)
  └── Copilot (/copilot)

⚡ VALIDATE — "Is it actually exploitable?"
  ├── MPTE Console (/attack/mpte)
  ├── Attack Simulation (/attack/simulation)
  ├── FAIL Engine (/attack/fail)
  ├── Playbooks (/protect/playbooks)
  ├── Reachability (/cloud/reachability)
  └── Attack Lab (/attack/lab)

🔧 REMEDIATE — "How do I fix it?"
  ├── Remediation Center (/protect/remediation)
  ├── AutoFix (/ai-engine/autofix)
  ├── Bulk Operations (/protect/bulk)
  ├── Collaboration (/protect/collaboration)
  ├── Workflows (/protect/workflows)
  └── Tickets (/protect/tickets)

🛡️ COMPLY — "Can I prove we're secure?"
  ├── Compliance Dashboard (/evidence/compliance)
  ├── Evidence Vault (/evidence/bundles)
  ├── Evidence Export (/evidence/export)
  ├── Audit Trail (/evidence/audit-logs)
  ├── Reports (/evidence/reports)
  └── Analytics (/evidence/analytics)
```

**Instructions**:
1. Edit `suite-ui/aldeci/src/layouts/MainLayout.tsx`
2. Replace the 8 NavSection[] groups (lines 74-186) with 5 Workflow Space groups
3. Keep ALL existing page routes — just reorganize which group they're in
4. Use icons: Target, Search, Zap, Wrench, Shield (from lucide-react)
5. Keep the existing route paths — do NOT change route URLs
6. Test: `cd suite-ui/aldeci && npm run build` must succeed

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

---

## Self-Learning Directives (NEW — prevent recurring failures)

### Problem Pattern: Contradictions Across Docs
**Root cause**: Agent defs snapshot LOC/counts at creation time, never auto-update.
**Fix**: context-engineer MUST run a contradiction check at end of every cycle:
```bash
# Check if LOC counts in agent defs match reality
wc -l suite-core/core/brain_pipeline.py  # compare vs agent defs claiming "864 LOC"
wc -l suite-core/core/autofix_engine.py  # compare vs agent defs claiming "1,260 LOC"
```
If drift >10%, update the agent def. Log the correction.

### Problem Pattern: Vision-UI Drift Goes Undetected
**Root cause**: vision-agent scored UI by LOC/errors/build, never checked information architecture.
**Fix**: vision-agent Phase 10 MUST include:
1. Extract sidebar group labels from MainLayout.tsx
2. Compare against 5 Workflow Spaces from VISION_TO_ACCOMPLISH.MD Section 4.2
3. Score: 1.0 = all 5 spaces match, 0.0 = still 8 technical suites
4. Flag score < 0.8 as CRITICAL vision drift

### Problem Pattern: Non-Existent Directory Referenced
**Root cause**: aldeci-ui-new was aspirational but never built, yet copilot-instructions directed all work there.
**Fix**: context-engineer MUST verify every file/directory referenced in copilot-instructions.md and CLAUDE.md EXISTS on disk. Non-existent paths = CRITICAL error.

### Test-to-Code Ratio (flagged by CEO)
**Finding**: Backend real code: 193K LOC. Backend test code: 187K LOC. Ratio: ~1:1.
**Assessment**: This is actually HEALTHY for a security platform. Industry standard is 1:1 to 1:3 (test:code). 
**However**: 19.25% coverage with 187K test LOC suggests many tests may be shallow/repetitive. QA engineer should audit test QUALITY not just quantity.
**Action**: qa-engineer to run `pytest --co -q | wc -l` vs `pytest -x --tb=short` and report pass rate.

## Stub Page Verification (completed 2026-03-03)
14/15 former stub pages are REAL (make real API calls, proper loading/error states).
1/15 PARTIAL: EvidenceBundles.tsx — makes real API calls but falls back to DEMO_BUNDLES with Math.random() on error.
**Action**: frontend-craftsman to remove Math.random() fallback from EvidenceBundles.tsx, show error state instead.

---

## New Systems Added (2026-03-03 — late session)

### Self-Learning Failure Memory (V8)
**Problem**: 39 fix-agent spawns historically, ALL produced 0-byte output. No learning from past failures.
**Solution**: Created `.claude/team-state/failure-ledger.json` — persistent failure memory.
- `load_failure_lessons(agent)` — injects known failure patterns into fix-agent prompts
- `record_fix_attempt(agent, ...)` — records every fix-agent outcome (success/fail/category)
- `broadcast_failure_alert(agent, ...)` — writes to `failure-alerts.md` for cross-team visibility
- Auto-creates new known patterns after 3+ recurring same-category failures
- 4 seed patterns: KP-001 EMPTY_OUTPUT, KP-002 HALLUCINATION aldeci-ui-new, KP-003 VISION_DRIFT sidebar, KP-004 CONFIG_ISSUE LOC drift
- Wired into `build_retry_context()` and `controller_spawn_fix_agent()` in `run-ctem-swarm.sh`

### Persona-API-Validator Agent (#19, Phase 4.5)
**Problem**: No validation that APIs work end-to-end for actual user personas before demo/UI wiring.
**Solution**: Created `.claude/agents/persona-api-validator.md` — runs 7 Postman collections via Newman.
- 5 personas: Sarah Chen (CISO), Raj Patel (DevSecOps), Jason Park (Pentester), Alex Rivera (SecEng), Maria Santos (Compliance)
- Maps to 5 Workflow Spaces: Mission Control, Discover, Validate, Remediate, Comply
- Outputs: `persona-api-status.md` (report), `persona-api-alerts.md` (cross-team broadcast)
- Registered in swarm script: AGENT_TURNS, AGENT_MIN_RAM, AGENT_PHASES (4.5), PHASE_DEPENDS_ON, PERSONA_TITLE, PERSONA_MARKERS, all_agents arrays

### Cross-Team Notification
5 agent definitions updated with failure-ledger + persona-api-alerts in Shared Context Protocol:
- backend-hardener, frontend-craftsman, threat-architect, sales-engineer, qa-engineer
- Each agent now reads `failure-alerts.md` and `persona-api-alerts.md` as part of SCP
