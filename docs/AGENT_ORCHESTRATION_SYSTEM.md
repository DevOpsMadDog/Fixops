# ALdeci Agent Orchestration System — Tandem Design

> **Purpose**: This document defines how all 16 AI agents + 30 junior swarm workers operate as a unified virtual company. Not 16 independent scripts — one organism.
>
> **Key insight**: The orchestrator currently runs agents in phases with dependency ordering, but agents are stateless between runs, don't reference the vision, don't share memory, and don't validate vision alignment. This document fixes all of that.
>
> **References**: CEO_VISION.md (north star), VISION_TO_ACCOMPLISH.MD (build spec), context_log.md (session memory)

---

## 1. Current State Assessment

### What Exists (Strong Foundation)
| Component | Status | Quality |
|-----------|--------|---------|
| 16 agent definitions in `.claude/agents/` | ✅ Defined | Excellent — clear roles, tools, outputs |
| 10-phase orchestrator (`run-ai-team.sh`, 869 LOC) | ✅ Built | Good — dependency ordering, parallel execution |
| Junior swarm spawner (`spawn-swarm.sh`, 616 LOC) | ✅ Built | Good — 30-worker parallel, wave-based |
| 5-tier runtime budget (`budget-config.sh`, 176 LOC) | ✅ Built | Good — Claude/Codex/Grok/Copilot/Ollama |
| Debate protocol with VETO power | ✅ Designed | Good — structured, evidence-based |
| Coordination notes (data flow contracts) | ✅ Documented | Excellent — every agent→output→consumer mapped |
| Team state directory structure | ✅ Created | Good — all dirs exist |

### What's Missing (Critical Gaps)

| Gap | Impact | Fix |
|-----|--------|-----|
| **No vision alignment** | Agents work in isolation, not toward pillars | Add vision-agent, mandatory pillar tags |
| **No persistent memory** | Each run starts from zero context | Add context_log.md read at boot |
| **Sprint board stale** | Dates from Jan 2025, wrong priorities | Update from VISION_TO_ACCOMPLISH.MD |
| **Never successfully run** | All metrics zero, all statuses unknown | Bootstrap with --all --force run |
| **No automated startup** | Human must run scripts manually | Add launchd/cron automation |
| **Cost override missing** | Budget $350/mo hardcoded, CEO says uncap | Create unleashed mode |
| **No cross-run learning** | Agent Doctor reads logs but doesn't improve prompts | Add feedback-loop-agent |
| **No customer feedback input** | CEO talks to customers but no input channel | Add customer-feedback inbox |
| **Vision docs not referenced** | Agents don't read CEO_VISION.md | Add to every agent's preamble |

---

## 2. The Tandem Architecture

### 2.1 Shared Context Protocol (SCP)

Every agent, before executing its daily mission, MUST:

```
1. Read context_log.md          → "What happened before me?"
2. Read CEO_VISION.md           → "What's the north star?"
3. Read VISION_TO_ACCOMPLISH.MD → "What specifically do we build?"
4. Read sprint-board.json       → "What's the current sprint?"
5. Read briefing-{date}.md      → "What changed today?"
6. Read own-status.md           → "What did I do last time?"
```

**Implementation**: Add to every agent's `.md` file:

```markdown
## Pre-Mission Context Loading (MANDATORY)
Before ANY work, read these files in order:
1. `context_log.md` — Session log, what happened recently
2. `docs/CEO_VISION.md` — CEO's north-star vision (Sections I-XII)
3. `docs/VISION_TO_ACCOMPLISH.MD` — Complete build specification
4. `.claude/team-state/sprint-board.json` — Current sprint priorities
5. `.claude/team-state/briefing-{YYYY-MM-DD}.md` — Today's context briefing
6. `.claude/team-state/{your-name}-status.md` — Your last run's status

## Post-Mission Logging (MANDATORY)
After ALL work, append to `context_log.md`:
### [YYYY-MM-DD HH:MM] {your-name} — {ACTION_TYPE}
- **What**: {description}
- **Files touched**: {list}
- **Outcome**: SUCCESS | PARTIAL | FAILED | BLOCKED
- **Pillar(s) served**: V1-V10
```

### 2.2 Vision Bus (Event-Driven Coordination)

Instead of agents only reading static files, they publish **events** that other agents consume:

```
┌─────────────────────────────────────────────────────────┐
│                     VISION BUS                           │
│  (file-based pub/sub via .claude/team-state/events/)    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  EVENT TYPES:                                           │
│  • code-changed    → triggers QA, Security, DevOps     │
│  • test-failed     → triggers Backend/Frontend fix      │
│  • security-alert  → triggers Backend Hardener          │
│  • feature-shipped → triggers Marketing, Sales, Writer  │
│  • debate-opened   → triggers all agents in Phase 6     │
│  • vision-drift    → triggers Vision Agent escalation   │
│  • customer-feedback → triggers prioritization review   │
│  • agent-failed    → triggers Agent Doctor              │
│  • sprint-changed  → triggers all agents' context       │
│  • demo-ready      → triggers Scrum Master              │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Implementation**: Events are JSON files in `.claude/team-state/events/`:
```json
{
  "id": "evt-2026-02-27-001",
  "type": "code-changed",
  "source_agent": "backend-hardener",
  "timestamp": "2026-02-27T10:00:00Z",
  "data": {
    "files": ["suite-core/core/fail_engine.py"],
    "summary": "Implemented FAIL Engine core (1,830 LOC)",
    "pillar": "V5",
    "sprint_item": "SPRINT1-001"
  },
  "consumers": ["qa-engineer", "security-analyst", "devops-engineer"],
  "consumed_by": []
}
```

### 2.3 The Tandem Dependency Graph

This is the full dependency map — who needs what from whom:

```
                    CEO_VISION.md
                         │
                    ┌────▼────┐
                    │ VISION  │ ← New agent: validates vision alignment
                    │ AGENT   │
                    └────┬────┘
                         │
                    ┌────▼────┐
                    │ AGENT   │ ← Phase 0: health check all agents
                    │ DOCTOR  │
                    └────┬────┘
                         │
                    ┌────▼─────┐
                    │ CONTEXT  │ ← Phase 1: scan codebase, update maps
                    │ ENGINEER │
                    └──┬──┬──┬─┘
           ┌───────────┘  │  └───────────┐
     ┌─────▼─────┐  ┌────▼────┐  ┌──────▼──────┐
     │    AI      │  │  DATA   │  │ ENTERPRISE  │ ← Phase 2: parallel
     │ RESEARCHER │  │SCIENTIST│  │ ARCHITECT   │
     └─────┬─────┘  └────┬────┘  └──────┬──────┘
           │              │              │
     ┌─────▼─────┐  ┌────▼───────┐  ┌───▼──────────┐
     │ THREAT    │  │  BACKEND   │  │  FRONTEND    │ ← Phase 3: parallel
     │ ARCHITECT │  │  HARDENER  │  │  CRAFTSMAN   │
     └─────┬─────┘  └────┬───────┘  └───┬──────────┘
           │              │              │
           └──────┬───────┴──────┬───────┘
                  │              │
            ┌─────▼──────┐ ┌────▼──────────┐
            │   SWARM    │ │ 30 JUNIOR     │ ← Phase 3.5: parallel
            │ CONTROLLER │→│ WORKERS       │
            └─────┬──────┘ └────┬──────────┘
                  │              │
           ┌──────▼───────┬─────▼─────────┐
     ┌─────▼─────┐  ┌────▼────┐           │
     │ SECURITY  │  │   QA    │           │ ← Phase 4: validate
     │ ANALYST   │  │ENGINEER │           │
     └─────┬─────┘  └────┬────┘           │
           │              │               │
           └──────┬───────┘               │
            ┌─────▼──────┐                │
            │  DEVOPS    │ ← Phase 5: infrastructure
            │  ENGINEER  │                │
            └─────┬──────┘                │
                  │                       │
            ══════▼═══════                │
            ║  DEBATE    ║ ← Phase 6: all agents argue
            ║  ROUND     ║
            ══════┬═══════
                  │
     ┌────────────┼────────────┐
┌────▼─────┐ ┌───▼──────┐ ┌───▼──────┐
│MARKETING │ │TECHNICAL │ │  SALES   │ ← Phase 7: go-to-market
│  HEAD    │ │ WRITER   │ │ ENGINEER │
└────┬─────┘ └───┬──────┘ └───┬──────┘
     │            │            │
     └────────────┼────────────┘
            ┌─────▼──────┐
            │   SCRUM    │ ← Phase 8: coordinate, demo
            │   MASTER   │
            └─────┬──────┘
                  │
            ┌─────▼──────┐
            │   AGENT    │ ← Phase 9: post-mortem
            │   DOCTOR   │
            └─────┬──────┘
                  │
            ┌─────▼──────┐
            │  VISION    │ ← Phase 10 (NEW): alignment check
            │  AGENT     │
            └────────────┘
```

### 2.4 Cross-Agent Data Contracts (Upgraded)

Every agent produces typed outputs. Consumers declare what they need.

| Producer | Output | Type | Consumers |
|----------|--------|------|-----------|
| Vision Agent | `vision-alignment-{date}.json` | JSON | ALL agents, CEO |
| Context Engineer | `codebase-map.json` | JSON | ALL agents |
| Context Engineer | `briefing-{date}.md` | MD | ALL agents |
| AI Researcher | `research/pulse-{date}.md` | MD | Marketing, Data Sci, Scrum |
| Data Scientist | `data-science/daily-intel.json` | JSON | Security, Backend |
| Data Scientist | `data-science/consensus-calibration.json` | JSON | Enterprise Arch |
| Enterprise Architect | `architecture/adrs/ADR-NNN.md` | MD | ALL builders |
| Enterprise Architect | `architecture/tech-debt.json` | JSON | Backend, Scrum |
| Backend Hardener | CODE CHANGES | Python | QA, Security, DevOps |
| Frontend Craftsman | CODE CHANGES | TSX | QA, Sales |
| Threat Architect | `threat-architect/feeds/*.json` | JSON | Backend, APIs |
| Security Analyst | `security-dashboard.json` | JSON | Scrum, Enterprise |
| Security Analyst | `compliance-matrix.json` | JSON | Marketing, Sales |
| QA Engineer | `quality-gate.json` | JSON | Scrum, DevOps |
| QA Engineer | TEST FILES | Python | Backend, Frontend |
| DevOps Engineer | INFRA CHANGES | Docker/CI | Context, Sales |
| Swarm Controller | `swarm/task-queue.json` | JSON | Juniors, Agent Doctor |
| Marketing Head | `marketing/content/` | MD | Writer, Scrum |
| Technical Writer | `docs/*.md` | MD | Sales, Marketing |
| Sales Engineer | `sales/demo-scripts/` | MD | Scrum |
| Scrum Master | `sprint-board.json` | JSON | ALL agents |
| Scrum Master | `daily-demo-{date}.md` | MD | CEO |
| Agent Doctor | `health-dashboard.json` | JSON | Scrum, DevOps |
| ALL agents | `{agent}-status.md` | MD | Scrum, Agent Doctor |
| ALL agents | `context_log.md` (append) | MD | ALL agents |

---

## 3. New Agent: Vision Agent

### Role
The Vision Agent ensures every agent's work aligns with the CEO's vision and the 10 pillars. It runs at Phase 0 (with Agent Doctor) and Phase 10 (after everything).

### What It Does
1. **Pre-run (Phase 0)**: Reads sprint-board.json and validates every item maps to V1-V10
2. **Post-run (Phase 10)**: Reads all agent status files and checks work aligned with vision
3. **Drift detection**: Compares actual work done vs planned sprint items
4. **Pillar coverage**: Tracks which pillars are getting attention this sprint
5. **CEO briefing**: Produces vision-alignment-{date}.json for CEO review

### Output
```json
{
  "date": "2026-02-27",
  "overall_alignment": 0.85,
  "pillar_coverage": {
    "V1": {"items": 2, "progress": 0.4},
    "V2": {"items": 1, "progress": 0.2},
    "V3": {"items": 3, "progress": 0.6},
    "V5": {"items": 2, "progress": 0.3},
    "V7": {"items": 1, "progress": 0.1}
  },
  "drift_detected": [
    {"agent": "backend-hardener", "did": "refactored auth", "should": "build FAIL Engine"}
  ],
  "uncovered_pillars": ["V4", "V6", "V8", "V9", "V10"],
  "recommendation": "Sprint 1 focuses on V3/V5/V7 — V4,V6,V8 deferred to Sprint 2"
}
```

---

## 4. The Unleashed Mode

Per CEO request: override cost parameters, use best model everywhere, maximize parallelism.

### Changes from Standard Mode
| Parameter | Standard ($350/mo) | Unleashed (unlimited) |
|-----------|-------------------|----------------------|
| Model | 5-tier (Claude/Codex/Grok/Copilot/Ollama) | Claude opus everywhere |
| Schedule | Rotating (daily/MWF/TTh/Fri) | ALL agents, EVERY day |
| Juniors | 30 max, Ollama | 50 max, Claude sonnet |
| Timeout | 300-600s | 1800s (30 min) |
| Parallelism | Phase-ordered | Max parallel within phases |
| Debate | 1 round | 3 rounds until consensus |
| Verification | Grok | Claude opus |
| Sunday | OFF | ON |

### Activation
```bash
# Standard mode (budget-aware)
./scripts/run-ai-team.sh

# Unleashed mode (unlimited budget, best models)
./scripts/run-ai-team-unleashed.sh --all

# Unleashed single agent
./scripts/run-ai-team-unleashed.sh --agent backend-hardener
```

---

## 5. Memory System (Cross-Run Persistence)

### Problem
Each agent run is stateless. The agent-doctor reads logs, but agents themselves don't remember what they did.

### Solution: Three-Layer Memory

```
Layer 1: context_log.md (append-only session log)
├── Every agent appends after every run
├── Agent Doctor reads to detect patterns
├── Context Engineer reads to update briefings
└── Any agent can read to resume work

Layer 2: .claude/team-state/{agent}-memory.json (per-agent persistent state)
├── Agent's last 7 runs summarized
├── Decisions made and their outcomes
├── Known issues and workarounds
└── Learning: "what worked, what didn't"

Layer 3: .claude/team-state/institutional-knowledge.md (team-wide accumulated wisdom)
├── Patterns that work (e.g., "always run tests before committing")
├── Patterns that fail (e.g., "Ollama can't handle >5000 LOC context")
├── Customer feedback themes
├── Technical decisions and rationale
└── Updated by Context Engineer + Scrum Master
```

### Per-Agent Memory Format
```json
{
  "agent": "backend-hardener",
  "last_updated": "2026-02-27",
  "recent_runs": [
    {
      "date": "2026-02-27",
      "duration_s": 240,
      "outcome": "success",
      "files_changed": ["suite-core/core/fail_engine.py"],
      "tests_added": 3,
      "issues_found": 2,
      "issues_fixed": 2,
      "pillar": "V5"
    }
  ],
  "learnings": [
    "SQLite WAL mode required for concurrent test runs",
    "Always check imports via sitecustomize.py, never sys.path"
  ],
  "blockers_history": [],
  "confidence_areas": ["FastAPI routers", "SQLite", "pytest"],
  "struggle_areas": ["Frontend TypeScript", "Docker networking"]
}
```

---

## 6. Automated Bootstrap Sequence

### First-Time Setup (run once)
```bash
#!/bin/bash
# scripts/bootstrap-ai-team.sh

# 1. Ensure all directories exist
mkdir -p .claude/team-state/{events,architecture/adrs,architecture/reviews}
mkdir -p .claude/team-state/{research,marketing/{content,battlecards}}
mkdir -p .claude/team-state/{data-science/models,sales/{demo-scripts,poc-templates}}
mkdir -p .claude/team-state/{qa,threat-architect/{architectures,threat-models,feeds}}
mkdir -p .claude/team-state/{swarm/{assignments,outputs,verifications},debates/{active,resolved}}
mkdir -p logs/ai-team/swarm

# 2. Initialize context_log.md if missing
[[ ! -f context_log.md ]] && echo "# ALdeci Context Log" > context_log.md

# 3. Initialize metrics.json with baseline scan
python3 -c "
import subprocess, json, os, glob
# Count files and LOC
py_files = subprocess.getoutput('find suite-* -name \"*.py\" | wc -l').strip()
ts_files = subprocess.getoutput('find suite-ui -name \"*.tsx\" -o -name \"*.ts\" | wc -l').strip()
py_loc = subprocess.getoutput('find suite-* -name \"*.py\" -exec cat {} + | wc -l').strip()
ts_loc = subprocess.getoutput('find suite-ui -name \"*.tsx\" -o -name \"*.ts\" | xargs cat 2>/dev/null | wc -l').strip()
tests = subprocess.getoutput('find tests -name \"test_*.py\" | wc -l').strip()
endpoints = subprocess.getoutput('grep -r \"@.*\\.get\\|@.*\\.post\\|@.*\\.put\\|@.*\\.delete\\|@.*\\.patch\" suite-api suite-core suite-attack suite-evidence-risk suite-feeds suite-integrations 2>/dev/null | wc -l').strip()
pages = subprocess.getoutput('find suite-ui/aldeci/src/pages -name \"*.tsx\" | wc -l').strip()

metrics = {
    'project': 'ALdeci',
    'lastUpdated': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'codebase': {
        'pythonFiles': int(py_files),
        'tsFiles': int(ts_files),
        'pythonLOC': int(py_loc),
        'tsLOC': int(ts_loc),
        'testFiles': int(tests),
        'apiEndpoints': int(endpoints),
        'uiPages': int(pages)
    }
}
json.dump(metrics, open('.claude/team-state/metrics.json', 'w'), indent=2)
print(f'Metrics initialized: {py_files} py, {ts_files} ts, {py_loc} py LOC, {ts_loc} ts LOC')
"

# 4. Validate all agent files
for agent in agent-doctor swarm-controller scrum-master context-engineer \
  backend-hardener frontend-craftsman enterprise-architect threat-architect \
  ai-researcher data-scientist security-analyst qa-engineer devops-engineer \
  marketing-head technical-writer sales-engineer vision-agent; do
  if [[ ! -f ".claude/agents/${agent}.md" ]]; then
    echo "MISSING: .claude/agents/${agent}.md"
  fi
done

echo "Bootstrap complete."
```

### Daily Automated Run (launchd/cron)
```bash
# Add to crontab or launchd (already exists: scripts/com.aldeci.ai-team.plist)
# Runs at 6:00 AM local time
0 6 * * 1-6 cd /Users/devops.ai/developement/fixops/Fixops && ./scripts/run-ai-team.sh >> logs/ai-team/cron.log 2>&1
```

---

## 7. Quality Assurance Pipeline

### The Quality Gate (Upgraded)

The QA Engineer's quality gate now includes vision alignment:

```json
{
  "passed": false,
  "date": "2026-02-27",
  "criteria": {
    "all_tests_pass": false,
    "coverage_above_60": false,
    "no_critical_security": false,
    "no_regressions": true,
    "api_smoke_pass": false,
    "vision_aligned": true,
    "context_log_updated": true,
    "sprint_items_progressed": true
  },
  "verdict": "BLOCK|WARN|PASS"
}
```

### Cross-Review Matrix (Unchanged — Already Excellent)

| Agent | Reviewed By |
|-------|-------------|
| Backend Hardener | Security Analyst, QA Engineer |
| Frontend Craftsman | QA Engineer, Sales Engineer |
| Threat Architect | Security Analyst, Enterprise Architect |
| Enterprise Architect | Backend Hardener, DevOps Engineer |
| Security Analyst | Backend Hardener, Enterprise Architect |
| QA Engineer | Backend Hardener, DevOps Engineer |
| DevOps Engineer | Enterprise Architect, Security Analyst |
| Technical Writer | Marketing Head, Enterprise Architect |
| Marketing Head | Sales Engineer, AI Researcher |
| Sales Engineer | Marketing Head, Technical Writer |
| AI Researcher | Data Scientist, Security Analyst |
| Data Scientist | Enterprise Architect, AI Researcher |

---

## 8. Customer Feedback Loop

### Problem
CEO talks to customers but there's no structured way to feed insights back to agents.

### Solution: Customer Feedback Inbox

```
.claude/team-state/customer-feedback/
├── feedback-{date}-{id}.json
└── feedback-summary.json
```

```json
{
  "id": "cf-001",
  "date": "2026-02-27",
  "source": "design-partner-healthpay",
  "type": "feature-request|bug-report|praise|objection",
  "summary": "Need one-click compliance export for SOC2 auditor",
  "pillar": "V6",
  "priority": "P0",
  "action_items": [
    {"agent": "frontend-craftsman", "task": "Add export button to Comply space"},
    {"agent": "backend-hardener", "task": "Implement /api/v1/evidence/export endpoint"}
  ],
  "status": "new|assigned|in-progress|shipped|rejected"
}
```

The Vision Agent reads customer feedback and adjusts sprint priorities.

---

## 9. Metrics That Matter

### Daily Dashboard (generated by Scrum Master)

| Category | Metric | Source | Target |
|----------|--------|--------|--------|
| **Code** | Total LOC | Context Engineer | Track |
| **Code** | Test coverage % | QA Engineer | >60% → 80% |
| **Code** | Tests passing | QA Engineer | 100% |
| **Code** | Security issues | Security Analyst | <5 HIGH |
| **Agents** | Agents healthy | Agent Doctor | >90% |
| **Agents** | Junior pass rate | Swarm Controller | >80% |
| **Sprint** | Items completed | Scrum Master | On track |
| **Sprint** | Vision alignment | Vision Agent | >80% |
| **Demo** | Demo-ready | Scrum Master | Always |
| **Market** | Content pieces | Marketing Head | 1/week |
| **Customer** | Feedback items | CEO | 3/week |
| **Budget** | Monthly spend | Cost tracker | <$350 (or unlimited) |

---

## 10. Failure Recovery Protocol

### When an Agent Fails

```
Agent fails
  ↓
Agent Doctor detects (Phase 9)
  ↓
Diagnose root cause:
  ├── Rate limit → reduce maxTurns, add backoff
  ├── Timeout → simplify mission, split tasks
  ├── Permission → create missing dirs, fix paths
  ├── Module not found → update requirements.txt
  ├── YAML broken → regenerate frontmatter
  ├── Context overflow → reduce context, trim instructions
  └── Auth expired → re-authenticate runtime
  ↓
Apply fix automatically
  ↓
Log fix to context_log.md
  ↓
Schedule retry for next run
```

### When Multiple Agents Fail (Cascading Failure)

```
>3 agents fail in same run
  ↓
Agent Doctor: SYSTEM_DEGRADED
  ↓
Skip dependent phases (only run Phase 0-1)
  ↓
Notify CEO via context_log.md entry
  ↓
Agent Doctor attempts fixes
  ↓
Next run: --all --force (retry everything)
```

---

## 11. The Complete Agent Roster (17 Agents)

| # | Agent | Model (Unleashed) | Phase | Role Type | Critical? |
|---|-------|--------------------|-------|-----------|-----------|
| 0 | **Vision Agent** (NEW) | opus | 0, 10 | Meta | YES |
| 1 | **Agent Doctor** | opus | 0, 9 | Meta | YES |
| 2 | **Swarm Controller** | sonnet | 3.5 | Meta | No |
| 3 | **Context Engineer** | opus | 1 | Builder | YES |
| 4 | **AI Researcher** | opus | 2 | Strategist | No |
| 5 | **Data Scientist** | opus | 2 | Builder | Yes |
| 6 | **Enterprise Architect** | opus | 2 | Strategist | YES |
| 7 | **Backend Hardener** | opus | 3 | Builder | YES |
| 8 | **Frontend Craftsman** | opus | 3 | Builder | YES |
| 9 | **Threat Architect** | opus | 3 | Builder | YES |
| 10 | **Security Analyst** | opus | 4 | Validator | YES (VETO) |
| 11 | **QA Engineer** | opus | 4 | Validator | YES |
| 12 | **DevOps Engineer** | opus | 5 | Validator | Yes |
| 13 | **Marketing Head** | opus | 7 | GTM | No |
| 14 | **Technical Writer** | opus | 7 | GTM | No |
| 15 | **Sales Engineer** | opus | 7 | GTM | No |
| 16 | **Scrum Master** | opus | 8 | Coordinator | YES |

**+ 50 Junior Workers** (sonnet, Phase 3.5, parallelized)

---

## 12. Implementation Checklist

- [x] Create CEO_VISION.md
- [x] Create context_log.md
- [x] Create AGENT_ORCHESTRATION_SYSTEM.md (this document)
- [x] Create vision-agent.md
- [x] Update sprint-board.json
- [x] Create run-ai-team-unleashed.sh
- [ ] Add SCP (Shared Context Protocol) to all 16 agent .md files
- [ ] Create .claude/team-state/events/ directory
- [ ] Create per-agent memory files
- [ ] Create institutional-knowledge.md
- [ ] Create customer-feedback inbox structure
- [ ] Test unleashed orchestrator end-to-end
- [ ] Set up daily cron/launchd automation
- [ ] First full team run with --all --force

---

*This document is maintained by the Vision Agent and Scrum Master. Updated after every significant system change.*
