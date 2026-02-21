# ALdeci AI Team — Coordination Notes (16 Agents + Junior Swarm)

## Inter-Agent Communication Protocol

Each agent reads from and writes to `.claude/team-state/`. This file
documents the data-flow contracts between agents.

### Data Flow

```
context-engineer
  └──▶ codebase-map.json          (read by: ALL agents)
  └──▶ dependency-graph.json      (read by: enterprise-architect, devops-engineer)
  └──▶ architecture-context.md    (read by: enterprise-architect, technical-writer)
  └──▶ briefing-{date}.md         (read by: ALL agents)
  └──▶ context-engineer-status.md (read by: scrum-master)

ai-researcher
  └──▶ research/aldeci-pulse-{date}.md (read by: marketing-head, data-scientist, scrum-master)
  └──▶ research/pitch-data.json        (read by: marketing-head, sales-engineer)
  └──▶ ai-researcher-status.md         (read by: scrum-master)

data-scientist
  └──▶ data-science/daily-intel.json          (read by: security-analyst, backend-hardener)
  └──▶ data-science/consensus-calibration.json (read by: enterprise-architect)
  └──▶ data-science/models/model_card_*.md    (read by: technical-writer)
  └──▶ data-scientist-status.md               (read by: scrum-master)

enterprise-architect
  └──▶ architecture/adrs/ADR-NNN.md         (read by: all builders, technical-writer)
  └──▶ architecture/tech-debt.json          (read by: backend-hardener, scrum-master)
  └──▶ architecture/roadmap.md              (read by: marketing-head, sales-engineer)
  └──▶ architecture/reviews/*.md            (read by: backend-hardener, security-analyst)
  └──▶ enterprise-architect-status.md       (read by: scrum-master)

backend-hardener
  └──▶ ACTUAL CODE CHANGES (suite-core/, suite-api/, suite-attack/)
  └──▶ backend-hardener-status.md   (read by: qa-engineer, scrum-master)

frontend-craftsman
  └──▶ ACTUAL CODE CHANGES (suite-ui/aldeci/)
  └──▶ frontend-inventory.json      (read by: qa-engineer, sales-engineer)
  └──▶ frontend-craftsman-status.md (read by: scrum-master)

threat-architect
  └──▶ threat-architect/architectures/arch-{day}.json  (read by: security-analyst, enterprise-architect)
  └──▶ threat-architect/threat-models/tm-{day}.json    (read by: security-analyst, data-scientist)
  └──▶ threat-architect/feeds/{sbom,cve,sarif,cnapp,vex,context}-{day}.json (read by: backend-hardener)
  └──▶ FEEDS DATA INTO ALDECI APIs (localhost:8000/inputs/*)
  └──▶ threat-architect-status.md   (read by: scrum-master)

security-analyst
  └──▶ security-dashboard.json     (read by: scrum-master, enterprise-architect)
  └──▶ compliance-matrix.json      (read by: marketing-head, sales-engineer)
  └──▶ threat-model.md             (read by: enterprise-architect)
  └──▶ security-analyst-status.md  (read by: scrum-master)

qa-engineer
  └──▶ qa-coverage.json            (read by: scrum-master)
  └──▶ qa-regression-report.md     (read by: backend-hardener, frontend-craftsman)
  └──▶ quality-gate.json           (read by: scrum-master, devops-engineer)
  └──▶ ACTUAL TEST FILES (tests/)
  └──▶ qa-engineer-status.md       (read by: scrum-master)

devops-engineer
  └──▶ dev-environment.md          (read by: context-engineer, sales-engineer)
  └──▶ ACTUAL INFRA CHANGES (Docker, CI/CD, scripts)
  └──▶ devops-engineer-status.md   (read by: scrum-master)

marketing-head
  └──▶ marketing/content/...             (read by: technical-writer, scrum-master)
  └──▶ marketing/battlecards/...         (read by: sales-engineer)
  └──▶ marketing/investor-narrative.md   (read by: sales-engineer, scrum-master)
  └──▶ marketing-head-status.md          (read by: scrum-master)

technical-writer
  └──▶ docs/API_REFERENCE.md       (read by: sales-engineer)
  └──▶ docs/USER_GUIDE.md          (read by: sales-engineer)
  └──▶ docs/ARCHITECTURE.md        (read by: enterprise-architect)
  └──▶ CHANGELOG.md                (read by: marketing-head)
  └──▶ technical-writer-status.md  (read by: scrum-master)

sales-engineer
  └──▶ sales/demo-scripts/...      (read by: scrum-master)
  └──▶ sales/poc-templates/...     (read by: marketing-head)
  └──▶ sales/objection-handling.md (read by: marketing-head)
  └──▶ sales-engineer-status.md    (read by: scrum-master)

scrum-master
  └──▶ daily-demo-{date}.md        (read by: founder/user)
  └──▶ standup-{date}.md           (read by: ALL agents)
  └──▶ debate-summary-{date}.md    (read by: ALL agents)
  └──▶ sprint-board.json           (read by: ALL agents)
  └──▶ metrics.json                (read by: ALL agents)
  └──▶ scrum-master-status.md      (self)

agent-doctor
  └──▶ health-dashboard.json       (read by: scrum-master, devops-engineer)
  └──▶ health-report-{date}.md     (read by: ALL agents)
  └──▶ health-diagnosis-{date}.md  (read by: scrum-master)
  └──▶ FIXES BROKEN AGENT CONFIGS  (.claude/agents/*.md)
  └──▶ agent-doctor-status.md      (read by: scrum-master)

swarm-controller
  └──▶ swarm/task-queue.json        (read by: agent-doctor)
  └──▶ swarm/assignments/*.json     (read by: junior workers)
  └──▶ swarm/outputs/*/status.json  (read by: senior verifiers)
  └──▶ swarm/verifications/*.json   (read by: agent-doctor, scrum-master)
  └──▶ swarm/swarm-report-{date}.md (read by: scrum-master)
  └──▶ swarm-controller-status.md   (read by: scrum-master, agent-doctor)

junior-workers (sonnet pool, 20-30+ concurrent)
  └──▶ swarm/outputs/{task-id}/status.json   (read by: swarm-controller)
  └──▶ CODE/TEST/DOC CHANGES                (verified by: opus seniors)
  └──▶ Task types: test-run, lint-fix, docs-update, code-cleanup, config-audit, data-gen
```

### Run Order (enforced by orchestrator — 10 phases)

| Phase | Agent(s)                                      | Depends On       |
|-------|-----------------------------------------------|------------------|
| 0     | agent-doctor (pre-flight health check)        | —                |
| 1     | context-engineer                              | Phase 0          |
| 2     | ai-researcher, data-scientist, enterprise-architect | Phase 1     |
| 3     | backend-hardener, frontend-craftsman, threat-architect | Phase 1, 2 |
| 3.5   | swarm-controller + junior pool (20-30+)       | Phase 3          |
| 4     | security-analyst, qa-engineer                 | Phase 1-3.5      |
| 5     | devops-engineer                               | Phase 1-4        |
| 6     | **DEBATE ROUND** (all agents review proposals)| Phase 1-5        |
| 7     | marketing-head, technical-writer, sales-engineer | Phase 1-6     |
| 8     | scrum-master                                  | Phase 1-7        |
| 9     | agent-doctor (post-run health audit + fixes)  | Phase 1-8        |

### Debate Protocol
See `.claude/team-state/debates/protocol.md` for full details.
- Proposals go to `debates/active/`
- Agents respond during Phase 6 with SUPPORT/CHALLENGE/MODIFY/ABSTAIN
- Scrum Master resolves in Phase 8
- Resolved debates move to `debates/resolved/`

### Cross-Review Matrix

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
| Context Engineer | Enterprise Architect, Scrum Master |
| Agent Doctor | Scrum Master, Enterprise Architect |
| Swarm Controller | Agent Doctor, QA Engineer |
| Junior Workers | Verified by source senior (opus 4.6) |

### Conventions
- All dates in ISO 8601: `YYYY-MM-DD`
- Status files use emoji: ✅ Completed, 🔄 Running, ❌ Failed
- JSON files must be valid JSON (agents validate before writing)
- Markdown files use ATX headings (`#`, `##`, `###`)
- Each agent writes its own `-status.md` at the end of its run
- Code-writing agents (backend-hardener, frontend-craftsman, threat-architect) create git branches
- Junior worker outputs MUST be verified by senior (opus) before merge
- Agent-doctor has authority to modify agent configs (.claude/agents/*.md)
- Swarm capacity: 30 concurrent juniors max, 10 per wave, 50 turns each
