# ALdeci Multi-Agent Debate Protocol

## Overview

Inspired by OpenClaw's multi-agent debate system, ALdeci agents don't just work
in silos — they **discuss, challenge, and refine** each other's decisions through
a structured debate protocol. This produces better outcomes than any single agent
could achieve alone.

## How It Works

### 1. Proposal Phase (during regular work)
Any agent can write a proposal to `.claude/team-state/debates/active/`:

```markdown
<!-- debate-{id}.md -->
# DEBATE-{id}: {Title}

## Metadata
- **Proposed by:** {agent-name}
- **Date:** {YYYY-MM-DD}
- **Category:** architecture | security | feature | process | quality
- **Priority:** P0 (blocking) | P1 (important) | P2 (nice-to-have)
- **Status:** open | voting | resolved | escalated
- **Reviewers needed:** {agent1}, {agent2}

## Proposal
{What the agent wants to do/change}

## Evidence
{Data, metrics, or findings supporting the proposal}

## Trade-offs
{What we gain vs what we lose}

## Responses
<!-- Other agents append their responses below -->
```

### 2. Response Phase (debate round)
During the debate phase of orchestration, each agent:
1. Reads ALL active debates in `debates/active/`
2. Writes responses using one of these stances:

```markdown
### Response from {agent-name} — {STANCE}
**Stance:** SUPPORT | CHALLENGE | MODIFY | ABSTAIN
**Argument:** {why}
**Evidence:** {data}
**Counter-proposal (if MODIFY):** {alternative}
```

### 3. Resolution Phase
The **Scrum Master** tallies votes and resolves debates:

| Outcome | Condition |
|---------|-----------|
| **ACCEPTED** | Majority SUPPORT + no CRITICAL CHALLENGE |
| **MODIFIED** | Majority MODIFY + consensus on alternative |
| **REJECTED** | Majority CHALLENGE |
| **ESCALATED** | No consensus after 2 rounds → founder decides |

Resolved debates move to `debates/resolved/` with resolution notes.

### 4. Debate Categories

| Category | Primary Debaters | Typical Topics |
|----------|-----------------|----------------|
| Architecture | Enterprise Architect, Backend Hardener, DevOps | Database choice, module boundaries, API design |
| Security | Security Analyst, Backend Hardener, QA | Vulnerability prioritization, auth strategy |
| Feature | Frontend Craftsman, Sales Engineer, Marketing | What to build next, UX decisions |
| Quality | QA Engineer, Backend Hardener, Enterprise Architect | Test coverage targets, tech debt priority |
| Process | Scrum Master, all agents | Sprint planning, workflow changes |
| Data | Data Scientist, AI Researcher, Security Analyst | Model weights, data sources, scoring |

### 5. Debate Rules

1. **Evidence-based only** — No opinions without data
2. **Constructive challenges** — Explain WHY something is wrong + propose alternative
3. **Time-boxed** — Debates auto-escalate after 2 rounds (2 orchestrator runs)
4. **No blocking** — Work continues on the current approach while debating
5. **Scrum Master is moderator** — Not a voter (unless tie-breaking)
6. **Security overrides** — Security Analyst can VETO any proposal on security grounds
7. **Enterprise Architect has final say** on architecture decisions

### 6. Cross-Review Matrix

Every agent's output is reviewed by at least 2 others:

| Agent | Reviewed By |
|-------|-------------|
| Backend Hardener | Security Analyst, QA Engineer |
| Frontend Craftsman | QA Engineer, Sales Engineer |
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

### 7. Daily Debate Summary

The Scrum Master produces `.claude/team-state/debate-summary-{date}.md`:
```markdown
# Debate Summary — {date}

## Active Debates
| ID | Title | Proposed By | Supports | Challenges | Status |
|----|-------|-------------|----------|------------|--------|

## Resolved Today
| ID | Title | Resolution | Outcome |
|----|-------|------------|---------|

## Escalated to Founder
| ID | Title | Why |
|----|-------|-----|
```

## File Structure
```
.claude/team-state/debates/
├── active/              # Currently debated proposals
│   ├── debate-001.md
│   └── debate-002.md
├── resolved/            # Decided debates (archive)
│   └── debate-000.md
└── protocol.md          # This file
```
