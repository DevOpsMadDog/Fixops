# ALdeci AI Agent Swarm — Complete Operations Guide

> **Last Updated**: 2026-02-28
> **Model**: Claude Opus 4.6 (fast mode) via Claude Code CLI
> **Plan**: Claude Max (flat-rate, unlimited tokens)
> **Minimum Requirements**: macOS with 8GB+ RAM, bash 4+, Node.js 18+

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Scripts](#2-scripts)
   - [run-ctem-swarm.sh](#21-run-ctem-swarmsh--the-engine)
   - [jarvis-launcher.sh](#22-jarvis-launchersh--the-wrapper)
3. [All 17 Agents](#3-all-17-agents)
4. [Phase Execution Pipeline](#4-phase-execution-pipeline)
5. [Shared Context Protocol (SCP)](#5-shared-context-protocol-scp)
6. [Memory Management](#6-memory-management)
7. [Self-Healing & Resilience](#7-self-healing--resilience)
8. [Vision Documents](#8-vision-documents)
9. [.claude/ Directory Structure](#9-claude-directory-structure)
10. [Command Reference](#10-command-reference)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  jarvis-launcher.sh (776 LOC) — Immortal Wrapper        │
│  Auto-restart · Self-heal · Caffeinate · Slack alerts    │
│                                                          │
│  ┌───────────────────────────────────────────────────┐   │
│  │  run-ctem-swarm.sh (6,700+ LOC) — Orchestrator    │   │
│  │  11 phases · Dependency graph · Circuit breakers   │   │
│  │  5-layer hallucination protection · SCP injection  │   │
│  │                                                    │   │
│  │   Phase 0    ──►  Phase 1  ──►  Phase 2  ──►      │   │
│  │   (preflight)    (context)     (research)          │   │
│  │                                                    │   │
│  │   Phase 3    ──►  Phase 3.5 ──► Phase 4  ──►      │   │
│  │   (builders)     (swarm)       (validate)          │   │
│  │                                                    │   │
│  │   Phase 5  ──► Phase 6  ──► Phase 7  ──►          │   │
│  │   (infra)     (debate)     (go-to-market)          │   │
│  │                                                    │   │
│  │   Phase 8    ──►  Phase 9  ──►  Phase 10          │   │
│  │   (scrum)        (audit)       (post-flight)       │   │
│  └───────────────────────────────────────────────────┘   │
│                         │                                │
│         ┌───────────────┼───────────────┐                │
│         ▼               ▼               ▼                │
│   claude --agent   claude --agent   claude --agent       │
│   (Opus 4.6 fast)  (Opus 4.6 fast)  (Opus 4.6 fast)     │
└─────────────────────────────────────────────────────────┘
```

**Relationship**: `jarvis-launcher.sh` → calls → `run-ctem-swarm.sh` → calls → `claude` CLI (17 agents)

- **jarvis-launcher.sh** = ignition key + roadside assistance (keeps the engine alive)
- **run-ctem-swarm.sh** = the engine itself (orchestrates all agent work)
- **claude CLI agents** = the workers (read/write code, run tests, make decisions)

---

## 2. Scripts

### 2.1 `run-ctem-swarm.sh` — The Engine

**Location**: `scripts/run-ctem-swarm.sh`
**Size**: ~6,700 lines
**Purpose**: Orchestrate 17 AI agents through an 11-phase pipeline with self-healing, convergence loops, and hallucination protection.

#### Run Modes

| Mode | Command | Description |
|------|---------|-------------|
| **Full Swarm** | `./scripts/run-ctem-swarm.sh` | All 17 agents, 11 phases, 3 debate rounds, 3 convergence iterations |
| **War Room** | `./scripts/run-ctem-swarm.sh --war-room` | Laser-focused on shipping 3 UI screens in 30 days |
| **Single Agent** | `./scripts/run-ctem-swarm.sh --agent backend-hardener` | Run one agent with full SCP context |
| **Single Phase** | `./scripts/run-ctem-swarm.sh --phase 3` | Run one phase (e.g., builders only) |
| **Debate Only** | `./scripts/run-ctem-swarm.sh --debate` | Run vision debate (5 agents, 3 rounds) |
| **Health Check** | `./scripts/run-ctem-swarm.sh --health` | Validate all agent .md files and configs |
| **Cost Report** | `./scripts/run-ctem-swarm.sh --cost-report` | Monthly usage report (informational on Claude Max) |
| **Resume** | `./scripts/run-ctem-swarm.sh --resume` | Resume from last checkpoint after a crash |
| **Digest** | `./scripts/run-ctem-swarm.sh --digest` | Generate Daily Digest (vision/feature/quality summary) |
| **Dry Run** | `./scripts/run-ctem-swarm.sh --dry-run` | Show execution plan without running agents |

#### All CLI Options

```
--agent NAME           Run single agent with full SCP context
--phase N              Run single phase (0-10)
--war-room             90-Day War Room mode (3 UI screens focus)
--dry-run              Show plan without running agents
--debate               Run vision debate only
--health               Agent health check
--cost-report          Show usage report
--resume               Resume from last checkpoint
--digest               Generate Daily Digest report
--no-parallel          Sequential execution (good for debugging)
--verbose              Extra logging (prompts, SCP context)
--timeout SECS         Override default timeout (default: 2700 = 45 min)
--budget-cap USD       Alert threshold (informational on Claude Max)
--max-retries N        Max retries per failed agent (default: 5)
--iterations N         Number of build→test→fix iterations (default: 3)
--min-runtime H        Minimum runtime in hours before early exit (default: 10)
--no-converge          Disable convergence loop (single pass)
--newman-threshold N   Newman pass rate (%) required to exit early (default: 85)
--controller           Enable JARVIS Controller self-healing (default: on)
--no-controller        Disable JARVIS Controller
--controller-cycles N  Max fix cycles per failed agent (default: 3)
--never-give-up        Controller never abandons failed agents
```

#### Key Configuration (Lines 130-240)

| Variable | Default | Purpose |
|----------|---------|---------|
| `MODEL` | `claude-opus-4-6-fast` | Claude model for all agents |
| `TIMEOUT_DEFAULT` | 2700 (45 min) | Per-agent timeout |
| `TIMEOUT_CRITICAL` | 3600 (60 min) | Timeout for heavy agents |
| `MAX_RETRIES` | 5 | Retries per failed agent |
| `MAX_TURNS_DEFAULT` | 300 | Max Claude turns per agent |
| `MIN_MEMORY_MB` | 800 | Min free RAM to launch any agent |
| `ITERATIONS` | 3 | Build→test→fix convergence loops |
| `MIN_RUNTIME_HOURS` | 10 | Min total runtime before early exit |
| `NEWMAN_PASS_THRESHOLD` | 85% | Test pass rate to skip iterations |
| `BUDGET_CAP` | 9999 | No-op on Claude Max |
| `CIRCUIT_BREAKER_THRESHOLD` | 2 | Phase trips if ≥2 agents fail |
| `GLOBAL_FAIL_THRESHOLD` | 10 | Stop swarm if ≥10 agents fail |

#### Digest Mode (`--digest`)

Generates a Daily Digest report summarizing:
- **Vision alignment**: Which V1-V10 pillars had work done today
- **Feature progress**: Sprint board item status changes
- **Quality metrics**: Test pass rates, coverage, API health
- **Agent performance**: Who ran, duration, success/failure

Output: `.claude/team-state/daily-digest-{date}.md`

Use this at end-of-day to review what the swarm accomplished.

---

### 2.2 `jarvis-launcher.sh` — The Wrapper

**Location**: `scripts/jarvis-launcher.sh`
**Size**: 776 lines
**Purpose**: Immortal wrapper that keeps `run-ctem-swarm.sh` alive through crashes, OOM kills, and transient failures.

#### Features

| Feature | Description |
|---------|-------------|
| **Auto-restart** | Up to 10 restarts with exponential backoff (30s → 60s → 120s → 240s → 300s cap) |
| **11 Pre-flight Checks** | Bash version, shebang fix, set -e removal, directories, chmod, coreutils, Claude CLI install, auth, lock files, heartbeat cleanup |
| **Crash Diagnosis** | Reads crash log, auto-fixes: bash version, set -e, permissions, PATH, port conflicts, timeout/coreutils missing |
| **Heartbeat** | Updates `jarvis-heartbeat.json` every 60s for external monitoring |
| **Live Status Ticker** | 10s interval showing: current agent, done/fail counts, restart count, file changes |
| **Caffeinate** | Prevents macOS sleep during multi-hour runs |
| **Lock File** | Prevents duplicate launcher instances |
| **Slack Notifications** | Optional webhook for crash/completion alerts |
| **Fast Crash Detection** | Aborts after 3 consecutive crashes < 60s (config error, not transient) |
| **Circuit Breaker Awareness** | Clears stale halt state between restarts to prevent re-halts |

#### CLI Options

```
--max-restarts N       Max crash restarts (default: 10)
--slack-webhook URL    Notify on crash/completion
--dry-run              Show plan without executing
--stop                 Kill running JARVIS instance
--status               Check if JARVIS is alive + last heartbeat
--help                 Show help
-- <swarm-args>        Pass remaining args to run-ctem-swarm.sh
```

#### Recommended Launch

```bash
# In tmux (recommended — detachable)
tmux new -s jarvis './scripts/jarvis-launcher.sh 2>&1 | tee logs/jarvis.log'
# Ctrl+B, D to detach. Walk away. Come back whenever.

# Direct launch (stays in terminal)
./scripts/jarvis-launcher.sh

# With custom args passed to swarm
./scripts/jarvis-launcher.sh -- --iterations 5 --min-runtime 15

# Check status from anywhere
./scripts/jarvis-launcher.sh --status

# Stop gracefully
./scripts/jarvis-launcher.sh --stop
```

#### Status Files

| File | Purpose |
|------|---------|
| `.claude/team-state/jarvis-heartbeat.json` | Current status, PID, uptime, restart count |
| `.claude/team-state/jarvis.lock` | Prevents duplicate launchers |
| `.claude/team-state/jarvis.pid` | PID for `--stop` command |
| `logs/jarvis/crash-history.log` | Timestamped crash log with exit codes |
| `logs/jarvis/run-{N}-{timestamp}.log` | Per-run output log |

---

## 3. All 17 Agents

Agent definitions live in `.claude/agents/*.md`. Each agent runs Claude Opus 4.6 (fast mode) with `--dangerously-skip-permissions`.

### Phase 0 — Pre-flight

| # | Agent | Role | Turns | Min RAM | Vision |
|---|-------|------|-------|---------|--------|
| 1 | **vision-agent** | Vision Alignment Guardian | 50 | 400MB | V1-V10 (all) |
| 2 | **agent-doctor** | Agent Health Monitor & Fixer | 50 | 400MB | All |

- **vision-agent**: Ensures ALL work maps to CEO_VISION.md pillars. Detects vision drift, uncovered pillars, misaligned sprint items. Produces `vision-alignment-{date}.json`.
- **agent-doctor**: Reads all agent status files, detects failures/timeouts/regressions, diagnoses root causes, fixes broken configs. Also manages junior swarm workers.

### Phase 1 — Context Building

| # | Agent | Role | Turns | Min RAM | Vision |
|---|-------|------|-------|---------|--------|
| 3 | **context-engineer** | Senior Context Engineer | 200 | 600MB | All |

- Maintains codebase knowledge graph, keeps CLAUDE.md updated, maps all dependencies/data flows. Ensures every agent has perfect context before work begins.

### Phase 2 — Research (Parallel)

| # | Agent | Role | Turns | Min RAM | Vision |
|---|-------|------|-------|---------|--------|
| 4 | **ai-researcher** | AI Research Analyst | 200 | 600MB | All |
| 5 | **data-scientist** | Data Scientist | 150 | 600MB | V3, V4, V8 |
| 6 | **enterprise-architect** | Enterprise Architect | 200 | 600MB | V1, V2, V3 |

- **ai-researcher**: Daily intelligence on competitors, market trends, CVE feeds, funding landscape
- **data-scientist**: ML models for vulnerability prioritization, risk scoring, anomaly detection
- **enterprise-architect**: Architectural decisions, system design, scalability, technical roadmaps

### Phase 3 — Build + Harden (Parallel)

| # | Agent | Role | Turns | Min RAM | Vision |
|---|-------|------|-------|---------|--------|
| 7 | **backend-hardener** | Backend Hardener | 300 | 800MB | V3, V5, V9 |
| 8 | **frontend-craftsman** | Frontend Craftsman | 300 | 800MB | V7 |
| 9 | **threat-architect** | Threat Architect | 300 | 800MB | V1, V5, V10 |

- **backend-hardener**: Finds/fixes vulns, perf bottlenecks, code smells in all Python backend code. Hardens APIs, adds validation, fixes SQLi, optimizes hot paths. **Writes production code.**
- **frontend-craftsman**: Builds/polishes React UI in `aldeci-ui-new/`. Implements Figma specs, animations, responsive design. **Writes production code.**
- **threat-architect**: Builds real enterprise architectures (AWS/Azure/GCP), threat-models them (STRIDE/DREAD/MITRE ATT&CK), generates SBOMs/SARIF/CNAPP findings, feeds into ALdeci APIs. **Writes production code.**

### Phase 3.5 — Swarm Micro-Tasks

| # | Agent | Role | Turns | Min RAM | Vision |
|---|-------|------|-------|---------|--------|
| 10 | **swarm-controller** | Swarm Foreman | 100 | 500MB | All |

- Decomposes tasks from senior agents into parallelizable units, spawns 20-30+ junior workers, collects outputs, coordinates verification. The labor foreman.

### Phase 4 — Validate + Test (Parallel)

| # | Agent | Role | Turns | Min RAM | Vision |
|---|-------|------|-------|---------|--------|
| 11 | **security-analyst** | Security Analyst | 200 | 600MB | V5, V6, V10 |
| 12 | **qa-engineer** | QA Engineer | 200 | 600MB | All |

- **security-analyst**: Runs SAST/DAST on ALdeci's own codebase ("eat your own dog food"), manages vuln lifecycle, tracks compliance
- **qa-engineer**: Writes tests, runs suites, measures coverage, catches regressions. Owns the quality gate — nothing ships without QA approval.

### Phase 5 — Infrastructure

| # | Agent | Role | Turns | Min RAM | Vision |
|---|-------|------|-------|---------|--------|
| 13 | **devops-engineer** | DevOps Engineer | 150 | 600MB | V9, V10 |

- CI/CD pipelines, Docker configs, deployment scripts, monitoring. Air-gapped Docker packaging.

### Phase 7 — Go-to-Market (Parallel)

| # | Agent | Role | Turns | Min RAM | Vision |
|---|-------|------|-------|---------|--------|
| 14 | **marketing-head** | VP Marketing | 80 | 400MB | All |
| 15 | **technical-writer** | Technical Writer | 80 | 400MB | All |
| 16 | **sales-engineer** | Sales Engineer | 80 | 400MB | All |

- **marketing-head**: Positioning, messaging, pitch materials, competitive narratives
- **technical-writer**: API docs, user guides, architecture diagrams, README — investor-quality
- **sales-engineer**: Demo scripts, POC templates, customer onboarding, competitive win/loss

### Phase 8 — Coordination

| # | Agent | Role | Turns | Min RAM | Vision |
|---|-------|------|-------|---------|--------|
| 17 | **scrum-master** | Scrum Master | 100 | 500MB | All |

- Tracks all agent work, manages sprint backlog, identifies blockers, produces daily demo reports.

### Phase 9 — Post-Run Audit

- **agent-doctor** runs again — audits all agent outputs, checks for regressions

### Phase 10 — Post-Flight

- **vision-agent** runs again — validates all work aligns with V1-V10 pillars

---

## 4. Phase Execution Pipeline

### Phase Dependency Graph

```
Phase 0  (vision-agent, agent-doctor)     ← always runs
  ↓
Phase 1  (context-engineer)               ← depends on Phase 0
  ↓
Phase 2  (ai-researcher, data-scientist,  ← depends on Phase 1
           enterprise-architect)           ← PARALLEL
  ↓
Phase 3  (backend-hardener,               ← depends on Phase 1
           frontend-craftsman,             ← PARALLEL
           threat-architect)
  ↓
Phase 3.5 (swarm-controller)              ← depends on Phase 3
  ↓
Phase 4  (security-analyst, qa-engineer)  ← depends on Phase 3 ← PARALLEL
  ↓
Phase 5  (devops-engineer)                ← depends on Phase 1
  ↓
Phase 6  (debate — 3 rounds)             ← always runs
  ↓
Phase 7  (marketing, writer, sales)       ← always runs ← PARALLEL
  ↓
Phase 8  (scrum-master)                   ← always runs
  ↓
Phase 9  (agent-doctor post-audit)        ← always runs
  ↓
Phase 10 (vision-agent post-flight)       ← always runs
```

### Circuit Breaker Rules

- **Per-phase**: If ≥ 2 agents fail in one phase → trip circuit breaker, skip remaining agents in that phase
- **Global**: If ≥ 10 agents fail total → halt entire swarm
- **Cascade**: If a phase's dependency failed → skip the dependent phase (garbage-in-garbage-out prevention)

### Convergence Loop

```
Iteration 1: Build → Test → Check pass rate
Iteration 2: Fix failures from iteration 1 → Retest → Check
Iteration 3: Fix remaining → Final test
Early exit: If Newman pass rate ≥ 85%, skip remaining iterations
```

---

## 5. Shared Context Protocol (SCP)

Every agent receives a **context injection** before starting work. This is the "shared memory" of the swarm.

### 16 Data Sources (Full SCP)

| # | Source | Size | What it contains |
|---|--------|------|-----------------|
| 1 | Vision Mandate | ~500 bytes | Hardcoded: 3 Core + 4 Constraints + 3 Deferred |
| 2 | Sprint Digest | ~1 KB | Compressed sprint board (vs 17KB raw) |
| 3 | Metrics Digest | ~300 bytes | LOC, tests, coverage, endpoints (vs 8KB raw) |
| 4 | Decisions Digest | ~800 bytes | Last 5 decisions (vs 41KB raw) |
| 5 | Agent Outcomes | ~1 KB | Who ran, what happened, pass/fail |
| 6 | Agent's Own Briefing | ~1 KB | Personal memory + status + role pointers |
| 7 | Codebase Map | ~3 KB | Architecture reference from knowledge index |
| 8 | Active Debates | variable | Only if debates exist — agents must respond |
| 9 | Iteration Context | ~500 bytes | Previous test failures (fix-first on iteration 2+) |
| 10 | Coordination Pointer | ~300 bytes | Points to coordination-notes.md (not content) |
| 11 | Rules | ~500 bytes | Standard operating procedures |

### Per-Agent SCP Profiles (Optimization)

Not every agent needs all 16 sources. Lightweight agents skip irrelevant data to reduce prompt size by 30-60%:

| Agent Category | Skipped SCP Sources | Prompt Reduction |
|---|---|---|
| **Phase 0/9/10** (vision-agent, agent-doctor) | Codebase map, debates, iteration ctx | ~40% smaller |
| **Phase 7** (marketing, writer, sales) | Codebase map, iteration ctx, debates, decisions | ~60% smaller |
| **Phase 1** (context-engineer) | Debates, iteration ctx | ~20% smaller |
| **Phase 2** (researchers) | Iteration ctx | ~10% smaller |
| **Phase 3** (builders) | Full SCP — needs everything | 0% reduction |
| **Phase 4** (validators) | Full SCP — needs iteration ctx | 0% reduction |

---

## 6. Memory Management

### Per-Agent Resource Profiles

| Agent | Min RAM (Gate) | Max RAM (Limit) | Max Turns |
|-------|---------------|-----------------|-----------|
| vision-agent | 400 MB | 1,200 MB | 50 |
| agent-doctor | 400 MB | 1,200 MB | 50 |
| context-engineer | 600 MB | 1,800 MB | 200 |
| ai-researcher | 600 MB | 1,800 MB | 200 |
| data-scientist | 600 MB | 1,800 MB | 150 |
| enterprise-architect | 600 MB | 1,800 MB | 200 |
| **backend-hardener** | **800 MB** | **2,400 MB** | **300** |
| **frontend-craftsman** | **800 MB** | **2,400 MB** | **300** |
| **threat-architect** | **800 MB** | **2,400 MB** | **300** |
| swarm-controller | 500 MB | 1,500 MB | 100 |
| security-analyst | 600 MB | 1,800 MB | 200 |
| qa-engineer | 600 MB | 1,800 MB | 200 |
| devops-engineer | 600 MB | 1,800 MB | 150 |
| marketing-head | 400 MB | 1,200 MB | 80 |
| technical-writer | 400 MB | 1,200 MB | 80 |
| sales-engineer | 400 MB | 1,200 MB | 80 |
| scrum-master | 500 MB | 1,500 MB | 100 |

### Three Layers of Protection

1. **Pre-launch gate** (`pre_agent_memory_gate`): Checks free RAM ≥ `AGENT_MIN_RAM[agent]` before starting. If insufficient, attempts `purge` + kills orphan processes to reclaim. If still insufficient, agent is SKIPPED.

2. **Per-process limit** (`apply_agent_memory_limit`): Sets `ulimit -Sv` inside the subshell before launching `claude`. This is a hard ceiling — the OS kills the process if it exceeds the limit. The limit is 3× the min RAM to give headroom for Node.js growth.

3. **OOM recovery** (exit code 137): If macOS kernel kills a process, the script saves an incremental checkpoint, reduces `MAX_TURNS` by 1/3 for retries, kills orphaned processes, waits 20s for memory reclaim, then retries.

### Inter-Phase Cleanup

After each phase completes, `inter_phase_cleanup()` runs:
- Kills orphaned `node.*claude` processes from completed agents
- Runs `purge` to reclaim macOS inactive memory
- Waits 3s for OS reclamation
- Logs free RAM after cleanup

### Memory-Aware Parallelism

When launching parallel agents (Phase 2, 3, 4, 7), the script:
1. Calculates `total_ram_needed` = sum of all agents' `AGENT_MIN_RAM`
2. If `free_mb < total_ram_needed`: falls back to **sequential execution** (one agent at a time)
3. Per-agent memory gate checked before each parallel launch

---

## 7. Self-Healing & Resilience

### 5-Layer Hallucination Protection

| Layer | What | Action |
|-------|------|--------|
| 1 | **Vision Pillar Check** | Agent output must mention V3/V5/V7 core pillars |
| 2 | **Real-Time Monitor** | Watches agent logs during execution for hallucination patterns |
| 3 | **Stub Code Detection** | Rejects `return {}`, `pass # TODO`, `raise NotImplementedError` |
| 4 | **Cross-Agent Conflict** | Reject if ≥3 contradictions found between agents |
| 5 | **Code Verification** | Runs tests on builder agent code changes |

### Agent Retry with Progressive Escalation

Each agent gets 5 retry attempts with:
- **Exponential backoff**: 15s → 30s → 60s → 120s → 240s
- **Progressive context**: Each retry injects the specific failure reason
- **OOM healing**: On exit code 137, reduces turns by 1/3 and waits for memory

### Crash Recovery

- `cleanup_on_crash()`: Saves full state to `crash-state.json` on any non-zero exit
- `--resume`: Reads crash state + agent checkpoints, skips completed agents
- Stale prompt.tmp files cleaned automatically

### JARVIS Controller (Reconciliation Loop)

When enabled (`--controller`), runs every 30s in background:
- Probes API health
- Detects failed agents
- Spawns fix-agents to repair failures (up to 3 fix cycles per agent)
- With `--never-give-up`: retries forever until it works

---

## 8. Vision Documents

| Document | Location | Purpose |
|----------|----------|---------|
| **CEO_VISION.md** | `docs/CEO_VISION.md` | Foundational vision document. Every agent reads this. |
| **VISION_TO_ACCOMPLISH.MD** | `docs/VISION_TO_ACCOMPLISH.MD` | Complete technical spec: 10 pillars, 25 personas, sprint plan, architecture, UI specs (~2,200 lines) |
| **CTEM_PLUS_IDENTITY.md** | `docs/CTEM_PLUS_IDENTITY.md` | Scanner/AutoFix/Pipeline reference. 8 native scanners, AutoFix engine, 12-step brain pipeline. |
| **VISION_DEBATE_TRANSCRIPT.md** | `docs/VISION_DEBATE_TRANSCRIPT.md` | 5-agent debate verdict. Restructured vision into 3 Core + 4 Constraints + 3 Deferred. |

### Vision Structure (Post-Debate)

```
3 CORE PILLARS (active investment):
  V3 — Decision Intelligence (brain pipeline, risk scoring)
  V5 — MPTE Verification (prove exploitability)
  V7 — MCP-Native Platform (AI agent integration)

4 DESIGN CONSTRAINTS (maintained, not actively built):
  V1 — APP_ID-Centric Architecture
  V2 — 10-Phase Security Lifecycle
  V9 — Air-Gapped / On-Prem Deployment
  V10 — CTEM Full Loop with Cryptographic Proof

3 DEFERRED (do NOT build this sprint):
  V4 — Multi-LLM Consensus
  V6 — Quantum-Secure Evidence
  V8 — Self-Learning Feedback Loops
```

---

## 9. `.claude/` Directory Structure

```
.claude/
├── agents/                     # 17 agent definition .md files
│   ├── vision-agent.md
│   ├── agent-doctor.md
│   ├── context-engineer.md
│   ├── ai-researcher.md
│   ├── data-scientist.md
│   ├── enterprise-architect.md
│   ├── backend-hardener.md
│   ├── frontend-craftsman.md
│   ├── threat-architect.md
│   ├── swarm-controller.md
│   ├── security-analyst.md
│   ├── qa-engineer.md
│   ├── devops-engineer.md
│   ├── marketing-head.md
│   ├── technical-writer.md
│   ├── sales-engineer.md
│   ├── scrum-master.md
│   └── templates/              # Agent file templates
│
├── team-state/                 # Shared state (communication layer)
│   ├── sprint-board.json       # Sprint backlog (17KB)
│   ├── metrics.json            # Project metrics (8KB)
│   ├── decisions.log           # Autonomous decisions log (41KB)
│   ├── coordination-notes.md   # Inter-agent data-flow contracts (9KB)
│   ├── crash-state.json        # Last crash state (for --resume)
│   ├── jarvis-heartbeat.json   # Launcher heartbeat
│   ├── jarvis.lock             # Launcher lock file
│   ├── jarvis.pid              # Launcher PID
│   ├── *-status.md             # Per-agent status files
│   ├── *-memory.json           # Per-agent persistent memory
│   ├── agent-performance.json  # Historical speed/quality per agent
│   ├── health-dashboard.json   # Agent health dashboard
│   ├── .jarvis-current-agent   # Currently running agent name
│   ├── telemetry-*.jsonl       # CPU/memory/disk snapshots
│   ├── swarm-halted.json       # Circuit breaker halt state
│   ├── qa/                     # QA iteration results
│   ├── debates/                # Debate state
│   │   ├── active/*.md         # Open debates (agents must respond)
│   │   └── resolved/*.md       # Closed debates
│   ├── architecture/           # ADRs and architecture reviews
│   ├── research/               # ai-researcher outputs
│   ├── marketing/              # marketing-head outputs
│   ├── sales/                  # sales-engineer outputs
│   ├── data-science/           # data-scientist models
│   ├── threat-architect/       # Architectures, threat models, feeds
│   └── swarm/                  # Swarm worker assignments + outputs
│
├── knowledge-index/            # Compact digests (generated)
│   ├── sprint-digest.json      # 1KB vs 17KB raw sprint board
│   ├── metrics-digest.json     # 300B vs 8KB raw metrics
│   ├── decisions-digest.json   # 800B vs 41KB raw decisions
│   ├── agent-outcomes.json     # Who ran, what happened
│   ├── codebase-map.json       # Architecture reference
│   └── {agent}-briefing.json   # Per-agent briefing
│
├── checkpoints/                # Incremental checkpoints (OOM recovery)
│   └── *.oom                   # OOM kill checkpoints
│
├── agent-memory/               # Agent persistent memory (cross-run)
│
└── guardian/                   # Vision guardian state
```

---

## 10. Command Reference

### Quick Start

```bash
# Full swarm (recommended first run)
./scripts/run-ctem-swarm.sh

# With jarvis wrapper (recommended for overnight runs)
tmux new -s jarvis './scripts/jarvis-launcher.sh 2>&1 | tee logs/jarvis.log'

# Single agent for debugging
./scripts/run-ctem-swarm.sh --agent backend-hardener --verbose

# Preview without running
./scripts/run-ctem-swarm.sh --dry-run
```

### Common Operations

```bash
# Resume after crash
./scripts/run-ctem-swarm.sh --resume

# Generate end-of-day summary
./scripts/run-ctem-swarm.sh --digest

# Run specific phase only
./scripts/run-ctem-swarm.sh --phase 3          # builders only
./scripts/run-ctem-swarm.sh --phase 4          # validators only

# Override convergence settings
./scripts/run-ctem-swarm.sh --iterations 5 --min-runtime 15  # 5 loops, 15hr min
./scripts/run-ctem-swarm.sh --no-converge                     # single pass

# Sequential mode (debug memory issues)
./scripts/run-ctem-swarm.sh --no-parallel --verbose

# War room (ship 3 UI screens)
./scripts/run-ctem-swarm.sh --war-room
```

### JARVIS Operations

```bash
# Check if running
./scripts/jarvis-launcher.sh --status

# Stop gracefully
./scripts/jarvis-launcher.sh --stop

# Launch with Slack notifications
./scripts/jarvis-launcher.sh --slack-webhook https://hooks.slack.com/services/...

# More restarts for long runs
./scripts/jarvis-launcher.sh --max-restarts 20

# Pass args through to swarm
./scripts/jarvis-launcher.sh -- --war-room --iterations 5
```

---

## 11. Troubleshooting

### Common Issues

| Problem | Cause | Fix |
|---------|-------|-----|
| "declare: -A: invalid option" | macOS system bash (3.x) | `brew install bash` — jarvis auto-fixes this |
| OOM kills (exit 137) | Agent exceeds memory | Script auto-heals: reduces turns, waits, retries |
| "Claude CLI not found" | PATH issue after crash | Jarvis auto-fixes: searches common paths |
| Port 8000 in use | Stale server process | Jarvis auto-fixes: kills process on port |
| Swarm halts immediately on `--resume` | Stale `swarm-halted.json` | `rm .claude/team-state/swarm-halted.json` |
| 3 consecutive fast crashes | Config error, not transient | Check `logs/jarvis/run-*.log` for root cause |
| Agent produces 0-byte output | Prompt too large (>50KB) | Auto-truncated; if persistent, check SCP injection |

### Checking Agent State

```bash
# Which agents completed?
grep -l "✅ Completed" .claude/team-state/*-status.md

# Which agents failed?
grep -l "❌ Failed" .claude/team-state/*-status.md

# Last crash state
cat .claude/team-state/crash-state.json

# Agent performance history
cat .claude/team-state/agent-performance.json | python3 -m json.tool

# OOM kill history
ls .claude/checkpoints/*.oom 2>/dev/null
```

### Logs

```
logs/ai-team/           # Per-agent run logs (date_agent_runid.log)
logs/jarvis/            # Launcher logs + crash history
.claude/team-state/     # Status files, metrics, decisions
```

---

## Appendix: Claude Max Considerations

On Claude Max (flat-rate):
- **Token budget**: Unlimited — `BUDGET_CAP=9999` is a no-op
- **Turn limits**: Free — keep `MAX_TURNS=300` for builders
- **Iterations**: Free — 3 convergence loops cost $0
- **Real constraint**: Your Mac's **physical RAM** and Anthropic's **per-minute rate limits**
- **Time**: Full swarm takes 10+ hours (`MIN_RUNTIME_HOURS=10`)

To maximize throughput: ensure 16GB+ RAM for parallel phases (3 agents × 800MB = 2.4GB).
