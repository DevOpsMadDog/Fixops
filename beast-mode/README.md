# Beast Mode v6 — Autonomous ALDECI Development Orchestrator

Beast Mode is an autonomous AI development system that orchestrates Claude Code agents to build ALDECI (Fixops) across 10 sequential phases with 80+ parallel tasks. It runs 24/7 to accelerate development with minimal human intervention.

## Overview

**What it does:**
- Executes 10 phases sequentially, each with 5-10 parallel tasks
- Spawns Claude Code agents (`--dangerously-skip-permissions` mode) for each task
- Validates phase completion with automated gates (tests, lint, type checks, E2E personas)
- Tracks progress, logs errors, and auto-retries failed tasks (3x max)
- Provides real-time terminal dashboard and JSON status API

**Architecture:**
- **Orchestrator** (`beast.py`): Loads phases, executes sequentially, manages task concurrency
- **Phase Executor**: Runs tasks in parallel (configurable concurrency), tracks state
- **Validation Gates** (`gate_runner.py`): Blocks phase progression until gates pass
- **Agent Config** (`agents/agent_config.py`): 8 specialized agents with domain expertise
- **Dashboard** (`dashboard/status.py`): Real-time progress visualization

## Quick Start

```bash
cd ~/fixops/beast-mode

# Run all phases (start from scratch)
python beast.py run

# Run single phase (e.g., Phase 3)
python beast.py run-phase 3

# View real-time status
python beast.py status

# View phase definitions
python beast.py list-phases

# View logs
tail -f logs/beast.log
```

## Configuration

Edit `beast.config.yaml`:

```yaml
fixops_path: ~/Fixops                    # Path to ALDECI codebase
claude_model: opus                       # Claude model to use
max_retries: 3                          # Retry failed tasks
task_timeout_minutes: 30                # Per-task timeout
phase_timeout_minutes: 120              # Per-phase timeout
parallel_tasks: 4                       # Concurrent task limit
log_level: INFO                         # DEBUG, INFO, WARNING, ERROR
```

## The 10 Phases

| Phase | Name | Duration | Focus |
|-------|------|----------|-------|
| 1 | Core Engine Foundation | Days 1-3 | Connector framework, TrustGraph schemas, normalizers |
| 2 | PULL Activation | Days 4-6 | Bidirectional sync, 20 connectors live, n8n |
| 3 | LLM Council + AI Pipeline | Days 7-10 | OllamaProvider, 3-stage council, Opus CTO escalation |
| 4 | Integration + Testing | Days 11-14 | Full E2E pipeline, 30 personas, benchmarks |
| 5 | Enterprise Hardening | Days 15-21 | RBAC, multi-tenancy, audit logging, encryption |
| 6 | Load Testing + Performance | Days 22-28 | k6 tests, connection pooling, caching, optimization |
| 7 | Security + Compliance | Days 29-35 | OWASP ZAP, dependency audit, SOC2, HIPAA |
| 8 | Onboarding + UX | Days 36-42 | Setup wizard, getting started guide, Copilot, polish |
| 9 | Pilot Preparation | Days 43-49 | Staging deploy, customer data import, monitoring |
| 10 | Launch | Days 50-56 | Production deploy, DNS/SSL, CDN, support workflow |

## Phase Definitions

Each phase is defined in `phases/phase_NN.yaml`:

```yaml
name: "Phase Name"
description: "What gets built"
days: "1-3"
tasks:
  - id: "1.1"
    name: "Task description"
    prompt: |
      Claude Code prompt with context and instructions...
    parallel_group: "a"        # Tasks in same group run in parallel
    timeout_minutes: 30
    depends_on: ["1.0"]        # (optional) wait for other task IDs
```

## Validation Gates

Gates run between phases to ensure quality:

- **test_gate**: Runs pytest, requires all tests pass
- **lint_gate**: Runs ruff check, zero errors allowed
- **type_gate**: Runs mypy/pyright, no type errors
- **build_gate**: Docker build success
- **persona_gate**: Persona E2E tests (all must pass)
- **custom_gate**: Arbitrary shell commands

Gates defined in `gates/phase_gates.yaml`. Example:

```yaml
phase_1:
  - type: test
    command: "cd ~/Fixops && python -m pytest tests/test_connectors.py -v"
    name: "Connector Tests"
```

## State and Progress

State saved to `logs/beast_state.json`:

```json
{
  "status": "RUNNING",
  "current_phase": 1,
  "phases": {
    "1": {
      "status": "RUNNING",
      "tasks": [
        {"id": "1.1", "status": "PASSED", "duration_seconds": 1234}
      ],
      "gate": {"status": "PASSED", "duration_seconds": 567}
    }
  },
  "start_time": "2026-04-12T10:00:00Z",
  "errors": []
}
```

## Task Status Values

- `PENDING`: Waiting to start
- `RUNNING`: Currently executing
- `PASSED`: Completed successfully
- `FAILED`: Failed (may retry)
- `BLOCKED`: Phase blocked due to gate failure
- `SKIPPED`: Not executed (dependency failed)

## Logging

All output goes to `logs/beast.log`. Console shows real-time task progress:

```
[10:05:23] Phase 1/10: Core Engine Foundation [████████░░░░░░░░░░] 45%
  Task 1.1: Wire connectors ............................ PASSED (145s)
  Task 1.2: Build TrustGraph ........................... RUNNING
  Task 1.3: Bridge normalizers ......................... PENDING
```

## Error Handling

- Failed tasks auto-retry up to 3x
- After 3 failures, phase marked BLOCKED
- Error details logged with timestamp and context
- SIGINT (Ctrl+C) gracefully stops, saves state
- Resumable: `python beast.py run` picks up from last phase

## Extending Beast Mode

**Add a new phase:**
1. Create `phases/phase_11.yaml` with tasks and prompts
2. Add gate definitions to `gates/phase_gates.yaml`
3. Update phase list in `beast.py`

**Add a new agent:**
1. Edit `agents/agent_config.py`, add to AGENT_TEAM
2. Reference by name in phase task prompts

**Custom gates:**
1. Extend `GateRunner` in `gates/gate_runner.py`
2. Add YAML config in `gates/phase_gates.yaml`

## Monitoring

**Live dashboard:**
```bash
python beast.py status
```

**Watch logs:**
```bash
tail -f logs/beast.log
```

**Check specific phase:**
```bash
python beast.py status --phase 3
```

## Production Notes

- Runs in `--dangerously-skip-permissions` mode (no user prompts)
- Designed for 24/7 operation on dedicated agent VM
- State recoverable: no work is lost on crash
- Parallel concurrency configurable per environment
- Model selection (Haiku/Sonnet/Opus) configurable per agent
- All prompts reference actual Fixops file paths
- Gates prevent broken code from propagating between phases

---

**Version:** 6.0  
**Last Updated:** 2026-04-12  
**Status:** Ready for autonomous experimentation
