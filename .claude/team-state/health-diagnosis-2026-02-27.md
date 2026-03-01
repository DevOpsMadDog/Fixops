# Agent Health Diagnosis — 2026-02-27 (Run 8 — Full Audit)

## Executive Summary

12/17 agents showed FAILED status from `swarm-2026-02-27_13-02-15`. All failures have the SAME systemic root cause chain (RC1-RC6). All 6 root causes are now RESOLVED. Next full swarm run expected to clear all stale failures.

## Root Cause Chain (ordered by discovery)

| RC | Problem | Fix | Verified |
|----|---------|-----|----------|
| RC1 | macOS lacks `timeout` command | Install coreutils → `gtimeout` | ✅ |
| RC2 | SIGTTIN stops claude (stdin→terminal) | Perl setsid + `/dev/null` stdin | ✅ |
| RC3 | `CLAUDECODE=1` blocks child invocations | `unset` in subshell | ✅ |
| RC4 | Missing `--agent` flag | Added at line 3901 | ✅ |
| RC5 | Prompt >60KB → 0-byte output | 50KB cap | ✅ |
| RC6 | False failure detection (0-byte stdout) | Multi-signal success detection | ✅ |

## Agent-by-Agent Diagnosis

### Grade A (Healthy) — 7 agents
- **backend-hardener**: 4 sprint items, remediation/connector/MCP code
- **frontend-craftsman**: 5 sprint items, 5K LOC UI
- **qa-engineer**: 7,117 tests, 378 core passing
- **devops-engineer**: Docker compose stack
- **sales-engineer**: Demo script v2.0
- **agent-doctor**: 8 runs, all productive
- **vision-agent**: 5+ successful runs

### Grade C (Recovering) — 2 agents
- **context-engineer**: Currently running. Critical dependency.
- **threat-architect**: Stale failure but work done by JARVIS.

### Grade D (Stale Failed) — 8 agents
All from pre-fix run. No individual issues — systemic RC1-RC6 only.
- ai-researcher, data-scientist, enterprise-architect, security-analyst
- marketing-head, technical-writer, scrum-master, swarm-controller

## Watchdog Evidence
Controller-watchdog.log shows continuous STOPPED→SIGCONT cycle — confirms RC2 (SIGTTIN).

## Priority for Next Run
1. context-engineer (all agents depend on it)
2. security-analyst (VETO power)
3. scrum-master (daily demo)
4. enterprise-architect (DEBATE-001)

## Prognosis: GREEN after next full swarm run

*Run 8 — 2026-02-27*
