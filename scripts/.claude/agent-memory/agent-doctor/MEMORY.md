# Agent Doctor — Persistent Memory

## Key Root Causes Found (2026-02-27)

### RC1-RC5: Infrastructure Issues
- macOS lacks `timeout` → use `gtimeout` from coreutils
- SIGTTIN stops claude when stdin=terminal → use `perl -MPOSIX setsid()` wrapper
- `CLAUDECODE=1` env var blocks nested claude → `unset` in subshell
- Missing `--agent` flag → always pass it for agent mode
- Prompts >60KB → cap at 50KB

### RC6: FALSE FAILURE DETECTION (Critical Pattern)
`claude --agent --print` mode works via tool calls (Read/Write/Edit/Bash).
Output goes into FILES the agent modifies, NOT stdout.
The `--print` flag only captures final text response, which is empty for tool-heavy work.
**Fix**: Check exit code + status file recency + git changes, not just stdout bytes.
Location: `run-ctem-swarm.sh` lines 4224-4275.

## Agent YAML Standards
- All 16 files in `.claude/agents/`: valid YAML, model=claude-opus-4-6-fast, maxTurns≥200
- All reference CTEM+ and docs/CTEM_PLUS_IDENTITY.md
- Scanner-facing agents (backend-hardener, security-analyst, qa-engineer, threat-architect) reference scanner engines

## CTEM+ Engine Locations
- Scanners: `suite-core/core/{secrets,iac,container,real}_scanner.py` (3,912 LOC)
- AutoFix: `suite-core/core/autofix_engine.py` (1,259 LOC)
- Brain Pipeline: `suite-core/core/brain_pipeline.py` (863 LOC, 12 steps)
- MPTE: `suite-core/core/mpte_{advanced,db,models}.py` + `suite-attack/api/mpte_*.py` (3,341 LOC)
- FAIL Engine: `suite-core/core/fail_{engine,db}.py` (968 LOC)
- MCP Router: `suite-api/apps/api/mcp_router.py` (977 LOC, auto-discovery)
- Connectors: `suite-core/connectors/universal_connector.py` (1,637 LOC) + router (334 LOC)
- Remediation: `suite-core/automation/remediation.py` (1,543 LOC, 5 CWE templates)

## Sprint State (as of run 6)
- 12/17 items done, all P0 complete
- TODO: 007 (feeds), 009 (compliance, deferred), 011 (docker), 012 (api docs), 013 (CVE pipeline)
- 233 test files, 90K LOC tests, ~40% coverage

## Project Root
`/Users/devops.ai/developement/fixops/Fixops/`

## Key Patterns
- Always check `context_log.md` tail for latest agent completions
- Status files (`.claude/team-state/*-status.md`) may be stale from old runs
- Physical file verification > status file claims
- The swarm script is at `scripts/run-ctem-swarm.sh` (~5,800 lines)
