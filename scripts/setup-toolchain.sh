#!/usr/bin/env bash
#
# ALDECI toolchain — one script, idempotent, safe to re-run.
#
# Every tool here earned its place by measurement on THIS repository
# (2.2M LOC, 5,829 Python files). See docs/TOOLING_ASSESSMENT_2026-08-25.md
# for what was tested and what was rejected.
#
# The ranking that matters, measured:
#
#   Read brain_pipeline.py in full ....... 64,689 tokens
#   Same question via symbol outline .......... 35 tokens
#   ------------------------------------------------------
#   reduction ............................... 1,848x
#
# Full-file reads are essentially the entire token bill. Everything else is
# rounding error. So the toolchain's first job is to make reading a whole file
# unnecessary, and its second job is to run the cheap work on a cheap model.
#
#   ./scripts/setup-toolchain.sh              install everything
#   ./scripts/setup-toolchain.sh --check      report status, change nothing
#
set -uo pipefail

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UA_HOME="$HOME/.understand-anything"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
skip() { printf '  \033[90m·\033[0m %s\n' "$1"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

run() {  # run unless --check
  if [[ $CHECK_ONLY -eq 1 ]]; then skip "would run: $*"; return 0; fi
  "$@"
}

# ─────────────────────────────────────────────────────────────────────────
head_ "1. ast-grep — structural queries instead of file reads"
# The single highest-value item. Answers "what functions exist", "who calls
# this", "where is this pattern" in tens of tokens rather than tens of
# thousands. omc's ast_grep_search MCP tool needs this native module present.
#
# IMPORTANT: the MCP server binds its modules at startup. Installing this into
# a running session does nothing — Claude Code must be RESTARTED afterwards.
OMC_PLUGIN="$(ls -d "$HOME"/.claude/plugins/cache/omc/oh-my-claudecode/* 2>/dev/null | sort -V | tail -1 || true)"
if [[ -n "$OMC_PLUGIN" ]]; then
  if node -e "require.resolve('@ast-grep/napi',{paths:['$OMC_PLUGIN']})" 2>/dev/null; then
    ok "@ast-grep/napi present in $(basename "$OMC_PLUGIN")"
  else
    run bash -c "cd '$OMC_PLUGIN' && npm install @ast-grep/napi --no-save --silent" \
      && ok "installed @ast-grep/napi (RESTART Claude Code to bind it)" \
      || warn "install failed — ast_grep_search will stay unavailable"
  fi
else
  warn "omc plugin not found; ast_grep_search unavailable"
fi

# ─────────────────────────────────────────────────────────────────────────
head_ "2. Hydra — run cheap work on a cheap model"
# Writes standard Claude Code subagent files (.claude/agents/*.md with a
# `model:` field) and lets NATIVE dispatch execute them. It does not own the
# execution loop, which is exactly why it works where ruflo does not — ruflo's
# `task assign` dies on a null dereference and its tasks report
# "Task: undefined" (verified on v3.7.0-alpha.7).
#
# 7 of its 10 heads run on Haiku. Grep, file listing, test running, commit
# messages and doc edits are all Haiku work.
#
# PROJECT SCOPE deliberately: it must not quietly reshape the global config,
# and removal must be one `rm -rf`.
if [[ -d "$REPO_ROOT/.claude/agents" ]] && ls "$REPO_ROOT/.claude/agents"/hydra-* >/dev/null 2>&1; then
  ok "hydra agents already installed (project scope)"
else
  if [[ $CHECK_ONLY -eq 1 ]]; then
    skip "would run: npx hail-hydra-cc@latest --local"
  else
    ( cd "$REPO_ROOT" && npx -y hail-hydra-cc@latest --local </dev/null ) \
      && ok "hydra installed to ./.claude" \
      || warn "hydra install failed — native Agent dispatch still works without it"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────
head_ "3. repomix — packing and the secret gate"
# Config lives in repomix.config.json. Its token-weight ranking is a better
# god-file signal than graphify's degree count, because it is not polluted by
# name collisions.
#
# Its security scan flagged 23 files here; ALL were false positives — demo
# scripts carrying deliberately-fake credentials (AKIAIOSFODNN7EXAMPLE is AWS's
# own documentation example key) posted to our own secret scanner. Keep the
# gate, but triage its output rather than trusting it.
if npx --no-install repomix --version >/dev/null 2>&1 || command -v repomix >/dev/null 2>&1; then
  ok "repomix reachable"
else
  run bash -c "npx -y repomix@latest --version >/dev/null 2>&1" \
    && ok "repomix warmed (npx)" || warn "repomix unavailable"
fi
[[ -f "$REPO_ROOT/repomix.config.json" ]] && ok "repomix.config.json present" \
  || warn "repomix.config.json missing"

# ─────────────────────────────────────────────────────────────────────────
head_ "4. Understand-Anything — semantic understanding, SCOPED"
# A real plugin (v2.9.4). An earlier assessment called it broken; that was a
# verdict on a partial extraction left in /private/tmp with an empty
# .claude-plugin/ and no SKILL.md files, not on the tool.
#
# It dispatches an LLM subagent per BATCH of files and its own SKILL.md warns
# above 100 files. This repo has 5,829 Python files, so an unscoped /understand
# is roughly 580 dispatches. ALWAYS pass a scoped path.
if [[ -d "$UA_HOME/repo/understand-anything-plugin" ]]; then
  ok "understand-anything present at $UA_HOME/repo"
else
  if [[ $CHECK_ONLY -eq 1 ]]; then
    skip "would clone Understand-Anything to $UA_HOME/repo"
  else
    run mkdir -p "$UA_HOME"
    run git clone --depth 1 https://github.com/Egonex-AI/Understand-Anything.git "$UA_HOME/repo" \
      && ok "cloned understand-anything" || warn "clone failed"
  fi
fi
if [[ -d "$UA_HOME/repo/understand-anything-plugin/skills" ]]; then
  run mkdir -p "$HOME/.claude/skills"
  for s in understand understand-explain understand-diff understand-domain understand-knowledge understand-onboard; do
    src="$UA_HOME/repo/understand-anything-plugin/skills/$s"
    [[ -d "$src" ]] && run ln -sfn "$src" "$HOME/.claude/skills/$s"
  done
  ok "linked 6 understand-* skills"
fi

# ─────────────────────────────────────────────────────────────────────────
head_ "5. graphify — file-level map ONLY"
# Rebuilds clean (186,500 nodes / 572,016 edges / 4,041 communities, AST-only,
# no LLM cost). Use it for file-level containment and community structure.
#
# Do NOT trust its call-level output. Measured here: the most-connected node in
# the whole codebase is `sast_router_policystate_get` with 11,791 edges — a
# three-line thread-safe dict getter. Graphify collapses every `.get()` call in
# the repo into it. `graphify path brain_pipeline security_findings_engine`
# returns a 4-hop path through `.get()` linking two unrelated TEST files.
if command -v graphify >/dev/null 2>&1; then
  ok "graphify installed ($(graphify --version 2>/dev/null | head -1 || echo 'version unknown'))"
  [[ -f "$REPO_ROOT/graphify-out/graph.json" ]] && ok "graph present" \
    || warn "graph missing — run: graphify update . --no-llm  (~20 min)"
else
  warn "graphify not installed (optional)"
fi

# ─────────────────────────────────────────────────────────────────────────
head_ "6. Multica — the task board"
# Works as a board (3,756 done). Its agent layer — agent, agent_runtime,
# agent_skill, agent_task_queue, autopilot, autopilot_run — is ALL EMPTY and
# has never orchestrated anything. Treat it as a task list, not a scheduler.
#
# Credentials: user `multica`, db `multica`. Docs elsewhere say `postgres`,
# which is wrong and is why past board queries "failed".
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q multica-postgres; then
  counts=$(docker exec multica-postgres-1 psql -U multica -d multica -At \
    -c "SELECT status || '=' || count(*) FROM issue GROUP BY status ORDER BY count(*) DESC;" 2>/dev/null \
    | tr '\n' ' ')
  ok "multica up — board: ${counts:-unreadable}"
else
  warn "multica not running (docker compose up in the multica repo)"
fi

# ─────────────────────────────────────────────────────────────────────────
head_ "Status"
cat <<'EOF'
  Restart Claude Code if ast-grep was installed this run — the MCP server
  binds its native modules at startup and will not pick it up otherwise.

  Then, in order of measured value:
    1. outline before read      lsp_document_symbols / ast_grep_search
    2. scope every UA run       /understand <path>   never bare
    3. filter every tool call   pytest ... | tail -5, never raw output
    4. delegate cheap work      hydra heads on Haiku
EOF
