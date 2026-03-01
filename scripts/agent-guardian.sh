#!/opt/homebrew/bin/bash
###############################################################################
# ALdeci Agent Guardian — Architectural Safety Net
#
# Purpose: Protect the codebase from destructive agent edits by:
#   1. Snapshotting state BEFORE each agent runs (git stash + tag)
#   2. Validating changes AFTER each agent runs (syntax, tests, critical files)
#   3. Auto-rollback if agent broke critical functionality
#   4. Vision-linked changelog: every change mapped to V1-V10 pillars
#   5. Change impact scoring — quantify risk of each agent's changes
#
# This is the IMMUNE SYSTEM of the swarm. Agents create. Guardian protects.
#
# Usage (called by run-ctem-swarm.sh — NOT standalone):
#   source scripts/agent-guardian.sh   # Load all functions
#   guardian_pre_agent "backend-hardener"
#   ... agent runs ...
#   guardian_post_agent "backend-hardener" 0  # exit_code
#
# Vision Pillar: V3 (Decision Intelligence — deciding WHAT is safe to keep)
#                V10 (CTEM Full Loop — evidence of what changed and why)
###############################################################################

# ── Guardian Configuration ──────────────────────────────────────────────────
# PROJECT_ROOT should be set by the caller (run-ctem-swarm.sh sets it)
# Fall back to git root or script directory if not set
if [[ -z "${PROJECT_ROOT:-}" ]]; then
  PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fi

GUARDIAN_DIR="${PROJECT_ROOT}/.claude/guardian"
GUARDIAN_LOG="${GUARDIAN_DIR}/guardian.log"
GUARDIAN_CHANGELOG="${GUARDIAN_DIR}/vision-changelog.jsonl"
GUARDIAN_ROLLBACK_LOG="${GUARDIAN_DIR}/rollbacks.jsonl"

# Critical files that agents MUST NOT delete or empty (can modify with care)
CRITICAL_FILES=(
  "suite-api/apps/api/app.py"
  "suite-core/core/brain_pipeline.py"
  "suite-core/core/autofix_engine.py"
  "suite-core/core/connectors.py"
  "suite-core/core/crypto.py"
  "suite-core/core/event_bus.py"
  "suite-core/core/micro_pentest.py"
  "suite-core/core/sast_engine.py"
  "suite-core/core/dast_engine.py"
  "suite-core/core/secrets_scanner.py"
  "suite-core/core/container_scanner.py"
  "suite-core/core/cspm_engine.py"
  "sitecustomize.py"
  "requirements.txt"
  "pyproject.toml"
  "Makefile"
  "scripts/run-ctem-swarm.sh"
  "scripts/jarvis-launcher.sh"
  "scripts/jarvis-monitor.sh"
)

# Files that should NEVER be modified by agents (read-only / frozen)
FROZEN_FILES=(
  "docs/CEO_VISION.md"
  "docs/VISION_TO_ACCOMPLISH.MD"
  "docs/VISION_DEBATE_TRANSCRIPT.md"
  "CLAUDE.md"
  ".github/copilot-instructions.md"
)

# Minimum sizes: if a critical file drops below this, it was likely corrupted
declare -A CRITICAL_FILE_MIN_BYTES
CRITICAL_FILE_MIN_BYTES=(
  ["suite-api/apps/api/app.py"]=5000
  ["suite-core/core/brain_pipeline.py"]=2000
  ["suite-core/core/connectors.py"]=5000
  ["suite-core/core/autofix_engine.py"]=2000
  ["suite-core/core/micro_pentest.py"]=3000
  ["sitecustomize.py"]=200
  ["requirements.txt"]=500
)

# Vision pillar keywords for auto-detection from git diffs
declare -A VISION_KEYWORDS
VISION_KEYWORDS=(
  ["V1"]="app_id|APP_ID|component|feature.*hierarchy"
  ["V2"]="lifecycle|phase|design.*review|pre.*merge|build.*pipeline"
  ["V3"]="brain|decision|triage|autofix|FAIL|scoring|prioriti"
  ["V4"]="multi.*llm|consensus|llm.*provider|voting"
  ["V5"]="mpte|micro.*pentest|exploit|attack.*sim|reachability"
  ["V6"]="quantum|ml.*dsa|fips.*204|worm|evidence.*sign"
  ["V7"]="mcp|tool.*discover|ai.*agent|gateway"
  ["V8"]="self.*learn|feedback.*loop|retrain|outcome.*track"
  ["V9"]="air.*gap|offline|on.*prem|zero.*depend"
  ["V10"]="ctem|evidence|compliance|audit|crypto.*proof|signed"
)

# Agent risk tiers — how much trust each agent gets
declare -A AGENT_RISK_TIER
AGENT_RISK_TIER=(
  # LOW RISK: read-mostly agents (docs, analysis, status)
  ["vision-agent"]="low"
  ["agent-doctor"]="low"
  ["context-engineer"]="low"
  ["ai-researcher"]="low"
  ["data-scientist"]="low"
  ["marketing-head"]="low"
  ["technical-writer"]="low"
  ["sales-engineer"]="low"
  ["scrum-master"]="low"
  # MEDIUM RISK: modifies code but scoped
  ["qa-engineer"]="medium"
  ["security-analyst"]="medium"
  ["devops-engineer"]="medium"
  ["swarm-controller"]="medium"
  # HIGH RISK: modifies core engines and architecture
  ["backend-hardener"]="high"
  ["frontend-craftsman"]="high"
  ["threat-architect"]="high"
  ["enterprise-architect"]="high"
)

###############################################################################
# Safe associative array lookup — avoids bash set -u arithmetic evaluation
# of hyphenated keys like "agent-doctor" (parsed as agent minus doctor)
###############################################################################
_guardian_risk_tier() {
  local name="$1"
  local default="${2:-medium}"
  # Temporarily disable set -u to prevent arithmetic evaluation of hyphenated keys
  # Also use printf '%s' to avoid bash parsing hyphens as arithmetic operators
  local result
  local _key
  _key="$name"
  set +u
  result="${AGENT_RISK_TIER["$_key"]:-$default}"
  set -u
  echo "$result"
}

###############################################################################
# Guardian Initialization
###############################################################################
guardian_init() {
  mkdir -p "$GUARDIAN_DIR" 2>/dev/null || true
  touch "$GUARDIAN_LOG" "$GUARDIAN_CHANGELOG" "$GUARDIAN_ROLLBACK_LOG" 2>/dev/null || true
  _guardian_log "Guardian initialized for run ${RUN_ID:-unknown}"
}

###############################################################################
# Internal logging
###############################################################################
_guardian_log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >> "$GUARDIAN_LOG" 2>/dev/null || true
}

###############################################################################
# PRE-AGENT HOOK — Called BEFORE every agent runs
#
# What it does:
#   1. Creates a git snapshot (lightweight tag) of current HEAD
#   2. Records file sizes of all critical files (for delta comparison)
#   3. Records the current test baseline (if tests exist)
#   4. Saves a manifest of critical file hashes
#
# Args: $1 = agent_name
###############################################################################
guardian_pre_agent() {
  local agent_name="$1"
  local snapshot_dir="$GUARDIAN_DIR/snapshots/${RUN_ID:-unknown}"
  mkdir -p "$snapshot_dir" 2>/dev/null || true

  _guardian_log "PRE-AGENT: ${agent_name} — starting safety snapshot"

  # ── 1. Record the current git HEAD for precise rollback ──
  local head_sha
  head_sha=$(cd "$PROJECT_ROOT" && git rev-parse HEAD 2>/dev/null || echo "unknown")
  _guardian_log "  Git HEAD: ${head_sha}"

  # ── 2. Record critical file sizes + hashes ──
  # Ensure snapshot dir exists (create fresh each time)
  mkdir -p "$snapshot_dir" 2>/dev/null || true
  local manifest="$snapshot_dir/${agent_name}-pre-manifest.json"
  {
    echo "{"
    echo "  \"agent\": \"${agent_name}\","
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"run_id\": \"${RUN_ID:-unknown}\","
    echo "  \"risk_tier\": \"$(_guardian_risk_tier "$agent_name" "unknown")\","
    echo "  \"files\": {"
    local first=true
    for f in "${CRITICAL_FILES[@]}" "${FROZEN_FILES[@]}"; do
      local full_path="$PROJECT_ROOT/$f"
      if [[ -f "$full_path" ]]; then
        local size hash
        size=$(wc -c < "$full_path" 2>/dev/null | tr -d ' ')
        hash=$(md5 -q "$full_path" 2>/dev/null || md5sum "$full_path" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
        $first || echo ","
        echo -n "    \"${f}\": {\"size\": ${size}, \"hash\": \"${hash}\"}"
        first=false
      fi
    done
    echo ""
    echo "  },"

    # ── 3. Git status (what's dirty before agent runs) ──
    local dirty_count
    dirty_count=$(cd "$PROJECT_ROOT" && git status --porcelain 2>/dev/null | wc -l | tr -d ' ')
    echo "  \"pre_dirty_files\": ${dirty_count},"

    # ── 4. Quick test baseline (just count, don't run full suite) ──
    local test_count
    test_count=$(find "$PROJECT_ROOT/tests" -name "test_*.py" 2>/dev/null | wc -l | tr -d ' ')
    echo "  \"test_file_count\": ${test_count}"
    echo "}"
  } > "$manifest" 2>/dev/null || true

  _guardian_log "PRE-AGENT: ${agent_name} — manifest saved (${#CRITICAL_FILES[@]} critical + ${#FROZEN_FILES[@]} frozen files tracked)"
}

###############################################################################
# POST-AGENT HOOK — Called AFTER every agent completes
#
# What it does:
#   1. Compare critical file sizes/hashes against pre-agent manifest
#   2. Detect deleted or corrupted critical files → AUTO-ROLLBACK
#   3. Detect frozen file modifications → AUTO-ROLLBACK
#   4. Run syntax validation on changed Python files
#   5. Compute change impact score (files changed, LOC delta, risk tier)
#   6. Auto-detect vision pillar from diffs → write vision-changelog entry
#   7. If HIGH-RISK agent made dangerous changes, run targeted tests
#
# Args: $1 = agent_name, $2 = exit_code
# Returns: 0 = safe, 1 = rolled back (agent output rejected)
###############################################################################
guardian_post_agent() {
  local agent_name="$1"
  local exit_code="${2:-0}"
  local snapshot_dir="$GUARDIAN_DIR/snapshots/${RUN_ID:-unknown}"
  local manifest="$snapshot_dir/${agent_name}-pre-manifest.json"
  local risk_tier
  risk_tier="$(_guardian_risk_tier "$agent_name" "medium")"
  local violations=0
  local rollback_needed=false
  local violation_details=""

  _guardian_log "POST-AGENT: ${agent_name} (exit: ${exit_code}, risk: ${risk_tier})"

  # Skip validation if agent failed (nothing to validate)
  if [[ "$exit_code" != "0" ]]; then
    _guardian_log "POST-AGENT: ${agent_name} failed (exit ${exit_code}) — skipping validation"
    guardian_write_changelog "$agent_name" "FAILED" "" "Agent failed with exit code ${exit_code}"
    return 0
  fi

  # ── 1. Check frozen files (MUST NOT be modified) ──
  if [[ -f "$manifest" ]]; then
    for f in "${FROZEN_FILES[@]}"; do
      local full_path="$PROJECT_ROOT/$f"
      if [[ -f "$full_path" ]]; then
        local pre_hash current_hash
        pre_hash=$(python3 -c "import json; d=json.load(open('$manifest')); print(d.get('files',{}).get('$f',{}).get('hash',''))" 2>/dev/null || echo "")
        current_hash=$(md5 -q "$full_path" 2>/dev/null || md5sum "$full_path" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
        if [[ -n "$pre_hash" && "$pre_hash" != "$current_hash" ]]; then
          violations=$((violations + 1))
          rollback_needed=true
          violation_details+="FROZEN_FILE_MODIFIED: ${f} (was: ${pre_hash:0:8}, now: ${current_hash:0:8}); "
          _guardian_log "  🚨 VIOLATION: Frozen file modified: ${f}"
        fi
      fi
    done
  fi

  # ── 2. Check critical files (deletion or corruption) ──
  if [[ -f "$manifest" ]]; then
    for f in "${CRITICAL_FILES[@]}"; do
      local full_path="$PROJECT_ROOT/$f"

      # Check deletion
      if [[ ! -f "$full_path" ]]; then
        local pre_existed
        pre_existed=$(python3 -c "import json; d=json.load(open('$manifest')); print('yes' if '$f' in d.get('files',{}) else 'no')" 2>/dev/null || echo "no")
        if [[ "$pre_existed" == "yes" ]]; then
          violations=$((violations + 1))
          rollback_needed=true
          violation_details+="CRITICAL_FILE_DELETED: ${f}; "
          _guardian_log "  🚨 VIOLATION: Critical file DELETED: ${f}"
        fi
        continue
      fi

      # Check corruption (file shrunk below minimum)
      local min_bytes="${CRITICAL_FILE_MIN_BYTES[$f]:-0}"
      if [[ $min_bytes -gt 0 ]]; then
        local current_size
        current_size=$(wc -c < "$full_path" 2>/dev/null | tr -d ' ')
        if [[ $current_size -lt $min_bytes ]]; then
          violations=$((violations + 1))
          rollback_needed=true
          violation_details+="CRITICAL_FILE_CORRUPTED: ${f} (${current_size} bytes, min: ${min_bytes}); "
          _guardian_log "  🚨 VIOLATION: Critical file corrupted: ${f} (${current_size} < ${min_bytes} bytes)"
        fi
      fi

      # Check massive unintended changes (>50% size delta for critical files)
      local pre_size current_size
      pre_size=$(python3 -c "import json; d=json.load(open('$manifest')); print(d.get('files',{}).get('$f',{}).get('size',0))" 2>/dev/null || echo "0")
      current_size=$(wc -c < "$full_path" 2>/dev/null | tr -d ' ')
      if [[ $pre_size -gt 0 && $current_size -gt 0 ]]; then
        local delta_pct=$(( ((current_size - pre_size) * 100) / pre_size ))
        # Negative delta_pct means file shrunk
        if [[ $delta_pct -lt -50 ]]; then
          violations=$((violations + 1))
          violation_details+="CRITICAL_FILE_SHRUNK: ${f} (${pre_size}→${current_size}, ${delta_pct}%); "
          _guardian_log "  ⚠️  WARNING: Critical file shrunk >50%: ${f} (${delta_pct}%)"
          # Only auto-rollback if HIGH risk agent shrunk a file >50%
          [[ "$risk_tier" == "high" ]] && rollback_needed=true
        fi
      fi
    done
  fi

  # ── 3. Syntax validation on changed Python files ──
  local changed_py_files
  changed_py_files=$(cd "$PROJECT_ROOT" && git diff --name-only HEAD 2>/dev/null | grep '\.py$' || true)
  local syntax_failures=0
  if [[ -n "$changed_py_files" ]]; then
    while IFS= read -r pyfile; do
      local full_py="$PROJECT_ROOT/$pyfile"
      if [[ -f "$full_py" ]]; then
        if ! python3 -c "import ast; ast.parse(open('$full_py').read())" 2>/dev/null; then
          syntax_failures=$((syntax_failures + 1))
          violation_details+="SYNTAX_ERROR: ${pyfile}; "
          _guardian_log "  🚨 SYNTAX ERROR: ${pyfile}"
        fi
      fi
    done <<< "$changed_py_files"

    # Syntax errors in critical files → auto-rollback
    if [[ $syntax_failures -gt 0 ]]; then
      violations=$((violations + syntax_failures))
      for f in "${CRITICAL_FILES[@]}"; do
        if echo "$changed_py_files" | grep -q "$f" 2>/dev/null; then
          if ! python3 -c "import ast; ast.parse(open('$PROJECT_ROOT/$f').read())" 2>/dev/null; then
            rollback_needed=true
            _guardian_log "  🚨 CRITICAL: Syntax error in critical file: ${f} — rollback required"
          fi
        fi
      done
    fi
  fi

  # ── 4. For HIGH-RISK agents: run targeted tests on changed modules ──
  local test_failures=0
  if [[ "$risk_tier" == "high" && -n "$changed_py_files" ]]; then
    # Find test files that correspond to changed source files
    while IFS= read -r pyfile; do
      local base_name
      base_name=$(basename "$pyfile" .py)
      local test_file="$PROJECT_ROOT/tests/test_${base_name}.py"
      if [[ -f "$test_file" ]]; then
        _guardian_log "  Running targeted test: test_${base_name}.py"
        if ! timeout 30 python3 -m pytest "$test_file" -x -q --timeout=10 2>/dev/null; then
          test_failures=$((test_failures + 1))
          violation_details+="TEST_FAILURE: test_${base_name}.py; "
          _guardian_log "  🚨 TEST FAILURE: test_${base_name}.py"
        fi
      fi
    done <<< "$changed_py_files"
  fi

  # ── 5. Compute change impact score ──
  local files_changed lines_added lines_removed impact_score
  files_changed=$(cd "$PROJECT_ROOT" && git diff --name-only HEAD 2>/dev/null | wc -l | tr -d ' ')
  lines_added=$(cd "$PROJECT_ROOT" && git diff --stat HEAD 2>/dev/null | tail -1 | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+' || echo "0")
  lines_removed=$(cd "$PROJECT_ROOT" && git diff --stat HEAD 2>/dev/null | tail -1 | grep -oE '[0-9]+ deletion' | grep -oE '[0-9]+' || echo "0")
  [[ -z "$lines_added" ]] && lines_added=0
  [[ -z "$lines_removed" ]] && lines_removed=0

  # Impact score: weighted by risk tier, files changed, and LOC
  local tier_weight=1
  case "$risk_tier" in
    low) tier_weight=1 ;;
    medium) tier_weight=2 ;;
    high) tier_weight=3 ;;
  esac
  impact_score=$(( (files_changed * tier_weight) + (lines_added / 10) + (lines_removed / 5) + (violations * 20) + (syntax_failures * 30) + (test_failures * 50) ))

  # ── 6. Auto-detect vision pillars from changes ──
  local detected_pillars=""
  local diff_content
  diff_content=$(cd "$PROJECT_ROOT" && git diff HEAD 2>/dev/null | head -500 || echo "")
  local new_file_content
  new_file_content=$(cd "$PROJECT_ROOT" && git diff --cached --name-only 2>/dev/null | head -20 || echo "")

  set +u
  for pillar in V1 V2 V3 V4 V5 V6 V7 V8 V9 V10; do
    local keywords="${VISION_KEYWORDS["$pillar"]:-}"
    if [[ -n "$keywords" && -n "$diff_content" ]]; then
      if echo "$diff_content" | grep -qiE "$keywords" 2>/dev/null; then
        detected_pillars+="${pillar} "
      fi
    fi
  done
  set -u
  [[ -z "$detected_pillars" ]] && detected_pillars="NONE"

  # ── 7. Auto-rollback if needed ──
  if $rollback_needed; then
    _guardian_log "POST-AGENT: ${agent_name} — ROLLING BACK (${violations} violations)"
    guardian_rollback "$agent_name" "$violation_details"
    guardian_write_changelog "$agent_name" "ROLLED_BACK" "$detected_pillars" \
      "Agent changes rolled back: ${violation_details}" "$impact_score"
    return 1  # Signal to swarm: discard this agent's output
  fi

  # ── 8. Write vision-changelog entry ──
  local change_summary
  change_summary=$(cd "$PROJECT_ROOT" && git diff --name-only HEAD 2>/dev/null | head -10 | tr '\n' ', ' || echo "none")
  guardian_write_changelog "$agent_name" "ACCEPTED" "$detected_pillars" \
    "files:${files_changed} +${lines_added}/-${lines_removed} violations:${violations} syntax_err:${syntax_failures} test_fail:${test_failures} changed:[${change_summary}]" \
    "$impact_score"

  _guardian_log "POST-AGENT: ${agent_name} — ACCEPTED (impact: ${impact_score}, pillars: ${detected_pillars}, violations: ${violations})"

  # ── 9. Warn on high impact ──
  if [[ $impact_score -gt 100 ]]; then
    _guardian_log "  ⚠️  HIGH IMPACT SCORE (${impact_score}) — review recommended"
  fi

  return 0
}

###############################################################################
# ROLLBACK — Revert an agent's changes using git
###############################################################################
guardian_rollback() {
  local agent_name="$1"
  local reason="${2:-unknown}"

  _guardian_log "ROLLBACK: ${agent_name} — reverting all uncommitted changes"

  # Restore from git (discard all uncommitted changes)
  (cd "$PROJECT_ROOT" && git checkout -- . 2>/dev/null) || true
  # Also remove any new untracked files the agent created
  (cd "$PROJECT_ROOT" && git clean -fd 2>/dev/null) || true

  # Log the rollback
  local entry
  entry=$(cat <<RBJSON
{"ts":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","agent":"${agent_name}","run_id":"${RUN_ID:-unknown}","action":"rollback","reason":"$(echo "$reason" | sed 's/"/\\"/g' | head -c 500)"}
RBJSON
  )
  echo "$entry" >> "$GUARDIAN_ROLLBACK_LOG" 2>/dev/null || true

  _guardian_log "ROLLBACK: ${agent_name} — completed"

  # Notify (if voice/notify functions are available from swarm)
  type voice &>/dev/null && voice "Guardian rolled back ${agent_name} changes" "critical"
  type notify &>/dev/null && notify "Guardian Rollback" "${agent_name}: ${reason:0:100}"
}

###############################################################################
# VISION CHANGELOG — Human-readable record of every change
#
# Every line answers: "What changed? Why? Which vision pillar? Who did it?
# Was it safe? What was the impact?"
###############################################################################
guardian_write_changelog() {
  local agent_name="$1"
  local status="$2"           # ACCEPTED, ROLLED_BACK, FAILED
  local pillars="${3:-NONE}"
  local details="${4:-}"
  local impact_score="${5:-0}"
  local risk_tier
  risk_tier="$(_guardian_risk_tier "$agent_name" "unknown")"

  local entry
  entry=$(cat <<CLJSON
{"ts":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","run_id":"${RUN_ID:-unknown}","agent":"${agent_name}","risk_tier":"${risk_tier}","status":"${status}","vision_pillars":"${pillars}","impact_score":${impact_score},"details":"$(echo "$details" | sed 's/"/\\"/g' | head -c 1000)"}
CLJSON
  )
  echo "$entry" >> "$GUARDIAN_CHANGELOG" 2>/dev/null || true
}

###############################################################################
# DAILY GUARDIAN REPORT — Human-readable summary of all agent activity
#
# Called after swarm completes. Generates a markdown report that answers:
#   - What did each agent change today?
#   - Which vision pillars were advanced?
#   - Were any changes rolled back?
#   - What's the overall health of the codebase?
###############################################################################
guardian_daily_report() {
  local report_file="$GUARDIAN_DIR/daily-report-${DATE_TODAY:-$(date +%Y-%m-%d)}.md"
  local today="${DATE_TODAY:-$(date +%Y-%m-%d)}"

  {
    echo "# Guardian Daily Report — ${today}"
    echo ""
    echo "> **Run ID**: ${RUN_ID:-unknown}"
    echo "> **Generated**: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "> **Vision**: Every change must serve V1-V10. This report proves it."
    echo ""
    echo "---"
    echo ""

    # ── Summary Statistics ──
    local total=0 accepted=0 rolled_back=0 failed=0
    if [[ -f "$GUARDIAN_CHANGELOG" ]]; then
      total=$(grep -c "\"run_id\":\"${RUN_ID:-unknown}\"" "$GUARDIAN_CHANGELOG" 2>/dev/null || echo "0")
      accepted=$(grep "\"run_id\":\"${RUN_ID:-unknown}\"" "$GUARDIAN_CHANGELOG" 2>/dev/null | grep -c '"ACCEPTED"' || echo "0")
      rolled_back=$(grep "\"run_id\":\"${RUN_ID:-unknown}\"" "$GUARDIAN_CHANGELOG" 2>/dev/null | grep -c '"ROLLED_BACK"' || echo "0")
      failed=$(grep "\"run_id\":\"${RUN_ID:-unknown}\"" "$GUARDIAN_CHANGELOG" 2>/dev/null | grep -c '"FAILED"' || echo "0")
    fi

    echo "## Summary"
    echo ""
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Total agent runs | ${total} |"
    echo "| ✅ Accepted | ${accepted} |"
    echo "| 🔄 Rolled Back | ${rolled_back} |"
    echo "| ❌ Failed | ${failed} |"
    echo "| 🛡️ Codebase Protected | $([ $rolled_back -gt 0 ] && echo "YES — ${rolled_back} destructive changes prevented" || echo "No rollbacks needed") |"
    echo ""

    # ── Vision Pillar Activity ──
    echo "## Vision Pillar Activity"
    echo ""
    echo "Which pillars were advanced today:"
    echo ""
    for pillar in V1 V2 V3 V4 V5 V6 V7 V8 V9 V10; do
      local count
      count=$(grep "\"run_id\":\"${RUN_ID:-unknown}\"" "$GUARDIAN_CHANGELOG" 2>/dev/null | grep -c "$pillar" || echo "0")
      local status_icon="⬜"
      [[ $count -gt 0 ]] && status_icon="🟢"
      echo "- ${status_icon} **${pillar}**: ${count} agent(s) contributed"
    done
    echo ""

    # ── Per-Agent Detail ──
    echo "## Agent Activity Detail"
    echo ""
    echo "| Agent | Risk | Status | Vision Pillars | Impact | Details |"
    echo "|-------|------|--------|----------------|--------|---------|"
    if [[ -f "$GUARDIAN_CHANGELOG" ]]; then
      grep "\"run_id\":\"${RUN_ID:-unknown}\"" "$GUARDIAN_CHANGELOG" 2>/dev/null | while IFS= read -r line; do
        local ag st rt vp is dt
        ag=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('agent','?'))" 2>/dev/null || echo "?")
        st=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('status','?'))" 2>/dev/null || echo "?")
        rt=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('risk_tier','?'))" 2>/dev/null || echo "?")
        vp=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('vision_pillars','?'))" 2>/dev/null || echo "?")
        is=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('impact_score',0))" 2>/dev/null || echo "0")
        dt=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('details','')[:80])" 2>/dev/null || echo "")
        local status_icon="✅"
        [[ "$st" == "ROLLED_BACK" ]] && status_icon="🔄"
        [[ "$st" == "FAILED" ]] && status_icon="❌"
        echo "| ${ag} | ${rt} | ${status_icon} ${st} | ${vp} | ${is} | ${dt} |"
      done
    fi
    echo ""

    # ── Rollback Details ──
    if [[ $rolled_back -gt 0 ]]; then
      echo "## 🔄 Rollback Details"
      echo ""
      echo "The Guardian protected the codebase from these destructive changes:"
      echo ""
      grep "\"run_id\":\"${RUN_ID:-unknown}\"" "$GUARDIAN_ROLLBACK_LOG" 2>/dev/null | while IFS= read -r line; do
        local ag reason
        ag=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('agent','?'))" 2>/dev/null || echo "?")
        reason=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('reason','?'))" 2>/dev/null || echo "?")
        echo "- **${ag}**: ${reason}"
      done
      echo ""
    fi

    # ── Critical File Health ──
    echo "## Critical File Health"
    echo ""
    echo "| File | Size | Status |"
    echo "|------|------|--------|"
    for f in "${CRITICAL_FILES[@]}"; do
      local full_path="$PROJECT_ROOT/$f"
      if [[ -f "$full_path" ]]; then
        local size
        size=$(wc -c < "$full_path" 2>/dev/null | tr -d ' ')
        local min="${CRITICAL_FILE_MIN_BYTES[$f]:-0}"
        local health="✅ Healthy"
        if [[ $min -gt 0 && $size -lt $min ]]; then
          health="🚨 BELOW MINIMUM (${size} < ${min})"
        fi
        echo "| ${f} | ${size} bytes | ${health} |"
      else
        echo "| ${f} | MISSING | 🚨 DELETED |"
      fi
    done
    echo ""

    echo "---"
    echo "*Generated by ALdeci Agent Guardian — protecting the vision, one commit at a time.*"

  } > "$report_file" 2>/dev/null || true

  _guardian_log "DAILY REPORT: Generated at ${report_file}"
  echo "$report_file"
}

###############################################################################
# QUICK HEALTH CHECK — Can be called anytime to verify codebase integrity
###############################################################################
guardian_health_check() {
  local issues=0

  for f in "${CRITICAL_FILES[@]}"; do
    local full_path="$PROJECT_ROOT/$f"
    if [[ ! -f "$full_path" ]]; then
      echo "🚨 MISSING: $f"
      issues=$((issues + 1))
    else
      local min="${CRITICAL_FILE_MIN_BYTES[$f]:-0}"
      local size
      size=$(wc -c < "$full_path" 2>/dev/null | tr -d ' ')
      if [[ $min -gt 0 && $size -lt $min ]]; then
        echo "🚨 CORRUPTED: $f (${size} < ${min} bytes)"
        issues=$((issues + 1))
      fi
    fi
  done

  for f in "${FROZEN_FILES[@]}"; do
    if [[ ! -f "$PROJECT_ROOT/$f" ]]; then
      echo "⚠️  FROZEN FILE MISSING: $f"
      issues=$((issues + 1))
    fi
  done

  if [[ $issues -eq 0 ]]; then
    echo "✅ All ${#CRITICAL_FILES[@]} critical files + ${#FROZEN_FILES[@]} frozen files healthy"
  else
    echo "🚨 ${issues} issue(s) found"
  fi

  return $issues
}
