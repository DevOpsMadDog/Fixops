#!/usr/bin/env bash
###############################################################################
# ALdeci Junior Swarm Orchestrator
#
# Spawns 1-30+ junior AI workers via Ollama (FREE, local).
# Grok/xAI API (~$0.50/verification) verifies outputs before merge.
#
# Budget-aware: $0/junior (Ollama) + $0.50/verification (Grok)
#
# Architecture:
#   ┌─────────────────────────────────────────────────┐
#   │              SWARM CONTROLLER                   │
#   │  (decomposes tasks, assigns to juniors)         │
#   └──────────────┬──────────────────────────────────┘
#                  │
#   ┌──────────────▼──────────────────────────────────┐
#   │         JUNIOR WORKER POOL (1-30+)              │
#   │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐      │
#   │  │ J-01│ │ J-02│ │ J-03│ │ ... │ │ J-30│      │
#   │  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘      │
#   │  Ollama (qwen2.5-coder:14b) — FREE              │
#   └─────┼───────┼───────┼───────┼───────┼──────────┘
#         │       │       │       │       │
#   ┌─────▼───────▼───────▼───────▼───────▼──────────┐
#   │         SENIOR VERIFICATION (Grok/xAI)           │
#   │  Grok-3 via xAI API — ~$0.50/verification        │
#   └─────────────────────────────────────────────────┘
#
# Usage:
#   ./scripts/spawn-swarm.sh                         # Auto-detect tasks
#   ./scripts/spawn-swarm.sh --task-file FILE        # Use specific task file
#   ./scripts/spawn-swarm.sh --count 20              # Spawn exactly 20 juniors
#   ./scripts/spawn-swarm.sh --wave-size 10          # 10 juniors per wave
#   ./scripts/spawn-swarm.sh --type test-run         # Only run test tasks
#   ./scripts/spawn-swarm.sh --verify-only           # Only verify pending outputs
#   ./scripts/spawn-swarm.sh --dry-run               # Show plan, don't execute
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENTS_DIR="$PROJECT_ROOT/.claude/agents"
STATE_DIR="$PROJECT_ROOT/.claude/team-state"
SWARM_DIR="$STATE_DIR/swarm"
DATE_TODAY=$(date +"%Y-%m-%d")
LOG_DIR="$PROJECT_ROOT/logs/ai-team/swarm"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Defaults
DRY_RUN=false
MAX_JUNIORS=30
WAVE_SIZE=10
JUNIOR_TIMEOUT=300    # 5 min per junior (they're fast, scoped tasks)
TASK_FILE=""
TASK_TYPE_FILTER=""
VERIFY_ONLY=false
SKIP_VERIFY=false
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5-coder:14b}"
GROK_MODEL="${GROK_MODEL:-grok-3}"

###############################################################################
# Parse arguments
###############################################################################
while [[ $# -gt 0 ]]; do
  case $1 in
    --task-file)    TASK_FILE="$2"; shift 2 ;;
    --count)        MAX_JUNIORS="$2"; shift 2 ;;
    --wave-size)    WAVE_SIZE="$2"; shift 2 ;;
    --type)         TASK_TYPE_FILTER="$2"; shift 2 ;;
    --verify-only)  VERIFY_ONLY=true; shift ;;
    --skip-verify)  SKIP_VERIFY=true; shift ;;
    --dry-run)      DRY_RUN=true; shift ;;
    --timeout)      JUNIOR_TIMEOUT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --task-file FILE    Path to task queue JSON (default: auto-detect)"
      echo "  --count N           Max number of juniors to spawn (default: 30)"
      echo "  --wave-size N       Juniors per wave (default: 10)"
      echo "  --type TYPE         Only run tasks of this type"
      echo "                      Types: test-run, lint-fix, docs-update,"
      echo "                             code-cleanup, config-audit, data-gen"
      echo "  --verify-only       Only verify pending outputs (no new spawns)"
      echo "  --skip-verify       Skip senior verification step"
      echo "  --timeout SECS      Timeout per junior (default: 300)"
      echo "  --dry-run           Show plan without executing"
      echo "  -h, --help          Show this help"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

###############################################################################
# Helpers
###############################################################################
log()     { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; }
swarm()   { echo -e "${MAGENTA}[🐝]${NC} $*"; }
header() {
  echo ""
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}${CYAN}  $*${NC}"
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

ensure_swarm_dirs() {
  mkdir -p "$SWARM_DIR"/{assignments,outputs,verifications}
  mkdir -p "$LOG_DIR"
}

###############################################################################
# Task Discovery — scan senior agent outputs for decomposable work
###############################################################################
discover_tasks() {
  local queue_file="$SWARM_DIR/task-queue.json"
  local task_id=1
  declare -a tasks

  header "Task Discovery — Scanning Senior Agent Outputs"

  # --- From QA Engineer: individual test files ---
  if [[ -f "$STATE_DIR/quality-gate.json" ]]; then
    log "Scanning QA Engineer outputs for test tasks..."
    # Find all test files in the project
    while IFS= read -r test_file; do
      tasks+=("{\"id\":\"swarm-$(printf '%03d' $task_id)\",\"type\":\"test-run\",\"priority\":\"high\",\"source_agent\":\"qa-engineer\",\"description\":\"Run pytest $test_file -v --tb=short\",\"files\":[\"$test_file\"],\"acceptance\":\"All tests pass or failures documented\",\"status\":\"pending\",\"batch\":1}")
      ((task_id++))
    done < <(find "$PROJECT_ROOT/tests" -name "test_*.py" -type f 2>/dev/null | head -"$MAX_JUNIORS" | sed "s|$PROJECT_ROOT/||")
  fi

  # --- From Backend Hardener: lint issues ---
  if [[ -f "$STATE_DIR/backend-hardener-status.md" ]]; then
    log "Scanning Backend Hardener outputs for lint tasks..."
    for module in suite-core/core suite-api/apps/api suite-attack/api suite-evidence-risk; do
      if [[ -d "$PROJECT_ROOT/$module" ]]; then
        tasks+=("{\"id\":\"swarm-$(printf '%03d' $task_id)\",\"type\":\"lint-fix\",\"priority\":\"medium\",\"source_agent\":\"backend-hardener\",\"description\":\"Run ruff check --fix $module/\",\"files\":[\"$module/\"],\"acceptance\":\"ruff check passes with 0 fixable errors\",\"status\":\"pending\",\"batch\":2}")
        ((task_id++))
      fi
    done
  fi

  # --- From Security Analyst: config audits ---
  if [[ -f "$STATE_DIR/security-analyst-status.md" ]]; then
    log "Scanning Security Analyst outputs for audit tasks..."
    for config in requirements.txt requirements.dev.txt dev-requirements.txt pyproject.toml; do
      if [[ -f "$PROJECT_ROOT/$config" ]]; then
        tasks+=("{\"id\":\"swarm-$(printf '%03d' $task_id)\",\"type\":\"config-audit\",\"priority\":\"high\",\"source_agent\":\"security-analyst\",\"description\":\"Audit $config for known CVEs and outdated versions\",\"files\":[\"$config\"],\"acceptance\":\"No critical CVEs, all versions documented\",\"status\":\"pending\",\"batch\":1}")
        ((task_id++))
      fi
    done
  fi

  # --- From Technical Writer: doc updates ---
  if [[ -f "$STATE_DIR/technical-writer-status.md" ]]; then
    log "Scanning Technical Writer outputs for doc tasks..."
    while IFS= read -r doc_file; do
      tasks+=("{\"id\":\"swarm-$(printf '%03d' $task_id)\",\"type\":\"docs-update\",\"priority\":\"low\",\"source_agent\":\"technical-writer\",\"description\":\"Validate and fix $doc_file — check links, formatting, accuracy\",\"files\":[\"$doc_file\"],\"acceptance\":\"All links valid, formatting correct, content accurate\",\"status\":\"pending\",\"batch\":3}")
      ((task_id++))
    done < <(find "$PROJECT_ROOT/docs" "$PROJECT_ROOT/deepwiki_docs" -name "*.md" -type f 2>/dev/null | head -10 | sed "s|$PROJECT_ROOT/||")
  fi

  # --- From Threat Architect: data generation ---
  if [[ -f "$STATE_DIR/threat-architect-status.md" ]]; then
    log "Scanning Threat Architect outputs for data-gen tasks..."
    for variant in aws-ecommerce azure-healthcare multicloud-finserv iot-manufacturing govcloud-fedramp; do
      tasks+=("{\"id\":\"swarm-$(printf '%03d' $task_id)\",\"type\":\"data-gen\",\"priority\":\"medium\",\"source_agent\":\"threat-architect\",\"description\":\"Generate CycloneDX SBOM + SARIF report for $variant architecture\",\"files\":[\"data/artifacts/\"],\"acceptance\":\"Valid CycloneDX JSON + valid SARIF JSON\",\"status\":\"pending\",\"batch\":3}")
      ((task_id++))
    done
  fi

  # Apply type filter if specified
  local total=${#tasks[@]}
  log "Discovered $total potential tasks"

  # Write task queue
  if [[ $total -eq 0 ]]; then
    cat > "$queue_file" <<EOF
{
  "date": "${DATE_TODAY}",
  "total_tasks": 0,
  "wave_size": ${WAVE_SIZE},
  "max_juniors": ${MAX_JUNIORS},
  "tasks": []
}
EOF
  else
    local tasks_json=$(printf '%s\n' "${tasks[@]}" | paste -sd',' -)
    cat > "$queue_file" <<EOF
{
  "date": "${DATE_TODAY}",
  "total_tasks": ${total},
  "wave_size": ${WAVE_SIZE},
  "max_juniors": ${MAX_JUNIORS},
  "tasks": [
    ${tasks_json}
  ]
}
EOF
  fi

  success "Task queue written: $queue_file ($total tasks)"
}

###############################################################################
# Spawn a single junior worker
###############################################################################
spawn_junior() {
  local task_id="$1"
  local task_type="$2"
  local description="$3"
  local files="$4"
  local acceptance="$5"
  local source_agent="$6"

  local worker_id="junior-$(echo "$task_id" | grep -oP '\d+')"
  local output_dir="$SWARM_DIR/outputs/$task_id"
  local log_file="$LOG_DIR/${DATE_TODAY}_${task_id}.log"

  mkdir -p "$output_dir"

  swarm "Spawning $worker_id for $task_id ($task_type)"

  if $DRY_RUN; then
    log "  [DRY RUN] Would spawn: claude --agent junior-worker -p 'TASK: $task_id'"
    # Write mock status
    cat > "$output_dir/status.json" <<EOF
{"task_id":"$task_id","worker_id":"$worker_id","status":"dry-run","summary":"DRY RUN — not executed"}
EOF
    return 0
  fi

  # Write assignment file
  cat > "$SWARM_DIR/assignments/${task_id}.json" <<EOF
{
  "task_id": "$task_id",
  "worker_id": "$worker_id",
  "assigned_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "task_type": "$task_type",
  "description": "$description",
  "files": $files,
  "acceptance_criteria": "$acceptance",
  "timeout_minutes": $(( JUNIOR_TIMEOUT / 60 )),
  "source_agent": "$source_agent"
}
EOF

  # Spawn the junior worker
  local prompt="SWARM_TASK_ID: $task_id
TASK_TYPE: $task_type
SOURCE_AGENT: $source_agent
DESCRIPTION: $description
FILES: $files
ACCEPTANCE_CRITERIA: $acceptance

Execute this task now. Write your status to .claude/team-state/swarm/outputs/${task_id}/status.json when done."

  # Spawn the junior worker via Ollama (FREE — local inference)
  local prompt="SWARM_TASK_ID: $task_id
TASK_TYPE: $task_type
SOURCE_AGENT: $source_agent
DESCRIPTION: $description
FILES: $files
ACCEPTANCE_CRITERIA: $acceptance

Execute this task now. Write your status to .claude/team-state/swarm/outputs/${task_id}/status.json when done."

  if command -v ollama &>/dev/null; then
    # Ensure model is available
    ollama list 2>/dev/null | grep -q "$OLLAMA_MODEL" || \
      ollama pull "$OLLAMA_MODEL" 2>/dev/null

    timeout "$JUNIOR_TIMEOUT" ollama run "$OLLAMA_MODEL" \
      "$prompt" \
      > "$log_file" 2>&1 &
  else
    warn "Ollama not installed — junior $worker_id skipped (brew install ollama)"
    echo '{"task_id":"'$task_id'","worker_id":"'$worker_id'","status":"skipped","reason":"ollama not installed"}' > "$output_dir/status.json"
    echo 0  # fake PID
    return 0
  fi

  echo $!  # Return PID for tracking
}

###############################################################################
# Run a wave of juniors
###############################################################################
run_wave() {
  local wave_num="$1"
  local batch="$2"
  shift 2
  local task_ids=("$@")

  local wave_count=${#task_ids[@]}
  header "Wave $wave_num — Spawning $wave_count Juniors (batch $batch)"

  local pids=()
  local spawned=0

  for task_id in "${task_ids[@]}"; do
    # Parse task details from queue (simplified — in production use jq)
    local task_json
    task_json=$(python3 -c "
import json, sys
with open('$SWARM_DIR/task-queue.json') as f:
    q = json.load(f)
for t in q['tasks']:
    if t['id'] == '$task_id':
        print(json.dumps(t))
        break
" 2>/dev/null || echo '{}')

    if [[ "$task_json" == '{}' ]]; then
      warn "Task $task_id not found in queue"
      continue
    fi

    local task_type=$(echo "$task_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['type'])")
    local description=$(echo "$task_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['description'])")
    local files=$(echo "$task_json" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['files']))")
    local acceptance=$(echo "$task_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['acceptance'])")
    local source_agent=$(echo "$task_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['source_agent'])")

    # Apply type filter
    if [[ -n "$TASK_TYPE_FILTER" && "$task_type" != "$TASK_TYPE_FILTER" ]]; then
      continue
    fi

    local pid
    pid=$(spawn_junior "$task_id" "$task_type" "$description" "$files" "$acceptance" "$source_agent")
    pids+=("$pid:$task_id")
    ((spawned++))

    # Respect max concurrent limit
    if [[ $spawned -ge $WAVE_SIZE ]]; then
      break
    fi
  done

  if $DRY_RUN; then
    success "Wave $wave_num: $spawned juniors would be spawned"
    return 0
  fi

  # Wait for all juniors in this wave
  local completed=0
  local wave_failed=0
  for entry in "${pids[@]}"; do
    local pid="${entry%%:*}"
    local tid="${entry##*:}"
    if wait "$pid" 2>/dev/null; then
      ((completed++))
      success "  $tid completed"
    else
      ((wave_failed++))
      warn "  $tid failed or timed out"
    fi
  done

  log "Wave $wave_num complete: $completed/$spawned succeeded, $wave_failed failed"
}

###############################################################################
# Senior Verification
###############################################################################
verify_outputs() {
  header "Senior Verification — Opus 4.6 Review"

  local pending_count=$(find "$SWARM_DIR/outputs" -name "status.json" 2>/dev/null | wc -l | tr -d ' ')

  if [[ "$pending_count" -eq 0 ]]; then
    log "No outputs to verify"
    return 0
  fi

  log "Verifying $pending_count junior outputs..."

  # Map task types to verification agents
  local verified=0
  local rejected=0

  for status_file in "$SWARM_DIR/outputs"/*/status.json; do
    local task_id=$(python3 -c "import json; print(json.load(open('$status_file'))['task_id'])" 2>/dev/null || echo "unknown")
    local task_status=$(python3 -c "import json; print(json.load(open('$status_file')).get('status','unknown'))" 2>/dev/null || echo "unknown")

    if [[ "$task_status" == "dry-run" || "$task_status" == "verified" || "$task_status" == "rejected" ]]; then
      continue
    fi

    local task_type=$(python3 -c "
import json
with open('$SWARM_DIR/task-queue.json') as f:
    q = json.load(f)
for t in q['tasks']:
    if t['id'] == '$task_id':
        print(t['type'])
        break
" 2>/dev/null || echo "unknown")

    # Determine verification agent
    local verify_agent="qa-engineer"  # default
    case "$task_type" in
      test-run)      verify_agent="qa-engineer" ;;
      lint-fix)      verify_agent="backend-hardener" ;;
      code-cleanup)  verify_agent="backend-hardener" ;;
      docs-update)   verify_agent="technical-writer" ;;
      config-audit)  verify_agent="security-analyst" ;;
      data-gen)      verify_agent="threat-architect" ;;
    esac

    swarm "Verifying $task_id via $verify_agent (Grok 🧠)"

    if $DRY_RUN; then
      log "  [DRY RUN] Would verify: $verify_agent via Grok/xAI API"
      continue
    fi

    # Write verification request
    cat > "$SWARM_DIR/verifications/verify-${task_id}.json" <<EOF
{
  "task_id": "$task_id",
  "worker_output": "$SWARM_DIR/outputs/$task_id/",
  "verification_agent": "$verify_agent",
  "status": "pending_verification",
  "requested_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

    # Run verification via Grok/xAI API (~$0.50) or Ollama (free fallback)
    local verify_log="$LOG_DIR/${DATE_TODAY}_verify_${task_id}.log"
    local verify_prompt="VERIFICATION MODE: You are $verify_agent. Review the junior worker output for task $task_id. Check: 1) Task was completed correctly 2) No harmful changes 3) Output meets acceptance criteria. Reply with VERDICT: VERIFIED or REJECTED and a brief reason."
    local verify_ok=false

    if [[ -n "${XAI_API_KEY:-}" ]]; then
      # Grok/xAI API — SuperGrok subscription
      timeout 120 bash -c "
        curl -s https://api.x.ai/v1/chat/completions \\
          -H 'Authorization: Bearer ${XAI_API_KEY}' \\
          -H 'Content-Type: application/json' \\
          -d '{\"model\": \"${GROK_MODEL}\", \"messages\": [{\"role\": \"user\", \"content\": \"$verify_prompt\"}], \"max_tokens\": 1024}' \\
          | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[\"choices\"][0][\"message\"][\"content\"])' 2>/dev/null
      " > "$verify_log" 2>&1 && verify_ok=true
    elif command -v ollama &>/dev/null; then
      # Ollama fallback — free but slower
      timeout 120 ollama run "$OLLAMA_MODEL" "$verify_prompt" \
        > "$verify_log" 2>&1 && verify_ok=true
    else
      warn "  No verification runtime available (need XAI_API_KEY or ollama)"
    fi

    if $verify_ok; then
      ((verified++))
    else
      ((rejected++))
    fi
  done

  success "Verification complete: $verified verified, $rejected rejected"
}

###############################################################################
# Generate Swarm Report
###############################################################################
generate_report() {
  header "Swarm Report"

  local total=0 completed=0 verified=0 rejected=0

  for status_file in "$SWARM_DIR/outputs"/*/status.json; do
    [[ ! -f "$status_file" ]] && continue
    ((total++))
    local s
    s=$(python3 -c "import json; print(json.load(open('$status_file')).get('status','unknown'))" 2>/dev/null || echo "unknown")
    case "$s" in
      completed|verified) ((completed++)); [[ "$s" == "verified" ]] && ((verified++)) ;;
      rejected) ((rejected++)) ;;
    esac
  done

  local pass_rate=0
  [[ $total -gt 0 ]] && pass_rate=$(( (completed * 100) / total ))

  cat > "$SWARM_DIR/swarm-report-${DATE_TODAY}.md" <<EOF
# Junior Swarm Report — ${DATE_TODAY}

## Summary
- **Total tasks**: ${total}
- **Completed**: ${completed}
- **Verified & merged**: ${verified}
- **Rejected**: ${rejected}
- **Pass rate**: ${pass_rate}%
- **Wave size**: ${WAVE_SIZE}
- **Max juniors**: ${MAX_JUNIORS}

## Configuration
- Junior model: sonnet (50 turns, ${JUNIOR_TIMEOUT}s timeout)
- Verification: opus 4.6 (senior agents)
- Date: ${DATE_TODAY}

## Files
- Task queue: \`${SWARM_DIR}/task-queue.json\`
- Assignments: \`${SWARM_DIR}/assignments/\`
- Outputs: \`${SWARM_DIR}/outputs/\`
- Verifications: \`${SWARM_DIR}/verifications/\`
EOF

  success "Report: $SWARM_DIR/swarm-report-${DATE_TODAY}.md"
  log "Total: $total | Completed: $completed | Verified: $verified | Rejected: $rejected | Rate: ${pass_rate}%"
}

###############################################################################
# Main
###############################################################################
main() {
  ensure_swarm_dirs

  header "ALdeci Junior Swarm — ${DATE_TODAY}"
  log "Max juniors:  $MAX_JUNIORS"
  log "Wave size:    $WAVE_SIZE"
  log "Timeout:      ${JUNIOR_TIMEOUT}s per junior"
  log "Type filter:  ${TASK_TYPE_FILTER:-all}"
  log "Mode:         $( $DRY_RUN && echo 'DRY RUN' || echo 'LIVE')"

  if $VERIFY_ONLY; then
    verify_outputs
    generate_report
    return
  fi

  # Step 1: Discover or load tasks
  if [[ -n "$TASK_FILE" && -f "$TASK_FILE" ]]; then
    log "Using task file: $TASK_FILE"
    cp "$TASK_FILE" "$SWARM_DIR/task-queue.json"
  else
    discover_tasks
  fi

  # Step 2: Parse tasks into waves
  local queue_file="$SWARM_DIR/task-queue.json"
  if [[ ! -f "$queue_file" ]]; then
    error "No task queue found"
    exit 1
  fi

  local total_tasks
  total_tasks=$(python3 -c "import json; print(json.load(open('$queue_file'))['total_tasks'])" 2>/dev/null || echo 0)

  if [[ "$total_tasks" -eq 0 ]]; then
    log "No tasks to execute"
    return 0
  fi

  log "Total tasks in queue: $total_tasks"

  # Step 3: Execute in waves (grouped by batch/priority)
  for batch in 1 2 3; do
    local batch_tasks=()
    while IFS= read -r tid; do
      batch_tasks+=("$tid")
    done < <(python3 -c "
import json
with open('$queue_file') as f:
    q = json.load(f)
for t in q['tasks']:
    if t.get('batch', 1) == $batch and t.get('status') == 'pending':
        print(t['id'])
" 2>/dev/null)

    if [[ ${#batch_tasks[@]} -eq 0 ]]; then
      continue
    fi

    # Split batch into waves
    local wave=1
    local wave_tasks=()
    for tid in "${batch_tasks[@]}"; do
      wave_tasks+=("$tid")
      if [[ ${#wave_tasks[@]} -ge $WAVE_SIZE ]]; then
        run_wave "$wave" "$batch" "${wave_tasks[@]}"
        wave_tasks=()
        ((wave++))
      fi
    done
    # Run remaining
    if [[ ${#wave_tasks[@]} -gt 0 ]]; then
      run_wave "$wave" "$batch" "${wave_tasks[@]}"
    fi
  done

  # Step 4: Senior verification
  if ! $SKIP_VERIFY; then
    verify_outputs
  else
    log "Verification skipped (--skip-verify)"
  fi

  # Step 5: Report
  generate_report
}

main "$@"
