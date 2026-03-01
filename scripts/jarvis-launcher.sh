#!/opt/homebrew/bin/bash
###############################################################################
# JARVIS Launcher — Immortal Wrapper for run-ctem-swarm.sh
#
# This script wraps the swarm and auto-restarts on crash. It will keep
# resurrecting JARVIS until the vision is accomplished or max retries hit.
#
# Features:
#   - Auto-restart on crash with exponential backoff (30s → 60s → 120s → 240s)
#   - Heartbeat file updated every 60s (for external monitoring)
#   - Crash log with timestamps and exit codes
#   - Max restart limit (default: 10) to prevent infinite loops
#   - Slack webhook notification on crash/completion (optional)
#   - Lock file to prevent duplicate launches
#   - Full stdout/stderr logging with rotation
#   - caffeinate built-in (prevents Mac sleep)
#   - Works inside tmux or standalone
#
# Usage:
#   ./scripts/jarvis-launcher.sh                    # Default: 3 iterations, auto-restart
#   ./scripts/jarvis-launcher.sh --max-restarts 20  # Allow more restarts
#   ./scripts/jarvis-launcher.sh --slack-webhook URL # Notify on crash/done
#   ./scripts/jarvis-launcher.sh --dry-run           # Show what would happen
#   ./scripts/jarvis-launcher.sh --stop              # Kill running JARVIS
#   ./scripts/jarvis-launcher.sh --status            # Check if JARVIS is alive
#
# Quick start (recommended):
#   tmux new -s jarvis './scripts/jarvis-launcher.sh 2>&1 | tee logs/jarvis.log'
#   # Then Ctrl+B, D to detach. Walk away. Come back whenever.
#
###############################################################################

set -uo pipefail  # No -e: we handle errors ourselves

# ━━━ PATHS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SWARM_SCRIPT="$SCRIPT_DIR/run-ctem-swarm.sh"
LOG_DIR="$PROJECT_ROOT/logs/jarvis"
STATE_DIR="$PROJECT_ROOT/.claude/team-state"
LOCK_FILE="$PROJECT_ROOT/.claude/team-state/jarvis.lock"
HEARTBEAT_FILE="$PROJECT_ROOT/.claude/team-state/jarvis-heartbeat.json"
CRASH_LOG="$PROJECT_ROOT/logs/jarvis/crash-history.log"
PID_FILE="$PROJECT_ROOT/.claude/team-state/jarvis.pid"

# ━━━ CONFIG ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MAX_RESTARTS=15                # More resilience for fast iteration
BACKOFF_BASE=10                # First retry after 10s (fast recovery)
BACKOFF_CAP=120                # Max backoff: 2 minutes
HEARTBEAT_INTERVAL=60          # Update heartbeat file every 60s
SLACK_WEBHOOK=""               # Set via --slack-webhook or JARVIS_SLACK_WEBHOOK env
DRY_RUN=false
SWARM_ARGS=""                  # Extra args to pass to run-ctem-swarm.sh
CAFFEINATE_PID=""

# ━━━ RUNTIME STATE (initialized early so cleanup trap never hits unbound vars) ━━━
LAUNCHER_START=$(date +%s)
RESTART_COUNT=0
LAST_EXIT_CODE=0
CONSECUTIVE_FAST_CRASHES=0
HEARTBEAT_PID=""
CURRENT_RUN_START="not-started"

# ━━━ COLORS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ━━━ PARSE ARGS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-restarts) MAX_RESTARTS="$2"; shift 2 ;;
    --slack-webhook) SLACK_WEBHOOK="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --stop)
      if [[ -f "$PID_FILE" ]]; then
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
          echo -e "${YELLOW}Stopping JARVIS (PID: $pid)...${NC}"
          kill "$pid"
          rm -f "$LOCK_FILE" "$PID_FILE"
          echo -e "${GREEN}JARVIS stopped.${NC}"
        else
          echo "JARVIS not running (stale PID file). Cleaning up."
          rm -f "$LOCK_FILE" "$PID_FILE"
        fi
      else
        echo "No PID file found. JARVIS may not be running."
        rm -f "$LOCK_FILE"
      fi
      exit 0
      ;;
    --status)
      if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo -e "${GREEN}JARVIS is ALIVE${NC} (PID: $(cat "$PID_FILE"))"
        if [[ -f "$HEARTBEAT_FILE" ]]; then
          echo "Last heartbeat:"
          cat "$HEARTBEAT_FILE"
        fi
      else
        echo -e "${RED}JARVIS is NOT running${NC}"
        [[ -f "$CRASH_LOG" ]] && echo "Last crash:" && tail -5 "$CRASH_LOG"
      fi
      exit 0
      ;;
    --help|-h)
      echo "JARVIS Launcher — Immortal wrapper for the CTEM+ AI Swarm"
      echo ""
      echo "Usage: $0 [options] [-- swarm-args...]"
      echo ""
      echo "Options:"
      echo "  --max-restarts N     Max crash restarts (default: 10)"
      echo "  --slack-webhook URL  Notify on crash/completion"
      echo "  --dry-run            Show plan without executing"
      echo "  --stop               Kill running JARVIS"
      echo "  --status             Check if JARVIS is alive"
      echo "  --help               Show this help"
      echo ""
      echo "Examples:"
      echo "  $0                                      # Default launch"
      echo "  $0 --max-restarts 20                    # Allow more restarts"
      echo "  $0 -- --iterations 5 --min-runtime 15   # Pass args to swarm"
      echo "  tmux new -s jarvis '$0'                 # Launch in tmux (recommended)"
      exit 0
      ;;
    --)
      shift
      SWARM_ARGS="$*"
      break
      ;;
    *)
      SWARM_ARGS+=" $1"
      shift
      ;;
  esac
done

# Use env var as fallback for Slack
[[ -z "$SLACK_WEBHOOK" && -n "${JARVIS_SLACK_WEBHOOK:-}" ]] && SLACK_WEBHOOK="$JARVIS_SLACK_WEBHOOK"

# ━━━ FUNCTIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

log()  { echo -e "${CYAN}[JARVIS $(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[JARVIS $(date +%H:%M:%S)] ⚠${NC}  $*"; }
err()  { echo -e "${RED}[JARVIS $(date +%H:%M:%S)] ✖${NC}  $*"; }
ok()   { echo -e "${GREEN}[JARVIS $(date +%H:%M:%S)] ✔${NC}  $*"; }

notify_slack() {
  local message="$1"
  if [[ -n "$SLACK_WEBHOOK" ]]; then
    curl -s -X POST -H 'Content-type: application/json' \
      --data "{\"text\":\"🤖 JARVIS: ${message}\"}" \
      "$SLACK_WEBHOOK" > /dev/null 2>&1 || true
  fi
}

notify_macos() {
  local title="$1"
  local message="$2"
  osascript -e "display notification \"$message\" with title \"$title\"" 2>/dev/null || true
}

update_heartbeat() {
  cat > "$HEARTBEAT_FILE" <<EOF
{
  "status": "$1",
  "pid": $$,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "uptime_seconds": $(( $(date +%s) - LAUNCHER_START )),
  "restart_count": $RESTART_COUNT,
  "max_restarts": $MAX_RESTARTS,
  "current_run_start": "${CURRENT_RUN_START:-unknown}",
  "last_exit_code": ${LAST_EXIT_CODE:-0}
}
EOF
}

heartbeat_loop() {
  while true; do
    sleep "$HEARTBEAT_INTERVAL"
    update_heartbeat "running"
  done
}

# ━━━ LIVE STATUS TICKER — Shows user what JARVIS is doing every 10s ━━━━━━━
STATUS_TICKER_PID=""
CURRENT_AGENT_FILE="$STATE_DIR/.jarvis-current-agent"

live_status_ticker() {
  local tick=0
  local spinner=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  
  while true; do
    sleep 10
    tick=$((tick + 1))
    local elapsed=$(( $(date +%s) - LAUNCHER_START ))
    local hours=$((elapsed / 3600))
    local mins=$(( (elapsed % 3600) / 60 ))
    local secs=$((elapsed % 60))
    local s_idx=$(( tick % ${#spinner[@]} ))
    local spin="${spinner[$s_idx]}"
    
    # Read current agent from status file (set by swarm script)
    local current_agent="initializing..."
    if [[ -f "$CURRENT_AGENT_FILE" ]]; then
      current_agent=$(cat "$CURRENT_AGENT_FILE" 2>/dev/null || echo "unknown")
    fi

    # Count completed agents
    local done_count=0
    local fail_count=0
    for sf in "$STATE_DIR"/*-status.md; do
      [[ -f "$sf" ]] || continue
      if grep -q '✅ Completed' "$sf" 2>/dev/null; then
        done_count=$((done_count + 1))
      elif grep -q '❌ Failed' "$sf" 2>/dev/null; then
        fail_count=$((fail_count + 1))
      fi
    done

    # Count app file changes (ignore .claude/, logs/, data/, __pycache__)
    local recent_changes=0
    if command -v git &>/dev/null; then
      recent_changes=$(git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null | grep -vcE '^(\.claude/|logs/|data/|__pycache__|node_modules/|WIP/)' || true)
    fi

    # Format status line
    printf "\r\033[K\033[0;36m${spin} JARVIS [%02d:%02d:%02d] │ Agent: %-22s │ Done: %d │ Failed: %d │ Restarts: %d │ App files: %d changed\033[0m" \
      "$hours" "$mins" "$secs" "$current_agent" "$done_count" "$fail_count" "$RESTART_COUNT" "$recent_changes"
  done
}

start_status_ticker() {
  # Create initial status file
  echo "starting" > "$CURRENT_AGENT_FILE"
  live_status_ticker &
  STATUS_TICKER_PID=$!
}

stop_status_ticker() {
  if [[ -n "${STATUS_TICKER_PID:-}" ]]; then
    kill "$STATUS_TICKER_PID" 2>/dev/null || true
    STATUS_TICKER_PID=""
    printf "\r\033[K"  # Clear the status line
  fi
}

log_crash() {
  local exit_code="$1"
  local attempt="$2"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "[$timestamp] CRASH #${attempt} — exit code: ${exit_code} — will retry" >> "$CRASH_LOG"
}

acquire_lock() {
  if [[ -f "$LOCK_FILE" ]]; then
    local lock_pid
    lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
      err "Another JARVIS instance is running (PID: $lock_pid)"
      err "Use '$0 --stop' to kill it, or '$0 --status' to check"
      exit 1
    else
      warn "Stale lock file found (PID $lock_pid not running). Removing."
      rm -f "$LOCK_FILE"
    fi
  fi
  echo $$ > "$LOCK_FILE"
  echo $$ > "$PID_FILE"
}

release_lock() {
  rm -f "$LOCK_FILE" "$PID_FILE"
}

cleanup() {
  log "Shutting down JARVIS launcher..."
  # Kill status ticker
  stop_status_ticker
  # Kill heartbeat background process
  [[ -n "${HEARTBEAT_PID:-}" ]] && kill "$HEARTBEAT_PID" 2>/dev/null
  # Kill caffeinate
  [[ -n "$CAFFEINATE_PID" ]] && kill "$CAFFEINATE_PID" 2>/dev/null
  update_heartbeat "stopped"
  release_lock
  log "JARVIS launcher stopped."
}

trap cleanup EXIT
trap 'log "Received SIGINT — shutting down..."; exit 130' INT
trap 'log "Received SIGTERM — shutting down..."; exit 143' TERM

# ━━━ SELF-HEALING PRE-FLIGHT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# JARVIS fixes its own problems before they become crashes.
# Every check follows: detect → warn → auto-fix → verify

HEAL_COUNT=0

mkdir -p "$LOG_DIR" "$STATE_DIR"

# ── 1. Bash version check ──────────────────────────────────────────────────
# The swarm script uses declare -A (associative arrays) which requires bash 4+
BASH_MAJOR="${BASH_VERSINFO[0]}"
if [[ "$BASH_MAJOR" -lt 4 ]]; then
  warn "Bash $BASH_VERSION detected — swarm requires bash 4+ (for associative arrays)"
  if [[ -x /opt/homebrew/bin/bash ]]; then
    ok "Auto-healing: Re-launching with /opt/homebrew/bin/bash"
    exec /opt/homebrew/bin/bash "$0" "$@"
  elif command -v brew &>/dev/null; then
    warn "Auto-healing: Installing modern bash via Homebrew..."
    brew install bash 2>&1 | tail -3
    if [[ -x /opt/homebrew/bin/bash ]]; then
      ok "Auto-healing: Bash 5 installed. Re-launching..."
      exec /opt/homebrew/bin/bash "$0" "$@"
    fi
  fi
  err "Cannot auto-heal: Install bash 4+ manually (brew install bash)"
  exit 1
fi
ok "Bash version: $BASH_VERSION"
HEAL_COUNT=$((HEAL_COUNT + 1))

# ── 2. Swarm script shebang check ──────────────────────────────────────────
# Ensure swarm script also uses modern bash
if [[ -f "$SWARM_SCRIPT" ]]; then
  swarm_shebang=$(head -1 "$SWARM_SCRIPT")
  if [[ "$swarm_shebang" == "#!/usr/bin/env bash" || "$swarm_shebang" == "#!/bin/bash" ]]; then
    if [[ -x /opt/homebrew/bin/bash ]]; then
      warn "Auto-healing: Swarm script uses system bash shebang — patching to /opt/homebrew/bin/bash"
      sed -i '' "1s|.*|#!/opt/homebrew/bin/bash|" "$SWARM_SCRIPT"
      ok "Swarm script shebang auto-fixed"
    fi
  fi
fi
HEAL_COUNT=$((HEAL_COUNT + 1))

# ── 3. Swarm script set -e check ──────────────────────────────────────────
# set -e causes false crashes in large scripts with optional file checks
if [[ -f "$SWARM_SCRIPT" ]] && grep -q '^set -euo pipefail' "$SWARM_SCRIPT"; then
  warn "Auto-healing: Swarm script has 'set -euo pipefail' (causes false crashes)"
  sed -i '' 's/^set -euo pipefail/set -uo pipefail/' "$SWARM_SCRIPT"
  ok "Removed set -e from swarm script (kept -u and pipefail)"
  HEAL_COUNT=$((HEAL_COUNT + 1))
fi

# ── 4. Swarm script debug() function check ────────────────────────────────
# debug() using $VERBOSE && echo... without || true crashes under set -e
if [[ -f "$SWARM_SCRIPT" ]] && grep -q 'VERBOSE && echo.*}$' "$SWARM_SCRIPT"; then
  warn "Auto-healing: debug() function missing || true guard"
  sed -i '' 's/\$VERBOSE && echo -e "\${DIM}\[…\] \$\*\${NC}"; }/$VERBOSE \&\& echo -e "\${DIM}[…] $*\${NC}" || true; }/' "$SWARM_SCRIPT" 2>/dev/null || true
  ok "Patched debug() with || true"
  HEAL_COUNT=$((HEAL_COUNT + 1))
fi

# ── 5. Required directories ───────────────────────────────────────────────
for dir in "$STATE_DIR"/{architecture/adrs,architecture/reviews,debates/active,debates/resolved,qa,swarm/assignments,swarm/outputs,swarm/verifications,research,marketing/battlecards,marketing/content,sales/demo-scripts,sales/poc-templates,data-science/models,threat-architect/architectures,threat-architect/feeds,threat-architect/threat-models}; do
  mkdir -p "$dir" 2>/dev/null || true
done
HEAL_COUNT=$((HEAL_COUNT + 1))

# ── 6. Swarm script executable ────────────────────────────────────────────
# Verify swarm script exists and is executable
if [[ ! -x "$SWARM_SCRIPT" ]]; then
  if [[ -f "$SWARM_SCRIPT" ]]; then
    chmod +x "$SWARM_SCRIPT"
  else
    err "Swarm script not found: $SWARM_SCRIPT"
    exit 1
  fi
fi

# ── 7. GNU coreutils (timeout command) ────────────────────────────────────
# macOS doesn't have 'timeout' — it's 'gtimeout' from coreutils
if ! command -v timeout &>/dev/null && ! command -v gtimeout &>/dev/null; then
  warn "GNU timeout not found (needed for agent time limits)"
  if command -v brew &>/dev/null; then
    warn "Auto-healing: Installing coreutils via Homebrew..."
    brew install coreutils 2>&1 | tail -3
    ok "coreutils installed (gtimeout available)"
    HEAL_COUNT=$((HEAL_COUNT + 1))
  else
    warn "Install manually: brew install coreutils"
  fi
fi

# ── 8. Claude CLI — auto-install if missing ───────────────────────────────
if ! command -v claude &>/dev/null; then
  warn "Claude CLI not found. Installing..."
  if command -v npm &>/dev/null; then
    npm install -g @anthropic-ai/claude-code 2>&1 | tail -5
    if ! command -v claude &>/dev/null; then
      # Try finding it in npm global bin
      npm_bin=$(npm bin -g 2>/dev/null || echo "")
      if [[ -n "$npm_bin" && -f "$npm_bin/claude" ]]; then
        export PATH="$npm_bin:$PATH"
        log "Added $npm_bin to PATH"
      else
        err "Claude CLI install failed. Install manually: npm install -g @anthropic-ai/claude-code"
        exit 1
      fi
    fi
    ok "Claude CLI installed successfully"
  else
    err "npm not found. Install Node.js first, then: npm install -g @anthropic-ai/claude-code"
    exit 1
  fi
fi

# ── 9. Claude CLI authentication check ────────────────────────────────────
# Verify Claude is authenticated (not just installed)
if command -v claude &>/dev/null; then
  if ! claude --version &>/dev/null; then
    warn "Claude CLI installed but not responding. May need re-authentication."
    warn "If this crashes, run 'claude' interactively first to authenticate."
  fi
fi
HEAL_COUNT=$((HEAL_COUNT + 1))

# ── 10. Clean stale lock files ─────────────────────────────────────────────
if [[ -f "$LOCK_FILE" ]]; then
  stale_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
  if [[ -n "$stale_pid" ]] && ! kill -0 "$stale_pid" 2>/dev/null; then
    warn "Auto-healing: Removing stale lock file (PID $stale_pid is dead)"
    rm -f "$LOCK_FILE" "$PID_FILE"
    HEAL_COUNT=$((HEAL_COUNT + 1))
  fi
fi

# ── 11. Clean stale heartbeat ─────────────────────────────────────────────
if [[ -f "$HEARTBEAT_FILE" ]]; then
  hb_age=$(( $(date +%s) - $(stat -f %m "$HEARTBEAT_FILE" 2>/dev/null || echo "0") ))
  if [[ $hb_age -gt 300 ]]; then
    warn "Auto-healing: Stale heartbeat (${hb_age}s old). Cleaning."
    rm -f "$HEARTBEAT_FILE"
    HEAL_COUNT=$((HEAL_COUNT + 1))
  fi
fi

ok "Self-healing pre-flight complete (${HEAL_COUNT} checks passed)"
echo ""

# Acquire exclusive lock
acquire_lock

# Prevent Mac sleep
caffeinate -dims &
CAFFEINATE_PID=$!

# ━━━ BANNER ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔════════════════════════════════════════════════════════════╗"
echo "  ║                                                            ║"
echo "  ║       ██╗ █████╗ ██████╗ ██╗   ██╗██╗███████╗              ║"
echo "  ║       ██║██╔══██╗██╔══██╗██║   ██║██║██╔════╝              ║"
echo "  ║       ██║███████║██████╔╝██║   ██║██║███████╗              ║"
echo "  ║  ██   ██║██╔══██║██╔══██╗╚██╗ ██╔╝██║╚════██║              ║"
echo "  ║  ╚█████╔╝██║  ██║██║  ██║ ╚████╔╝ ██║███████║              ║"
echo "  ║   ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝              ║"
echo "  ║                                                            ║"
echo "  ║           IMMORTAL AUTONOMOUS ENGINE                       ║"
echo "  ║    Auto-Restart · Self-Heal · Never Stop · Never Ask       ║"
echo "  ║                                                            ║"
echo "  ╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
log "Max restarts: ${MAX_RESTARTS}"
log "Backoff: ${BACKOFF_BASE}s base, ${BACKOFF_CAP}s cap"
log "Heartbeat: ${HEARTBEAT_FILE} (every ${HEARTBEAT_INTERVAL}s)"
log "Crash log: ${CRASH_LOG}"
log "Lock: ${LOCK_FILE} (PID: $$)"
[[ -n "$SLACK_WEBHOOK" ]] && log "Slack notifications: ENABLED"
[[ -n "$SWARM_ARGS" ]] && log "Swarm args: ${SWARM_ARGS}"
echo ""

if $DRY_RUN; then
  log "[DRY RUN] Would launch: $SWARM_SCRIPT --resume $SWARM_ARGS"
  log "[DRY RUN] With auto-restart up to $MAX_RESTARTS times"
  exit 0
fi

# ━━━ IMMORTAL LOOP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LAUNCHER_START=$(date +%s)  # Reset to actual launch time (was initialized early for trap safety)

# Start heartbeat in background
heartbeat_loop &
HEARTBEAT_PID=$!

# Start live status ticker (10s interval, shows current agent + progress)
start_status_ticker

notify_slack "Launcher started — max $MAX_RESTARTS restarts, PID $$"
notify_macos "JARVIS" "Autonomous engine started"

while [[ $RESTART_COUNT -le $MAX_RESTARTS ]]; do
  CURRENT_RUN_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local_start=$(date +%s)

  if [[ $RESTART_COUNT -eq 0 ]]; then
    log "━━━ INITIAL LAUNCH ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "Starting swarm (first run)..."
  else
    log "━━━ RESTART #${RESTART_COUNT} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "Auto-restarting swarm with --resume..."
  fi

  update_heartbeat "running"

  # Determine if we should use --resume (yes for restarts, no for first run)
  resume_flag=""
  if [[ $RESTART_COUNT -gt 0 ]]; then
    resume_flag="--resume"
  fi

  # Create per-run log file
  run_log="$LOG_DIR/run-${RESTART_COUNT}-$(date +%Y%m%d_%H%M%S).log"

  # ── LAUNCH THE SWARM ──
  # Output goes to BOTH screen AND log (tee), so user sees real-time progress
  # Use gstdbuf/stdbuf to force line-buffered stdout through pipe to tee
  # Without this, pipe buffer (64KB) delays output visibility by minutes
  local stdbuf_cmd=""
  if command -v gstdbuf &>/dev/null; then
    stdbuf_cmd="gstdbuf -oL"
  elif command -v stdbuf &>/dev/null; then
    stdbuf_cmd="stdbuf -oL"
  fi
  # shellcheck disable=SC2086
  $stdbuf_cmd "$SWARM_SCRIPT" $resume_flag $SWARM_ARGS 2>&1 | tee "$run_log"
  LAST_EXIT_CODE=${PIPESTATUS[0]}

  run_duration=$(( $(date +%s) - local_start ))

  if [[ $LAST_EXIT_CODE -eq 0 ]]; then
    # ── CLEAN EXIT — VISION ACCOMPLISHED ──
    stop_status_ticker
    ok "━━━ SWARM COMPLETED SUCCESSFULLY ━━━ (${run_duration}s)"
    update_heartbeat "completed"
    notify_slack "COMPLETED SUCCESSFULLY after ${RESTART_COUNT} restarts, total $(( $(date +%s) - LAUNCHER_START ))s"
    notify_macos "JARVIS" "Mission accomplished! All iterations complete."
    log "Total runtime: $(( $(date +%s) - LAUNCHER_START ))s"
    log "Total restarts: ${RESTART_COUNT}"
    log "Results in: .claude/team-state/"
    exit 0
  fi

  # ── CRASH DETECTED — SELF-HEALING ANALYSIS ──
  stop_status_ticker
  RESTART_COUNT=$((RESTART_COUNT + 1))
  log_crash "$LAST_EXIT_CODE" "$RESTART_COUNT"

  # ── AUTO-DIAGNOSE & HEAL ──
  # Analyze the crash log and attempt to fix common issues before restarting
  if [[ -f "$run_log" ]]; then
    warn "Analyzing crash log: $run_log"

    # Heal: declare -A failure (bash version too old)
    if grep -q 'declare: -A: invalid option\|declare: usage:' "$run_log" 2>/dev/null; then
      warn "DIAGNOSED: Bash too old for associative arrays"
      if [[ -x /opt/homebrew/bin/bash ]]; then
        warn "AUTO-FIX: Patching swarm shebang to /opt/homebrew/bin/bash"
        sed -i '' "1s|.*|#!/opt/homebrew/bin/bash|" "$SWARM_SCRIPT"
        ok "Fixed: Swarm script will use bash 5 on next restart"
      elif command -v brew &>/dev/null; then
        warn "AUTO-FIX: Installing bash 5 via Homebrew..."
        brew install bash 2>&1 | tail -3
        [[ -x /opt/homebrew/bin/bash ]] && sed -i '' "1s|.*|#!/opt/homebrew/bin/bash|" "$SWARM_SCRIPT"
        ok "Fixed: Installed bash 5 and patched shebang"
      fi
    fi

    # Heal: set -e false positive (unbound variable or boolean guard)
    if grep -q 'unbound variable' "$run_log" 2>/dev/null; then
      warn "DIAGNOSED: Unbound variable crash (set -euo pipefail)"
      if grep -q '^set -euo pipefail' "$SWARM_SCRIPT"; then
        warn "AUTO-FIX: Removing set -e from swarm script"
        sed -i '' 's/^set -euo pipefail/set -uo pipefail/' "$SWARM_SCRIPT"
        ok "Fixed: Removed set -e (kept -u and pipefail)"
      fi
    fi

    # Heal: debug() or boolean function returning false under set -e
    if grep -qE '\+ (false|debug)$' "$run_log" 2>/dev/null; then
      warn "DIAGNOSED: Boolean function returning false under set -e"
      if grep -q '^set -euo pipefail' "$SWARM_SCRIPT"; then
        warn "AUTO-FIX: Removing set -e"
        sed -i '' 's/^set -euo pipefail/set -uo pipefail/' "$SWARM_SCRIPT"
        ok "Fixed: Removed set -e"
      fi
    fi

    # Heal: Permission denied on script
    if grep -q 'Permission denied' "$run_log" 2>/dev/null; then
      warn "DIAGNOSED: Permission denied"
      warn "AUTO-FIX: chmod +x on swarm script"
      chmod +x "$SWARM_SCRIPT"
      ok "Fixed: Made swarm script executable"
    fi

    # Heal: Claude CLI not found (PATH issue after restart)
    if grep -q 'Claude Code CLI not found\|claude: command not found' "$run_log" 2>/dev/null; then
      warn "DIAGNOSED: Claude CLI not in PATH"
      for p in /opt/homebrew/bin /usr/local/bin "$HOME/.npm-global/bin"; do
        if [[ -f "$p/claude" ]]; then
          export PATH="$p:$PATH"
          warn "AUTO-FIX: Added $p to PATH"
          ok "Fixed: Claude CLI found at $p/claude"
          break
        fi
      done
    fi

    # Heal: Node/npm not found
    if grep -q 'npm not found\|node: command not found' "$run_log" 2>/dev/null; then
      warn "DIAGNOSED: Node.js not in PATH"
      for p in /opt/homebrew/bin /usr/local/bin; do
        if [[ -f "$p/node" ]]; then
          export PATH="$p:$PATH"
          warn "AUTO-FIX: Added $p to PATH"
          break
        fi
      done
    fi

    # Heal: timeout (GNU coreutils) not found — macOS doesn't ship it
    if grep -q 'timeout: command not found' "$run_log" 2>/dev/null; then
      warn "DIAGNOSED: GNU timeout not found (macOS needs coreutils)"
      if command -v gtimeout &>/dev/null; then
        warn "AUTO-FIX: gtimeout exists — adding gnubin to PATH"
        local gnubin="/opt/homebrew/opt/coreutils/libexec/gnubin"
        [[ -d "$gnubin" ]] && export PATH="$gnubin:$PATH"
        ok "Fixed: Added gnubin to PATH"
      elif command -v brew &>/dev/null; then
        warn "AUTO-FIX: Installing coreutils via Homebrew..."
        brew install coreutils 2>&1 | tail -3
        local gnubin="/opt/homebrew/opt/coreutils/libexec/gnubin"
        [[ -d "$gnubin" ]] && export PATH="$gnubin:$PATH"
        ok "Fixed: Installed coreutils"
      fi
    fi

    # Heal: Port 8000 conflict (API server)
    if grep -q 'Address already in use\|port 8000' "$run_log" 2>/dev/null; then
      warn "DIAGNOSED: Port 8000 already in use"
      pid_on_port=$(lsof -ti:8000 2>/dev/null || echo "")
      if [[ -n "$pid_on_port" ]]; then
        warn "AUTO-FIX: Killing process on port 8000 (PID: $pid_on_port)"
        kill "$pid_on_port" 2>/dev/null || true
        sleep 2
        ok "Fixed: Freed port 8000"
      fi
    fi

    # Log the last 10 meaningful lines for manual review
    log "Last meaningful output from crash:"
    grep -v '^$\|^[[:space:]]*$' "$run_log" | tail -10 | while IFS= read -r line; do
      echo "  > $(echo "$line" | sed 's/\x1b\[[0-9;]*m//g' | head -c 120)"
    done
  fi

  # Check for fast crashes (config errors, not transient failures)
  if [[ $run_duration -lt 60 ]]; then
    CONSECUTIVE_FAST_CRASHES=$((CONSECUTIVE_FAST_CRASHES + 1))
    if [[ $CONSECUTIVE_FAST_CRASHES -ge 3 ]]; then
      err "3 consecutive fast crashes (<60s each) — likely a config error, not a transient failure"
      err "Check the log: $run_log"
      err "Last exit code: $LAST_EXIT_CODE"
      update_heartbeat "failed-fast-crash"
      notify_slack "ABORTED: 3 consecutive fast crashes. Check logs. Exit code: $LAST_EXIT_CODE"
      notify_macos "JARVIS" "ABORTED: Repeated fast crashes. Check config."
      exit 1
    fi
  else
    CONSECUTIVE_FAST_CRASHES=0  # Reset if it ran for a decent time
  fi

  if [[ $RESTART_COUNT -gt $MAX_RESTARTS ]]; then
    err "━━━ MAX RESTARTS REACHED ($MAX_RESTARTS) ━━━"
    err "Giving up. Check crash history: $CRASH_LOG"
    update_heartbeat "failed-max-restarts"
    notify_slack "GAVE UP after $MAX_RESTARTS restarts. Last exit code: $LAST_EXIT_CODE. Total runtime: $(( $(date +%s) - LAUNCHER_START ))s"
    notify_macos "JARVIS" "Gave up after $MAX_RESTARTS restarts. Check logs."
    exit 1
  fi

  # ── EXPONENTIAL BACKOFF ──
  backoff=$(( BACKOFF_BASE * (2 ** (RESTART_COUNT - 1)) ))
  [[ $backoff -gt $BACKOFF_CAP ]] && backoff=$BACKOFF_CAP

  warn "Crash detected (exit: $LAST_EXIT_CODE, ran for ${run_duration}s)"
  warn "Restart ${RESTART_COUNT}/${MAX_RESTARTS} in ${backoff}s..."
  update_heartbeat "waiting-restart"

  # ── CIRCUIT BREAKER AWARENESS (pre-restart self-healing) ──
  # If swarm halted via circuit breaker, analyze whether the halt was from
  # infrastructure issues that our self-healing above has already fixed.
  # If so, clear the halt so --resume doesn't immediately re-halt.
  local STATE_DIR="$PROJECT_ROOT/.claude/team-state"
  if [[ -f "$STATE_DIR/swarm-halted.json" ]]; then
    warn "CIRCUIT BREAKER: Swarm was halted by circuit breaker"
    local halt_reason
    halt_reason=$(python3 -c "import json; print(json.load(open('$STATE_DIR/swarm-halted.json')).get('reason','unknown'))" 2>/dev/null || echo "unknown")
    log "  Halt reason: $halt_reason"

    # Check if we just fixed infrastructure issues that caused the halt
    local infra_healed=false
    if [[ -f "$run_log" ]]; then
      # If we detected and fixed the issue in the self-healing section above,
      # the halt was infrastructure — clear it so the next run starts fresh
      if grep -q 'AUTO-FIX:' "$run_log" 2>/dev/null; then
        infra_healed=true
        ok "CIRCUIT BREAKER: Infrastructure issues detected and fixed — clearing halt state"
      fi
      # If crash was from timeout/SIGKILL but the agent made progress, clear halt
      if grep -qE 'Agent completed|completed successfully|timed out.*progress' "$run_log" 2>/dev/null; then
        infra_healed=true
        ok "CIRCUIT BREAKER: Agents made progress despite crash — clearing halt state"
      fi
    fi

    # Also clear if halt is from a previous day (stale)
    local halt_ts
    halt_ts=$(python3 -c "import json; print(json.load(open('$STATE_DIR/swarm-halted.json')).get('timestamp',''))" 2>/dev/null || echo "")
    if [[ -n "$halt_ts" ]]; then
      local halt_date="${halt_ts:0:10}"
      local today_date
      today_date=$(date -u +%Y-%m-%d)
      if [[ "$halt_date" != "$today_date" ]]; then
        infra_healed=true
        ok "CIRCUIT BREAKER: Halt from previous day ($halt_date) — clearing stale halt"
      fi
    fi

    if $infra_healed; then
      rm -f "$STATE_DIR/swarm-halted.json" 2>/dev/null || true
      # Also clean stale failure files from previous runs
      for ff in "$STATE_DIR"/*-failure.json; do
        [[ -f "$ff" ]] || continue
        local ff_age
        ff_age=$(( $(date +%s) - $(/usr/bin/stat -f '%m' "$ff" 2>/dev/null || echo "$(date +%s)") ))
        if [[ $ff_age -gt 3600 ]]; then
          rm -f "$ff" 2>/dev/null || true
        fi
      done
      ok "CIRCUIT BREAKER: Halt state and stale failures cleared — next run starts fresh"
    else
      warn "CIRCUIT BREAKER: Could not determine halt cause was infrastructure"
      warn "  The swarm may re-halt. If so, manually clear:"
      warn "    rm $STATE_DIR/swarm-halted.json"
    fi
  fi

  # ── PATH BOOTSTRAP before restart ──
  # Ensure the swarm inherits a healthy PATH even after crash/env corruption
  for p in /opt/homebrew/bin /opt/homebrew/sbin /opt/homebrew/opt/coreutils/libexec/gnubin /usr/local/bin "$HOME/.npm-global/bin"; do
    [[ -d "$p" && ":$PATH:" != *":$p:"* ]] && export PATH="$p:$PATH"
  done

  # Re-verify critical tools are reachable before restart
  if ! command -v claude &>/dev/null; then
    warn "Claude CLI not in PATH after crash — re-searching..."
    for p in /opt/homebrew/bin /usr/local/bin "$HOME/.npm-global/bin"; do
      [[ -x "$p/claude" ]] && { export PATH="$p:$PATH"; ok "Found claude at $p"; break; }
    done
  fi

  # Activate Python venv for agents that need it
  [[ -f "$PROJECT_ROOT/.venv/bin/activate" ]] && source "$PROJECT_ROOT/.venv/bin/activate" 2>/dev/null || true

  notify_slack "Crash #${RESTART_COUNT}/${MAX_RESTARTS} (exit: $LAST_EXIT_CODE, ran ${run_duration}s). Restarting in ${backoff}s..."

  sleep "$backoff"

  # Restart status ticker for next run
  start_status_ticker
done

err "Exited immortal loop unexpectedly"
exit 1
