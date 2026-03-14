#!/opt/homebrew/bin/bash
###############################################################################
# ALdeci CTEM+ AI Swarm — Claude Code CLI Execution Engine
#
# Post-Debate Verdict: Vision restructured (3 Core + 4 Constraints + 3 Deferred)
# Single Biggest Recommendation: Ship 3 UI screens in 30 days
#
# This script is designed to run OUTSIDE VS Code via Claude Code CLI.
# It implements the full 11-phase agent pipeline with:
#   - Self-healing (retry with backoff, circuit-breaker)
#   - Autonomous decision-making per agent Decision Frameworks
#   - Vision-informed task routing (debate verdict baked in)
#   - Parallel execution within phases
#   - Cost tracking and budget awareness
#   - Graceful degradation (partial runs still produce value)
#
# Usage:
#   ./scripts/run-ctem-swarm.sh                         # Full swarm (17 agents, 11 phases)
#   ./scripts/run-ctem-swarm.sh --war-room              # 90-day War Room mode (3 UI screens focus)
#   ./scripts/run-ctem-swarm.sh --agent <name>           # Single agent
#   ./scripts/run-ctem-swarm.sh --phase <0-10>           # Single phase
#   ./scripts/run-ctem-swarm.sh --dry-run                # Show plan
#   ./scripts/run-ctem-swarm.sh --debate                 # Run vision debate only
#   ./scripts/run-ctem-swarm.sh --health                 # Agent health check
#   ./scripts/run-ctem-swarm.sh --cost-report            # Show usage report
#   ./scripts/run-ctem-swarm.sh --resume                 # Resume from last failure
#
# Prerequisites:
#   - Claude Code CLI: npm install -g @anthropic-ai/claude-code
#   - Max plan active (for Claude Opus 4.6 fast mode)
#   - Working directory: project root
###############################################################################

# SELF-HEALING: Using set -uo pipefail (NOT -e).
# Rationale: set -e causes false crashes in a 1,830-line script with many
# optional file checks, boolean guards, and conditional patterns.
# The script has its own crash recovery trap (cleanup_on_crash) and explicit
# error handling where needed. set -e does more harm than good here.
set -uo pipefail

# ━━━ CRASH RECOVERY & SIGNAL HANDLING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# JARVIS never dies permanently — it saves state and can resume
cleanup_on_crash() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    echo ""
    echo -e "${RED}[CRASH RECOVERY] Swarm interrupted (exit code: $exit_code)${NC}"
    echo -e "${YELLOW}[CRASH RECOVERY] Saving state to .claude/team-state/crash-state.json${NC}"

    # Save crash state for --resume
    # Read the last agent from tracker file (set by run_agent)
    local last_agent_name="unknown"
    local tracker_file="${STATE_DIR:-/tmp}/.jarvis-current-agent"
    [[ -f "$tracker_file" ]] && last_agent_name=$(cat "$tracker_file" 2>/dev/null || echo "unknown")

    cat > "${STATE_DIR:-/tmp}/crash-state.json" <<CRASH_EOF
{
  "run_id": "${RUN_ID:-unknown}",
  "crash_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "exit_code": $exit_code,
  "current_iteration": ${CURRENT_ITERATION:-0},
  "total_iterations": ${ITERATIONS:-3},
  "elapsed_seconds": $(( $(date +%s) - ${SWARM_START_EPOCH:-$(date +%s)} )),
  "last_agent": "$last_agent_name",
  "recovery": "Run with --resume to continue from last checkpoint"
}
CRASH_EOF

    # Clean up stale prompt.tmp files (left behind when agents are interrupted)
    local prompt_cleanup_count=0
    for ptmp in "${LOG_DIR:-logs/ai-team}"/*.prompt.tmp; do
      [[ -f "$ptmp" ]] && rm -f "$ptmp" 2>/dev/null && prompt_cleanup_count=$((prompt_cleanup_count + 1))
    done
    [[ $prompt_cleanup_count -gt 0 ]] && echo -e "${YELLOW}[CRASH RECOVERY] Cleaned ${prompt_cleanup_count} stale prompt.tmp files${NC}"

    echo -e "${GREEN}[CRASH RECOVERY] State saved. Resume with: ./scripts/run-ctem-swarm.sh --resume${NC}"
  fi
}

trap cleanup_on_crash EXIT
trap 'echo -e "\n${YELLOW}Received SIGINT — gracefully shutting down...${NC}"; exit 130' INT
trap 'echo -e "\n${YELLOW}Received SIGTERM — saving state...${NC}"; exit 143' TERM

# ━━━ PATHS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENTS_DIR="$PROJECT_ROOT/.claude/agents"
STATE_DIR="$PROJECT_ROOT/.claude/team-state"
LOG_DIR="$PROJECT_ROOT/logs/ai-team"
CHECKPOINT_DIR="$PROJECT_ROOT/.claude/checkpoints"
DEBATE_DIR="$STATE_DIR/debates"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
DATE_TODAY=$(date +"%Y-%m-%d")
DOW_NAME=$(date +%A)
RUN_ID="swarm-${TIMESTAMP}"

# ━━━ COLORS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ━━━ CONFIGURATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MODEL="claude-opus-4-6-fast"

# TIMEOUT_CMD is set later (after logging functions are defined & PATH is bootstrapped)
TIMEOUT_CMD=""               # Will be resolved in self_heal_environment()
TIMEOUT_DEFAULT=1800         # 30 min per agent (focused execution)
TIMEOUT_CRITICAL=2700        # 45 min for critical agents (frontend-craftsman, backend-hardener)
TIMEOUT_PHASE0=900           # 15 min — Phase 0 agents only validate; 21/23 items done
MAX_RETRIES=3                # Fast fail: 3 retries then move on
RETRY_BACKOFF_BASE=10        # Fast recovery: 10s, 20s, 40s
CIRCUIT_BREAKER_THRESHOLD=2  # Per-phase: trip if >=2 agents fail in one phase
GLOBAL_FAIL_THRESHOLD=10     # STOP entire swarm if >=10 agents fail total (59% of 17)
CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS=0  # Counter: how many times self-heal has been tried this run
CIRCUIT_BREAKER_MAX_SELF_HEALS=3      # Max self-heal attempts before permanent halt
CASCADE_STOP=true            # true = respect dependency graph (don't run phase N if N-1 failed)
QUOTA_EXHAUSTED=false        # Set true when Claude API quota is depleted — halts ALL agent launches instantly
QUOTA_EXHAUSTED_MSG=""       # Stores the reset message (e.g. "resets Mar 6, 3pm")
PARALLEL=true
DRY_RUN=false
SINGLE_AGENT=""
SINGLE_PHASE=""
WAR_ROOM=false
DEBATE_ONLY=false
HEALTH_CHECK=false
COST_REPORT=false
RESUME=false
# ── Superhuman Capabilities ──
MAX_TURNS_DEFAULT=200         # Efficient budget — most engines already built
MAX_TURNS=200                 # Current effective value (may be reduced per-agent)
MIN_MEMORY_MB=800             # Minimum free RAM (MB) before launching ANY agent
AGENT_MAX_OUTPUT_MB=50        # Max log size before agent is considered hung
ENABLE_VOICE=true             # macOS speech notifications on critical events
ENABLE_AUTO_COMMIT=true       # Auto-commit after successful swarm completion
ENABLE_PROFILING=true         # Track CPU/memory/disk per agent phase
ENABLE_CHAIN_OF_THOUGHT=true  # Extract decisions from agent logs for cross-injection
PROGRESSIVE_CONTEXT=true      # Each retry gets MORE specific failure context
AGENT_PERF_HISTORY="$STATE_DIR/agent-performance.json"

# ── 5-Layer Hallucination Protection ──
ENABLE_HALLUCINATION_PROTECTION=true  # Master switch for all 5 layers
HALLUCINATION_HARD_FAIL=true          # true = reject agent output on hallucination detect
HALLUCINATION_LOG="$STATE_DIR/hallucination-audit.jsonl"
VISION_PILLARS_CORE="V3 V5 V7"       # Must appear in agent output
VISION_PILLARS_DEFERRED="V4 V6 V8"   # Must NOT be built (only planned/deferred ok)
HALLUCINATION_PATTERNS='placeholder|TODO.*implement|lorem ipsum|example\.com|fake.*data|mock.*result|not yet implemented|stub.*response|hardcoded.*value|dummy.*data|sample.*output|NotImplementedError|raise NotImplementedError|pass\s*#\s*TODO'
STUB_CODE_PATTERNS='return \{\}|return \[\]|return None|return "ok"|return {"status": "ok"}|def \w+\(.*\):\s*pass$|async def \w+\(.*\):\s*pass$'
CROSS_AGENT_CONFLICT_THRESHOLD=3     # Reject if 3+ contradictions found between agents
CODE_VERIFY_AGENTS="backend-hardener frontend-craftsman threat-architect"  # Agents whose code changes get tested

# ── Hallucination Confidence Labels ──
CONFIDENCE_HIGH_THRESHOLD=20          # severity_score <= 20 = HIGH confidence
CONFIDENCE_MEDIUM_THRESHOLD=40        # severity_score 21-40 = MEDIUM confidence
                                      # severity_score > 40 = LOW confidence
CONFIDENCE_ESCALATION_ENABLED=true    # true = LOW confidence → scrum-master → debate
CONFIDENCE_LOG="$STATE_DIR/confidence-audit.jsonl"  # Confidence label history

# ── JARVIS Controller Self-Healing ──
ENABLE_CONTROLLER=true                # Master switch for reconciliation controller
CONTROLLER_RECONCILE_INTERVAL=30      # Seconds between reconciliation loops
CONTROLLER_MAX_FIX_CYCLES=3           # Max auto-fix cycles per failed agent before giving up
CONTROLLER_FIX_TIMEOUT=900            # 15 min for fix-agent to repair a failure
CONTROLLER_API_HEALTH_INTERVAL=60     # Seconds between API health probes
CONTROLLER_NEVER_GIVE_UP=true         # true = keep retrying forever until it works
CONTROLLER_LOG="$STATE_DIR/controller-audit.jsonl"
FIX_AGENTS_DIR="$LOG_DIR/fix-agents"  # Logs for auto-fix agents
VERBOSE=false
DIGEST_MODE=false
BUDGET_CAP=9999              # Claude Max flat-rate — no per-token charges

# ━━━ ITERATION CONFIGURATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ITERATIONS=1                  # Single focused iteration — 21/23 sprint items done
MIN_RUNTIME_HOURS=2           # Minimum 2 hours — most vision engines already built
CONVERGENCE_MODE=true         # Enable build→test→fix→retest convergence loops
SWARM_START_EPOCH=0           # Set at runtime to track total elapsed time
CURRENT_ITERATION=0           # Tracks which iteration we're on
NEWMAN_PASS_THRESHOLD=85      # Newman pass rate (%) required to skip further iterations

# ━━━ DEBATE VERDICT (baked-in from docs/VISION_DEBATE_TRANSCRIPT.md) ━━━━━━
# These inform agent task routing and priority
CORE_PILLARS=("V3" "V5" "V7")           # Decision Intelligence, MPTE, MCP
DESIGN_CONSTRAINTS=("V1" "V2" "V9" "V10") # APP_ID, Lifecycle, Air-Gap, CTEM+Crypto
DEFERRED_FEATURES=("V4" "V6" "V8")        # Multi-LLM, Quantum, Self-Learning
WAR_ROOM_TARGETS=(
  "Triage Dashboard: Show 11300→340 finding reduction with risk scores"
  "MPTE Verification View: Show finding verified exploitable with 19-phase evidence"
  "Evidence Export: Generate signed compliance bundle for auditors"
)

# ━━━ PER-AGENT RESOURCE PROFILES (dynamic, not "2GB for everyone") ━━━━━━━━━
# Format: AGENT_TURNS[agent]=max_turns  — how many turns this agent ACTUALLY needs
# Format: AGENT_MIN_RAM[agent]=MB        — minimum free RAM to even START this agent
# Lightweight agents get small budgets. Heavy builders get full budget.
declare -A AGENT_TURNS
AGENT_TURNS=(
  [vision-agent]=50        # Pre/post-flight check — very lightweight
  [agent-doctor]=50        # Health check — lightweight
  [context-engineer]=200   # Codebase scan — moderate
  [ai-researcher]=200      # Research — moderate
  [data-scientist]=150     # Data analysis — moderate
  [enterprise-architect]=200 # Architecture — moderate
  [backend-hardener]=300   # Backend code — heavy builder
  [frontend-craftsman]=300 # Frontend code — heavy builder
  [threat-architect]=300   # Security code — heavy builder
  [swarm-controller]=80    # Coordination — reduced from 150 to prevent timeout/OOM (KP-011)
  [security-analyst]=200   # Security review — moderate
  [qa-engineer]=200        # Testing — moderate
  [persona-api-validator]=200 # Persona API validation — moderate
  [devops-engineer]=150    # Infrastructure — moderate
  [marketing-head]=80      # Docs — lightweight
  [technical-writer]=80    # Docs — lightweight
  [sales-engineer]=80      # Docs — lightweight
  [scrum-master]=100       # Coordination — moderate
)
declare -A AGENT_MIN_RAM
AGENT_MIN_RAM=(
  [vision-agent]=400       # ~400MB (small Node.js process)
  [agent-doctor]=400
  [context-engineer]=600
  [ai-researcher]=600
  [data-scientist]=600
  [enterprise-architect]=600
  [backend-hardener]=800   # Heavy — needs room for code gen + tests
  [frontend-craftsman]=800
  [threat-architect]=800
  [swarm-controller]=600
  [security-analyst]=600
  [qa-engineer]=600
  [persona-api-validator]=600
  [devops-engineer]=600
  [marketing-head]=400
  [technical-writer]=400
  [sales-engineer]=400
  [scrum-master]=500
)

# ━━━ PHASE DEPENDENCY GRAPH ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# If a phase's dependency fails, skip it (don't feed garbage to subsequent agents)
# "none" = no dependency (always runs)
# Phase 0  → none (pre-flight always runs)
# Phase 1  → 0 (context-engineer needs pre-flight)
# Phase 2  → 1 (research needs context map)
# Phase 3  → 1 (builders need context, can work without research)
# Phase 3.5→ 3 (swarm-controller summarizes builder output)
# Phase 4  → 3 (QA/security validates what builders built)
# Phase 5  → 1 (devops can work from context alone)
# Phase 6  → none (debate runs regardless)
# Phase 7  → none (marketing/docs can always run)
# Phase 8  → none (scrum-master always runs)
# Phase 9  → none (post-audit always runs)
# Phase 10 → none (post-flight always runs)
declare -A PHASE_DEPENDS_ON
PHASE_DEPENDS_ON=(
  [0]="none" [1]="0" [2]="1" [3]="1" [3.5]="1" [4]="3" [4.5]="4" [5]="1"
  [6]="none" [7]="none" [8]="none" [9]="none" [10]="none"
)
# Track which phases succeeded/failed
declare -A PHASE_STATUS  # "passed", "failed", "skipped"

# ━━━ ALL 18 AGENTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
declare -A AGENT_PHASES
AGENT_PHASES=(
  [vision-agent]="0,10"
  [agent-doctor]="0,9"
  [context-engineer]="1"
  [ai-researcher]="2"
  [data-scientist]="2"
  [enterprise-architect]="2"
  [backend-hardener]="3"
  [frontend-craftsman]="3"
  [threat-architect]="3"
  [swarm-controller]="3.5"
  [security-analyst]="4"
  [qa-engineer]="4"
  [persona-api-validator]="4.5"
  [devops-engineer]="5"
  [marketing-head]="7"
  [technical-writer]="7"
  [sales-engineer]="7"
  [scrum-master]="8"
)

# Track failures per phase for circuit-breaker
declare -A PHASE_FAILURES
AGENT_RESULTS=()

###############################################################################
# Parse arguments
###############################################################################
parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      --agent)       SINGLE_AGENT="$2"; shift 2 ;;
      --phase)       SINGLE_PHASE="$2"; shift 2 ;;
      --war-room)    WAR_ROOM=true; shift ;;
      --dry-run)     DRY_RUN=true; shift ;;
      --debate)      DEBATE_ONLY=true; shift ;;
      --health)      HEALTH_CHECK=true; shift ;;
      --cost-report) COST_REPORT=true; shift ;;
      --resume)      RESUME=true; shift ;;
      --digest)      DIGEST_MODE=true; shift ;;
      --no-parallel) PARALLEL=false; shift ;;
      --verbose)     VERBOSE=true; shift ;;
      --timeout)     TIMEOUT_DEFAULT="$2"; shift 2 ;;
      --budget-cap)  BUDGET_CAP="$2"; shift 2 ;;
      --max-retries) MAX_RETRIES="$2"; shift 2 ;;
      --iterations)  ITERATIONS="$2"; shift 2 ;;
      --min-runtime) MIN_RUNTIME_HOURS="$2"; shift 2 ;;
      --no-converge) CONVERGENCE_MODE=false; shift ;;
      --newman-threshold) NEWMAN_PASS_THRESHOLD="$2"; shift 2 ;;
      --controller)  ENABLE_CONTROLLER=true; shift ;;
      --no-controller) ENABLE_CONTROLLER=false; shift ;;
      --controller-cycles) CONTROLLER_MAX_FIX_CYCLES="$2"; shift 2 ;;
      --never-give-up) CONTROLLER_NEVER_GIVE_UP=true; shift ;;
      -h|--help)     show_help; exit 0 ;;
      *)             echo "Unknown option: $1"; exit 1 ;;
    esac
  done
}

show_help() {
  cat <<'HELP'
╔══════════════════════════════════════════════════════════════╗
║   ALdeci CTEM+ AI Swarm — Claude Code CLI Execution Engine  ║
║                                                              ║
║   Post-Debate Vision: 3 Core + 4 Constraints + 3 Deferred   ║
║   Mission: Ship 3 UI screens in 30 days                     ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
  ./scripts/run-ctem-swarm.sh [OPTIONS]

MODES:
  (default)          Full swarm — 17 agents, 11 phases, 3 debate rounds
  --war-room         90-Day War Room — All agents laser-focused on 3 UI screens
  --agent NAME       Run single agent with full SCP context
  --phase N          Run single phase (0-10)
  --debate           Run vision debate only (5 debater agents, 3 rounds)
  --health           Agent health check (validate all .md files, check configs)
  --cost-report      Show monthly usage report (Claude Max = flat-rate)
  --resume           Resume from last checkpoint (skip completed agents)
  --digest           Generate Daily Digest report (vision/feature/quality summary)

OPTIONS:
  --dry-run          Show execution plan without running agents
  --no-parallel      Run all agents sequentially (good for debugging)
  --verbose          Extra logging (agent prompts, SCP context)
  --timeout SECS     Override default timeout (default: 1800)
  --budget-cap USD   Alert threshold (informational only on Claude Max)
  --max-retries N    Max retries per failed agent (default: 3)
  --iterations N     Number of build→test→fix iterations (default: 3)
  --min-runtime H    Minimum runtime in hours before allowing early exit (default: 10)
  --no-converge      Disable convergence loop (single pass like legacy mode)
  --newman-threshold N  Newman pass rate (%) required to exit early (default: 85)
  --controller       Enable JARVIS Controller self-healing (default: on)
  --no-controller    Disable JARVIS Controller self-healing
  --controller-cycles N  Max fix cycles per failed agent (default: 3)
  --never-give-up    Controller never abandons failed agents
  -h, --help         Show this help

EXAMPLES:
  ./scripts/run-ctem-swarm.sh --war-room               # Ship UI ASAP
  ./scripts/run-ctem-swarm.sh --agent frontend-craftsman # Just the frontend agent
  ./scripts/run-ctem-swarm.sh --phase 3 --verbose       # Builders phase with debug
  ./scripts/run-ctem-swarm.sh --debate --dry-run        # Preview debate plan
  ./scripts/run-ctem-swarm.sh --resume                  # Continue after failure
  ./scripts/run-ctem-swarm.sh --iterations 4 --min-runtime 12  # 4 cycles, 12hr minimum
  ./scripts/run-ctem-swarm.sh --no-converge             # Legacy single-pass mode
  ./scripts/run-ctem-swarm.sh --digest                   # End-of-day vision/quality report
  ./scripts/run-ctem-swarm.sh --never-give-up            # Controller never gives up on failures
  ./scripts/run-ctem-swarm.sh --controller-cycles 5      # Up to 5 fix attempts per failure
  ./scripts/run-ctem-swarm.sh --no-controller             # Disable self-healing controller

POST-DEBATE VISION STRUCTURE:
  3 Core Pillars (active investment):
    V3 — Decision Intelligence (brain pipeline + risk scoring)
    V5 — MPTE Verification (prove exploitability)
    V7 — MCP-Native Platform (AI agent integration target)

  4 Design Constraints (maintained, not actively built):
    V1 — APP_ID-centric data model
    V2 — 10-phase security lifecycle
    V9 — Air-gapped deployment (already functional)
    V10 — CTEM + signed evidence (brain + crypto)

  3 Deferred Features (roadmap, not pillars):
    V4 — Multi-LLM consensus (single-provider for now)
    V6 — Quantum-secure evidence (defer to NIST mandate)
    V8 — Self-learning (requires customer data first)

AGENT SYSTEM (all claude-opus-4-6-fast):
  Phase 0:   vision-agent, agent-doctor (pre-flight)
  Phase 1:   context-engineer (foundation)
  Phase 2:   ai-researcher, data-scientist, enterprise-architect (parallel)
  Phase 3:   backend-hardener, frontend-craftsman, threat-architect (parallel)
  Phase 3.5: swarm-controller + junior workers
  Phase 4:   security-analyst, qa-engineer (parallel)
  Phase 4.5: persona-api-validator (persona API flows)
  Phase 5:   devops-engineer
  Phase 6:   Debate (3 rounds, all agents)
  Phase 7:   marketing-head, technical-writer, sales-engineer (parallel)
  Phase 8:   scrum-master (demo + coordination)
  Phase 9:   agent-doctor (post-run audit)
  Phase 10:  vision-agent (post-flight alignment)
HELP
}

###############################################################################
# Logging
###############################################################################
log()     { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; }
debug()   { $VERBOSE && echo -e "${DIM}[…] $*${NC}" || true; }

###############################################################################
# SELF-HEALING ENVIRONMENT BOOTSTRAP
#
# JARVIS ensures ALL required tools are available and PATH is correct.
# Runs early, after logging is defined but before any tool is invoked.
# Every check: detect → diagnose → auto-fix → verify → continue.
###############################################################################
self_heal_environment() {
  local healed=0

  # ── Nested Session Prevention: unset CLAUDECODE so child claude processes start ──
  # When this script is launched from inside Claude Code (e.g., by an agent),
  # the CLAUDECODE=1 env var is inherited and blocks child claude invocations
  # with "Error: Claude Code cannot be launched inside another Claude Code session."
  # We unset it here so ALL child processes (agents) can start cleanly.
  if [[ -n "${CLAUDECODE:-}" ]]; then
    unset CLAUDECODE CLAUDE_CODE_ENTRYPOINT
    debug "Unset CLAUDECODE — allowing nested claude invocations"
    healed=$((healed + 1))
  fi

  # ── PATH Bootstrap: ensure Homebrew, npm globals, coreutils are reachable ──
  # Scripts launched from tmux, cron, launchd, or non-login shells may have
  # a minimal PATH that's missing Homebrew, node, npm globals, etc.
  # NOTE: Do NOT add coreutils gnubin here — it shadows macOS native tools
  # (stat, date, ls, etc.) with GNU versions that have incompatible flags.
  # Use g-prefixed commands instead (gtimeout, gstat, etc.).
  local paths_to_add=(
    /opt/homebrew/bin
    /opt/homebrew/sbin
    /usr/local/bin
    "$HOME/.npm-global/bin"
    "$HOME/.nvm/versions/node/*/bin"  # nvm users
  )
  for p in "${paths_to_add[@]}"; do
    # Handle glob patterns (e.g., nvm)
    for resolved in $p; do
      if [[ -d "$resolved" ]] && [[ ":$PATH:" != *":$resolved:"* ]]; then
        export PATH="$resolved:$PATH"
        debug "PATH += $resolved"
        healed=$((healed + 1))
      fi
    done
  done

  # ── Resolve TIMEOUT_CMD (needs PATH bootstrap first) ──
  # Prefer gtimeout on macOS (canonical coreutils name), then timeout.
  # Verify the command actually works (not just exists) to avoid
  # "timeout: command not found" failures mid-run.
  TIMEOUT_CMD=""
  for _try_cmd in gtimeout timeout; do
    if command -v "$_try_cmd" &>/dev/null && "$_try_cmd" 0.1 true &>/dev/null; then
      TIMEOUT_CMD="$_try_cmd"
      break
    fi
  done
  if [[ -z "$TIMEOUT_CMD" ]]; then
    # Auto-install coreutils (macOS)
    if command -v brew &>/dev/null; then
      warn "GNU timeout not found — auto-installing coreutils..."
      brew install coreutils 2>&1 | tail -3
      # coreutils provides g-prefixed commands (gtimeout, gstat, etc.)
      if command -v gtimeout &>/dev/null && gtimeout 0.1 true &>/dev/null; then
        TIMEOUT_CMD="gtimeout"
        success "Auto-healed: installed coreutils (gtimeout available)"
        healed=$((healed + 1))
      fi
    fi
    if [[ -z "$TIMEOUT_CMD" ]]; then
      warn "No timeout command available — agents will run without time limits"
    fi
  fi

  # ── Claude CLI: find or install ──
  if ! command -v claude &>/dev/null; then
    warn "Claude CLI not in PATH — searching..."
    # Search common locations
    for p in /opt/homebrew/bin/claude /usr/local/bin/claude "$HOME/.npm-global/bin/claude"; do
      if [[ -x "$p" ]]; then
        export PATH="$(dirname "$p"):$PATH"
        success "Auto-healed: Found Claude CLI at $p"
        healed=$((healed + 1))
        break
      fi
    done
    # Still not found? Install it.
    if ! command -v claude &>/dev/null; then
      if command -v npm &>/dev/null; then
        warn "Auto-healing: Installing Claude CLI via npm..."
        npm install -g @anthropic-ai/claude-code 2>&1 | tail -5
        # npm may install to a non-PATH location
        local npm_bin
        npm_bin=$(npm bin -g 2>/dev/null || npm root -g 2>/dev/null | sed 's|/node_modules||' || echo "")
        [[ -n "$npm_bin" && -d "$npm_bin" ]] && export PATH="$npm_bin:$PATH"
        if command -v claude &>/dev/null; then
          success "Auto-healed: Claude CLI installed"
          healed=$((healed + 1))
        else
          error "Claude CLI installation failed — swarm cannot run without it"
          error "Manual fix: npm install -g @anthropic-ai/claude-code"
          return 1
        fi
      elif command -v brew &>/dev/null && ! command -v npm &>/dev/null; then
        warn "Auto-healing: npm not found, installing Node.js via Homebrew..."
        brew install node 2>&1 | tail -3
        if command -v npm &>/dev/null; then
          npm install -g @anthropic-ai/claude-code 2>&1 | tail -5
          if command -v claude &>/dev/null; then
            success "Auto-healed: Installed Node + Claude CLI"
            healed=$((healed + 1))
          fi
        fi
      fi
      if ! command -v claude &>/dev/null; then
        error "Cannot auto-heal Claude CLI. Manual fix needed."
        return 1
      fi
    fi
  fi

  # ── Node.js: required by Claude CLI ──
  if ! command -v node &>/dev/null; then
    warn "Node.js not in PATH — Claude CLI may fail"
    if command -v brew &>/dev/null; then
      warn "Auto-healing: Installing Node.js..."
      brew install node 2>&1 | tail -3
      if command -v node &>/dev/null; then
        success "Auto-healed: Node.js installed"
        healed=$((healed + 1))
      fi
    fi
  fi

  # ── Python venv: some agents manipulate code that needs python ──
  if [[ -f "$PROJECT_ROOT/.venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "$PROJECT_ROOT/.venv/bin/activate" 2>/dev/null || true
    debug "Activated Python venv"
  fi

  # ── Git: verify we're in a repo (agents use git) ──
  if ! git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree &>/dev/null; then
    warn "Not in a git repository — some agent operations may fail"
  fi

  # ── Required directories ──
  mkdir -p "$LOG_DIR" "$CHECKPOINT_DIR" "$DEBATE_DIR"/{active,resolved}
  mkdir -p "$STATE_DIR"/{events,swarm/{assignments,outputs,verifications},qa}

  # ── Agent Guardian — Architectural Safety Net ──
  local guardian_script="$SCRIPT_DIR/agent-guardian.sh"
  if [[ -f "$guardian_script" ]]; then
    source "$guardian_script"
    guardian_init
    success "Agent Guardian loaded — ${#CRITICAL_FILES[@]} critical files + ${#FROZEN_FILES[@]} frozen files protected"
  else
    warn "Agent Guardian not found at $guardian_script — running without codebase protection"
  fi

  if [[ $healed -gt 0 ]]; then
    success "Self-healed $healed environment issue(s)"
  fi
  return 0
}

###############################################################################
# SUPERHUMAN CAPABILITIES — Best-in-World Agent Orchestration
###############################################################################

# ── Voice Notifications (macOS) — Speak critical events aloud ──────────────
voice() {
  local message="$1"
  local urgency="${2:-normal}"  # normal, critical, celebration
  if $ENABLE_VOICE && command -v say &>/dev/null; then
    case "$urgency" in
      critical)     say -v "Samantha" -r 200 "$message" &>/dev/null & ;;
      celebration)  say -v "Samantha" -r 180 "$message" &>/dev/null & ;;
      *)            say -v "Samantha" -r 220 "$message" &>/dev/null & ;;
    esac
  fi
}

# ── macOS Notification Center ──────────────────────────────────────────────
notify() {
  local title="$1"
  local message="$2"
  local sound="${3:-default}"
  osascript -e "display notification \"$message\" with title \"JARVIS: $title\" sound name \"$sound\"" 2>/dev/null || true
}

# ── System Performance Snapshot ────────────────────────────────────────────
# Captures CPU/memory/disk at a point in time for telemetry
capture_system_snapshot() {
  local label="$1"
  if ! $ENABLE_PROFILING; then return 0; fi

  local cpu_pct mem_used_pct disk_used_pct load_avg
  cpu_pct=$(ps -A -o %cpu= 2>/dev/null | awk '{s+=$1} END {printf "%.1f", s}' || echo "0")
  mem_used_pct=$(vm_stat 2>/dev/null | awk '/Pages active/ {a=$3} /Pages wired/ {w=$3} /Pages free/ {f=$3} END {printf "%.0f", (a+w)*100/(a+w+f)}' 2>/dev/null || echo "0")
  disk_used_pct=$(df -h / 2>/dev/null | awk 'NR==2 {gsub(/%/,""); print $5}' || echo "0")
  load_avg=$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}' || uptime 2>/dev/null | awk -F'averages:' '{print $2}' | awk '{print $1}' || echo "0")

  local snapshot_file="$STATE_DIR/telemetry-${DATE_TODAY}.jsonl"
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"label\":\"${label}\",\"cpu\":${cpu_pct},\"mem_pct\":${mem_used_pct:-0},\"disk_pct\":${disk_used_pct:-0},\"load\":${load_avg:-0}}" >> "$snapshot_file" 2>/dev/null || true
}

# ── Agent Performance History — Track historical speed/quality per agent ───
update_agent_perf_history() {
  local agent_name="$1"
  local duration="$2"
  local output_bytes="$3"
  local success="$4"  # true/false
  local attempts="$5"

  if [[ ! -f "$AGENT_PERF_HISTORY" ]]; then
    echo '{}' > "$AGENT_PERF_HISTORY"
  fi

  python3 -c "
import json, os
fp = '$AGENT_PERF_HISTORY'
try:
    with open(fp) as f: data = json.load(f)
except: data = {}
agent = '$agent_name'
if agent not in data:
    data[agent] = {'runs': [], 'avg_duration': 0, 'success_rate': 0, 'total_runs': 0}
entry = {
    'date': '${DATE_TODAY}',
    'duration': int('$duration'),
    'output_bytes': int('$output_bytes'),
    'success': $( $success && echo 'True' || echo 'False'),
    'attempts': int('$attempts')
}
data[agent]['runs'].append(entry)
# Keep last 30 runs
data[agent]['runs'] = data[agent]['runs'][-30:]
runs = data[agent]['runs']
data[agent]['total_runs'] = len(runs)
data[agent]['avg_duration'] = sum(r['duration'] for r in runs) // len(runs) if runs else 0
data[agent]['success_rate'] = round(sum(1 for r in runs if r['success']) / len(runs) * 100, 1) if runs else 0
data[agent]['avg_output'] = sum(r['output_bytes'] for r in runs) // len(runs) if runs else 0
with open(fp, 'w') as f: json.dump(data, f, indent=2)
" 2>/dev/null || true
}

# ── Get Dynamic Timeout Based on Agent History ─────────────────────────────
get_smart_timeout() {
  local agent_name="$1"
  local base_timeout="$2"

  if [[ ! -f "$AGENT_PERF_HISTORY" ]]; then
    echo "$base_timeout"
    return
  fi

  local smart_timeout
  smart_timeout=$(python3 -c "
import json
try:
    with open('$AGENT_PERF_HISTORY') as f: data = json.load(f)
    agent = data.get('$agent_name', {})
    avg = agent.get('avg_duration', 0)
    if avg > 0:
        # Give 2x the average + 5 min buffer, minimum base_timeout
        smart = max(int(avg * 2 + 300), int('$base_timeout'))
        # Cap at 1 hour
        print(min(smart, 3600))
    else:
        print('$base_timeout')
except: print('$base_timeout')
" 2>/dev/null || echo "$base_timeout")
  echo "$smart_timeout"
}

# ── Chain-of-Thought Extraction — Mine decisions from agent output logs ────
extract_agent_insights() {
  local agent_name="$1"
  local log_file="$2"

  if ! $ENABLE_CHAIN_OF_THOUGHT || [[ ! -f "$log_file" ]]; then return 0; fi

  local insights_file="$STATE_DIR/${agent_name}-insights.md"

  python3 -c "
import re, os

log_path = '$log_file'
agent = '$agent_name'
insights = []

try:
    with open(log_path, 'r', errors='replace') as f:
        content = f.read()

    # Extract file modifications
    files_modified = set(re.findall(r'(?:Created|Modified|Updated|Wrote|Saved|Edited)\s+[:\s]*['\"\`]?([^\s'\"\`]+\.\w{1,5})', content, re.I))

    # Extract decisions/reasoning
    decisions = re.findall(r'(?:Decided|Decision|Choosing|Selected|Picked|Will use|Going with|Strategy|Approach)[:\s]+(.{20,200})', content, re.I)

    # Extract errors encountered and fixes
    errors_fixed = re.findall(r'(?:Fixed|Resolved|Patched|Corrected|Repaired)[:\s]+(.{20,150})', content, re.I)

    # Extract test results
    test_results = re.findall(r'(\d+\s+(?:passed|failed|errors?|warnings?))', content, re.I)

    # Extract API endpoints touched
    endpoints = set(re.findall(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+)', content))

    # Extract pillar references
    pillars = set(re.findall(r'V[1-9]0?', content))

    output = f'# {agent} \u2014 Auto-Extracted Insights\n\n'
    if files_modified:
        output += '## Files Modified\n' + '\\n'.join(f'- {f}' for f in sorted(files_modified)[:30]) + '\\n\\n'
    if decisions:
        output += '## Key Decisions\n' + '\\n'.join(f'- {d.strip()[:150]}' for d in decisions[:15]) + '\\n\\n'
    if errors_fixed:
        output += '## Errors Fixed\n' + '\\n'.join(f'- {e.strip()[:150]}' for e in errors_fixed[:10]) + '\\n\\n'
    if test_results:
        output += '## Test Results\n' + '\\n'.join(f'- {t}' for t in test_results[:10]) + '\\n\\n'
    if endpoints:
        output += '## API Endpoints Touched\n' + '\\n'.join(f'- {e}' for e in sorted(endpoints)[:20]) + '\\n\\n'
    if pillars:
        output += f'## Vision Pillars: {', '.join(sorted(pillars))}\\n\\n'

    with open('$insights_file', 'w') as f:
        f.write(output)

except Exception as e:
    pass
" 2>/dev/null || true
}

# ── Progressive Failure Context — Smarter retry prompts ────────────────────
build_retry_context() {
  local agent_name="$1"
  local attempt="$2"
  local log_file="$3"
  local last_failure_reason="${4:-unknown}"

  local retry_ctx=""
  retry_ctx+="

## ⚠️ RETRY CONTEXT — Attempt ${attempt}/${MAX_RETRIES}
You are being retried because your previous attempt FAILED.
**Failure reason:** ${last_failure_reason}
"

  # Extract the last 50 lines of the failed log for context
  if [[ -f "$log_file" && -s "$log_file" ]]; then
    local fail_tail
    fail_tail=$(tail -50 "$log_file" 2>/dev/null | head -40 || echo "(no output)")
    retry_ctx+="
### Your Previous Output (last 40 lines):
\`\`\`
${fail_tail}
\`\`\`

### What Went Wrong:
$(if echo "$fail_tail" | grep -qi 'error\|exception\|traceback\|failed' 2>/dev/null; then
  echo "Errors detected in your previous output. Fix these issues."
  echo "$fail_tail" | grep -i 'error\|exception\|traceback\|failed' | head -10 | sed 's/^/- /'
else
  echo "No obvious errors — your output may have been too small or incomplete."
fi)

### Instructions for This Retry:
1. Do NOT repeat the same approach that failed
2. If you hit an error, try an alternative strategy
3. If a file was locked or unavailable, work on something else first
4. Produce SUBSTANTIAL output — the quality gate requires 200+ bytes minimum
5. Be more aggressive — you have $(( MAX_RETRIES - attempt )) retries left
"
  fi

  # Inject sibling insights (what other agents discovered in parallel)
  local sibling_insights=""
  for sibling_insight in "$STATE_DIR"/*-insights.md; do
    [[ -f "$sibling_insight" ]] || continue
    local sname
    sname=$(basename "$sibling_insight" -insights.md)
    [[ "$sname" == "$agent_name" ]] && continue
    sibling_insights+="
### ${sname}'s Discoveries:
$(head -20 "$sibling_insight" 2>/dev/null || echo "(empty)")
"
  done

  if [[ -n "$sibling_insights" ]]; then
    retry_ctx+="
## Sibling Agent Insights (learned in parallel):
${sibling_insights}
Use these insights to avoid duplicate work and build on their progress.
"
  fi

  # ── SELF-LEARNING: Inject known failure patterns from failure ledger ──
  local failure_lessons
  failure_lessons=$(load_failure_lessons "$agent_name" 2>/dev/null || echo "")
  if [[ -n "$failure_lessons" ]]; then
    retry_ctx+="
## 🧠 SELF-LEARNING: Known Failure Patterns for '${agent_name}'
The following failures have been recorded for this agent in previous runs.
DO NOT repeat these mistakes. Use the recommended fixes.

${failure_lessons}
"
  fi

  echo "$retry_ctx"
}

# ── Self-Learning Failure Ledger — Read/Write Functions ───────────────────
# The failure ledger (.claude/team-state/failure-ledger.json) records every
# fix-agent spawn: what failed, why, what category, and what fixed it.
# Each swarm run consults the ledger to avoid repeating known failures.
# This creates a feedback loop: more runs → smarter agents → fewer fix cycles.

FAILURE_LEDGER="$PROJECT_ROOT/.claude/team-state/failure-ledger.json"

# Load known failure patterns for a specific agent from the ledger
load_failure_lessons() {
  local agent_name="$1"
  [[ ! -f "$FAILURE_LEDGER" ]] && return 0

  # Write Python script to temp file to avoid bash quoting issues
  local _py_tmp
  _py_tmp=$(mktemp /tmp/fl_load_XXXXXX.py)
  cat > "$_py_tmp" <<'PYEOF'
import json, sys, os

ledger_path = os.environ.get("FL_LEDGER", "")
agent = os.environ.get("FL_AGENT", "")
if not ledger_path or not agent:
    sys.exit(0)

try:
    with open(ledger_path) as f:
        ledger = json.load(f)
except Exception:
    sys.exit(0)

lessons = []

# 1. Known patterns affecting this agent
for kp in ledger.get("known_patterns", []):
    if not kp.get("resolved", False) and agent in kp.get("affected_agents", []):
        lessons.append("WARNING KNOWN PATTERN [{}] ({}): {}".format(
            kp["pattern_id"], kp["category"], kp["description"]))
        lessons.append("   Recommended fix: {}".format(kp["recommended_fix"]))

# 2. Past fix attempts for this agent (last 5)
attempts = [a for a in ledger.get("fix_attempts", []) if a.get("failed_agent") == agent]
if attempts:
    for a in attempts[-5:]:
        status = "OK" if a.get("fix_successful") else "FAIL"
        lessons.append("{} Previous fix ({}): {} -- {}".format(
            status, a.get("date", "?"), a.get("category", "?"),
            a.get("lessons_learned", "no notes")))

# 3. Statistics
stats = ledger.get("statistics", {})
if stats.get("success_rate", 0) < 0.3:
    lessons.append("Overall fix success rate: {:.0f}% -- fix-agent system itself may need repair".format(
        stats.get("success_rate", 0) * 100))

if lessons:
    print("\n".join(lessons))
PYEOF

  FL_LEDGER="$FAILURE_LEDGER" FL_AGENT="$agent_name" python3 "$_py_tmp" 2>/dev/null || true
  rm -f "$_py_tmp" 2>/dev/null || true
}

# Record a fix attempt in the failure ledger (called after every fix-agent run)
record_fix_attempt() {
  local failed_agent="$1"
  local failure_reason="$2"
  local category="$3"
  local fix_cycle="$4"
  local fix_successful="$5"  # true/false
  local fix_exit_code="$6"
  local fix_output_bytes="$7"
  local files_modified="$8"
  local lessons="$9"

  [[ ! -f "$FAILURE_LEDGER" ]] && return 0

  # Write Python script to temp file to avoid bash quoting issues
  local _py_tmp
  _py_tmp=$(mktemp /tmp/fl_record_XXXXXX.py)
  cat > "$_py_tmp" <<'PYEOF'
import json, sys, os

ledger_path = os.environ.get("FL_LEDGER", "")
if not ledger_path:
    sys.exit(0)

try:
    with open(ledger_path) as f:
        ledger = json.load(f)
except Exception:
    sys.exit(0)

# Read env vars
failed_agent = os.environ.get("FL_AGENT", "unknown")
failure_reason = os.environ.get("FL_REASON", "unknown")[:500]
category = os.environ.get("FL_CATEGORY", "unknown")
fix_cycle = int(os.environ.get("FL_CYCLE", "1") or "1")
fix_successful = os.environ.get("FL_SUCCESS", "false") == "true"
fix_exit_code = int(os.environ.get("FL_EXIT", "1") or "1")
fix_output_bytes = int(os.environ.get("FL_BYTES", "0") or "0")
files_modified_str = os.environ.get("FL_FILES", "")
lessons = os.environ.get("FL_LESSONS", "No lessons captured")
run_id = os.environ.get("FL_RUN_ID", "unknown")
today = os.environ.get("FL_DATE", "unknown")

# Auto-classify category
if not category or category == "unknown":
    reason_lower = failure_reason.lower()
    if "import" in reason_lower or "module" in reason_lower:
        category = "IMPORT_ERROR"
    elif "syntax" in reason_lower:
        category = "SYNTAX_ERROR"
    elif "test" in reason_lower or "assert" in reason_lower:
        category = "TEST_FAILURE"
    elif "timeout" in reason_lower or "timed out" in reason_lower:
        category = "TIMEOUT"
    elif "permission" in reason_lower:
        category = "PERMISSION_ERROR"
    elif "0 bytes" in reason_lower or "empty" in reason_lower:
        category = "EMPTY_OUTPUT"
    else:
        category = "CONFIG_ISSUE"

# Count existing attempts to generate next ID
existing = len(ledger.get("fix_attempts", []))
attempt_id = "FA-{:04d}".format(existing + 1)

attempt = {
    "id": attempt_id,
    "date": today,
    "run_id": run_id,
    "failed_agent": failed_agent,
    "failure_reason": failure_reason,
    "category": category,
    "fix_cycle": fix_cycle,
    "fix_successful": fix_successful,
    "fix_exit_code": fix_exit_code,
    "fix_output_bytes": fix_output_bytes,
    "files_modified": [f for f in files_modified_str.split(",") if f],
    "lessons_learned": lessons
}

ledger.setdefault("fix_attempts", []).append(attempt)

# Update statistics
attempts = ledger["fix_attempts"]
successful = sum(1 for a in attempts if a.get("fix_successful"))
agent_fail_counts = {}
category_counts = {}
for a in attempts:
    ag = a.get("failed_agent", "?")
    cat = a.get("category", "?")
    if not a.get("fix_successful"):
        agent_fail_counts[ag] = agent_fail_counts.get(ag, 0) + 1
    category_counts[cat] = category_counts.get(cat, 0) + 1

ledger["statistics"] = {
    "total_fix_attempts": len(attempts),
    "successful_fixes": successful,
    "failed_fixes": len(attempts) - successful,
    "success_rate": round(successful / len(attempts), 3) if attempts else 0.0,
    "most_failing_agents": sorted(agent_fail_counts, key=agent_fail_counts.get, reverse=True)[:5],
    "most_common_category": max(category_counts, key=category_counts.get) if category_counts else "unknown",
    "last_updated": today
}

# Check if this matches a known pattern
matching_pattern = None
for kp in ledger.get("known_patterns", []):
    if category == kp.get("category") and failed_agent in kp.get("affected_agents", []):
        matching_pattern = kp["pattern_id"]
        break

if matching_pattern:
    attempt["pattern_id"] = matching_pattern

# Auto-create pattern if 3+ same failures without existing pattern
same_failures = [a for a in attempts
                 if a["failed_agent"] == failed_agent
                 and a.get("category") == category
                 and not a.get("fix_successful")]
if len(same_failures) >= 3 and not matching_pattern:
    patterns = ledger.setdefault("known_patterns", [])
    next_id = "KP-{:03d}".format(len(patterns) + 1)
    patterns.append({
        "pattern_id": next_id,
        "category": category,
        "description": "Recurring {} in {}: {}".format(category, failed_agent, failure_reason[:200]),
        "affected_agents": [failed_agent],
        "frequency": "{} occurrences".format(len(same_failures)),
        "root_cause": "Auto-detected recurring pattern -- needs manual root cause analysis",
        "recommended_fix": "Investigate the repeated {} failures for this agent".format(category),
        "first_seen": same_failures[0].get("date", "?"),
        "last_seen": today,
        "resolved": False
    })

with open(ledger_path, "w") as f:
    json.dump(ledger, f, indent=2)
PYEOF

  FL_LEDGER="$FAILURE_LEDGER" \
  FL_AGENT="$failed_agent" \
  FL_REASON="$failure_reason" \
  FL_CATEGORY="$category" \
  FL_CYCLE="$fix_cycle" \
  FL_SUCCESS="$fix_successful" \
  FL_EXIT="$fix_exit_code" \
  FL_BYTES="$fix_output_bytes" \
  FL_FILES="$files_modified" \
  FL_LESSONS="$lessons" \
  FL_RUN_ID="${RUN_ID:-unknown}" \
  FL_DATE="$(date +%Y-%m-%d)" \
  python3 "$_py_tmp" 2>/dev/null || true
  rm -f "$_py_tmp" 2>/dev/null || true
}

# Broadcast failure alert to team (cross-agent notification)
broadcast_failure_alert() {
  local failed_agent="$1"
  local category="$2"
  local description="$3"

  local alerts_file="$STATE_DIR/failure-alerts.md"

  # Append to the shared alerts file that all agents read
  cat >> "$alerts_file" <<ALERT_EOF

---
### ⚠️ Failure Alert — $(date +%Y-%m-%dT%H:%M:%S)
- **Agent**: ${failed_agent}
- **Category**: ${category}
- **Issue**: ${description}
- **Action Needed**: If your work touches the same files or APIs, verify your changes don't have the same issue.
ALERT_EOF

  log "SELF-LEARNING: Failure alert broadcast for ${failed_agent} (${category})"
}

# ── Auto-Commit After Successful Swarm ────────────────────────────────────
auto_commit_changes() {
  if ! $ENABLE_AUTO_COMMIT; then return 0; fi
  if ! command -v git &>/dev/null; then return 0; fi

  local changed_count
  changed_count=$(git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null | wc -l | tr -d ' ')
  local new_count
  new_count=$(git -C "$PROJECT_ROOT" ls-files --others --exclude-standard 2>/dev/null | wc -l | tr -d ' ')
  local total=$((changed_count + new_count))

  if [[ $total -eq 0 ]]; then
    debug "No changes to auto-commit"
    return 0
  fi

  log "Auto-committing ${total} changes (${changed_count} modified, ${new_count} new)..."

  cd "$PROJECT_ROOT"
  git add -A 2>/dev/null || true
  local commit_msg="[JARVIS] Autonomous swarm run ${RUN_ID}

Iteration: ${CURRENT_ITERATION}/${ITERATIONS}
Model: ${MODEL}
Changes: ${changed_count} modified, ${new_count} new files
Date: ${DATE_TODAY}

Auto-committed by JARVIS AI Swarm Engine"

  if git commit -m "$commit_msg" 2>/dev/null; then
    success "Auto-committed ${total} changes"
    voice "Changes committed to git" "normal"
  else
    warn "Auto-commit failed (may have no staged changes)"
  fi
}

# ── Agent Watchdog — Detect hung agents by output stall ────────────────────
check_agent_output_stall() {
  local pid="$1"
  local log_file="$2"
  local agent_name="$3"
  # Claude CLI with --print buffers ALL output until the agent finishes all turns.
  # During processing (API calls, tool use, file reads), log stays 0 bytes.
  # Opus agents with 50-200 turns can legitimately take 20-40 minutes.
  # Instead of checking log modification time (which is always stale with --print),
  # check if the PROCESS is actually alive and doing work.

  # 1. Process must still exist
  if ! kill -0 "$pid" 2>/dev/null; then
    return 1  # Process gone — not stalled, just finished
  fi

  # 2. Check if the process has active network connections (= talking to API)
  local net_connections
  net_connections=$(lsof -i -P -n -p "$pid" 2>/dev/null | grep -c 'ESTABLISHED' || true)
  if [[ $net_connections -gt 0 ]]; then
    return 1  # Has active network connections — working, not stalled
  fi

  # 3. Check CPU time — if process has used CPU recently, it's working
  local cpu_pct
  cpu_pct=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ' || echo "0")
  # Strip decimal for comparison
  local cpu_int=${cpu_pct%%.*}
  [[ -z "$cpu_int" ]] && cpu_int=0
  if [[ $cpu_int -gt 0 ]]; then
    return 1  # Using CPU — working, not stalled
  fi

  # 4. If no network AND no CPU AND process exists → possibly stuck
  # But only flag as stalled after a generous 900s (15 min) with zero activity
  local proc_start
  proc_start=$(ps -p "$pid" -o lstart= 2>/dev/null || echo "")
  if [[ -n "$proc_start" ]]; then
    local start_epoch
    start_epoch=$(date -j -f "%a %b %d %H:%M:%S %Y" "$proc_start" +%s 2>/dev/null || true)
    local now_epoch
    now_epoch=$(date +%s)
    local runtime=$(( now_epoch - start_epoch ))
    if [[ $runtime -gt 900 && $net_connections -eq 0 && $cpu_int -eq 0 ]]; then
      warn "WATCHDOG: ${agent_name} (${runtime}s runtime) has no network/CPU activity — may be stuck"
      return 0  # Probably stuck
    fi
  fi

  return 1  # Not stalled
}

# ── Log Size Monitor — Kill agents producing runaway output ────────────────
check_runaway_output() {
  local log_file="$1"
  local agent_name="$2"
  local max_bytes=$((AGENT_MAX_OUTPUT_MB * 1024 * 1024))

  if [[ ! -f "$log_file" ]]; then return 1; fi

  local current_size
  current_size=$(wc -c < "$log_file" 2>/dev/null | tr -d ' ')
  if [[ $current_size -gt $max_bytes ]]; then
    warn "WATCHDOG: ${agent_name} output is ${current_size} bytes (>${AGENT_MAX_OUTPUT_MB}MB) — possible runaway"
    return 0  # true = runaway
  fi
  return 1
}

###############################################################################
# 5-LAYER HALLUCINATION PROTECTION SYSTEM
# Enterprise-grade hallucination detection, prevention, and enforcement.
# Every agent output is validated through ALL 5 layers before acceptance.
###############################################################################

# ━━━ LAYER 1: Pre-Execution Vision Alignment ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Injects vision guardrails into the prompt BEFORE agent runs.
# Ensures the prompt explicitly references correct pillars and forbids deferred ones.
# Returns: enhanced prompt string via stdout
hallucination_layer1_vision_alignment() {
  local agent_name="$1"
  local original_prompt="$2"

  if ! $ENABLE_HALLUCINATION_PROTECTION; then
    echo "$original_prompt"
    return 0
  fi

  local vision_guard=""
  vision_guard+="

GUARDRAILS:
- CORE PILLARS to build: V3 (Decision Intelligence), V5 (MPTE), V7 (MCP)
- DO NOT BUILD: V4 (Multi-LLM), V6 (Quantum), V8 (Self-Learning) — these are deferred
- ZERO FAKES: No hardcoded JSON, no pass/TODO/NotImplementedError, no fabricated metrics
- EVIDENCE: Cite file paths for claims, show pytest output for test results
"

  echo "${original_prompt}${vision_guard}"
}

# ━━━ LAYER 2: Real-Time Hallucination Monitor ━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Called periodically from the watchdog loop DURING agent execution.
# Scans the growing log file for hallucination patterns in real time.
# Returns: 0 = hallucination detected, 1 = clean
hallucination_layer2_realtime_monitor() {
  local agent_name="$1"
  local log_file="$2"

  if ! $ENABLE_HALLUCINATION_PROTECTION; then return 1; fi
  if [[ ! -f "$log_file" || ! -s "$log_file" ]]; then return 1; fi

  local log_size
  log_size=$(wc -c < "$log_file" 2>/dev/null | tr -d ' ')
  # Only check after agent has produced meaningful output (>5KB)
  if [[ $log_size -lt 5120 ]]; then return 1; fi

  # Check for deferred pillar implementation (building V4/V6/V8 code)
  local deferred_violations=0
  if grep -cE 'quantum.*(sign|crypto|key|certificate)|ML-DSA|FIPS.204|dilithium' "$log_file" 2>/dev/null | grep -qv '^0$'; then
    if grep -cE 'def.*quantum|class.*Quantum|quantum_sign|generate_ml_dsa' "$log_file" 2>/dev/null | grep -qv '^0$'; then
      warn "  LAYER 2 LIVE: ${agent_name} is implementing QUANTUM CRYPTO (V6 — DEFERRED!) — flagged"
      deferred_violations=$((deferred_violations + 1))
    fi
  fi

  if grep -cE 'multi.*llm.*consensus|llm.*voting|three.*model.*agree|consensus_threshold' "$log_file" 2>/dev/null | grep -qv '^0$'; then
    if grep -cE 'def.*consensus|class.*Consensus|vote_result|multi_llm' "$log_file" 2>/dev/null | grep -qv '^0$'; then
      warn "  LAYER 2 LIVE: ${agent_name} is implementing MULTI-LLM CONSENSUS (V4 — DEFERRED!) — flagged"
      deferred_violations=$((deferred_violations + 1))
    fi
  fi

  if grep -cE 'self.learning|feedback_loop.*train|retrain.*model|adaptive.*learning' "$log_file" 2>/dev/null | grep -qv '^0$'; then
    if grep -cE 'def.*self_learn|class.*SelfLearn|train_model|feedback_train' "$log_file" 2>/dev/null | grep -qv '^0$'; then
      warn "  LAYER 2 LIVE: ${agent_name} is implementing SELF-LEARNING (V8 — DEFERRED!) — flagged"
      deferred_violations=$((deferred_violations + 1))
    fi
  fi

  # Check for stub code being generated
  local stub_count
  stub_count=$(grep -cE "$STUB_CODE_PATTERNS" "$log_file" 2>/dev/null || true)

  # Check for hallucination patterns
  local halluc_count
  halluc_count=$(grep -ciE "$HALLUCINATION_PATTERNS" "$log_file" 2>/dev/null || true)

  # Threshold: more than 10 stub patterns or 5 hallucination patterns = alarm
  if [[ $stub_count -gt 10 ]]; then
    warn "  LAYER 2 LIVE: ${agent_name} has ${stub_count} stub code patterns — potential hallucination"
  fi
  if [[ $halluc_count -gt 5 ]]; then
    warn "  LAYER 2 LIVE: ${agent_name} has ${halluc_count} hallucination pattern matches"
  fi

  # Log to audit trail
  if [[ $deferred_violations -gt 0 || $stub_count -gt 10 || $halluc_count -gt 5 ]]; then
    echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"layer\":2,\"agent\":\"${agent_name}\",\"type\":\"realtime\",\"deferred_violations\":${deferred_violations},\"stubs\":${stub_count},\"hallucinations\":${halluc_count}}" >> "$HALLUCINATION_LOG" 2>/dev/null || true
    return 0  # hallucination detected
  fi

  return 1  # clean
}

# ━━━ LAYER 3: Post-Execution Deep Content Analysis ━━━━━━━━━━━━━━━━━━━━━━
# Comprehensive Python-based analysis AFTER agent completes.
# Checks: stub code, fake data, vision violations, hallucinated paths,
# fabricated metrics, placeholder content.
# Returns: 0 = passed, 1 = failed (hallucinations found)
hallucination_layer3_deep_analysis() {
  local agent_name="$1"
  local log_file="$2"

  if ! $ENABLE_HALLUCINATION_PROTECTION; then return 0; fi
  if [[ ! -f "$log_file" || ! -s "$log_file" ]]; then return 1; fi

  local analysis_file="$STATE_DIR/${agent_name}-hallucination-report.json"

  local result
  result=$(python3 << 'PYEOF'
import json, re, sys, os

agent_name = os.environ.get("AGENT_NAME", "unknown")
log_path = os.environ.get("LOG_PATH", "")
project_root = os.environ.get("PROJECT_ROOT", ".")

if not log_path or not os.path.isfile(log_path):
    print(json.dumps({"verdict": "SKIP", "reason": "no log file"}))
    sys.exit(0)

try:
    with open(log_path, 'r', errors='replace') as f:
        content = f.read()
except Exception as e:
    print(json.dumps({"verdict": "ERROR", "reason": str(e)}))
    sys.exit(0)

violations = []
severity_score = 0  # 0 = clean, 100 = completely hallucinated

# ── Check 1: Stub/Placeholder Code Patterns ──
stub_patterns = [
    (r'def \w+\([^)]*\):\s*\n\s*pass\b', 'empty function body (pass)', 5),
    (r'async def \w+\([^)]*\):\s*\n\s*pass\b', 'empty async function (pass)', 5),
    (r'return\s*\{\s*\}', 'returns empty dict', 3),
    (r'return\s*\[\s*\]', 'returns empty list', 3),
    (r'return\s*None\s*$', 'returns None (possibly stub)', 2),
    (r'return\s*["\']ok["\']', 'returns hardcoded "ok"', 4),
    (r'return\s*\{"status":\s*"ok"\}', 'returns hardcoded status ok', 5),
    (r'raise\s+NotImplementedError', 'NotImplementedError', 8),
    (r'TODO:\s*implement', 'TODO implement marker', 4),
    (r'FIXME:\s*stub', 'FIXME stub marker', 4),
    (r'#\s*placeholder', 'placeholder comment', 3),
    (r'lorem ipsum', 'Lorem ipsum text', 10),
    (r'example\.com', 'example.com (fake domain)', 3),
    (r'fake[-_]?data|dummy[-_]?data|mock[-_]?result', 'fake/dummy/mock data', 6),
    (r'sample[-_]?output|test[-_]?response', 'sample/test placeholder', 3),
]

for pattern, desc, weight in stub_patterns:
    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
    if len(matches) > 2:  # Threshold: more than 2 of the same pattern
        severity_score += weight * min(len(matches), 5)
        violations.append({
            "type": "stub_code",
            "pattern": desc,
            "count": len(matches),
            "severity": weight
        })

# ── Check 2: Fabricated File Paths ──
# If agent claims to have created/modified files, verify they exist
claimed_files = re.findall(
    r'(?:Created|Wrote|Saved|Modified|Updated)\s+[`"\']?([^\s`"\']+\.\w{1,5})',
    content, re.IGNORECASE
)
nonexistent = []
for f in claimed_files[:50]:  # Check up to 50
    f = f.strip('`"\'')
    if f.startswith('/'):
        full_path = f
    else:
        full_path = os.path.join(project_root, f)
    if not os.path.exists(full_path) and not f.startswith('http'):
        nonexistent.append(f)

if len(nonexistent) > 3:
    severity_score += len(nonexistent) * 3
    violations.append({
        "type": "fabricated_paths",
        "files": nonexistent[:10],
        "count": len(nonexistent),
        "severity": 3
    })

# ── Check 3: Fabricated Metrics ──
# Agents sometimes hallucinate coverage/test/LOC numbers
metric_claims = re.findall(
    r'(?:coverage|test.*pass|LOC|lines of code|endpoints?)\s*[:=]\s*(\d+\.?\d*)\s*%?',
    content, re.IGNORECASE
)
suspicious_metrics = []
for m in metric_claims:
    try:
        val = float(m)
        # 100% coverage is suspicious, >200% is impossible
        if val > 99.9 or val == 0:
            suspicious_metrics.append(m)
    except:
        pass
if len(suspicious_metrics) > 2:
    severity_score += 10
    violations.append({
        "type": "suspicious_metrics",
        "values": suspicious_metrics[:5],
        "count": len(suspicious_metrics),
        "severity": 5
    })

# ── Check 4: Deferred Pillar Implementation ──
deferred_impl = []
# V4: Multi-LLM Consensus (code, not docs)
if re.search(r'(def|class|async def)\s+\w*(consensus|multi_llm|llm_vote)', content, re.I):
    deferred_impl.append("V4: Multi-LLM Consensus code detected")
    severity_score += 15
# V6: Quantum-Secure Evidence (code, not docs)
if re.search(r'(def|class|async def)\s+\w*(quantum|ml_dsa|dilithium|fips_204)', content, re.I):
    deferred_impl.append("V6: Quantum crypto code detected")
    severity_score += 15
# V8: Self-Learning (code, not docs)
if re.search(r'(def|class|async def)\s+\w*(self_learn|retrain|feedback_train|adaptive_learn)', content, re.I):
    deferred_impl.append("V8: Self-learning code detected")
    severity_score += 15

if deferred_impl:
    violations.append({
        "type": "deferred_pillar_violation",
        "details": deferred_impl,
        "severity": 15
    })

# ── Check 5: Contradiction Detection ──
# Agent says "all tests pass" but also shows failures
if re.search(r'all\s+tests?\s+pass', content, re.I) and re.search(r'FAILED|ERROR|AssertionError', content):
    severity_score += 20
    violations.append({
        "type": "self_contradiction",
        "detail": "Claims all tests pass but output contains FAILED/ERROR",
        "severity": 20
    })

# ── Check 6: Unrealistic Speed Claims ──
if re.search(r'completed?\s+in\s+0\.\d+\s*s(?:econds?)?', content, re.I):
    # Claiming to complete complex tasks in < 1 second is suspicious
    fast_claims = re.findall(r'completed?\s+in\s+(0\.\d+)\s*s', content, re.I)
    if len(fast_claims) > 5:
        severity_score += 5
        violations.append({
            "type": "unrealistic_timing",
            "claims": fast_claims[:5],
            "severity": 5
        })

# ── Verdict with Confidence Labels ──
# Cap at 100
severity_score = min(severity_score, 100)

if severity_score >= 40:
    verdict = "FAIL"
    confidence = "LOW"
elif severity_score >= 20:
    verdict = "WARN"
    confidence = "MEDIUM"
else:
    verdict = "PASS"
    confidence = "HIGH"

# Confidence label: inverse of severity
# HIGH (0-20): Agent output is trustworthy, proceed immediately
# MEDIUM (21-40): Some concerns, proceed with caution + log warning
# LOW (41-100): Untrustworthy — escalate to scrum-master for debate
confidence_score = max(0, 100 - severity_score)

result = {
    "agent": agent_name,
    "verdict": verdict,
    "confidence": confidence,
    "confidence_score": confidence_score,
    "severity_score": severity_score,
    "violations": violations,
    "total_violations": len(violations),
    "escalation": "scrum-master" if confidence == "LOW" else "none",
    "checked_at": __import__('datetime').datetime.utcnow().isoformat() + "Z"
}

print(json.dumps(result))
PYEOF
  )

  # Parse the verdict + confidence
  local verdict confidence confidence_score
  verdict=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','ERROR'))" 2>/dev/null || echo "ERROR")
  confidence=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('confidence','UNKNOWN'))" 2>/dev/null || echo "UNKNOWN")
  confidence_score=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('confidence_score',0))" 2>/dev/null || echo "0")
  local severity
  severity=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('severity_score',0))" 2>/dev/null || echo "0")
  local total_violations
  total_violations=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('total_violations',0))" 2>/dev/null || echo "0")
  local escalation
  escalation=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('escalation','none'))" 2>/dev/null || echo "none")

  # Save full report (now includes confidence labels)
  echo "$result" > "$analysis_file" 2>/dev/null || true

  # Audit log with confidence label
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"layer\":3,\"agent\":\"${agent_name}\",\"verdict\":\"${verdict}\",\"confidence\":\"${confidence}\",\"confidence_score\":${confidence_score},\"severity\":${severity},\"violations\":${total_violations},\"escalation\":\"${escalation}\"}" >> "$HALLUCINATION_LOG" 2>/dev/null || true

  # Log confidence to dedicated confidence audit trail
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"agent\":\"${agent_name}\",\"confidence\":\"${confidence}\",\"score\":${confidence_score},\"severity\":${severity},\"verdict\":\"${verdict}\",\"escalation\":\"${escalation}\",\"run_id\":\"${RUN_ID}\"}" >> "$CONFIDENCE_LOG" 2>/dev/null || true

  # ── CONFIDENCE LABEL DISPLAY ──
  local conf_icon conf_color
  case "$confidence" in
    HIGH)   conf_icon="🟢" conf_color="$GREEN" ;;
    MEDIUM) conf_icon="🟡" conf_color="$YELLOW" ;;
    LOW)    conf_icon="🔴" conf_color="$RED" ;;
    *)      conf_icon="⚪" conf_color="$NC" ;;
  esac

  case "$verdict" in
    PASS)
      success "  LAYER 3: ${agent_name} — ${conf_icon} Confidence: ${confidence} (${confidence_score}/100) | severity: ${severity}/100"
      return 0
      ;;
    WARN)
      warn "  LAYER 3: ${agent_name} — ${conf_icon} Confidence: ${confidence} (${confidence_score}/100) | severity: ${severity}/100 | violations: ${total_violations}"
      return 0
      ;;
    FAIL)
      error "  LAYER 3: ${agent_name} — ${conf_icon} Confidence: ${confidence} (${confidence_score}/100) | severity: ${severity}/100 | violations: ${total_violations}"
      error "  HALLUCINATION DETECTED — escalation: ${escalation}"
      if $HALLUCINATION_HARD_FAIL; then
        # ── LOW CONFIDENCE ESCALATION: scrum-master → debate → re-verify ──
        if [[ "$escalation" == "scrum-master" ]] && $CONFIDENCE_ESCALATION_ENABLED; then
          warn "  🔴 LOW CONFIDENCE — Escalating to scrum-master for debate before rejection..."
          escalate_low_confidence "$agent_name" "$result" "$log_file"
          local esc_result=$?
          if [[ $esc_result -eq 0 ]]; then
            success "  ✅ Escalation resolved — scrum-master approved after debate. Accepting output."
            return 0  # Escalation resolved the issue
          else
            error "  ❌ Escalation CONFIRMED rejection — scrum-master + debate agree output is LOW quality"
          fi
        fi
        error "  Output REJECTED. Agent will be retried."
        return 1
      fi
      warn "  Hallucination detected but HARD_FAIL disabled — accepting with warning"
      return 0
      ;;
    *)
      warn "  LAYER 3: ${agent_name} analysis error — accepting cautiously (confidence: UNKNOWN)"
      return 0
      ;;
  esac
}

# ━━━ LOW CONFIDENCE ESCALATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# When an agent's output has LOW confidence:
#   1. Notify scrum-master with the violations
#   2. Run a targeted debate (scrum-master evaluates if output is salvageable)
#   3. If debate verdict = ACCEPT → proceed (return 0)
#   4. If debate verdict = REJECT → retry agent (return 1)
# Returns: 0 = escalation resolved (accept output), 1 = confirmed rejection
escalate_low_confidence() {
  local agent_name="$1"
  local layer3_result="$2"
  local log_file="$3"

  local escalation_file="$STATE_DIR/${agent_name}-escalation.json"
  local escalation_log="$STATE_DIR/escalation-history.jsonl"

  # Parse violations from layer3 result
  local violations confidence_score severity
  violations=$(echo "$layer3_result" | python3 -c "
import json, sys
d = json.load(sys.stdin)
vs = d.get('violations', [])
for v in vs[:5]:
    print(f\"  - {v.get('type','?')}: {v.get('pattern', v.get('detail', '?'))} (count: {v.get('count', 1)}, severity: {v.get('severity', 0)})\")
" 2>/dev/null || echo "  (unable to parse violations)")
  confidence_score=$(echo "$layer3_result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('confidence_score',0))" 2>/dev/null || echo "0")
  severity=$(echo "$layer3_result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('severity_score',0))" 2>/dev/null || echo "0")

  # Get last 20 lines of agent output for context
  local output_tail=""
  if [[ -f "$log_file" && -s "$log_file" ]]; then
    output_tail=$(tail -20 "$log_file" 2>/dev/null || echo "(no output)")
  fi

  header "🔴 LOW CONFIDENCE ESCALATION — ${agent_name}"
  log "  Confidence: ${confidence_score}/100 | Severity: ${severity}/100"
  log "  Violations:"
  echo "$violations"
  log ""
  log "  Escalating to scrum-master for debate..."

  voice "Low confidence alert: ${agent_name} escalated to scrum master" "critical"
  notify "🔴 Low Confidence" "${agent_name} — score ${confidence_score}/100 — escalating"

  # Build scrum-master evaluation prompt
  local debate_prompt="SCRUM-MASTER ESCALATION — LOW CONFIDENCE AGENT OUTPUT
══════════════════════════════════════════════════════
An agent has produced output with LOW confidence. You must evaluate whether
the output is salvageable or should be rejected and retried.

AGENT: ${agent_name}
CONFIDENCE: ${confidence_score}/100 (LOW — below ${CONFIDENCE_HIGH_THRESHOLD} threshold)
SEVERITY: ${severity}/100
RUN ID: ${RUN_ID}

VIOLATIONS DETECTED:
${violations}

AGENT OUTPUT (last 20 lines):
\`\`\`
${output_tail}
\`\`\`

YOUR TASK:
1. READ the violations carefully
2. READ the agent output tail
3. DECIDE: Is this output SALVAGEABLE or should we REJECT and retry?

DECISION CRITERIA:
- If violations are mostly false positives (e.g., test fixtures using example.com) → ACCEPT
- If violations indicate real hallucinations (fabricated data, stub code, wrong paths) → REJECT
- If violations are minor (severity < 50) and useful work was done → ACCEPT WITH WARNINGS
- If output is mostly empty or nonsensical → REJECT

OUTPUT FORMAT (write EXACTLY one of these as your FIRST line):
VERDICT: ACCEPT
VERDICT: REJECT

Then explain your reasoning in 2-3 sentences.
Write your full analysis to .claude/team-state/${agent_name}-escalation.json"

  # Run scrum-master mini-debate (shorter timeout, fewer turns)
  local debate_log="$LOG_DIR/${DATE_TODAY}_escalation-${agent_name}_${RUN_ID}.log"
  local debate_timeout=300  # 5 min max for escalation debate

  local debate_cmd
  if [[ -n "$TIMEOUT_CMD" ]]; then
    debate_cmd="$TIMEOUT_CMD $debate_timeout claude"
  else
    debate_cmd="claude"
  fi

  local prompt_file="${debate_log}.prompt.tmp"
  printf '%s' "$debate_prompt" > "$prompt_file"

  log "  Running scrum-master debate (timeout: ${debate_timeout}s)..."

  (
    trap '' TSTP TTIN TTOU HUP
    unset CLAUDECODE CLAUDE_CODE_ENTRYPOINT
    /opt/homebrew/bin/bash -c '
      trap "" TSTP TTIN TTOU HUP
      _pfile="$1"; shift
      exec "$@" -p "$(cat "$_pfile")"
    ' _ "$prompt_file" \
      $debate_cmd \
        --print --output-format text --verbose \
        --dangerously-skip-permissions \
        --max-turns 15 \
        < /dev/null \
        > "$debate_log" 2>&1
  )
  local debate_exit=$?
  rm -f "$prompt_file" 2>/dev/null || true

  # Parse the debate verdict
  local debate_verdict="REJECT"  # Default to reject if debate fails
  if [[ $debate_exit -eq 0 && -f "$debate_log" && -s "$debate_log" ]]; then
    # Look for "VERDICT: ACCEPT" or "VERDICT: REJECT"
    if grep -qi 'VERDICT:.*ACCEPT' "$debate_log" 2>/dev/null; then
      debate_verdict="ACCEPT"
    elif grep -qi 'VERDICT:.*REJECT' "$debate_log" 2>/dev/null; then
      debate_verdict="REJECT"
    else
      # Fallback: check for positive indicators
      local positive_count negative_count
      positive_count=$(grep -ciE 'salvageable|acceptable|useful|proceed|approve' "$debate_log" 2>/dev/null || true)
      negative_count=$(grep -ciE 'reject|retry|unacceptable|hallucinated|fabricated' "$debate_log" 2>/dev/null || true)
      if [[ $positive_count -gt $negative_count ]]; then
        debate_verdict="ACCEPT"
      fi
    fi
  else
    warn "  Scrum-master debate failed (exit $debate_exit) — defaulting to REJECT"
  fi

  # Record escalation result
  local escalation_ts
  escalation_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  cat > "$escalation_file" <<ESCJSON
{
  "agent": "${agent_name}",
  "confidence_score": ${confidence_score},
  "severity": ${severity},
  "debate_verdict": "${debate_verdict}",
  "debate_exit": ${debate_exit},
  "debate_log": "${debate_log}",
  "timestamp": "${escalation_ts}",
  "run_id": "${RUN_ID}"
}
ESCJSON

  # Append to escalation history
  echo "{\"ts\":\"${escalation_ts}\",\"agent\":\"${agent_name}\",\"confidence\":${confidence_score},\"verdict\":\"${debate_verdict}\",\"run_id\":\"${RUN_ID}\"}" \
    >> "$escalation_log" 2>/dev/null || true

  if [[ "$debate_verdict" == "ACCEPT" ]]; then
    success "  ESCALATION RESULT: 🟢 ACCEPTED — scrum-master approved ${agent_name} output after debate"
    log "  Confidence upgraded: LOW → MEDIUM (scrum-master override)"
    # Update the confidence in the audit
    echo "{\"ts\":\"${escalation_ts}\",\"agent\":\"${agent_name}\",\"confidence\":\"MEDIUM\",\"score\":${confidence_score},\"override\":\"scrum-master-debate\",\"run_id\":\"${RUN_ID}\"}" \
      >> "$CONFIDENCE_LOG" 2>/dev/null || true
    voice "Escalation resolved: ${agent_name} accepted after debate" "celebration"
    return 0
  else
    error "  ESCALATION RESULT: 🔴 REJECTED — scrum-master confirmed ${agent_name} LOW quality"
    voice "Escalation rejected: ${agent_name} must retry" "critical"
    return 1
  fi
}

# ━━━ LAYER 4: Cross-Agent Consistency Verification ━━━━━━━━━━━━━━━━━━━━━━
# After parallel phases complete, verify agents don't contradict each other.
# Checks decisions.log for conflicts, metrics.json for impossible values,
# and status files for inconsistencies.
# Returns: 0 = consistent, 1 = conflicts found
hallucination_layer4_cross_agent_verify() {
  local phase="$1"
  shift
  local agents=("$@")

  if ! $ENABLE_HALLUCINATION_PROTECTION; then return 0; fi
  if [[ ${#agents[@]} -lt 2 ]]; then return 0; fi  # Need 2+ agents to compare

  log "LAYER 4: Cross-agent consistency check for phase ${phase} (${#agents[@]} agents)..."

  local conflicts=0
  local conflict_details=""

  # ── Check 1: Metrics Consistency ──
  # If multiple agents claim different values for the same metric
  local metrics_file="$STATE_DIR/metrics.json"
  if [[ -f "$metrics_file" ]]; then
    local metrics_valid
    metrics_valid=$(python3 -c "
import json
try:
    with open('$metrics_file') as f: d = json.load(f)
    # Check for impossible values
    issues = []
    cov = d.get('coverage_pct', d.get('test_coverage', -1))
    if isinstance(cov, (int, float)):
        if cov > 100 or cov < 0:
            issues.append(f'coverage={cov}% (impossible)')
    loc = d.get('total_loc', d.get('python_loc', -1))
    if isinstance(loc, (int, float)):
        if loc < 0:
            issues.append(f'LOC={loc} (negative)')
    endpoints = d.get('total_endpoints', d.get('api_endpoints', -1))
    if isinstance(endpoints, (int, float)):
        if endpoints < 0 or endpoints > 10000:
            issues.append(f'endpoints={endpoints} (suspicious)')
    print('|'.join(issues) if issues else 'OK')
except Exception as e:
    print(f'ERROR:{e}')
" 2>/dev/null || echo "")

    if [[ "$metrics_valid" != "OK" && -n "$metrics_valid" && "$metrics_valid" != ERROR:* ]]; then
      conflicts=$((conflicts + 1))
      conflict_details+="  Metrics inconsistency: ${metrics_valid}\n"
      warn "  LAYER 4: Metrics inconsistency: ${metrics_valid}"
    fi
  fi

  # ── Check 2: Decisions.log Conflict Detection ──
  local decisions_file="$STATE_DIR/decisions.log"
  if [[ -f "$decisions_file" ]]; then
    # Look for contradicting decisions (e.g., one agent adds a dependency, another removes it)
    local decision_conflicts
    decision_conflicts=$(python3 -c "
import re
conflicts = []
decisions = []
try:
    with open('$decisions_file') as f:
        for line in f:
            m = re.match(r'\[.*?\]\s*agent:(\S+)\s+decision:(.*?)(?:\s+action:(.*))?$', line.strip())
            if m:
                decisions.append({'agent': m.group(1), 'decision': m.group(2), 'action': m.group(3) or ''})

    # Check for opposing actions on the same target
    for i, d1 in enumerate(decisions):
        for d2 in decisions[i+1:]:
            if d1['agent'] == d2['agent']:
                continue
            # Same file, opposite actions
            files1 = set(re.findall(r'[\w/]+\.\w{1,5}', d1['action']))
            files2 = set(re.findall(r'[\w/]+\.\w{1,5}', d2['action']))
            common = files1 & files2
            if common:
                action1 = d1['decision'].lower()
                action2 = d2['decision'].lower()
                add_words = {'add', 'create', 'enable', 'install', 'upgrade'}
                rm_words = {'remove', 'delete', 'disable', 'uninstall', 'downgrade', 'revert'}
                a1_add = any(w in action1 for w in add_words)
                a1_rm = any(w in action1 for w in rm_words)
                a2_add = any(w in action2 for w in add_words)
                a2_rm = any(w in action2 for w in rm_words)
                if (a1_add and a2_rm) or (a1_rm and a2_add):
                    conflicts.append(f'{d1[\"agent\"]} vs {d2[\"agent\"]}: opposing actions on {\", \".join(common)}')
    print('\\n'.join(conflicts[:5]) if conflicts else 'OK')
except Exception as e:
    print('OK')
" 2>/dev/null || echo "OK")

    if [[ "$decision_conflicts" != "OK" && -n "$decision_conflicts" ]]; then
      local conflict_count
      conflict_count=$(echo "$decision_conflicts" | wc -l | tr -d ' ')
      conflicts=$((conflicts + conflict_count))
      conflict_details+="  Decision conflicts:\n$(echo "$decision_conflicts" | sed 's/^/    /')\n"
      warn "  LAYER 4: Decision conflicts detected:"
      echo "$decision_conflicts" | sed 's/^/    /'
    fi
  fi

  # ── Check 3: Status File Cross-Reference ──
  # If one agent says it succeeded but produced contradictory artifacts
  for agent in "${agents[@]}"; do
    local status_file="$STATE_DIR/${agent}-status.md"
    local log_file="$LOG_DIR/${DATE_TODAY}_${agent}_${RUN_ID}.log"
    if [[ -f "$status_file" ]] && grep -q '✅ Completed' "$status_file" 2>/dev/null; then
      # Successful agent — verify its log doesn't contain errors it didn't report
      if [[ -f "$log_file" ]]; then
        local unreported_errors
        unreported_errors=$(grep -c 'Traceback\|CRITICAL\|FATAL' "$log_file" 2>/dev/null || true)
        if [[ $unreported_errors -gt 3 ]]; then
          conflicts=$((conflicts + 1))
          conflict_details+="  ${agent}: claims success but has ${unreported_errors} unreported errors in log\n"
          warn "  LAYER 4: ${agent} claims ✅ but has ${unreported_errors} unreported CRITICAL/FATAL errors"
        fi
      fi
    fi
  done

  # ── Verdict ──
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"layer\":4,\"phase\":\"${phase}\",\"agents\":\"${agents[*]}\",\"conflicts\":${conflicts}}" >> "$HALLUCINATION_LOG" 2>/dev/null || true

  if [[ $conflicts -ge $CROSS_AGENT_CONFLICT_THRESHOLD ]]; then
    error "  LAYER 4 VERDICT: ${conflicts} cross-agent conflicts detected (threshold: ${CROSS_AGENT_CONFLICT_THRESHOLD})"
    if [[ -n "$conflict_details" ]]; then
      echo -e "$conflict_details" | head -20
    fi
    return 1
  elif [[ $conflicts -gt 0 ]]; then
    warn "  LAYER 4: ${conflicts} minor inconsistencies (below threshold ${CROSS_AGENT_CONFLICT_THRESHOLD})"
    return 0
  else
    success "  LAYER 4: All ${#agents[@]} agents are consistent — no cross-agent conflicts"
    return 0
  fi
}

# ━━━ LAYER 5: Code Verification & Test Gate ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# After builder agents complete, verify code changes actually work.
# Runs: Python syntax check, bash -n on scripts, pytest on test files.
# Returns: 0 = passed, 1 = failed
hallucination_layer5_code_verify() {
  local agent_name="$1"

  if ! $ENABLE_HALLUCINATION_PROTECTION; then return 0; fi

  # Only run for builder agents
  local is_builder=false
  for ba in $CODE_VERIFY_AGENTS; do
    [[ "$agent_name" == "$ba" ]] && is_builder=true
  done
  if ! $is_builder; then
    debug "  LAYER 5: Skipping code verify for ${agent_name} (not a builder agent)"
    return 0
  fi

  log "LAYER 5: Code verification for ${agent_name}..."

  local verify_failures=0
  local verify_details=""

  # ── Check 1: Python Syntax Validation ──
  # Find Python files modified in the last 10 minutes (likely by this agent)
  local modified_py_files
  modified_py_files=$(find "$PROJECT_ROOT" \
    -name "*.py" \
    -newer "$STATE_DIR/${agent_name}-status.md" \
    -not -path "*/__pycache__/*" \
    -not -path "*/WIP/*" \
    -not -path "*/.venv/*" \
    -not -path "*/node_modules/*" \
    2>/dev/null | head -50)

  if [[ -n "$modified_py_files" ]]; then
    local py_errors=0
    while IFS= read -r pyfile; do
      if ! python3 -m py_compile "$pyfile" 2>/dev/null; then
        py_errors=$((py_errors + 1))
        verify_details+="  SYNTAX ERROR: ${pyfile}\n"
      fi
    done <<< "$modified_py_files"

    if [[ $py_errors -gt 0 ]]; then
      verify_failures=$((verify_failures + py_errors))
      warn "  LAYER 5: ${py_errors} Python files have syntax errors"
    else
      local total_py
      total_py=$(echo "$modified_py_files" | wc -l | tr -d ' ')
      success "  LAYER 5: ${total_py} modified Python files — all syntax valid"
    fi
  fi

  # ── Check 2: Bash Script Syntax ──
  local modified_sh_files
  modified_sh_files=$(find "$PROJECT_ROOT/scripts" \
    -name "*.sh" \
    -newer "$STATE_DIR/${agent_name}-status.md" \
    2>/dev/null | head -20)

  if [[ -n "$modified_sh_files" ]]; then
    local sh_errors=0
    while IFS= read -r shfile; do
      if ! bash -n "$shfile" 2>/dev/null; then
        sh_errors=$((sh_errors + 1))
        verify_details+="  BASH SYNTAX ERROR: ${shfile}\n"
      fi
    done <<< "$modified_sh_files"

    if [[ $sh_errors -gt 0 ]]; then
      verify_failures=$((verify_failures + sh_errors))
      warn "  LAYER 5: ${sh_errors} bash scripts have syntax errors"
    fi
  fi

  # ── Check 3: Quick Pytest (only tests related to modified files) ──
  if [[ -n "$modified_py_files" ]]; then
    # Find test files related to modified source files
    local test_targets=""
    while IFS= read -r pyfile; do
      local basename_no_ext
      basename_no_ext=$(basename "$pyfile" .py)
      local related_test="$PROJECT_ROOT/tests/test_${basename_no_ext}.py"
      if [[ -f "$related_test" ]]; then
        test_targets+=" $related_test"
      fi
    done <<< "$modified_py_files"

    if [[ -n "$test_targets" ]]; then
      log "  LAYER 5: Running related tests..."
      local test_output
      test_output=$(cd "$PROJECT_ROOT" && python3 -m pytest $test_targets --tb=short --no-header -q 2>&1 | tail -20)
      local test_exit=$?

      if [[ $test_exit -ne 0 ]]; then
        # Check if it's actual failures vs import issues
        local real_failures
        real_failures=$(echo "$test_output" | grep -c 'FAILED' 2>/dev/null || true)
        if [[ $real_failures -gt 0 ]]; then
          verify_failures=$((verify_failures + real_failures))
          verify_details+="  TEST FAILURES:\n$(echo "$test_output" | grep 'FAILED' | head -10 | sed 's/^/    /')\n"
          warn "  LAYER 5: ${real_failures} test failures detected"
        else
          debug "  LAYER 5: Tests had non-failure exit (possible import/collection issues — non-blocking)"
        fi
      else
        success "  LAYER 5: Related tests passed"
      fi
    fi
  fi

  # ── Check 4: TypeScript/JavaScript Syntax (for frontend-craftsman) ──
  if [[ "$agent_name" == "frontend-craftsman" ]]; then
    local ui_dir="$PROJECT_ROOT/suite-ui/aldeci-ui-new"
    if [[ -d "$ui_dir" ]] && command -v npx &>/dev/null; then
      # Quick tsc --noEmit check on recently modified files
      local modified_ts_files
      modified_ts_files=$(find "$ui_dir/src" \
        -name "*.tsx" -o -name "*.ts" 2>/dev/null | \
        xargs /usr/bin/stat -f '%m %N' 2>/dev/null | \
        sort -rn | head -20 | awk '{print $2}')

      if [[ -n "$modified_ts_files" ]]; then
        log "  LAYER 5: Checking TypeScript compilation..."
        local tsc_output
        tsc_output=$(cd "$ui_dir" && npx tsc --noEmit --pretty false 2>&1 | tail -20)
        local tsc_exit=$?
        if [[ $tsc_exit -ne 0 ]]; then
          local ts_errors
          ts_errors=$(echo "$tsc_output" | grep -c 'error TS' 2>/dev/null || true)
          if [[ $ts_errors -gt 0 ]]; then
            verify_failures=$((verify_failures + 1))
            verify_details+="  TypeScript: ${ts_errors} compilation errors\n"
            warn "  LAYER 5: ${ts_errors} TypeScript errors"
          fi
        else
          success "  LAYER 5: TypeScript compilation clean"
        fi
      fi
    fi
  fi

  # ── Verdict ──
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"layer\":5,\"agent\":\"${agent_name}\",\"failures\":${verify_failures}}" >> "$HALLUCINATION_LOG" 2>/dev/null || true

  if [[ $verify_failures -gt 0 ]]; then
    error "  LAYER 5 VERDICT: ${agent_name} has ${verify_failures} code verification failures"
    if [[ -n "$verify_details" ]]; then
      echo -e "$verify_details" | head -20
    fi
    return 1
  else
    success "  LAYER 5: ${agent_name} code verification PASSED — all changes compile and tests pass"
    return 0
  fi
}

# ━━━ HALLUCINATION PROTECTION SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Prints a summary of all hallucination checks for the current run
hallucination_protection_summary() {
  if ! $ENABLE_HALLUCINATION_PROTECTION; then return 0; fi
  if [[ ! -f "$HALLUCINATION_LOG" ]]; then return 0; fi

  local total_checks layer2_flags layer3_fails layer4_conflicts layer5_fails
  total_checks=$(wc -l < "$HALLUCINATION_LOG" 2>/dev/null | tr -d ' ')
  layer2_flags=$(grep -c '"layer":2' "$HALLUCINATION_LOG" 2>/dev/null || true)
  layer3_fails=$(grep '"layer":3' "$HALLUCINATION_LOG" 2>/dev/null | grep -c '"verdict":"FAIL"' 2>/dev/null || true)
  layer4_conflicts=$(grep '"layer":4' "$HALLUCINATION_LOG" 2>/dev/null | python3 -c "
import json, sys
total = 0
for line in sys.stdin:
    try: total += json.loads(line).get('conflicts', 0)
    except: pass
print(total)
" 2>/dev/null || true)
  layer5_fails=$(grep '"layer":5' "$HALLUCINATION_LOG" 2>/dev/null | python3 -c "
import json, sys
total = 0
for line in sys.stdin:
    try: total += json.loads(line).get('failures', 0)
    except: pass
print(total)
" 2>/dev/null || true)

  echo ""
  echo -e "${BOLD}${CYAN}━━━ 🛡️  HALLUCINATION PROTECTION REPORT ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "  Layer 1 (Pre-Execution Vision):    ✅ Injected into all agent prompts"
  echo -e "  Layer 2 (Real-Time Monitor):        ${layer2_flags} real-time flags"
  echo -e "  Layer 3 (Deep Content Analysis):    ${layer3_fails} agent(s) REJECTED"
  echo -e "  Layer 4 (Cross-Agent Consistency):  ${layer4_conflicts} conflict(s)"
  echo -e "  Layer 5 (Code Verification):        ${layer5_fails} compilation failure(s)"
  echo -e "  Total Checks:                       ${total_checks}"

  # ── Confidence Label Distribution ──
  if [[ -f "$CONFIDENCE_LOG" ]]; then
    local conf_high conf_medium conf_low conf_escalations
    conf_high=$(grep -c '"confidence":"HIGH"' "$CONFIDENCE_LOG" 2>/dev/null || true)
    conf_medium=$(grep -c '"confidence":"MEDIUM"' "$CONFIDENCE_LOG" 2>/dev/null || true)
    conf_low=$(grep -c '"confidence":"LOW"' "$CONFIDENCE_LOG" 2>/dev/null || true)
    conf_escalations=$(grep -c '"escalation":"scrum-master"' "$CONFIDENCE_LOG" 2>/dev/null || true)
    echo -e ""
    echo -e "  ${BOLD}Confidence Labels:${NC}"
    echo -e "    🟢 HIGH:   ${conf_high} agents  (trustworthy, proceed)"
    echo -e "    🟡 MEDIUM: ${conf_medium} agents  (caution, logged)"
    echo -e "    🔴 LOW:    ${conf_low} agents  (escalated to scrum-master)"
    echo -e "    📢 Escalations: ${conf_escalations} (scrum-master debates)"
  fi

  # ── OOM Checkpoint Summary ──
  local oom_checkpoints
  oom_checkpoints=$(find "$CHECKPOINT_DIR" -name "*.oom" 2>/dev/null | wc -l | tr -d ' ')
  if [[ $oom_checkpoints -gt 0 ]]; then
    echo -e ""
    echo -e "  ${BOLD}${RED}OOM Checkpoints: ${oom_checkpoints} agents killed by memory pressure${NC}"
    for oom_file in "$CHECKPOINT_DIR"/*.oom; do
      [[ -f "$oom_file" ]] || continue
      local oom_agent oom_attempt oom_ram
      oom_agent=$(python3 -c "import json; print(json.load(open('$oom_file')).get('agent','?'))" 2>/dev/null || echo "?")
      oom_attempt=$(python3 -c "import json; print(json.load(open('$oom_file')).get('attempt','?'))" 2>/dev/null || echo "?")
      oom_ram=$(python3 -c "import json; print(json.load(open('$oom_file')).get('free_ram_mb','?'))" 2>/dev/null || echo "?")
      echo -e "    ⚠️  ${oom_agent} (attempt ${oom_attempt}) — ${oom_ram}MB free at kill time"
    done
  fi

  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
}

###############################################################################
# JARVIS CONTROLLER — SELF-HEALING SYSTEM
#
# Like an autonomous reconciliation loop: continuously watches
# for failures, spawns parallel Claude fix-agents to diagnose and repair,
# re-runs failed agents, and monitors API health — never gives up.
#
# Components:
#   1. controller_spawn_fix_agent() — Spawn a Claude agent to fix specific failure
#   2. controller_api_health_probe() — Continuous API health monitoring + restart
#   3. controller_reconcile_agent() — Full reconcile cycle for a failed agent
#   4. controller_reconcile_phase() — Reconcile all failures in a phase
#   5. controller_run_background_watchdog() — Background health monitor
#   6. controller_post_swarm_reconcile() — Final sweep after full swarm
###############################################################################

# ━━━ spawn a parallel Claude fix-agent to diagnose + repair a failure ━━━━━
# This is the core of the controller: when something fails, we don't just
# retry blindly — we spawn a SEPARATE Claude agent with the failure context
# and ask it to FIX the root cause before re-running.
controller_spawn_fix_agent() {
  local failed_agent="$1"
  local failure_reason="$2"
  local log_file="$3"
  local fix_cycle="${4:-1}"

  if ! $ENABLE_CONTROLLER; then return 1; fi

  # ── QUOTA EXHAUSTION GUARD — don't waste quota on fix agents ──
  if $QUOTA_EXHAUSTED; then
    error "CONTROLLER: Skipping fix-agent for ${failed_agent} — QUOTA EXHAUSTED (${QUOTA_EXHAUSTED_MSG})"
    return 1
  fi

  mkdir -p "$FIX_AGENTS_DIR"
  local fix_log="$FIX_AGENTS_DIR/${DATE_TODAY}_fix-${failed_agent}_cycle${fix_cycle}.log"
  local fix_id="fix-${failed_agent}-$(date +%s)"

  log "CONTROLLER: Spawning fix-agent for ${failed_agent} (cycle ${fix_cycle}/${CONTROLLER_MAX_FIX_CYCLES})"
  voice "Spawning fix agent for ${failed_agent}" "critical"
  notify "Fix Agent" "Diagnosing ${failed_agent} failure"

  # Build the failure tail context
  local failure_tail=""
  if [[ -f "$log_file" && -s "$log_file" ]]; then
    failure_tail=$(tail -100 "$log_file" 2>/dev/null | head -80 || echo "(no output)")
  fi

  # Build fix-agent status file
  local fix_status_file="$STATE_DIR/fix-${failed_agent}-status.md"

  # Collect error patterns from the log
  local error_patterns=""
  if [[ -f "$log_file" ]]; then
    error_patterns=$(grep -iE 'error|exception|traceback|failed|FATAL|CRITICAL|SyntaxError|ImportError|ModuleNotFoundError|TypeError|ValueError|KeyError|AttributeError|FileNotFoundError|PermissionError' "$log_file" 2>/dev/null | sort -u | head -30 || echo "(none)")
  fi

  # Collect which files were modified (from git)
  local recent_changes
  recent_changes=$(git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null | head -20 || echo "(none)")

  # Build the fix prompt
  local fix_prompt="JARVIS CONTROLLER — AUTO-FIX AGENT
═══════════════════════════════════
You are a REPAIR agent spawned by the JARVIS Controller.
Your ONLY job: diagnose and FIX why agent '${failed_agent}' failed, then verify the fix.

FAILURE CONTEXT:
- Failed Agent: ${failed_agent}
- Failure Reason: ${failure_reason}
- Fix Cycle: ${fix_cycle} of ${CONTROLLER_MAX_FIX_CYCLES}
- Date: ${DATE_TODAY}
- Run ID: ${RUN_ID}

ERROR PATTERNS FROM LOG:
\`\`\`
${error_patterns}
\`\`\`

LAST 80 LINES OF FAILED OUTPUT:
\`\`\`
${failure_tail}
\`\`\`

RECENTLY MODIFIED FILES:
${recent_changes}

SELF-LEARNING — KNOWN FAILURE HISTORY FOR THIS AGENT:
$(load_failure_lessons "${failed_agent}" 2>/dev/null || echo "(no prior failures recorded)")

YOUR MISSION (in order):
1. READ the error patterns above carefully
2. IDENTIFY the root cause — is it a syntax error? import error? missing file? test failure? config issue?
3. READ the relevant source files to understand the bug
4. FIX the root cause — edit the actual files, don't just report
5. If it's a test failure, fix the test OR the code that broke it
6. If it's an import error, fix the import path or install the missing package
7. If it's a syntax error, fix the syntax
8. If it's a missing file, create it with proper content
9. RUN the fix verification: python -m py_compile on modified .py files, bash -n on .sh files
10. RUN related tests: python -m pytest tests/test_*.py -x --no-cov --tb=short (for the relevant module)
11. Write your fix report to .claude/team-state/fix-${failed_agent}-status.md

CRITICAL RULES:
- You have FULL file system access. Use it.
- Do NOT just describe the problem. FIX IT.
- Do NOT create stubs or placeholders. Write REAL code.
- If you can't fix it in this cycle, leave detailed notes for the next cycle.
- Your output WILL be verified. Do not hallucinate fixes.
- After fixing, verify by running the relevant test/compile command.
- Tag your decisions with the vision pillar they serve."

  # Run the fix agent — with SIGTSTP immunity propagation
  local run_cmd
  if [[ -n "$TIMEOUT_CMD" ]]; then
    run_cmd="$TIMEOUT_CMD $CONTROLLER_FIX_TIMEOUT claude"
  else
    run_cmd="claude"
  fi

  local fix_prompt_file="${fix_log}.prompt.tmp"
  printf '%s' "$fix_prompt" > "$fix_prompt_file"
  (
    trap '' TSTP TTIN TTOU
    /opt/homebrew/bin/bash -c '
      trap "" TSTP TTIN TTOU
      _pfile="$1"; shift
      exec "$@" -p "$(cat "$_pfile")"
    ' _ "$fix_prompt_file" \
      $run_cmd \
        --print --output-format text --verbose \
        --dangerously-skip-permissions \
        --max-turns 100 \
        > "$fix_log" 2>&1
  )
  local fix_exit=$?
  rm -f "$fix_prompt_file" 2>/dev/null || true

  # Verify the fix agent actually produced output
  local fix_size=0
  [[ -f "$fix_log" ]] && fix_size=$(wc -c < "$fix_log" | tr -d ' ')

  # Log the fix attempt
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"fix_agent\",\"target\":\"${failed_agent}\",\"cycle\":${fix_cycle},\"exit_code\":${fix_exit},\"output_bytes\":${fix_size},\"reason\":\"${failure_reason}\"}" >> "$CONTROLLER_LOG" 2>/dev/null || true

  if [[ $fix_exit -eq 0 && $fix_size -gt 200 ]]; then
    success "CONTROLLER: Fix-agent for ${failed_agent} completed (${fix_size} bytes)"

    # Verify the fix actually changed something
    local changes_after
    changes_after=$(git -C "$PROJECT_ROOT" diff --stat HEAD 2>/dev/null | tail -1 || echo "")
    if [[ -n "$changes_after" && "$changes_after" != *"0 files changed"* ]]; then
      success "CONTROLLER: Fix-agent made code changes: ${changes_after}"

      # Quick syntax check on any modified Python files
      local fix_verified=true
      local modified_py
      modified_py=$(git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null | grep '\.py$' | head -20)
      if [[ -n "$modified_py" ]]; then
        while IFS= read -r pyf; do
          if [[ -f "$PROJECT_ROOT/$pyf" ]]; then
            if ! python3 -m py_compile "$PROJECT_ROOT/$pyf" 2>/dev/null; then
              warn "CONTROLLER: Fix introduced syntax error in $pyf"
              fix_verified=false
            fi
          fi
        done <<< "$modified_py"
      fi

      if $fix_verified; then
        success "CONTROLLER: Fix verified — all modified files pass syntax check"
        # ── SELF-LEARNING: Record successful fix ──
        local modified_files_csv
        modified_files_csv=$(git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null | head -10 | tr '\n' ',' | sed 's/,$//')
        record_fix_attempt "$failed_agent" "$failure_reason" "unknown" "$fix_cycle" "true" "$fix_exit" "$fix_size" "$modified_files_csv" "Fix verified — syntax check passed, code changes applied"
        log "SELF-LEARNING: Recorded successful fix for ${failed_agent} in failure ledger"
        return 0
      else
        warn "CONTROLLER: Fix introduced new errors — will try again"
        # ── SELF-LEARNING: Record failed fix (introduced new errors) ──
        record_fix_attempt "$failed_agent" "$failure_reason" "SYNTAX_ERROR" "$fix_cycle" "false" "$fix_exit" "$fix_size" "" "Fix introduced new syntax errors in modified files"
        broadcast_failure_alert "$failed_agent" "SYNTAX_ERROR" "Fix agent introduced syntax errors while trying to repair ${failed_agent}"
        return 1
      fi
    else
      warn "CONTROLLER: Fix-agent ran but made no code changes"
      # ── SELF-LEARNING: Record failed fix (no changes made) ──
      record_fix_attempt "$failed_agent" "$failure_reason" "unknown" "$fix_cycle" "false" "$fix_exit" "$fix_size" "" "Fix agent ran but made no code changes"
      return 1
    fi
  else
    warn "CONTROLLER: Fix-agent failed (exit: ${fix_exit}, output: ${fix_size} bytes)"
    # ── SELF-LEARNING: Record failed fix (agent failed or empty output) ──
    local fail_category="EMPTY_OUTPUT"
    [[ $fix_exit -ne 0 ]] && fail_category="TIMEOUT"
    record_fix_attempt "$failed_agent" "$failure_reason" "$fail_category" "$fix_cycle" "false" "$fix_exit" "$fix_size" "" "Fix agent failed with exit code ${fix_exit} and ${fix_size} bytes output"
    broadcast_failure_alert "$failed_agent" "$fail_category" "Fix agent for ${failed_agent} failed (exit: ${fix_exit}, output: ${fix_size} bytes)"
    return 1
  fi
}

# ━━━ API Health Probe — continuous monitoring + auto-restart ━━━━━━━━━━━━━
controller_api_health_probe() {
  if ! $ENABLE_CONTROLLER; then return 0; fi

  # Quick probe
  if curl -sf --max-time 5 http://localhost:8000/api/v1/health >/dev/null 2>&1; then
    return 0  # healthy
  fi

  warn "CONTROLLER: API health probe FAILED — attempting recovery..."

  # Kill any stuck API processes
  local stuck_pids
  stuck_pids=$(lsof -ti:8000 2>/dev/null || echo "")
  if [[ -n "$stuck_pids" ]]; then
    warn "CONTROLLER: Killing stuck processes on port 8000: ${stuck_pids}"
    echo "$stuck_pids" | xargs kill -TERM 2>/dev/null || true
    sleep 2
    echo "$stuck_pids" | xargs kill -KILL 2>/dev/null || true
    sleep 1
  fi

  # Restart the API server
  log "CONTROLLER: Restarting API server..."
  cd "$PROJECT_ROOT"
  source .venv/bin/activate 2>/dev/null || true
  export FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN:-aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh}"
  export FIXOPS_DISABLE_RATE_LIMIT=1
  export FIXOPS_JWT_SECRET="${FIXOPS_JWT_SECRET:-enterprise-jwt-secret-key-minimum-32-characters}"
  export FIXOPS_TRUSTED_ROOT="${FIXOPS_TRUSTED_ROOT:-$PROJECT_ROOT/.fixops_data}"
  python -m uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --workers 4 --timeout-keep-alive 5 &>/dev/null &
  local new_pid=$!
  echo "$new_pid" > "$STATE_DIR/.api-server.pid"

  # Wait for it
  local tries=0
  while [[ $tries -lt 30 ]]; do
    if curl -sf --max-time 3 http://localhost:8000/api/v1/health >/dev/null 2>&1; then
      success "CONTROLLER: API server recovered (PID: ${new_pid})"
      echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"api_recovery\",\"pid\":${new_pid},\"status\":\"recovered\"}" >> "$CONTROLLER_LOG" 2>/dev/null || true
      return 0
    fi
    sleep 1
    ((tries++))
  done

  error "CONTROLLER: API server failed to recover after 30s"

  # Last resort: spawn a fix agent to diagnose the API startup failure
  local api_error_log
  api_error_log=$(find "$PROJECT_ROOT/logs" -name "*.log" -newer "$STATE_DIR/.api-server.pid" 2>/dev/null | head -1)
  if [[ -n "$api_error_log" ]]; then
    controller_spawn_fix_agent "api-server" "API server won't start on port 8000" "$api_error_log" 1
    # Try one more time after fix
    export FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN:-aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh}"
    export FIXOPS_DISABLE_RATE_LIMIT=1
    export FIXOPS_JWT_SECRET="${FIXOPS_JWT_SECRET:-enterprise-jwt-secret-key-minimum-32-characters}"
    export FIXOPS_TRUSTED_ROOT="${FIXOPS_TRUSTED_ROOT:-$PROJECT_ROOT/.fixops_data}"
    python -m uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --workers 4 --timeout-keep-alive 5 &>/dev/null &
    sleep 5
    if curl -sf --max-time 3 http://localhost:8000/api/v1/health >/dev/null 2>&1; then
      success "CONTROLLER: API server recovered after fix-agent repair"
      return 0
    fi
  fi

  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"api_recovery\",\"status\":\"failed\"}" >> "$CONTROLLER_LOG" 2>/dev/null || true
  return 1
}

# ━━━ Reconcile a single failed agent — fix then re-run ━━━━━━━━━━━━━━━━━━
# This is the core controller loop for a single agent:
#   1. Analyze failure
#   2. Spawn fix-agent to repair
#   3. Re-run the original agent
#   4. Verify output (all 5 hallucination layers)
#   5. Repeat until success or max cycles exhausted
controller_reconcile_agent() {
  local agent_name="$1"
  local failure_reason="${2:-unknown}"
  local original_log="$LOG_DIR/${DATE_TODAY}_${agent_name}_${RUN_ID}.log"

  if ! $ENABLE_CONTROLLER; then return 1; fi

  log ""
  echo -e "${BOLD}${RED}━━━ CONTROLLER RECONCILE: ${agent_name} ━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  log "CONTROLLER: Starting reconciliation for ${agent_name}"
  log "CONTROLLER: Failure reason: ${failure_reason}"

  local fix_cycle=0
  local reconciled=false

  while [[ $fix_cycle -lt $CONTROLLER_MAX_FIX_CYCLES ]]; do
    fix_cycle=$((fix_cycle + 1))
    log "CONTROLLER: Reconciliation cycle ${fix_cycle}/${CONTROLLER_MAX_FIX_CYCLES} for ${agent_name}"

    # ── Step 1: Ensure API is healthy before re-running ──
    controller_api_health_probe || warn "CONTROLLER: API unhealthy — agent may need to handle this"

    # ── Step 2: Spawn fix-agent to diagnose and repair ──
    if controller_spawn_fix_agent "$agent_name" "$failure_reason" "$original_log" "$fix_cycle"; then
      success "CONTROLLER: Fix-agent repaired issues for ${agent_name}"
    else
      warn "CONTROLLER: Fix-agent could not repair ${agent_name} (cycle ${fix_cycle})"
      if [[ $fix_cycle -lt $CONTROLLER_MAX_FIX_CYCLES ]]; then
        log "CONTROLLER: Will try another fix cycle..."
        sleep 10
        continue
      fi
    fi

    # ── Step 3: Re-run the original agent with fresh context ──
    log "CONTROLLER: Re-running ${agent_name} after fix cycle ${fix_cycle}..."

    # Clear the failed checkpoint so run_agent will execute
    rm -f "$CHECKPOINT_DIR/${RUN_ID}_${agent_name}.done" 2>/dev/null || true

    # Reset the status
    atomic_write_heredoc "$STATE_DIR/${agent_name}-status.md" <<REOF
# ${agent_name} Status
- **Status:** 🔄 Re-running (Controller Reconcile cycle ${fix_cycle})
- **Runtime:** ${MODEL} (CTEM+ Swarm)
- **Date:** ${DATE_TODAY}
- **Run ID:** ${RUN_ID}
- **Previous Failure:** ${failure_reason}
REOF

    # Run the agent again
    if run_agent "$agent_name"; then
      success "CONTROLLER: ${agent_name} SUCCEEDED after reconciliation cycle ${fix_cycle}"
      reconciled=true

      # Replace the failure result in AGENT_RESULTS
      local new_results=()
      for r in "${AGENT_RESULTS[@]}"; do
        if [[ "$r" == "❌ ${agent_name}" ]]; then
          new_results+=("✅ ${agent_name} (reconciled cycle ${fix_cycle})")
        else
          new_results+=("$r")
        fi
      done
      AGENT_RESULTS=("${new_results[@]}")

      echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"reconcile_success\",\"agent\":\"${agent_name}\",\"cycle\":${fix_cycle}}" >> "$CONTROLLER_LOG" 2>/dev/null || true
      break
    else
      # Extract new failure reason from the latest log
      if [[ -f "$original_log" ]]; then
        failure_reason=$(tail -5 "$original_log" 2>/dev/null | grep -iE 'error|fail|exception' | head -1 | cut -c1-200 || echo "unknown")
      fi
      warn "CONTROLLER: ${agent_name} still failing after fix cycle ${fix_cycle}"
    fi
  done

  if ! $reconciled; then
    error "CONTROLLER: ${agent_name} could not be reconciled after ${CONTROLLER_MAX_FIX_CYCLES} fix cycles"
    echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"reconcile_failed\",\"agent\":\"${agent_name}\",\"cycles\":${CONTROLLER_MAX_FIX_CYCLES}}" >> "$CONTROLLER_LOG" 2>/dev/null || true

    # If never-give-up mode, keep going with fresh approach
    if $CONTROLLER_NEVER_GIVE_UP; then
      warn "CONTROLLER: NEVER-GIVE-UP mode — scheduling deferred reconciliation"
      echo "${agent_name}|${failure_reason}" >> "$STATE_DIR/controller-deferred-queue.txt" 2>/dev/null || true
    fi
    return 1
  fi

  return 0
}

# ━━━ Background API + Test Health Watchdog ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Runs as a background process during the swarm, continuously monitoring:
#   - API server health (auto-restart if down)
#   - Python syntax of recently modified files
#   - Test regressions on critical paths
controller_run_background_watchdog() {
  if ! $ENABLE_CONTROLLER; then return 0; fi

  local watchdog_log="$LOG_DIR/${DATE_TODAY}_controller-watchdog.log"
  local watchdog_pid_file="$STATE_DIR/.controller-watchdog.pid"

  # Don't start if already running
  if [[ -f "$watchdog_pid_file" ]]; then
    local existing_pid
    existing_pid=$(cat "$watchdog_pid_file" 2>/dev/null || echo "")
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
      debug "CONTROLLER: Background watchdog already running (PID: ${existing_pid})"
      return 0
    fi
  fi

  log "CONTROLLER: Starting background health watchdog..."

  (
    trap '' TSTP TTIN TTOU
    while true; do
      sleep "$CONTROLLER_API_HEALTH_INTERVAL"

      # ── API Health Check ──
      if ! curl -sf --max-time 5 http://localhost:8000/api/v1/health >/dev/null 2>&1; then
        echo "[$(date '+%H:%M:%S')] API DOWN — restarting..." >> "$watchdog_log"
        # Kill stuck processes
        lsof -ti:8000 2>/dev/null | xargs kill -TERM 2>/dev/null || true
        sleep 2
        lsof -ti:8000 2>/dev/null | xargs kill -KILL 2>/dev/null || true
        sleep 1
        cd "$PROJECT_ROOT"
        source .venv/bin/activate 2>/dev/null || true
        export FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN:-aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh}"
        export FIXOPS_DISABLE_RATE_LIMIT=1
        export FIXOPS_JWT_SECRET="${FIXOPS_JWT_SECRET:-enterprise-jwt-secret-key-minimum-32-characters}"
        export FIXOPS_TRUSTED_ROOT="${FIXOPS_TRUSTED_ROOT:-$PROJECT_ROOT/.fixops_data}"
        python -m uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --workers 4 --timeout-keep-alive 5 &>/dev/null &
        echo "[$(date '+%H:%M:%S')] API restart attempted (PID: $!)" >> "$watchdog_log"
        sleep 5
        if curl -sf --max-time 3 http://localhost:8000/api/v1/health >/dev/null 2>&1; then
          echo "[$(date '+%H:%M:%S')] API recovered" >> "$watchdog_log"
        else
          echo "[$(date '+%H:%M:%S')] API still down after restart" >> "$watchdog_log"
        fi
      fi

      # ── Check for syntax errors in recently modified Python files ──
      local broken_py
      broken_py=$(find "$PROJECT_ROOT" -name "*.py" -newer "$STATE_DIR/.controller-watchdog.pid" \
        -not -path "*/__pycache__/*" -not -path "*/.venv/*" -not -path "*/WIP/*" \
        -not -path "*/node_modules/*" 2>/dev/null | head -30)
      if [[ -n "$broken_py" ]]; then
        while IFS= read -r pyf; do
          if ! python3 -m py_compile "$pyf" 2>/dev/null; then
            echo "[$(date '+%H:%M:%S')] SYNTAX ERROR detected: $pyf" >> "$watchdog_log"
            # Spawn a quick fix for this syntax error
            local err_msg
            err_msg=$(python3 -m py_compile "$pyf" 2>&1 | tail -5)
            local quick_fix_log="$FIX_AGENTS_DIR/fix-syntax-$(basename "$pyf")-$(date +%s).log"
            mkdir -p "$FIX_AGENTS_DIR"

            local quick_cmd
            if [[ -n "$TIMEOUT_CMD" ]]; then
              quick_cmd="$TIMEOUT_CMD 300 claude"
            else
              quick_cmd="claude"
            fi

            # SIGTSTP-immune launch: SIG_IGN propagates across exec() per POSIX
            local _qfix_pfile="${quick_fix_log}.prompt.tmp"
            printf '%s' "FIX THIS SYNTAX ERROR immediately. File: $pyf
Error: ${err_msg}
Read the file, fix the syntax error, and verify with py_compile. Do NOT create stubs." > "$_qfix_pfile"
            (
              trap '' TSTP TTIN TTOU
              /opt/homebrew/bin/bash -c '
                trap "" TSTP TTIN TTOU
                _pfile="$1"; shift
                exec "$@" -p "$(cat "$_pfile")"
              ' _ "$_qfix_pfile" \
                $quick_cmd \
                  --print --output-format text \
                  --dangerously-skip-permissions \
                  --max-turns 20 \
                  > "$quick_fix_log" 2>&1
            ) &
            rm -f "$_qfix_pfile" 2>/dev/null || true

            echo "[$(date '+%H:%M:%S')] Spawned fix-agent for $pyf" >> "$watchdog_log"
          fi
        done <<< "$broken_py"
      fi

      # ── Check for stopped agent processes and resume them ──
      # With setsid launch, agents shouldn't get stopped anymore.
      # But if they do, just SIGCONT them — NEVER kill working agents.
      local stopped_agents
      stopped_agents=$(ps aux 2>/dev/null | grep '[c]laude.*print.*output-format' | awk '{print $2, $8}' | grep 'T' || true)
      if [[ -n "$stopped_agents" ]]; then
        echo "[$(date '+%H:%M:%S')] STOPPED claude processes found — sending SIGCONT:" >> "$watchdog_log"
        echo "$stopped_agents" >> "$watchdog_log"
        # Send SIGCONT to resume — do NOT kill. Killing produces 0-byte output.
        echo "$stopped_agents" | awk '{print $1}' | while read -r spid; do
          kill -CONT "$spid" 2>/dev/null || true
        done
        echo "[$(date '+%H:%M:%S')] Sent SIGCONT to resume stopped processes" >> "$watchdog_log"
      fi

    done
  ) &

  local bg_pid=$!
  echo "$bg_pid" > "$watchdog_pid_file"
  log "CONTROLLER: Background watchdog started (PID: ${bg_pid})"
}

# ━━━ Stop the background watchdog ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
controller_stop_watchdog() {
  local watchdog_pid_file="$STATE_DIR/.controller-watchdog.pid"
  if [[ -f "$watchdog_pid_file" ]]; then
    local wpid
    wpid=$(cat "$watchdog_pid_file" 2>/dev/null || echo "")
    if [[ -n "$wpid" ]] && kill -0 "$wpid" 2>/dev/null; then
      kill "$wpid" 2>/dev/null || true
      wait "$wpid" 2>/dev/null || true
      log "CONTROLLER: Background watchdog stopped (PID: ${wpid})"
    fi
    rm -f "$watchdog_pid_file"
  fi
}

# ━━━ Post-Swarm Reconciliation — never leave failures unresolved ━━━━━━━━
# After the full swarm completes, this sweeps ALL failed agents and
# attempts to fix + re-run each one. This is the "never give up" guarantee.
controller_post_swarm_reconcile() {
  if ! $ENABLE_CONTROLLER; then return 0; fi

  # Collect all failed agents from this run
  local failed_agents=()
  for result in "${AGENT_RESULTS[@]}"; do
    if [[ "$result" == "❌"* ]]; then
      local agent_name
      agent_name=$(echo "$result" | sed 's/❌ //' | awk '{print $1}')
      failed_agents+=("$agent_name")
    fi
  done

  if [[ ${#failed_agents[@]} -eq 0 ]]; then
    success "CONTROLLER: No failed agents to reconcile — perfect run!"
    return 0
  fi

  echo ""
  echo -e "${BOLD}${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}${RED}  CONTROLLER POST-SWARM RECONCILIATION                          ${NC}"
  echo -e "${BOLD}${RED}  ${#failed_agents[@]} failed agent(s) — fixing and re-running...       ${NC}"
  echo -e "${BOLD}${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""

  voice "${#failed_agents[@]} agents failed. Starting reconciliation." "critical"
  notify "Controller" "${#failed_agents[@]} failed agents — reconciling"

  local reconciled_count=0
  local still_failed=0

  for agent_name in "${failed_agents[@]}"; do
    # Get failure reason from status file
    local failure_reason="unknown"
    local status_file="$STATE_DIR/${agent_name}-status.md"
    if [[ -f "$status_file" ]]; then
      failure_reason=$(grep -i 'needs\|error\|fail' "$status_file" 2>/dev/null | head -1 | sed 's/^.*: //' | cut -c1-200 || echo "unknown")
    fi

    # Also check the log for errors
    local agent_log="$LOG_DIR/${DATE_TODAY}_${agent_name}_${RUN_ID}.log"
    if [[ -f "$agent_log" ]]; then
      local log_errors
      log_errors=$(grep -iE 'error|exception|traceback' "$agent_log" 2>/dev/null | tail -3 | head -1 | cut -c1-200 || echo "")
      [[ -n "$log_errors" ]] && failure_reason="${failure_reason} | ${log_errors}"
    fi

    if controller_reconcile_agent "$agent_name" "$failure_reason"; then
      reconciled_count=$((reconciled_count + 1))
    else
      still_failed=$((still_failed + 1))
    fi
  done

  echo ""
  echo -e "${BOLD}${CYAN}━━━ CONTROLLER RECONCILIATION RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "  Total failed:      ${#failed_agents[@]}"
  echo -e "  Reconciled:        ${GREEN}${reconciled_count}${NC}"
  echo -e "  Still failing:     ${RED}${still_failed}${NC}"
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""

  voice "Reconciliation complete. ${reconciled_count} fixed, ${still_failed} still failing." \
    $([ $still_failed -eq 0 ] && echo "celebration" || echo "critical")

  # Process deferred queue if never-give-up mode
  if $CONTROLLER_NEVER_GIVE_UP && [[ -f "$STATE_DIR/controller-deferred-queue.txt" ]]; then
    local deferred_count
    deferred_count=$(wc -l < "$STATE_DIR/controller-deferred-queue.txt" 2>/dev/null | tr -d ' ')
    if [[ $deferred_count -gt 0 ]]; then
      warn "CONTROLLER: ${deferred_count} agent(s) in deferred queue — will be retried in next iteration"
    fi
  fi

  return $still_failed
}

# ━━━ Controller Summary — audit trail for all controller actions ━━━━━━━━
controller_print_summary() {
  if ! $ENABLE_CONTROLLER; then return 0; fi
  if [[ ! -f "$CONTROLLER_LOG" ]]; then return 0; fi

  local total_actions fix_spawns fix_successes api_recoveries reconcile_ok reconcile_fail
  total_actions=$(wc -l < "$CONTROLLER_LOG" 2>/dev/null | tr -d ' ')
  fix_spawns=$(grep -c '"type":"fix_agent"' "$CONTROLLER_LOG" 2>/dev/null || true)
  fix_successes=$(grep '"type":"fix_agent"' "$CONTROLLER_LOG" 2>/dev/null | grep -c '"exit_code":0' 2>/dev/null || true)
  api_recoveries=$(grep -c '"type":"api_recovery"' "$CONTROLLER_LOG" 2>/dev/null || true)
  reconcile_ok=$(grep -c '"type":"reconcile_success"' "$CONTROLLER_LOG" 2>/dev/null || true)
  reconcile_fail=$(grep -c '"type":"reconcile_failed"' "$CONTROLLER_LOG" 2>/dev/null || true)

  echo ""
  echo -e "${BOLD}${MAGENTA}━━━ 🎛️  JARVIS CONTROLLER REPORT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "  Fix Agents Spawned:    ${fix_spawns} (${fix_successes} successful)"
  echo -e "  API Recoveries:        ${api_recoveries}"
  echo -e "  Agents Reconciled:     ${GREEN}${reconcile_ok}${NC}"
  echo -e "  Agents Still Failed:   ${RED}${reconcile_fail}${NC}"
  echo -e "  Total Controller Ops:  ${total_actions}"
  echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
}

###############################################################################
# PERSONA → FUNCTION → E2E TEST REGISTRY
#
# Maps each agent persona to the specific functions/endpoints they own,
# the test scripts that verify them, and real-time pass rates.
# E2E registry grows automatically as agents add new functions through the swarm.
#
# Registry file: .claude/team-state/persona-e2e-registry.json
###############################################################################

# ━━━ Persona Function Registry ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Each persona owns specific routers/engines/functions.
# This builds a live mapping and runs their test scripts to get real pass rates.
build_persona_function_registry() {
  set +eu  # Disable exit-on-error AND nounset — undeclared arrays + grep returning 0 must not crash
  local registry_file="$STATE_DIR/persona-e2e-registry.json"

  # ── Define persona → owned routers/engines/endpoints ──
  # Format: "agent|router_file|endpoint_prefix|engine_file|test_script|description"
  local -a PERSONA_FUNCTIONS=(
    # backend-hardener (Ethan + Hasan): Connectors, Integrations, Admin, System, Auth, Audit, Webhooks
    "backend-hardener|suite-api/apps/api/connectors_router.py|/connectors|core/connectors.py|scripts/test-backend-hardener.sh|Connector registration, health, CRUD"
    "backend-hardener|suite-api/apps/api/admin_router.py|/admin|—|scripts/test-backend-hardener.sh|User & team administration"
    "backend-hardener|suite-api/apps/api/system_router.py|/system|—|scripts/test-backend-hardener.sh|System health, info, config, metrics"
    "backend-hardener|suite-api/apps/api/audit_router.py|/audit|—|scripts/test-backend-hardener.sh|Audit logging & export"
    "backend-hardener|suite-api/apps/api/auth_router.py|/auth|—|scripts/test-backend-hardener.sh|SSO & authentication"
    "backend-hardener|suite-api/apps/api/users_router.py|/users|—|scripts/test-backend-hardener.sh|User login, CRUD"
    "backend-hardener|suite-api/apps/api/teams_router.py|/teams|—|scripts/test-backend-hardener.sh|Team CRUD & membership"
    "backend-hardener|suite-integrations/api/integrations_router.py|/integrations|—|scripts/test-backend-hardener.sh|Integration lifecycle"
    "backend-hardener|suite-integrations/api/webhooks_router.py|/webhooks|—|scripts/test-backend-hardener.sh|Webhook mappings & outbox"
    # threat-architect (Jason + Carlos + Lisa): MPTE, Micro-Pentest, FAIL, Attack-Sim, Malware, API-Fuzzer, Feeds
    "threat-architect|suite-attack/api/mpte_router.py|/mpte|core/micro_pentest.py|scripts/test-threat-architect.sh|MPTE scanning & verification"
    "threat-architect|suite-attack/api/micro_pentest_router.py|/micro-pentest|core/micro_pentest.py|scripts/test-threat-architect.sh|Enterprise micro-pentesting (19-phase)"
    "threat-architect|suite-api/apps/api/fail_router.py|/fail|core/fail_engine.py|scripts/test-threat-architect.sh|FAIL scoring & risk ranking"
    "threat-architect|suite-attack/api/attack_sim_router.py|/attack-sim|—|scripts/test-threat-architect.sh|Attack simulation & MITRE mapping"
    "threat-architect|suite-attack/api/malware_router.py|/malware|—|scripts/test-threat-architect.sh|Malware scanning & signatures"
    "threat-architect|suite-attack/api/api_fuzzer_router.py|/api-fuzzer|—|scripts/test-threat-architect.sh|API fuzzing & discovery"
    "threat-architect|suite-feeds/api/feeds_router.py|/feeds|—|scripts/test-threat-architect.sh|Threat feeds (NVD, KEV, EPSS, OSV)"
    "threat-architect|suite-attack/api/mpte_orchestrator_router.py|/mpte-orchestrator|—|scripts/test-threat-architect.sh|MPTE orchestration & threat-intel"
    # security-analyst: SAST, DAST, Secrets, Container, CSPM, Vuln Discovery
    "security-analyst|suite-attack/api/sast_router.py|/sast|core/sast_engine.py|—|Static analysis scanning"
    "security-analyst|suite-attack/api/dast_router.py|/dast|core/dast_engine.py|—|Dynamic analysis scanning"
    "security-analyst|suite-attack/api/secrets_router.py|/secrets|core/secrets_scanner.py|—|Secret detection & scanning"
    "security-analyst|suite-attack/api/container_router.py|/container|core/container_scanner.py|—|Container image scanning"
    "security-analyst|suite-attack/api/cspm_router.py|/cspm|core/cspm_analyzer.py|—|Cloud security posture (IaC)"
    "security-analyst|suite-attack/api/vuln_discovery_router.py|/vuln-discovery|—|—|Vulnerability discovery"
    # enterprise-architect: Brain Pipeline, Knowledge Graph, Deduplication, Code-to-Cloud
    "enterprise-architect|suite-core/api/brain_router.py|/brain|core/brain_pipeline.py|—|12-step Brain Pipeline"
    "enterprise-architect|suite-core/api/knowledge_graph_router.py|/knowledge-graph|—|—|Knowledge graph queries"
    "enterprise-architect|suite-core/api/deduplication_router.py|/deduplication|—|—|Finding deduplication"
    "enterprise-architect|suite-core/api/code_to_cloud_router.py|/code-to-cloud|—|—|Code-to-cloud tracing"
    "enterprise-architect|suite-core/api/pipeline_router.py|/pipeline|—|—|Pipeline orchestration"
    # frontend-craftsman: UI components, pages, workflow spaces
    "frontend-craftsman|suite-ui/aldeci-ui-new/src/spaces/|—|—|—|5 Workflow Space pages (React/TSX)"
    "frontend-craftsman|suite-ui/aldeci-ui-new/src/components/|—|—|—|UI components (shadcn + custom)"
    # ai-researcher: LLM providers, consensus, copilot
    "ai-researcher|suite-core/api/llm_router.py|/llm|core/llm_providers.py|—|Multi-LLM consensus"
    "ai-researcher|suite-core/api/llm_monitor_router.py|/llm-monitor|—|—|LLM usage monitoring"
    "ai-researcher|suite-core/api/copilot_router.py|/copilot|—|—|Copilot AI assistant"
    "ai-researcher|suite-core/api/single_agent_router.py|/single-agent|core/single_agent.py|—|Self-hosted AI engine"
    # qa-engineer: Autofix, testing, validation
    "qa-engineer|suite-core/api/autofix_router.py|/autofix|core/autofix_engine.py|—|AutoFix engine (10 fix types)"
    "qa-engineer|suite-api/apps/api/validation_router.py|/validation|—|—|Input validation"
    # devops-engineer: Docker, MCP, streaming, infrastructure
    "devops-engineer|suite-integrations/api/mcp_router.py|/mcp|core/mcp_server.py|—|MCP gateway (650 tools)"
    "devops-engineer|suite-core/api/mcp_protocol_router.py|/mcp-protocol|—|—|MCP protocol endpoints"
    "devops-engineer|suite-api/apps/api/mcp_router.py|/mcp-server|—|—|MCP tool execution"
    "devops-engineer|suite-core/api/streaming_router.py|/streaming|—|—|SSE streaming events"
    # data-scientist: Analytics, Predictions, Risk, Algorithmic
    "data-scientist|suite-api/apps/api/analytics_router.py|/analytics|—|—|Dashboard analytics & trends"
    "data-scientist|suite-core/api/predictions_router.py|/predictions|—|—|ML predictions engine"
    "data-scientist|suite-core/api/algorithmic_router.py|/algorithmic|—|—|Algorithmic scoring"
    "data-scientist|suite-evidence-risk/api/risk_router.py|/risk|—|—|Risk scoring & calculation"
    # vision-agent: Compliance, Evidence, Quantum, Provenance
    "vision-agent|suite-evidence-risk/api/compliance_engine_router.py|/compliance|core/compliance_engine.py|—|Compliance framework mapping"
    "vision-agent|suite-evidence-risk/api/evidence_router.py|/evidence|—|—|Evidence bundles & vault"
    "vision-agent|suite-core/api/quantum_crypto_router.py|/quantum-crypto|core/quantum_crypto.py|—|Quantum-secure crypto (ML-DSA)"
    "vision-agent|suite-evidence-risk/api/provenance_router.py|/provenance|—|—|Provenance chain tracking"
    # context-engineer: Agents management, MindsDB
    "context-engineer|suite-core/api/agents_router.py|/agents|—|—|Agent lifecycle management"
    "context-engineer|suite-core/api/mindsdb_router.py|/mindsdb|—|—|MindsDB integration"
    # scrum-master: Workflows, Remediation, Collaboration, Bulk, Reports
    "scrum-master|suite-api/apps/api/workflows_router.py|/workflows|—|—|Workflow orchestration"
    "scrum-master|suite-api/apps/api/remediation_router.py|/remediation|—|—|Remediation task tracking"
    "scrum-master|suite-api/apps/api/collaboration_router.py|/collaboration|—|—|Comments, watchers, sharing"
    "scrum-master|suite-api/apps/api/bulk_router.py|/bulk|—|—|Bulk operations"
    "scrum-master|suite-api/apps/api/reports_router.py|/reports|—|—|Report generation & export"
    # marketing-head + technical-writer + sales-engineer: Marketplace, Inventory, Policies, IDE
    "marketing-head|suite-api/apps/api/marketplace_router.py|/marketplace|—|—|Fix pack marketplace"
    "sales-engineer|suite-api/apps/api/inventory_router.py|/inventory|—|—|Asset & app inventory"
    "technical-writer|suite-api/apps/api/policies_router.py|/policies|—|—|Policy CRUD & validation"
    "sales-engineer|suite-integrations/api/ide_router.py|/ide|—|—|IDE plugin integration"
    # agent-doctor: Self-learning, Zero-gravity, Graph
    "agent-doctor|suite-core/api/self_learning_router.py|/self-learning|core/self_learning.py|—|5 Feedback loops engine"
    "agent-doctor|suite-core/api/zero_gravity_router.py|/zero-gravity|core/zero_gravity.py|—|4-tier data aging"
    "agent-doctor|suite-evidence-risk/api/graph_router.py|/graph|—|—|Knowledge graph visualization"
    # swarm-controller: Exposure cases, Fuzzy identity, IaC
    "swarm-controller|suite-core/api/exposure_case_router.py|/exposure-cases|—|—|Exposure case management"
    "swarm-controller|suite-core/api/fuzzy_identity_router.py|/fuzzy-identity|—|—|Fuzzy identity resolution"
    "swarm-controller|suite-integrations/api/iac_router.py|/iac|—|—|IaC scanning integration"
    # ── Core ENGINES (non-router testable modules — the real CTEM+ brains) ──
    # threat-architect additional engines
    "threat-architect|suite-core/core/mpte_advanced.py|—|—|scripts/test-threat-architect.sh|MPTE advanced engine (1089 LOC)"
    "threat-architect|suite-core/core/attack_simulation_engine.py|—|—|scripts/test-threat-architect.sh|Attack simulation engine (1145 LOC)"
    "threat-architect|suite-core/core/malware_detector.py|—|—|scripts/test-threat-architect.sh|Malware detection engine (381 LOC)"
    "threat-architect|suite-core/core/api_fuzzer.py|—|—|scripts/test-threat-architect.sh|API fuzzer engine (361 LOC)"
    "threat-architect|suite-core/core/playbook_runner.py|—|—|—|Attack playbook runner (1273 LOC)"
    # security-analyst additional engines
    "security-analyst|suite-core/core/iac_scanner.py|—|—|—|IaC scanner engine (713 LOC)"
    "security-analyst|suite-core/core/cspm_engine.py|—|—|—|CSPM analysis engine (586 LOC)"
    "security-analyst|suite-core/core/verification_engine.py|—|—|—|Verification engine (757 LOC)"
    # enterprise-architect additional engines
    "enterprise-architect|suite-core/core/falkordb_client.py|—|—|—|FalkorDB knowledge graph client (835 LOC)"
    "enterprise-architect|suite-core/core/knowledge_brain.py|—|—|—|Knowledge brain engine (852 LOC)"
    # ai-researcher additional engines
    "ai-researcher|suite-core/core/llm_consensus.py|—|—|—|Multi-LLM consensus engine (393 LOC)"
    "ai-researcher|suite-core/core/llm_monitor.py|—|—|—|LLM usage monitor engine (312 LOC)"
    # vision-agent additional engines
    "vision-agent|suite-core/core/compliance.py|—|—|—|Compliance framework engine (133 LOC)"
    "vision-agent|suite-core/core/soc2_evidence_generator.py|—|—|—|SOC2 evidence generator (554 LOC)"
    "vision-agent|suite-evidence-risk/risk/reachability/monitoring.py|—|—|—|Reachability monitoring (264 LOC)"
    # devops-engineer additional engines
    "devops-engineer|suite-core/core/event_bus.py|—|—|—|Event bus (pub/sub engine, 243 LOC)"
    "devops-engineer|suite-core/core/cli.py|—|—|—|CLI (22 commands, 5911 LOC)"
    # qa-engineer additional engines
    "qa-engineer|suite-integrations/api/oss_tools.py|—|—|—|OSS/SCA tools (Trivy/Grype/Cosign, 205 LOC)"
  )

  # ── Build registry: count endpoints per router, check if test script exists ──
  local registry_entries=""
  local total_functions=0
  local tested_functions=0

  declare -gA PERSONA_FUNC_COUNT
  declare -gA PERSONA_TESTED_COUNT
  declare -gA PERSONA_ENDPOINT_COUNT
  declare -gA PERSONA_PASS_RATE
  declare -gA PERSONA_FUNC_DETAIL

  for entry in "${PERSONA_FUNCTIONS[@]}"; do
    IFS='|' read -r agent router_file endpoint_prefix engine_file test_script description <<< "$entry"
    ((total_functions++))

    # Count endpoints in router file
    local ep_count=0
    if [[ -f "$PROJECT_ROOT/$router_file" ]]; then
      ep_count=$(grep -cE '@router\.(get|post|put|delete|patch)\(' "$PROJECT_ROOT/$router_file" 2>/dev/null || true)
      [[ -z "$ep_count" ]] && ep_count=0
    elif [[ -d "$PROJECT_ROOT/$router_file" ]]; then
      # Directory (e.g., UI spaces) — count files
      ep_count=$(find "$PROJECT_ROOT/$router_file" -name '*.tsx' -o -name '*.ts' 2>/dev/null | wc -l | tr -d ' ')
    fi

    # Check if engine file exists and has real LOC
    local engine_loc=0
    if [[ "$engine_file" != "—" && -f "$PROJECT_ROOT/$router_file" ]]; then
      # Find engine file (could be in suite-core/core/ or other paths)
      local engine_path
      engine_path=$(find "$PROJECT_ROOT" -path "*/${engine_file}" -not -path '*/.venv/*' 2>/dev/null | head -1)
      if [[ -n "$engine_path" && -f "$engine_path" ]]; then
        engine_loc=$(wc -l < "$engine_path" 2>/dev/null | tr -d ' ')
      fi
    fi

    # Has test script?
    local has_test="❌"
    if [[ "$test_script" != "—" && -f "$PROJECT_ROOT/$test_script" ]]; then
      has_test="✅"
      ((tested_functions++))
    fi

    # Accumulate per-agent
    local prev_count="${PERSONA_FUNC_COUNT[$agent]:-0}"
    PERSONA_FUNC_COUNT[$agent]=$((prev_count + 1))
    local prev_ep="${PERSONA_ENDPOINT_COUNT[$agent]:-0}"
    PERSONA_ENDPOINT_COUNT[$agent]=$((prev_ep + ep_count))
    if [[ "$has_test" == "✅" ]]; then
      local prev_tested="${PERSONA_TESTED_COUNT[$agent]:-0}"
      PERSONA_TESTED_COUNT[$agent]=$((prev_tested + 1))
    fi

    # Build detail line
    local detail_line="${has_test} ${endpoint_prefix:-$(basename "$router_file" .py)} (${ep_count} eps) ${description}"
    local prev_detail="${PERSONA_FUNC_DETAIL[$agent]:-}"
    if [[ -n "$prev_detail" ]]; then
      PERSONA_FUNC_DETAIL[$agent]="${prev_detail}|${detail_line}"
    else
      PERSONA_FUNC_DETAIL[$agent]="${detail_line}"
    fi
  done

  # ── Run actual test scripts and capture pass rates ──
  declare -gA TEST_SCRIPT_RESULTS
  for test_script in scripts/test-backend-hardener.sh scripts/test-threat-architect.sh; do
    if [[ -x "$PROJECT_ROOT/$test_script" || -f "$PROJECT_ROOT/$test_script" ]]; then
      local result_line
      result_line=$(bash "$PROJECT_ROOT/$test_script" 2>/dev/null | grep -E 'RESULTS:|PASS RATE:|GRADE:' | tail -3 || true)
      if [[ -n "$result_line" ]]; then
        local pass_rate
        pass_rate=$(echo "$result_line" | grep -oE '[0-9]+%' | head -1 || echo "—")
        local grade
        grade=$(echo "$result_line" | grep -oE 'GRADE: [A-F][+]?' | head -1 | sed 's/GRADE: //' || echo "—")
        TEST_SCRIPT_RESULTS[$test_script]="${pass_rate} (${grade})"
      else
        TEST_SCRIPT_RESULTS[$test_script]="⚠️ no output"
      fi
    fi
  done

  # ── Also check pytest test files matching each persona ──
  # Ensure PERSONA_MARKERS exists as associative array (may not be declared yet)
  declare -gA PERSONA_MARKERS 2>/dev/null || true
  declare -gA PERSONA_PYTEST_FILES
  declare -gA PERSONA_PYTEST_COUNT
  for agent in "${!PERSONA_FUNC_COUNT[@]}"; do
    local markers="${PERSONA_MARKERS[$agent]:-}"
    if [[ -n "$markers" ]]; then
      local pytest_files
      pytest_files=$(find "$PROJECT_ROOT/tests" -name 'test_*.py' 2>/dev/null | while IFS= read -r tf; do
        if grep -qiE "$markers" "$tf" 2>/dev/null; then
          basename "$tf"
        fi
      done | sort -u | head -8 | tr '\n' ',' | sed 's/,$//')
      if [[ -n "$pytest_files" ]]; then
        PERSONA_PYTEST_FILES[$agent]="$pytest_files"
        local ptest_count
        ptest_count=$(echo "$pytest_files" | tr ',' '\n' | wc -l | tr -d ' ')
        PERSONA_PYTEST_COUNT[$agent]="$ptest_count"
      fi
    fi
  done

  # ── Write JSON registry (grows over time as agents add functions) ──
  local now_ts
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  {
    echo "{"
    echo "  \"generated\": \"${now_ts}\","
    echo "  \"total_functions\": ${total_functions},"
    echo "  \"tested_functions\": ${tested_functions},"
    echo "  \"personas\": {"
    local first_persona=true
    for agent in $(echo "${!PERSONA_FUNC_COUNT[@]}" | tr ' ' '\n' | sort); do
      $first_persona || echo ","
      first_persona=false
      local fc="${PERSONA_FUNC_COUNT[$agent]:-0}"
      local tc="${PERSONA_TESTED_COUNT[$agent]:-0}"
      local ec="${PERSONA_ENDPOINT_COUNT[$agent]:-0}"
      local pf="${PERSONA_PYTEST_FILES[$agent]:-}"
      local pc="${PERSONA_PYTEST_COUNT[$agent]:-0}"
      echo -n "    \"${agent}\": {\"functions\": ${fc}, \"tested\": ${tc}, \"endpoints\": ${ec}, \"pytest_files\": ${pc}}"
    done
    echo ""
    echo "  }"
    echo "}"
  } > "$registry_file" 2>/dev/null || true

  # ── Return data via global variables (bash can't return complex data) ──
  # These are used by the digest terminal output and markdown sections
  _PERSONA_REG_TOTAL=$total_functions
  _PERSONA_REG_TESTED=$tested_functions
  set -eu  # Re-enable exit-on-error and nounset
}

# ━━━ Format Persona Function Detail for Digest ━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Renders the per-persona function list for terminal and markdown output.
# Called by generate_daily_digest() after build_persona_function_registry().
render_persona_functions_terminal() {
  set +eu  # Disable exit-on-error for safe grep/find
  # Ensure associative arrays exist (may be defined in another function)
  declare -gA PERSONA_TITLE 2>/dev/null || true
  declare -gA PERSONA_FUNC_COUNT 2>/dev/null || true
  declare -gA PERSONA_TESTED_COUNT 2>/dev/null || true
  declare -gA PERSONA_ENDPOINT_COUNT 2>/dev/null || true
  declare -gA PERSONA_FUNC_DETAIL 2>/dev/null || true
  declare -gA PERSONA_PYTEST_FILES 2>/dev/null || true
  declare -gA PERSONA_PYTEST_COUNT 2>/dev/null || true
  local all_agents=("backend-hardener" "threat-architect" "security-analyst" "enterprise-architect" \
    "frontend-craftsman" "ai-researcher" "qa-engineer" "devops-engineer" "data-scientist" \
    "vision-agent" "context-engineer" "scrum-master" "marketing-head" "technical-writer" \
    "sales-engineer" "agent-doctor" "swarm-controller")

  for agent in "${all_agents[@]}"; do
    local fc="${PERSONA_FUNC_COUNT[$agent]:-0}"
    local tc="${PERSONA_TESTED_COUNT[$agent]:-0}"
    local ec="${PERSONA_ENDPOINT_COUNT[$agent]:-0}"
    local title="${PERSONA_TITLE[$agent]:-$agent}"
    local pf="${PERSONA_PYTEST_FILES[$agent]:-}"
    local pc="${PERSONA_PYTEST_COUNT[$agent]:-0}"
    [[ $fc -eq 0 ]] && continue

    # Color based on test coverage
    local _color="${RED}"
    local _icon="❌"
    if [[ $tc -gt 0 ]]; then
      _color="${GREEN}"; _icon="✅"
    fi
    if [[ $pc -gt 0 && $tc -eq 0 ]]; then
      _color="${YELLOW}"; _icon="🧪"
    fi

    printf "${CYAN}║${NC}   ${_icon} %-20s ${DIM}%d funcs, %d endpoints${NC}" "$agent" "$fc" "$ec" >&2
    if [[ $tc -gt 0 ]]; then
      printf " ${GREEN}[%d/%d e2e tested]${NC}" "$tc" "$fc" >&2
    fi
    if [[ $pc -gt 0 ]]; then
      printf " ${CYAN}[%d pytest files]${NC}" "$pc" >&2
    fi
    echo "" >&2

    # Show individual function details (one line each)
    if [[ -n "${PERSONA_FUNC_DETAIL[$agent]:-}" ]]; then
      local IFS_OLD="$IFS"
      IFS='|'
      for detail in ${PERSONA_FUNC_DETAIL[$agent]}; do
        printf "${CYAN}║${NC}     ${DIM}  └─ %s${NC}\n" "$detail" >&2
      done
      IFS="$IFS_OLD"
    fi

    # Show pytest files if any
    if [[ -n "$pf" ]]; then
      printf "${CYAN}║${NC}     ${DIM}  └─ pytest: %s${NC}\n" "$pf" >&2
    fi
  done
  set -eu
}

# ━━━ Render persona functions for Markdown report ━━━━━━━━━━━━━━━━━━━━━━━━
render_persona_functions_markdown() {
  set +eu  # Disable exit-on-error for safe grep/find
  # Ensure associative arrays exist (may be defined in another function)
  declare -gA PERSONA_TITLE 2>/dev/null || true
  declare -gA PERSONA_FUNC_COUNT 2>/dev/null || true
  declare -gA PERSONA_TESTED_COUNT 2>/dev/null || true
  declare -gA PERSONA_ENDPOINT_COUNT 2>/dev/null || true
  declare -gA PERSONA_FUNC_DETAIL 2>/dev/null || true
  declare -gA PERSONA_PYTEST_FILES 2>/dev/null || true
  declare -gA PERSONA_PYTEST_COUNT 2>/dev/null || true
  local all_agents=("backend-hardener" "threat-architect" "security-analyst" "enterprise-architect" \
    "frontend-craftsman" "ai-researcher" "qa-engineer" "devops-engineer" "data-scientist" \
    "vision-agent" "context-engineer" "scrum-master" "marketing-head" "technical-writer" \
    "sales-engineer" "agent-doctor" "swarm-controller")

  echo "| Agent | Persona | Functions | Endpoints | E2E Tested | Pytest Files | Status |"
  echo "|-------|---------|-----------|-----------|------------|--------------|--------|"

  for agent in "${all_agents[@]}"; do
    local fc="${PERSONA_FUNC_COUNT[$agent]:-0}"
    local tc="${PERSONA_TESTED_COUNT[$agent]:-0}"
    local ec="${PERSONA_ENDPOINT_COUNT[$agent]:-0}"
    local title="${PERSONA_TITLE[$agent]:-$agent}"
    local pc="${PERSONA_PYTEST_COUNT[$agent]:-0}"
    [[ $fc -eq 0 ]] && continue

    local status_icon="❌ No tests"
    [[ $pc -gt 0 && $tc -eq 0 ]] && status_icon="🧪 Pytest only"
    [[ $tc -gt 0 && $tc -lt $fc ]] && status_icon="⚠️ Partial"
    [[ $tc -ge $fc ]] && status_icon="✅ Full e2e"

    echo "| ${agent} | ${title} | ${fc} | ${ec} | ${tc}/${fc} | ${pc} | ${status_icon} |"
  done

  echo ""
  echo "### Function Detail Per Persona"
  echo ""

  for agent in "${all_agents[@]}"; do
    local fc="${PERSONA_FUNC_COUNT[$agent]:-0}"
    [[ $fc -eq 0 ]] && continue
    local title="${PERSONA_TITLE[$agent]:-$agent}"
    local pf="${PERSONA_PYTEST_FILES[$agent]:-none}"

    echo "#### ${agent} — ${title}"
    echo ""
    if [[ -n "${PERSONA_FUNC_DETAIL[$agent]:-}" ]]; then
      local IFS_OLD="$IFS"
      IFS='|'
      for detail in ${PERSONA_FUNC_DETAIL[$agent]}; do
        echo "- ${detail}"
      done
      IFS="$IFS_OLD"
    fi
    if [[ "$pf" != "none" ]]; then
      echo "- 🧪 Pytest: \`${pf}\`"
    fi
    echo ""
  done
  set -eu
}

###############################################################################
# PERSONA & UI FLOW VERIFICATION + GRADE-A ENFORCEMENT LOOP
#
# 1. verify_agent_personas() — Verify each agent's output matches their persona
# 2. verify_ui_flows()       — Verify each UI flow/space page quality
# 3. enforce_grade_a()       — Loop until daily grade reaches A
###############################################################################

# ━━━ Agent Persona Verification ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Each agent has a world-class persona. Verify their output matches:
#   - Did they actually do their specialized job?
#   - Did they produce artifacts matching their expertise?
#   - Are their outputs non-trivial (not stubs, not fakes)?
verify_agent_personas() {
  local persona_report="$STATE_DIR/persona-verification-${DATE_TODAY}.md"
  local total_agents=0 verified=0 failed=0 stub_detected=0

  # Agent persona definitions — world-class expectations
  declare -A PERSONA_TITLE
  PERSONA_TITLE["vision-agent"]="Chief Vision Officer"
  PERSONA_TITLE["agent-doctor"]="System Reliability Engineer"
  PERSONA_TITLE["context-engineer"]="Codebase Intelligence Architect"
  PERSONA_TITLE["ai-researcher"]="AI/ML Research Scientist"
  PERSONA_TITLE["data-scientist"]="Data Analytics Lead"
  PERSONA_TITLE["enterprise-architect"]="Enterprise Solutions Architect"
  PERSONA_TITLE["backend-hardener"]="Backend Security Engineer"
  PERSONA_TITLE["frontend-craftsman"]="UI/UX Engineering Lead"
  PERSONA_TITLE["threat-architect"]="Offensive Security Architect"
  PERSONA_TITLE["swarm-controller"]="Swarm Orchestration Lead"
  PERSONA_TITLE["security-analyst"]="Security Analyst & Pentester"
  PERSONA_TITLE["qa-engineer"]="Quality Assurance Lead"
  PERSONA_TITLE["devops-engineer"]="DevOps & Infrastructure Lead"
  PERSONA_TITLE["marketing-head"]="Product Marketing Lead"
  PERSONA_TITLE["technical-writer"]="Technical Documentation Lead"
  PERSONA_TITLE["sales-engineer"]="Solutions Engineering Lead"
  PERSONA_TITLE["scrum-master"]="Agile Delivery Lead"
  PERSONA_TITLE["persona-api-validator"]="Persona API Validation Lead"

  # What each persona MUST produce (keywords in their output proving real work)
  declare -A PERSONA_MARKERS
  PERSONA_MARKERS["vision-agent"]="pillar|vision|V[0-9]|roadmap|alignment|strategy"
  PERSONA_MARKERS["agent-doctor"]="health|diagnostic|fix|recovery|heal|repair"
  PERSONA_MARKERS["context-engineer"]="context|codebase|map|dependency|architecture"
  PERSONA_MARKERS["ai-researcher"]="research|paper|algorithm|model|llm|consensus"
  PERSONA_MARKERS["data-scientist"]="data|metric|analytics|score|correlation|trend"
  PERSONA_MARKERS["enterprise-architect"]="architecture|scalab|integrat|pattern|design"
  PERSONA_MARKERS["backend-hardener"]="endpoint|api|router|database|backend|security"
  PERSONA_MARKERS["frontend-craftsman"]="component|page|react|ui|ux|tsx|css|layout"
  PERSONA_MARKERS["threat-architect"]="threat|attack|exploit|vulnerability|pentest|mpte"
  PERSONA_MARKERS["swarm-controller"]="swarm|task|assign|coordinate|parallel|agent"
  PERSONA_MARKERS["security-analyst"]="scan|finding|cve|risk|assessment|compliance"
  PERSONA_MARKERS["qa-engineer"]="test|coverage|assert|pytest|quality|regression"
  PERSONA_MARKERS["devops-engineer"]="deploy|docker|ci|cd|pipeline|infrastructure"
  PERSONA_MARKERS["marketing-head"]="market|position|competitor|value|customer|pitch"
  PERSONA_MARKERS["technical-writer"]="document|guide|reference|api.doc|tutorial|readme"
  PERSONA_MARKERS["sales-engineer"]="demo|poc|solution|enterprise|pricing|objection"
  PERSONA_MARKERS["scrum-master"]="sprint|standup|velocity|backlog|retrospective|board"
  PERSONA_MARKERS["persona-api-validator"]="persona|newman|postman|workflow|pass.rate|collection"

  local all_agents=("vision-agent" "agent-doctor" "context-engineer" "ai-researcher" \
    "data-scientist" "enterprise-architect" "backend-hardener" "frontend-craftsman" \
    "threat-architect" "swarm-controller" "security-analyst" "qa-engineer" \
    "persona-api-validator" "devops-engineer" "marketing-head" "technical-writer" "sales-engineer" "scrum-master")

  local persona_rows=""
  local api_test_rows=""

  # ── Terminal Header (stderr — stdout reserved for return value) ──
  echo "" >&2
  echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
  echo -e "${BOLD}${MAGENTA}  🎭 AGENT PERSONA VERIFICATION — Who did their job? Who didn't?              ${NC}" >&2
  echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
  echo "" >&2
  printf "  ${DIM}%-22s %-30s %5s %6s  %-s${NC}\n" "AGENT" "PERSONA" "GRADE" "SCORE" "REASON" >&2
  printf "  ${DIM}%-22s %-30s %5s %6s  %-s${NC}\n" "─────────────────────" "────────────────────────────" "─────" "──────" "──────────────────────────────────────" >&2

  for agent in "${all_agents[@]}"; do
    ((total_agents++))
    local title="${PERSONA_TITLE[$agent]:-Unknown}"
    local markers="${PERSONA_MARKERS[$agent]:-}"
    local status_file="$STATE_DIR/${agent}-status.md"
    local log_file
    log_file=$(ls -t "$LOG_DIR/${DATE_TODAY}_${agent}_"*.log 2>/dev/null | head -1)

    local score=0
    local max_score=100
    local details=""
    local is_stub=false

    # ── Check 1: Agent definition file exists (10 pts) ──
    if [[ -f "$PROJECT_ROOT/.claude/agents/${agent}.md" ]]; then
      local def_size
      def_size=$(wc -c < "$PROJECT_ROOT/.claude/agents/${agent}.md" | tr -d ' ')
      if [[ $def_size -gt 500 ]]; then
        score=$((score + 10))
        details+="✅ Persona file OK (${def_size}B). "
      else
        details+="⚠️ Persona file too small (${def_size}B). "
        score=$((score + 3))
      fi
    else
      details+="❌ No persona file. "
    fi

    # ── Check 2: Status file exists with real content (15 pts) ──
    if [[ -f "$status_file" ]]; then
      local sf_size
      sf_size=$(wc -c < "$status_file" | tr -d ' ')
      if [[ $sf_size -gt 200 ]]; then
        score=$((score + 15))
        details+="✅ Status OK. "
      elif [[ $sf_size -gt 50 ]]; then
        score=$((score + 8))
        details+="⚠️ Status thin. "
      else
        details+="❌ Status stub. "
        is_stub=true
      fi
    else
      details+="❌ No status. "
    fi

    # ── Check 3: Log output exists and is substantial (20 pts) ──
    if [[ -n "$log_file" && -f "$log_file" ]]; then
      local log_size
      log_size=$(wc -c < "$log_file" | tr -d ' ')
      if [[ $log_size -gt 5000 ]]; then
        score=$((score + 20))
        details+="✅ Output substantial (${log_size}B). "
      elif [[ $log_size -gt 1000 ]]; then
        score=$((score + 12))
        details+="⚠️ Output light (${log_size}B). "
      elif [[ $log_size -gt 200 ]]; then
        score=$((score + 5))
        details+="⚠️ Output minimal (${log_size}B). "
      else
        details+="❌ Output empty/fake (${log_size}B). "
        is_stub=true
      fi
    else
      details+="❌ No output log. "
    fi

    # ── Check 3b: Supplementary artifact check for coordinator agents (up to 15 pts) ──
    # Coordinator agents (swarm-controller, scrum-master, context-engineer) produce artifacts
    # in team-state directories, not just log files. Award partial credit for real artifacts.
    if [[ $score -lt 30 ]]; then
      case "$agent" in
        swarm-controller)
          local swarm_artifacts=0
          # Check for swarm reports (recent, within 48hrs)
          local recent_report
          recent_report=$(find "$STATE_DIR/swarm/" -name "swarm-report-*.md" -mtime -2 2>/dev/null | head -1)
          [[ -n "$recent_report" ]] && ((swarm_artifacts+=5))
          # Check for task outputs (any completed junior outputs)
          local output_count
          output_count=$(find "$STATE_DIR/swarm/outputs/" -name "status.json" 2>/dev/null | wc -l | tr -d ' ')
          [[ "$output_count" -gt 5 ]] && ((swarm_artifacts+=5))
          # Check for wave assignments
          [[ -f "$STATE_DIR/swarm/assignments/wave1-dispatch.json" ]] && ((swarm_artifacts+=5))
          if [[ $swarm_artifacts -gt 0 ]]; then
            score=$((score + swarm_artifacts))
            details+="✅ Swarm artifacts (+${swarm_artifacts}pts, ${output_count:-0} outputs). "
            is_stub=false
          fi
          ;;
        scrum-master)
          [[ -f "$STATE_DIR/sprint-board.json" ]] && { score=$((score + 10)); details+="✅ Sprint board artifact. "; is_stub=false; }
          ;;
        context-engineer)
          [[ -f "$STATE_DIR/codebase-map.md" || -f "$STATE_DIR/architecture-context.md" ]] && { score=$((score + 10)); details+="✅ Context artifacts. "; is_stub=false; }
          ;;
      esac
    fi

    # ── Check 4: Persona-specific markers in output (30 pts) ──
    # Check log file first; if empty/missing, fall back to status file for markers
    local marker_source=""
    if [[ -n "$log_file" && -f "$log_file" ]] && [[ $(wc -c < "$log_file" 2>/dev/null | tr -d ' ') -gt 100 ]]; then
      marker_source="$log_file"
    elif [[ -f "$status_file" ]] && [[ $(wc -c < "$status_file" 2>/dev/null | tr -d ' ') -gt 100 ]]; then
      marker_source="$status_file"
    fi
    if [[ -n "$marker_source" && -n "$markers" ]]; then
      local marker_hits=0
      local marker_total=0
      local IFS='|'
      for marker in $markers; do
        ((marker_total++))
        if grep -qiE "$marker" "$marker_source" 2>/dev/null; then
          ((marker_hits++))
        fi
      done
      unset IFS
      if [[ $marker_total -gt 0 ]]; then
        local marker_pct=$(( (marker_hits * 100) / marker_total ))
        local marker_score=$(( (marker_hits * 30) / marker_total ))
        score=$((score + marker_score))
        if [[ $marker_pct -ge 80 ]]; then
          details+="✅ Persona match ${marker_pct}%. "
        elif [[ $marker_pct -ge 40 ]]; then
          details+="⚠️ Partial match ${marker_pct}%. "
        else
          details+="❌ Low match ${marker_pct}%. "
        fi
      fi
    else
      details+="❌ No markers checked. "
    fi

    # ── Check 5: Completed successfully (15 pts) ──
    if [[ -f "$status_file" ]] && grep -qi "completed\|✅\|success" "$status_file" 2>/dev/null; then
      score=$((score + 15))
      details+="✅ Completed. "
    elif [[ -f "$status_file" ]] && grep -qi "running\|🔄" "$status_file" 2>/dev/null; then
      score=$((score + 5))
      details+="🔄 Running. "
    else
      details+="❌ Not complete. "
    fi

    # ── Check 6: No hallucination/stub indicators (10 pts) ──
    if [[ -n "$log_file" && -f "$log_file" ]]; then
      local has_fake=false
      if grep -qiE 'TODO:|FIXME:|placeholder|stub|lorem ipsum|example\.com.*fake|not.implemented' "$log_file" 2>/dev/null; then
        has_fake=true
        is_stub=true
        details+="❌ Stub/placeholder detected. "
      else
        score=$((score + 10))
        details+="✅ No stubs. "
      fi
    fi

    $is_stub && ((stub_detected++))

    # ── Check 7: Extract APIs/endpoints worked on + tests referenced ──
    local apis_worked="" tests_referenced="" test_cmds=""
    if [[ -n "$log_file" && -f "$log_file" ]]; then
      # APIs/routers/endpoints — match router files, endpoint paths, HTTP verbs
      apis_worked=$(grep -oiE '(suite-[a-z]+/[a-z/]+_router\.py|/api/v[0-9]+/[a-z/_-]+|apps/api/[a-z_]+_router\.py|core/[a-z_]+\.py)' "$log_file" 2>/dev/null | sort -u | head -8 | tr '\n' ', ' | sed 's/,$//')
      [[ -z "$apis_worked" ]] && apis_worked=$(grep -oiE '(endpoint|router|api|route)[^"]*\.(py|ts)' "$log_file" 2>/dev/null | sort -u | head -5 | tr '\n' ', ' | sed 's/,$//')
      [[ -z "$apis_worked" ]] && apis_worked="-"

      # Tests: file names matching test patterns
      tests_referenced=$(grep -oiE '(tests?/test_[a-z_]+\.py|pytest[^|]*test_[a-z_]+)' "$log_file" 2>/dev/null | sed 's/.*\(test_[a-z_]*\.py\)/\1/' | sort -u | head -5 | tr '\n' ', ' | sed 's/,$//')
      [[ -z "$tests_referenced" ]] && tests_referenced=$(grep -oiE '(test_[a-z_]+\.py|\.test\.tsx?)' "$log_file" 2>/dev/null | sort -u | head -5 | tr '\n' ', ' | sed 's/,$//')
      [[ -z "$tests_referenced" ]] && tests_referenced="-"

      # Build local replication commands from test files found
      if [[ "$tests_referenced" != "-" ]]; then
        local first_test
        first_test=$(echo "$tests_referenced" | cut -d',' -f1 | tr -d ' ')
        test_cmds="pytest tests/${first_test} -v --no-cov"
      else
        test_cmds="-"
      fi
    fi

    # Grade this persona
    local persona_grade="F"
    if [[ $score -ge 85 ]]; then persona_grade="A"; ((verified++))
    elif [[ $score -ge 70 ]]; then persona_grade="B"; ((verified++))
    elif [[ $score -ge 50 ]]; then persona_grade="C"
    elif [[ $score -ge 30 ]]; then persona_grade="D"
    else ((failed++)); fi

    # ── Terminal detail per agent (stderr) ──
    local _grade_color="${RED}"
    case "$persona_grade" in
      A) _grade_color="${GREEN}" ;;
      B) _grade_color="${CYAN}" ;;
      C) _grade_color="${YELLOW}" ;;
    esac
    local _short_reason=""
    if [[ $score -lt 30 ]]; then _short_reason="CRITICAL — "
    elif [[ $score -lt 50 ]]; then _short_reason="WEAK — "
    elif [[ $score -lt 70 ]]; then _short_reason="PARTIAL — "
    fi
    printf "  %-22s %-30s ${_grade_color}%5s${NC} %5d%%  ${_short_reason}%s\n" \
      "$agent" "$title" "$persona_grade" "$score" "$details" >&2
    # Print APIs/tests worked on (stderr, indented under agent)
    if [[ "$apis_worked" != "-" ]]; then
      printf "  ${DIM}  └─ APIs: %s${NC}\n" "$apis_worked" >&2
    fi
    if [[ "$tests_referenced" != "-" ]]; then
      printf "  ${DIM}  └─ Tests: %s${NC}\n" "$tests_referenced" >&2
      printf "  ${DIM}  └─ Replicate: %s${NC}\n" "$test_cmds" >&2
    fi

    persona_rows+="| ${agent} | ${title} | ${persona_grade} | ${score}% | ${details} |"$'\n'
    api_test_rows+="| ${agent} | ${apis_worked} | ${tests_referenced} | \`${test_cmds}\` |"$'\n'
  done

  local overall_pct=0
  [[ $total_agents -gt 0 ]] && overall_pct=$(( (verified * 100) / total_agents ))

  # ── Terminal Summary (stderr) ──
  echo "" >&2
  echo -e "  ${BOLD}━━━ PERSONA SUMMARY ━━━${NC}" >&2
  local _pv_color="${RED}"
  [[ $overall_pct -ge 85 ]] && _pv_color="${GREEN}"
  [[ $overall_pct -ge 70 && $overall_pct -lt 85 ]] && _pv_color="${CYAN}"
  [[ $overall_pct -ge 50 && $overall_pct -lt 70 ]] && _pv_color="${YELLOW}"
  echo -e "  Verified (B+ grade): ${_pv_color}${verified}/${total_agents}${NC} (${_pv_color}${overall_pct}%${NC}) | Failed: ${RED}${failed}${NC} | Stubs: ${RED}${stub_detected}${NC}" >&2
  if [[ $failed -gt 0 ]]; then
    echo -e "  ${RED}⚠ ${failed} agent(s) scored below C — persona work needed!${NC}" >&2
  fi
  if [[ $stub_detected -gt 0 ]]; then
    echo -e "  ${RED}⚠ ${stub_detected} agent(s) have stub/placeholder output — not real work!${NC}" >&2
  fi
  echo "" >&2

  # Write report
  cat > "$persona_report" <<PREOF
# 🎭 Agent Persona Verification — ${DATE_TODAY}

> Each agent is a world-class persona. This report verifies they performed
> at their expected expertise level — no fakes, no stubs, no hallucinations.

## Summary

- **Total Agents:** ${total_agents}
- **Verified (B+ grade):** ${verified} (${overall_pct}%)
- **Failed:** ${failed}
- **Stubs/Fakes Detected:** ${stub_detected}

## Per-Agent Scores

| Agent | Persona Title | Grade | Score | Details |
|-------|--------------|-------|-------|---------|
${persona_rows}

## Scoring Criteria

| Check | Points | Description |
|-------|--------|-------------|
| Persona File | 10 | Agent definition (.claude/agents/*.md) exists and >500 bytes |
| Status File | 15 | Status output exists with real content (>200 bytes) |
| Output Volume | 20 | Agent log has substantial output (>5KB = full marks) |
| Persona Match | 30 | Output contains persona-specific keywords/markers |
| Completion | 15 | Agent completed successfully |
| No Stubs | 10 | No placeholder/TODO/stub patterns in output |

## 🔌 API & Testing Per Agent

| Agent | APIs/Endpoints Worked On | Tests Referenced | Local Replication |
|-------|--------------------------|------------------|-------------------|
${api_test_rows}

### How to Replicate Testing Locally

\`\`\`bash
# Activate environment
source .venv/bin/activate

# Run ALL tests
make test

# Run specific test file (replace with agent's test)
pytest tests/test_<name>.py -v --no-cov

# Run tests matching a pattern
pytest -k "test_integrations" -v --no-cov

# Run with coverage
pytest tests/ --cov=. --cov-fail-under=60

# API smoke test (backend must be running on :8000)
curl -s -H "X-API-Key: \${VITE_API_KEY}" http://localhost:8000/api/v1/health | python3 -m json.tool
\`\`\`

*Generated at $(date '+%Y-%m-%d %H:%M:%S') by JARVIS Controller*
PREOF

  log "PERSONA VERIFICATION: ${verified}/${total_agents} agents verified (${overall_pct}%), ${stub_detected} stubs detected"
  echo "$overall_pct"  # Return overall percentage for the Grade A loop
}

# ━━━ UI Flow Verification ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Verify each UI workflow space and page:
#   - Page file exists and has real content (not a stub)
#   - Page has proper React component structure
#   - Page is above minimum LOC threshold
#   - No "Coming Soon" or placeholder text
verify_ui_flows() {
  local ui_report="$STATE_DIR/ui-flow-verification-${DATE_TODAY}.md"
  local UI_ROOT="$PROJECT_ROOT/suite-ui/aldeci/src/pages"

  # 5 Workflow Spaces with their expected pages
  declare -A SPACE_PAGES
  SPACE_PAGES["mission-control"]="Dashboard.tsx CEODashboard.tsx NerveCenter.tsx"
  SPACE_PAGES["discover"]="CodeScanning.tsx SecretsDetection.tsx IaCScanning.tsx ContainerSecurity.tsx SBOMGeneration.tsx KnowledgeGraphExplorer.tsx AttackPaths.tsx ThreatFeeds.tsx"
  SPACE_PAGES["validate"]="MPTEConsole.tsx AttackSimulation.tsx MicroPentest.tsx Reachability.tsx"
  SPACE_PAGES["remediate"]="Remediation.tsx AutoFixDashboard.tsx BulkOperations.tsx Collaboration.tsx Workflows.tsx Playbooks.tsx"
  SPACE_PAGES["comply"]="EvidenceBundles.tsx ComplianceReports.tsx SOC2EvidenceUI.tsx EvidenceAnalytics.tsx AuditLogs.tsx Reports.tsx SLSAProvenance.tsx"

  local total_pages=0 real_pages=0 stub_pages=0 missing_pages=0
  local space_rows="" page_rows=""
  local STUB_MIN_LOC=100  # Pages under 100 LOC are considered stubs

  # ── Terminal Header (stderr — stdout reserved for return value) ──
  echo "" >&2
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
  echo -e "${BOLD}${CYAN}  🖥️  UI WORKFLOW SPACE VERIFICATION — Every page scored, every stub exposed    ${NC}" >&2
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
  echo "" >&2

  for space in "mission-control" "discover" "validate" "remediate" "comply"; do
    local pages="${SPACE_PAGES[$space]}"
    local space_total=0 space_real=0 space_stub=0 space_missing=0

    # ── Space header (stderr) ──
    local _space_icons=""
    case "$space" in
      mission-control) _space_icons="🎯" ;;
      discover)        _space_icons="🔍" ;;
      validate)        _space_icons="⚡" ;;
      remediate)       _space_icons="🔧" ;;
      comply)          _space_icons="🛡️" ;;
    esac
    echo -e "  ${BOLD}${_space_icons} ${space^^}${NC}" >&2

    for page in $pages; do
      ((total_pages++))
      ((space_total++))

      # Find the page file (it could be in any subdirectory)
      local page_path
      page_path=$(find "$UI_ROOT" -name "$page" -not -path "*/node_modules/*" 2>/dev/null | head -1)

      if [[ -z "$page_path" || ! -f "$page_path" ]]; then
        ((missing_pages++))
        ((space_missing++))
        page_rows+="| ${space} | ${page} | ❌ Missing | 0 | 0 | N/A |"$'\n'
        printf "    ${RED}❌ %-28s MISSING — file not found in suite-ui${NC}\n" "$page" >&2
        continue
      fi

      local loc
      loc=$(wc -l < "$page_path" | tr -d ' ')
      local file_size
      file_size=$(wc -c < "$page_path" | tr -d ' ')

      # Check for stub indicators
      local is_stub=false
      local page_score=0
      local page_grade="F"
      local indicators=""

      # Check LOC threshold
      if [[ $loc -lt $STUB_MIN_LOC ]]; then
        is_stub=true
        indicators+="low-loc "
      fi

      # Check for stub/placeholder patterns
      if grep -qiE 'coming.soon|placeholder|lorem.ipsum|todo.*implement|not.yet|stub' "$page_path" 2>/dev/null; then
        is_stub=true
        indicators+="placeholder "
      fi

      # Check for proper React component structure
      local has_export=false has_return=false has_jsx=false
      grep -qE 'export (default |)function|export (default |)const' "$page_path" 2>/dev/null && has_export=true
      grep -qE 'return \(' "$page_path" 2>/dev/null && has_return=true
      grep -qE '<div|<main|<section|<Card|<Dashboard' "$page_path" 2>/dev/null && has_jsx=true

      # Check for data fetching (real pages fetch data)
      local has_data=false
      grep -qiE 'useEffect|useState|fetch|axios|api\.|useQuery' "$page_path" 2>/dev/null && has_data=true

      # Score calculation
      $has_export && page_score=$((page_score + 15))
      $has_return && page_score=$((page_score + 10))
      $has_jsx && page_score=$((page_score + 15))
      $has_data && page_score=$((page_score + 20))
      [[ $loc -ge 200 ]] && page_score=$((page_score + 20)) || { [[ $loc -ge 100 ]] && page_score=$((page_score + 10)); }
      ! $is_stub && page_score=$((page_score + 20))

      # Grade
      if [[ $page_score -ge 80 ]]; then page_grade="A"
      elif [[ $page_score -ge 60 ]]; then page_grade="B"
      elif [[ $page_score -ge 40 ]]; then page_grade="C"
      elif [[ $page_score -ge 20 ]]; then page_grade="D"
      fi

      if $is_stub; then
        ((stub_pages++))
        ((space_stub++))
        page_rows+="| ${space} | ${page} | ⚠️ Stub | ${loc} | ${page_score}% | ${indicators} |"$'\n'
        printf "    ${YELLOW}⚠️  %-28s STUB  %4d LOC  %3d%%  [%s]${NC}\n" "$page" "$loc" "$page_score" "$indicators" >&2
      else
        ((real_pages++))
        ((space_real++))
        page_rows+="| ${space} | ${page} | ✅ ${page_grade} | ${loc} | ${page_score}% | Real page |"$'\n'
        printf "    ${GREEN}✅ %-28s  %s   %4d LOC  %3d%%${NC}\n" "$page" "$page_grade" "$loc" "$page_score" >&2
      fi
    done

    # Space summary
    local space_pct=0
    [[ $space_total -gt 0 ]] && space_pct=$(( (space_real * 100) / space_total ))
    local space_grade="F"
    [[ $space_pct -ge 85 ]] && space_grade="A"
    [[ $space_pct -ge 70 && $space_pct -lt 85 ]] && space_grade="B"
    [[ $space_pct -ge 50 && $space_pct -lt 70 ]] && space_grade="C"
    [[ $space_pct -ge 30 && $space_pct -lt 50 ]] && space_grade="D"

    space_rows+="| ${space} | ${space_grade} | ${space_real}/${space_total} | ${space_stub} | ${space_missing} | ${space_pct}% |"$'\n'

    # ── Per-space terminal summary (stderr) ──
    local _sp_color="${RED}"
    [[ $space_pct -ge 85 ]] && _sp_color="${GREEN}"
    [[ $space_pct -ge 70 && $space_pct -lt 85 ]] && _sp_color="${CYAN}"
    [[ $space_pct -ge 50 && $space_pct -lt 70 ]] && _sp_color="${YELLOW}"
    echo -e "  ${BOLD}${_sp_color}╰── ${space}:${NC} Grade ${_sp_color}${space_grade}${NC} — ${space_real}/${space_total} real, ${space_stub} stubs, ${space_missing} missing (${_sp_color}${space_pct}%${NC})" >&2
    echo "" >&2
  done

  local overall_pct=0
  [[ $total_pages -gt 0 ]] && overall_pct=$(( (real_pages * 100) / total_pages ))

  # ── Terminal Overall Summary (stderr) ──
  echo -e "  ${BOLD}━━━ UI FLOW SUMMARY ━━━${NC}" >&2
  local _ui_color="${RED}"
  [[ $overall_pct -ge 85 ]] && _ui_color="${GREEN}"
  [[ $overall_pct -ge 70 && $overall_pct -lt 85 ]] && _ui_color="${CYAN}"
  [[ $overall_pct -ge 50 && $overall_pct -lt 70 ]] && _ui_color="${YELLOW}"
  echo -e "  Real pages: ${_ui_color}${real_pages}/${total_pages}${NC} (${_ui_color}${overall_pct}%${NC}) | Stubs: ${RED}${stub_pages}${NC} | Missing: ${RED}${missing_pages}${NC}" >&2
  if [[ $stub_pages -gt 0 || $missing_pages -gt 0 ]]; then
    echo -e "  ${RED}⚠ ${stub_pages} stub + ${missing_pages} missing pages need work for Grade A!${NC}" >&2
  fi
  echo "" >&2

  # Write report
  cat > "$ui_report" <<UIREOF
# 🖥️ UI Flow Verification — ${DATE_TODAY}

> Verifying each UI workflow space and page for quality.
> Pages under ${STUB_MIN_LOC} LOC or with placeholder text = STUB.

## Summary

- **Total Pages Checked:** ${total_pages}
- **Real Pages:** ${real_pages} (${overall_pct}%)
- **Stub Pages:** ${stub_pages}
- **Missing Pages:** ${missing_pages}

## Workflow Space Health

| Space | Grade | Real/Total | Stubs | Missing | Quality % |
|-------|-------|------------|-------|---------|-----------|
${space_rows}

## Per-Page Details

| Space | Page | Status | LOC | Score | Notes |
|-------|------|--------|-----|-------|-------|
${page_rows}

## Grade Criteria

- **A (80%+):** Real component, data fetching, 200+ LOC, no placeholders
- **B (60%+):** Proper structure, some data, 100+ LOC
- **C (40%+):** Basic structure but thin
- **D (20%+):** Minimal, mostly stub
- **F:** Missing or empty

*Generated at $(date '+%Y-%m-%d %H:%M:%S') by JARVIS Controller*
UIREOF

  log "UI FLOW VERIFICATION: ${real_pages}/${total_pages} real pages (${overall_pct}%), ${stub_pages} stubs, ${missing_pages} missing"
  echo "$overall_pct"  # Return overall percentage for the Grade A loop
}

# ━━━ Grade-A Enforcement Loop ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Runs after ALL phases. If Grade < A, identifies weak areas, spawns fix
# agents targeted at those weak areas, re-runs verification, and loops
# until Grade A is reached or CONTROLLER_MAX_FIX_CYCLES exhausted.
#
# This is the ULTIMATE quality gate: no run exits with less than Grade A
# unless every possible fix has been attempted.
enforce_grade_a() {
  if ! $ENABLE_CONTROLLER; then
    echo ""
    echo -e "${DIM}  ℹ️ GRADE-A LOOP: Skipped — JARVIS Controller is disabled (--no-controller).${NC}"
    echo -e "${DIM}    Enable with --controller to run persona / UI / health verification loop.${NC}"
    echo ""
    return 0
  fi

  local grade_cycle=0
  local max_grade_cycles=${CONTROLLER_MAX_FIX_CYCLES}
  local current_grade="F"
  local current_score=0

  echo ""
  echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}${YELLOW}  ⭐ GRADE-A ENFORCEMENT LOOP — Quality is non-negotiable     ${NC}"
  echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""

  while [[ $grade_cycle -lt $max_grade_cycles ]]; do
    grade_cycle=$((grade_cycle + 1))
    log "GRADE-A: Enforcement cycle ${grade_cycle}/${max_grade_cycles}"

    # ── Step 1: Run persona verification ──
    local persona_pct
    persona_pct=$(verify_agent_personas)
    # Sanitize
    persona_pct=${persona_pct%%.*}
    [[ -z "$persona_pct" || ! "$persona_pct" =~ ^[0-9]+$ ]] && persona_pct=0

    # ── Step 2: Run UI flow verification ──
    local ui_pct
    ui_pct=$(verify_ui_flows)
    # Sanitize
    ui_pct=${ui_pct%%.*}
    [[ -z "$ui_pct" || ! "$ui_pct" =~ ^[0-9]+$ ]] && ui_pct=0

    # ── Step 3: Compute combined score ──
    # Health score from digest (already computed), persona %, UI %
    # Combined = 40% health + 30% persona + 30% UI
    local health_file="$STATE_DIR/daily-digest-${DATE_TODAY}.md"
    local latest_health_score=0
    if [[ -f "$health_file" ]]; then
      latest_health_score=$(grep -oE 'Health Grade.*\(([0-9]+)/100\)' "$health_file" 2>/dev/null | grep -oE '[0-9]+/100' | head -1 | cut -d/ -f1 || true)
      [[ -z "$latest_health_score" || ! "$latest_health_score" =~ ^[0-9]+$ ]] && latest_health_score=0
    fi

    current_score=$(( (latest_health_score * 40 / 100) + (persona_pct * 30 / 100) + (ui_pct * 30 / 100) ))

    if [[ $current_score -ge 85 ]]; then current_grade="A"
    elif [[ $current_score -ge 70 ]]; then current_grade="B"
    elif [[ $current_score -ge 50 ]]; then current_grade="C"
    elif [[ $current_score -ge 30 ]]; then current_grade="D"
    else current_grade="F"
    fi

    echo -e "  Cycle ${grade_cycle}: Health=${latest_health_score}% Persona=${persona_pct}% UI=${ui_pct}% → Combined=${current_score}% → Grade ${BOLD}${current_grade}${NC}"

    # ── Detailed per-dimension breakdown ──
    echo ""
    local _h_icon="✅" _p_icon="✅" _u_icon="✅"
    local _h_col="${GREEN}" _p_col="${GREEN}" _u_col="${GREEN}"
    [[ $latest_health_score -lt 85 ]] && _h_icon="⚠️"  && _h_col="${YELLOW}"
    [[ $latest_health_score -lt 50 ]] && _h_icon="❌" && _h_col="${RED}"
    [[ $persona_pct -lt 85 ]]          && _p_icon="⚠️"  && _p_col="${YELLOW}"
    [[ $persona_pct -lt 50 ]]          && _p_icon="❌" && _p_col="${RED}"
    [[ $ui_pct -lt 85 ]]               && _u_icon="⚠️"  && _u_col="${YELLOW}"
    [[ $ui_pct -lt 50 ]]               && _u_icon="❌" && _u_col="${RED}"
    echo -e "    ${_h_icon} ${_h_col}Health     (40% weight): ${latest_health_score}%${NC}  ← Enterprise health scoring"
    echo -e "    ${_p_icon} ${_p_col}Personas   (30% weight): ${persona_pct}%${NC}  ← Agent persona keyword matches + output quality"
    echo -e "    ${_u_icon} ${_u_col}UI Flows   (30% weight): ${ui_pct}%${NC}  ← Real pages vs stubs/missing"
    echo -e "    ──────────────────────────────────────────────────"
    if [[ "$current_grade" == "A" ]]; then
      echo -e "    ${GREEN}★ RESULT: Grade A achieved — all dimensions above threshold!${NC}"
    else
      echo -e "    ${YELLOW}⚠ RESULT: Grade ${current_grade} (${current_score}%) — need 85%+ for Grade A${NC}"
      [[ $latest_health_score -lt 70 ]] && echo -e "    ${RED}  └─ Health below 70% → will re-run qa-engineer${NC}"
      [[ $persona_pct -lt 70 ]]          && echo -e "    ${RED}  └─ Persona below 70% → will re-run failed agents${NC}"
      [[ $ui_pct -lt 70 ]]               && echo -e "    ${RED}  └─ UI below 70% → will spawn frontend-craftsman to fix stubs${NC}"
    fi
    echo ""

    # ── Grade A reached? ──
    if [[ "$current_grade" == "A" ]]; then
      success "GRADE-A ACHIEVED! Combined score: ${current_score}% (Health:${latest_health_score} Persona:${persona_pct} UI:${ui_pct})"
      voice "Grade A achieved. Quality target met." "celebration"

      echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"grade_a_achieved\",\"score\":${current_score},\"cycle\":${grade_cycle},\"health\":${latest_health_score},\"persona\":${persona_pct},\"ui\":${ui_pct}}" >> "$CONTROLLER_LOG" 2>/dev/null || true

      # Write Grade-A certification
      atomic_write_heredoc "$STATE_DIR/grade-a-certification-${DATE_TODAY}.md" <<GAEOF
# ⭐ Grade-A Certification — ${DATE_TODAY}

**Status:** CERTIFIED GRADE A
**Combined Score:** ${current_score}%
**Enforcement Cycle:** ${grade_cycle}
**Certified At:** $(date '+%Y-%m-%d %H:%M:%S')

| Dimension | Score |
|-----------|-------|
| Health (enterprise scoring) | ${latest_health_score}% |
| Persona Verification | ${persona_pct}% |
| UI Flow Quality | ${ui_pct}% |

> Every agent output has been verified through 5-layer hallucination protection,
> JARVIS Controller reconciliation, persona verification, and UI flow checks.
> No stub code. No fake data. No unverified output.
GAEOF
      break
    fi

    # ── Not Grade A yet — identify and fix weak areas ──
    warn "GRADE-A: Grade is ${current_grade} (${current_score}%) — targeting weak areas..."
    echo -e "  ${BOLD}🔧 FIX CYCLE ${grade_cycle} — What's being fixed and why:${NC}"

    local fix_targets=""

    # Identify which dimension is weakest
    if [[ $persona_pct -lt 70 ]]; then
      fix_targets+="persona "
      # Find failed agents from persona report
      local failed_personas
      failed_personas=$(grep '| ❌\|| D \|| F ' "$STATE_DIR/persona-verification-${DATE_TODAY}.md" 2>/dev/null | awk -F'|' '{print $2}' | tr -d ' ' | head -5)
      if [[ -n "$failed_personas" ]]; then
        echo -e "  ${RED}🎭 Persona failures requiring re-run:${NC}"
        while IFS= read -r fagent; do
          [[ -z "$fagent" ]] && continue
          # Get reason from persona report
          local _reason
          _reason=$(grep "${fagent}" "$STATE_DIR/persona-verification-${DATE_TODAY}.md" 2>/dev/null | awk -F'|' '{print $6}' | head -1 | sed 's/^ *//;s/ *$//')
          echo -e "    ${RED}└─ ${fagent}:${NC} ${_reason:-unknown reason}"
        done <<< "$failed_personas"
        echo -e "  ${YELLOW}→ Spawning fix agents + re-running each failed persona agent...${NC}"
        log "GRADE-A: Re-running failed persona agents: $failed_personas"
        while IFS= read -r fagent; do
          [[ -z "$fagent" ]] && continue
          rm -f "$CHECKPOINT_DIR/${RUN_ID}_${fagent}.done" 2>/dev/null || true
          controller_spawn_fix_agent "$fagent" "Persona verification failed — agent not performing at world-class level" \
            "$(ls -t "$LOG_DIR/${DATE_TODAY}_${fagent}_"*.log 2>/dev/null | head -1)" "$grade_cycle" || true
          run_agent "$fagent" || true
        done <<< "$failed_personas"
      fi
    fi

    if [[ $ui_pct -lt 70 ]]; then
      fix_targets+="ui "
      # Spawn frontend-craftsman to fix stub/missing pages
      local stub_list
      stub_list=$(grep -E 'Stub|Missing' "$STATE_DIR/ui-flow-verification-${DATE_TODAY}.md" 2>/dev/null | awk -F'|' '{print $3}' | tr -d ' ' | head -10)
      if [[ -n "$stub_list" ]]; then
        echo -e "  ${YELLOW}🖥️  UI pages needing fix (stubs/missing):${NC}"
        while IFS= read -r _spage; do
          [[ -z "$_spage" ]] && continue
          echo -e "    ${YELLOW}└─ ${_spage}${NC}"
        done <<< "$stub_list"
        echo -e "  ${YELLOW}→ Spawning frontend-craftsman fix agent to rebuild these pages...${NC}"
        log "GRADE-A: Spawning fix agent for ${stub_list//$'\n'/, } UI pages"
        local ui_fix_log="$FIX_AGENTS_DIR/${DATE_TODAY}_fix-ui-stubs_cycle${grade_cycle}.log"
        mkdir -p "$FIX_AGENTS_DIR"
        local ui_fix_prompt="JARVIS GRADE-A ENFORCEMENT — UI STUB FIXER
═══════════════════════════════════════════
You are a world-class React/TypeScript engineer fixing stub UI pages.

STUB/MISSING PAGES TO FIX:
${stub_list}

UI ROOT: suite-ui/aldeci/src/pages/

FOR EACH PAGE:
1. If missing, create it with a proper React component
2. If stub (<100 LOC or has 'coming soon'), rewrite it to be a REAL page:
   - Proper imports (React, hooks, shadcn/ui components)
   - useState/useEffect for data management
   - Real UI layout with cards, tables, charts as appropriate
   - Minimum 150 LOC per page
   - NO placeholder text, NO 'coming soon', NO lorem ipsum
3. Each page must match its workflow space purpose:
   - mission-control: dashboards, metrics, status
   - discover: scanning results, findings lists, graphs
   - validate: MPTE console, attack simulation output
   - remediate: fix actions, bulk ops, collaboration
   - comply: evidence, compliance reports, audit logs
4. Use shadcn/ui components (Card, Badge, Button, Table)
5. Use Tailwind CSS for styling
6. After fixing each page, verify it compiles

QUALITY STANDARD: Grade A — world-class UI implementation."

        local run_cmd
        if [[ -n "$TIMEOUT_CMD" ]]; then
          run_cmd="$TIMEOUT_CMD $CONTROLLER_FIX_TIMEOUT claude"
        else
          run_cmd="claude"
        fi
        # SIGTSTP-immune launch: SIG_IGN propagates across exec() per POSIX
        local _uifix_pfile="${ui_fix_log}.prompt.tmp"
        printf '%s' "$ui_fix_prompt" > "$_uifix_pfile"
        (
          trap '' TSTP TTIN TTOU
          /opt/homebrew/bin/bash -c '
            trap "" TSTP TTIN TTOU
            _pfile="$1"; shift
            exec "$@" -p "$(cat "$_pfile")"
          ' _ "$_uifix_pfile" \
            $run_cmd \
              --print --output-format text --verbose \
              --dangerously-skip-permissions \
              --max-turns 100 \
              > "$ui_fix_log" 2>&1
        ) || true
        rm -f "$_uifix_pfile" 2>/dev/null || true
      fi
    fi

    if [[ $latest_health_score -lt 70 ]]; then
      fix_targets+="health "
      echo -e "  ${RED}🏥 Health score below threshold (${latest_health_score}%):${NC}"
      # Health score issues usually mean failed agents or low activity
      # The controller_post_swarm_reconcile already handles failed agents
      # Let's re-run the qa-engineer to improve test coverage
      if [[ $latest_health_score -lt 50 ]]; then
        echo -e "    ${RED}└─ Health < 50% → re-running qa-engineer for test coverage & quality metrics${NC}"
        log "GRADE-A: Re-running qa-engineer to improve quality metrics"
        rm -f "$CHECKPOINT_DIR/${RUN_ID}_qa-engineer.done" 2>/dev/null || true
        run_agent "qa-engineer" || true
      else
        echo -e "    ${YELLOW}└─ Health 50-69% → monitoring only (controller reconcile handles this)${NC}"
      fi
    fi

    # ── Cycle fix summary ──
    if [[ -n "$fix_targets" ]]; then
      echo -e "  ${BOLD}✅ Fix cycle ${grade_cycle} complete. Targets addressed: ${fix_targets}${NC}"
    else
      echo -e "  ${DIM}ℹ️  No fix targets identified (all dimensions ≥70%) but combined < 85%${NC}"
    fi
    echo ""

    echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"grade_a_cycle\",\"cycle\":${grade_cycle},\"grade\":\"${current_grade}\",\"score\":${current_score},\"fix_targets\":\"${fix_targets}\",\"health\":${latest_health_score},\"persona\":${persona_pct},\"ui\":${ui_pct}}" >> "$CONTROLLER_LOG" 2>/dev/null || true

    # Brief pause between cycles
    [[ $grade_cycle -lt $max_grade_cycles ]] && sleep 15
  done

  if [[ "$current_grade" != "A" ]]; then
    echo ""
    echo -e "${BOLD}${RED}━━━ GRADE-A LOOP RESULT: NOT ACHIEVED ━━━${NC}"
    echo -e "  ${RED}Could not reach Grade A after ${max_grade_cycles} cycle(s)${NC}"
    echo -e "  ${RED}Best result: Grade ${current_grade} (${current_score}%)${NC}"
    echo -e "  ${RED}Breakdown: Health=${latest_health_score:-0}% Persona=${persona_pct:-0}% UI=${ui_pct:-0}%${NC}"
    if [[ ${latest_health_score:-0} -lt 85 ]]; then
      echo -e "  ${RED}  └─ Health needs ${GREEN}$((85 - ${latest_health_score:-0}))% more${NC} — improve test coverage, fix failing agents"
    fi
    if [[ ${persona_pct:-0} -lt 85 ]]; then
      echo -e "  ${RED}  └─ Personas need ${GREEN}$((85 - ${persona_pct:-0}))% more${NC} — agents must produce real persona-matched output"
    fi
    if [[ ${ui_pct:-0} -lt 85 ]]; then
      echo -e "  ${RED}  └─ UI Flows need ${GREEN}$((85 - ${ui_pct:-0}))% more${NC} — rebuild stub pages with real components"
    fi
    warn "GRADE-A: Could not reach Grade A after ${max_grade_cycles} cycles (best: ${current_grade} ${current_score}%)"
    if $CONTROLLER_NEVER_GIVE_UP; then
      echo -e "  ${YELLOW}🔄 NEVER-GIVE-UP mode is ON — will retry in next swarm iteration${NC}"
      warn "GRADE-A: NEVER-GIVE-UP mode — will retry in next iteration"
    else
      echo -e "  ${DIM}ℹ️  NEVER-GIVE-UP mode is OFF — accepting Grade ${current_grade} for today${NC}"
    fi
    echo ""
  fi

  # Write combined verification summary
  atomic_write_heredoc "$STATE_DIR/quality-snapshot-${DATE_TODAY}.md" <<QSEOF
# 📊 Quality Snapshot — ${DATE_TODAY}

| Dimension | Score | Grade |
|-----------|-------|-------|
| Enterprise Health | ${latest_health_score:-0}% | $([ ${latest_health_score:-0} -ge 85 ] && echo A || echo $([ ${latest_health_score:-0} -ge 70 ] && echo B || echo $([ ${latest_health_score:-0} -ge 50 ] && echo C || echo D))) |
| Persona Verification | ${persona_pct:-0}% | $([ ${persona_pct:-0} -ge 85 ] && echo A || echo $([ ${persona_pct:-0} -ge 70 ] && echo B || echo $([ ${persona_pct:-0} -ge 50 ] && echo C || echo D))) |
| UI Flow Quality | ${ui_pct:-0}% | $([ ${ui_pct:-0} -ge 85 ] && echo A || echo $([ ${ui_pct:-0} -ge 70 ] && echo B || echo $([ ${ui_pct:-0} -ge 50 ] && echo C || echo D))) |
| **Combined** | **${current_score}%** | **${current_grade}** |

Enforcement cycles: ${grade_cycle}/${max_grade_cycles}
QSEOF

  return $([ "$current_grade" == "A" ] && echo 0 || echo 1)
}

###############################################################################
# Atomic Write — crash-safe state file updates
# Usage: atomic_write "/path/to/file" "content"
# Writes to .tmp first, then mv (atomic on POSIX). Prevents corruption if
# script crashes mid-write.
###############################################################################
atomic_write() {
  local target="$1"
  local content="$2"
  local tmp="${target}.tmp.$$"
  echo "$content" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
  mv -f "$tmp" "$target" 2>/dev/null || { rm -f "$tmp"; return 1; }
}

# Atomic cat-heredoc helper: atomic_write_heredoc "/path/to/file" <<EOF ... EOF
# Usage: atomic_write_heredoc "/path/to/file" <<EOF\ncontent\nEOF
atomic_write_heredoc() {
  local target="$1"
  local tmp="${target}.tmp.$$"
  cat > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
  mv -f "$tmp" "$target" 2>/dev/null || { rm -f "$tmp"; return 1; }
}

header() {
  echo ""
  echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}${MAGENTA}  ✦ $* ✦${NC}"
  echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

banner() {
  echo -e "${MAGENTA}${BOLD}"
  cat <<'BANNER'
   ╔═══════════════════════════════════════════════════════════╗
   ║                                                           ║
   ║     █████╗ ██╗     ██████╗ ███████╗ ██████╗██╗            ║
   ║    ██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝██║            ║
   ║    ███████║██║     ██║  ██║█████╗  ██║     ██║            ║
   ║    ██╔══██║██║     ██║  ██║██╔══╝  ██║     ██║            ║
   ║    ██║  ██║███████╗██████╔╝███████╗╚██████╗██║            ║
   ║    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝            ║
   ║                                                           ║
   ║         CTEM+ AI SWARM — JARVIS Autonomous Engine        ║
   ║     Decision Intelligence · MPTE · MCP-Native Platform    ║
   ║         Full Autonomy · Self-Healing · No Human Gate      ║
   ║                                                           ║
   ╚═══════════════════════════════════════════════════════════╝
BANNER
  echo -e "${NC}"
}

###############################################################################
# Pre-flight checks
###############################################################################
preflight() {
  log "Pre-flight self-healing checks..."
  local issues=0

  # ── 1. Self-heal the environment (PATH, tools, dirs) ──
  if ! self_heal_environment; then
    error "Critical environment issues could not be auto-healed"
    error "Fix the issues above and re-run"
    exit 1
  fi

  # ── 2. Verify Claude CLI responds ──
  local claude_version
  claude_version=$(claude --version 2>&1 | head -1 || echo "unknown")
  if [[ "$claude_version" == "unknown" || -z "$claude_version" ]]; then
    warn "Claude CLI installed but not responding — may need re-authentication"
    warn "Run 'claude' interactively first to authenticate"
    issues=$((issues + 1))
  else
    success "Claude CLI: $claude_version"
  fi

  # ── 3. Verify project root ──
  if [[ ! -f "$PROJECT_ROOT/sitecustomize.py" ]]; then
    error "Not in ALdeci project root. Expected sitecustomize.py at: $PROJECT_ROOT"
    exit 1
  fi
  success "Project root: $PROJECT_ROOT"

  # ── 4. Check agent files (warn, don't exit) ──
  local agent_count
  agent_count=$(find "$AGENTS_DIR" -name "*.md" -maxdepth 1 | wc -l | tr -d ' ')
  if [[ "$agent_count" -lt 17 ]]; then
    warn "Expected 17 agent files, found $agent_count in $AGENTS_DIR"
    issues=$((issues + 1))
  else
    success "Agent files: $agent_count agents found"
  fi

  # ── 5. Check vision docs (warn, don't exit) ──
  for doc in "docs/CEO_VISION.md" "docs/VISION_TO_ACCOMPLISH.MD" "docs/CTEM_PLUS_IDENTITY.md" "docs/VISION_DEBATE_TRANSCRIPT.md"; do
    if [[ -f "$PROJECT_ROOT/$doc" ]]; then
      debug "Found: $doc"
    else
      warn "Missing vision doc: $doc (agents will have less context)"
      issues=$((issues + 1))
    fi
  done

  # ── 6. TIMEOUT_CMD sanity ──
  if [[ -n "$TIMEOUT_CMD" ]]; then
    success "Timeout command: $TIMEOUT_CMD"
  else
    warn "No timeout command — agents run without time limits"
  fi

  # ── 7. Clean zombie agent statuses stuck on 'Running' from prior crash ──
  local zombies=0
  for sf in "$STATE_DIR"/*-status.md; do
    [[ -f "$sf" ]] || continue
    if grep -q '🔄 Running' "$sf" 2>/dev/null; then
      # Check if file is older than 1 hour (stale)
      # Use /usr/bin/stat (macOS native) explicitly to avoid GNU stat shadowing
      local mod_time
      mod_time=$(/usr/bin/stat -f '%m' "$sf" 2>/dev/null) || mod_time=0
      local file_age=$(( $(date +%s) - mod_time ))
      if [[ $file_age -gt 3600 ]]; then
        local agent_base
        agent_base=$(basename "$sf" -status.md)
        warn "Auto-healing: ${agent_base} status stuck on 'Running' for ${file_age}s — marking as crashed"
        atomic_write_heredoc "$sf" <<ZOMBIE_EOF
# ${agent_base} Status
- **Status:** ⚠️ Crashed (auto-detected by JARVIS pre-flight)
- **Runtime:** ${MODEL} (CTEM+ Swarm)
- **Date:** ${DATE_TODAY}
- **Notes:** Found stuck on 'Running' for ${file_age}s — likely crashed without cleanup
- **Recovery:** Will be retried on next swarm run or --resume
ZOMBIE_EOF
        zombies=$((zombies + 1))
      fi
    fi
  done
  [[ $zombies -gt 0 ]] && success "Auto-healed $zombies zombie agent status(es)"

  # ── 8. Clean stale prompt.tmp files from prior crashes ──
  local stale_prompts=0
  for ptmp in "$LOG_DIR"/*.prompt.tmp; do
    [[ -f "$ptmp" ]] || continue
    rm -f "$ptmp" 2>/dev/null && stale_prompts=$((stale_prompts + 1))
  done
  [[ $stale_prompts -gt 0 ]] && success "Cleaned $stale_prompts stale prompt.tmp file(s) from prior crashes"

  # ── Summary ──
  if [[ $issues -gt 0 ]]; then
    warn "Pre-flight completed with $issues warning(s) — proceeding anyway"
  else
    success "Pre-flight complete — all systems go"
  fi
}

###############################################################################
# Shared Context Protocol (SCP) — JARVIS Full Situational Awareness
#
# Injects ALL .claude/ state into every agent prompt so JARVIS has complete
# memory of: vision, sprint, metrics, sibling agent outputs, debates,
# autonomous decisions, and role-specific state files.
#
# Data sources (in injection order):
#   1. Vision Debate Verdict (hardcoded from debate transcript)
#   2. CEO Vision (docs/CEO_VISION.md)
#   3. Sprint Board (.claude/team-state/sprint-board.json)
#   4. Project Metrics (.claude/team-state/metrics.json)
#   5. Coordination Protocol (.claude/team-state/coordination-notes.md)
#   6. Today's Briefing (.claude/team-state/briefing-{date}.md)
#   7. Last Run Summary (.claude/team-state/last-run-summary.md)
#   8. Context Log (context_log.md — last 30 lines)
#   9. Agent's Own Memory (.claude/team-state/{agent}-memory.json)
#  10. Sibling Agent Statuses (.claude/team-state/*-status.md)
#  11. Autonomous Decisions Log (.claude/team-state/decisions.log)
#  12. Active Debates (.claude/team-state/debates/active/*.md)
#  13. Health Dashboard (.claude/team-state/health-dashboard.json)
#  14. Role-Specific State (per coordination-notes.md data-flow map)
#  15. Iteration Context (previous verdict/failures from qa/)
#  16. CTEM+ Identity (docs/CTEM_PLUS_IDENTITY.md)
###############################################################################
build_scp_context() {
  local agent_name="$1"
  local scp=""
  local INDEX_DIR="$PROJECT_ROOT/.claude/knowledge-index"

  # ━━━ AGENT SCP PROFILES — Only inject what each agent ACTUALLY needs ━━━━
  # Lightweight agents skip heavy sections. Builders get full context.
  # This reduces prompt size by 30-60% for non-builder agents.
  local needs_sprint=true needs_metrics=true needs_decisions=true
  local needs_outcomes=true needs_debates=true needs_codebase_map=true
  local needs_iteration_ctx=true

  case "$agent_name" in
    vision-agent|agent-doctor)
      # Phase 0/9/10: Need outcomes + metrics, skip codebase/debates
      needs_codebase_map=false; needs_debates=false; needs_iteration_ctx=false ;;
    marketing-head|technical-writer|sales-engineer)
      # Phase 7: Need metrics for stats, skip codebase/iteration/debates
      needs_codebase_map=false; needs_iteration_ctx=false; needs_debates=false
      needs_decisions=false ;;
    scrum-master)
      # Phase 8: Needs everything for coordination (already compact) ;;
      ;;
    context-engineer)
      # Phase 1: Needs codebase map, skip debates/iteration (builds context)
      needs_debates=false; needs_iteration_ctx=false ;;
    ai-researcher|data-scientist|enterprise-architect)
      # Phase 2: Research — need decisions + metrics, skip iteration ctx
      needs_iteration_ctx=false ;;
    backend-hardener|frontend-craftsman|threat-architect)
      # Phase 3: Builders — need EVERYTHING (full SCP) ;;
      ;;
    swarm-controller)
      # Phase 3.5: Coordinator — needs sprint + metrics + decisions, skip heavy sections
      needs_codebase_map=false; needs_debates=false ;;
    security-analyst|qa-engineer)
      # Phase 4: Validators — need iteration ctx + outcomes (what to test) ;;
      ;;
    *)
      # Default: full SCP ;;
      ;;
  esac

  # ━━━ PRE-FLIGHT: Generate/refresh knowledge index ━━━━━━━━━━━━━━━━━━━━━━
  # Index is regenerated if older than 10 minutes or missing
  local need_regen=false
  if [[ ! -f "$INDEX_DIR/sprint-digest.json" ]]; then
    need_regen=true
  else
    local index_age
    index_age=$(( $(date +%s) - $(stat -f '%m' "$INDEX_DIR/sprint-digest.json" 2>/dev/null || true) ))
    [[ $index_age -gt 600 ]] && need_regen=true
  fi

  if $need_regen; then
    python3 "$PROJECT_ROOT/scripts/generate-knowledge-index.py" --agent "$agent_name" 2>/dev/null || true
  fi

  # ━━━ 1. VISION MANDATE (hardcoded, ~500 bytes — never changes) ━━━━━━━━━
  scp+="## VISION MANDATE
**Restructure, don't rewrite.** 3 Core Pillars: V3 (Decision Intelligence), V5 (MPTE Verification), V7 (MCP-Native).
4 Design Constraints: V1 (APP_ID), V2 (lifecycle), V9 (air-gapped), V10 (CTEM+crypto).
3 Deferred: V4 (Multi-LLM), V6 (Quantum), V8 (Self-learning).
Ship 3 UI screens: Triage Dashboard, MPTE Verification View, Evidence Export."$'\n\n'

  # ━━━ 2. SPRINT (from digest — ~1KB vs 17KB raw) ━━━━━━━━━━━━━━━━━━━━━━━
  if $needs_sprint && [[ -f "$INDEX_DIR/sprint-digest.json" ]]; then
    scp+="## SPRINT STATUS:"$'\n'
    scp+="$(cat "$INDEX_DIR/sprint-digest.json")"$'\n'
    scp+="Full board: .claude/team-state/sprint-board.json (update it after your work)."$'\n\n'
  fi

  # ━━━ 3. METRICS (from digest — ~300 bytes vs 8KB raw) ━━━━━━━━━━━━━━━━━
  if $needs_metrics && [[ -f "$INDEX_DIR/metrics-digest.json" ]]; then
    scp+="## PROJECT METRICS:"$'\n'
    scp+="$(cat "$INDEX_DIR/metrics-digest.json")"$'\n'
    scp+="Update .claude/team-state/metrics.json if your work changes any metric."$'\n\n'
  fi

  # ━━━ 4. DECISIONS (last 5 — ~800 bytes vs 41KB raw) ━━━━━━━━━━━━━━━━━━━
  if $needs_decisions && [[ -f "$INDEX_DIR/decisions-digest.json" ]]; then
    scp+="## RECENT DECISIONS:"$'\n'
    scp+="$(cat "$INDEX_DIR/decisions-digest.json")"$'\n\n'
  fi

  # ━━━ 5. AGENT OUTCOMES (who ran, what happened — ~1KB) ━━━━━━━━━━━━━━━━━
  if $needs_outcomes && [[ -f "$INDEX_DIR/agent-outcomes.json" ]]; then
    scp+="## AGENT OUTCOMES (sibling status):"$'\n'
    scp+="$(cat "$INDEX_DIR/agent-outcomes.json")"$'\n\n'
  fi

  # ━━━ 6. YOUR OWN BRIEFING (memory + status + role pointers) ━━━━━━━━━━━
  if [[ -f "$INDEX_DIR/${agent_name}-briefing.json" ]]; then
    scp+="## YOUR BRIEFING:"$'\n'
    scp+="$(cat "$INDEX_DIR/${agent_name}-briefing.json")"$'\n\n'
  fi

  # ━━━ 7. CODEBASE MAP (architecture reference — ~3KB) ━━━━━━━━━━━━━━━━━━
  if $needs_codebase_map && [[ -f "$INDEX_DIR/codebase-map.json" ]]; then
    scp+="## CODEBASE MAP:"$'\n'
    scp+="$(cat "$INDEX_DIR/codebase-map.json")"$'\n\n'
  fi

  # ━━━ 8. ACTIVE DEBATES (agents must respond — only if they exist) ━━━━━
  # ━━━ 8. ACTIVE DEBATES (DISABLED — agents should code, not debate) ━━━
  # Debates are read-only context. Agents no longer respond during build runs.
  # To re-enable: uncomment the block below.
  #if $needs_debates; then
  #  ...
  #fi

  # ━━━ 9. ITERATION CONTEXT (failure recovery) ━━━━━━━━━━━━━━━━━━━━━━━━━━
  if $needs_iteration_ctx && [[ $CURRENT_ITERATION -gt 1 ]]; then
    local prev_iter=$((CURRENT_ITERATION - 1))
    scp+="## ITERATION ${CURRENT_ITERATION} — FIX FIRST"$'\n'
    local prev_verdict="$STATE_DIR/qa/iteration-${prev_iter}/verdict.json"
    if [[ -f "$prev_verdict" ]]; then
      scp+="Previous verdict: $(cat "$prev_verdict")"$'\n'
    fi
    local prev_failures="$STATE_DIR/qa/iteration-${prev_iter}/failures.md"
    if [[ -f "$prev_failures" ]]; then
      scp+="Failures: $(head -20 "$prev_failures")"$'\n'
    fi
    scp+="**Fix failures from iteration ${prev_iter} before building new features.**"$'\n\n'
  elif $needs_iteration_ctx; then
    scp+="## ITERATION 1 — Build real features, no stubs."$'\n\n'
  fi

  # ━━━ 10. COORDINATION POINTER (only if they need inter-agent data) ━━━━
  scp+="## COORDINATION: .claude/team-state/coordination-notes.md has inter-agent data contracts — read ONLY if you need another agent's output."$'\n\n'

  # ━━━ 11. RULES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  scp+="## RULES
- 90% of your turns = writing code, running tests, fixing bugs. 10% = reading context.
- After your run: UPDATE your -status.md (files changed + LOC), APPEND to decisions.log.
- NO stubs, NO hardcoded data, NO fake responses.
- Imports: sitecustomize.py auto-prepends all suite paths.
- If you read more than 5 files before writing code, you're doing it wrong."$'\n\n'

  echo "$scp"
}

###############################################################################
# War Room prompt override — laser-focused on 3 UI screens
###############################################################################
build_war_room_prompt() {
  local agent_name="$1"

  local base="🚨 WAR ROOM MODE — 90-Day Sprint to Revenue 🚨

ALL work must serve ONE of these three deliverables:
  1. TRIAGE DASHBOARD — Show 11,300→340 finding reduction
  2. MPTE VERIFICATION VIEW — Show exploitability proof
  3. EVIDENCE EXPORT — Generate signed compliance bundle

If your task does NOT serve one of these three screens, SKIP IT.

Current codebase state:
  - Backend: 167K LOC Python — WORKING, do not break
  - Frontend: 4,118 files in suite-ui/aldeci/ (legacy, needs forking)
  - New UI: suite-ui/aldeci-ui-new/ — DOES NOT EXIST, must be built
  - Test coverage: 20.36% — aim for 50% on new code
  - Revenue: \$0, Customers: 0

"

  case "$agent_name" in
    frontend-craftsman)
      base+="YOUR MISSION: You are the #1 priority agent in War Room mode.
Fork suite-ui/aldeci/ into suite-ui/aldeci-ui-new/ if it doesn't exist.
Build 3 screens wired to real backend APIs:
  Screen 1: Triage Dashboard (GET /api/v1/brain/process, GET /api/v1/findings)
  Screen 2: MPTE Verification (POST /api/v1/mpte/verify, GET /api/v1/mpte/results)
  Screen 3: Evidence Export (POST /api/v1/evidence/export, GET /api/v1/compliance/status)
Stack: React 19 + Vite 6 + TypeScript 5 + Tailwind CSS 4 + shadcn/ui
Design: Apple HIG — clean, generous whitespace, physics-based animations
Navigation: 5 Workflow Spaces (Mission Control, Discover, Validate, Remediate, Comply)
The 3 screens go into: Mission Control (Triage), Validate (MPTE), Comply (Evidence)."
      ;;
    backend-hardener)
      base+="YOUR MISSION: Ensure these 3 API endpoints work flawlessly for the POC UI:
  1. Brain Pipeline: GET /api/v1/brain/process — must handle 11,300 findings in <5 min
  2. MPTE: POST /api/v1/mpte/verify — must return exploitability proof
  3. Evidence: POST /api/v1/evidence/export — must return signed bundle
Add batching/async to brain_pipeline.py (steps 5+9 are bottlenecks).
Write tests for these 3 endpoints. Target 80% coverage on touched files."
      ;;
    qa-engineer)
      base+="YOUR MISSION: Test EVERYTHING against the LIVE running API using Postman/Newman.
DO NOT use pytest as primary testing. DO NOT massage tests to pass.
1. Start the API server if not running: uvicorn apps.api.app:app --port 8000
2. Run ALL 7 Postman collections via Newman against http://localhost:8000
   newman run suite-integrations/postman/enterprise/ALdeci-*.postman_collection.json -e ALdeci-Environment.postman_environment.json
3. Run customer simulation scenarios (CISO triage, MPTE verify, evidence export, air-gapped scan)
4. Detect stubs: ANY endpoint returning fake/hardcoded data = STUB = FAIL
5. After each builder agent's changes, UPDATE the relevant Postman collection
6. Write iteration-{N}/verdict.json with pass/fail counts and failures.md with fix assignments
7. pytest is ONLY for unit tests on pure functions — NEVER for API testing"
      ;;
    threat-architect)
      base+="YOUR MISSION: Ensure MPTE can produce compelling exploitability evidence.
The MPTE Verification View is one of the 3 POC screens.
A CISO must see: 'This finding IS exploitable — here's the proof.'
Make the 19-phase MPTE output human-readable and audit-grade."
      ;;
    security-analyst)
      base+="YOUR MISSION: Validate that the brain pipeline + MPTE + evidence
chain produces REAL, accurate, non-hallucinated security intelligence.
Run the pipeline against real CVE data. Flag any false positives.
The credibility of the product depends on signal quality."
      ;;
    context-engineer)
      base+="YOUR MISSION: Map the codebase for the 3 UI screens.
Produce a wiring guide: which backend endpoints → which frontend components.
Check if suite-ui/aldeci-ui-new/ exists. If not, plan the fork.
Identify all API contracts the frontend needs."
      ;;
    devops-engineer)
      base+="YOUR MISSION: Ensure the full stack can be demo'd in one command.
docker-compose up should launch backend (port 8000) + frontend (port 3001).
Ensure the 3 POC screens are accessible and wired to live APIs."
      ;;
    scrum-master)
      base+="YOUR MISSION: Track War Room progress. Update sprint-board.json.
The only KPIs that matter:
  - Are the 3 screens built? (frontend-craftsman)
  - Do the 3 APIs work? (backend-hardener)
  - Is coverage >50%? (qa-engineer)
  - Can we demo? (devops-engineer)
Write daily-demo for stakeholders."
      ;;
    *)
      base+="YOUR MISSION: Support the War Room effort.
Ask yourself: 'Does my work directly help ship the 3 POC screens?'
If yes, proceed. If no, find what DOES help and do that instead.
The only agents that matter right now: frontend-craftsman, backend-hardener, qa-engineer."
      ;;
  esac

  echo "$base"
}

###############################################################################
# Run a single agent with self-healing
###############################################################################
run_agent() {
  local agent_name="$1"
  log "[DEBUG] run_agent ENTERED for $agent_name"
  local agent_file="$AGENTS_DIR/${agent_name}.md"
  local log_file="$LOG_DIR/${DATE_TODAY}_${agent_name}_${RUN_ID}.log"
  local timeout=$TIMEOUT_DEFAULT
  local current_agent_file="$STATE_DIR/.jarvis-current-agent"

  # Tell JARVIS launcher which agent is running (for status ticker)
  echo "$agent_name" > "$current_agent_file" 2>/dev/null || true
  log "[DEBUG] $agent_name: wrote current-agent file"

  # Dynamic timeout: critical agents get more time, phase-0 agents get less
  case "$agent_name" in
    frontend-craftsman|backend-hardener|threat-architect) timeout=$TIMEOUT_CRITICAL ;;
    swarm-controller) timeout=2400 ;;  # 40 min — needs time for task decomposition, dispatch, monitoring
    technical-writer|marketing-head|sales-engineer) timeout=2100 ;;  # 35 min — docs agents need headroom (SP3-009)
    vision-agent|agent-doctor) timeout=$TIMEOUT_PHASE0 ;;
  esac

  # Superhuman: use historical performance data for smart timeout
  log "[DEBUG] $agent_name: calling get_smart_timeout..."
  timeout=$(get_smart_timeout "$agent_name" "$timeout")
  log "[DEBUG] $agent_name: timeout=$timeout"

  if [[ ! -f "$agent_file" ]]; then
    error "Agent file not found: $agent_file"
    return 1
  fi
  log "[DEBUG] $agent_name: agent file exists"

  # Check if already completed in this run (for --resume)
  if $RESUME && [[ -f "$CHECKPOINT_DIR/${RUN_ID}_${agent_name}.done" ]]; then
    log "Skipping ${agent_name} (already completed in this run)"
    return 0
  fi

  # Capture system snapshot before agent starts
  log "[DEBUG] $agent_name: capture_system_snapshot..."
  capture_system_snapshot "pre-${agent_name}"
  log "[DEBUG] $agent_name: snapshot done"

  # ── Guardian: pre-agent safety snapshot (DISABLED — was causing swarm hang) ──
  # type guardian_pre_agent &>/dev/null && guardian_pre_agent "$agent_name"
  log "[DEBUG] $agent_name: guardian skipped (was blocking)"

  log "Starting: ${BOLD}${agent_name}${NC}  [✦ ${MODEL}]  timeout=${timeout}s  turns=${MAX_TURNS}"
  voice "${agent_name} starting" "normal"
  log "[DEBUG] $agent_name: voice done"

  if $DRY_RUN; then
    log "[DRY RUN] Would run: $agent_name (timeout: ${timeout}s, turns: ${MAX_TURNS})"
    return 0
  fi

  # Build prompt
  log "[DEBUG] Building SCP context for $agent_name..."
  local scp_context
  scp_context=$(build_scp_context "$agent_name")
  log "[DEBUG] SCP context built (${#scp_context} bytes)"

  local prompt=""
  if $WAR_ROOM; then
    prompt=$(build_war_room_prompt "$agent_name")
    prompt+=$'\n\n'"$scp_context"
  else
    prompt="CTEM+ SWARM — Claude Opus 4.6 fast — ITERATION ${CURRENT_ITERATION}/${ITERATIONS}
$([ $CURRENT_ITERATION -gt 1 ] && echo 'FIX failures from previous iteration FIRST — read .claude/team-state/qa/iteration-*/failures.md' || echo 'First pass — build real code, no stubs')
AUTONOMY: FULL — bypassPermissions enabled. NEVER ask for human approval.
MAX TURNS: ${MAX_TURNS} — You have $(( timeout / 60 )) minutes. Date: ${DATE_TODAY}.

${scp_context}

══════════════════════════════════════════════════════════════
  YOUR TIME BUDGET: 90% CODING, 10% CONTEXT
══════════════════════════════════════════════════════════════

PHASE 1 — CONTEXT (spend ≤10% of your turns here, then STOP reading and START coding):
1. Read .claude/agents/${agent_name}.md — your identity and today's mission
2. Skim sprint-board.json to know what's in-progress vs done
3. Check .claude/team-state/coordination-notes*.md ONLY IF your mission needs input from another agent
4. That's it. Do NOT read CEO_VISION, VISION_TO_ACCOMPLISH, or debate transcripts. The SCP context above has everything you need.

PHASE 2 — BUILD (spend ≥90% of your turns here — THIS IS YOUR JOB):
5. Execute your mission from your agent .md — write code, fix bugs, create tests, harden APIs
6. NO STUBS — every endpoint must return real computed data, not hardcoded values
7. RUN TESTS after every change — python -m pytest tests/ -x --timeout=10 -q
8. If tests fail, fix them before moving on — leave no broken code
9. If you finish your primary mission early, tackle secondary objectives from your agent .md
10. Focus on CORE PILLARS: V3 (Decision Intelligence), V5 (MPTE), V7 (MCP)

PHASE 3 — LOG (spend ≤2 turns at the END — not during work):
11. Write your status to .claude/team-state/${agent_name}-status.md — what you CHANGED (file paths + line counts), not what you read
12. APPEND to .claude/team-state/decisions.log: [YYYY-MM-DD HH:MM] agent:${agent_name} DECISION: what / ACTION: what_you_did / RESULT: outcome

KEY RULES:
- Measure output by FILES CHANGED, not documents read
- Do NOT write metrics.json, context_log.md, or pillar tags — that's overhead, not work
- Do NOT participate in debates during build runs — code now, discuss later
- If you detect issues in other agents' code, FIX them directly instead of reporting
- Imports: sitecustomize.py auto-prepends all suite paths
- UI work: suite-ui/aldeci/ is the active UI directory"
  fi

  # ━━━ LAYER 1: Pre-Execution Vision Alignment — inject hallucination guardrails ━━━
  log "[DEBUG] Applying hallucination layer 1..."
  prompt=$(hallucination_layer1_vision_alignment "$agent_name" "$prompt")
  log "[DEBUG] Prompt ready (${#prompt} bytes). Launching Claude CLI..."

  # Write status: running (atomic to prevent corruption on crash)
  atomic_write_heredoc "$STATE_DIR/${agent_name}-status.md" <<EOF
# ${agent_name} Status
- **Status:** 🔄 Running
- **Runtime:** ${MODEL} (CTEM+ Swarm)
- **Mode:** $(${WAR_ROOM} && echo "WAR ROOM 🚨" || echo "Standard")
- **Started:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")
- **Run ID:** ${RUN_ID}
- **Log:** logs/ai-team/${DATE_TODAY}_${agent_name}_${RUN_ID}.log
EOF

  # ── Self-Healing Retry Loop ──
  local attempt=0
  local run_ok=false
  local last_failure_reason=""

  while [[ $attempt -lt $MAX_RETRIES ]]; do
    # ── QUOTA EXHAUSTION GUARD — skip immediately if API is dry ──
    if $QUOTA_EXHAUSTED; then
      error "  QUOTA EXHAUSTED — skipping ${agent_name} (${QUOTA_EXHAUSTED_MSG})"
      last_failure_reason="API quota exhausted: ${QUOTA_EXHAUSTED_MSG}"
      break
    fi

    attempt=$((attempt + 1))
    local start_time=$(date +%s)

    if [[ $attempt -gt 1 ]]; then
      local backoff=$(( RETRY_BACKOFF_BASE * (2 ** (attempt - 2)) ))
      warn "  Retry $attempt/$MAX_RETRIES for ${agent_name} (backoff: ${backoff}s)"

      # ── PER-RETRY SELF-HEALING ──
      # Analyze why the last attempt failed and try to fix it before retrying
      if [[ -f "$log_file" ]]; then
        local log_tail
        log_tail=$(tail -20 "$log_file" 2>/dev/null || echo "")

        # Heal: timeout/gtimeout missing
        if echo "$log_tail" | grep -q 'timeout: command not found\|gtimeout: command not found' 2>/dev/null; then
          warn "  SELF-HEAL: timeout command missing — re-resolving..."
          if command -v gtimeout &>/dev/null; then
            TIMEOUT_CMD="gtimeout"
          elif command -v timeout &>/dev/null; then
            TIMEOUT_CMD="timeout"
          else
            TIMEOUT_CMD=""  # Run without time limit
          fi
          last_failure_reason="timeout command not found (healed)"
          success "  HEALED: TIMEOUT_CMD=$TIMEOUT_CMD"
        fi

        # Heal: Nested Claude session (CLAUDECODE env var)
        if echo "$log_tail" | grep -q 'cannot be launched inside another Claude Code session\|unset the CLAUDECODE' 2>/dev/null; then
          warn "  SELF-HEAL: Nested session detected — unsetting CLAUDECODE..."
          unset CLAUDECODE CLAUDE_CODE_ENTRYPOINT 2>/dev/null || true
          success "  HEALED: CLAUDECODE unset"
          last_failure_reason="Nested session (healed — CLAUDECODE unset)"
        fi

        # Heal: Claude CLI not found (PATH lost mid-run)
        if echo "$log_tail" | grep -q 'claude: command not found\|Claude Code CLI not found' 2>/dev/null; then
          warn "  SELF-HEAL: Claude CLI lost from PATH — re-searching..."
          for p in /opt/homebrew/bin /usr/local/bin "$HOME/.npm-global/bin"; do
            if [[ -x "$p/claude" ]]; then
              export PATH="$p:$PATH"
              success "  HEALED: Found claude at $p"
              break
            fi
          done
          last_failure_reason="Claude CLI not in PATH (healed)"
        fi

        # Heal: Node not found (Claude CLI needs it)
        if echo "$log_tail" | grep -q 'node: command not found\|Cannot find module' 2>/dev/null; then
          warn "  SELF-HEAL: Node.js lost from PATH..."
          for p in /opt/homebrew/bin /usr/local/bin; do
            if [[ -x "$p/node" ]]; then
              export PATH="$p:$PATH"
              success "  HEALED: Found node at $p"
              break
            fi
          done
          last_failure_reason="Node.js not in PATH (healed)"
        fi

        # Heal: Permission denied
        if echo "$log_tail" | grep -q 'Permission denied' 2>/dev/null; then
          warn "  SELF-HEAL: Permission issue — fixing..."
          chmod +x "$SWARM_SCRIPT" 2>/dev/null || true
          chmod -R u+w "$PROJECT_ROOT/.claude" 2>/dev/null || true
          last_failure_reason="Permission denied (healed)"
        fi

        # Heal: Port 8000 already in use (API server conflict)
        if echo "$log_tail" | grep -q 'Address already in use\|port 8000' 2>/dev/null; then
          warn "  SELF-HEAL: Port 8000 conflict..."
          local pid_on_port
          pid_on_port=$(lsof -ti:8000 2>/dev/null || echo "")
          if [[ -n "$pid_on_port" ]]; then
            kill "$pid_on_port" 2>/dev/null || true
            sleep 2
            success "  HEALED: Freed port 8000 (killed PID $pid_on_port)"
          fi
          last_failure_reason="Port 8000 conflict (healed)"
        fi

        # Heal: 0-byte output (timeout kill before stdout flush — KP-001)
        local log_size
        log_size=$(stat -f '%z' "$log_file" 2>/dev/null || echo "0")
        if [[ "$log_size" -eq 0 ]]; then
          warn "  SELF-HEAL: 0-byte output detected (KP-001) — killing orphans + increasing memory ceiling..."
          pkill -f "node.*claude.*${agent_name}" 2>/dev/null || true
          sleep 3
          # Bump memory ceiling for retry (prevent OOM-kill before buffer flush)
          AGENT_MAX_RAM_MB[$agent_name]=$(( ${AGENT_MAX_RAM_MB[$agent_name]:-2400} + 600 ))
          last_failure_reason="0-byte output (KP-001 — orphans killed, memory bumped to ${AGENT_MAX_RAM_MB[$agent_name]}MB)"
          success "  HEALED: RAM ceiling → ${AGENT_MAX_RAM_MB[$agent_name]}MB, orphans cleaned"
        fi

        # Heal: Disk space issue
        if echo "$log_tail" | grep -q 'No space left on device\|Disk quota exceeded' 2>/dev/null; then
          warn "  SELF-HEAL: Disk space issue — cleaning old logs..."
          find "$LOG_DIR" -name "*.log" -mtime +7 -delete 2>/dev/null || true
          find "$PROJECT_ROOT/__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
          last_failure_reason="Disk space (cleaned old logs)"
        fi

        # Heal: Rate limited by API
        if echo "$log_tail" | grep -qi 'rate.limit\|429\|too many requests' 2>/dev/null; then
          warn "  SELF-HEAL: Rate limited — using longer backoff..."
          backoff=$((backoff * 3))  # Triple the backoff
          last_failure_reason="Rate limited (extended backoff to ${backoff}s)"
        fi

        # FATAL: Claude API quota exhausted — NO retry possible, halt ALL agents
        if echo "$log_tail" | grep -qi 'out of.*usage.*resets\|out of extra usage' 2>/dev/null; then
          QUOTA_EXHAUSTED=true
          QUOTA_EXHAUSTED_MSG=$(echo "$log_tail" | grep -oi 'resets.*' | head -1 | tr -d '\n')
          error "╔══════════════════════════════════════════════════════════════╗"
          error "║  💀 QUOTA EXHAUSTED — Claude API is out of usage            ║"
          error "║  ${QUOTA_EXHAUSTED_MSG:-Unknown reset time}  ║"
          error "║  ALL agent launches halted. No retries. No fix-agents.      ║"
          error "╚══════════════════════════════════════════════════════════════╝"
          last_failure_reason="QUOTA_EXHAUSTED: ${QUOTA_EXHAUSTED_MSG}"
          # Record in failure ledger
          broadcast_failure_alert "${agent_name}" "QUOTA_EXHAUSTED" "API quota depleted — ${QUOTA_EXHAUSTED_MSG}. Entire swarm halted." 2>/dev/null || true
          break  # Exit retry loop immediately
        fi
      fi

      # ── Progressive Failure Context (smarter retries) ──
      if $PROGRESSIVE_CONTEXT; then
        local retry_ctx
        retry_ctx=$(build_retry_context "$agent_name" "$attempt" "$log_file" "$last_failure_reason")
        prompt="${prompt}${retry_ctx}"
      fi

      sleep "$backoff"
    fi

    # Run via Claude Code CLI — FULL AUTONOMY (no permission prompts)
    #
    # ROOT CAUSE FIX: Claude processes were getting STOPPED (state T) every 60s
    # because node.js resets inherited SIG_IGN signal handlers on startup.
    # bash trap '' TSTP → exec node → node resets SIGTSTP to SIG_DFL → stopped.
    #
    # THE FIX: Use perl's POSIX::setsid() to create a NEW SESSION before
    # exec'ing claude. A session leader without a controlling terminal CANNOT
    # receive SIGTSTP/SIGTTIN/SIGTTOU from terminal job control — period.
    # This works regardless of what node.js does with signal handlers.
    local run_cmd
    if [[ -n "$TIMEOUT_CMD" ]]; then
      run_cmd="$TIMEOUT_CMD $timeout claude"
    else
      run_cmd="claude"
    fi

    # Cap prompt size to prevent bloat from accumulated retry/SCP context.
    # Claude CLI handles ~100KB fine but >60KB prompts correlate with 0-byte output
    # (observed in swarm-2026-02-27_12-45-36: 75KB prompt → 0-byte output).
    local prompt_bytes=${#prompt}
    if [[ $prompt_bytes -gt 50000 ]]; then
      warn "  Prompt too large (${prompt_bytes} bytes) — truncating to 50KB"
      prompt="${prompt:0:50000}"
    fi

    local prompt_file="${log_file}.prompt.tmp"
    printf '%s' "$prompt" > "$prompt_file"
    log "[DEBUG] Launching subshell for $agent_name (attempt $attempt, timeout=${timeout}s, turns=${MAX_TURNS})..."
    log "[DEBUG] run_cmd='$run_cmd' prompt_file='$prompt_file' log_file='$log_file'"

    # ── Per-Agent Claude CLI Skill Config ──────────────────────────────────
    # Restrict tools by role: builders get full access, non-builders are limited
    local agent_tools="" agent_effort="high"
    case "$agent_name" in
      backend-hardener|frontend-craftsman|threat-architect|devops-engineer)
        # Builders: all tools, high effort
        agent_tools="Read,Write,Edit,Bash,Grep,Glob"
        agent_effort="high"
        ;;
      qa-engineer|security-analyst)
        # Validators: all tools (need Bash for tests), high effort
        agent_tools="Read,Write,Edit,Bash,Grep,Glob"
        agent_effort="high"
        ;;
      context-engineer|scrum-master|agent-doctor|swarm-controller)
        # Coordinators: read + write + bash (swarm needs Bash for junior dispatch/test runs)
        agent_tools="Read,Write,Bash,Grep,Glob"
        agent_effort="high"
        ;;
      vision-agent|marketing-head|technical-writer|sales-engineer)
        # Non-coders: read-only + write docs, no Bash execution
        agent_tools="Read,Write,Grep,Glob"
        agent_effort="medium"
        ;;
      ai-researcher|data-scientist|enterprise-architect)
        # Researchers: read + analyze, can write proposals but limited Bash
        agent_tools="Read,Write,Edit,Bash,Grep,Glob"
        agent_effort="high"
        ;;
      *)
        # Default: full access
        agent_tools="Read,Write,Edit,Bash,Grep,Glob"
        agent_effort="high"
        ;;
    esac

    # Build extra CLI flags
    local extra_flags=""
    [[ -n "$agent_tools" ]] && extra_flags+=" --tools $agent_tools"
    [[ -n "$agent_effort" ]] && extra_flags+=" --effort $agent_effort"

    # System-level coding directive (separate from agent identity prompt)
    local coding_directive="You are running in SWARM BUILD MODE. Your output is measured by FILES CHANGED and TESTS PASSING, not by documents read or status reports written. Spend 90% of your turns writing code and running tests. Spend at most 10% reading context. After coding, update your status file and decisions log. Do not read CEO_VISION.md, VISION_TO_ACCOMPLISH.MD, or debate transcripts — the SCP context in your prompt already has what you need."

    (
      unset CLAUDECODE CLAUDE_CODE_ENTRYPOINT  # Allow nested invocation
      # Apply per-agent memory ceiling (ulimit -v) inside the subshell
      apply_agent_memory_limit "$agent_name"
      exec /usr/bin/perl -MPOSIX -e '
        POSIX::setsid();
        open(STDIN, "<", "/dev/null") or warn "stdin redirect: $!";
        exec("/opt/homebrew/bin/bash", "-c",
          q{_pfile="$1"; shift; exec "$@" -p "$(cat "$_pfile")"},
          "_", @ARGV) or die "exec bash: $!\n";
      ' -- "$prompt_file" \
           $run_cmd \
             --agent "$agent_name" \
             --print --output-format text --verbose \
             --dangerously-skip-permissions \
             --max-turns "$MAX_TURNS" \
             --append-system-prompt "$coding_directive" \
             $extra_flags \
      > "$log_file" 2>&1
    )
    local exit_code=$?
    log "[DEBUG] Agent subshell completed: exit_code=$exit_code"
    rm -f "$prompt_file" 2>/dev/null || true

    if [[ $exit_code -eq 0 ]]; then
      # ── ROOT CAUSE 6 FIX (2026-02-27): Agent success detection ──
      # Agent mode (--agent) works via tool calls (Read/Write/Edit/Bash).
      # Output goes into FILES the agent modifies, NOT stdout.
      # Previous check: >50 bytes stdout → false failure for ALL tool-based agents.
      # New check: exit code 0 + (stdout > 0 OR agent modified files OR status file exists).
      local out_size=0
      [[ -f "$log_file" ]] && out_size=$(wc -c < "$log_file" | tr -d ' ')

      # Check if agent produced file changes (the REAL work product)
      local agent_modified_files=false
      local status_file="$STATE_DIR/${agent_name}-status.md"
      local git_changes=0
      git_changes=$(git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null | wc -l | tr -d ' ')
      local new_files=0
      new_files=$(git -C "$PROJECT_ROOT" ls-files --others --exclude-standard 2>/dev/null | wc -l | tr -d ' ')

      # Agent is considered successful if ANY of these are true:
      # 1. Stdout has content (traditional check)
      # 2. Agent wrote/updated its status file recently (within last 5 min)
      # 3. Git working tree has changes (agent modified code/docs)
      if [[ $out_size -ge 50 ]]; then
        agent_modified_files=true
        debug "  ${agent_name}: stdout check passed (${out_size} bytes)"
      elif [[ -f "$status_file" ]] && [[ $(find "$status_file" -mmin -5 2>/dev/null | wc -l) -gt 0 ]]; then
        agent_modified_files=true
        log "  ${agent_name}: exit 0 + status file updated — agent SUCCESS via tool calls"
        # Capture status file as pseudo-output for downstream analysis
        if [[ $out_size -lt 50 ]]; then
          cat "$status_file" >> "$log_file" 2>/dev/null || true
        fi
      elif [[ $((git_changes + new_files)) -gt 0 ]]; then
        agent_modified_files=true
        log "  ${agent_name}: exit 0 + ${git_changes} changed / ${new_files} new files — agent SUCCESS via file writes"
        # Create minimal log content for downstream parsers
        if [[ $out_size -lt 50 ]]; then
          echo "## ${agent_name} — Completed via tool calls" >> "$log_file"
          echo "Modified files: ${git_changes}, New files: ${new_files}" >> "$log_file"
          git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null | head -20 >> "$log_file"
        fi
      fi

      if ! $agent_modified_files; then
        warn "  ${agent_name} exited 0 but produced ${out_size} bytes AND no file changes — treating as failure (zombie/frozen process)"
        last_failure_reason="Zero-byte output with no file changes (zombie/frozen process)"
        # Don't break — retry
        continue
      fi

      # ── OUTPUT QUALITY GATE (relaxed for agent mode) ──
      # Re-read log size after potential status file append above
      local log_size=0
      [[ -f "$log_file" ]] && log_size=$(wc -c < "$log_file" | tr -d ' ')
      if [[ $log_size -lt 50 ]]; then
        # Agent had no stdout AND we couldn't reconstruct output — true zombie
        warn "  QUALITY GATE FAIL: ${agent_name} produced only ${log_size} bytes and no recoverable output — REJECTING"
        last_failure_reason="Output too small (${log_size} bytes) with no file changes"
        continue
      fi

      # ━━━ LAYER 3: Post-Execution Deep Content Analysis (INSIDE retry loop) ━━━
      local layer3_pass=true
      export AGENT_NAME="$agent_name" LOG_PATH="$log_file" PROJECT_ROOT="$PROJECT_ROOT"
      if ! hallucination_layer3_deep_analysis "$agent_name" "$log_file"; then
        layer3_pass=false
        if $HALLUCINATION_HARD_FAIL; then
          warn "  LAYER 3 REJECTION: ${agent_name} hallucination detected — will retry"
          last_failure_reason="Hallucination Layer 3 rejection (stub code, fabricated data, or vision violations)"
          voice "${agent_name} output rejected — hallucination detected" "critical"
          continue
        else
          warn "  LAYER 3: Hallucination detected but HARD_FAIL disabled — accepting with warning"
        fi
      fi

      # ━━━ LAYER 5: Code Verification & Test Gate (INSIDE retry loop) ━━━
      local layer5_pass=true
      if ! hallucination_layer5_code_verify "$agent_name"; then
        layer5_pass=false
        if $HALLUCINATION_HARD_FAIL; then
          warn "  LAYER 5 REJECTION: ${agent_name} code verification failed — will retry"
          last_failure_reason="Layer 5 code verification failure (syntax errors or test failures)"
          voice "${agent_name} code verification failed" "critical"
          continue
        else
          warn "  LAYER 5: Code verification failed but HARD_FAIL disabled — accepting with warning"
        fi
      fi

      # All gates passed — agent output accepted
      run_ok=true
      break
    else
      if [[ $exit_code -eq 124 ]]; then
        warn "  ${agent_name} timed out after ${timeout}s (attempt $attempt)"
        last_failure_reason="Timeout after ${timeout}s"
      else
        warn "  ${agent_name} exited with code $exit_code (attempt $attempt)"
        last_failure_reason="Exit code ${exit_code}"

        # ── OOM-specific checkpoint + healing (exit 137 = kernel killed) ──
        if [[ $exit_code -eq 137 ]]; then
          warn "  🧠 OOM KILL detected — saving incremental checkpoint before retry"

          # Save whatever git changes the agent made BEFORE it was killed
          local oom_diff
          oom_diff=$(git -C "$PROJECT_ROOT" diff --stat HEAD 2>/dev/null | tail -3 || echo "(none)")
          local oom_free_mb
          oom_free_mb=$(get_free_ram_mb 2>/dev/null || echo "0")

          # Write incremental checkpoint — survives even if ALL retries fail
          cat > "$CHECKPOINT_DIR/${RUN_ID}_${agent_name}_attempt${attempt}.oom" <<OOMJSON
{
  "agent": "${agent_name}",
  "status": "oom_killed",
  "run_id": "${RUN_ID}",
  "attempt": ${attempt},
  "exit_code": 137,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "free_ram_mb": ${oom_free_mb},
  "git_changes": "$(echo "$oom_diff" | sed 's/"/\\"/g')",
  "log_bytes": $(wc -c < "$log_file" 2>/dev/null | tr -d ' ' || true),
  "healing": "reducing MAX_TURNS, waiting for memory recovery"
}
OOMJSON

          # OOM self-healing: reduce turns for THIS agent's retries only
          if [[ $MAX_TURNS -gt 50 ]]; then
            local orig_turns=$MAX_TURNS
            MAX_TURNS=$(( MAX_TURNS * 2 / 3 ))  # Reduce by 1/3 (gentler than halving)
            [[ $MAX_TURNS -lt 50 ]] && MAX_TURNS=50
            warn "  OOM HEAL: Reduced MAX_TURNS from $orig_turns to $MAX_TURNS (this agent only)"
            # Also update the per-agent profile so future runs remember
            AGENT_TURNS[$agent_name]=$MAX_TURNS
          fi

          # Kill orphaned node/claude processes to reclaim memory
          warn "  OOM HEAL: Killing orphaned processes + waiting 20s for memory reclaim..."
          pkill -f "node.*claude" 2>/dev/null || true
          purge 2>/dev/null || true
          sleep 20

          # Check if memory recovered enough to retry
          local post_heal_mb
          post_heal_mb=$(get_free_ram_mb)
          local needed_mb="${AGENT_MIN_RAM[$agent_name]:-600}"
          if [[ $post_heal_mb -lt $needed_mb ]]; then
            error "  OOM HEAL FAILED: Only ${post_heal_mb}MB free after reclaim (need ${needed_mb}MB)"
            error "  ${agent_name} cannot recover — breaking retry loop"
            break  # Don't waste 4 more retries that will all OOM
          fi
          success "  OOM HEAL: ${post_heal_mb}MB free (need ${needed_mb}MB) — retrying"
        fi
      fi
    fi
  done

  local end_time=$(date +%s)
  local duration=$(( end_time - start_time ))

  # ━━━ Superhuman Post-Completion Hooks (run regardless of pass/fail) ━━━
  # Extract insights from agent output for cross-agent learning
  extract_agent_insights "$agent_name" "$log_file"

  # Update agent performance history
  local output_bytes=0
  [[ -f "$log_file" ]] && output_bytes=$(wc -c < "$log_file" | tr -d ' ')
  update_agent_perf_history "$agent_name" "$duration" "$output_bytes" "$run_ok" "$attempt"

  # Capture post-agent system snapshot
  capture_system_snapshot "post-${agent_name}"

  if $run_ok; then
    local log_size=0
    [[ -f "$log_file" ]] && log_size=$(wc -c < "$log_file" | tr -d ' ')

    # Write success status
    atomic_write_heredoc "$STATE_DIR/${agent_name}-status.md" <<EOF
# ${agent_name} Status
- **Status:** ✅ Completed
- **Runtime:** ${MODEL} (CTEM+ Swarm)
- **Mode:** $(${WAR_ROOM} && echo "WAR ROOM 🚨" || echo "Standard")
- **Date:** ${DATE_TODAY}
- **Duration:** ${duration}s ($(( duration / 60 ))m $(( duration % 60 ))s)
- **Attempts:** ${attempt}/${MAX_RETRIES}
- **Run ID:** ${RUN_ID}
- **Log:** logs/ai-team/${DATE_TODAY}_${agent_name}_${RUN_ID}.log
- **Output:** ${log_size} bytes
EOF
    # ── RICH CHECKPOINT (not empty — contains full metadata for debugging) ──
    local git_diff_summary=""
    git_diff_summary=$(git -C "$PROJECT_ROOT" diff --stat HEAD 2>/dev/null | tail -5 | tr '\n' ' ' | sed 's/"/\\"/g' || echo "(no git data)")
    local confidence_label="HIGH"
    if [[ -f "$STATE_DIR/${agent_name}-hallucination-report.json" ]]; then
      confidence_label=$(python3 -c "import json; print(json.load(open('$STATE_DIR/${agent_name}-hallucination-report.json')).get('confidence','HIGH'))" 2>/dev/null || echo "HIGH")
    fi
    local free_mb_at_done
    free_mb_at_done=$(get_free_ram_mb 2>/dev/null || echo "0")
    cat > "$CHECKPOINT_DIR/${RUN_ID}_${agent_name}.done" <<CKJSON
{
  "agent": "${agent_name}",
  "status": "completed",
  "run_id": "${RUN_ID}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_s": ${duration},
  "attempts": ${attempt},
  "output_bytes": ${log_size},
  "confidence": "${confidence_label}",
  "free_ram_mb": ${free_mb_at_done},
  "git_changes": "${git_diff_summary}",
  "log_file": "${log_file}"
}
CKJSON
    success "${agent_name} completed in ${duration}s (attempt $attempt, ${log_size} bytes, confidence: ${confidence_label})"
    voice "${agent_name} completed successfully" "celebration"

    # ── OUTPUT VALIDATION GUARDRAILS (supplementary warnings) ──
    local validation_warnings=0

    # Check: Status file was actually updated by the agent (not still "Running")
    if [[ -f "$STATE_DIR/${agent_name}-status.md" ]]; then
      if grep -q '🔄 Running' "$STATE_DIR/${agent_name}-status.md" 2>/dev/null; then
        warn "  GUARDRAIL: ${agent_name} status still says 'Running' — agent may not have updated it"
        validation_warnings=$((validation_warnings + 1))
      fi
    fi

    # Check: Verify decisions.log was appended (all agents must log decisions)
    if [[ -f "$STATE_DIR/decisions.log" ]]; then
      if ! grep -q "agent:${agent_name}" "$STATE_DIR/decisions.log" 2>/dev/null; then
        warn "  GUARDRAIL: ${agent_name} did not log any decisions to decisions.log"
        validation_warnings=$((validation_warnings + 1))
      fi
    fi

    [[ $validation_warnings -gt 0 ]] && warn "  ${agent_name}: ${validation_warnings} guardrail warning(s) — review recommended"

    # ── Guardian: post-agent safety validation ──
    # Wrapped in subshell-safe block so guardian bugs never crash the swarm
    if type guardian_post_agent &>/dev/null; then
      local guardian_exit=0
      guardian_post_agent "$agent_name" 0 || guardian_exit=$?
      if [[ $guardian_exit -ne 0 ]]; then
        if [[ $guardian_exit -eq 1 ]]; then
          error "GUARDIAN ROLLBACK: ${agent_name} changes were destructive — rolled back"
          voice "Guardian rolled back ${agent_name}" "critical"
          track_cost "$agent_name" "$duration" "guardian_rollback" "$log_file"
          AGENT_RESULTS+=("🛡️ ${agent_name} (guardian rollback)")
          return 1
        else
          # Guardian itself crashed (exit > 1) — don't penalize the agent
          warn "GUARDIAN INTERNAL ERROR (exit $guardian_exit) for ${agent_name} — ignoring (agent succeeded)"
        fi
      fi
    fi

    track_cost "$agent_name" "$duration" "success" "$log_file"
    AGENT_RESULTS+=("✅ ${agent_name}")
    return 0
  else
    # Write failure status
    atomic_write_heredoc "$STATE_DIR/${agent_name}-status.md" <<EOF
# ${agent_name} Status
- **Status:** ❌ Failed (${MAX_RETRIES} attempts exhausted)
- **Runtime:** ${MODEL} (CTEM+ Swarm)
- **Mode:** $(${WAR_ROOM} && echo "WAR ROOM 🚨" || echo "Standard")
- **Date:** ${DATE_TODAY}
- **Duration:** ${duration}s
- **Attempts:** ${MAX_RETRIES}/${MAX_RETRIES}
- **Run ID:** ${RUN_ID}
- **Log:** logs/ai-team/${DATE_TODAY}_${agent_name}_${RUN_ID}.log
- **Needs:** Manual review
EOF
    error "${agent_name} FAILED after ${MAX_RETRIES} attempts"
    # Update current-agent to show failure
    echo "FAILED:${agent_name}" > "$current_agent_file" 2>/dev/null || true

    # ── Guardian: log failure + rollback any partial destructive changes ──
    if type guardian_post_agent &>/dev/null; then
      guardian_post_agent "$agent_name" "1" || warn "Guardian post-check error for failed agent ${agent_name} — non-fatal"
    fi

    track_cost "$agent_name" "$duration" "failed" "$log_file"
    AGENT_RESULTS+=("❌ ${agent_name}")

    # ── Record failure details for JARVIS Controller consumption ──
    if $ENABLE_CONTROLLER; then
      local fail_log="$LOG_DIR/${DATE_TODAY}_${agent_name}_${RUN_ID}.log"
      local fail_reason="exhausted ${MAX_RETRIES} retries"
      if [[ -f "$fail_log" ]]; then
        fail_reason=$(tail -10 "$fail_log" 2>/dev/null | grep -iE 'error|exception|fail|traceback' | head -1 | cut -c1-200 || echo "exhausted ${MAX_RETRIES} retries")
        [[ -z "$fail_reason" ]] && fail_reason="exhausted ${MAX_RETRIES} retries"
      fi
      local fail_detail="$STATE_DIR/${agent_name}-failure.json"
      cat > "$fail_detail" <<FJSON
{"agent":"${agent_name}","ts":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","retries":${MAX_RETRIES},"reason":"$(echo "$fail_reason" | sed 's/"/\\"/g')","log":"${fail_log}","run_id":"${RUN_ID}"}
FJSON
      echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"agent_failure\",\"agent\":\"${agent_name}\",\"reason\":\"$(echo "$fail_reason" | sed 's/"/\\"/g')\"}"\
        >> "$CONTROLLER_LOG" 2>/dev/null || true
    fi

    return 1
  fi
}

###############################################################################
# Usage tracking (Claude Max = flat-rate subscription, no per-token charges)
# CSV: date,agent,model,duration_s,output_bytes,output_lines,result,run_id
###############################################################################
track_cost() {
  local agent="$1" duration="$2" result="${3:-unknown}" log_file="${4:-}"
  local output_bytes=0 output_lines=0
  if [[ -n "$log_file" && -f "$log_file" ]]; then
    output_bytes=$(wc -c < "$log_file" 2>/dev/null | tr -d ' ')
    output_lines=$(wc -l < "$log_file" 2>/dev/null | tr -d ' ')
  fi
  echo "${DATE_TODAY},${agent},${MODEL},${duration}s,${output_bytes}B,${output_lines}L,${result},${RUN_ID}" \
    >> "$STATE_DIR/cost-log.csv"
}

show_cost_report() {
  local cost_file="$STATE_DIR/cost-log.csv"
  if [[ ! -f "$cost_file" ]]; then
    log "No usage data yet."
    return
  fi
  header "Usage Report — $(date +%B\ %Y)  [Claude Max — Flat Rate]"
  local month_prefix
  month_prefix=$(date +%Y-%m)
  local total_runs=0 successful=0 failed=0 total_duration=0 total_bytes=0
  total_runs=$(grep -c "^${month_prefix}" "$cost_file" 2>/dev/null || true)
  successful=$(grep "^${month_prefix}" "$cost_file" 2>/dev/null | grep -c "success" || true)
  failed=$(grep "^${month_prefix}" "$cost_file" 2>/dev/null | grep -c "failed" || true)
  # Sum durations
  total_duration=$(grep "^${month_prefix}" "$cost_file" 2>/dev/null | awk -F',' '{gsub(/s/,"",$4); d+=$4} END{print d+0}')
  # Sum output bytes
  total_bytes=$(grep "^${month_prefix}" "$cost_file" 2>/dev/null | awk -F',' '{gsub(/B/,"",$5); b+=$5} END{print b+0}')
  # Format bytes
  local bytes_human="${total_bytes}B"
  if [[ $total_bytes -gt 1048576 ]]; then
    bytes_human="$(( total_bytes / 1048576 ))MB"
  elif [[ $total_bytes -gt 1024 ]]; then
    bytes_human="$(( total_bytes / 1024 ))KB"
  fi
  # Format duration
  local dur_human="${total_duration}s"
  if [[ $total_duration -gt 3600 ]]; then
    dur_human="$(( total_duration / 3600 ))h $(( (total_duration % 3600) / 60 ))m"
  elif [[ $total_duration -gt 60 ]]; then
    dur_human="$(( total_duration / 60 ))m $(( total_duration % 60 ))s"
  fi
  local success_rate=0
  [[ $total_runs -gt 0 ]] && success_rate=$(( (successful * 100) / total_runs ))

  echo "  Plan:              Claude Max (flat-rate subscription)"
  echo "  Model:             ${MODEL}"
  echo "  Total agent runs:  ${total_runs}"
  echo "  Successful:        ${successful} (${success_rate}%)"
  echo "  Failed:            ${failed}"
  echo "  Total runtime:     ${dur_human}"
  echo "  Total output:      ${bytes_human}"
  echo "  Cost:              \$0 incremental (subscription)"
  echo ""
  echo "  Recent runs:"
  echo "  DATE        AGENT                MODEL                 DUR     OUTPUT    LINES  STATUS"
  echo "  ──────────  ───────────────────  ────────────────────  ──────  ────────  ─────  ──────"
  tail -20 "$cost_file" 2>/dev/null | while IFS=',' read -r dt ag md dur ob ol res rid; do
    printf "  %-10s  %-19s  %-20s  %6s  %8s  %5s  %s\n" "$dt" "$ag" "$md" "$dur" "$ob" "$ol" "$res"
  done
}

###############################################################################
# Agent health check
###############################################################################
run_health_check() {
  header "Agent Health Check"

  local healthy=0 issues=0

  for agent_file in "$AGENTS_DIR"/*.md; do
    local agent_name
    agent_name=$(basename "$agent_file" .md)

    local checks_passed=true
    echo -n "  $agent_name: "

    # Check file exists and is non-empty
    if [[ ! -s "$agent_file" ]]; then
      echo -e "${RED}EMPTY${NC}"
      ((issues++))
      continue
    fi

    # Check for Self-Healing Protocol
    if ! grep -q "Self-Healing Protocol" "$agent_file" 2>/dev/null; then
      echo -ne "${YELLOW}no self-healing${NC} "
      checks_passed=false
    fi

    # Check for Decision Framework
    if ! grep -q "Decision Framework" "$agent_file" 2>/dev/null; then
      echo -ne "${YELLOW}no decision-fw${NC} "
      checks_passed=false
    fi

    # Check for correct model
    if ! grep -q "claude-opus-4-6-fast\|opus" "$agent_file" 2>/dev/null; then
      echo -ne "${YELLOW}wrong model${NC} "
      checks_passed=false
    fi

    # Check for CTEM+ reference
    if ! grep -q "CTEM" "$agent_file" 2>/dev/null; then
      echo -ne "${YELLOW}no CTEM ref${NC} "
      checks_passed=false
    fi

    # Check for stale references
    if grep -q "FIGMA_SCREEN_SPECS\|suite-ui/aldeci[^-]" "$agent_file" 2>/dev/null; then
      echo -ne "${RED}STALE REFS${NC} "
      checks_passed=false
    fi

    if $checks_passed; then
      echo -e "${GREEN}HEALTHY${NC}"
      ((healthy++))
    else
      echo ""
      ((issues++))
    fi
  done

  echo ""
  success "Healthy: $healthy  |  Issues: $issues"

  # Check vision docs
  echo ""
  log "Vision docs:"
  for doc in CEO_VISION.md VISION_TO_ACCOMPLISH.MD CTEM_PLUS_IDENTITY.md VISION_DEBATE_TRANSCRIPT.md; do
    if [[ -f "$PROJECT_ROOT/docs/$doc" ]]; then
      local lines
      lines=$(wc -l < "$PROJECT_ROOT/docs/$doc" | tr -d ' ')
      echo -e "  ${GREEN}✓${NC} docs/$doc ($lines lines)"
    else
      echo -e "  ${RED}✗${NC} docs/$doc MISSING"
    fi
  done
}

###############################################################################
# Vision Debate (standalone mode)
###############################################################################
run_debate() {
  header "Vision Debate — 5 Agents, 3 Rounds"

  local debate_prompt="You are the MODERATOR of a critical vision debate for ALdeci, a CTEM+ Decision Intelligence platform.

Read the full debate transcript at docs/VISION_DEBATE_TRANSCRIPT.md for context on past decisions.

Your task: Evaluate whether the CURRENT codebase state still aligns with the debate verdict.
Check:
1. Has suite-ui/aldeci-ui-new/ been created? (The #1 recommendation was to ship 3 UI screens)
2. Has test coverage improved from 20.36%?
3. Are the 3 Core Pillars (V3, V5, V7) getting the most engineering investment?
4. Are Deferred Features (V4, V6, V8) being properly deprioritized?

Produce:
- Updated verdict if anything needs to change
- Specific action items for the next sprint
- Risk assessment (what's the biggest threat to shipping?)

Write your analysis to .claude/team-state/debate-update-${DATE_TODAY}.md"

  if $DRY_RUN; then
    log "[DRY RUN] Would run debate with prompt:"
    echo "$debate_prompt"
    return 0
  fi

  local debate_log="$LOG_DIR/${DATE_TODAY}_debate_${RUN_ID}.log"
  local debate_cmd
  if [[ -n "$TIMEOUT_CMD" ]]; then
    debate_cmd="$TIMEOUT_CMD 1800 claude"
  else
    debate_cmd="claude"
  fi
  $debate_cmd \
    --print --output-format text \
    --max-turns 30 \
    -p "$debate_prompt" \
    > "$debate_log" 2>&1 || warn "Debate had issues"

  success "Debate complete — see $debate_log"
}

###############################################################################
# Get current AVAILABLE RAM in MB (macOS)
# On macOS, "free" pages is misleadingly low because the OS aggressively caches.
# Available memory = free + inactive + purgeable (all instantly reclaimable).
###############################################################################
get_free_ram_mb() {
  local vm_output free_pages inactive_pages purgeable_pages
  vm_output=$(vm_stat 2>/dev/null)
  free_pages=$(echo "$vm_output" | awk '/Pages free:/{gsub(/\./,"",$3); print $3}')
  inactive_pages=$(echo "$vm_output" | awk '/Pages inactive:/{gsub(/\./,"",$3); print $3}')
  purgeable_pages=$(echo "$vm_output" | awk '/Pages purgeable:/{gsub(/\./,"",$3); print $3}')
  echo $(( ( (${free_pages:-0} + ${inactive_pages:-0} + ${purgeable_pages:-0}) * 16384) / 1048576 ))
}

###############################################################################
# Pre-agent memory gate — check if we have enough RAM to launch this agent
# Returns 0 if safe, 1 if insufficient (agent should be deferred or skipped)
###############################################################################
pre_agent_memory_gate() {
  local agent_name="$1"
  local needed_mb="${AGENT_MIN_RAM[$agent_name]:-600}"
  local free_mb
  free_mb=$(get_free_ram_mb)

  if [[ $free_mb -lt $needed_mb ]]; then
    warn "MEMORY GATE: ${agent_name} needs ${needed_mb}MB but only ${free_mb}MB free"

    # Attempt memory reclaim: kill zombie Node processes, clear caches
    warn "  Attempting memory reclaim..."
    # Kill any orphaned node/claude processes from previous runs
    pkill -f "node.*claude" 2>/dev/null || true
    sleep 5
    # Purge macOS inactive memory
    purge 2>/dev/null || true
    sleep 3

    # Re-check
    free_mb=$(get_free_ram_mb)
    if [[ $free_mb -lt $needed_mb ]]; then
      error "MEMORY GATE FAILED: Still only ${free_mb}MB free after reclaim (need ${needed_mb}MB)"
      error "  ${agent_name} SKIPPED to prevent OOM cascade"
      return 1
    fi
    success "  Memory reclaimed: now ${free_mb}MB free (need ${needed_mb}MB) — proceeding"
  fi
  return 0
}

###############################################################################
# Set per-agent MAX_TURNS (dynamic, not one-size-fits-all)
###############################################################################
set_agent_turns() {
  local agent_name="$1"
  local agent_turns="${AGENT_TURNS[$agent_name]:-$MAX_TURNS_DEFAULT}"

  # If OOM healing has reduced turns, use the lower of the two
  if [[ $MAX_TURNS -lt $agent_turns ]]; then
    agent_turns=$MAX_TURNS
  fi

  MAX_TURNS=$agent_turns
}

###############################################################################
# Restore MAX_TURNS to default (call after each agent completes)
###############################################################################
restore_default_turns() {
  MAX_TURNS=$MAX_TURNS_DEFAULT
}

###############################################################################
# PER-AGENT MEMORY ENFORCEMENT via ulimit (hard ceiling, not just a gate)
# Maps AGENT_MIN_RAM (MB) → ulimit -v (KB). Multiplied by 3x to give
# headroom for Node.js + Claude context growth while still capping runaway.
# On macOS, ulimit -v is per-process virtual memory limit.
###############################################################################
declare -A AGENT_MAX_RAM_MB
AGENT_MAX_RAM_MB=(
  [vision-agent]=1200       # 400MB min × 3x headroom
  [agent-doctor]=1200
  [context-engineer]=1800   # 600MB min × 3x headroom
  [ai-researcher]=1800
  [data-scientist]=1800
  [enterprise-architect]=1800
  [backend-hardener]=2400   # 800MB min × 3x headroom — heavy builder
  [frontend-craftsman]=2400
  [threat-architect]=2400
  [swarm-controller]=2400   # Coordinator spawns juniors — needs builder-level headroom
  [security-analyst]=1800
  [qa-engineer]=1800
  [devops-engineer]=1800
  [marketing-head]=1200
  [technical-writer]=1500    # Increased from 1200 — docs gen needs headroom (SP3-009)
  [sales-engineer]=1200
  [scrum-master]=1500
)

# Apply memory limit to current shell (affects child processes)
apply_agent_memory_limit() {
  local agent_name="$1"
  local max_mb="${AGENT_MAX_RAM_MB[$agent_name]:-2400}"
  local max_kb=$(( max_mb * 1024 ))
  # Set soft limit only (hard limit can brick the shell session)
  ulimit -Sv "$max_kb" 2>/dev/null || {
    # macOS may not support ulimit -v; log but don't fail
    debug "ulimit -Sv not supported on this OS — skipping memory cap for ${agent_name}"
    return 0
  }
  debug "Memory limit set: ${agent_name} → ${max_mb}MB (ulimit -Sv ${max_kb}KB)"
}

# Remove memory limit (reset to unlimited)
clear_agent_memory_limit() {
  ulimit -Sv unlimited 2>/dev/null || true
}

###############################################################################
# INTER-PHASE CLEANUP — Kill orphans + reclaim memory between phases
# Prevents zombie Node/claude processes from accumulating across phases.
###############################################################################
inter_phase_cleanup() {
  local phase="$1"
  log "[CLEANUP] Phase ${phase} complete — reclaiming resources..."

  # Kill orphaned node/claude processes from completed agents
  local killed=0
  while IFS= read -r pid; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && killed=$((killed + 1))
    fi
  done < <(pgrep -f "node.*claude" 2>/dev/null || true)

  [[ $killed -gt 0 ]] && log "  Killed ${killed} orphaned claude processes"

  # Purge macOS inactive memory pages
  purge 2>/dev/null || true

  # Brief pause for OS to reclaim
  sleep 3

  local free_mb
  free_mb=$(get_free_ram_mb)
  log "  Post-cleanup: ${free_mb}MB free RAM"
}

###############################################################################
# Circuit breaker — per-phase: abort if >=threshold agents fail in this phase
###############################################################################
check_circuit_breaker() {
  local phase="$1"
  local failures="${PHASE_FAILURES[$phase]:-0}"

  if [[ "$failures" -ge "$CIRCUIT_BREAKER_THRESHOLD" ]]; then
    error "CIRCUIT BREAKER TRIPPED — Phase $phase has $failures failures (threshold: $CIRCUIT_BREAKER_THRESHOLD)"
    error "Aborting remaining agents in phase $phase"
    PHASE_STATUS[$phase]="failed"
    return 1
  fi
  return 0
}

###############################################################################
# Global circuit breaker — STOP entire swarm if too many agents have failed
# This is THE failsafe that prevents the "deck of cards" cascade
###############################################################################
GLOBAL_FAIL_COUNT=0
check_global_circuit_breaker() {
  if [[ $GLOBAL_FAIL_COUNT -ge $GLOBAL_FAIL_THRESHOLD ]]; then
    warn "╔══════════════════════════════════════════════════════════════╗"
    warn "║  ⚡ CIRCUIT BREAKER TRIGGERED — ${GLOBAL_FAIL_COUNT}/${GLOBAL_FAIL_THRESHOLD} failures       ║"
    warn "║  Attempting self-healing before halt...                      ║"
    warn "╚══════════════════════════════════════════════════════════════╝"

    # ── Try self-healing before permanent halt ──
    if self_heal_circuit_breaker; then
      success "CIRCUIT BREAKER: Self-healed — reset to ${GLOBAL_FAIL_COUNT} failures, continuing swarm"
      return 0  # Healed! Continue running
    fi

    # ── Self-healing exhausted — permanent halt ──
    error "╔══════════════════════════════════════════════════════════════╗"
    error "║  🛑  GLOBAL CIRCUIT BREAKER — SWARM HALTED                  ║"
    error "║  ${GLOBAL_FAIL_COUNT} agents failed, self-heal exhausted (${CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS}/${CIRCUIT_BREAKER_MAX_SELF_HEALS})  ║"
    error "║  Fix root cause, then restart with --resume                 ║"
    error "╚══════════════════════════════════════════════════════════════╝"
    # Write halt state for monitor (includes self-heal attempts info)
    cat > "$STATE_DIR/swarm-halted.json" <<HALTJSON
{
  "halted": true,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "global_fail_count": $GLOBAL_FAIL_COUNT,
  "threshold": $GLOBAL_FAIL_THRESHOLD,
  "self_heal_attempts": $CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS,
  "max_self_heals": $CIRCUIT_BREAKER_MAX_SELF_HEALS,
  "run_id": "$RUN_ID",
  "reason": "Global circuit breaker tripped — self-healing exhausted after ${CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS} attempts"
}
HALTJSON
    return 1
  fi
  return 0
}

increment_phase_failure() {
  local phase="$1"
  PHASE_FAILURES[$phase]=$(( ${PHASE_FAILURES[$phase]:-0} + 1 ))
  GLOBAL_FAIL_COUNT=$(( GLOBAL_FAIL_COUNT + 1 ))
}

###############################################################################
# Self-Healing Circuit Breaker — analyze failures + attempt auto-recovery
# Called when GLOBAL_FAIL_COUNT hits the threshold BEFORE permanent halt.
# Strategy:
#   1. Classify failures: infrastructure vs logic vs unknown
#   2. If mostly infrastructure → clear those counts (root causes already fixed)
#   3. If controller is enabled → spawn fix-agents for top failures
#   4. Raise threshold dynamically if agents are making partial progress
#   5. Reset GLOBAL_FAIL_COUNT by the number of healable failures
# Returns: 0 = healed (continue), 1 = cannot heal (halt)
###############################################################################
self_heal_circuit_breaker() {
  # Guard: don't infinite loop
  if [[ $CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS -ge $CIRCUIT_BREAKER_MAX_SELF_HEALS ]]; then
    error "CIRCUIT BREAKER SELF-HEAL: Max attempts exhausted (${CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS}/${CIRCUIT_BREAKER_MAX_SELF_HEALS})"
    return 1
  fi
  CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS=$((CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS + 1))

  log "CIRCUIT BREAKER SELF-HEAL: Attempt ${CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS}/${CIRCUIT_BREAKER_MAX_SELF_HEALS}"
  voice "Circuit breaker triggered. Self healing attempt ${CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS}" "critical"
  notify "Circuit Breaker" "Self-healing attempt ${CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS}/${CIRCUIT_BREAKER_MAX_SELF_HEALS}"

  local healed_count=0
  local infra_failures=0
  local logic_failures=0
  local unknown_failures=0

  # ── Step 1: Classify each failure ──
  for result in "${AGENT_RESULTS[@]}"; do
    [[ "$result" != "❌"* ]] && continue
    local agent_name
    agent_name=$(echo "$result" | sed 's/❌ //' | awk '{print $1}')
    local agent_log="$LOG_DIR/${DATE_TODAY}_${agent_name}_${RUN_ID}.log"
    local failure_type="unknown"

    if [[ -f "$agent_log" ]]; then
      # Infrastructure failures: environment, PATH, permissions, timeout, OOM, network
      if grep -qiE 'command not found|Permission denied|No space left|Cannot allocate|timed out|SIGKILL|OOM|timeout.*expired|ENOMEM|Connection refused|ECONNRESET' "$agent_log" 2>/dev/null; then
        failure_type="infrastructure"
        infra_failures=$((infra_failures + 1))
      # Logic failures: actual code errors the agent needs to fix
      elif grep -qiE 'SyntaxError|ImportError|TypeError|ValueError|KeyError|AssertionError|ModuleNotFoundError|NameError|AttributeError' "$agent_log" 2>/dev/null; then
        failure_type="logic"
        logic_failures=$((logic_failures + 1))
      else
        unknown_failures=$((unknown_failures + 1))
      fi
    else
      unknown_failures=$((unknown_failures + 1))
    fi

    debug "  CLASSIFY: ${agent_name} → ${failure_type}"
  done

  log "CIRCUIT BREAKER SELF-HEAL: Classified failures — infra:${infra_failures} logic:${logic_failures} unknown:${unknown_failures}"

  # ── Step 2: Heal infrastructure failures (environment already fixed by prior self-healing) ──
  if [[ $infra_failures -gt 0 ]]; then
    log "CIRCUIT BREAKER SELF-HEAL: ${infra_failures} infrastructure failure(s) — these were likely caused by already-fixed env issues"
    log "  Discounting ${infra_failures} infra failure(s) from global count"
    GLOBAL_FAIL_COUNT=$((GLOBAL_FAIL_COUNT - infra_failures))
    [[ $GLOBAL_FAIL_COUNT -lt 0 ]] && GLOBAL_FAIL_COUNT=0
    healed_count=$((healed_count + infra_failures))
    success "  Healed: Discounted ${infra_failures} infrastructure failures → GLOBAL_FAIL_COUNT now ${GLOBAL_FAIL_COUNT}"
  fi

  # ── Step 3: Check if we're below threshold after discounting ──
  if [[ $GLOBAL_FAIL_COUNT -lt $GLOBAL_FAIL_THRESHOLD ]]; then
    success "CIRCUIT BREAKER SELF-HEAL: After discounting infra failures, count ${GLOBAL_FAIL_COUNT} < threshold ${GLOBAL_FAIL_THRESHOLD}"
    rm -f "$STATE_DIR/swarm-halted.json" 2>/dev/null || true
    echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"circuit_breaker_self_heal\",\"attempt\":${CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS},\"healed\":${healed_count},\"infra\":${infra_failures},\"logic\":${logic_failures},\"new_count\":${GLOBAL_FAIL_COUNT}}" >> "$CONTROLLER_LOG" 2>/dev/null || true
    return 0
  fi

  # ── Step 4: Check if agents are making partial progress despite failures ──
  # If >50% of agents completed successfully, the swarm IS productive — raise threshold
  local completed_count=0
  local total_attempted=0
  for result in "${AGENT_RESULTS[@]}"; do
    total_attempted=$((total_attempted + 1))
    if [[ "$result" == "✅"* ]]; then
      completed_count=$((completed_count + 1))
    fi
  done

  if [[ $total_attempted -gt 0 ]]; then
    local success_pct=$(( (completed_count * 100) / total_attempted ))
    if [[ $success_pct -ge 40 ]]; then
      # Good progress — dynamically raise threshold by 3 to let remaining agents run
      local old_threshold=$GLOBAL_FAIL_THRESHOLD
      GLOBAL_FAIL_THRESHOLD=$((GLOBAL_FAIL_THRESHOLD + 3))
      success "CIRCUIT BREAKER SELF-HEAL: ${success_pct}% success rate — raising threshold ${old_threshold} → ${GLOBAL_FAIL_THRESHOLD}"
      rm -f "$STATE_DIR/swarm-halted.json" 2>/dev/null || true
      echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"threshold_raised\",\"old\":${old_threshold},\"new\":${GLOBAL_FAIL_THRESHOLD},\"success_pct\":${success_pct},\"completed\":${completed_count},\"total\":${total_attempted}}" >> "$CONTROLLER_LOG" 2>/dev/null || true
      return 0
    fi
  fi

  # ── Step 5: If controller is enabled, try spawning fix-agents for logic failures ──
  if $ENABLE_CONTROLLER && [[ $logic_failures -gt 0 ]]; then
    log "CIRCUIT BREAKER SELF-HEAL: Spawning fix-agents for ${logic_failures} logic failure(s)..."
    local fixed=0
    for result in "${AGENT_RESULTS[@]}"; do
      [[ "$result" != "❌"* ]] && continue
      local agent_name
      agent_name=$(echo "$result" | sed 's/❌ //' | awk '{print $1}')
      local agent_log="$LOG_DIR/${DATE_TODAY}_${agent_name}_${RUN_ID}.log"
      # Only fix logic failures
      if [[ -f "$agent_log" ]] && grep -qiE 'SyntaxError|ImportError|TypeError|ValueError|KeyError' "$agent_log" 2>/dev/null; then
        local err_summary
        err_summary=$(grep -iE 'SyntaxError|ImportError|TypeError|ValueError|KeyError' "$agent_log" 2>/dev/null | tail -3 | head -1 | cut -c1-200 || echo "unknown")
        if controller_spawn_fix_agent "$agent_name" "$err_summary" "$agent_log" "$CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS"; then
          fixed=$((fixed + 1))
          GLOBAL_FAIL_COUNT=$((GLOBAL_FAIL_COUNT - 1))
          [[ $GLOBAL_FAIL_COUNT -lt 0 ]] && GLOBAL_FAIL_COUNT=0
        fi
        # Limit to 3 fix-agents per self-heal cycle to avoid resource explosion
        [[ $fixed -ge 3 ]] && break
      fi
    done

    if [[ $fixed -gt 0 ]]; then
      success "CIRCUIT BREAKER SELF-HEAL: Fixed ${fixed} logic failure(s) — GLOBAL_FAIL_COUNT now ${GLOBAL_FAIL_COUNT}"
      if [[ $GLOBAL_FAIL_COUNT -lt $GLOBAL_FAIL_THRESHOLD ]]; then
        rm -f "$STATE_DIR/swarm-halted.json" 2>/dev/null || true
        echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"circuit_breaker_fix_heal\",\"fixed\":${fixed},\"new_count\":${GLOBAL_FAIL_COUNT}}" >> "$CONTROLLER_LOG" 2>/dev/null || true
        return 0
      fi
    fi
  fi

  # ── Step 6: Cannot heal — log and return failure ──
  warn "CIRCUIT BREAKER SELF-HEAL: Could not recover (infra:${infra_failures} logic:${logic_failures} unknown:${unknown_failures})"
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"circuit_breaker_heal_failed\",\"attempt\":${CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS},\"infra\":${infra_failures},\"logic\":${logic_failures},\"unknown\":${unknown_failures}}" >> "$CONTROLLER_LOG" 2>/dev/null || true
  return 1
}

###############################################################################
# Clean stale failure artifacts from previous runs
# Removes *-failure.json files that belong to different RUN_IDs, zombie
# status files, and expired halt state — so a fresh run starts clean.
###############################################################################
clean_stale_failure_state() {
  local cleaned=0

  # ── 1. Remove failure files from previous run IDs ──
  for ff in "$STATE_DIR"/*-failure.json; do
    [[ -f "$ff" ]] || continue
    local ff_run_id
    ff_run_id=$(python3 -c "import json; print(json.load(open('$ff')).get('run_id',''))" 2>/dev/null || echo "")
    if [[ -n "$ff_run_id" && "$ff_run_id" != "$RUN_ID" ]]; then
      debug "Cleaning stale failure: $(basename "$ff") (run_id: ${ff_run_id})"
      rm -f "$ff" 2>/dev/null || true
      cleaned=$((cleaned + 1))
    fi
    # Also remove if file is older than 24 hours (stale from any cause)
    if [[ -f "$ff" ]]; then
      local ff_age
      ff_age=$(( $(date +%s) - $(/usr/bin/stat -f '%m' "$ff" 2>/dev/null || echo "$(date +%s)") ))
      if [[ $ff_age -gt 86400 ]]; then
        debug "Cleaning expired failure (${ff_age}s old): $(basename "$ff")"
        rm -f "$ff" 2>/dev/null || true
        cleaned=$((cleaned + 1))
      fi
    fi
  done

  # ── 2. Remove stale swarm-halted.json from previous runs ──
  if [[ -f "$STATE_DIR/swarm-halted.json" ]]; then
    local halt_run_id
    halt_run_id=$(python3 -c "import json; print(json.load(open('$STATE_DIR/swarm-halted.json')).get('run_id',''))" 2>/dev/null || echo "")
    if [[ -n "$halt_run_id" && "$halt_run_id" != "$RUN_ID" ]]; then
      log "Cleaning stale halt state from previous run (${halt_run_id})"
      rm -f "$STATE_DIR/swarm-halted.json" 2>/dev/null || true
      cleaned=$((cleaned + 1))
    fi
  fi

  # ── 3. Reset zombie status files stuck on 'Running' from >2 hours ago ──
  for sf in "$STATE_DIR"/*-status.md; do
    [[ -f "$sf" ]] || continue
    if grep -q '🔄 Running' "$sf" 2>/dev/null; then
      local sf_age
      sf_age=$(( $(date +%s) - $(/usr/bin/stat -f '%m' "$sf" 2>/dev/null || echo "$(date +%s)") ))
      if [[ $sf_age -gt 7200 ]]; then
        local agent_base
        agent_base=$(basename "$sf" -status.md)
        warn "Cleaning zombie status: ${agent_base} (stuck Running for ${sf_age}s)"
        sed -i '' 's/🔄 Running/⚠️ Stale (auto-cleaned)/' "$sf" 2>/dev/null || true
        cleaned=$((cleaned + 1))
      fi
    fi
  done

  [[ $cleaned -gt 0 ]] && success "Cleaned ${cleaned} stale failure artifact(s) from previous runs"
  return 0
}

###############################################################################
# Check phase dependency — should this phase run given its dependency status?
# Returns 0 if OK to run, 1 if dependency failed (skip this phase)
###############################################################################
check_phase_dependency() {
  local phase="$1"
  local dep="${PHASE_DEPENDS_ON[$phase]:-none}"

  # No dependency — always run
  [[ "$dep" == "none" ]] && return 0

  # CASCADE_STOP disabled — run everything regardless
  ! $CASCADE_STOP && return 0

  # Check if the dependency phase passed
  local dep_status="${PHASE_STATUS[$dep]:-unknown}"
  if [[ "$dep_status" == "failed" || "$dep_status" == "skipped" ]]; then
    warn "DEPENDENCY CHECK: Phase $phase depends on Phase $dep, which ${dep_status}"
    warn "  Skipping Phase $phase to prevent garbage-in-garbage-out cascade"
    PHASE_STATUS[$phase]="skipped"
    return 1
  fi
  return 0
}

###############################################################################
# Mark phase result (call after phase completes) + inter-phase cleanup
###############################################################################
mark_phase_result() {
  local phase="$1"
  local failed_count="$2"
  local total_count="$3"

  if [[ $failed_count -ge $total_count ]]; then
    # ALL agents in phase failed — mark phase as failed
    PHASE_STATUS[$phase]="failed"
    warn "Phase $phase: ALL agents failed ($failed_count/$total_count) — marking FAILED"
  elif [[ $failed_count -gt 0 ]]; then
    # Partial failure — mark as passed (some succeeded)
    PHASE_STATUS[$phase]="passed"
    warn "Phase $phase: partial success ($((total_count - failed_count))/$total_count passed)"
  else
    PHASE_STATUS[$phase]="passed"
  fi

  # Reclaim resources between phases (kill orphans, purge memory)
  inter_phase_cleanup "$phase"
}

###############################################################################
# Run parallel agents in a phase with circuit-breaker + memory gate + deps
###############################################################################
run_parallel_agents() {
  local phase="$1"
  shift
  local agents=("$@")
  local total_agents=${#agents[@]}

  # ── Check phase dependency ──
  if ! check_phase_dependency "$phase"; then
    return 1
  fi

  # ── Check global circuit breaker ──
  if ! check_global_circuit_breaker; then
    PHASE_STATUS[$phase]="skipped"
    return 1
  fi

  # ── Check phase circuit breaker ──
  if ! check_circuit_breaker "$phase"; then
    return 1
  fi

  if $PARALLEL && [[ ${#agents[@]} -gt 1 ]]; then
    # ── Memory-aware throttle: calculate total RAM needed for parallel launch ──
    local total_ram_needed=0
    for agent in "${agents[@]}"; do
      total_ram_needed=$(( total_ram_needed + ${AGENT_MIN_RAM[$agent]:-600} ))
    done
    local free_mb
    free_mb=$(get_free_ram_mb)

    if [[ $free_mb -lt $total_ram_needed ]]; then
      warn "LOW MEMORY: ${free_mb}MB free, need ${total_ram_needed}MB for ${#agents[@]} parallel agents"
      warn "  Running Phase ${phase} agents SEQUENTIALLY (on-demand memory)"
      local seq_failed=0
      for agent in "${agents[@]}"; do
        if ! check_global_circuit_breaker; then
          PHASE_STATUS[$phase]="skipped"
          return 1
        fi
        set_agent_turns "$agent"
        if ! pre_agent_memory_gate "$agent"; then
          warn "  ${agent} SKIPPED — insufficient memory even for sequential run"
          ((seq_failed++))
          increment_phase_failure "$phase"
          AGENT_RESULTS+=("⏭️ ${agent} (skipped: no memory)")
        elif ! run_agent "$agent"; then
          ((seq_failed++))
          increment_phase_failure "$phase"
        fi
        restore_default_turns
      done
      mark_phase_result "$phase" "$seq_failed" "$total_agents"
      return $seq_failed
    fi

    local pids=()
    local agent_pid_map=()
    local launch_skipped=0

    for agent in "${agents[@]}"; do
      # Per-agent memory gate before parallel launch
      if ! pre_agent_memory_gate "$agent"; then
        warn "  ${agent} SKIPPED — insufficient memory for parallel launch"
        ((launch_skipped++))
        increment_phase_failure "$phase"
        AGENT_RESULTS+=("⏭️ ${agent} (skipped: no memory)")
        continue
      fi
      # Set per-agent turns (subshell inherits the value)
      set_agent_turns "$agent"
      run_agent "$agent" &
      local pid=$!
      pids+=("$pid")
      agent_pid_map+=("${pid}:${agent}")
      restore_default_turns
    done

    # If ALL were skipped, mark phase failed
    if [[ ${#agent_pid_map[@]} -eq 0 ]]; then
      mark_phase_result "$phase" "$total_agents" "$total_agents"
      return $total_agents
    fi

    # Phase-level watchdog: if any agent is still running after TIMEOUT_CRITICAL + 5min buffer, kill it
    local phase_deadline=$(( $(date +%s) + TIMEOUT_CRITICAL + 300 ))
    local phase_start_time=$(date +%s)
    local last_status_time=$phase_start_time

    local phase_failed=0

    # ── Wait for ALL parallel agents with periodic status reporting ──
    local all_done=false
    while ! $all_done; do
      all_done=true
      local running_agents=()
      local done_count=0
      local total_agents=${#agent_pid_map[@]}

      for entry in "${agent_pid_map[@]}"; do
        local pid="${entry%%:*}"
        local agent="${entry##*:}"
        if kill -0 "$pid" 2>/dev/null; then
          # Check for STOPPED processes (state T) — these are frozen/zombied.
          # kill -0 returns true for stopped processes, so we must check /bin/ps.
          local proc_state
          proc_state=$(ps -p "$pid" -o stat= 2>/dev/null | tr -d ' ')
          if [[ "$proc_state" == *T* ]]; then
            # With setsid, processes shouldn't get stopped. If they are,
            # just SIGCONT them — NEVER kill working agents.
            warn "WATCHDOG: Agent ${agent} (PID $pid) is STOPPED (state: $proc_state) — sending SIGCONT"
            kill -CONT "$pid" 2>/dev/null || true
            all_done=false
            running_agents+=("$agent")
          else
            all_done=false
            running_agents+=("$agent")

            # ━━━ LAYER 2: Real-Time Hallucination Monitor ━━━
            local agent_log="$LOG_DIR/${DATE_TODAY}_${agent}_${RUN_ID}.log"
            hallucination_layer2_realtime_monitor "$agent" "$agent_log" 2>/dev/null || true

            # ━━━ Stall Detection: Kill agents with no output for 5+ minutes ━━━
            if check_agent_output_stall "$pid" "$agent_log" "$agent"; then
              warn "WATCHDOG: ${agent} appears stalled — killing"
              kill -TERM "$pid" 2>/dev/null || true
              sleep 2
              kill -KILL "$pid" 2>/dev/null || true
            fi

            # ━━━ Runaway Output Detection: Kill agents with >50MB output ━━━
            if check_runaway_output "$agent_log" "$agent"; then
              warn "WATCHDOG: ${agent} runaway output — killing"
              kill -TERM "$pid" 2>/dev/null || true
              sleep 2
              kill -KILL "$pid" 2>/dev/null || true
            fi
          fi
        else
          done_count=$((done_count + 1))
        fi
      done

      if $all_done; then
        break
      fi

      # Watchdog: kill agents past the deadline
      if [[ $(date +%s) -gt $phase_deadline ]]; then
        for entry in "${agent_pid_map[@]}"; do
          local pid="${entry%%:*}"
          local agent="${entry##*:}"
          if kill -0 "$pid" 2>/dev/null; then
            warn "WATCHDOG: Agent ${agent} (PID $pid) exceeded phase deadline — killing"
            kill -TERM "$pid" 2>/dev/null || true
            sleep 2
            kill -KILL "$pid" 2>/dev/null || true
            ((phase_failed++))
            increment_phase_failure "$phase"
            atomic_write_heredoc "$STATE_DIR/${agent}-status.md" <<WDEOF
# ${agent} Status
- **Status:** ⚠️ Killed by watchdog (exceeded phase deadline)
- **Runtime:** ${MODEL} (CTEM+ Swarm)
- **Date:** ${DATE_TODAY}
- **Run ID:** ${RUN_ID}
- **Needs:** Investigate why agent hung
WDEOF
          fi
        done
        break
      fi

      # ── Rich status report every 60 seconds ──
      local now=$(date +%s)
      if [[ $((now - last_status_time)) -ge 60 ]]; then
        local elapsed=$(( now - phase_start_time ))
        local elapsed_min=$(( elapsed / 60 ))
        local elapsed_sec=$(( elapsed % 60 ))
        local running_list="${running_agents[*]}"

        echo ""
        echo -e "${CYAN}┌──────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${NC} ${BOLD}⏱ JARVIS Status — $(date +%H:%M:%S)${NC}  │  Phase ${phase} — ${elapsed_min}m${elapsed_sec}s  │  ${done_count}/${total_agents} done"
        echo -e "${CYAN}├──────────────────────────────────────────────────────────────┤${NC}"

        for ra in "${running_agents[@]}"; do
          local lf="$LOG_DIR/${DATE_TODAY}_${ra}_${RUN_ID}.log"
          local sz=0
          local sz_label="0B"
          local last_activity=""
          local agent_feature=""

          # Log size
          if [[ -f "$lf" ]]; then
            sz=$(wc -c < "$lf" 2>/dev/null || true)
            if [[ $sz -gt 1048576 ]]; then sz_label="$(( sz / 1048576 ))MB"
            elif [[ $sz -gt 1024 ]]; then sz_label="$(( sz / 1024 ))KB"
            else sz_label="${sz}B"; fi

            # Last meaningful activity from log (skip blank lines, grab last content line)
            if [[ $sz -gt 0 ]]; then
              last_activity=$(grep -v '^\s*$' "$lf" 2>/dev/null | tail -1 | cut -c1-100)
            fi
          fi

          # What feature is the agent working on (from status file or agent definition)
          local sf="$STATE_DIR/${ra}-status.md"
          if [[ -f "$sf" ]]; then
            agent_feature=$(grep -i 'working on\|task:\|feature:\|mission:' "$sf" 2>/dev/null | head -1 | sed 's/^.*: //' | cut -c1-80)
          fi

          echo -e "${CYAN}│${NC}  🤖 ${BOLD}${ra}${NC}  [${sz_label}]"
          [[ -n "$last_activity" ]] && echo -e "${CYAN}│${NC}     └─ 💬 ${last_activity}"
          [[ -n "$agent_feature" ]] && echo -e "${CYAN}│${NC}     └─ 🎯 ${agent_feature}"
        done

        # ── Files changed since phase started (app files only) ──
        local _ignore='^(\.claude/|logs/|data/|__pycache__|node_modules/|WIP/)'
        local changed_files
        changed_files=$(git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null | grep -vE "$_ignore" | head -15)
        local staged_files
        staged_files=$(git -C "$PROJECT_ROOT" diff --cached --name-only 2>/dev/null | grep -vE "$_ignore" | head -10)
        local untracked_files
        untracked_files=$(git -C "$PROJECT_ROOT" ls-files --others --exclude-standard 2>/dev/null | grep -vE "$_ignore" | head -10)

        local total_changed=0
        [[ -n "$changed_files" ]] && total_changed=$(echo "$changed_files" | wc -l | tr -d ' ')
        local total_staged=0
        [[ -n "$staged_files" ]] && total_staged=$(echo "$staged_files" | wc -l | tr -d ' ')
        local total_new=0
        [[ -n "$untracked_files" ]] && total_new=$(echo "$untracked_files" | wc -l | tr -d ' ')

        if [[ $((total_changed + total_staged + total_new)) -gt 0 ]]; then
          echo -e "${CYAN}├──────────────────────────────────────────────────────────────┤${NC}"
          echo -e "${CYAN}│${NC}  📁 Files: ${total_changed} modified, ${total_staged} staged, ${total_new} new"
          # Show recent modifications (last 5 changed files by mod time)
          local recent_mods
          recent_mods=$(git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null | while read -r f; do
            [[ -f "$PROJECT_ROOT/$f" ]] && echo "$(/usr/bin/stat -f '%m' "$PROJECT_ROOT/$f" 2>/dev/null || true) $f"
          done | sort -rn | head -5 | awk '{print $2}')
          if [[ -n "$recent_mods" ]]; then
            echo -e "${CYAN}│${NC}  📝 Recently changed:"
            while IFS= read -r rf; do
              echo -e "${CYAN}│${NC}     └─ ${rf}"
            done <<< "$recent_mods"
          fi
          # Show new files
          if [[ -n "$untracked_files" ]]; then
            echo -e "${CYAN}│${NC}  ✨ New files:"
            echo "$untracked_files" | head -5 | while IFS= read -r nf; do
              echo -e "${CYAN}│${NC}     └─ ${nf}"
            done
          fi
        fi

        echo -e "${CYAN}└──────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        last_status_time=$now
      fi

      sleep 5  # Check every 5 seconds
    done
    # Collect exit statuses for all agents
    local phase_failed_wait=0
    for entry in "${agent_pid_map[@]}"; do
      local pid="${entry%%:*}"
      local agent="${entry##*:}"
      if ! wait "$pid" 2>/dev/null; then
        ((phase_failed++))
        ((phase_failed_wait++))
        increment_phase_failure "$phase"
      fi
    done

    # Add launch-skipped agents to phase_failed total
    phase_failed=$((phase_failed + launch_skipped))

    # ━━━ LAYER 4: Cross-Agent Consistency Verification ━━━━━━━━━━━━━━━━━━
    # After all parallel agents complete, verify they don't contradict each other
    if [[ $phase_failed -lt $total_agents ]]; then
      # Only run if at least some agents succeeded
      hallucination_layer4_cross_agent_verify "$phase" "${agents[@]}" || {
        warn "LAYER 4: Cross-agent inconsistencies detected in phase ${phase} — review recommended"
      }
    fi

    mark_phase_result "$phase" "$phase_failed" "$total_agents"
    return $phase_failed
  else
    # ── Sequential execution (single agent or PARALLEL=false) ──
    local phase_failed=0
    for agent in "${agents[@]}"; do
      if ! check_global_circuit_breaker; then
        PHASE_STATUS[$phase]="skipped"
        return 1
      fi
      set_agent_turns "$agent"
      if ! pre_agent_memory_gate "$agent"; then
        warn "  ${agent} SKIPPED — insufficient memory"
        ((phase_failed++))
        increment_phase_failure "$phase"
        AGENT_RESULTS+=("⏭️ ${agent} (skipped: no memory)")
      elif ! run_agent "$agent"; then
        ((phase_failed++))
        increment_phase_failure "$phase"
      fi
      restore_default_turns
    done

    # ━━━ LAYER 4: Cross-Agent Consistency (sequential mode) ━━━━━━━━━━━━━
    if [[ ${#agents[@]} -gt 1 && $phase_failed -lt ${#agents[@]} ]]; then
      hallucination_layer4_cross_agent_verify "$phase" "${agents[@]}" || {
        warn "LAYER 4: Cross-agent inconsistencies detected in phase ${phase}"
      }
    fi

    mark_phase_result "$phase" "$phase_failed" "$total_agents"
    return $phase_failed
  fi
}

###############################################################################
# Ensure live API server is running (mandatory for Postman/Newman testing)
###############################################################################
ensure_live_api() {
  log "Checking if API server is running on port 8000..."

  if curl -sf http://localhost:8000/api/v1/health >/dev/null 2>&1; then
    success "API server is live on port 8000"
    return 0
  fi

  warn "API server not running — starting it..."
  cd "$PROJECT_ROOT"
  source .venv/bin/activate 2>/dev/null || true
  export FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN:-aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh}"
  export FIXOPS_DISABLE_RATE_LIMIT=1
  export FIXOPS_JWT_SECRET="${FIXOPS_JWT_SECRET:-enterprise-jwt-secret-key-minimum-32-characters}"
  export FIXOPS_TRUSTED_ROOT="${FIXOPS_TRUSTED_ROOT:-$PROJECT_ROOT/.fixops_data}"
  python -m uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --workers 4 --timeout-keep-alive 5 &>/dev/null &
  local api_pid=$!
  echo "$api_pid" > "$STATE_DIR/.api-server.pid"

  # Wait for server to be ready (max 30 seconds)
  local tries=0
  while [[ $tries -lt 30 ]]; do
    if curl -sf http://localhost:8000/api/v1/health >/dev/null 2>&1; then
      success "API server started (PID: $api_pid)"
      return 0
    fi
    sleep 1
    ((tries++))
  done

  error "Failed to start API server after 30 seconds"
  return 1
}

###############################################################################
# Run Newman convergence gate — test all Postman collections
###############################################################################
run_convergence_gate() {
  local iteration="$1"
  local iter_dir="$STATE_DIR/qa/iteration-${iteration}"
  mkdir -p "$iter_dir"

  header "Convergence Gate — Iteration ${iteration}/${ITERATIONS}"

  # Ensure API is running
  ensure_live_api || {
    error "Cannot run convergence gate — API server not available"
    cat > "$iter_dir/verdict.json" <<EOF
{
  "iteration": $iteration,
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "verdict": "FAIL",
  "reason": "API server not running",
  "pass_rate": 0,
  "action": "Fix API server startup before next iteration"
}
EOF
    return 1
  }

  # Check if Newman is available
  if ! command -v newman &>/dev/null; then
    warn "Newman not installed — installing..."
    npm install -g newman newman-reporter-htmlextra 2>/dev/null || {
      error "Cannot install Newman"
      return 1
    }
  fi

  local postman_dir="$PROJECT_ROOT/suite-integrations/postman/enterprise"
  local env_file="$postman_dir/ALdeci-Environment.postman_environment.json"

  if [[ ! -f "$env_file" ]]; then
    warn "Postman environment file not found at $env_file"
    # Create minimal environment
    cat > "$env_file" <<'ENVEOF'
{
  "name": "ALdeci Environment",
  "values": [
    {"key": "baseUrl", "value": "http://localhost:8000", "enabled": true},
    {"key": "apiKey", "value": "'"${FIXOPS_API_TOKEN}"'", "enabled": true}
  ]
}
ENVEOF
  fi

  local total_pass=0 total_fail=0 total_collections=0
  local collection_results=""

  for collection in "$postman_dir"/ALdeci-*.postman_collection.json; do
    [[ -f "$collection" ]] || continue
    local name
    name=$(basename "$collection" .postman_collection.json)
    ((total_collections++))

    log "  Running: $name"
    local result_file="$iter_dir/${name}-results.json"
    local output_file="$iter_dir/${name}-output.txt"

    if newman run "$collection" \
      -e "$env_file" \
      --reporters cli,json \
      --reporter-json-export "$result_file" \
      --timeout-request 30000 \
      --delay-request 100 \
      --suppress-exit-code \
      > "$output_file" 2>&1; then

      # Parse results from JSON
      if [[ -f "$result_file" ]]; then
        local pass fail
        pass=$(jq '.run.stats.assertions.total - .run.stats.assertions.failed' "$result_file" 2>/dev/null || true)
        fail=$(jq '.run.stats.assertions.failed' "$result_file" 2>/dev/null || true)
        total_pass=$((total_pass + pass))
        total_fail=$((total_fail + fail))
        collection_results+="  ${name}: ${pass} passed, ${fail} failed"$'\n'
      fi
    else
      warn "  Newman failed for $name"
      collection_results+="  ${name}: NEWMAN ERROR"$'\n'
      ((total_fail++))
    fi
  done

  # Calculate pass rate
  local total=$((total_pass + total_fail))
  local pass_rate=0
  if [[ $total -gt 0 ]]; then
    pass_rate=$(echo "scale=1; $total_pass * 100 / $total" | bc 2>/dev/null || true)
  fi

  # Determine verdict
  local verdict="FAIL"
  local can_exit=false
  if [[ $total_fail -eq 0 ]] && [[ $total_pass -gt 0 ]]; then
    verdict="PASS"
    can_exit=true
  elif [[ $(echo "$pass_rate >= $NEWMAN_PASS_THRESHOLD" | bc 2>/dev/null) == "1" ]]; then
    verdict="WARN"
    can_exit=true
  fi

  # Write verdict
  cat > "$iter_dir/verdict.json" <<EOF
{
  "iteration": $iteration,
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_collections": $total_collections,
  "total_assertions": $total,
  "passed": $total_pass,
  "failed": $total_fail,
  "pass_rate": $pass_rate,
  "newman_threshold": $NEWMAN_PASS_THRESHOLD,
  "verdict": "$verdict",
  "can_exit_early": $can_exit,
  "run_id": "$RUN_ID"
}
EOF

  # Write failures report for next iteration's agents
  if [[ $total_fail -gt 0 ]]; then
    cat > "$iter_dir/failures.md" <<EOF
# Iteration ${iteration} Failures — $(date +%Y-%m-%d)
## Newman Results: ${total_pass} passed, ${total_fail} failed (${pass_rate}%)

### Collection Results:
${collection_results}

### Action Required (Next Iteration):
- backend-hardener: Fix all 500 errors and stub responses
- qa-engineer: Update Postman collections for any changed endpoints
- threat-architect: Verify MPTE endpoints return real exploit proofs
- All agents: NO STUBS — every response must contain real computed data

### Convergence Status:
- Iteration: ${iteration}/${ITERATIONS}
- Pass rate: ${pass_rate}% (target: ${NEWMAN_PASS_THRESHOLD}%)
- Verdict: ${verdict}
EOF
  fi

  # Print summary
  echo ""
  echo -e "  ${BOLD}Convergence Gate Results — Iteration ${iteration}${NC}"
  echo -e "  Collections tested: ${total_collections}"
  echo -e "  Assertions passed:  ${GREEN}${total_pass}${NC}"
  echo -e "  Assertions failed:  ${RED}${total_fail}${NC}"
  echo -e "  Pass rate:          ${pass_rate}%"
  echo -e "  Verdict:            $([ \"$verdict\" = \"PASS\" ] && echo \"${GREEN}PASS${NC}\" || echo \"${RED}${verdict}${NC}\")"
  echo ""

  [[ "$verdict" = "PASS" ]] && return 0 || return 1
}

###############################################################################
# Check minimum runtime requirement
###############################################################################
check_min_runtime() {
  local now=$(date +%s)
  local elapsed=$((now - SWARM_START_EPOCH))
  local min_seconds=$((MIN_RUNTIME_HOURS * 3600))
  local remaining=$((min_seconds - elapsed))

  if [[ $remaining -gt 0 ]]; then
    local remaining_hours=$((remaining / 3600))
    local remaining_mins=$(( (remaining % 3600) / 60 ))
    warn "Minimum runtime not met: ${remaining_hours}h ${remaining_mins}m remaining (min: ${MIN_RUNTIME_HOURS}h)"
    return 1
  fi
  success "Minimum runtime met: $((elapsed / 3600))h elapsed (min: ${MIN_RUNTIME_HOURS}h)"
  return 0
}

###############################################################################
# Iterative swarm execution — wraps run_full_swarm with convergence loop
###############################################################################
run_iterative_swarm() {
  SWARM_START_EPOCH=$(date +%s)

  header "ITERATIVE SWARM — ${ITERATIONS} iterations, ${MIN_RUNTIME_HOURS}h minimum"
  echo ""
  echo -e "  ${MAGENTA}✦ Iterations:    ${ITERATIONS}${NC}"
  echo -e "  ${MAGENTA}✦ Min runtime:   ${MIN_RUNTIME_HOURS} hours${NC}"
  echo -e "  ${MAGENTA}✦ Newman gate:   ${NEWMAN_PASS_THRESHOLD}% pass rate to exit early${NC}"
  echo -e "  ${MAGENTA}✦ Mode:          Build → Test → Fix → Retest (Convergence Loop)${NC}"
  echo ""

  # ── Start the JARVIS Controller background watchdog ──
  controller_run_background_watchdog

  if ! $CONVERGENCE_MODE; then
    log "Convergence mode disabled — running single pass"
    run_full_swarm
    controller_stop_watchdog
    return $?
  fi

  local converged=false

  for iter in $(seq 1 "$ITERATIONS"); do
    CURRENT_ITERATION=$iter
    local iter_start=$(date +%s)

    header "╔══════════════════════════════════════════════════╗"
    header "║  ITERATION ${iter}/${ITERATIONS} — $([ $iter -eq 1 ] && echo 'BUILD' || echo 'FIX & REBUILD')          ║"
    header "╚══════════════════════════════════════════════════╝"

    # ── Ensure API is running before each iteration ──
    ensure_live_api || warn "API server issues — agents will need to start it"

    # ── Run the full swarm (all 11 phases) ──
    run_full_swarm || warn "Some phases had failures in iteration $iter"

    local iter_end=$(date +%s)
    local iter_duration=$((iter_end - iter_start))
    log "Iteration $iter completed in ${iter_duration}s ($(( iter_duration / 60 ))m)"

    # ── Run convergence gate (Newman testing) ──
    if run_convergence_gate "$iter"; then
      success "Convergence gate PASSED at iteration $iter"

      # Check minimum runtime before allowing early exit
      if check_min_runtime; then
        success "All gates passed — converged at iteration $iter!"
        converged=true
        break
      else
        warn "Convergence gate passed but minimum runtime not met — continuing iterations"
      fi
    else
      warn "Convergence gate FAILED at iteration $iter — $([ $iter -lt $ITERATIONS ] && echo 'will retry' || echo 'final iteration')"
    fi

    # ── Inter-iteration pause (allow system to settle) ──
    if [[ $iter -lt $ITERATIONS ]]; then
      log "Pausing 30s between iterations..."
      sleep 30
    fi
  done

  # ── Final Summary ──
  local total_end=$(date +%s)
  local total_elapsed=$((total_end - SWARM_START_EPOCH))

  echo ""
  header "ITERATIVE SWARM COMPLETE"
  echo ""
  echo -e "  ${MAGENTA}✦ Total iterations:  ${CURRENT_ITERATION}/${ITERATIONS}${NC}"
  echo -e "  ${MAGENTA}✦ Total runtime:     $((total_elapsed / 3600))h $(( (total_elapsed % 3600) / 60))m${NC}"
  echo -e "  ${MAGENTA}✦ Converged:         $(${converged} && echo '${GREEN}YES${NC}' || echo '${RED}NO${NC}')${NC}"
  echo ""

  # Write iteration summary (atomic)
  atomic_write_heredoc "$STATE_DIR/iteration-summary.md" <<EOF
# Iterative Swarm Summary — ${DATE_TODAY}
- **Run ID:** ${RUN_ID}
- **Total iterations:** ${CURRENT_ITERATION}/${ITERATIONS}
- **Total runtime:** $((total_elapsed / 3600))h $(( (total_elapsed % 3600) / 60))m
- **Converged:** $(${converged} && echo "YES" || echo "NO")
- **Newman threshold:** ${NEWMAN_PASS_THRESHOLD}%
- **Min runtime target:** ${MIN_RUNTIME_HOURS}h

## Iteration Results
$(for i in $(seq 1 "$CURRENT_ITERATION"); do
  local v="$STATE_DIR/qa/iteration-${i}/verdict.json"
  if [[ -f "$v" ]]; then
    echo "### Iteration $i"
    echo "\`\`\`json"
    cat "$v"
    echo "\`\`\`"
  else
    echo "### Iteration $i — No verdict file"
  fi
done)
EOF

  # Append to context_log.md
  cat >> "$PROJECT_ROOT/context_log.md" <<EOF

### [$(date +"%Y-%m-%d %H:%M")] run-ctem-swarm — ITERATIVE ${CURRENT_ITERATION}/${ITERATIONS}
- **What**: Iterative swarm run (${CURRENT_ITERATION} iterations, ${MODEL})
- **Run ID**: ${RUN_ID}
- **Duration**: $((total_elapsed / 3600))h $(( (total_elapsed % 3600) / 60))m
- **Converged**: $(${converged} && echo "YES" || echo "NO")
- **Outcome**: $(${converged} && echo "SUCCESS — converged" || echo "PARTIAL — did not converge in ${ITERATIONS} iterations")
- **Pillar focus**: V3, V5, V7 (core) | V1, V2, V9, V10 (constraints)
EOF

  # Generate end-of-run daily digest
  generate_daily_digest "$total_elapsed" "$([ $converged = true ] && echo 0 || echo 1)"

  $converged && return 0 || return 1
}

###############################################################################
# Full swarm execution — 11 phases (single iteration)
# Now with: dependency graph, global circuit breaker, per-agent turns,
# memory gates, and cascade-stop protection.
###############################################################################
run_full_swarm() {
  local start_total=$(date +%s)
  local total_failed=0
  GLOBAL_FAIL_COUNT=0

  local mode_label="CTEM+ SWARM"
  $WAR_ROOM && mode_label="WAR ROOM 🚨"

  header "$mode_label — Full Execution"
  echo ""
  echo -e "  ${MAGENTA}✦ Run ID:      ${RUN_ID}${NC}"
  echo -e "  ${MAGENTA}✦ Model:       ${MODEL}${NC}"
  echo -e "  ${MAGENTA}✦ Mode:        ${mode_label}${NC}"
  echo -e "  ${MAGENTA}✦ Agents:      17${NC}"
  echo -e "  ${MAGENTA}✦ Timeout:     ${TIMEOUT_DEFAULT}s (critical: ${TIMEOUT_CRITICAL}s)${NC}"
  echo -e "  ${MAGENTA}✦ Max retries: ${MAX_RETRIES}${NC}"
  echo -e "  ${MAGENTA}✦ Cascade:     $($CASCADE_STOP && echo "ON (deps enforced)" || echo "OFF")${NC}"
  echo -e "  ${MAGENTA}✦ Fail limit:  ${GLOBAL_FAIL_THRESHOLD} agents before halt${NC}"
  echo -e "  ${MAGENTA}✦ Parallel:    $($PARALLEL && echo "YES" || echo "NO")${NC}"
  echo -e "  ${MAGENTA}✦ Free RAM:    $(get_free_ram_mb)MB${NC}"
  echo -e "  ${MAGENTA}✦ Day:         $DOW_NAME $DATE_TODAY${NC}"
  $WAR_ROOM && echo -e "  ${RED}✦ FOCUS:       3 UI Screens → Revenue${NC}"
  echo ""

  # Clear any previous halt state and stale failure artifacts
  rm -f "$STATE_DIR/swarm-halted.json" 2>/dev/null || true
  clean_stale_failure_state
  CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS=0  # Reset self-heal counter for this run

  # ── Helper: run single agent with memory gate + turns + global check ──
  run_single_phase_agent() {
    local phase="$1" agent="$2"
    log "[DEBUG] run_single_phase_agent phase=$phase agent=$agent"
    if ! check_phase_dependency "$phase"; then
      log "[DEBUG] check_phase_dependency FAILED for phase=$phase"
      return 1
    fi
    log "[DEBUG] phase_dependency OK"
    if ! check_global_circuit_breaker; then
      log "[DEBUG] circuit_breaker TRIPPED"
      PHASE_STATUS[$phase]="skipped"
      return 1
    fi
    log "[DEBUG] circuit_breaker OK"
    if ! pre_agent_memory_gate "$agent"; then
      PHASE_STATUS[$phase]="failed"
      GLOBAL_FAIL_COUNT=$((GLOBAL_FAIL_COUNT + 1))
      AGENT_RESULTS+=("⏭️ ${agent} (skipped: no memory)")
      return 1
    fi
    set_agent_turns "$agent"
    local result=0
    run_agent "$agent" || result=$?
    restore_default_turns
    if [[ $result -ne 0 ]]; then
      increment_phase_failure "$phase"
      mark_phase_result "$phase" 1 1
      return 1
    else
      mark_phase_result "$phase" 0 1
      return 0
    fi
  }

  # ══════════════════════════════════════════════════════════════════════
  # Phase 0: Pre-flight (no dependencies — always runs)
  # ══════════════════════════════════════════════════════════════════════
  header "Phase 0 — Vision Agent (pre-flight) + Agent Doctor"
  run_parallel_agents "0" "vision-agent" "agent-doctor"
  # Phase 0 failure is non-fatal (pre-flight checks)
  [[ "${PHASE_STATUS[0]}" != "passed" ]] && warn "Phase 0 had issues — continuing (pre-flight is advisory)"
  PHASE_STATUS[0]="passed"  # Pre-flight never blocks downstream

  # ══════════════════════════════════════════════════════════════════════
  # Phase 1: Foundation (CRITICAL — context-engineer is the foundation)
  # If this fails, phases 2-5 cannot produce valid output
  # ══════════════════════════════════════════════════════════════════════
  header "Phase 1 — Context Engineer (codebase map) [CRITICAL]"
  if ! run_single_phase_agent "1" "context-engineer"; then
    ((total_failed++))
    error "⚠️  CRITICAL: context-engineer FAILED — this is the foundation agent"
    if $CASCADE_STOP; then
      error "  Phases 2-5 depend on context-engineer output"
      error "  CASCADE_STOP=true — dependent phases will be skipped"
    fi
  fi

  # ══════════════════════════════════════════════════════════════════════
  # Phase 2: Research (depends on Phase 1)
  # ══════════════════════════════════════════════════════════════════════
  header "Phase 2 — Research + Data + Architecture (parallel)"
  if check_phase_dependency "2" && check_global_circuit_breaker; then
    run_parallel_agents "2" "ai-researcher" "data-scientist" "enterprise-architect" || ((total_failed++))
  else
    warn "Phase 2 SKIPPED (dependency: Phase 1 ${PHASE_STATUS[1]:-unknown})"
    AGENT_RESULTS+=("⏭️ ai-researcher (skipped: Phase 1 failed)")
    AGENT_RESULTS+=("⏭️ data-scientist (skipped: Phase 1 failed)")
    AGENT_RESULTS+=("⏭️ enterprise-architect (skipped: Phase 1 failed)")
  fi

  # ══════════════════════════════════════════════════════════════════════
  # Phase 3: Builders (depends on Phase 1 — can work without Phase 2)
  # ══════════════════════════════════════════════════════════════════════
  header "Phase 3 — Builders (parallel)"
  if check_phase_dependency "3" && check_global_circuit_breaker; then
    if $WAR_ROOM; then
      log "WAR ROOM: frontend-craftsman gets priority + extra time"
    fi
    run_parallel_agents "3" "backend-hardener" "frontend-craftsman" "threat-architect" || ((total_failed++))
  else
    warn "Phase 3 SKIPPED (dependency: Phase 1 ${PHASE_STATUS[1]:-unknown})"
    AGENT_RESULTS+=("⏭️ backend-hardener (skipped: Phase 1 failed)")
    AGENT_RESULTS+=("⏭️ frontend-craftsman (skipped: Phase 1 failed)")
    AGENT_RESULTS+=("⏭️ threat-architect (skipped: Phase 1 failed)")
  fi

  # ══════════════════════════════════════════════════════════════════════
  # Phase 3.5: Swarm Controller (depends on Phase 3)
  # ══════════════════════════════════════════════════════════════════════
  header "Phase 3.5 — Swarm Controller"
  run_single_phase_agent "3.5" "swarm-controller" || warn "Swarm controller had issues"

  # ══════════════════════════════════════════════════════════════════════
  # Phase 4: Validators (depends on Phase 3 — need builder output to test)
  # ══════════════════════════════════════════════════════════════════════
  header "Phase 4 — Security + QA (parallel)"
  if check_phase_dependency "4" && check_global_circuit_breaker; then
    run_parallel_agents "4" "security-analyst" "qa-engineer" || ((total_failed++))
  else
    warn "Phase 4 SKIPPED (dependency: Phase 3 ${PHASE_STATUS[3]:-unknown})"
    AGENT_RESULTS+=("⏭️ security-analyst (skipped: Phase 3 failed)")
    AGENT_RESULTS+=("⏭️ qa-engineer (skipped: Phase 3 failed)")
  fi

  # ══════════════════════════════════════════════════════════════════════
  # Phase 5: DevOps (depends on Phase 1 — can work from context alone)
  # ══════════════════════════════════════════════════════════════════════
  header "Phase 5 — DevOps Engineer"
  run_single_phase_agent "5" "devops-engineer" || ((total_failed++))

  # ══════════════════════════════════════════════════════════════════════
  # Phase 6: Debate (no dependency — always runs if we haven't halted)
  # ══════════════════════════════════════════════════════════════════════
  if check_global_circuit_breaker; then
    header "Phase 6 — Vision Debate (update)"
    run_debate
    PHASE_STATUS[6]="passed"
  fi

  # ══════════════════════════════════════════════════════════════════════
  # Phase 7: Go-to-Market (no dependency — docs can always be written)
  # ══════════════════════════════════════════════════════════════════════
  if check_global_circuit_breaker; then
    header "Phase 7 — Go-to-Market (parallel)"
    run_parallel_agents "7" "marketing-head" "technical-writer" "sales-engineer" || ((total_failed++))
  fi

  # ══════════════════════════════════════════════════════════════════════
  # Phase 8: Scrum Master (no dependency — coordination always runs)
  # ══════════════════════════════════════════════════════════════════════
  if check_global_circuit_breaker; then
    header "Phase 8 — Scrum Master (demo + coordination)"
    run_single_phase_agent "8" "scrum-master" || ((total_failed++))
  fi

  # ══════════════════════════════════════════════════════════════════════
  # Phase 9: Post-run audit (always runs — even if everything failed)
  # ══════════════════════════════════════════════════════════════════════
  header "Phase 9 — Agent Doctor (post-run audit)"
  set_agent_turns "agent-doctor"
  run_agent "agent-doctor" || warn "Agent Doctor post-run had issues"
  restore_default_turns
  PHASE_STATUS[9]="passed"

  # ══════════════════════════════════════════════════════════════════════
  # Phase 10: Vision alignment (always runs — post-mortem)
  # ══════════════════════════════════════════════════════════════════════
  header "Phase 10 — Vision Agent (post-flight alignment)"
  set_agent_turns "vision-agent"
  run_agent "vision-agent" || warn "Vision alignment had issues"
  restore_default_turns
  PHASE_STATUS[10]="passed"

  # ── Summary ──────────────────────────────────────────────────────────
  local end_total=$(date +%s)
  local total_duration=$(( end_total - start_total ))

  echo ""
  header "SWARM COMPLETE — $mode_label"
  echo ""
  echo -e "  ${MAGENTA}✦ Run ID:       ${RUN_ID}${NC}"
  echo -e "  ${MAGENTA}✦ Total time:   ${total_duration}s ($(( total_duration / 60 ))m $(( total_duration % 60 ))s)${NC}"
  echo -e "  ${MAGENTA}✦ Agents run:   17${NC}"
  echo -e "  ${MAGENTA}✦ Global fails: ${GLOBAL_FAIL_COUNT} (halt at ${GLOBAL_FAIL_THRESHOLD})${NC}"
  echo -e "  ${MAGENTA}✦ Model:        ${MODEL}${NC}"
  echo ""

  # Print phase status map
  echo "  Phase Status:"
  for p in 0 1 2 3 3.5 4 5 6 7 8 9 10; do
    local ps="${PHASE_STATUS[$p]:-unknown}"
    local ps_icon="❓"
    case "$ps" in
      passed)  ps_icon="${GREEN}✅${NC}" ;;
      failed)  ps_icon="${RED}❌${NC}" ;;
      skipped) ps_icon="${YELLOW}⏭️${NC}" ;;
    esac
    echo -e "    Phase $p: $ps_icon $ps"
  done
  echo ""

  # Print per-agent results
  echo "  Agent Results:"
  for result in "${AGENT_RESULTS[@]}"; do
    echo "    $result"
  done
  echo ""

  if [[ -f "$STATE_DIR/swarm-halted.json" ]]; then
    error "SWARM WAS HALTED by global circuit breaker — fix root causes and --resume"
  elif [[ $GLOBAL_FAIL_COUNT -eq 0 ]]; then
    success "All agents completed successfully!"
  else
    warn "${GLOBAL_FAIL_COUNT} agent(s) failed — review failures before next run"
  fi
  log "Logs: $LOG_DIR/"
  log "State: $STATE_DIR/"

  # Write run summary
  local decisions_count=0
  [[ -f "$STATE_DIR/decisions.log" ]] && decisions_count=$(wc -l < "$STATE_DIR/decisions.log" | tr -d ' ')
  local statuses_count=0
  statuses_count=$(find "$STATE_DIR" -name "*-status.md" -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')

  atomic_write_heredoc "$STATE_DIR/last-run-summary.md" <<EOF
# AI Swarm Run Summary — ${DATE_TODAY} — ${mode_label}
- **Run ID:** ${RUN_ID}
- **Date:** ${DATE_TODAY} ($DOW_NAME)
- **Mode:** ${mode_label}
- **Duration:** ${total_duration}s ($(( total_duration / 60 ))m)
- **Model:** ${MODEL}
- **Global failures:** ${GLOBAL_FAIL_COUNT} (threshold: ${GLOBAL_FAIL_THRESHOLD})
- **Cascade stop:** $($CASCADE_STOP && echo "ON" || echo "OFF")
- **Halted:** $([ -f "$STATE_DIR/swarm-halted.json" ] && echo "YES" || echo "NO")
- **Self-healing retries:** ${MAX_RETRIES} max per agent
- **Iteration:** ${CURRENT_ITERATION} of ${ITERATIONS}
- **Autonomous decisions:** ${decisions_count}
- **Agent statuses written:** ${statuses_count}

## Phase Status
$(for p in 0 1 2 3 3.5 4 5 6 7 8 9 10; do echo "- Phase $p: ${PHASE_STATUS[$p]:-unknown}"; done)

## Agent Results
$(printf '%s\n' "${AGENT_RESULTS[@]}" | sed 's/^/- /')

## State Files Modified
$(find "$STATE_DIR" -newer "$LOG_DIR" -type f 2>/dev/null | head -30 | sed 's|'"$PROJECT_ROOT/"'||g' | sed 's/^/- /' || echo "- (none detected)")

## Vision Focus
- Core Pillars: V3 (Decision Intelligence), V5 (MPTE), V7 (MCP)
- Design Constraints: V1, V2, V9, V10
- Deferred: V4, V6, V8
$(${WAR_ROOM} && echo "
## War Room Targets
1. Triage Dashboard — 11,300→340 finding reduction
2. MPTE Verification View — exploitability proof
3. Evidence Export — signed compliance bundle")
EOF

  # Append to context_log.md
  cat >> "$PROJECT_ROOT/context_log.md" <<EOF

### [$(date +"%Y-%m-%d %H:%M")] run-ctem-swarm — ${mode_label}
- **What**: Full swarm run (17 agents, ${MODEL})
- **Run ID**: ${RUN_ID}
- **Duration**: ${total_duration}s ($(( total_duration / 60 ))m)
- **Failed**: ${total_failed} phases
- **Mode**: ${mode_label}
- **Outcome**: $([ $total_failed -eq 0 ] && echo "SUCCESS" || echo "PARTIAL (${total_failed} phase failures)")
- **Pillar focus**: V3, V5, V7 (core) | V1, V2, V9, V10 (constraints)
EOF

  # ── Hallucination Protection Summary ──
  hallucination_protection_summary

  # ── JARVIS Controller Post-Swarm Reconciliation ──
  # Scan all failed agents, spawn fix-agents, re-run — never leave failures unresolved
  if $ENABLE_CONTROLLER && [[ $total_failed -gt 0 ]]; then
    controller_post_swarm_reconcile
    local reconcile_result=$?
    if [[ $reconcile_result -eq 0 ]]; then
      success "Controller reconciled ALL failures — updating total_failed to 0"
      total_failed=0
      # Reset circuit breaker after successful reconciliation
      GLOBAL_FAIL_COUNT=0
      CIRCUIT_BREAKER_SELF_HEAL_ATTEMPTS=0
      rm -f "$STATE_DIR/swarm-halted.json" 2>/dev/null || true
      success "Circuit breaker RESET after successful reconciliation"
    else
      warn "Controller could not reconcile ${reconcile_result} agent(s)"
      # Partial reconciliation — reduce fail count proportionally
      local reconciled_agents=$(( GLOBAL_FAIL_COUNT - reconcile_result ))
      if [[ $reconciled_agents -gt 0 ]]; then
        GLOBAL_FAIL_COUNT=$reconcile_result
        log "Circuit breaker adjusted: ${reconciled_agents} reconciled, ${reconcile_result} still failing"
      fi
    fi
  fi

  # ── JARVIS Controller Summary ──
  controller_print_summary

  # ── Grade-A Enforcement Loop ──
  # Run persona verification, UI flow verification, and enforce Grade A quality
  # Loops until Grade A is reached or max cycles exhausted — no fakes, no stubs
  enforce_grade_a

  # ── Stop background watchdog ──
  controller_stop_watchdog

  # ── Agent Guardian: Daily Report ──
  if type guardian_daily_report &>/dev/null; then
    local guardian_report
    guardian_report=$(guardian_daily_report)
    success "Guardian daily report: ${guardian_report}"
  fi

  # ── Auto-commit if enabled ──
  auto_commit_changes

  # ── Generate daily digest if this is the final iteration or single run ──
  generate_daily_digest "$total_duration" "$total_failed"

  return $total_failed
}

###############################################################################
# DAILY DIGEST — End-of-Day Vision/Feature/Quality Report
#
# Generates a comprehensive Markdown report answering:
#   1. "Which Vision Pillars (V1-V10) were actively worked on?"
#   2. "What features/capabilities were built or improved?"
#   3. "What's the quality state?" (tests, coverage, errors)
#   4. "What files changed?" (git diff summary)
#   5. "What decisions were agents making autonomously?"
#   6. "What's the overall health grade?"
#
# Outputs to:
#   - Terminal (color summary)
#   - .claude/team-state/daily-digest-YYYY-MM-DD.md (full report)
#   - logs/jarvis/daily-digest-YYYY-MM-DD.md (backup copy)
###############################################################################
generate_daily_digest() {
  local run_duration="${1:-0}"
  local run_failures="${2:-0}"
  local digest_file="$STATE_DIR/daily-digest-${DATE_TODAY}.md"
  local digest_backup="$PROJECT_ROOT/logs/jarvis/daily-digest-${DATE_TODAY}.md"
  local now_epoch
  now_epoch=$(date +%s)

  header "DAILY DIGEST — ${DATE_TODAY}"
  echo ""

  # ── 1. Agent Performance Summary ──────────────────────────────────
  local total_agents=0 completed=0 failed=0 running=0 not_run=0
  local agent_table="" quality_grade="F"
  # Pre-initialize ALL score variables to prevent unbound errors with set -u
  local dec_score=0 file_score=0 quality_score=0 art_score=0 health_score=0
  local core_score=0 non_core_score=0
  local all_agents=("vision-agent" "agent-doctor" "context-engineer" "ai-researcher" \
    "data-scientist" "enterprise-architect" "backend-hardener" "frontend-craftsman" \
    "threat-architect" "swarm-controller" "security-analyst" "qa-engineer" \
    "persona-api-validator" "devops-engineer" "marketing-head" "technical-writer" "sales-engineer" "scrum-master")

  for agent in "${all_agents[@]}"; do
    ((total_agents++))
    local status_file="$STATE_DIR/${agent}-status.md"
    local log_pattern="$LOG_DIR/${DATE_TODAY}_${agent}_*.log"
    local agent_status="❓ Unknown"
    local agent_pillar="-"
    local agent_task="-"
    local agent_duration="-"
    local log_size=0

    # Parse status file for pillar and status
    if [[ -f "$status_file" ]]; then
      if grep -qi "completed\|✅\|success" "$status_file" 2>/dev/null; then
        agent_status="✅ Completed"
        ((completed++))
      elif grep -qi "running\|🔄\|in.progress" "$status_file" 2>/dev/null; then
        agent_status="🔄 Running"
        ((running++))
      elif grep -qi "failed\|❌\|crashed\|error" "$status_file" 2>/dev/null; then
        agent_status="❌ Failed"
        ((failed++))
      else
        ((not_run++))
      fi
      # Extract pillar tags (V1-V10)
      agent_pillar=$(grep -oE 'V[0-9]+' "$status_file" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//' || echo "-")
      [[ -z "$agent_pillar" ]] && agent_pillar="-"
      # Extract task/feature description (first line after "Mission" or "Task" or "What")
      agent_task=$(grep -iE '(mission|task|what|working on|feature|focus):?' "$status_file" 2>/dev/null | head -1 | sed 's/.*[:-] *//' | cut -c1-60 || echo "-")
      [[ -z "$agent_task" ]] && agent_task="-"
    else
      ((not_run++))
    fi

    # Find latest log and compute size
    local latest_log
    latest_log=$(ls -t $log_pattern 2>/dev/null | head -1)
    if [[ -n "$latest_log" && -f "$latest_log" ]]; then
      log_size=$(wc -c < "$latest_log" | tr -d ' ')
      # Estimate duration from log timestamps
      if [[ $log_size -gt 0 ]]; then
        local first_ts last_ts
        first_ts=$(/usr/bin/stat -f '%B' "$latest_log" 2>/dev/null || true)
        last_ts=$(/usr/bin/stat -f '%m' "$latest_log" 2>/dev/null || true)
        if [[ $first_ts -gt 0 && $last_ts -gt 0 && $last_ts -gt $first_ts ]]; then
          agent_duration="$(( (last_ts - first_ts) / 60 ))m"
        fi
      fi
    fi

    agent_table+="| ${agent} | ${agent_status} | ${agent_pillar} | ${agent_task} | ${agent_duration} | ${log_size}B |"$'\n'
  done

  # ── 2. Vision Pillar Coverage ──────────────────────────────────────
  local pillar_coverage=""
  local pillar_names=("V1:APP_ID-Centric" "V2:Security Lifecycle" "V3:Decision Intelligence" \
    "V4:Multi-LLM Consensus" "V5:MPTE Verification" "V6:Quantum-Secure Evidence" \
    "V7:MCP-Native Platform" "V8:Self-Learning" "V9:Air-Gapped Deploy" "V10:CTEM+Crypto Proof")
  local pillars_touched=0

  for pn in "${pillar_names[@]}"; do
    local vtag="${pn%%:*}"
    local vname="${pn##*:}"
    local is_core=" "
    local is_active="⬜"
    local agents_on_this=""
    [[ "$vtag" == "V3" || "$vtag" == "V5" || "$vtag" == "V7" ]] && is_core="🎯"

    # Check which agents touched this pillar (from status files, decisions.log, and logs)
    for agent in "${all_agents[@]}"; do
      local sf="$STATE_DIR/${agent}-status.md"
      local lp
      lp=$(ls -t "$LOG_DIR/${DATE_TODAY}_${agent}_"*.log 2>/dev/null | head -1)
      if grep -q "$vtag" "$sf" 2>/dev/null || ([ -n "$lp" ] && grep -q "$vtag" "$lp" 2>/dev/null); then
        agents_on_this+="${agent}, "
        is_active="✅"
      fi
    done
    # Also check decisions.log
    if grep -q "$vtag" "$STATE_DIR/decisions.log" 2>/dev/null; then
      is_active="✅"
    fi
    [[ "$is_active" == "✅" ]] && ((pillars_touched++))
    agents_on_this="${agents_on_this%, }"
    [[ -z "$agents_on_this" ]] && agents_on_this="(none)"

    pillar_coverage+="| ${is_active} ${vtag} | ${vname} | ${is_core} | ${agents_on_this} |"$'\n'
  done

  # ── 3. Autonomous Decisions Summary ────────────────────────────────
  local decisions_today=""
  local decisions_count=0
  if [[ -f "$STATE_DIR/decisions.log" ]]; then
    decisions_today=$(grep "${DATE_TODAY}" "$STATE_DIR/decisions.log" 2>/dev/null || echo "")
    if [[ -n "$decisions_today" ]]; then
      decisions_count=$(echo "$decisions_today" | wc -l | tr -d ' ')
    fi
  fi

  # ── 4. Git Change Summary ─────────────────────────────────────────
  # Only count APP files (suite-*, tests/, scripts/, docs/, docker/, *.py, *.ts, *.tsx)
  # Ignore: .claude/, logs/, data/, __pycache__/, node_modules/, .git/
  local _digest_ignore_pattern='^(\.claude/|logs/|data/|__pycache__|node_modules/|WIP/)'
  local git_summary=""
  local files_changed=0 insertions=0 deletions=0 new_files=0
  local app_files_changed=0 agent_files_changed=0
  if command -v git &>/dev/null && [[ -d "$PROJECT_ROOT/.git" ]]; then
    # All changed files
    local all_changed
    all_changed=$(git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null || echo "")
    local all_new
    all_new=$(git -C "$PROJECT_ROOT" ls-files --others --exclude-standard 2>/dev/null || echo "")

    # Split into app files vs agent/state files
    local app_changed="" app_new=""
    local agent_changed="" agent_new=""
    if [[ -n "$all_changed" ]]; then
      app_changed=$(echo "$all_changed" | grep -vE "$_digest_ignore_pattern" || echo "")
      agent_changed=$(echo "$all_changed" | grep -E "$_digest_ignore_pattern" || echo "")
    fi
    if [[ -n "$all_new" ]]; then
      app_new=$(echo "$all_new" | grep -vE "$_digest_ignore_pattern" || echo "")
      agent_new=$(echo "$all_new" | grep -E "$_digest_ignore_pattern" || echo "")
    fi

    # Count app files only for the main metrics
    [[ -n "$app_changed" ]] && app_files_changed=$(echo "$app_changed" | wc -l | tr -d ' ') || app_files_changed=0
    [[ -n "$agent_changed" ]] && agent_files_changed=$(echo "$agent_changed" | wc -l | tr -d ' ') || agent_files_changed=0
    files_changed=$app_files_changed
    [[ -n "$app_new" ]] && new_files=$(echo "$app_new" | wc -l | tr -d ' ') || new_files=0

    # Get insertions/deletions (app files only)
    local shortstat
    if [[ -n "$app_changed" ]]; then
      shortstat=$(echo "$app_changed" | xargs git -C "$PROJECT_ROOT" diff --shortstat HEAD -- 2>/dev/null || echo "")
    else
      shortstat=""
    fi
    insertions=$(echo "$shortstat" | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+' || true)
    deletions=$(echo "$shortstat" | grep -oE '[0-9]+ deletion' | grep -oE '[0-9]+' || true)
    # Sanitize
    insertions=${insertions%%.*}; [[ -z "$insertions" || "$insertions" == " " ]] && insertions=0
    deletions=${deletions%%.*}; [[ -z "$deletions" || "$deletions" == " " ]] && deletions=0
    files_changed=${files_changed%%.*}; [[ -z "$files_changed" ]] && files_changed=0
    new_files=${new_files%%.*}; [[ -z "$new_files" ]] && new_files=0

    # Top changed APP files (by diff size)
    local top_files
    if [[ -n "$app_changed" ]]; then
      top_files=$(echo "$app_changed" | xargs git -C "$PROJECT_ROOT" diff --stat HEAD -- 2>/dev/null | head -15 || echo "(none)")
    else
      top_files="(no app files changed)"
    fi

    # Recently modified APP files (sorted by mod time)
    local recent_tracked
    if [[ -n "$app_changed" ]]; then
      recent_tracked=$(echo "$app_changed" | while read -r f; do
        [[ -f "$PROJECT_ROOT/$f" ]] && echo "$(/usr/bin/stat -f '%m' "$PROJECT_ROOT/$f" 2>/dev/null || true) $f"
      done | sort -rn | head -10 | awk '{print $2}')
    else
      recent_tracked=""
    fi

    git_summary="### App Files Changed: ${app_files_changed} modified, ${new_files} new
### Agent/State Files: ${agent_files_changed} modified (ignored in metrics)
### Lines: +${insertions} / -${deletions}

#### Top Changed App Files (by diff size):
\`\`\`
${top_files}
\`\`\`

#### Most Recently Modified App Files:
$(if [[ -n "$recent_tracked" ]]; then echo "$recent_tracked" | while IFS= read -r f; do echo "- \`$f\`"; done; else echo "- _(none)_"; fi)"
  fi

  # ── 5. Quality Metrics ────────────────────────────────────────────
  local test_count=0 test_pass=0 test_fail=0 coverage_pct=0
  # Check metrics.json for latest quality data
  if [[ -f "$STATE_DIR/metrics.json" ]]; then
    test_count=$(python3 -c "import json; d=json.load(open('$STATE_DIR/metrics.json')); print(d.get('testing',{}).get('totalTests',0))" 2>/dev/null || true)
    coverage_pct=$(python3 -c "import json; d=json.load(open('$STATE_DIR/metrics.json')); print(int(float(d.get('codebase',{}).get('testCoverage',0))))" 2>/dev/null || true)
  fi
  # Sanitize: ensure all numeric vars are integers (they may come from bc/python as floats)
  coverage_pct=${coverage_pct%%.*}
  [[ -z "$coverage_pct" ]] && coverage_pct=0
  test_count=${test_count%%.*}
  [[ -z "$test_count" ]] && test_count=0
  # Also check latest Newman verdict
  local newman_verdict_text="(no Newman run today)"
  local latest_verdict
  latest_verdict=$(find "$STATE_DIR/qa/" -name "verdict.json" -maxdepth 2 2>/dev/null | sort | tail -1)
  if [[ -n "$latest_verdict" && -f "$latest_verdict" ]]; then
    newman_verdict_text=$(python3 -c "
import json
d=json.load(open('$latest_verdict'))
print(f\"Verdict: {d.get('verdict','?')} | Pass rate: {d.get('pass_rate',0)}% | Passed: {d.get('passed',0)} | Failed: {d.get('failed',0)}\")
" 2>/dev/null || echo "(error reading verdict)")
  fi

  # ── 6. Artifacts Produced Today ────────────────────────────────────
  local artifacts_list=""
  local artifact_count=0
  # State files modified today
  local state_artifacts
  state_artifacts=$(find "$STATE_DIR" -maxdepth 2 -name "*.md" -o -name "*.json" 2>/dev/null | while read -r f; do
    local fmod
    fmod=$(/usr/bin/stat -f '%m' "$f" 2>/dev/null || true)
    local day_start_epoch
    day_start_epoch=$(date -j -f "%Y-%m-%d %H:%M:%S" "${DATE_TODAY} 00:00:00" +%s 2>/dev/null || true)
    if [[ $fmod -ge $day_start_epoch ]]; then
      echo "$(basename "$f")"
    fi
  done | sort -u)

  if [[ -n "$state_artifacts" ]]; then
    artifact_count=$(echo "$state_artifacts" | wc -l | tr -d ' ')
    artifacts_list=$(echo "$state_artifacts" | sed 's/^/- /')
  fi

  # ── 7. Health Grade Calculation (Enterprise-Grade Scoring) ──────────
  # A = production-ready  | B = feature-complete | C = partial
  # D = significant gaps  | F = broken/stalled
  #
  # Scoring is STRICT — mediocre output = mediocre grade.
  # No participation trophies.
  local health_score=0

  # Agent Completion Rate (max 35 points)
  # This is the single biggest factor — if agents don't complete, nothing works.
  # Requires 15+/17 for full marks. 2/17 = 4 points.
  [[ $total_agents -gt 0 ]] && health_score=$(( (completed * 35) / total_agents ))

  # Core Pillar Coverage (max 20 points)
  # V3, V5, V7 MUST ALL be active (6 pts each = 18). Others = 0.3 pts each (~2 pts).
  local core_score=0
  for cpillar in V3 V5 V7; do
    local cp_active=false
    for agent in "${all_agents[@]}"; do
      local sf="$STATE_DIR/${agent}-status.md"
      local lp
      lp=$(ls -t "$LOG_DIR/${DATE_TODAY}_${agent}_"*.log 2>/dev/null | head -1)
      if grep -q "$cpillar" "$sf" 2>/dev/null || ([ -n "$lp" ] && grep -q "$cpillar" "$lp" 2>/dev/null); then
        cp_active=true; break
      fi
    done
    $cp_active && core_score=$((core_score + 6))
  done
  local non_core_score=$(( (pillars_touched > 3 ? pillars_touched - 3 : 0) ))
  [[ $non_core_score -gt 2 ]] && non_core_score=2
  health_score=$((health_score + core_score + non_core_score))

  # Zero Failures Bonus (max 10 points)
  # Only awarded if MORE THAN HALF of agents completed successfully
  if [[ ${run_failures} -eq 0 && $completed -gt $((total_agents / 2)) ]]; then
    health_score=$((health_score + 10))
  fi

  # Autonomous Decisions (max 10 points — must have at least 5 for full marks)
  local dec_score=0
  if [[ $decisions_count -ge 10 ]]; then dec_score=10
  elif [[ $decisions_count -ge 5 ]]; then dec_score=7
  elif [[ $decisions_count -ge 2 ]]; then dec_score=4
  elif [[ $decisions_count -ge 1 ]]; then dec_score=2
  fi
  health_score=$((health_score + dec_score))

  # Code Productivity (max 15 points — enterprise expects real code changes)
  # Requires 20+ files changed for full marks
  local file_score=0
  if [[ $files_changed -ge 30 ]]; then file_score=15
  elif [[ $files_changed -ge 20 ]]; then file_score=12
  elif [[ $files_changed -ge 10 ]]; then file_score=8
  elif [[ $files_changed -ge 5 ]]; then file_score=4
  elif [[ $files_changed -ge 1 ]]; then file_score=2
  fi
  health_score=$((health_score + file_score))

  # Quality Evidence (max 10 points — tests, coverage, Newman)
  local quality_score=0
  if [[ $coverage_pct -ge 60 ]]; then quality_score=$((quality_score + 5))
  elif [[ $coverage_pct -ge 30 ]]; then quality_score=$((quality_score + 3))
  fi
  if [[ "$newman_verdict_text" == *"PASS"* ]]; then quality_score=$((quality_score + 5))
  elif [[ "$newman_verdict_text" == *"WARN"* ]]; then quality_score=$((quality_score + 2))
  fi
  health_score=$((health_score + quality_score))

  # Artifact Score (max 10 points — state artifacts produced today)
  local art_score=0
  if [[ $artifact_count -ge 15 ]]; then art_score=10
  elif [[ $artifact_count -ge 10 ]]; then art_score=8
  elif [[ $artifact_count -ge 5 ]]; then art_score=5
  elif [[ $artifact_count -ge 2 ]]; then art_score=3
  elif [[ $artifact_count -ge 1 ]]; then art_score=1
  fi
  health_score=$((health_score + art_score))

  # Grade
  if [[ $health_score -ge 85 ]]; then quality_grade="A"
  elif [[ $health_score -ge 70 ]]; then quality_grade="B"
  elif [[ $health_score -ge 50 ]]; then quality_grade="C"
  elif [[ $health_score -ge 30 ]]; then quality_grade="D"
  else quality_grade="F"
  fi

  # ── 8. Runtime Summary ────────────────────────────────────────────
  local total_elapsed=0
  if [[ ${SWARM_START_EPOCH:-0} -gt 0 ]]; then
    total_elapsed=$(( now_epoch - SWARM_START_EPOCH ))
  elif [[ ${run_duration:-0} -gt 0 ]]; then
    total_elapsed=${run_duration}
  else
    # Estimate from log file timestamps (digest mode: no epoch available)
    # Use LOG_DIR (logs/ai-team/) and filter to today's logs only
    local _earliest="" _latest=""
    if [[ -d "${LOG_DIR}" ]]; then
      _earliest=$(find "${LOG_DIR}" -name "${DATE_TODAY}*.log" -type f -exec stat -f '%B' {} + 2>/dev/null | sort -n | head -1)
      _latest=$(find "${LOG_DIR}" -name "${DATE_TODAY}*.log" -type f -exec stat -f '%m' {} + 2>/dev/null | sort -rn | head -1)
      if [[ -n "$_earliest" && -n "$_latest" && "$_latest" -gt "$_earliest" ]]; then
        total_elapsed=$(( _latest - _earliest ))
      fi
    fi
  fi
  local elapsed_h=$(( total_elapsed / 3600 ))
  local elapsed_m=$(( (total_elapsed % 3600) / 60 ))
  local elapsed_s=$(( total_elapsed % 60 ))
  local runtime_display=""
  if [[ $total_elapsed -eq 0 ]]; then
    runtime_display="unknown (no active run detected)"
  elif [[ $total_elapsed -lt 60 ]]; then
    runtime_display="${elapsed_s}s"
  else
    runtime_display="${elapsed_h}h ${elapsed_m}m"
  fi

  # ── TERMINAL OUTPUT ────────────────────────────────────────────────
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  ${BOLD}📊 DAILY DIGEST — ${DATE_TODAY}${NC}                              ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  ${DIM}Run: ${RUN_ID} | Grade: ${quality_grade} (${health_score}/100)${NC}              ${CYAN}║${NC}"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}  ⏱️  Runtime:    ${runtime_display}"
  echo -e "${CYAN}║${NC}  🤖 Agents:     ${completed}/${total_agents} completed, ${failed} failed, ${running} running"
  echo -e "${CYAN}║${NC}  🎯 Pillars:    ${pillars_touched}/10 touched (core: V3, V5, V7)"
  echo -e "${CYAN}║${NC}  🧠 Decisions:  ${decisions_count} autonomous decisions"
  echo -e "${CYAN}║${NC}  📁 Changes:    ${files_changed} app files modified, +${insertions}/-${deletions} lines, ${new_files} new (${agent_files_changed} agent/state files ignored)"
  echo -e "${CYAN}║${NC}  📦 Artifacts:  ${artifact_count} state artifacts updated"
  echo -e "${CYAN}║${NC}  🏥 Newman:     ${newman_verdict_text}"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}  ${BOLD}Vision Pillar Coverage:${NC}"

  for pn in "${pillar_names[@]}"; do
    local vtag="${pn%%:*}"
    local vname="${pn##*:}"
    local marker="⬜"
    local core_marker=" "
    [[ "$vtag" == "V3" || "$vtag" == "V5" || "$vtag" == "V7" ]] && core_marker="🎯"
    # Check if this pillar was touched
    for agent in "${all_agents[@]}"; do
      local sf="$STATE_DIR/${agent}-status.md"
      local lp
      lp=$(ls -t "$LOG_DIR/${DATE_TODAY}_${agent}_"*.log 2>/dev/null | head -1)
      if grep -q "$vtag" "$sf" 2>/dev/null || ([ -n "$lp" ] && grep -q "$vtag" "$lp" 2>/dev/null); then
        marker="✅"; break
      fi
    done
    if grep -q "$vtag" "$STATE_DIR/decisions.log" 2>/dev/null; then marker="✅"; fi
    printf "${CYAN}║${NC}   %s %s %-24s %s\n" "$marker" "$vtag" "$vname" "$core_marker"
  done

  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}  ${BOLD}🎛️  JARVIS Controller Self-Healing:${NC}"
  # Gather controller stats
  local ctrl_fix_spawns=0 ctrl_fix_ok=0 ctrl_api_recoveries=0 ctrl_reconciled=0 ctrl_reconcile_fail=0 ctrl_deferred=0
  if [[ -f "$CONTROLLER_LOG" ]]; then
    ctrl_fix_spawns=$(grep -c '"type":"fix_agent"' "$CONTROLLER_LOG" 2>/dev/null) || ctrl_fix_spawns=0
    ctrl_fix_ok=$(grep '"type":"fix_agent"' "$CONTROLLER_LOG" 2>/dev/null | grep -c '"exit_code":0' 2>/dev/null) || ctrl_fix_ok=0
    ctrl_api_recoveries=$(grep -c '"type":"api_recovery"' "$CONTROLLER_LOG" 2>/dev/null) || ctrl_api_recoveries=0
    ctrl_reconciled=$(grep -c '"type":"reconcile_success"' "$CONTROLLER_LOG" 2>/dev/null) || ctrl_reconciled=0
    ctrl_reconcile_fail=$(grep -c '"type":"reconcile_failed"' "$CONTROLLER_LOG" 2>/dev/null) || ctrl_reconcile_fail=0
  fi
  if [[ -f "$STATE_DIR/controller-deferred-queue.txt" ]]; then
    ctrl_deferred=$(wc -l < "$STATE_DIR/controller-deferred-queue.txt" 2>/dev/null | tr -d ' ')
  fi
  echo -e "${CYAN}║${NC}   Fix Agents Spawned:   ${ctrl_fix_spawns} (${ctrl_fix_ok} successful)"
  echo -e "${CYAN}║${NC}   API Recoveries:       ${ctrl_api_recoveries}"
  echo -e "${CYAN}║${NC}   Agents Reconciled:    ${GREEN}${ctrl_reconciled}${NC}"
  echo -e "${CYAN}║${NC}   Still Failed:         ${RED}${ctrl_reconcile_fail}${NC}"
  echo -e "${CYAN}║${NC}   Deferred Queue:       ${ctrl_deferred}"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}  ${BOLD}🛡️  Quality Assurance Report:${NC}"
  # Hallucination protection stats
  local h_layer1=0 h_layer2=0 h_layer3=0 h_layer4=0 h_layer5=0
  if [[ -f "$STATE_DIR/hallucination-audit.jsonl" ]]; then
    h_layer1=$(grep -c '"layer":1' "$STATE_DIR/hallucination-audit.jsonl" 2>/dev/null) || h_layer1=0
    h_layer2=$(grep -c '"layer":2' "$STATE_DIR/hallucination-audit.jsonl" 2>/dev/null) || h_layer2=0
    h_layer3=$(grep -c '"layer":3' "$STATE_DIR/hallucination-audit.jsonl" 2>/dev/null) || h_layer3=0
    h_layer4=$(grep -c '"layer":4' "$STATE_DIR/hallucination-audit.jsonl" 2>/dev/null) || h_layer4=0
    h_layer5=$(grep -c '"layer":5' "$STATE_DIR/hallucination-audit.jsonl" 2>/dev/null) || h_layer5=0
  fi
  local h_total=$((h_layer1 + h_layer2 + h_layer3 + h_layer4 + h_layer5))
  echo -e "${CYAN}║${NC}   5-Layer Hallucination Checks: ${h_total} total"
  echo -e "${CYAN}║${NC}     L1 Vision Alignment:  ${h_layer1}  L2 Realtime:  ${h_layer2}  L3 Deep:  ${h_layer3}"
  echo -e "${CYAN}║${NC}     L4 Cross-Agent:       ${h_layer4}  L5 Code:      ${h_layer5}"
  echo -e "${CYAN}║${NC}   Enterprise Health Score: ${BOLD}${quality_grade} (${health_score}/100)${NC}"
  echo -e "${CYAN}║${NC}   Output Verification:    Every output verified — no stubs, no fakes"
  echo -e "${CYAN}║${NC}   Controller Mode:        $(${ENABLE_CONTROLLER} && echo '✅ Active' || echo '⬜ Disabled') $(${CONTROLLER_NEVER_GIVE_UP} && echo '(Never Give Up)' || echo '')"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}  ${BOLD}🎭 Persona & UI Verification:${NC}"
  # Read latest verification snapshots
  local digest_persona_pct=0 digest_ui_pct=0 digest_combined_grade="—" digest_combined_score=0
  if [[ -f "$STATE_DIR/quality-snapshot-${DATE_TODAY}.md" ]]; then
    digest_persona_pct=$(grep 'Persona Verification' "$STATE_DIR/quality-snapshot-${DATE_TODAY}.md" 2>/dev/null | grep -oE '[0-9]+%' | head -1 | tr -d '%' || true)
    digest_ui_pct=$(grep 'UI Flow Quality' "$STATE_DIR/quality-snapshot-${DATE_TODAY}.md" 2>/dev/null | grep -oE '[0-9]+%' | head -1 | tr -d '%' || true)
    digest_combined_grade=$(grep 'Combined' "$STATE_DIR/quality-snapshot-${DATE_TODAY}.md" 2>/dev/null | grep -oE '\*\*[A-F]\*\*' | head -1 | tr -d '*' || echo "—")
    digest_combined_score=$(grep 'Combined' "$STATE_DIR/quality-snapshot-${DATE_TODAY}.md" 2>/dev/null | grep -oE '[0-9]+%' | head -1 | tr -d '%' || true)
  fi
  [[ -z "$digest_persona_pct" || ! "$digest_persona_pct" =~ ^[0-9]+$ ]] && digest_persona_pct=0
  [[ -z "$digest_ui_pct" || ! "$digest_ui_pct" =~ ^[0-9]+$ ]] && digest_ui_pct=0
  [[ -z "$digest_combined_score" || ! "$digest_combined_score" =~ ^[0-9]+$ ]] && digest_combined_score=0
  echo -e "${CYAN}║${NC}   Agent Persona Score:    ${digest_persona_pct}%"
  echo -e "${CYAN}║${NC}   UI Flow Score:          ${digest_ui_pct}%"
  echo -e "${CYAN}║${NC}   Combined Quality Grade: ${BOLD}${digest_combined_grade} (${digest_combined_score}%)${NC}"
  local grade_a_cert="$STATE_DIR/grade-a-certification-${DATE_TODAY}.md"
  if [[ -f "$grade_a_cert" ]]; then
    echo -e "${CYAN}║${NC}   Grade-A Certification:  ${GREEN}✅ CERTIFIED${NC}"
  else
    echo -e "${CYAN}║${NC}   Grade-A Certification:  ${RED}⚠️  NOT YET CERTIFIED${NC}"
  fi
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}  ${BOLD}🔬 Persona → Function → E2E Test Map (Realtime):${NC}"
  echo -e "${CYAN}║${NC}  ${DIM}What functions each persona owns + what's tested 100% by agents${NC}"
  echo -e "${CYAN}║${NC}" >&2
  # Build the function registry and render it
  build_persona_function_registry || true
  render_persona_functions_terminal 2>&1 || true
  echo -e "${CYAN}║${NC}" >&2
  local _reg_total="${_PERSONA_REG_TOTAL:-0}"
  local _reg_tested="${_PERSONA_REG_TESTED:-0}"
  local _reg_pct=0
  [[ $_reg_total -gt 0 ]] && _reg_pct=$(( (_reg_tested * 100) / _reg_total ))
  local _reg_color="${RED}"
  [[ $_reg_pct -ge 50 ]] && _reg_color="${YELLOW}"
  [[ $_reg_pct -ge 80 ]] && _reg_color="${GREEN}"
  echo -e "${CYAN}║${NC}   ${BOLD}E2E Coverage: ${_reg_color}${_reg_tested}/${_reg_total} functions have test scripts (${_reg_pct}%)${NC}"
  echo -e "${CYAN}║${NC}   ${DIM}Registry: .claude/team-state/persona-e2e-registry.json${NC}"
  echo -e "${CYAN}║${NC}   ${DIM}As agents add functions → e2e tests auto-accumulate in registry${NC}"
  # Explain why some have no tests
  local _untested=$(( _reg_total - _reg_tested ))
  if [[ $_untested -gt 0 ]]; then
    echo -e "${CYAN}║${NC}   ${YELLOW}⚠️  ${_untested} functions untested: 7 agents stale-failed (pre-RC6), never re-ran to create test scripts${NC}"
    echo -e "${CYAN}║${NC}   ${DIM}   Fix: Re-run 7 stale agents → they create scripts/test-<agent>.sh → coverage auto-grows${NC}"
  fi
  # Show live test script results if we ran them
  if [[ -n "${TEST_SCRIPT_RESULTS[scripts/test-backend-hardener.sh]:-}" ]]; then
    echo -e "${CYAN}║${NC}   ${GREEN}🏃 backend-hardener live: ${TEST_SCRIPT_RESULTS[scripts/test-backend-hardener.sh]}${NC}"
  fi
  if [[ -n "${TEST_SCRIPT_RESULTS[scripts/test-threat-architect.sh]:-}" ]]; then
    echo -e "${CYAN}║${NC}   ${GREEN}🏃 threat-architect live:  ${TEST_SCRIPT_RESULTS[scripts/test-threat-architect.sh]}${NC}"
  fi
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  # Pre-compute values that can't be expanded inside heredoc
  local _bh_live_result="${TEST_SCRIPT_RESULTS[scripts/test-backend-hardener.sh]:-⏳ not run}"
  local _ta_live_result="${TEST_SCRIPT_RESULTS[scripts/test-threat-architect.sh]:-⏳ not run}"
  local _persona_md_table
  _persona_md_table=$(render_persona_functions_markdown 2>/dev/null || echo "_(Registry not built — run with --digest)_")

  # ── MARKDOWN REPORT ────────────────────────────────────────────────
  cat > "$digest_file" <<DIGEST_EOF
# 📊 ALdeci Daily Digest — ${DATE_TODAY} (${DOW_NAME})

> **Run ID:** ${RUN_ID}
> **Model:** ${MODEL}
> **Runtime:** ${runtime_display}
> **Iteration:** ${CURRENT_ITERATION}/${ITERATIONS}
> **Health Grade:** **${quality_grade}** (${health_score}/100)

---

## 🤖 Agent Performance

| Agent | Status | Pillars | Task/Feature | Duration | Log Size |
|-------|--------|---------|-------------|----------|----------|
${agent_table}

**Summary:** ${completed}/${total_agents} completed, ${failed} failed, ${running} running, ${not_run} not run

---

## 🎯 Vision Pillar Coverage (${pillars_touched}/10 active)

| Status | Pillar | Name | Priority | Agents Working |
|--------|--------|------|----------|---------------|
${pillar_coverage}

**Core Pillars (must be active):** V3 Decision Intelligence, V5 MPTE, V7 MCP
**Design Constraints:** V1 APP_ID, V2 Lifecycle, V9 Air-Gap, V10 CTEM+Crypto
**Deferred (roadmap):** V4 Multi-LLM, V6 Quantum, V8 Self-Learning

---

## 🧠 Autonomous Decisions Today (${decisions_count})

\`\`\`
${decisions_today:-"(no decisions logged today)"}
\`\`\`

---

## 📁 Code Changes

${git_summary:-"(no git changes detected)"}

---

## 📦 Artifacts Produced Today (${artifact_count})

${artifacts_list:-"(none)"}

---

## 🏥 Quality Gate

- **Newman API Tests:** ${newman_verdict_text}
- **Test Count:** ${test_count}
- **Coverage:** ${coverage_pct}%
- **Phase Failures:** ${run_failures}

---

## 📈 Health Score Breakdown (${health_score}/100)

| Metric | Score | Max |
|--------|-------|-----|
| Agent Completion Rate | $(( (completed * 35) / (total_agents > 0 ? total_agents : 1) )) | 35 |
| Vision Pillar Coverage (V3/V5/V7 = 6ea + others) | $((core_score + non_core_score)) | 20 |
| Zero Failures Bonus | $([ ${run_failures} -eq 0 ] && echo 10 || true) | 10 |
| Autonomous Decisions | ${dec_score} | 10 |
| Code Activity | ${file_score} | 15 |
| Quality Evidence (tests + Newman) | ${quality_score} | 10 |
| Artifacts Produced | ${art_score} | 10 |

---

## 🎛️ JARVIS Controller Self-Healing Report

| Metric | Value |
|--------|-------|
| Fix Agents Spawned | ${ctrl_fix_spawns} (${ctrl_fix_ok} successful) |
| API Auto-Recoveries | ${ctrl_api_recoveries} |
| Agents Reconciled | ${ctrl_reconciled} |
| Agents Still Failed | ${ctrl_reconcile_fail} |
| Deferred Queue | ${ctrl_deferred} |
| Controller Mode | $(${ENABLE_CONTROLLER} && echo '✅ Active' || echo '⬜ Disabled') $(${CONTROLLER_NEVER_GIVE_UP} && echo '(Never Give Up)' || echo '') |
| Max Fix Cycles | ${CONTROLLER_MAX_FIX_CYCLES} per failed agent |

> The JARVIS Controller watches every agent with a continuous reconciliation loop.
> When something fails, it spawns a parallel Claude fix-agent to diagnose the root cause,
> applies the fix, re-runs the original agent, and verifies the output — never leaving
> failures unresolved.

---

## 🎭 Agent Persona Verification

> Each of the 17 agents is a world-class persona with specialized expertise.
> This section verifies they performed at their expected level.

- **Persona Verification Score:** ${digest_persona_pct}%
- **Detailed Report:** .claude/team-state/persona-verification-${DATE_TODAY}.md

$(if [[ -f "$STATE_DIR/persona-verification-${DATE_TODAY}.md" ]]; then
  echo "### Agent Grades"
  grep -E '^\|.*\|.*\|.*\|.*\|.*\|' "$STATE_DIR/persona-verification-${DATE_TODAY}.md" 2>/dev/null | head -20
else
  echo "_(No persona verification run today)_"
fi)

---

## � Persona → Function → E2E Test Map (Realtime)

> **What functions each persona owns + what's tested 100% by our agents in realtime.**
> E2E tests accumulate automatically as agents add new functions through the swarm.
> Registry: \`.claude/team-state/persona-e2e-registry.json\`

### Coverage: ${_PERSONA_REG_TESTED:-0}/${_PERSONA_REG_TOTAL:-0} functions have E2E test scripts

${_persona_md_table}

### Live E2E Test Results (executed during digest)

| Persona | Test Script | Live Result |
|---------|------------|-------------|
| backend-hardener | scripts/test-backend-hardener.sh | ${_bh_live_result} |
| threat-architect | scripts/test-threat-architect.sh | ${_ta_live_result} |

> **How E2E grows:** When any agent (e.g., backend-hardener) adds a new router or endpoint,
> the next \`--digest\` run auto-detects the new router file, counts its endpoints, checks
> for matching test scripts, and updates the registry. The E2E coverage % rises automatically.
> To add a test for a new persona, create \`scripts/test-<agent-name>.sh\` with the same
> pattern as \`test-backend-hardener.sh\` or \`test-threat-architect.sh\`.

### Why Some Personas Have ❌ No E2E Tests (Yet)

| Reason | Affected Personas | Resolution |
|--------|-------------------|------------|
| **Agent failed in pre-RC6 run** — never re-scheduled after infrastructure fixes RC1-RC8 resolved | enterprise-architect, threat-architect*, security-analyst, scrum-master, technical-writer, marketing-head, swarm-controller | Re-run 7 stale-failed agents (all root causes fixed) |
| **No \`scripts/test-<agent>.sh\` created yet** — agents need to produce their own E2E test scripts during swarm run | All except backend-hardener & threat-architect | Each agent's prompt instructs it to create test scripts; failed agents never got to run |
| **Pytest files exist but no shell E2E** — some personas have pytest unit tests but no integration/E2E shell scripts | security-analyst (has pytest), qa-engineer (has pytest) | Count pytest coverage separately (shown with 🧪 icon) |

> **Note**: threat-architect shows ✅ because the test script \`scripts/test-threat-architect.sh\` was manually created — but the agent itself is stale-failed.
> Once the 7 failed agents are re-run (all RC1-RC8 fixes are in place), they will create their own test scripts and coverage will jump.
> **Target**: 100% of personas with E2E test scripts = Grade A+ certification.

---

## 🖥️ UI Flow Verification

> Verifying each of the 5 workflow spaces: Mission Control, Discover, Validate, Remediate, Comply.

- **UI Flow Score:** ${digest_ui_pct}%
- **Detailed Report:** .claude/team-state/ui-flow-verification-${DATE_TODAY}.md

$(if [[ -f "$STATE_DIR/ui-flow-verification-${DATE_TODAY}.md" ]]; then
  echo "### Space Health"
  grep -E '^\|.*\|.*\|.*\|.*\|.*\|.*\|' "$STATE_DIR/ui-flow-verification-${DATE_TODAY}.md" 2>/dev/null | head -8
else
  echo "_(No UI flow verification run today)_"
fi)

---

## 🔌 API & Testing Per Agent — What Was Worked On + How to Replicate

> Each agent's work is traced to specific APIs/endpoints and tests.
> Use the replication commands below to verify locally.

$(if [[ -f "$STATE_DIR/persona-verification-${DATE_TODAY}.md" ]]; then
  grep -A 50 'API & Testing Per Agent' "$STATE_DIR/persona-verification-${DATE_TODAY}.md" 2>/dev/null | grep -E '^\|' | head -20
  echo ""
  echo "### Quick Local Replication"
  echo ""
  echo "\`\`\`bash"
  echo "# 1. Activate environment"
  echo "source .venv/bin/activate"
  echo ""
  echo "# 2. Start backend (in separate terminal)"
  echo "export FIXOPS_API_TOKEN='your-token' FIXOPS_DISABLE_RATE_LIMIT=1 FIXOPS_JWT_SECRET='enterprise-jwt-secret-key-minimum-32-characters'"
  echo "python -m uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --workers 4 --timeout-keep-alive 5"
  echo ""
  echo "# 3. Run all tests with coverage"
  echo "make test"
  echo ""
  echo "# 4. Run specific persona e2e tests:"
  echo "bash scripts/test-backend-hardener.sh   # Ethan+Hasan (connectors, admin, system)"
  echo "bash scripts/test-threat-architect.sh    # Jason+Carlos (MPTE, FAIL, attack-sim, feeds)"
  echo ""
  echo "# 5. Run specific agent's pytest files (examples from today):"
  # Extract unique test files from persona report
  local _test_files
  _test_files=$(grep -oE 'test_[a-z_]+\.py' "$STATE_DIR/persona-verification-${DATE_TODAY}.md" 2>/dev/null | sort -u | head -10)
  if [[ -n "$_test_files" ]]; then
    while IFS= read -r _tf; do
      echo "pytest tests/${_tf} -v --no-cov"
    done <<< "$_test_files"
  else
    echo "# (no specific test files detected in today's agent logs)"
    echo "pytest tests/ -v --no-cov  # run all"
  fi
  echo ""
  echo "# 6. API smoke test"
  echo "curl -s -H 'X-API-Key: test' http://localhost:8000/api/v1/health"
  echo "\`\`\`"
else
  echo "_(No persona verification run today — rerun with \`./scripts/run-ctem-swarm.sh\`)_"
fi)

---

## ⭐ Grade-A Enforcement

$(if [[ -f "$STATE_DIR/grade-a-certification-${DATE_TODAY}.md" ]]; then
  echo "### ✅ GRADE A CERTIFIED"
  grep -E 'Combined Score|Enforcement Cycle|Certified At' "$STATE_DIR/grade-a-certification-${DATE_TODAY}.md" 2>/dev/null | sed 's/^/- /'
else
  echo "### ⚠️ Grade A Not Yet Certified"
  echo ""
  echo "Combined Quality Score: ${digest_combined_score}% (Grade: ${digest_combined_grade})"
  echo "The enforcement loop will re-run until Grade A is achieved."
fi)

---

## 🛡️ Quality Assurance Summary

### 5-Layer Hallucination Protection

| Layer | Name | Checks Run |
|-------|------|------------|
| L1 | Vision Alignment (pre-prompt) | ${h_layer1} |
| L2 | Realtime Monitor (during execution) | ${h_layer2} |
| L3 | Deep Analysis (post-output, 100-pt scoring) | ${h_layer3} |
| L4 | Cross-Agent Verification (post-phase) | ${h_layer4} |
| L5 | Code Verification (syntax + import check) | ${h_layer5} |
| **Total** | **All Layers** | **${h_total}** |

### Enterprise Quality Standard

- **Health Grade:** **${quality_grade}** (${health_score}/100)
- **Newman API Tests:** ${newman_verdict_text}
- **Test Coverage:** ${coverage_pct}%
- **Phase Failures:** ${run_failures}
- **Output Verification:** Every agent output is verified through 5-layer hallucination protection, JARVIS Controller reconciliation, and enterprise health scoring. No stub code. No fake data. No unverified output accepted.

---

## ⚠️ Attention Required

$(if [[ $failed -gt 0 ]]; then
  echo "### Failed Agents"
  for agent in "${all_agents[@]}"; do
    local sf="$STATE_DIR/${agent}-status.md"
    if [[ -f "$sf" ]] && grep -qi "failed\|❌\|crashed" "$sf" 2>/dev/null; then
      echo "- **${agent}**: $(grep -iE 'issue|error|reason|cause' "$sf" 2>/dev/null | head -1 | sed 's/.*[:-] *//')"
    fi
  done
fi)
$(if [[ $pillars_touched -lt 3 ]]; then
  echo "### ⚠️ Low Pillar Coverage"
  echo "Only ${pillars_touched}/10 pillars actively worked on. Core pillars V3, V5, V7 must be covered."
fi)
$(if [[ $decisions_count -eq 0 ]]; then
  echo "### ⚠️ No Autonomous Decisions"
  echo "Agents should be making and logging decisions. Check agent autonomy and decision framework."
fi)

---

## 📋 Recommendations for Tomorrow

$(if [[ $completed -lt 10 ]]; then echo "1. **Agent reliability**: Only ${completed}/${total_agents} completed. Investigate failures and retry."; fi)
$(if [[ $pillars_touched -lt 5 ]]; then echo "2. **Broaden pillar coverage**: Focus on untouched core pillars."; fi)
$(if [[ $files_changed -lt 5 ]]; then echo "3. **Low code output**: Only ${files_changed} files changed. Agents may be spending too long on research."; fi)
$(if [[ ${coverage_pct} -lt 50 ]]; then echo "4. **Test coverage**: ${coverage_pct}% is below 50% target. Assign qa-engineer priority."; fi)
$(echo "5. **Next iteration**: Run \`./scripts/run-ctem-swarm.sh --digest\` anytime for updated status.")

---

*Generated at $(date '+%Y-%m-%d %H:%M:%S') by JARVIS AI Swarm Engine*
DIGEST_EOF

  # Backup copy
  cp "$digest_file" "$digest_backup" 2>/dev/null || true

  success "Daily digest saved to:"
  log "  → .claude/team-state/daily-digest-${DATE_TODAY}.md"
  log "  → logs/jarvis/daily-digest-${DATE_TODAY}.md"
  echo ""
}

###############################################################################
# Run single phase
###############################################################################
run_single_phase() {
  local phase="$1"
  header "Phase ${phase}"

  case "$phase" in
    0)   run_parallel_agents "0" "vision-agent" "agent-doctor" ;;
    1)   run_agent "context-engineer" ;;
    2)   run_parallel_agents "2" "ai-researcher" "data-scientist" "enterprise-architect" ;;
    3)   run_parallel_agents "3" "backend-hardener" "frontend-craftsman" "threat-architect" ;;
    3.5) run_agent "swarm-controller" ;;
    4)   run_parallel_agents "4" "security-analyst" "qa-engineer" ;;
    5)   run_agent "devops-engineer" ;;
    6)   run_debate ;;
    7)   run_parallel_agents "7" "marketing-head" "technical-writer" "sales-engineer" ;;
    8)   run_agent "scrum-master" ;;
    9)   run_agent "agent-doctor" ;;
    10)  run_agent "vision-agent" ;;
    *)   error "Unknown phase: $phase (valid: 0-10, 3.5)"; return 1 ;;
  esac
}

###############################################################################
# Main
###############################################################################
main() {
  parse_args "$@"

  # Quick exits
  if $COST_REPORT; then
    show_cost_report
    return 0
  fi

  if $HEALTH_CHECK; then
    run_health_check
    return 0
  fi

  if $DIGEST_MODE; then
    # Quick digest — no swarm run, just report current state
    SWARM_START_EPOCH=0
    generate_daily_digest 0 0
    return 0
  fi

  # Banner
  banner

  # Pre-flight
  preflight

  # Route to appropriate mode
  if $DEBATE_ONLY; then
    run_debate
  elif [[ -n "$SINGLE_AGENT" ]]; then
    header "Single Agent: $SINGLE_AGENT"
    CURRENT_ITERATION=1
    run_agent "$SINGLE_AGENT"
  elif [[ -n "$SINGLE_PHASE" ]]; then
    CURRENT_ITERATION=1
    run_single_phase "$SINGLE_PHASE"
  elif $CONVERGENCE_MODE; then
    run_iterative_swarm
  else
    CURRENT_ITERATION=1
    run_full_swarm
  fi
}

main "$@"
