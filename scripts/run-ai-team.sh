#!/usr/bin/env bash
###############################################################################
# ALdeci AI Team Orchestrator — 16 Senior Agents + Junior Swarm + Debate
# BUDGET: $350/month — 5-Tier Hybrid Runtime
#
# Runtime tiers:
#   ☁️  CLAUDE   ($100/mo)  — critical code/security (3 agents)
#   🤖 CODEX    ($20/mo)   — architecture + data science (2 agents)
#   🧠 GROK     ($30/mo)   — research + threats + debates/verify (2 agents)
#   🐙 COPILOT  ($39/mo)   — code generation + testing (3 agents)
#   🏠 OLLAMA   ($0)       — local inference (6 agents + juniors)
#   ───────────────────────
#   Committed: $189/mo | Buffer: $161/mo
#
# Schedule (not everything daily):
#   DAILY:     agent-doctor, context-engineer, backend-hardener, scrum-master
#   MON/WED/FRI: frontend-craftsman, qa, security, threat-architect
#   TUE/THU:   researcher, architect, data-sci, devops, tech-writer
#   FRIDAY:    marketing, sales (weekly)
#   SATURDAY:  junior swarm day (free on Ollama)
#   SUNDAY:    OFF
#
# Execution phases (dependency-ordered):
#   Phase 0: agent-doctor               (health check — pre-flight)
#   Phase 1: context-engineer            (foundation — codebase map)
#   Phase 2: ai-researcher + data-scientist + enterprise-architect  (parallel)
#   Phase 3: backend-hardener + frontend-craftsman + threat-architect  (parallel)
#   Phase 3.5: swarm-controller + junior swarm  (20-30 parallel juniors)
#   Phase 4: security-analyst + qa-engineer  (parallel — validate code)
#   Phase 5: devops-engineer             (infrastructure after code changes)
#   Phase 6: DEBATE ROUND — agents review + discuss proposals
#   Phase 7: marketing-head + technical-writer + sales-engineer  (parallel)
#   Phase 8: scrum-master  (reads ALL, resolves debates, produces demo)
#   Phase 9: agent-doctor  (post-run health audit + fix broken agents)
#
# Usage:
#   ./scripts/run-ai-team.sh                  # Run today's scheduled agents
#   ./scripts/run-ai-team.sh --all            # Force-run ALL 16 agents
#   ./scripts/run-ai-team.sh --agent backend-hardener   # Run one agent
#   ./scripts/run-ai-team.sh --dry-run        # Show plan without executing
#   ./scripts/run-ai-team.sh --demo-only      # Only run scrum-master (demo)
#   ./scripts/run-ai-team.sh --skip-debate    # Skip debate round
#   ./scripts/run-ai-team.sh --skip-swarm     # Skip junior swarm phase
#   ./scripts/run-ai-team.sh --builders-only  # Only phases 0-5 (no marketing)
#   ./scripts/run-ai-team.sh --cost-report    # Show estimated spend to date
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENTS_DIR="$PROJECT_ROOT/.claude/agents"
STATE_DIR="$PROJECT_ROOT/.claude/team-state"
LOG_DIR="$PROJECT_ROOT/logs/ai-team"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
DATE_TODAY=$(date +"%Y-%m-%d")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Defaults
DRY_RUN=false
SINGLE_AGENT=""
DEMO_ONLY=false
PARALLEL=true
TIMEOUT=600  # 10 min per agent
SKIP_DEBATE=false
BUILDERS_ONLY=false
SKIP_SWARM=false
FORCE_ALL=false
COST_REPORT=false

# Load budget config
BUDGET_CONFIG="$SCRIPT_DIR/budget-config.sh"
[[ -f "$BUDGET_CONFIG" ]] && source "$BUDGET_CONFIG"

# Day of week (1=Mon, 7=Sun)
DOW=$(date +%u)
DOW_NAME=$(date +%A)

TOTAL_AGENTS=16
ALL_AGENTS=(
  agent-doctor
  context-engineer
  ai-researcher data-scientist enterprise-architect
  backend-hardener frontend-craftsman threat-architect
  swarm-controller
  security-analyst qa-engineer
  devops-engineer
  marketing-head technical-writer sales-engineer
  scrum-master
)

###############################################################################
# Runtime tier mapping — which runtime runs which agent
# CLAUDE  = critical code/security ($100/mo subscription)
# CODEX   = structured analysis ($20/mo OpenAI Plus)
# GROK    = research + threats + debates/verify ($30/mo SuperGrok)
# COPILOT = code generation ($39/mo Pro+)
# OLLAMA  = free local inference (qwen2.5-coder:14b)
###############################################################################
_agent_runtime() {
  case "$1" in
    agent-doctor|backend-hardener|security-analyst) echo "claude" ;;
    enterprise-architect|data-scientist) echo "codex" ;;
    threat-architect|ai-researcher) echo "grok" ;;
    frontend-craftsman|qa-engineer|devops-engineer) echo "copilot" ;;
    *) echo "ollama" ;;
  esac
}

###############################################################################
# Schedule — which agents run on which day
#   DAILY:      agent-doctor, context-engineer, backend-hardener, scrum-master
#   MON/WED/FRI: + frontend-craftsman, qa, security, threat-architect
#   TUE/THU:    + researcher, architect, data-sci, devops, tech-writer
#   FRIDAY:     + marketing, sales
#   SATURDAY:   + swarm day (juniors only)
#   SUNDAY:     OFF
###############################################################################
DAILY_AGENTS=(agent-doctor context-engineer backend-hardener scrum-master)
MWF_AGENTS=(frontend-craftsman qa-engineer security-analyst threat-architect)
TTH_AGENTS=(ai-researcher enterprise-architect data-scientist devops-engineer technical-writer)
FRI_AGENTS=(marketing-head sales-engineer)
SAT_AGENTS=(swarm-controller)

get_scheduled_agents() {
  local agents=("${DAILY_AGENTS[@]}")

  case $DOW in
    1|3|5) agents+=("${MWF_AGENTS[@]}") ;;           # Mon/Wed/Fri
    2|4)   agents+=("${TTH_AGENTS[@]}") ;;            # Tue/Thu
  esac
  [[ $DOW -eq 5 ]] && agents+=("${FRI_AGENTS[@]}")   # Friday
  [[ $DOW -eq 6 ]] && agents+=("${SAT_AGENTS[@]}")   # Saturday

  echo "${agents[@]}"
}

###############################################################################
# Parse arguments
###############################################################################
while [[ $# -gt 0 ]]; do
  case $1 in
    --agent)     SINGLE_AGENT="$2"; shift 2 ;;
    --dry-run)   DRY_RUN=true; shift ;;
    --demo-only) DEMO_ONLY=true; shift ;;
    --no-parallel) PARALLEL=false; shift ;;
    --timeout)   TIMEOUT="$2"; shift 2 ;;
    --skip-debate) SKIP_DEBATE=true; shift ;;
    --builders-only) BUILDERS_ONLY=true; shift ;;
    --skip-swarm) SKIP_SWARM=true; shift ;;
    --all) FORCE_ALL=true; shift ;;
    --cost-report) COST_REPORT=true; shift ;;
    -h|--help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --agent NAME      Run a single agent (any of: ${ALL_AGENTS[*]})"
      echo "  --dry-run         Show execution plan without running agents"
      echo "  --demo-only       Run only the scrum-master to produce daily demo"
      echo "  --no-parallel     Run all agents sequentially"
      echo "  --skip-debate     Skip the multi-agent debate round"
      echo "  --skip-swarm      Skip junior swarm phase"
      echo "  --builders-only   Only run builder agents (phases 0-5), skip marketing/demo"
      echo "  --all             Force-run ALL agents regardless of schedule"
      echo "  --cost-report     Show estimated spend this month"
      echo "  --timeout SECS    Timeout per agent (default: 600)"
      echo "  -h, --help        Show this help"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

###############################################################################
# Helpers
###############################################################################
log() { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }
header() {
  echo ""
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}${CYAN}  $*${NC}"
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_runtimes() {
  if $DRY_RUN; then
    log "Runtimes: [dry-run — skipping check]"
    return 0
  fi
  # Check available runtimes — none are hard requirements in hybrid mode
  if command -v claude &>/dev/null; then
    log "☁️  Claude CLI: $(claude --version 2>/dev/null || echo 'available')"
  else
    warn "Claude CLI not installed — Claude-tier agents will fall back"
    log "  Install: npm install -g @anthropic-ai/claude-code"
  fi
  if command -v codex &>/dev/null; then
    log "🤖 Codex CLI: available"
  else
    warn "OpenAI Codex CLI not installed — Codex-tier agents will fall back"
    log "  Install: npm install -g @openai/codex"
  fi
  if command -v copilot &>/dev/null || command -v gh &>/dev/null; then
    log "🐙 GitHub Copilot: available"
  else
    warn "GitHub Copilot CLI not found — Copilot-tier agents will fall back"
    log "  Install: gh extension install github/gh-copilot"
  fi
  if [[ -n "${XAI_API_KEY:-}" ]]; then
    log "🧠 Grok/xAI API: key configured (agents + debates + verify)"
  else
    warn "XAI_API_KEY not set — Grok-tier agents will fall back"
    log "  Get key: https://console.x.ai/api"
  fi
  if command -v ollama &>/dev/null; then
    log "🏠 Ollama: $(ollama --version 2>/dev/null || echo 'available')"
  else
    warn "Ollama not installed — local agents will be skipped"
    log "  Install: brew install ollama && ollama pull qwen2.5-coder:14b"
  fi
}

ensure_dirs() {
  mkdir -p "$LOG_DIR"
  mkdir -p "$STATE_DIR"/{research,marketing/{content,battlecards},architecture/{adrs,reviews}}
  mkdir -p "$STATE_DIR"/{debates/{active,resolved},data-science/models,sales/{demo-scripts,poc-templates},qa,threat-architect/{architectures,threat-models,feeds}}
  mkdir -p "$STATE_DIR"/swarm/{assignments,outputs,verifications}
}

###############################################################################
# Determine runtime for an agent
###############################################################################
get_runtime() {
  local agent="$1"
  _agent_runtime "$agent"
}

runtime_label() {
  case "$1" in
    claude)  echo "☁️  Claude (opus)" ;;
    codex)   echo "🤖 Codex (OpenAI)" ;;
    grok)    echo "🧠 Grok (xAI)" ;;
    copilot) echo "🐙 Copilot (Pro+)" ;;
    ollama)  echo "🏠 Ollama (local)" ;;
    *)       echo "❓ $1" ;;
  esac
}

###############################################################################
# Check if an agent is scheduled today
###############################################################################
is_scheduled() {
  local agent="$1"
  if $FORCE_ALL; then return 0; fi
  local scheduled
  scheduled=$(get_scheduled_agents)
  [[ " $scheduled " == *" $agent "* ]]
}

###############################################################################
# Cost tracker — append to daily spend log
###############################################################################
track_cost() {
  local agent="$1" runtime="$2" duration="$3"
  local cost=0.00
  case "$runtime" in
    claude)  cost="5.00" ;;   # ~$5 per claude run
    codex)   cost="0.50" ;;   # Plus subscription
    grok)    cost="0.50" ;;   # SuperGrok subscription
    copilot) cost="0.25" ;;   # Pro+ subscription
    ollama)  cost="0.00" ;;   # Free
  esac
  echo "${DATE_TODAY},${agent},${runtime},${duration}s,\$${cost}" >> "$STATE_DIR/cost-log.csv"
}

###############################################################################
# Show cost report
###############################################################################
show_cost_report() {
  local cost_file="$STATE_DIR/cost-log.csv"
  if [[ ! -f "$cost_file" ]]; then
    log "No cost data yet. Run agents first."
    return
  fi

  header "Cost Report — $(date +%B\ %Y)"

  local month_prefix=$(date +%Y-%m)
  local claude_runs codex_runs grok_runs copilot_runs ollama_runs

  claude_runs=$(grep "^${month_prefix}.*,claude," "$cost_file" 2>/dev/null | wc -l | tr -d ' ')
  codex_runs=$(grep "^${month_prefix}.*,codex," "$cost_file" 2>/dev/null | wc -l | tr -d ' ')
  grok_runs=$(grep "^${month_prefix}.*,grok," "$cost_file" 2>/dev/null | wc -l | tr -d ' ')
  copilot_runs=$(grep "^${month_prefix}.*,copilot," "$cost_file" 2>/dev/null | wc -l | tr -d ' ')
  ollama_runs=$(grep "^${month_prefix}.*,ollama," "$cost_file" 2>/dev/null | wc -l | tr -d ' ')

  local claude_var=$(echo "$claude_runs * 5.00" | bc 2>/dev/null || echo "0")
  local codex_var=$(echo "$codex_runs * 0.50" | bc 2>/dev/null || echo "0")
  local grok_var=$(echo "$grok_runs * 0.50" | bc 2>/dev/null || echo "0")
  local copilot_var=$(echo "$copilot_runs * 0.25" | bc 2>/dev/null || echo "0")

  echo "  ☁️  Claude runs:  $claude_runs  (~\$${claude_var} variable + \$100 sub)"
  echo "  🤖 Codex runs:   $codex_runs  (~\$${codex_var} variable + \$20 sub)"
  echo "  🧠 Grok runs:    $grok_runs  (~\$${grok_var} variable + \$30 sub)"
  echo "  🐙 Copilot runs: $copilot_runs  (~\$${copilot_var} variable + \$39 sub)"
  echo "  🏠 Ollama runs:  $ollama_runs  (\$0 — free)"
  echo "  ─────────────────────────────────────"
  local subs=189
  local var_total=$(echo "$claude_var + $codex_var + $grok_var + $copilot_var" | bc 2>/dev/null || echo "0")
  local total=$(echo "$subs + $var_total" | bc 2>/dev/null || echo "$subs")
  local remaining=$(echo "350 - $total" | bc 2>/dev/null || echo "161")
  echo "  Subscriptions:  \$${subs}/mo (Claude+Codex+Grok+Copilot)"
  echo "  Variable usage: ~\$${var_total}"
  echo "  Est. total:     ~\$${total}"
  echo "  Budget:         \$350/month"
  echo "  Remaining:      ~\$${remaining}"
  echo ""
  echo "  Recent runs:"
  tail -10 "$cost_file" 2>/dev/null | column -t -s',' 2>/dev/null || tail -10 "$cost_file"
}

###############################################################################
# Run a single agent — dispatches to correct runtime
###############################################################################
run_agent() {
  local agent_name="$1"
  local agent_file="$AGENTS_DIR/${agent_name}.md"
  local log_file="$LOG_DIR/${DATE_TODAY}_${agent_name}.log"
  local runtime
  runtime=$(get_runtime "$agent_name")

  if [[ ! -f "$agent_file" ]]; then
    error "Agent file not found: $agent_file"
    return 1
  fi

  log "Starting agent: ${BOLD}${agent_name}${NC}  [$(runtime_label "$runtime")]"

  if $DRY_RUN; then
    log "[DRY RUN] Would run via $runtime: $agent_name"
    return 0
  fi

  # Record start time
  local start_time=$(date +%s)
  local agent_timeout="$TIMEOUT"

  # Set timeout per tier
  case "$runtime" in
    claude)  agent_timeout=300 ;;
    codex)   agent_timeout=300 ;;
    grok)    agent_timeout=300 ;;
    copilot) agent_timeout=300 ;;
    ollama)  agent_timeout=600 ;;
  esac

  # Write agent status: running
  cat > "$STATE_DIR/${agent_name}-status.md" <<EOF
# ${agent_name} Status
- **Status:** 🔄 Running
- **Runtime:** ${runtime}
- **Started:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")
- **Log:** logs/ai-team/${DATE_TODAY}_${agent_name}.log
EOF

  local prompt="Execute your daily mission for ${DATE_TODAY}. Read your instructions carefully, produce all required artifacts, and write your status to .claude/team-state/${agent_name}-status.md when done."
  local run_ok=false

  # ── Fallback chain: assigned tier → codex → copilot → grok → ollama ──
  # Each block tries its runtime; on failure sets runtime to next in chain.

  # TIER 1: Claude Code CLI
  if [[ "$runtime" == "claude" ]]; then
    if command -v claude &>/dev/null; then
      timeout "$agent_timeout" claude --agent "$agent_name" \
        --print --output-format text \
        -p "$prompt" \
        > "$log_file" 2>&1 && run_ok=true
    else
      warn "Claude CLI unavailable — falling back to Codex for $agent_name"
      runtime="codex"
    fi
  fi

  # TIER 2: OpenAI Codex CLI
  if [[ "$runtime" == "codex" ]] && ! $run_ok; then
    if command -v codex &>/dev/null; then
      local agent_context
      agent_context=$(head -60 "$agent_file" | tail -50 | tr '\n' ' ')
      timeout "$agent_timeout" codex \
        -q "You are ${agent_name}. ${agent_context} ${prompt}" \
        > "$log_file" 2>&1 && run_ok=true
    else
      warn "Codex CLI unavailable — falling back to Copilot for $agent_name"
      runtime="copilot"
    fi
  fi

  # TIER 3: SuperGrok / xAI API
  if [[ "$runtime" == "grok" ]] && ! $run_ok; then
    if [[ -n "${XAI_API_KEY:-}" ]]; then
      local grok_script
      grok_script=$(mktemp /tmp/grok-XXXXXX.sh)
      local sys_content
      sys_content=$(python3 -c "import json; print(json.dumps(open('$agent_file').read()))" 2>/dev/null || echo '""')
      local usr_content
      usr_content=$(python3 -c "import json; print(json.dumps('$prompt'))" 2>/dev/null || echo '""')
      cat > "$grok_script" <<GROKEOF
#!/usr/bin/env bash
curl -s https://api.x.ai/v1/chat/completions \
  -H "Authorization: Bearer ${XAI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model":"${GROK_MODEL:-grok-3}","messages":[{"role":"system","content":${sys_content}},{"role":"user","content":${usr_content}}],"max_tokens":4096}' \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r["choices"][0]["message"]["content"])' 2>/dev/null
GROKEOF
      chmod +x "$grok_script"
      timeout "$agent_timeout" bash "$grok_script" > "$log_file" 2>&1 && run_ok=true
      rm -f "$grok_script"
    else
      warn "xAI API key unavailable — falling back to Ollama for $agent_name"
      runtime="ollama"
    fi
  fi

  # TIER 4: GitHub Copilot (via gh copilot or coding agent)
  if [[ "$runtime" == "copilot" ]] && ! $run_ok; then
    if command -v gh &>/dev/null && gh copilot --help &>/dev/null 2>&1; then
      local agent_context
      agent_context=$(head -60 "$agent_file" | tail -50 | tr '\n' ' ')
      timeout "$agent_timeout" gh copilot suggest \
        "You are ${agent_name}. ${agent_context} ${prompt}" \
        > "$log_file" 2>&1 && run_ok=true
    elif command -v copilot &>/dev/null; then
      timeout "$agent_timeout" copilot \
        -p "You are ${agent_name}. ${prompt}" \
        > "$log_file" 2>&1 && run_ok=true
    else
      warn "Copilot CLI unavailable — falling back to Grok for $agent_name"
      runtime="grok"
    fi
  fi

  # TIER 5: Ollama (free local — last resort)
  if [[ "$runtime" == "ollama" ]] && ! $run_ok; then
    if command -v ollama &>/dev/null; then
      ollama list 2>/dev/null | grep -q "${OLLAMA_MODEL:-qwen2.5-coder:14b}" || \
        ollama pull "${OLLAMA_MODEL:-qwen2.5-coder:14b}" 2>/dev/null

      local agent_context
      agent_context=$(head -50 "$agent_file" | tail -40 | tr -d "'" | tr '\n' ' ')
      timeout "$agent_timeout" ollama run "${OLLAMA_MODEL:-qwen2.5-coder:14b}" \
        "You are ${agent_name}. ${agent_context} ${prompt}" \
        > "$log_file" 2>&1 && run_ok=true
    else
      warn "Ollama not installed — skipping $agent_name"
      echo "SKIPPED: No runtime available" > "$log_file"
    fi
  fi

  local end_time=$(date +%s)
  local duration=$(( end_time - start_time ))

  if $run_ok; then
    cat > "$STATE_DIR/${agent_name}-status.md" <<EOF
# ${agent_name} Status
- **Status:** ✅ Completed
- **Runtime:** ${runtime}
- **Date:** ${DATE_TODAY}
- **Duration:** ${duration}s
- **Log:** logs/ai-team/${DATE_TODAY}_${agent_name}.log
EOF
    success "${agent_name} completed in ${duration}s via $runtime"
    track_cost "$agent_name" "$runtime" "$duration"
  else
    local fail_reason="Failed"
    cat > "$STATE_DIR/${agent_name}-status.md" <<EOF
# ${agent_name} Status
- **Status:** ❌ ${fail_reason}
- **Runtime:** ${runtime}
- **Date:** ${DATE_TODAY}
- **Duration:** ${duration}s
- **Log:** logs/ai-team/${DATE_TODAY}_${agent_name}.log
EOF
    warn "${agent_name}: ${fail_reason} (check log: $log_file)"
    track_cost "$agent_name" "$runtime" "$duration"
    return 1
  fi
}

###############################################################################
# Run debate round — all agents review active proposals
###############################################################################
run_debate_round() {
  local debate_dir="$STATE_DIR/debates/active"
  local debate_count=$(find "$debate_dir" -name "debate-*.md" 2>/dev/null | wc -l | tr -d ' ')

  if [[ "$debate_count" -eq 0 ]]; then
    log "No active debates — skipping debate round"
    return 0
  fi

  header "Phase 6 — DEBATE ROUND ($debate_count active debates)"
  log "Active debates: $debate_count"

  # Only scheduled agents participate in debates today
  local debate_candidates=(
    agent-doctor backend-hardener frontend-craftsman threat-architect security-analyst qa-engineer
    devops-engineer enterprise-architect data-scientist ai-researcher
  )
  local debate_agents=()
  for agent in "${debate_candidates[@]}"; do
    is_scheduled "$agent" && debate_agents+=("$agent")
  done

  if [[ ${#debate_agents[@]} -eq 0 ]]; then
    log "No debate participants scheduled today — skipping"
    return 0
  fi
  log "Debate participants today: ${#debate_agents[@]}"

  for agent in "${debate_agents[@]}"; do
    local agent_file="$AGENTS_DIR/${agent}.md"
    [[ ! -f "$agent_file" ]] && continue
    local runtime
    runtime=$(get_runtime "$agent")

    log "  Debate participant: ${BOLD}${agent}${NC}  [$(runtime_label "$runtime")]"

    if $DRY_RUN; then
      log "  [DRY RUN] Would run: $agent via $runtime (debate mode)"
      continue
    fi

    local debate_log="$LOG_DIR/${DATE_TODAY}_debate_${agent}.log"
    local debate_prompt="DEBATE MODE: Read all proposals in .claude/team-state/debates/active/ and write your response to each debate. Use the format: '### Response from ${agent} — SUPPORT|CHALLENGE|MODIFY|ABSTAIN' with Argument, Evidence, and Counter-proposal (if MODIFY). Be concise but evidence-based."
    local debate_usr
    debate_usr=$(python3 -c "import json; print(json.dumps('$debate_prompt'))" 2>/dev/null || echo '""')

    # Dispatch debate to agent's assigned runtime (same 6-tier system)
    case "$runtime" in
      claude)
        if command -v claude &>/dev/null; then
          timeout 300 claude --agent "$agent" \
            --print --output-format text \
            -p "$debate_prompt" \
            > "$debate_log" 2>&1 || warn "  ${agent} debate failed (claude)"
        fi ;;
      codex)
        if command -v codex &>/dev/null; then
          timeout 300 codex -q "You are ${agent}. ${debate_prompt}" \
            > "$debate_log" 2>&1 || warn "  ${agent} debate failed (codex)"
        fi ;;
      grok)
        if [[ -n "${XAI_API_KEY:-}" ]]; then
          local ds=$(mktemp /tmp/grok-debate-XXXXXX.sh)
          cat > "$ds" <<DGEOF
#!/usr/bin/env bash
curl -s https://api.x.ai/v1/chat/completions \
  -H "Authorization: Bearer ${XAI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model":"${GROK_MODEL:-grok-3}","messages":[{"role":"system","content":"You are ${agent}."},{"role":"user","content":${debate_usr}}],"max_tokens":2048}' \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r["choices"][0]["message"]["content"])' 2>/dev/null
DGEOF
          chmod +x "$ds"
          timeout 300 bash "$ds" > "$debate_log" 2>&1 || warn "  ${agent} debate failed (grok)"
          rm -f "$ds"
        fi ;;
      copilot)
        if command -v gh &>/dev/null; then
          timeout 300 gh copilot suggest "You are ${agent}. ${debate_prompt}" \
            > "$debate_log" 2>&1 || warn "  ${agent} debate failed (copilot)"
        fi ;;
      ollama)
        if command -v ollama &>/dev/null; then
          timeout 300 ollama run "${OLLAMA_MODEL:-qwen2.5-coder:14b}" \
            "You are ${agent}. ${debate_prompt}" \
            > "$debate_log" 2>&1 || warn "  ${agent} debate failed (ollama)"
        fi ;;
    esac
  done

  success "Debate round complete (${#debate_agents[@]} participants)"
}

###############################################################################
# Run the full 14-agent team in dependency order + debate
###############################################################################
run_full_team() {
  local start_total=$(date +%s)
  local failed=0

  header "ALdeci AI Team — ${DOW_NAME} ${DATE_TODAY} (Budget: \$350/mo)"

  # Show today's schedule
  local scheduled_today
  scheduled_today=$(get_scheduled_agents)
  local scheduled_count
  scheduled_count=$(echo "$scheduled_today" | wc -w | tr -d ' ')

  log "Project root: $PROJECT_ROOT"
  log "Day:          $DOW_NAME ($( $FORCE_ALL && echo 'FORCE ALL' || echo "schedule: $scheduled_count agents" ))"
  log "Timeout:      ${TIMEOUT}s per agent"
  log "Parallel:     $PARALLEL"
  log "Debate:       $( $SKIP_DEBATE && echo 'skipped' || echo 'enabled')"
  log "Swarm:        $( $SKIP_SWARM && echo 'skipped' || echo 'enabled')"
  log "Mode:         $( $BUILDERS_ONLY && echo 'builders-only' || echo 'full team')"

  if ! $FORCE_ALL; then
    log "Scheduled:    $scheduled_today"
    echo ""
    log "Runtimes:"
    for a in $scheduled_today; do
      log "  $a → $(runtime_label "$(get_runtime "$a")")"
    done
  fi
  echo ""

  # Sunday = OFF
  if [[ $DOW -eq 7 ]] && ! $FORCE_ALL; then
    log "🌙 Sunday — team is OFF. Use --all to force-run."
    return 0
  fi

  # ── Phase 0: Agent Doctor — Pre-Flight Health Check ───────────────────
  if is_scheduled "agent-doctor"; then
    header "Phase 0 — Agent Doctor (pre-flight health check)"
    run_agent "agent-doctor" || warn "Agent Doctor pre-flight had issues (continuing)"
  fi

  # ── Phase 1: Context Engineer (foundational) ──────────────────────────
  if is_scheduled "context-engineer"; then
    header "Phase 1 — Context Engineer (foundation)"
    run_agent "context-engineer" || ((failed++))
  fi

  # ── Phase 2: Research + Data + Architecture (parallel) ────────────────
  local phase2_agents=()
  is_scheduled "ai-researcher" && phase2_agents+=("ai-researcher")
  is_scheduled "data-scientist" && phase2_agents+=("data-scientist")
  is_scheduled "enterprise-architect" && phase2_agents+=("enterprise-architect")

  if [[ ${#phase2_agents[@]} -gt 0 ]]; then
    header "Phase 2 — Research + Data + Architecture (${#phase2_agents[@]} agents)"
    if $PARALLEL && [[ ${#phase2_agents[@]} -gt 1 ]]; then
      local p2_pids=();
      for a in "${phase2_agents[@]}"; do run_agent "$a" & p2_pids+=($!); done
      for pid in "${p2_pids[@]}"; do wait "$pid" || ((failed++)); done
    else
      for a in "${phase2_agents[@]}"; do run_agent "$a" || ((failed++)); done
    fi
  fi

  # ── Phase 3: Builders (parallel, schedule-aware) ──────────────────────
  local phase3_agents=()
  is_scheduled "backend-hardener" && phase3_agents+=("backend-hardener")
  is_scheduled "frontend-craftsman" && phase3_agents+=("frontend-craftsman")
  is_scheduled "threat-architect" && phase3_agents+=("threat-architect")

  if [[ ${#phase3_agents[@]} -gt 0 ]]; then
    header "Phase 3 — Builders (${#phase3_agents[@]} agents)"
    if $PARALLEL && [[ ${#phase3_agents[@]} -gt 1 ]]; then
      local p3_pids=();
      for a in "${phase3_agents[@]}"; do run_agent "$a" & p3_pids+=($!); done
      for pid in "${p3_pids[@]}"; do wait "$pid" || ((failed++)); done
    else
      for a in "${phase3_agents[@]}"; do run_agent "$a" || ((failed++)); done
    fi
  fi

  # ── Phase 3.5: Junior Swarm (Saturdays + when scheduled) ──────────────
  if ! $SKIP_SWARM && is_scheduled "swarm-controller"; then
    header "Phase 3.5 — Junior Swarm (Ollama, free)"
    run_agent "swarm-controller" || warn "Swarm controller had issues"

    if [[ -x "$SCRIPT_DIR/spawn-swarm.sh" ]]; then
      log "Spawning junior workers..."
      if $DRY_RUN; then
        bash "$SCRIPT_DIR/spawn-swarm.sh" --dry-run 2>&1 | tail -20
      else
        bash "$SCRIPT_DIR/spawn-swarm.sh" --wave-size 10 2>&1 | tail -30 || warn "Some swarm workers had issues"
      fi
      success "Junior swarm phase complete"
    fi
  fi

  # ── Phase 4: Validators (parallel, schedule-aware) ────────────────────
  local phase4_agents=()
  is_scheduled "security-analyst" && phase4_agents+=("security-analyst")
  is_scheduled "qa-engineer" && phase4_agents+=("qa-engineer")

  if [[ ${#phase4_agents[@]} -gt 0 ]]; then
    header "Phase 4 — Validators (${#phase4_agents[@]} agents)"
    if $PARALLEL && [[ ${#phase4_agents[@]} -gt 1 ]]; then
      local p4_pids=();
      for a in "${phase4_agents[@]}"; do run_agent "$a" & p4_pids+=($!); done
      for pid in "${p4_pids[@]}"; do wait "$pid" || ((failed++)); done
    else
      for a in "${phase4_agents[@]}"; do run_agent "$a" || ((failed++)); done
    fi
  fi

  # ── Phase 5: DevOps (schedule-aware) ──────────────────────────────────
  if is_scheduled "devops-engineer"; then
    header "Phase 5 — DevOps Engineer"
    run_agent "devops-engineer" || ((failed++))
  fi

  # ── Phase 6: Debate Round (schedule-aware) ────────────────────────────
  if ! $SKIP_DEBATE; then
    run_debate_round
  else
    log "Debate round skipped (--skip-debate)"
  fi

  if ! $BUILDERS_ONLY; then
    # ── Phase 7: Go-to-Market (parallel, schedule-aware) ──────────────
    local phase7_agents=()
    is_scheduled "marketing-head" && phase7_agents+=("marketing-head")
    is_scheduled "technical-writer" && phase7_agents+=("technical-writer")
    is_scheduled "sales-engineer" && phase7_agents+=("sales-engineer")

    if [[ ${#phase7_agents[@]} -gt 0 ]]; then
      header "Phase 7 — Go-to-Market (${#phase7_agents[@]} agents)"
      if $PARALLEL && [[ ${#phase7_agents[@]} -gt 1 ]]; then
        local p7_pids=();
        for a in "${phase7_agents[@]}"; do run_agent "$a" & p7_pids+=($!); done
        for pid in "${p7_pids[@]}"; do wait "$pid" || ((failed++)); done
      else
        for a in "${phase7_agents[@]}"; do run_agent "$a" || ((failed++)); done
      fi
    fi

    # ── Phase 8: Scrum Master (schedule-aware) ────────────────────────
    if is_scheduled "scrum-master"; then
      header "Phase 8 — Scrum Master (daily demo + debate resolution)"
      run_agent "scrum-master" || ((failed++))
    fi
  else
    log "Phases 7-8 skipped (--builders-only)"
  fi

  # ── Phase 9: Agent Doctor — Post-Run Health Audit (schedule-aware) ────
  if is_scheduled "agent-doctor"; then
    header "Phase 9 — Agent Doctor (post-run health audit)"
    run_agent "agent-doctor" || warn "Agent Doctor post-run audit had issues"
  fi

  # ── Generate Daily Demo Report ────────────────────────────────────────
  if [[ -x "$SCRIPT_DIR/generate-daily-demo.sh" ]]; then
    log "Generating daily demo report..."
    bash "$SCRIPT_DIR/generate-daily-demo.sh" "$DATE_TODAY" 2>/dev/null || warn "Demo report generation failed"
  fi

  # ── Summary ───────────────────────────────────────────────────────────
  local end_total=$(date +%s)
  local total_duration=$(( end_total - start_total ))
  local agents_run="$scheduled_count"

  echo ""
  header "Run Complete — $DOW_NAME"
  log "Total time: ${total_duration}s ($(( total_duration / 60 ))m $(( total_duration % 60 ))s)"
  log "Failed agents: ${failed}/${agents_run}"
  [[ $failed -eq 0 ]] && success "All scheduled agents completed successfully!" || warn "${failed} agent(s) had issues"
  log "Daily demo: .claude/team-state/daily-demo-${DATE_TODAY}.md"
  log "Cost log:   .claude/team-state/cost-log.csv"
  log "Full logs:  $LOG_DIR/"

  # Write run summary
  cat > "$STATE_DIR/last-run-summary.md" <<EOF
# AI Team Run Summary — ${DATE_TODAY} ($DOW_NAME)
- **Date:** ${DATE_TODAY}
- **Day:** ${DOW_NAME}
- **Duration:** ${total_duration}s ($(( total_duration / 60 ))m)
- **Agents Scheduled:** ${agents_run} / $TOTAL_AGENTS
- **Failed:** ${failed}/${agents_run}
- **Mode:** $( $BUILDERS_ONLY && echo 'builders-only' || echo 'full team')
- **Budget:** \$350/month (3-tier hybrid)

## Agent Status
| Phase | Agent | Runtime | Status |
|-------|-------|---------|--------|
EOF

  # Dynamically build summary table from scheduled agents
  local summary_agents=(
    "0|agent-doctor"
    "1|context-engineer"
    "2|ai-researcher"
    "2|data-scientist"
    "2|enterprise-architect"
    "3|backend-hardener"
    "3|frontend-craftsman"
    "3|threat-architect"
    "3.5|swarm-controller"
    "4|security-analyst"
    "4|qa-engineer"
    "5|devops-engineer"
    "7|marketing-head"
    "7|technical-writer"
    "7|sales-engineer"
    "8|scrum-master"
    "9|agent-doctor"
  )

  for entry in "${summary_agents[@]}"; do
    local phase="${entry%%|*}"
    local agent="${entry##*|}"
    local rt=$(get_runtime "$agent")
    local rt_icon
    case "$rt" in
      claude)  rt_icon="☁️ claude" ;;
      codex)   rt_icon="🤖 codex" ;;
      grok)    rt_icon="🧠 grok" ;;
      copilot) rt_icon="🐙 copilot" ;;
      ollama)  rt_icon="🏠 ollama" ;;
      *)       rt_icon="$rt" ;;
    esac
    local status
    if is_scheduled "$agent"; then
      status=$(grep -o 'Status:.*' "$STATE_DIR/${agent}-status.md" 2>/dev/null || echo 'unknown')
    else
      status="⏭️ not scheduled ($DOW_NAME)"
    fi
    echo "| $phase | $agent | $rt_icon | $status |" >> "$STATE_DIR/last-run-summary.md"
  done

  echo "" >> "$STATE_DIR/last-run-summary.md"
  echo "## Cost" >> "$STATE_DIR/last-run-summary.md"
  echo "See \`.claude/team-state/cost-log.csv\` for detailed cost tracking." >> "$STATE_DIR/last-run-summary.md"

  return $failed
}

###############################################################################
# Main
###############################################################################
main() {
  check_runtimes
  ensure_dirs

  if $COST_REPORT; then
    show_cost_report
    return 0
  fi

  if [[ -n "$SINGLE_AGENT" ]]; then
    header "Running single agent: $SINGLE_AGENT"
    run_agent "$SINGLE_AGENT"
  elif $DEMO_ONLY; then
    header "Demo-only mode: running Scrum Master"
    run_agent "scrum-master"
  else
    run_full_team
  fi
}

main "$@"
