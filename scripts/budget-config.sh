###############################################################################
# ALdeci AI Team — Budget Configuration ($350/month)
#
# Five runtime tiers:
#   TIER 1 (Claude Code)   — opus/sonnet via CLI subscription     $100/mo
#   TIER 2 (OpenAI Codex)  — Codex CLI (Plus subscription)        $20/mo
#   TIER 3 (Grok)          — xAI API (SuperGrok subscription)     $30/mo
#   TIER 4 (GitHub Copilot)— Copilot Pro+ agent/CLI               $39/mo
#   TIER 5 (Ollama local)  — free, Mac M-series 24GB              $0
#
# Budget breakdown:
#   Claude Max subscription:   $100/month
#   OpenAI Plus (Codex CLI):   $20/month
#   Grok (SuperGrok/xAI):      $30/month
#   GitHub Copilot Pro+:       $39/month
#   Ollama:                    $0 (local)
#   ──────────────────────────────────
#   Committed:                 $189/month
#   Buffer:                    $161/month
#   Total budget:              $350/month
###############################################################################

###############################################################################
# RUNTIME CONFIGURATION
###############################################################################

# Tier 1 — Claude Code ($100/mo subscription)
# Critical agents that WRITE CODE or make SECURITY DECISIONS
CLAUDE_AGENTS=(
  backend-hardener      # WRITES production code — opus quality required
  security-analyst      # VETO power, compliance — can't be wrong
  agent-doctor          # Fixes other agents — needs deep understanding
)
CLAUDE_TIMEOUT=300

# Tier 2 — OpenAI Codex CLI ($20/mo Plus subscription)
# Strong at structured analysis, architecture, data work
CODEX_MODEL="${CODEX_MODEL:-o4-mini}"
CODEX_AGENTS=(
  enterprise-architect  # ADRs, system design — Codex excels at structured output
  data-scientist        # ML models, analysis — strong at math/reasoning
)
CODEX_TIMEOUT=300

# Tier 3 — Grok / xAI ($30/mo SuperGrok subscription)
# Grok excels at research, threat analysis, real-time knowledge
# Also used for debates, verification, and fallback
GROK_MODEL="${GROK_MODEL:-grok-3}"
GROK_AGENTS=(
  threat-architect      # Threat models + real-world attack research
  ai-researcher         # Research + trend analysis — Grok's real-time edge
)
GROK_TIMEOUT=300

# Tier 4 — GitHub Copilot Pro+ ($39/mo)
# Best-in-class for code generation, testing, DevOps configs
COPILOT_AGENTS=(
  frontend-craftsman    # UI code — Copilot's bread and butter
  qa-engineer           # Test generation — Copilot excels here
  devops-engineer       # Docker, CI/CD, configs — very accurate
)
COPILOT_TIMEOUT=300

# Tier 5 — Ollama (FREE, local)
# 24GB Mac = qwen2.5-coder:14b for lightweight tasks
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5-coder:14b}"
OLLAMA_AGENTS=(
  context-engineer      # Reads code, writes summaries
  marketing-head        # Content writing
  technical-writer      # Docs generation
  sales-engineer        # Demo scripts
  scrum-master          # Status reports, sprint management
  swarm-controller      # Task decomposition, JSON dispatch
)
OLLAMA_TIMEOUT=600

# Junior swarm — Ollama (free) with Grok verification (~$0.50/check)
JUNIOR_RUNTIME="ollama"
JUNIOR_MODEL="qwen2.5-coder:14b"
JUNIOR_VERIFY_RUNTIME="grok"

###############################################################################
# SCHEDULING — Not all agents every day
###############################################################################

# Daily (critical path)
#   backend-hardener  (☁️ claude)
#   context-engineer  (🏠 ollama, free)
#   scrum-master      (🏠 ollama, free)
#   agent-doctor      (☁️ claude, Phase 0 + 9)

# Mon/Wed/Fri (builders + validators)
#   frontend-craftsman (🐙 copilot)
#   qa-engineer        (🐙 copilot)
#   security-analyst   (☁️ claude)
#   threat-architect   (🧠 grok)

# Tue/Thu (research + docs + strategy)
#   ai-researcher        (🧠 grok)
#   enterprise-architect (🤖 codex)
#   data-scientist       (🤖 codex)
#   devops-engineer      (🐙 copilot)
#   technical-writer     (🏠 ollama, free)

# Friday only (go-to-market)
#   marketing-head  (🏠 ollama, free)
#   sales-engineer  (🏠 ollama, free)

# Saturday: Junior swarm day (30 parallel, Ollama=free, Grok verify)
# Sunday: OFF

###############################################################################
# COST TRACKING
###############################################################################

# Monthly budget
MONTHLY_BUDGET_USD=350
CLAUDE_BUDGET_USD=100    # Subscription
CODEX_BUDGET_USD=20      # OpenAI Plus
GROK_BUDGET_USD=30       # SuperGrok (also covers debates/verification)
COPILOT_BUDGET_USD=39    # Pro+
COMMITTED_USD=189
RESERVE_USD=161

# Per-run cost estimates (for tracking)
cost_per_run() {
  case "$1" in
    claude) echo "5.00" ;;    # ~50 turns, opus
    codex)  echo "0.50" ;;    # Plus subscription, light usage
    grok)   echo "0.50" ;;    # SuperGrok subscription
    copilot) echo "0.25" ;;   # Pro+ subscription
    ollama) echo "0.00" ;;    # Free
    *) echo "0.00" ;;
  esac
}

# Daily spend limit
DAILY_SPEND_LIMIT_USD=15

###############################################################################
# MAX TURNS PER TIER
###############################################################################

CLAUDE_MAX_TURNS=50       # Expensive — be surgical
CODEX_MAX_TURNS=80        # Plus subscription — moderate
GROK_MAX_TURNS=80         # SuperGrok — moderate (also debates)
COPILOT_MAX_TURNS=100     # Pro+ unlimited — let it work
OLLAMA_MAX_TURNS=100      # Free — let them work
JUNIOR_MAX_TURNS=25       # Ultra-scoped tasks

###############################################################################
# ESTIMATED MONTHLY COSTS
###############################################################################
#
# All subscriptions (fixed):
#   Claude Max:          $100/mo
#   OpenAI Plus (Codex): $20/mo
#   SuperGrok:           $30/mo
#   Copilot Pro+:        $39/mo
#   Ollama:              $0
#   ────────────────────────────
#   Subtotal:            $189/mo
#   Buffer:              $161/mo
#   Total budget:        $350/mo
#
# Per-runtime agent distribution:
#   ☁️  Claude (3 agents):  backend-hardener, security-analyst, agent-doctor
#   🤖 Codex  (2 agents):  enterprise-architect, data-scientist
#   🧠 Grok   (2+debates): threat-architect, ai-researcher + debates/verify
#   🐙 Copilot(3 agents):  frontend-craftsman, qa-engineer, devops-engineer
#   🏠 Ollama (6 agents):  context-eng, marketing, tech-writer, sales, scrum, swarm
#
# Fallback chain: claude → codex → copilot → grok → ollama
#
###############################################################################
