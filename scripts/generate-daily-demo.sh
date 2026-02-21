#!/usr/bin/env bash
###############################################################################
# ALdeci Daily Demo Generator
#
# Collects all agent outputs from .claude/team-state/ and produces a unified
# daily demo report that can be presented in <5 minutes.
#
# This runs as the final step after all agents complete, or standalone:
#   ./scripts/generate-daily-demo.sh
#   ./scripts/generate-daily-demo.sh --date 2025-01-27
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STATE_DIR="$PROJECT_ROOT/.claude/team-state"
DATE_TODAY=${1:-$(date +"%Y-%m-%d")}
DEMO_FILE="$STATE_DIR/daily-demo-${DATE_TODAY}.md"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}Generating daily demo for ${DATE_TODAY}...${NC}"

###############################################################################
# Collect agent statuses
###############################################################################
get_status() {
  local agent="$1"
  local status_file="$STATE_DIR/${agent}-status.md"
  if [[ -f "$status_file" ]]; then
    grep -o 'Status:.*' "$status_file" 2>/dev/null | head -1 || echo "Status: unknown"
  else
    echo "Status: ⏸️ Not run today"
  fi
}

get_duration() {
  local agent="$1"
  local status_file="$STATE_DIR/${agent}-status.md"
  if [[ -f "$status_file" ]]; then
    grep -o 'Duration:.*' "$status_file" 2>/dev/null | head -1 || echo ""
  fi
}

###############################################################################
# Collect artifacts
###############################################################################
collect_research() {
  local pulse="$STATE_DIR/research/aldeci-pulse-${DATE_TODAY}.md"
  if [[ -f "$pulse" ]]; then
    echo "### Research Highlights"
    echo ""
    head -50 "$pulse" | tail -45  # Skip header, take first 45 lines
  else
    echo "### Research"
    echo "_No research pulse available for today._"
  fi
}

collect_architecture() {
  echo "### Architecture Updates"
  echo ""
  # Check for new ADRs
  local adr_dir="$STATE_DIR/architecture/adrs"
  if [[ -d "$adr_dir" ]] && ls "$adr_dir"/*.md &>/dev/null; then
    local recent=$(find "$adr_dir" -name "*.md" -newer "$STATE_DIR/metrics.json" 2>/dev/null | head -5)
    if [[ -n "$recent" ]]; then
      echo "**New/Updated ADRs:**"
      for f in $recent; do
        echo "- $(basename "$f" .md): $(head -1 "$f" | sed 's/^# //')"
      done
    else
      echo "_No new ADRs today._"
    fi
  else
    echo "_No ADRs yet._"
  fi

  # Tech debt
  local debt="$STATE_DIR/architecture/tech-debt-tracker.md"
  if [[ -f "$debt" ]]; then
    echo ""
    echo "**Tech Debt Summary:**"
    head -10 "$debt" | tail -8
  fi
}

collect_marketing() {
  echo "### Marketing Updates"
  echo ""
  local narrative="$STATE_DIR/marketing/investor-narrative.md"
  if [[ -f "$narrative" ]]; then
    echo "**Investor Narrative:** $(wc -w < "$narrative" | tr -d ' ') words"
    echo ""
    head -5 "$narrative" | tail -3
    echo "..."
  else
    echo "_Investor narrative not yet started._"
  fi

  # Content count
  local content_dir="$STATE_DIR/marketing/content"
  if [[ -d "$content_dir" ]]; then
    local count=$(find "$content_dir" -type f 2>/dev/null | wc -l | tr -d ' ')
    echo ""
    echo "**Content pieces produced:** $count"
  fi
}

collect_codebase() {
  local map="$STATE_DIR/codebase-map.json"
  if [[ -f "$map" ]]; then
    echo "### Codebase Snapshot"
    echo ""
    echo '```json'
    head -20 "$map"
    echo '```'
  fi
}

###############################################################################
# Get metrics
###############################################################################
get_funding_readiness() {
  local metrics="$STATE_DIR/metrics.json"
  if [[ -f "$metrics" ]] && command -v python3 &>/dev/null; then
    python3 -c "
import json, sys
try:
    m = json.load(open('$metrics'))
    score = m.get('fundingReadiness', {}).get('score', '?')
    target = m.get('fundingReadiness', {}).get('target', 90)
    print(f'{score}% (target: {target}%)')
except:
    print('N/A')
" 2>/dev/null || echo "N/A"
  else
    echo "N/A"
  fi
}

get_sprint_info() {
  local board="$STATE_DIR/sprint-board.json"
  if [[ -f "$board" ]] && command -v python3 &>/dev/null; then
    python3 -c "
import json
try:
    b = json.load(open('$board'))
    s = b.get('sprint', {})
    v = b.get('velocity', {})
    items = b.get('backlog', [])
    done = len([i for i in items if i.get('status') == 'done'])
    total = len(items)
    print(f\"{s.get('name', 'Unknown')} | {done}/{total} items | {v.get('pointsCompleted', 0)} pts completed\")
except:
    print('Sprint data unavailable')
" 2>/dev/null || echo "Sprint data unavailable"
  else
    echo "Sprint data unavailable"
  fi
}

###############################################################################
# Generate the demo report
###############################################################################
cat > "$DEMO_FILE" <<HEREDOC
# ALdeci Daily Demo — ${DATE_TODAY}

> Auto-generated by the ALdeci AI Team at $(date +"%H:%M %Z")

---

## Team Status

| Agent | Status | Duration |
|-------|--------|----------|
| Context Engineer | $(get_status context-engineer) | $(get_duration context-engineer) |
| AI Researcher | $(get_status ai-researcher) | $(get_duration ai-researcher) |
| Enterprise Architect | $(get_status enterprise-architect) | $(get_duration enterprise-architect) |
| Marketing Head | $(get_status marketing-head) | $(get_duration marketing-head) |
| Scrum Master | $(get_status scrum-master) | $(get_duration scrum-master) |

## Key Metrics

- **Funding Readiness:** $(get_funding_readiness)
- **Sprint:** $(get_sprint_info)

---

## Agent Deliverables

$(collect_research)

$(collect_architecture)

$(collect_marketing)

$(collect_codebase)

---

## Demo Walkthrough

1. **Open ALdeci Dashboard** — \`http://localhost:3001\`
2. **Show Security Posture** — Unified vulnerability view with CVSS/EPSS scoring
3. **Run Micro-PenTest** — \`http://localhost:3001/attack/micro-pentest\`
4. **Show PentAGI Integration** — \`curl http://localhost:8000/api/v1/pentagi/health\`
5. **Present Investor Deck** — Key metrics, TAM/SAM/SOM, competitive moat

## What's Next

Check \`.claude/team-state/sprint-board.json\` for upcoming items.

---
*Generated by ALdeci AI Team Orchestrator*
HEREDOC

echo -e "${GREEN}[✓]${NC} Daily demo saved: ${BOLD}$DEMO_FILE${NC}"
echo ""
echo -e "  View it: ${CYAN}cat $DEMO_FILE${NC}"
echo -e "  Or open: ${CYAN}code $DEMO_FILE${NC}"
