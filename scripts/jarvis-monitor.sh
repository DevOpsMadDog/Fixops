#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  JARVIS Monitor — Lightweight failure & health monitor for the team
#  Usage:
#    ./scripts/jarvis-monitor.sh              # Quick status
#    ./scripts/jarvis-monitor.sh --watch      # Auto-refresh every 5s
#    ./scripts/jarvis-monitor.sh --failures   # Detailed failure report
#    ./scripts/jarvis-monitor.sh --report     # Full team report (markdown)
#    ./scripts/jarvis-monitor.sh --tail       # Tail latest agent log
#    ./scripts/jarvis-monitor.sh --memory     # Memory pressure check
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STATE_DIR="$PROJECT_ROOT/.claude/team-state"
LOG_DIR="$PROJECT_ROOT/logs/ai-team"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Helpers ────────────────────────────────────────────────────────

human_duration() {
    local s=$1
    if (( s >= 3600 )); then
        printf "%dh %dm %ds" $((s/3600)) $(((s%3600)/60)) $((s%60))
    elif (( s >= 60 )); then
        printf "%dm %ds" $((s/60)) $((s%60))
    else
        printf "%ds" "$s"
    fi
}

human_bytes() {
    local b=$1
    if (( b >= 1048576 )); then
        printf "%.1f MB" "$(echo "scale=1; $b/1048576" | bc)"
    elif (( b >= 1024 )); then
        printf "%.1f KB" "$(echo "scale=1; $b/1024" | bc)"
    else
        printf "%d B" "$b"
    fi
}

get_free_ram_mb() {
    local page_size free_pages
    page_size=$(sysctl -n hw.pagesize 2>/dev/null || echo 16384)
    free_pages=$(vm_stat 2>/dev/null | awk '/Pages free/ {gsub(/\./,"",$3); print $3}')
    echo $(( (free_pages * page_size) / 1048576 ))
}

get_swap_used_gb() {
    sysctl vm.swapusage 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="used") {gsub(/M/,"",$(i+2)); printf "%.1f", $(i+2)/1024}}' || echo "?"
}

# ─── Quick Status ───────────────────────────────────────────────────

show_status() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║           🤖  JARVIS SWARM MONITOR                          ║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    # ── Jarvis Process Status
    local jarvis_running=false
    local jarvis_pid=""
    if [[ -f "$STATE_DIR/jarvis.pid" ]]; then
        jarvis_pid=$(cat "$STATE_DIR/jarvis.pid" 2>/dev/null)
        if [[ -n "$jarvis_pid" ]] && kill -0 "$jarvis_pid" 2>/dev/null; then
            jarvis_running=true
        fi
    fi

    if $jarvis_running; then
        echo -e "  ${GREEN}●${RESET} Jarvis: ${GREEN}RUNNING${RESET} (PID $jarvis_pid)"
    else
        echo -e "  ${RED}●${RESET} Jarvis: ${RED}STOPPED${RESET}"
    fi

    # ── Heartbeat
    if [[ -f "$STATE_DIR/jarvis-heartbeat.json" ]]; then
        local hb_status hb_restarts
        hb_status=$(python3 -c "import json; d=json.load(open('$STATE_DIR/jarvis-heartbeat.json')); print(d.get('status','?'))" 2>/dev/null || echo "?")
        hb_restarts=$(python3 -c "import json; d=json.load(open('$STATE_DIR/jarvis-heartbeat.json')); print(d.get('restart_count',0))" 2>/dev/null || echo "?")
        echo -e "  ${DIM}Heartbeat: $hb_status | Restarts: $hb_restarts${RESET}"
    fi

    # ── Current Agent
    if [[ -f "$STATE_DIR/.jarvis-current-agent" ]]; then
        local cur_agent
        cur_agent=$(cat "$STATE_DIR/.jarvis-current-agent" 2>/dev/null)
        if [[ -n "$cur_agent" ]]; then
            echo -e "  ${YELLOW}▶${RESET} Current Agent: ${BOLD}$cur_agent${RESET}"
        fi
    fi

    # ── Halt state
    if [[ -f "$STATE_DIR/swarm-halted.json" ]]; then
        local halt_count halt_reason halt_heals halt_max_heals
        halt_count=$(python3 -c "import json; print(json.load(open('$STATE_DIR/swarm-halted.json')).get('global_fail_count','?'))" 2>/dev/null || echo "?")
        halt_reason=$(python3 -c "import json; print(json.load(open('$STATE_DIR/swarm-halted.json')).get('reason','?'))" 2>/dev/null || echo "?")
        halt_heals=$(python3 -c "import json; print(json.load(open('$STATE_DIR/swarm-halted.json')).get('self_heal_attempts','0'))" 2>/dev/null || echo "0")
        halt_max_heals=$(python3 -c "import json; print(json.load(open('$STATE_DIR/swarm-halted.json')).get('max_self_heals','3'))" 2>/dev/null || echo "3")
        echo -e "  ${RED}${BOLD}🛑 SWARM HALTED${RESET} — ${halt_count} failures — ${halt_reason}"
        echo -e "  ${RED}  Self-heal attempts: ${halt_heals}/${halt_max_heals}${RESET}"
        echo ""
        echo -e "  ${YELLOW}${BOLD}Recovery Options:${RESET}"
        echo -e "  ${DIM}  1. Resume (keeps progress):${RESET} ${CYAN}./scripts/run-ctem-swarm.sh --resume${RESET}"
        echo -e "  ${DIM}  2. Clear halt only:${RESET}         ${CYAN}rm .claude/team-state/swarm-halted.json${RESET}"
        echo -e "  ${DIM}  3. Full restart (fresh):${RESET}    ${CYAN}./scripts/run-ctem-swarm.sh${RESET}"
        echo -e "  ${DIM}  4. Reset all state:${RESET}         ${CYAN}rm .claude/team-state/*-failure.json .claude/team-state/swarm-halted.json${RESET}"
    fi

    # ── Memory
    local free_mb swap_gb
    free_mb=$(get_free_ram_mb)
    swap_gb=$(get_swap_used_gb)
    local mem_color="$GREEN"
    if (( free_mb < 1500 )); then mem_color="$RED"
    elif (( free_mb < 3000 )); then mem_color="$YELLOW"
    fi
    echo -e "  ${DIM}Memory:${RESET} ${mem_color}${free_mb} MB free${RESET} ${DIM}| Swap: ${swap_gb} GB used${RESET}"

    # ── Load
    local load
    load=$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2, $3, $4}')
    echo -e "  ${DIM}Load:${RESET} $load"

    echo ""

    # ── Run Summary
    echo -e "  ${BOLD}${WHITE}─── Agent Results ───${RESET}"
    echo ""

    local total=0 passed=0 failed=0 running=0

    # Collect all agent names from failure/status files
    local agents=()
    for f in "$STATE_DIR"/*-status.md; do
        [[ -f "$f" ]] || continue
        local name
        name=$(basename "$f" -status.md)
        agents+=("$name")
    done

    # Sort agents
    IFS=$'\n' agents=($(sort <<<"${agents[*]}")); unset IFS

    printf "  ${DIM}%-22s %-8s %-5s %-7s %-8s %s${RESET}\n" "AGENT" "STATUS" "TRY" "TIME" "CONF" "REASON"
    echo -e "  ${DIM}$(printf '%.0s─' {1..74})${RESET}"

    for agent in "${agents[@]}"; do
        total=$((total + 1))
        local status="unknown" tries="-" duration="-" reason="-" confidence="-"
        local status_color="$DIM"

        # Check confidence from hallucination report
        if [[ -f "$STATE_DIR/${agent}-hallucination-report.json" ]]; then
            confidence=$(python3 -c "import json; d=json.load(open('$STATE_DIR/${agent}-hallucination-report.json')); print(d.get('confidence','?'))" 2>/dev/null || echo "?")
        fi
        # Also check confidence audit log for latest
        if [[ -f "$STATE_DIR/confidence-audit.jsonl" ]]; then
            local latest_conf
            latest_conf=$(grep "\"agent\":\"${agent}\"" "$STATE_DIR/confidence-audit.jsonl" 2>/dev/null | tail -1 | python3 -c "import sys,json; print(json.load(sys.stdin).get('confidence','?'))" 2>/dev/null || echo "")
            [[ -n "$latest_conf" && "$latest_conf" != "?" ]] && confidence="$latest_conf"
        fi
        # Color the confidence
        local conf_display="$confidence"
        case "$confidence" in
            HIGH)   conf_display="${GREEN}🟢 HIGH${RESET}" ;;
            MEDIUM) conf_display="${YELLOW}🟡 MED${RESET}" ;;
            LOW)    conf_display="${RED}🔴 LOW${RESET}" ;;
        esac

        # Check failure file
        if [[ -f "$STATE_DIR/${agent}-failure.json" ]]; then
            local fdata
            fdata=$(cat "$STATE_DIR/${agent}-failure.json" 2>/dev/null)
            tries=$(echo "$fdata" | python3 -c "import sys,json; print(json.load(sys.stdin).get('retries','?'))" 2>/dev/null || echo "?")
            reason=$(echo "$fdata" | python3 -c "import sys,json; r=json.load(sys.stdin).get('reason','?'); print(r[:22])" 2>/dev/null || echo "?")
            status="FAILED"
            status_color="$RED"
            failed=$((failed + 1))
        fi

        # Check performance data for duration
        if [[ -f "$STATE_DIR/agent-performance.json" ]]; then
            duration=$(python3 -c "
import json
d=json.load(open('$STATE_DIR/agent-performance.json'))
a=d.get('$agent',{})
runs=a.get('runs',[])
if runs:
    print(f\"{runs[-1].get('duration',0)}s\")
else:
    print('-')
" 2>/dev/null || echo "-")
        fi

        # Check status md for completion, running, or process-based running
        if [[ -f "$STATE_DIR/${agent}-status.md" ]]; then
            if grep -qi "completed\|✅\|success" "$STATE_DIR/${agent}-status.md" 2>/dev/null; then
                status="PASSED"
                status_color="$GREEN"
                passed=$((passed + 1))
                if [[ -f "$STATE_DIR/${agent}-failure.json" ]]; then
                    # Has failure but also success — latest wins, undo failure count
                    failed=$((failed - 1))
                fi
            elif grep -qi "running\|🔄\|in.progress" "$STATE_DIR/${agent}-status.md" 2>/dev/null; then
                status="RUNNING"
                status_color="$CYAN"
                running=$((running + 1))
                if [[ -f "$STATE_DIR/${agent}-failure.json" ]]; then
                    failed=$((failed - 1))  # don't double count
                fi
            fi
        fi

        # Also check .jarvis-current-agent for agents not yet showing in status md
        if [[ "$status" != "PASSED" && "$status" != "RUNNING" ]]; then
            if [[ -f "$STATE_DIR/.jarvis-current-agent" ]]; then
                local cur
                cur=$(cat "$STATE_DIR/.jarvis-current-agent" 2>/dev/null)
                if [[ "$cur" == "$agent" ]]; then
                    status="RUNNING"
                    status_color="$CYAN"
                    running=$((running + 1))
                    if [[ -f "$STATE_DIR/${agent}-failure.json" ]]; then
                        failed=$((failed - 1))  # don't double count
                    fi
                fi
            fi
        fi

        printf "  ${status_color}%-22s %-8s %-5s %-7s${RESET} %-8b ${status_color}%s${RESET}\n" "$agent" "$status" "$tries" "$duration" "$conf_display" "$reason"
    done

    echo ""
    echo -e "  ${BOLD}Summary:${RESET} ${GREEN}$passed passed${RESET} | ${RED}$failed failed${RESET} | ${CYAN}$running running${RESET} | ${DIM}$total total${RESET}"

    # ── Confidence Distribution
    if [[ -f "$STATE_DIR/confidence-audit.jsonl" ]]; then
        local c_high c_med c_low c_esc
        c_high=$(grep -c '"confidence":"HIGH"' "$STATE_DIR/confidence-audit.jsonl" 2>/dev/null || true)
        c_med=$(grep -c '"confidence":"MEDIUM"' "$STATE_DIR/confidence-audit.jsonl" 2>/dev/null || true)
        c_low=$(grep -c '"confidence":"LOW"' "$STATE_DIR/confidence-audit.jsonl" 2>/dev/null || true)
        c_esc=$(grep -c '"escalation":"scrum-master"' "$STATE_DIR/confidence-audit.jsonl" 2>/dev/null || true)
        if (( c_high + c_med + c_low > 0 )); then
            echo -e "  ${BOLD}Confidence:${RESET} ${GREEN}🟢 $c_high HIGH${RESET} | ${YELLOW}🟡 $c_med MED${RESET} | ${RED}🔴 $c_low LOW${RESET} | 📢 $c_esc escalations"
        fi
    fi

    # ── OOM Checkpoints
    local checkpoint_dir="$PROJECT_ROOT/.claude/checkpoints"
    local oom_count=0
    oom_count=$(find "$checkpoint_dir" -name "*.oom" 2>/dev/null | wc -l | tr -d ' ')
    if (( oom_count > 0 )); then
        echo ""
        echo -e "  ${RED}${BOLD}⚠️  OOM Checkpoints: ${oom_count} agents killed by memory pressure${RESET}"
        for oom_file in "$checkpoint_dir"/*.oom; do
            [[ -f "$oom_file" ]] || continue
            local oom_agent oom_attempt oom_ram
            oom_agent=$(python3 -c "import json; print(json.load(open('$oom_file')).get('agent','?'))" 2>/dev/null || echo "?")
            oom_attempt=$(python3 -c "import json; print(json.load(open('$oom_file')).get('attempt','?'))" 2>/dev/null || echo "?")
            oom_ram=$(python3 -c "import json; print(json.load(open('$oom_file')).get('free_ram_mb','?'))" 2>/dev/null || echo "?")
            echo -e "    ${RED}●${RESET} ${oom_agent} (attempt ${oom_attempt}) — ${oom_ram}MB free at kill"
        done
    fi

    # ── Escalation History
    if [[ -f "$STATE_DIR/escalation-history.jsonl" ]]; then
        local esc_total
        esc_total=$(wc -l < "$STATE_DIR/escalation-history.jsonl" | tr -d ' ')
        if (( esc_total > 0 )); then
            echo ""
            echo -e "  ${BOLD}${MAGENTA}Escalation History (last 5):${RESET}"
            tail -5 "$STATE_DIR/escalation-history.jsonl" | while IFS= read -r line; do
                local e_agent e_verdict e_conf
                e_agent=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent','?'))" 2>/dev/null || echo "?")
                e_verdict=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verdict','?'))" 2>/dev/null || echo "?")
                e_conf=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('confidence','?'))" 2>/dev/null || echo "?")
                local v_icon="❌"
                [[ "$e_verdict" == "ACCEPT" ]] && v_icon="✅"
                echo -e "    ${v_icon} ${e_agent} — confidence ${e_conf}/100 — ${e_verdict}"
            done
        fi
    fi

    # ── Last crash
    if [[ -f "$STATE_DIR/crash-state.json" ]]; then
        local crash_agent crash_time crash_exit
        crash_agent=$(python3 -c "import json; d=json.load(open('$STATE_DIR/crash-state.json')); print(d.get('last_agent','?'))" 2>/dev/null || echo "?")
        crash_time=$(python3 -c "import json; d=json.load(open('$STATE_DIR/crash-state.json')); print(d.get('crash_time','?'))" 2>/dev/null || echo "?")
        crash_exit=$(python3 -c "import json; d=json.load(open('$STATE_DIR/crash-state.json')); print(d.get('exit_code','?'))" 2>/dev/null || echo "?")
        echo ""
        echo -e "  ${RED}Last Crash:${RESET} $crash_agent at $crash_time (exit $crash_exit)"
    fi

    # ── Cost log latest
    if [[ -f "$STATE_DIR/cost-log.csv" ]]; then
        local log_lines
        log_lines=$(wc -l < "$STATE_DIR/cost-log.csv" | tr -d ' ')
        if (( log_lines > 0 )); then
            echo ""
            echo -e "  ${DIM}Cost log entries: $log_lines${RESET}"
        fi
    fi

    echo ""
}

# ─── Detailed Failures ─────────────────────────────────────────────

show_failures() {
    echo ""
    echo -e "${BOLD}${RED}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${RED}║           ⚠️   FAILURE REPORT                                ║${RESET}"
    echo -e "${BOLD}${RED}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    local count=0
    for f in "$STATE_DIR"/*-failure.json; do
        [[ -f "$f" ]] || continue
        count=$((count + 1))

        local agent ts retries reason log_path run_id
        agent=$(python3 -c "import json; print(json.load(open('$f')).get('agent','?'))" 2>/dev/null)
        ts=$(python3 -c "import json; print(json.load(open('$f')).get('ts','?'))" 2>/dev/null)
        retries=$(python3 -c "import json; print(json.load(open('$f')).get('retries','?'))" 2>/dev/null)
        reason=$(python3 -c "import json; print(json.load(open('$f')).get('reason','?'))" 2>/dev/null)
        log_path=$(python3 -c "import json; print(json.load(open('$f')).get('log','?'))" 2>/dev/null)
        run_id=$(python3 -c "import json; print(json.load(open('$f')).get('run_id','?'))" 2>/dev/null)

        echo -e "  ${RED}━━━ $agent ━━━${RESET}"
        echo -e "  ${DIM}Time:${RESET}    $ts"
        echo -e "  ${DIM}Run ID:${RESET}  $run_id"
        echo -e "  ${DIM}Retries:${RESET} $retries"
        echo -e "  ${DIM}Reason:${RESET}  ${YELLOW}$reason${RESET}"

        # Show last 5 lines of log if available
        if [[ -f "$log_path" ]]; then
            local log_size
            log_size=$(wc -c < "$log_path" | tr -d ' ')
            echo -e "  ${DIM}Log:${RESET}     $log_path ($(human_bytes "$log_size"))"
            echo -e "  ${DIM}Last output:${RESET}"
            tail -5 "$log_path" 2>/dev/null | while IFS= read -r line; do
                echo -e "    ${DIM}│${RESET} $line"
            done
        else
            echo -e "  ${DIM}Log:${RESET}     ${RED}not found${RESET}"
        fi
        echo ""
    done

    if (( count == 0 )); then
        echo -e "  ${GREEN}No failures recorded! 🎉${RESET}"
    else
        echo -e "  ${RED}Total failures: $count${RESET}"
    fi

    # ── Exit Code Analysis
    echo ""
    echo -e "  ${BOLD}${WHITE}Exit Code Key:${RESET}"
    echo -e "  ${DIM}  137 = OOM killed (kernel out of memory)${RESET}"
    echo -e "  ${DIM}  143 = SIGTERM (timeout or manual kill)${RESET}"
    echo -e "  ${DIM}  130 = SIGINT (ctrl+c / interrupted)${RESET}"
    echo -e "  ${DIM}    1 = General error / crash${RESET}"
    echo -e "  ${DIM}    0 = Success (shouldn't appear in failures)${RESET}"

    # ── OOM Analysis
    local oom_count=0
    for f in "$LOG_DIR"/*.log; do
        [[ -f "$f" ]] || continue
        if [[ -s "$f" ]]; then
            continue
        fi
        oom_count=$((oom_count + 1))
    done
    local total_logs
    total_logs=$(ls "$LOG_DIR"/*.log 2>/dev/null | wc -l | tr -d ' ')
    echo ""
    echo -e "  ${BOLD}OOM Analysis:${RESET} $oom_count / $total_logs logs are 0-byte (killed before output)"
    echo ""
}

# ─── Memory Pressure ───────────────────────────────────────────────

show_memory() {
    echo ""
    echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${MAGENTA}║           💾  MEMORY PRESSURE                                ║${RESET}"
    echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    local free_mb swap_used total_ram
    free_mb=$(get_free_ram_mb)
    swap_used=$(sysctl vm.swapusage 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="used") gsub(/M/,"",$(i+2)); print $(i+2)}')
    total_ram=$(sysctl -n hw.memsize 2>/dev/null | awk '{printf "%.0f", $1/1048576}')

    echo -e "  ${BOLD}Total RAM:${RESET}  ${total_ram} MB"
    echo -e "  ${BOLD}Free RAM:${RESET}   ${free_mb} MB"
    echo -e "  ${BOLD}Swap Used:${RESET}  $(get_swap_used_gb) GB"

    # Bar chart
    local used_pct=$(( (total_ram - free_mb) * 100 / total_ram ))
    local bar_width=50
    local filled=$(( used_pct * bar_width / 100 ))
    local empty=$(( bar_width - filled ))
    local bar_color="$GREEN"
    if (( used_pct > 90 )); then bar_color="$RED"
    elif (( used_pct > 75 )); then bar_color="$YELLOW"
    fi
    printf "\n  RAM: ${bar_color}["
    printf '█%.0s' $(seq 1 $filled 2>/dev/null) || true
    printf '░%.0s' $(seq 1 $empty 2>/dev/null) || true
    printf "]${RESET} %d%%\n" "$used_pct"

    echo ""
    echo -e "  ${BOLD}${WHITE}Top Memory Consumers:${RESET}"
    echo ""
    ps aux --sort=-%mem 2>/dev/null | head -1 | awk '{printf "  %-8s %-6s %-6s %s\n", $1, $3, $4, $11}' || true
    ps aux 2>/dev/null | sort -k4 -rn | head -10 | awk '{printf "  %-8s %-6s %-6s %s\n", $1, $3, $4, $11}' || true

    # Telemetry trend
    echo ""
    echo -e "  ${BOLD}${WHITE}Memory History (from telemetry):${RESET}"
    if [[ -f "$STATE_DIR/telemetry-$(date +%Y-%m-%d).jsonl" ]]; then
        echo ""
        tail -10 "$STATE_DIR/telemetry-$(date +%Y-%m-%d).jsonl" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        ts = d.get('ts','?')[11:19]
        mem = d.get('mem_pct', 0)
        label = d.get('label','?')
        bar = '█' * (mem // 5) + '░' * (20 - mem // 5)
        color = '\033[31m' if mem > 95 else '\033[33m' if mem > 85 else '\033[32m'
        print(f'  {ts}  {color}[{bar}] {mem:3d}%\033[0m  {label}')
    except: pass
" 2>/dev/null
    else
        echo -e "  ${DIM}No telemetry data for today${RESET}"
    fi
    echo ""
}

# ─── Tail Latest Log ───────────────────────────────────────────────

tail_latest() {
    local agent="${1:-}"
    local log_file

    if [[ -n "$agent" ]]; then
        log_file=$(ls -t "$LOG_DIR"/*"${agent}"*.log 2>/dev/null | head -1)
    else
        log_file=$(ls -t "$LOG_DIR"/*.log 2>/dev/null | head -1)
    fi

    if [[ -z "$log_file" ]] || [[ ! -f "$log_file" ]]; then
        echo -e "${RED}No log files found${RESET}"
        return 1
    fi

    echo -e "${BOLD}${CYAN}Tailing: ${RESET}$log_file"
    echo -e "${DIM}$(printf '%.0s─' {1..70})${RESET}"
    tail -f "$log_file"
}

# ─── Team Report (Markdown) ────────────────────────────────────────

generate_report() {
    local report_file="$STATE_DIR/monitor-report-$(date +%Y-%m-%d_%H%M).md"
    local now
    now=$(date '+%Y-%m-%d %H:%M:%S')

    {
        echo "# JARVIS Swarm Monitor Report"
        echo ""
        echo "**Generated:** $now"
        echo ""

        # System Health
        local free_mb
        free_mb=$(get_free_ram_mb)
        local swap_gb
        swap_gb=$(get_swap_used_gb)
        echo "## System Health"
        echo ""
        echo "| Metric | Value |"
        echo "|--------|-------|"
        echo "| Free RAM | ${free_mb} MB |"
        echo "| Swap Used | ${swap_gb} GB |"
        echo "| Load | $(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2, $3, $4}') |"
        echo ""

        # Jarvis Status
        echo "## Jarvis Status"
        echo ""
        if [[ -f "$STATE_DIR/jarvis-heartbeat.json" ]]; then
            python3 -c "
import json
d = json.load(open('$STATE_DIR/jarvis-heartbeat.json'))
print(f\"| Field | Value |\\n|-------|-------|\\n| Status | {d.get('status','?')} |\\n| PID | {d.get('pid','?')} |\\n| Restarts | {d.get('restart_count',0)} |\\n| Uptime | {d.get('uptime_seconds',0)}s |\")
" 2>/dev/null || echo "_(heartbeat unavailable)_"
        fi
        echo ""

        # Agent Results
        echo "## Agent Results"
        echo ""
        echo "| Agent | Status | Retries | Duration | Reason |"
        echo "|-------|--------|---------|----------|--------|"

        local total=0 passed=0 failed=0
        for f in "$STATE_DIR"/*-failure.json; do
            [[ -f "$f" ]] || continue
            total=$((total + 1))
            failed=$((failed + 1))
            python3 -c "
import json
d = json.load(open('$f'))
agent = d.get('agent','?')
retries = d.get('retries','?')
reason = d.get('reason','?')
print(f'| {agent} | ❌ FAILED | {retries} | - | {reason} |')
" 2>/dev/null
        done

        for f in "$STATE_DIR"/*-status.md; do
            [[ -f "$f" ]] || continue
            local name
            name=$(basename "$f" -status.md)
            if ! [[ -f "$STATE_DIR/${name}-failure.json" ]]; then
                if grep -qi "completed\|success" "$f" 2>/dev/null; then
                    echo "| $name | ✅ PASSED | - | - | - |"
                    passed=$((passed + 1))
                    total=$((total + 1))
                fi
            fi
        done

        echo ""
        echo "**Summary:** $passed passed, $failed failed, $total total"
        echo ""

        # Failure Details
        if (( failed > 0 )); then
            echo "## Failure Details"
            echo ""
            for f in "$STATE_DIR"/*-failure.json; do
                [[ -f "$f" ]] || continue
                python3 -c "
import json
d = json.load(open('$f'))
print(f\"### {d.get('agent','?')}\")
print(f\"- **Time:** {d.get('ts','?')}\")
print(f\"- **Run ID:** {d.get('run_id','?')}\")
print(f\"- **Retries:** {d.get('retries','?')}\")
print(f\"- **Reason:** {d.get('reason','?')}\")
print(f\"- **Log:** \`{d.get('log','?')}\`\")
print()
" 2>/dev/null
            done
        fi

        # Recommendations
        echo "## Recommendations"
        echo ""
        if (( free_mb < 1500 )); then
            echo "- ⚠️ **Low memory** (${free_mb} MB free). Close unused apps or run headless."
        fi
        if (( failed > passed )); then
            echo "- 🔴 **More failures than passes.** Check OOM kills (exit 137) and memory pressure."
        fi
        local zero_byte_logs
        zero_byte_logs=$(find "$LOG_DIR" -name "*.log" -empty 2>/dev/null | wc -l | tr -d ' ')
        if (( zero_byte_logs > 5 )); then
            echo "- 📄 **${zero_byte_logs} empty log files** — agents killed before producing output (likely OOM)."
        fi
        echo "- Run \`./scripts/jarvis-monitor.sh --memory\` for detailed memory analysis."
        echo ""
    } > "$report_file"

    echo -e "${GREEN}Report saved:${RESET} $report_file"
    echo ""
    cat "$report_file"
}

# ─── Watch Mode ─────────────────────────────────────────────────────

watch_mode() {
    local interval="${1:-5}"
    while true; do
        clear
        echo -e "${DIM}Auto-refresh every ${interval}s | $(date '+%H:%M:%S') | Ctrl+C to exit${RESET}"
        show_status
        sleep "$interval"
    done
}

# ─── Main ───────────────────────────────────────────────────────────

case "${1:-}" in
    --watch|-w)
        watch_mode "${2:-5}"
        ;;
    --failures|-f)
        show_failures
        ;;
    --memory|-m)
        show_memory
        ;;
    --report|-r)
        generate_report
        ;;
    --tail|-t)
        tail_latest "${2:-}"
        ;;
    --help|-h)
        echo "JARVIS Swarm Monitor"
        echo ""
        echo "Usage: $0 [COMMAND]"
        echo ""
        echo "Commands:"
        echo "  (none)           Quick status overview"
        echo "  --watch, -w      Auto-refresh dashboard (every 5s)"
        echo "  --failures, -f   Detailed failure report"
        echo "  --memory, -m     Memory pressure analysis"
        echo "  --report, -r     Full team report (markdown)"
        echo "  --tail, -t       Tail latest agent log"
        echo "  --help, -h       This help"
        echo ""
        echo "Examples:"
        echo "  $0                   # Quick glance"
        echo "  $0 --watch 3         # Refresh every 3 seconds"
        echo "  $0 --tail agent-doctor  # Tail specific agent"
        ;;
    *)
        show_status
        ;;
esac
