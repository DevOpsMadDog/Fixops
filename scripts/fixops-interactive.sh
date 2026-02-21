#!/usr/bin/env bash
# ============================================================================
#  FixOps Interactive API & CLI Tester
#  A fancy animated wrapper for testing all FixOps endpoints
# ============================================================================

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================
FIXOPS_API_URL="${FIXOPS_API_URL:-http://127.0.0.1:8000}"
FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN:?ERROR: FIXOPS_API_TOKEN must be set}"
TEMP_DIR="${FIXOPS_TEMP_DIR:-/tmp/fixops-interactive}"
EDITOR="${EDITOR:-nano}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

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

# Disable animations if requested
NO_ANIM="${ALDECI_NO_ANIM:-0}"

# ============================================================================
# COLORS AND STYLING
# ============================================================================
if [[ "${NO_COLOR:-}" == "1" ]] || [[ "$PLAIN_MODE" == "1" ]]; then
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
    ITALIC=''
    UNDERLINE=''
    BLINK=''
    REVERSE=''
    NC=''
    BG_RED=''
    BG_GREEN=''
    BG_YELLOW=''
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
    ITALIC='\033[3m'
    UNDERLINE='\033[4m'
    BLINK='\033[5m'
    REVERSE='\033[7m'
    NC='\033[0m'
    # Background colors
    BG_RED='\033[41m'
    BG_GREEN='\033[42m'
    BG_YELLOW='\033[43m'
    BG_BLUE='\033[44m'
    BG_MAGENTA='\033[45m'
    BG_CYAN='\033[46m'
fi

# ============================================================================
# ANIMATION FRAMES
# ============================================================================
if [[ "$PLAIN_MODE" == "1" ]]; then
    # Plain ASCII mode - compatible with all terminals
    SPINNER_FRAMES=("-" "\\" "|" "/")
    PROGRESS_FRAMES=("[      ]" "[=     ]" "[==    ]" "[===   ]" "[====  ]" "[===== ]" "[======]" "[======]")
    ROCKET_FRAMES=("*     " " *    " "  *   " "   *  " "    * " "   *  " "  *   " " *    ")
    PULSE_FRAMES=("o" "O" "o" "O")
    WAVE_FRAMES=("~~~~~" "~~~~~" "~~~~~" "~~~~~")
    DNA_FRAMES=("+---+" "|+-+|" "|| ||" "|+-+|" "+---+")
    MATRIX_CHARS=("0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "A" "B")
    # Box drawing characters - ASCII fallback
    BOX_TL="+" BOX_TR="+" BOX_BL="+" BOX_BR="+"
    BOX_H="-" BOX_V="|" BOX_ML="+" BOX_MR="+"
else
    # Fancy Unicode mode
    SPINNER_FRAMES=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    PROGRESS_FRAMES=("▱▱▱▱▱▱▱" "▰▱▱▱▱▱▱" "▰▰▱▱▱▱▱" "▰▰▰▱▱▱▱" "▰▰▰▰▱▱▱" "▰▰▰▰▰▱▱" "▰▰▰▰▰▰▱" "▰▰▰▰▰▰▰")
    ROCKET_FRAMES=("*     " " *    " "  *   " "   *  " "    * " "   *  " "  *   " " *    ")
    PULSE_FRAMES=("●" "◉" "○" "◉")
    WAVE_FRAMES=("≋≈≋≈≋" "≈≋≈≋≈" "≋≈≋≈≋" "≈≋≈≋≈")
    DNA_FRAMES=("╔═══╗" "║╔═╗║" "║║═║║" "║╚═╝║" "╚═══╝")
    MATRIX_CHARS=("ア" "イ" "ウ" "エ" "オ" "カ" "キ" "ク" "ケ" "コ" "0" "1")
    # Box drawing characters - Unicode
    BOX_TL="╔" BOX_TR="╗" BOX_BL="╚" BOX_BR="╝"
    BOX_H="═" BOX_V="║" BOX_ML="╠" BOX_MR="╣"
fi

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Clear screen with animation
clear_screen() {
    printf '\033[2J\033[H'
}

# Move cursor
move_cursor() {
    printf '\033[%d;%dH' "$1" "$2"
}

# Hide/show cursor
hide_cursor() { printf '\033[?25l'; }
show_cursor() { printf '\033[?25h'; }

# Get terminal dimensions
get_term_width() { tput cols 2>/dev/null || echo 80; }
get_term_height() { tput lines 2>/dev/null || echo 24; }

# Center text
center_text() {
    local text="$1"
    local width=$(get_term_width)
    local text_len=${#text}
    local padding=$(( (width - text_len) / 2 ))
    printf "%${padding}s%s\n" "" "$text"
}

# Print colored text
print_color() {
    local color="$1"
    shift
    printf "${color}%s${NC}" "$*"
}

# Print with newline
println_color() {
    print_color "$@"
    echo
}

# Animated spinner
spinner() {
    local pid=$1
    local message="${2:-Processing}"
    local i=0
    hide_cursor
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}${SPINNER_FRAMES[$i]}${NC} ${message}..."
        i=$(( (i + 1) % ${#SPINNER_FRAMES[@]} ))
        sleep 0.1
    done
    printf "\r${GREEN}✓${NC} ${message}... Done!     \n"
    show_cursor
}

# Progress bar animation
progress_bar() {
    local current=$1
    local total=$2
    local width=40
    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf "\r${CYAN}["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "]${NC} ${WHITE}%3d%%${NC}" "$percent"
}

# Typewriter effect
typewriter() {
    local text="$1"
    local delay="${2:-0.03}"
    for ((i=0; i<${#text}; i++)); do
        printf "%s" "${text:$i:1}"
        sleep "$delay"
    done
    echo
}

# Matrix rain effect (brief)
matrix_rain() {
    local duration="${1:-1}"
    local width=$(get_term_width)
    local height=5
    hide_cursor
    for ((t=0; t<duration*10; t++)); do
        for ((y=0; y<height; y++)); do
            printf "${GREEN}"
            for ((x=0; x<width; x++)); do
                if (( RANDOM % 3 == 0 )); then
                    printf "%s" "${MATRIX_CHARS[$((RANDOM % ${#MATRIX_CHARS[@]}))]}"
                else
                    printf " "
                fi
            done
            printf "${NC}\n"
        done
        sleep 0.1
        printf '\033[%dA' "$height"
    done
    for ((y=0; y<height; y++)); do
        printf "%${width}s\n" ""
    done
    printf '\033[%dA' "$height"
    show_cursor
}

# Glowing text effect
glow_text() {
    local text="$1"
    local colors=("$DIM" "$NC" "$BOLD" "$NC" "$DIM")
    hide_cursor
    for color in "${colors[@]}"; do
        printf "\r${color}${CYAN}%s${NC}" "$text"
        sleep 0.15
    done
    printf "\r${BOLD}${CYAN}%s${NC}\n" "$text"
    show_cursor
}

# Pulse effect
pulse_text() {
    local text="$1"
    local count="${2:-3}"
    hide_cursor
    for ((i=0; i<count; i++)); do
        for frame in "${PULSE_FRAMES[@]}"; do
            printf "\r${MAGENTA}${frame}${NC} ${text}"
            sleep 0.1
        done
    done
    printf "\r${GREEN}●${NC} ${text}\n"
    show_cursor
}

# Box drawing
draw_box() {
    local title="$1"
    local width="${2:-60}"
    local color="${3:-$CYAN}"
    
    local tl tr bl br h v ml mr
    if [[ "$PLAIN_MODE" == "1" ]]; then
        tl="+" tr="+" bl="+" br="+" h="-" v="|" ml="+" mr="+"
    else
        tl="╔" tr="╗" bl="╚" br="╝" h="═" v="║" ml="╠" mr="╣"
    fi
    
    printf "${color}${tl}"
    printf -- "${h}%.0s" $(seq 1 $((width-2)))
    printf "${tr}${NC}\n"
    
    if [[ -n "$title" ]]; then
        local padding=$(( (width - 2 - ${#title}) / 2 ))
        printf "${color}${v}${NC}"
        printf "%${padding}s${BOLD}${WHITE}%s${NC}%$((width - 2 - padding - ${#title}))s" "" "$title" ""
        printf "${color}${v}${NC}\n"
        
        printf "${color}${ml}"
        printf -- "${h}%.0s" $(seq 1 $((width-2)))
        printf "${mr}${NC}\n"
    fi
}

draw_box_bottom() {
    local width="${1:-60}"
    local color="${2:-$CYAN}"
    
    local bl br h
    if [[ "$PLAIN_MODE" == "1" ]]; then
        bl="+" br="+" h="-"
    else
        bl="╚" br="╝" h="═"
    fi
    
    printf "${color}${bl}"
    printf -- "${h}%.0s" $(seq 1 $((width-2)))
    printf "${br}${NC}\n"
}

draw_box_line() {
    local text="$1"
    local width="${2:-60}"
    local color="${3:-$CYAN}"
    
    local v
    if [[ "$PLAIN_MODE" == "1" ]]; then
        v="|"
    else
        v="║"
    fi
    
    local text_len=${#text}
    local padding=$((width - 4 - text_len))
    if ((padding < 0)); then padding=0; fi
    printf "${color}${v}${NC} %s%${padding}s ${color}${v}${NC}\n" "$text" ""
}

# ============================================================================
# BANNER AND INTRO
# ============================================================================

show_banner() {
    clear_screen
    local width=$(get_term_width)
    
    # ASCII Art Banner with animation
    hide_cursor
    
    local banner=(
        "    ███████╗██╗██╗  ██╗ ██████╗ ██████╗ ███████╗"
        "    ██╔════╝██║╚██╗██╔╝██╔═══██╗██╔══██╗██╔════╝"
        "    █████╗  ██║ ╚███╔╝ ██║   ██║██████╔╝███████╗"
        "    ██╔══╝  ██║ ██╔██╗ ██║   ██║██╔═══╝ ╚════██║"
        "    ██║     ██║██╔╝ ██╗╚██████╔╝██║     ███████║"
        "    ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝"
    )
    
    # Animate banner appearance
    for ((i=0; i<${#banner[@]}; i++)); do
        printf "${CYAN}"
        center_text "${banner[$i]}"
        printf "${NC}"
        sleep 0.05
    done
    
    echo
    glow_text "    Interactive API & CLI Testing Suite"
    echo
    
    # Info box
    draw_box "System Information" 60
    draw_box_line "API URL: ${FIXOPS_API_URL}" 60
    draw_box_line "Token: ${FIXOPS_API_TOKEN:0:10}..." 60
    draw_box_line "Temp Dir: ${TEMP_DIR}" 60
    draw_box_line "Editor: ${EDITOR}" 60
    draw_box_bottom 60
    
    echo
    show_cursor
}

show_intro_animation() {
    hide_cursor
    echo
    printf "  ${CYAN}Initializing FixOps Interactive Tester${NC}"
    
    for frame in "${ROCKET_FRAMES[@]}"; do
        printf "\r  ${CYAN}Initializing FixOps Interactive Tester${NC} ${frame}"
        sleep 0.1
    done
    printf "\r  ${GREEN}✓ FixOps Interactive Tester Ready!${NC}              \n"
    echo
    show_cursor
}

# ============================================================================
# MENU SYSTEM
# ============================================================================

# Main menu categories
declare -A MENU_CATEGORIES=(
    ["1"]="Core Pipeline & Ingestion"
    ["2"]="Security Decision & Analysis"
    ["3"]="Compliance"
    ["4"]="Reports"
    ["5"]="Inventory"
    ["6"]="Policies"
    ["7"]="Integrations"
    ["8"]="Analytics"
    ["9"]="Audit"
    ["10"]="Workflows"
    ["11"]="Advanced Pen Testing"
    ["12"]="Reachability"
    ["13"]="Teams & Users"
    ["14"]="PentAGI"
    ["15"]="Evidence"
    ["16"]="Health & Status"
    ["17"]="Deduplication & Correlation"
    ["18"]="Remediation Lifecycle"
    ["19"]="Bulk Operations"
    ["20"]="Team Collaboration"
    ["21"]="Vulnerability Intelligence Feeds"
    ["22"]="Run All Tests"
    ["q"]="Quit"
)

show_main_menu() {
    echo
    draw_box "Main Menu - Select Category" 70 "$MAGENTA"
    
    local i=1
    for key in $(echo "${!MENU_CATEGORIES[@]}" | tr ' ' '\n' | sort -n); do
        if [[ "$key" == "q" ]]; then continue; fi
        local category="${MENU_CATEGORIES[$key]}"
        local num_color="$YELLOW"
        local text_color="$WHITE"
        if [[ "$key" == "22" ]]; then
            num_color="$GREEN"
            text_color="$GREEN"
        fi
        draw_box_line "  ${num_color}[${key}]${NC} ${text_color}${category}${NC}" 70 "$MAGENTA"
    done
    
    draw_box_line "" 70 "$MAGENTA"
    draw_box_line "  ${RED}[q]${NC} ${RED}Quit${NC}" 70 "$MAGENTA"
    draw_box_bottom 70 "$MAGENTA"
    
    echo
    printf "  ${CYAN}Enter your choice:${NC} "
}

# ============================================================================
# SAMPLE DATA GENERATORS
# ============================================================================

mkdir -p "$TEMP_DIR"

generate_design_sample() {
    cat > "$TEMP_DIR/design_sample.json" << 'EOF'
{
  "app_name": "my-application",
  "components": [
    {"name": "web-frontend", "tier": "tier-0", "exposure": "internet", "pii": true},
    {"name": "api-gateway", "tier": "tier-0", "exposure": "internal", "pii": false},
    {"name": "auth-service", "tier": "tier-0", "exposure": "internal", "pii": true},
    {"name": "database", "tier": "tier-1", "exposure": "internal", "pii": true}
  ],
  "flows": [
    ["internet", "web-frontend", "api-gateway"],
    ["api-gateway", "auth-service"],
    ["api-gateway", "database"]
  ],
  "threat_model_refs": ["tm/web-tm.md", "tm/api-dfd.md"]
}
EOF
    echo "$TEMP_DIR/design_sample.json"
}

generate_sbom_sample() {
    cat > "$TEMP_DIR/sbom_sample.json" << 'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "components": [
    {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21", "type": "library"},
    {"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2", "type": "library"},
    {"name": "openssl", "version": "1.1.1t", "purl": "pkg:generic/openssl@1.1.1t", "type": "library"},
    {"name": "log4j-core", "version": "2.17.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", "type": "library"},
    {"name": "spring-core", "version": "5.3.23", "purl": "pkg:maven/org.springframework/spring-core@5.3.23", "type": "library"}
  ]
}
EOF
    echo "$TEMP_DIR/sbom_sample.json"
}

generate_cve_sample() {
    cat > "$TEMP_DIR/cve_sample.json" << 'EOF'
{
  "cves": [
    {
      "id": "CVE-2021-44228",
      "description": "Apache Log4j2 JNDI features vulnerability (Log4Shell)",
      "severity": "CRITICAL",
      "cvss_score": 10.0,
      "published": "2021-12-10T10:15:00Z",
      "cpe": ["cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"],
      "cwe": ["CWE-502", "CWE-400"],
      "exploited": true,
      "epss_score": 0.975
    },
    {
      "id": "CVE-2022-22965",
      "description": "Spring Framework RCE via Data Binding (Spring4Shell)",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "published": "2022-04-01T23:15:00Z",
      "cpe": ["cpe:2.3:a:vmware:spring_framework:5.3.0:*:*:*:*:*:*:*"],
      "cwe": ["CWE-94"],
      "exploited": true,
      "epss_score": 0.892
    },
    {
      "id": "CVE-2023-44487",
      "description": "HTTP/2 Rapid Reset Attack (affects many servers)",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "published": "2023-10-10T14:15:00Z",
      "cpe": ["cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"],
      "cwe": ["CWE-400"],
      "exploited": true,
      "epss_score": 0.85
    }
  ]
}
EOF
    echo "$TEMP_DIR/cve_sample.json"
}

generate_sarif_sample() {
    cat > "$TEMP_DIR/sarif_sample.json" << 'EOF'
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SecurityScanner",
          "version": "1.0.0",
          "rules": [
            {"id": "SQL001", "name": "SQL Injection", "shortDescription": {"text": "SQL Injection vulnerability"}},
            {"id": "XSS001", "name": "Cross-Site Scripting", "shortDescription": {"text": "XSS vulnerability"}},
            {"id": "AUTH001", "name": "Broken Authentication", "shortDescription": {"text": "Authentication bypass"}}
          ]
        }
      },
      "results": [
        {
          "ruleId": "SQL001",
          "level": "error",
          "message": {"text": "SQL injection vulnerability in user input handling"},
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/db/queries.py"}, "region": {"startLine": 42}}}]
        },
        {
          "ruleId": "XSS001",
          "level": "warning",
          "message": {"text": "Potential XSS in template rendering"},
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/views/user.html"}, "region": {"startLine": 15}}}]
        }
      ]
    }
  ]
}
EOF
    echo "$TEMP_DIR/sarif_sample.json"
}

generate_vex_sample() {
    cat > "$TEMP_DIR/vex_sample.json" << 'EOF'
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/12345",
  "author": "security@example.com",
  "timestamp": "2024-01-15T10:00:00Z",
  "statements": [
    {
      "vulnerability": {"@id": "CVE-2021-44228"},
      "products": [{"@id": "pkg:npm/my-app@1.0.0"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "The vulnerable Log4j code path is not reachable in our configuration"
    },
    {
      "vulnerability": {"@id": "CVE-2022-22965"},
      "products": [{"@id": "pkg:npm/my-app@1.0.0"}],
      "status": "affected",
      "action_statement": "Upgrade to Spring Framework 5.3.18 or later"
    }
  ]
}
EOF
    echo "$TEMP_DIR/vex_sample.json"
}

generate_context_sample() {
    cat > "$TEMP_DIR/context_sample.json" << 'EOF'
{
  "application_id": "APP-12345",
  "environment": "production",
  "criticality": "high",
  "data_classification": "confidential",
  "compliance_frameworks": ["SOC2", "PCI-DSS", "GDPR"],
  "business_unit": "Financial Services",
  "owner": "security-team@example.com",
  "deployment_region": "us-east-1",
  "internet_facing": true,
  "handles_pii": true,
  "handles_phi": false,
  "handles_pci": true
}
EOF
    echo "$TEMP_DIR/context_sample.json"
}

generate_cnapp_sample() {
    cat > "$TEMP_DIR/cnapp_sample.json" << 'EOF'
{
  "provider": "aws",
  "account_id": "123456789012",
  "findings": [
    {
      "id": "CNAPP-001",
      "type": "misconfiguration",
      "resource_type": "aws_s3_bucket",
      "resource_id": "arn:aws:s3:::my-bucket",
      "severity": "high",
      "title": "S3 bucket publicly accessible",
      "description": "S3 bucket allows public read access",
      "remediation": "Remove public access block configuration"
    },
    {
      "id": "CNAPP-002",
      "type": "vulnerability",
      "resource_type": "aws_ecr_image",
      "resource_id": "arn:aws:ecr:us-east-1:123456789012:repository/my-app:latest",
      "severity": "critical",
      "title": "Container image contains critical CVE",
      "description": "Image contains CVE-2021-44228",
      "remediation": "Rebuild image with patched base"
    }
  ]
}
EOF
    echo "$TEMP_DIR/cnapp_sample.json"
}

generate_compare_llms_sample() {
    cat > "$TEMP_DIR/compare_llms_sample.json" << 'EOF'
{
  "service_name": "payment-gateway",
  "security_findings": [
    {
      "rule_id": "SQL001",
      "severity": "critical",
      "description": "SQL injection in payment processing endpoint",
      "location": "src/payments/process.py:142",
      "cwe": "CWE-89"
    },
    {
      "rule_id": "AUTH002",
      "severity": "high",
      "description": "Missing authentication on admin endpoint",
      "location": "src/admin/api.py:55",
      "cwe": "CWE-306"
    }
  ],
  "business_context": {
    "environment": "production",
    "criticality": "critical",
    "data_classification": "pci",
    "internet_facing": true
  }
}
EOF
    echo "$TEMP_DIR/compare_llms_sample.json"
}

generate_risk_score_sample() {
    cat > "$TEMP_DIR/risk_score_sample.json" << 'EOF'
{
  "application_id": "APP-12345",
  "findings": [
    {"cve_id": "CVE-2021-44228", "severity": "critical", "exploited": true},
    {"cve_id": "CVE-2022-22965", "severity": "critical", "exploited": true},
    {"cve_id": "CVE-2023-44487", "severity": "high", "exploited": true}
  ],
  "context": {
    "internet_facing": true,
    "handles_pii": true,
    "environment": "production"
  }
}
EOF
    echo "$TEMP_DIR/risk_score_sample.json"
}

generate_compliance_sample() {
    cat > "$TEMP_DIR/compliance_sample.json" << 'EOF'
{
  "framework": "SOC2",
  "scope": {
    "applications": ["APP-12345", "APP-67890"],
    "controls": ["CC6.1", "CC6.6", "CC6.7", "CC7.1", "CC7.2"]
  },
  "evidence": {
    "scan_results": true,
    "policy_attestations": true,
    "access_reviews": true
  }
}
EOF
    echo "$TEMP_DIR/compliance_sample.json"
}

generate_report_sample() {
    cat > "$TEMP_DIR/report_sample.json" << 'EOF'
{
  "type": "executive_summary",
  "format": "pdf",
  "date_range": {
    "start": "2024-01-01",
    "end": "2024-01-31"
  },
  "include_sections": [
    "risk_overview",
    "vulnerability_trends",
    "compliance_status",
    "remediation_progress",
    "recommendations"
  ],
  "filters": {
    "severity": ["critical", "high"],
    "applications": ["APP-12345"]
  }
}
EOF
    echo "$TEMP_DIR/report_sample.json"
}

generate_inventory_app_sample() {
    cat > "$TEMP_DIR/inventory_app_sample.json" << 'EOF'
{
  "name": "customer-portal",
  "description": "Customer-facing web portal for account management",
  "owner": "platform-team@example.com",
  "business_unit": "Customer Experience",
  "criticality": "high",
  "environment": "production",
  "tags": ["customer-facing", "pii", "pci"],
  "repository": "https://github.com/example/customer-portal",
  "deployment": {
    "type": "kubernetes",
    "cluster": "prod-us-east-1",
    "namespace": "customer-portal"
  }
}
EOF
    echo "$TEMP_DIR/inventory_app_sample.json"
}

generate_policy_sample() {
    cat > "$TEMP_DIR/policy_sample.json" << 'EOF'
{
  "name": "critical-vuln-block",
  "description": "Block deployments with critical vulnerabilities",
  "enabled": true,
  "rules": [
    {
      "condition": "severity == 'critical' AND exploited == true",
      "action": "block",
      "message": "Critical exploited vulnerability detected - deployment blocked"
    },
    {
      "condition": "severity == 'critical' AND internet_facing == true",
      "action": "block",
      "message": "Critical vulnerability on internet-facing service - deployment blocked"
    },
    {
      "condition": "severity == 'high' AND count > 10",
      "action": "warn",
      "message": "High number of high-severity vulnerabilities detected"
    }
  ],
  "exceptions": [
    {
      "application": "legacy-app",
      "reason": "Scheduled for decommission",
      "expires": "2024-06-30"
    }
  ]
}
EOF
    echo "$TEMP_DIR/policy_sample.json"
}

generate_integration_sample() {
    cat > "$TEMP_DIR/integration_sample.json" << 'EOF'
{
  "name": "jira",
  "type": "ticketing",
  "enabled": true,
  "config": {
    "url": "https://example.atlassian.net",
    "project": "SEC",
    "issue_type": "Bug",
    "priority_mapping": {
      "critical": "Highest",
      "high": "High",
      "medium": "Medium",
      "low": "Low"
    },
    "auto_create": true,
    "auto_close": true
  }
}
EOF
    echo "$TEMP_DIR/integration_sample.json"
}

generate_workflow_sample() {
    cat > "$TEMP_DIR/workflow_sample.json" << 'EOF'
{
  "name": "critical-vuln-response",
  "description": "Automated response workflow for critical vulnerabilities",
  "trigger": {
    "type": "finding",
    "conditions": {
      "severity": "critical",
      "exploited": true
    }
  },
  "steps": [
    {
      "name": "create-ticket",
      "action": "jira.create_issue",
      "params": {"priority": "Highest", "assignee": "security-oncall"}
    },
    {
      "name": "notify-slack",
      "action": "slack.send_message",
      "params": {"channel": "#security-alerts", "mention": "@security-team"}
    },
    {
      "name": "block-deployment",
      "action": "pipeline.block",
      "params": {"reason": "Critical vulnerability detected"}
    }
  ]
}
EOF
    echo "$TEMP_DIR/workflow_sample.json"
}

generate_pentest_sample() {
    cat > "$TEMP_DIR/pentest_sample.json" << 'EOF'
{
  "target": {
    "type": "web_application",
    "url": "https://app.example.com",
    "scope": ["*.example.com"]
  },
  "test_types": [
    "sql_injection",
    "xss",
    "authentication_bypass",
    "authorization_flaws",
    "ssrf",
    "xxe"
  ],
  "config": {
    "depth": "comprehensive",
    "authenticated": true,
    "credentials": {
      "username": "test-user",
      "password_env": "PENTEST_PASSWORD"
    },
    "rate_limit": 100,
    "timeout": 3600
  }
}
EOF
    echo "$TEMP_DIR/pentest_sample.json"
}

generate_reachability_sample() {
    cat > "$TEMP_DIR/reachability_sample.json" << 'EOF'
{
  "cve_id": "CVE-2021-44228",
  "application_id": "APP-12345",
  "sbom_ref": "sbom-12345.json",
  "analysis_type": "static",
  "include_transitive": true,
  "call_graph_depth": 5
}
EOF
    echo "$TEMP_DIR/reachability_sample.json"
}

generate_team_sample() {
    cat > "$TEMP_DIR/team_sample.json" << 'EOF'
{
  "name": "Platform Security",
  "description": "Platform security engineering team",
  "members": [
    {"email": "alice@example.com", "role": "lead"},
    {"email": "bob@example.com", "role": "engineer"},
    {"email": "carol@example.com", "role": "engineer"}
  ],
  "applications": ["APP-12345", "APP-67890"],
  "notifications": {
    "slack_channel": "#platform-security",
    "email_digest": "daily"
  }
}
EOF
    echo "$TEMP_DIR/team_sample.json"
}

generate_user_sample() {
    cat > "$TEMP_DIR/user_sample.json" << 'EOF'
{
  "email": "newuser@example.com",
  "name": "New User",
  "role": "analyst",
  "teams": ["Platform Security"],
  "permissions": [
    "view_findings",
    "create_tickets",
    "run_scans"
  ]
}
EOF
    echo "$TEMP_DIR/user_sample.json"
}

generate_pentagi_sample() {
    cat > "$TEMP_DIR/pentagi_sample.json" << 'EOF'
{
  "target_type": "api",
  "target_url": "https://api.example.com/v1",
  "openapi_spec": "https://api.example.com/v1/openapi.json",
  "test_scenarios": [
    "authentication_bypass",
    "authorization_escalation",
    "injection_attacks",
    "rate_limiting"
  ],
  "ai_config": {
    "model": "gpt-4",
    "creativity": 0.7,
    "max_attempts": 100
  }
}
EOF
    echo "$TEMP_DIR/pentagi_sample.json"
}

generate_dedup_sample() {
    cat > "$TEMP_DIR/dedup_sample.json" << 'EOF'
{
  "findings": [
    {
      "id": "finding-001",
      "type": "vulnerability",
      "cve_id": "CVE-2021-44228",
      "source": "scanner-a",
      "location": "src/app.java:42"
    },
    {
      "id": "finding-002",
      "type": "vulnerability",
      "cve_id": "CVE-2021-44228",
      "source": "scanner-b",
      "location": "src/app.java:42"
    },
    {
      "id": "finding-003",
      "type": "vulnerability",
      "cve_id": "CVE-2021-44228",
      "source": "scanner-c",
      "location": "src/app.java:45"
    }
  ],
  "config": {
    "similarity_threshold": 0.85,
    "merge_strategy": "highest_severity"
  }
}
EOF
    echo "$TEMP_DIR/dedup_sample.json"
}

generate_remediation_sample() {
    cat > "$TEMP_DIR/remediation_sample.json" << 'EOF'
{
  "finding_id": "finding-001",
  "cluster_id": "cluster-abc123",
  "severity": "critical",
  "assignee": "alice@example.com",
  "sla_hours": 24,
  "remediation_plan": {
    "steps": [
      "Upgrade log4j to version 2.17.1 or later",
      "Verify no JNDI lookups in configuration",
      "Run security scan to confirm fix"
    ],
    "estimated_effort": "2 hours",
    "risk_if_delayed": "Active exploitation in the wild"
  }
}
EOF
    echo "$TEMP_DIR/remediation_sample.json"
}

generate_bulk_sample() {
    cat > "$TEMP_DIR/bulk_sample.json" << 'EOF'
{
  "operation": "update_status",
  "cluster_ids": [
    "cluster-001",
    "cluster-002",
    "cluster-003",
    "cluster-004",
    "cluster-005"
  ],
  "new_status": "in_progress",
  "assignee": "security-team@example.com",
  "comment": "Bulk assignment for sprint remediation"
}
EOF
    echo "$TEMP_DIR/bulk_sample.json"
}

generate_collaboration_sample() {
    cat > "$TEMP_DIR/collaboration_sample.json" << 'EOF'
{
  "entity_type": "cluster",
  "entity_id": "cluster-abc123",
  "comment": {
    "text": "Investigated this finding - confirmed exploitable in our environment. @alice please prioritize. @bob can you check the WAF rules?",
    "attachments": []
  },
  "watchers": ["alice@example.com", "bob@example.com"]
}
EOF
    echo "$TEMP_DIR/collaboration_sample.json"
}

generate_feeds_sample() {
    cat > "$TEMP_DIR/feeds_sample.json" << 'EOF'
{
  "cve_ids": [
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2023-44487",
    "CVE-2024-3094"
  ],
  "include_epss": true,
  "include_kev": true,
  "include_exploits": true,
  "include_threat_actors": true
}
EOF
    echo "$TEMP_DIR/feeds_sample.json"
}

# ============================================================================
# API CALL FUNCTIONS
# ============================================================================

api_call() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    local content_type="${4:-application/json}"
    
    local curl_args=(-s -w "\n%{http_code}" -X "$method")
    curl_args+=(-H "X-API-Key: $FIXOPS_API_TOKEN")
    curl_args+=(-H "Content-Type: $content_type")
    
    if [[ -n "$data" ]]; then
        if [[ "$content_type" == "multipart/form-data" ]]; then
            curl_args+=(-F "file=@$data")
        else
            curl_args+=(-d "$data")
        fi
    fi
    
    local response
    response=$(curl "${curl_args[@]}" "${FIXOPS_API_URL}${endpoint}" 2>/dev/null)
    
    local http_code="${response##*$'\n'}"
    local body="${response%$'\n'*}"
    
    echo "$http_code"
    echo "$body"
}

# Pretty print JSON response
pretty_print_response() {
    local http_code="$1"
    local body="$2"
    local endpoint="$3"
    
    echo
    draw_box "Response" 70 "$GREEN"
    
    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        draw_box_line "${GREEN}Status: $http_code OK${NC}" 70 "$GREEN"
    elif [[ "$http_code" -ge 400 && "$http_code" -lt 500 ]]; then
        draw_box_line "${YELLOW}Status: $http_code Client Error${NC}" 70 "$GREEN"
    elif [[ "$http_code" -ge 500 ]]; then
        draw_box_line "${RED}Status: $http_code Server Error${NC}" 70 "$GREEN"
    else
        draw_box_line "${GRAY}Status: $http_code${NC}" 70 "$GREEN"
    fi
    
    draw_box_line "Endpoint: $endpoint" 70 "$GREEN"
    draw_box_bottom 70 "$GREEN"
    
    echo
    println_color "$CYAN" "Response Body:"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    echo
}

# ============================================================================
# INTERACTIVE ENDPOINT TESTING
# ============================================================================

edit_and_send() {
    local sample_file="$1"
    local method="$2"
    local endpoint="$3"
    local content_type="${4:-application/json}"
    local is_file_upload="${5:-false}"
    
    echo
    draw_box "Sample Input" 70 "$YELLOW"
    draw_box_line "File: $sample_file" 70 "$YELLOW"
    draw_box_bottom 70 "$YELLOW"
    
    echo
    println_color "$CYAN" "Current sample data:"
    echo
    cat "$sample_file" | jq '.' 2>/dev/null || cat "$sample_file"
    echo
    
    printf "${YELLOW}Options:${NC}\n"
    printf "  ${GREEN}[e]${NC} Edit sample before sending\n"
    printf "  ${GREEN}[s]${NC} Send as-is\n"
    printf "  ${GREEN}[l]${NC} Load from local file\n"
    printf "  ${RED}[c]${NC} Cancel\n"
    echo
    printf "${CYAN}Choice:${NC} "
    read -r choice
    
    case "$choice" in
        e|E)
            println_color "$YELLOW" "Opening editor..."
            $EDITOR "$sample_file"
            ;;
        l|L)
            printf "${CYAN}Enter path to local file:${NC} "
            read -r local_file
            if [[ -f "$local_file" ]]; then
                cp "$local_file" "$sample_file"
                println_color "$GREEN" "Loaded: $local_file"
            else
                println_color "$RED" "File not found: $local_file"
                return 1
            fi
            ;;
        c|C)
            println_color "$YELLOW" "Cancelled"
            return 1
            ;;
        s|S|"")
            ;;
        *)
            println_color "$RED" "Invalid choice"
            return 1
            ;;
    esac
    
    echo
    pulse_text "Sending request to $endpoint"
    
    local data
    if [[ "$is_file_upload" == "true" ]]; then
        data="$sample_file"
        content_type="multipart/form-data"
    else
        data=$(cat "$sample_file")
    fi
    
    local response
    response=$(api_call "$method" "$endpoint" "$data" "$content_type")
    
    local http_code=$(echo "$response" | head -1)
    local body=$(echo "$response" | tail -n +2)
    
    pretty_print_response "$http_code" "$body" "$endpoint"
    
    printf "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# Simple GET request
simple_get() {
    local endpoint="$1"
    local description="$2"
    
    echo
    draw_box "$description" 70 "$BLUE"
    draw_box_line "Endpoint: GET $endpoint" 70 "$BLUE"
    draw_box_bottom 70 "$BLUE"
    
    echo
    pulse_text "Fetching data from $endpoint"
    
    local response
    response=$(api_call "GET" "$endpoint" "" "application/json")
    
    local http_code=$(echo "$response" | head -1)
    local body=$(echo "$response" | tail -n +2)
    
    pretty_print_response "$http_code" "$body" "$endpoint"
    
    printf "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# ============================================================================
# CATEGORY HANDLERS
# ============================================================================

handle_core_pipeline() {
    while true; do
        clear_screen
        draw_box "Core Pipeline & Ingestion" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET  /health - Health check" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/status - Authenticated status" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /inputs/design - Upload design" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} POST /inputs/sbom - Upload SBOM" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} POST /inputs/cve - Upload CVE feed" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} POST /inputs/sarif - Upload SARIF" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} POST /inputs/vex - Upload VEX" 70 "$CYAN"
        draw_box_line "${YELLOW}[8]${NC} POST /inputs/cnapp - Upload CNAPP" 70 "$CYAN"
        draw_box_line "${YELLOW}[9]${NC} POST /inputs/context - Upload context" 70 "$CYAN"
        draw_box_line "${YELLOW}[10]${NC} GET /pipeline/run - Execute pipeline" 70 "$CYAN"
        draw_box_line "${YELLOW}[11]${NC} GET /api/v1/triage - Get triage results" 70 "$CYAN"
        draw_box_line "${YELLOW}[12]${NC} GET /api/v1/graph - Graph visualization" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/health" "Health Check" ;;
            2) simple_get "/api/v1/status" "Authenticated Status" ;;
            3) edit_and_send "$(generate_design_sample)" "POST" "/inputs/design" "multipart/form-data" "true" ;;
            4) edit_and_send "$(generate_sbom_sample)" "POST" "/inputs/sbom" "multipart/form-data" "true" ;;
            5) edit_and_send "$(generate_cve_sample)" "POST" "/inputs/cve" "multipart/form-data" "true" ;;
            6) edit_and_send "$(generate_sarif_sample)" "POST" "/inputs/sarif" "multipart/form-data" "true" ;;
            7) edit_and_send "$(generate_vex_sample)" "POST" "/inputs/vex" "multipart/form-data" "true" ;;
            8) edit_and_send "$(generate_cnapp_sample)" "POST" "/inputs/cnapp" "multipart/form-data" "true" ;;
            9) edit_and_send "$(generate_context_sample)" "POST" "/inputs/context" "multipart/form-data" "true" ;;
            10) simple_get "/pipeline/run" "Execute Pipeline" ;;
            11) simple_get "/api/v1/triage" "Triage Results" ;;
            12) simple_get "/api/v1/graph" "Graph Visualization" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_security_decision() {
    while true; do
        clear_screen
        draw_box "Security Decision & Analysis" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} POST /api/v1/enhanced/compare-llms" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/enhanced/capabilities" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/enhanced/multi-model" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} POST /api/v1/enhanced/consensus" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} POST /api/v1/risk/score" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} POST /api/v1/risk/blast-radius" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} GET  /api/v1/risk/exposure" 70 "$CYAN"
        draw_box_line "${YELLOW}[8]${NC} GET  /api/v1/graph/dependencies" 70 "$CYAN"
        draw_box_line "${YELLOW}[9]${NC} GET  /api/v1/graph/attack-paths" 70 "$CYAN"
        draw_box_line "${YELLOW}[10]${NC} GET /api/v1/evidence/bundles" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) edit_and_send "$(generate_compare_llms_sample)" "POST" "/api/v1/enhanced/compare-llms" ;;
            2) simple_get "/api/v1/enhanced/capabilities" "LLM Capabilities" ;;
            3) edit_and_send "$(generate_compare_llms_sample)" "POST" "/api/v1/enhanced/multi-model" ;;
            4) edit_and_send "$(generate_compare_llms_sample)" "POST" "/api/v1/enhanced/consensus" ;;
            5) edit_and_send "$(generate_risk_score_sample)" "POST" "/api/v1/risk/score" ;;
            6) edit_and_send "$(generate_risk_score_sample)" "POST" "/api/v1/risk/blast-radius" ;;
            7) simple_get "/api/v1/risk/exposure" "Risk Exposure" ;;
            8) simple_get "/api/v1/graph/dependencies" "Dependencies Graph" ;;
            9) simple_get "/api/v1/graph/attack-paths" "Attack Paths" ;;
            10) simple_get "/api/v1/evidence/bundles" "Evidence Bundles" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_compliance() {
    while true; do
        clear_screen
        draw_box "Compliance" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET  /api/v1/compliance/frameworks" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/compliance/frameworks/{id}" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/compliance/frameworks" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET  /api/v1/compliance/controls" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET  /api/v1/compliance/gaps" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/compliance/mapping" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} GET  /api/v1/compliance/coverage" 70 "$CYAN"
        draw_box_line "${YELLOW}[8]${NC} GET  /api/v1/compliance/report" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/compliance/frameworks" "List Frameworks" ;;
            2) 
                printf "${CYAN}Enter framework ID (e.g., SOC2):${NC} "
                read -r fw_id
                simple_get "/api/v1/compliance/frameworks/$fw_id" "Framework Details"
                ;;
            3) edit_and_send "$(generate_compliance_sample)" "POST" "/api/v1/compliance/frameworks" ;;
            4) simple_get "/api/v1/compliance/controls" "List Controls" ;;
            5) simple_get "/api/v1/compliance/gaps" "Compliance Gaps" ;;
            6) simple_get "/api/v1/compliance/mapping" "Control Mapping" ;;
            7) simple_get "/api/v1/compliance/coverage" "Coverage Metrics" ;;
            8) simple_get "/api/v1/compliance/report" "Compliance Report" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_reports() {
    while true; do
        clear_screen
        draw_box "Reports" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET  /api/v1/reports - List reports" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/reports/{id} - Get report" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/reports/generate - Generate" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET  /api/v1/reports/{id}/download" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET  /api/v1/reports/templates" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/reports/schedules" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/reports" "List Reports" ;;
            2)
                printf "${CYAN}Enter report ID:${NC} "
                read -r report_id
                simple_get "/api/v1/reports/$report_id" "Report Details"
                ;;
            3) edit_and_send "$(generate_report_sample)" "POST" "/api/v1/reports/generate" ;;
            4)
                printf "${CYAN}Enter report ID:${NC} "
                read -r report_id
                simple_get "/api/v1/reports/$report_id/download" "Download Report"
                ;;
            5) simple_get "/api/v1/reports/templates" "Report Templates" ;;
            6) simple_get "/api/v1/reports/schedules" "Report Schedules" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_inventory() {
    while true; do
        clear_screen
        draw_box "Inventory" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET  /api/v1/inventory/applications" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/inventory/applications/{id}" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/inventory/applications" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET  /api/v1/inventory/services" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET  /api/v1/inventory/components" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/inventory/dependencies" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} GET  /api/v1/inventory/search" 70 "$CYAN"
        draw_box_line "${YELLOW}[8]${NC} GET  /api/v1/inventory/tags" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/inventory/applications" "List Applications" ;;
            2)
                printf "${CYAN}Enter application ID:${NC} "
                read -r app_id
                simple_get "/api/v1/inventory/applications/$app_id" "Application Details"
                ;;
            3) edit_and_send "$(generate_inventory_app_sample)" "POST" "/api/v1/inventory/applications" ;;
            4) simple_get "/api/v1/inventory/services" "List Services" ;;
            5) simple_get "/api/v1/inventory/components" "List Components" ;;
            6) simple_get "/api/v1/inventory/dependencies" "List Dependencies" ;;
            7)
                printf "${CYAN}Enter search query:${NC} "
                read -r query
                simple_get "/api/v1/inventory/search?q=$query" "Search Results"
                ;;
            8) simple_get "/api/v1/inventory/tags" "List Tags" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_policies() {
    while true; do
        clear_screen
        draw_box "Policies" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET  /api/v1/policies - List policies" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/policies/{id} - Get policy" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/policies - Create policy" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} POST /api/v1/policies/validate - Validate" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} POST /api/v1/policies/test - Test policy" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/policies/export - Export" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/policies" "List Policies" ;;
            2)
                printf "${CYAN}Enter policy ID:${NC} "
                read -r policy_id
                simple_get "/api/v1/policies/$policy_id" "Policy Details"
                ;;
            3) edit_and_send "$(generate_policy_sample)" "POST" "/api/v1/policies" ;;
            4) edit_and_send "$(generate_policy_sample)" "POST" "/api/v1/policies/validate" ;;
            5) edit_and_send "$(generate_policy_sample)" "POST" "/api/v1/policies/test" ;;
            6) simple_get "/api/v1/policies/export" "Export Policies" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_integrations() {
    while true; do
        clear_screen
        draw_box "Integrations" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET  /api/v1/integrations - List" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/integrations/{id} - Get" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/integrations - Create" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} POST /api/v1/integrations/test - Test" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} POST /api/v1/integrations/sync - Sync" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/integrations/webhooks" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/integrations" "List Integrations" ;;
            2)
                printf "${CYAN}Enter integration ID:${NC} "
                read -r int_id
                simple_get "/api/v1/integrations/$int_id" "Integration Details"
                ;;
            3) edit_and_send "$(generate_integration_sample)" "POST" "/api/v1/integrations" ;;
            4) edit_and_send "$(generate_integration_sample)" "POST" "/api/v1/integrations/test" ;;
            5)
                printf "${CYAN}Enter integration name:${NC} "
                read -r int_name
                simple_get "/api/v1/integrations/sync?name=$int_name" "Sync Integration"
                ;;
            6) simple_get "/api/v1/integrations/webhooks" "List Webhooks" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_analytics() {
    while true; do
        clear_screen
        draw_box "Analytics" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET /api/v1/analytics/dashboard" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET /api/v1/analytics/findings" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} GET /api/v1/analytics/trends" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET /api/v1/analytics/mttr" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET /api/v1/analytics/coverage" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET /api/v1/analytics/roi" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} GET /api/v1/analytics/forecast" 70 "$CYAN"
        draw_box_line "${YELLOW}[8]${NC} GET /api/v1/analytics/benchmarks" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/analytics/dashboard" "Dashboard" ;;
            2) simple_get "/api/v1/analytics/findings" "Findings Analytics" ;;
            3) simple_get "/api/v1/analytics/trends" "Trends" ;;
            4) simple_get "/api/v1/analytics/mttr" "MTTR" ;;
            5) simple_get "/api/v1/analytics/coverage" "Coverage" ;;
            6) simple_get "/api/v1/analytics/roi" "ROI" ;;
            7) simple_get "/api/v1/analytics/forecast" "Forecast" ;;
            8) simple_get "/api/v1/analytics/benchmarks" "Benchmarks" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_audit() {
    while true; do
        clear_screen
        draw_box "Audit" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET /api/v1/audit/logs - List logs" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET /api/v1/audit/logs/{id} - Get log" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} GET /api/v1/audit/decisions - Decisions" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET /api/v1/audit/users - User activity" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET /api/v1/audit/policies - Policy changes" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET /api/v1/audit/export - Export" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/audit/logs" "Audit Logs" ;;
            2)
                printf "${CYAN}Enter log ID:${NC} "
                read -r log_id
                simple_get "/api/v1/audit/logs/$log_id" "Log Details"
                ;;
            3) simple_get "/api/v1/audit/decisions" "Decision Audit" ;;
            4) simple_get "/api/v1/audit/users" "User Activity" ;;
            5) simple_get "/api/v1/audit/policies" "Policy Changes" ;;
            6) simple_get "/api/v1/audit/export" "Export Audit" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_workflows() {
    while true; do
        clear_screen
        draw_box "Workflows" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET  /api/v1/workflows - List" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/workflows/{id} - Get" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/workflows - Create" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} POST /api/v1/workflows/{id}/execute" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET  /api/v1/workflows/{id}/history" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/workflows/templates" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/workflows" "List Workflows" ;;
            2)
                printf "${CYAN}Enter workflow ID:${NC} "
                read -r wf_id
                simple_get "/api/v1/workflows/$wf_id" "Workflow Details"
                ;;
            3) edit_and_send "$(generate_workflow_sample)" "POST" "/api/v1/workflows" ;;
            4)
                printf "${CYAN}Enter workflow ID:${NC} "
                read -r wf_id
                simple_get "/api/v1/workflows/$wf_id/execute" "Execute Workflow"
                ;;
            5)
                printf "${CYAN}Enter workflow ID:${NC} "
                read -r wf_id
                simple_get "/api/v1/workflows/$wf_id/history" "Workflow History"
                ;;
            6) simple_get "/api/v1/workflows/templates" "Workflow Templates" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_pentest() {
    while true; do
        clear_screen
        draw_box "Advanced Pen Testing" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} POST /api/v1/pentest/run - Run test" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/pentest/status/{id}" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} GET  /api/v1/pentest/results/{id}" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET  /api/v1/pentest/threat-intel" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} POST /api/v1/pentest/business-impact" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} POST /api/v1/pentest/simulate" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} GET  /api/v1/pentest/remediation/{cve}" 70 "$CYAN"
        draw_box_line "${YELLOW}[8]${NC} GET  /api/v1/pentest/capabilities" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) edit_and_send "$(generate_pentest_sample)" "POST" "/api/v1/pentest/run" ;;
            2)
                printf "${CYAN}Enter test ID:${NC} "
                read -r test_id
                simple_get "/api/v1/pentest/status/$test_id" "Test Status"
                ;;
            3)
                printf "${CYAN}Enter test ID:${NC} "
                read -r test_id
                simple_get "/api/v1/pentest/results/$test_id" "Test Results"
                ;;
            4) simple_get "/api/v1/pentest/threat-intel" "Threat Intelligence" ;;
            5) edit_and_send "$(generate_pentest_sample)" "POST" "/api/v1/pentest/business-impact" ;;
            6) edit_and_send "$(generate_pentest_sample)" "POST" "/api/v1/pentest/simulate" ;;
            7)
                printf "${CYAN}Enter CVE ID:${NC} "
                read -r cve_id
                simple_get "/api/v1/pentest/remediation/$cve_id" "Remediation Guidance"
                ;;
            8) simple_get "/api/v1/pentest/capabilities" "Capabilities" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_reachability() {
    while true; do
        clear_screen
        draw_box "Reachability Analysis" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} POST /api/v1/reachability/analyze" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/reachability/analyze/{cve}" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/reachability/bulk" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET  /api/v1/reachability/status/{job}" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET  /api/v1/reachability/call-graph" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/reachability/paths" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) edit_and_send "$(generate_reachability_sample)" "POST" "/api/v1/reachability/analyze" ;;
            2)
                printf "${CYAN}Enter CVE ID:${NC} "
                read -r cve_id
                simple_get "/api/v1/reachability/analyze/$cve_id" "Reachability Analysis"
                ;;
            3) edit_and_send "$(generate_reachability_sample)" "POST" "/api/v1/reachability/bulk" ;;
            4)
                printf "${CYAN}Enter job ID:${NC} "
                read -r job_id
                simple_get "/api/v1/reachability/status/$job_id" "Job Status"
                ;;
            5) simple_get "/api/v1/reachability/call-graph" "Call Graph" ;;
            6) simple_get "/api/v1/reachability/paths" "Attack Paths" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_teams_users() {
    while true; do
        clear_screen
        draw_box "Teams & Users" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET  /api/v1/teams - List teams" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/teams/{id} - Get team" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/teams - Create team" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET  /api/v1/users - List users" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET  /api/v1/users/{id} - Get user" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} POST /api/v1/users - Create user" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} GET  /api/v1/users/me - Current user" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/teams" "List Teams" ;;
            2)
                printf "${CYAN}Enter team ID:${NC} "
                read -r team_id
                simple_get "/api/v1/teams/$team_id" "Team Details"
                ;;
            3) edit_and_send "$(generate_team_sample)" "POST" "/api/v1/teams" ;;
            4) simple_get "/api/v1/users" "List Users" ;;
            5)
                printf "${CYAN}Enter user ID:${NC} "
                read -r user_id
                simple_get "/api/v1/users/$user_id" "User Details"
                ;;
            6) edit_and_send "$(generate_user_sample)" "POST" "/api/v1/users" ;;
            7) simple_get "/api/v1/users/me" "Current User" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_pentagi() {
    while true; do
        clear_screen
        draw_box "PentAGI" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET  /api/v1/pentagi/requests - List" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/pentagi/requests/{id}" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/pentagi/requests - Create" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET  /api/v1/pentagi/results/{id}" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET  /api/v1/pentagi/capabilities" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/pentagi/config" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/pentagi/requests" "List Requests" ;;
            2)
                printf "${CYAN}Enter request ID:${NC} "
                read -r req_id
                simple_get "/api/v1/pentagi/requests/$req_id" "Request Details"
                ;;
            3) edit_and_send "$(generate_pentagi_sample)" "POST" "/api/v1/pentagi/requests" ;;
            4)
                printf "${CYAN}Enter request ID:${NC} "
                read -r req_id
                simple_get "/api/v1/pentagi/results/$req_id" "Results"
                ;;
            5) simple_get "/api/v1/pentagi/capabilities" "Capabilities" ;;
            6) simple_get "/api/v1/pentagi/config" "Configuration" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_evidence() {
    while true; do
        clear_screen
        draw_box "Evidence" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET /api/v1/evidence/bundles - List" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET /api/v1/evidence/bundles/{id}" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} GET /api/v1/evidence/bundles/{id}/download" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET /api/v1/evidence/manifests" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} POST /api/v1/evidence/verify" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET /api/v1/evidence/search" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/evidence/bundles" "List Bundles" ;;
            2)
                printf "${CYAN}Enter bundle ID:${NC} "
                read -r bundle_id
                simple_get "/api/v1/evidence/bundles/$bundle_id" "Bundle Details"
                ;;
            3)
                printf "${CYAN}Enter bundle ID:${NC} "
                read -r bundle_id
                simple_get "/api/v1/evidence/bundles/$bundle_id/download" "Download Bundle"
                ;;
            4) simple_get "/api/v1/evidence/manifests" "List Manifests" ;;
            5)
                printf "${CYAN}Enter bundle ID to verify:${NC} "
                read -r bundle_id
                echo "{\"bundle_id\": \"$bundle_id\"}" > "$TEMP_DIR/verify_sample.json"
                edit_and_send "$TEMP_DIR/verify_sample.json" "POST" "/api/v1/evidence/verify"
                ;;
            6) simple_get "/api/v1/evidence/search" "Search Evidence" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_health() {
    while true; do
        clear_screen
        draw_box "Health & Status" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET /health - Basic health" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET /api/v1/status - Auth status" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} GET /api/v1/version - Version" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET /api/v1/config - Configuration" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/health" "Health Check" ;;
            2) simple_get "/api/v1/status" "Auth Status" ;;
            3) simple_get "/api/v1/version" "Version Info" ;;
            4) simple_get "/api/v1/config" "Configuration" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_deduplication() {
    while true; do
        clear_screen
        draw_box "Deduplication & Correlation" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} POST /api/v1/deduplication/process" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} POST /api/v1/deduplication/process/batch" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} GET  /api/v1/deduplication/clusters" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET  /api/v1/deduplication/clusters/{id}" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET  /api/v1/deduplication/stats" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} POST /api/v1/deduplication/clusters/merge" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} GET  /api/v1/deduplication/graph" 70 "$CYAN"
        draw_box_line "${YELLOW}[8]${NC} POST /api/v1/deduplication/feedback" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) edit_and_send "$(generate_dedup_sample)" "POST" "/api/v1/deduplication/process" ;;
            2) edit_and_send "$(generate_dedup_sample)" "POST" "/api/v1/deduplication/process/batch" ;;
            3) simple_get "/api/v1/deduplication/clusters" "List Clusters" ;;
            4)
                printf "${CYAN}Enter cluster ID:${NC} "
                read -r cluster_id
                simple_get "/api/v1/deduplication/clusters/$cluster_id" "Cluster Details"
                ;;
            5) simple_get "/api/v1/deduplication/stats" "Dedup Stats" ;;
            6) edit_and_send "$(generate_dedup_sample)" "POST" "/api/v1/deduplication/clusters/merge" ;;
            7) simple_get "/api/v1/deduplication/graph" "Correlation Graph" ;;
            8) edit_and_send "$(generate_dedup_sample)" "POST" "/api/v1/deduplication/feedback" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_remediation() {
    while true; do
        clear_screen
        draw_box "Remediation Lifecycle" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} POST /api/v1/remediation/tasks - Create" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/remediation/tasks - List" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} GET  /api/v1/remediation/tasks/{id}" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} PUT  /api/v1/remediation/tasks/{id}/status" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} PUT  /api/v1/remediation/tasks/{id}/assign" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} POST /api/v1/remediation/tasks/{id}/verify" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} POST /api/v1/remediation/sla/check" 70 "$CYAN"
        draw_box_line "${YELLOW}[8]${NC} GET  /api/v1/remediation/metrics" 70 "$CYAN"
        draw_box_line "${YELLOW}[9]${NC} GET  /api/v1/remediation/statuses" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) edit_and_send "$(generate_remediation_sample)" "POST" "/api/v1/remediation/tasks" ;;
            2) simple_get "/api/v1/remediation/tasks" "List Tasks" ;;
            3)
                printf "${CYAN}Enter task ID:${NC} "
                read -r task_id
                simple_get "/api/v1/remediation/tasks/$task_id" "Task Details"
                ;;
            4)
                printf "${CYAN}Enter task ID:${NC} "
                read -r task_id
                echo "{\"status\": \"in_progress\"}" > "$TEMP_DIR/status_sample.json"
                edit_and_send "$TEMP_DIR/status_sample.json" "PUT" "/api/v1/remediation/tasks/$task_id/status"
                ;;
            5)
                printf "${CYAN}Enter task ID:${NC} "
                read -r task_id
                echo "{\"assignee\": \"user@example.com\"}" > "$TEMP_DIR/assign_sample.json"
                edit_and_send "$TEMP_DIR/assign_sample.json" "PUT" "/api/v1/remediation/tasks/$task_id/assign"
                ;;
            6)
                printf "${CYAN}Enter task ID:${NC} "
                read -r task_id
                echo "{\"evidence\": \"Fix verified via scan\"}" > "$TEMP_DIR/verify_sample.json"
                edit_and_send "$TEMP_DIR/verify_sample.json" "POST" "/api/v1/remediation/tasks/$task_id/verify"
                ;;
            7) simple_get "/api/v1/remediation/sla/check" "SLA Check" ;;
            8) simple_get "/api/v1/remediation/metrics" "Remediation Metrics" ;;
            9) simple_get "/api/v1/remediation/statuses" "Valid Statuses" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_bulk() {
    while true; do
        clear_screen
        draw_box "Bulk Operations" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} POST /api/v1/bulk/clusters/status" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} POST /api/v1/bulk/clusters/assign" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/bulk/clusters/accept-risk" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} POST /api/v1/bulk/clusters/tickets" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} POST /api/v1/bulk/clusters/export" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/bulk/jobs - List jobs" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} GET  /api/v1/bulk/jobs/{id} - Job status" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) edit_and_send "$(generate_bulk_sample)" "POST" "/api/v1/bulk/clusters/status" ;;
            2) edit_and_send "$(generate_bulk_sample)" "POST" "/api/v1/bulk/clusters/assign" ;;
            3) edit_and_send "$(generate_bulk_sample)" "POST" "/api/v1/bulk/clusters/accept-risk" ;;
            4) edit_and_send "$(generate_bulk_sample)" "POST" "/api/v1/bulk/clusters/tickets" ;;
            5) edit_and_send "$(generate_bulk_sample)" "POST" "/api/v1/bulk/clusters/export" ;;
            6) simple_get "/api/v1/bulk/jobs" "List Jobs" ;;
            7)
                printf "${CYAN}Enter job ID:${NC} "
                read -r job_id
                simple_get "/api/v1/bulk/jobs/$job_id" "Job Status"
                ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_collaboration() {
    while true; do
        clear_screen
        draw_box "Team Collaboration" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} POST /api/v1/collaboration/comments" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} GET  /api/v1/collaboration/comments" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} POST /api/v1/collaboration/watchers" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} GET  /api/v1/collaboration/watchers" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET  /api/v1/collaboration/activities" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/collaboration/mentions/{user}" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} GET  /api/v1/collaboration/entity-types" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) edit_and_send "$(generate_collaboration_sample)" "POST" "/api/v1/collaboration/comments" ;;
            2) simple_get "/api/v1/collaboration/comments" "List Comments" ;;
            3) edit_and_send "$(generate_collaboration_sample)" "POST" "/api/v1/collaboration/watchers" ;;
            4) simple_get "/api/v1/collaboration/watchers" "List Watchers" ;;
            5) simple_get "/api/v1/collaboration/activities" "Activity Feed" ;;
            6)
                printf "${CYAN}Enter user ID:${NC} "
                read -r user_id
                simple_get "/api/v1/collaboration/mentions/$user_id" "User Mentions"
                ;;
            7) simple_get "/api/v1/collaboration/entity-types" "Entity Types" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

handle_feeds() {
    while true; do
        clear_screen
        draw_box "Vulnerability Intelligence Feeds" 70 "$CYAN"
        draw_box_line "${YELLOW}[1]${NC} GET  /api/v1/feeds/epss - EPSS scores" 70 "$CYAN"
        draw_box_line "${YELLOW}[2]${NC} POST /api/v1/feeds/epss/refresh" 70 "$CYAN"
        draw_box_line "${YELLOW}[3]${NC} GET  /api/v1/feeds/kev - CISA KEV" 70 "$CYAN"
        draw_box_line "${YELLOW}[4]${NC} POST /api/v1/feeds/kev/refresh" 70 "$CYAN"
        draw_box_line "${YELLOW}[5]${NC} GET  /api/v1/feeds/exploits/{cve}" 70 "$CYAN"
        draw_box_line "${YELLOW}[6]${NC} GET  /api/v1/feeds/threat-actors/{cve}" 70 "$CYAN"
        draw_box_line "${YELLOW}[7]${NC} GET  /api/v1/feeds/supply-chain/{pkg}" 70 "$CYAN"
        draw_box_line "${YELLOW}[8]${NC} GET  /api/v1/feeds/cloud-bulletins" 70 "$CYAN"
        draw_box_line "${YELLOW}[9]${NC} GET  /api/v1/feeds/early-signals" 70 "$CYAN"
        draw_box_line "${YELLOW}[10]${NC} POST /api/v1/feeds/enrich" 70 "$CYAN"
        draw_box_line "${YELLOW}[11]${NC} GET /api/v1/feeds/stats" 70 "$CYAN"
        draw_box_line "${YELLOW}[12]${NC} GET /api/v1/feeds/health" 70 "$CYAN"
        draw_box_line "" 70 "$CYAN"
        draw_box_line "${RED}[b]${NC} Back to main menu" 70 "$CYAN"
        draw_box_bottom 70 "$CYAN"
        
        printf "\n${CYAN}Choice:${NC} "
        read -r choice
        
        case "$choice" in
            1) simple_get "/api/v1/feeds/epss" "EPSS Scores" ;;
            2) simple_get "/api/v1/feeds/epss/refresh" "Refresh EPSS" ;;
            3) simple_get "/api/v1/feeds/kev" "CISA KEV" ;;
            4) simple_get "/api/v1/feeds/kev/refresh" "Refresh KEV" ;;
            5)
                printf "${CYAN}Enter CVE ID:${NC} "
                read -r cve_id
                simple_get "/api/v1/feeds/exploits/$cve_id" "Exploit Intel"
                ;;
            6)
                printf "${CYAN}Enter CVE ID:${NC} "
                read -r cve_id
                simple_get "/api/v1/feeds/threat-actors/$cve_id" "Threat Actors"
                ;;
            7)
                printf "${CYAN}Enter package name:${NC} "
                read -r pkg
                simple_get "/api/v1/feeds/supply-chain/$pkg" "Supply Chain"
                ;;
            8) simple_get "/api/v1/feeds/cloud-bulletins" "Cloud Bulletins" ;;
            9) simple_get "/api/v1/feeds/early-signals" "Early Signals" ;;
            10) edit_and_send "$(generate_feeds_sample)" "POST" "/api/v1/feeds/enrich" ;;
            11) simple_get "/api/v1/feeds/stats" "Feed Stats" ;;
            12) simple_get "/api/v1/feeds/health" "Feed Health" ;;
            b|B) return ;;
            *) println_color "$RED" "Invalid choice" ;;
        esac
    done
}

# ============================================================================
# RUN ALL TESTS
# ============================================================================

run_all_tests() {
    clear_screen
    draw_box "Running All API Tests" 70 "$GREEN"
    draw_box_line "This will test all major endpoints automatically" 70 "$GREEN"
    draw_box_bottom 70 "$GREEN"
    
    echo
    printf "${YELLOW}This will run tests against: ${FIXOPS_API_URL}${NC}\n"
    printf "${CYAN}Continue? [y/N]:${NC} "
    read -r confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        println_color "$YELLOW" "Cancelled"
        return
    fi
    
    local total=0
    local passed=0
    local failed=0
    
    local endpoints=(
        "GET:/health"
        "GET:/api/v1/status"
        "GET:/api/v1/enhanced/capabilities"
        "GET:/api/v1/compliance/frameworks"
        "GET:/api/v1/reports"
        "GET:/api/v1/inventory/applications"
        "GET:/api/v1/policies"
        "GET:/api/v1/integrations"
        "GET:/api/v1/analytics/dashboard"
        "GET:/api/v1/audit/logs"
        "GET:/api/v1/workflows"
        "GET:/api/v1/pentest/capabilities"
        "GET:/api/v1/teams"
        "GET:/api/v1/users"
        "GET:/api/v1/pentagi/requests"
        "GET:/api/v1/evidence/bundles"
        "GET:/api/v1/deduplication/clusters"
        "GET:/api/v1/remediation/tasks"
        "GET:/api/v1/bulk/jobs"
        "GET:/api/v1/collaboration/entity-types"
        "GET:/api/v1/feeds/stats"
        "GET:/api/v1/feeds/health"
    )
    
    echo
    println_color "$CYAN" "Testing ${#endpoints[@]} endpoints..."
    echo
    
    for endpoint_spec in "${endpoints[@]}"; do
        IFS=':' read -r method endpoint <<< "$endpoint_spec"
        ((total++))
        
        printf "${CYAN}[%2d/%2d]${NC} %-6s %-40s " "$total" "${#endpoints[@]}" "$method" "$endpoint"
        
        local response
        response=$(api_call "$method" "$endpoint" "" "application/json")
        local http_code=$(echo "$response" | head -1)
        
        if [[ "$http_code" -ge 200 && "$http_code" -lt 400 ]]; then
            printf "${GREEN}PASS${NC} (${http_code})\n"
            ((passed++))
        else
            printf "${RED}FAIL${NC} (${http_code})\n"
            ((failed++))
        fi
        
        sleep 0.1
    done
    
    echo
    draw_box "Test Results" 50 "$MAGENTA"
    draw_box_line "Total:  $total" 50 "$MAGENTA"
    draw_box_line "${GREEN}Passed: $passed${NC}" 50 "$MAGENTA"
    draw_box_line "${RED}Failed: $failed${NC}" 50 "$MAGENTA"
    draw_box_line "Success Rate: $((passed * 100 / total))%" 50 "$MAGENTA"
    draw_box_bottom 50 "$MAGENTA"
    
    echo
    printf "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# ============================================================================
# MAIN LOOP
# ============================================================================

main() {
    # Ensure temp directory exists
    mkdir -p "$TEMP_DIR"
    
    # Trap to clean up on exit
    trap 'show_cursor; echo' EXIT
    
    # Show banner and intro
    show_banner
    show_intro_animation
    
    # Main menu loop
    while true; do
        show_main_menu
        read -r choice
        
        case "$choice" in
            1) handle_core_pipeline ;;
            2) handle_security_decision ;;
            3) handle_compliance ;;
            4) handle_reports ;;
            5) handle_inventory ;;
            6) handle_policies ;;
            7) handle_integrations ;;
            8) handle_analytics ;;
            9) handle_audit ;;
            10) handle_workflows ;;
            11) handle_pentest ;;
            12) handle_reachability ;;
            13) handle_teams_users ;;
            14) handle_pentagi ;;
            15) handle_evidence ;;
            16) handle_health ;;
            17) handle_deduplication ;;
            18) handle_remediation ;;
            19) handle_bulk ;;
            20) handle_collaboration ;;
            21) handle_feeds ;;
            22) run_all_tests ;;
            q|Q)
                clear_screen
                println_color "$GREEN" "Thank you for using FixOps Interactive Tester!"
                println_color "$CYAN" "Goodbye!"
                exit 0
                ;;
            *)
                println_color "$RED" "Invalid choice. Please try again."
                sleep 1
                ;;
        esac
    done
}

# Run main
main "$@"
