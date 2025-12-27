#!/usr/bin/env bash
#
# ALDECI Compatibility Check Tool
# ================================
# Validates security tool outputs against FixOps API to ensure compatibility
# before deployment at customer sites.
#
# Usage:
#   ./aldeci-compatibility-check.sh [OPTIONS] <file1> [file2] ...
#
# Options:
#   -u, --url URL       FixOps API URL (default: http://localhost:8000)
#   -k, --api-key KEY   API key for authentication (or set FIXOPS_API_TOKEN)
#   -t, --type TYPE     Force input type (sarif|sbom|cve|vex|cnapp)
#   -v, --verbose       Show detailed output
#   -q, --quiet         Only show pass/fail status
#   -j, --json          Output results as JSON
#   -b, --batch         Process all files in batch mode
#   -e, --end-to-end    Run full pipeline after validation
#   -h, --help          Show this help message
#
# Examples:
#   # Validate a single SARIF file
#   ./aldeci-compatibility-check.sh scan-results.sarif
#
#   # Validate multiple files with custom API URL
#   ./aldeci-compatibility-check.sh -u https://fixops.example.com sbom.json cve.json
#
#   # Validate and run full pipeline
#   ./aldeci-compatibility-check.sh -e trivy-results.json
#
#   # Batch validate all files in a directory
#   ./aldeci-compatibility-check.sh -b ./security-outputs/*.json
#

set -euo pipefail

# Colors and formatting
if [[ -t 1 ]] && command -v tput &>/dev/null; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    CYAN=$(tput setaf 6)
    BOLD=$(tput bold)
    NC=$(tput sgr0)
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

# Default configuration
API_URL="${FIXOPS_API_URL:-http://localhost:8000}"
API_KEY="${FIXOPS_API_TOKEN:-}"
INPUT_TYPE=""
VERBOSE=false
QUIET=false
JSON_OUTPUT=false
BATCH_MODE=false
END_TO_END=false
FILES=()

# Counters
TOTAL=0
PASSED=0
FAILED=0
WARNINGS=0

# Print functions
print_header() {
    if [[ "$QUIET" == "false" && "$JSON_OUTPUT" == "false" ]]; then
        echo ""
        echo "${BOLD}${CYAN}========================================${NC}"
        echo "${BOLD}${CYAN}  ALDECI Compatibility Check Tool${NC}"
        echo "${BOLD}${CYAN}========================================${NC}"
        echo ""
    fi
}

print_info() {
    if [[ "$QUIET" == "false" && "$JSON_OUTPUT" == "false" ]]; then
        echo "${BLUE}[INFO]${NC} $1"
    fi
}

print_success() {
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        echo "${GREEN}[PASS]${NC} $1"
    fi
}

print_warning() {
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        echo "${YELLOW}[WARN]${NC} $1"
    fi
}

print_error() {
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        echo "${RED}[FAIL]${NC} $1"
    fi
}

print_verbose() {
    if [[ "$VERBOSE" == "true" && "$JSON_OUTPUT" == "false" ]]; then
        echo "${CYAN}[DEBUG]${NC} $1"
    fi
}

show_help() {
    cat << 'EOF'
ALDECI Compatibility Check Tool
================================

Validates security tool outputs against FixOps API to ensure compatibility
before deployment at customer sites.

USAGE:
    ./aldeci-compatibility-check.sh [OPTIONS] <file1> [file2] ...

OPTIONS:
    -u, --url URL       FixOps API URL (default: http://localhost:8000)
    -k, --api-key KEY   API key for authentication (or set FIXOPS_API_TOKEN)
    -t, --type TYPE     Force input type (sarif|sbom|cve|vex|cnapp)
    -v, --verbose       Show detailed output
    -q, --quiet         Only show pass/fail status
    -j, --json          Output results as JSON
    -b, --batch         Process all files in batch mode
    -e, --end-to-end    Run full pipeline after validation
    -h, --help          Show this help message

ENVIRONMENT VARIABLES:
    FIXOPS_API_URL      Default API URL
    FIXOPS_API_TOKEN    API key for authentication

SUPPORTED FORMATS:
    SARIF       Static analysis results (ESLint, Semgrep, CodeQL, Checkmarx)
    SBOM        Software Bill of Materials (CycloneDX, SPDX, Syft)
    CVE         Vulnerability feeds (Trivy, Grype, NVD, KEV)
    VEX         Vulnerability Exploitability eXchange (OpenVEX, CycloneDX VEX)
    CNAPP       Cloud-native findings (AWS Security Hub, Azure Defender, GCP SCC)

EXAMPLES:
    # Validate a single SARIF file
    ./aldeci-compatibility-check.sh scan-results.sarif

    # Validate multiple files with custom API URL
    ./aldeci-compatibility-check.sh -u https://fixops.example.com sbom.json cve.json

    # Validate and run full pipeline
    ./aldeci-compatibility-check.sh -e trivy-results.json

    # Batch validate all files in a directory
    ./aldeci-compatibility-check.sh -b ./security-outputs/*.json

    # JSON output for CI/CD integration
    ./aldeci-compatibility-check.sh -j -b *.json > results.json

EXIT CODES:
    0   All files validated successfully
    1   One or more files failed validation
    2   Invalid arguments or configuration error
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--url)
                API_URL="$2"
                shift 2
                ;;
            -k|--api-key)
                API_KEY="$2"
                shift 2
                ;;
            -t|--type)
                INPUT_TYPE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -j|--json)
                JSON_OUTPUT=true
                shift
                ;;
            -b|--batch)
                BATCH_MODE=true
                shift
                ;;
            -e|--end-to-end)
                END_TO_END=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                echo "Unknown option: $1" >&2
                show_help
                exit 2
                ;;
            *)
                FILES+=("$1")
                shift
                ;;
        esac
    done

    if [[ ${#FILES[@]} -eq 0 ]]; then
        echo "Error: No input files specified" >&2
        show_help
        exit 2
    fi

    if [[ -z "$API_KEY" ]]; then
        echo "Error: API key required. Set FIXOPS_API_TOKEN or use -k/--api-key" >&2
        exit 2
    fi
}

# Check API connectivity
check_api() {
    print_verbose "Checking API connectivity at $API_URL"
    
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-API-Key: $API_KEY" \
        "$API_URL/health" 2>/dev/null || echo "000")
    
    if [[ "$response" == "200" ]]; then
        print_info "API connection successful"
        return 0
    else
        print_error "Cannot connect to API at $API_URL (HTTP $response)"
        return 1
    fi
}

# Detect file type based on content
detect_file_type() {
    local file="$1"
    
    # Check if file exists
    if [[ ! -f "$file" ]]; then
        echo "unknown"
        return
    fi
    
    # Read first 1000 bytes for detection
    local content
    content=$(head -c 1000 "$file" 2>/dev/null || echo "")
    
    # SARIF detection
    if echo "$content" | grep -q '"$schema".*sarif' 2>/dev/null; then
        echo "sarif"
        return
    fi
    if echo "$content" | grep -q '"version".*"2.1.0"' 2>/dev/null && echo "$content" | grep -q '"runs"' 2>/dev/null; then
        echo "sarif"
        return
    fi
    
    # CycloneDX SBOM detection
    if echo "$content" | grep -q '"bomFormat".*"CycloneDX"' 2>/dev/null; then
        echo "sbom"
        return
    fi
    
    # SPDX detection
    if echo "$content" | grep -q '"spdxVersion"' 2>/dev/null; then
        echo "sbom"
        return
    fi
    
    # Trivy detection
    if echo "$content" | grep -q '"SchemaVersion"' 2>/dev/null && echo "$content" | grep -q '"Results"' 2>/dev/null; then
        echo "cve"
        return
    fi
    
    # Grype detection
    if echo "$content" | grep -q '"matches"' 2>/dev/null && echo "$content" | grep -q '"source"' 2>/dev/null; then
        echo "cve"
        return
    fi
    
    # VEX detection
    if echo "$content" | grep -q '"@context".*openvex' 2>/dev/null; then
        echo "vex"
        return
    fi
    
    # CNAPP detection
    if echo "$content" | grep -q '"findings"' 2>/dev/null && echo "$content" | grep -q '"provider"\|"cloudProvider"' 2>/dev/null; then
        echo "cnapp"
        return
    fi
    
    # Snyk detection (will be converted to SARIF)
    if echo "$content" | grep -q '"vulnerabilities"' 2>/dev/null && echo "$content" | grep -qi 'snyk\|packageManager' 2>/dev/null; then
        echo "sarif"
        return
    fi
    
    # Generic SBOM indicators
    if echo "$content" | grep -q '"components"\|"packages"\|"dependencies"' 2>/dev/null; then
        echo "sbom"
        return
    fi
    
    # CSV detection for design files
    if [[ "$file" == *.csv ]]; then
        echo "design"
        return
    fi
    
    echo "unknown"
}

# Validate a single file using the validation API
validate_file() {
    local file="$1"
    local file_type="${INPUT_TYPE:-$(detect_file_type "$file")}"
    local filename
    filename=$(basename "$file")
    
    ((TOTAL++))
    
    print_verbose "Validating: $file (detected type: $file_type)"
    
    if [[ ! -f "$file" ]]; then
        print_error "$filename: File not found"
        ((FAILED++))
        return 1
    fi
    
    if [[ "$file_type" == "unknown" ]]; then
        print_error "$filename: Could not detect file type"
        ((FAILED++))
        return 1
    fi
    
    # Call validation API
    local response
    local http_code
    local temp_file
    temp_file=$(mktemp)
    
    http_code=$(curl -s -w "%{http_code}" -o "$temp_file" \
        -H "X-API-Key: $API_KEY" \
        -F "file=@$file" \
        -F "input_type=$file_type" \
        "$API_URL/api/v1/validate/input" 2>/dev/null || echo "000")
    
    response=$(cat "$temp_file")
    rm -f "$temp_file"
    
    if [[ "$http_code" != "200" ]]; then
        # Fallback: try direct ingestion endpoint with dry validation
        print_verbose "Validation API returned $http_code, trying direct ingestion..."
        
        local endpoint="/inputs/$file_type"
        http_code=$(curl -s -w "%{http_code}" -o "$temp_file" \
            -H "X-API-Key: $API_KEY" \
            -F "file=@$file" \
            "$API_URL$endpoint" 2>/dev/null || echo "000")
        
        response=$(cat "$temp_file" 2>/dev/null || echo "{}")
        rm -f "$temp_file"
        
        if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
            print_success "$filename: Compatible (ingested successfully via $endpoint)"
            ((PASSED++))
            
            if [[ "$VERBOSE" == "true" ]]; then
                echo "$response" | jq -r '.status // "ok", .stage // "unknown"' 2>/dev/null || true
            fi
            return 0
        else
            print_error "$filename: Incompatible (HTTP $http_code)"
            if [[ "$VERBOSE" == "true" ]]; then
                echo "$response" | jq -r '.detail // .message // "Unknown error"' 2>/dev/null || echo "$response"
            fi
            ((FAILED++))
            return 1
        fi
    fi
    
    # Parse validation response
    local valid
    local warnings_count
    local errors_count
    local findings_count
    local detected_format
    local tool_name
    
    valid=$(echo "$response" | jq -r '.valid // false' 2>/dev/null || echo "false")
    warnings_count=$(echo "$response" | jq -r '.warnings | length // 0' 2>/dev/null || echo "0")
    errors_count=$(echo "$response" | jq -r '.errors | length // 0' 2>/dev/null || echo "0")
    findings_count=$(echo "$response" | jq -r '.findings_count // 0' 2>/dev/null || echo "0")
    detected_format=$(echo "$response" | jq -r '.detected_format // "unknown"' 2>/dev/null || echo "unknown")
    tool_name=$(echo "$response" | jq -r '.tool_name // "unknown"' 2>/dev/null || echo "unknown")
    
    if [[ "$valid" == "true" ]]; then
        if [[ "$warnings_count" -gt 0 ]]; then
            print_warning "$filename: Compatible with warnings ($detected_format, $findings_count findings)"
            ((PASSED++))
            ((WARNINGS++))
            if [[ "$VERBOSE" == "true" ]]; then
                echo "$response" | jq -r '.warnings[]' 2>/dev/null || true
            fi
        else
            print_success "$filename: Compatible ($detected_format, $findings_count findings)"
            ((PASSED++))
        fi
        
        if [[ "$VERBOSE" == "true" ]]; then
            print_verbose "  Tool: $tool_name"
            print_verbose "  Format: $detected_format"
            print_verbose "  Findings: $findings_count"
        fi
        return 0
    else
        print_error "$filename: Incompatible"
        if [[ "$VERBOSE" == "true" || "$errors_count" -gt 0 ]]; then
            echo "$response" | jq -r '.errors[]' 2>/dev/null || true
        fi
        ((FAILED++))
        return 1
    fi
}

# Run end-to-end pipeline test
run_end_to_end() {
    local file="$1"
    local file_type="${INPUT_TYPE:-$(detect_file_type "$file")}"
    local filename
    filename=$(basename "$file")
    
    print_info "Running end-to-end pipeline test for $filename..."
    
    # First, ingest the file
    local endpoint="/inputs/$file_type"
    local response
    local http_code
    local temp_file
    temp_file=$(mktemp)
    
    http_code=$(curl -s -w "%{http_code}" -o "$temp_file" \
        -H "X-API-Key: $API_KEY" \
        -F "file=@$file" \
        "$API_URL$endpoint" 2>/dev/null || echo "000")
    
    response=$(cat "$temp_file")
    rm -f "$temp_file"
    
    if [[ "$http_code" != "200" && "$http_code" != "201" ]]; then
        print_error "Ingestion failed (HTTP $http_code)"
        return 1
    fi
    
    print_verbose "Ingestion successful, running pipeline..."
    
    # Run the pipeline
    http_code=$(curl -s -w "%{http_code}" -o "$temp_file" \
        -H "X-API-Key: $API_KEY" \
        "$API_URL/pipeline/run" 2>/dev/null || echo "000")
    
    response=$(cat "$temp_file")
    rm -f "$temp_file"
    
    if [[ "$http_code" == "200" ]]; then
        local findings_count
        findings_count=$(echo "$response" | jq -r '.findings | length // 0' 2>/dev/null || echo "0")
        print_success "Pipeline completed: $findings_count findings processed"
        
        if [[ "$VERBOSE" == "true" ]]; then
            echo "$response" | jq -r '.summary // empty' 2>/dev/null || true
        fi
        return 0
    else
        print_error "Pipeline failed (HTTP $http_code)"
        return 1
    fi
}

# Output JSON results
output_json() {
    local results=()
    
    for file in "${FILES[@]}"; do
        local file_type="${INPUT_TYPE:-$(detect_file_type "$file")}"
        local filename
        filename=$(basename "$file")
        local status="unknown"
        
        if [[ -f "$file" ]]; then
            # Quick validation check
            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                -H "X-API-Key: $API_KEY" \
                -F "file=@$file" \
                "$API_URL/inputs/$file_type" 2>/dev/null || echo "000")
            
            if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
                status="pass"
            else
                status="fail"
            fi
        else
            status="error"
        fi
        
        # Use jq to properly escape special characters in filenames
        local json_entry
        json_entry=$(jq -n --arg file "$filename" --arg type "$file_type" --arg status "$status" \
            '{file: $file, type: $type, status: $status}')
        results+=("$json_entry")
    done
    
    local json_results
    json_results=$(printf '%s\n' "${results[@]}" | jq -s '.')
    
    jq -n \
        --argjson results "$json_results" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg api_url "$API_URL" \
        --argjson total "$TOTAL" \
        --argjson passed "$PASSED" \
        --argjson failed "$FAILED" \
        --argjson warnings "$WARNINGS" \
        '{
            timestamp: $timestamp,
            api_url: $api_url,
            summary: {
                total: $total,
                passed: $passed,
                failed: $failed,
                warnings: $warnings
            },
            results: $results
        }'
}

# Print summary
print_summary() {
    if [[ "$QUIET" == "false" && "$JSON_OUTPUT" == "false" ]]; then
        echo ""
        echo "${BOLD}========================================${NC}"
        echo "${BOLD}  Compatibility Check Summary${NC}"
        echo "${BOLD}========================================${NC}"
        echo ""
        echo "  Total files:    $TOTAL"
        echo "  ${GREEN}Passed:${NC}         $PASSED"
        echo "  ${RED}Failed:${NC}         $FAILED"
        echo "  ${YELLOW}Warnings:${NC}       $WARNINGS"
        echo ""
        
        if [[ $FAILED -eq 0 ]]; then
            echo "${GREEN}${BOLD}All files are compatible with FixOps!${NC}"
        else
            echo "${RED}${BOLD}Some files are not compatible. See errors above.${NC}"
        fi
        echo ""
    fi
}

# Main function
main() {
    parse_args "$@"
    
    print_header
    
    # Check API connectivity
    if ! check_api; then
        exit 2
    fi
    
    print_info "API URL: $API_URL"
    print_info "Files to validate: ${#FILES[@]}"
    echo ""
    
    # Process files
    if [[ "$BATCH_MODE" == "true" ]]; then
        # Batch mode - validate all files first
        for file in "${FILES[@]}"; do
            validate_file "$file" || true
        done
    else
        # Sequential mode with optional end-to-end
        for file in "${FILES[@]}"; do
            if validate_file "$file"; then
                if [[ "$END_TO_END" == "true" ]]; then
                    run_end_to_end "$file" || true
                fi
            fi
        done
    fi
    
    # Output results
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        output_json
    else
        print_summary
    fi
    
    # Exit with appropriate code
    if [[ $FAILED -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

# Run main function
main "$@"
