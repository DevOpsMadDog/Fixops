#!/usr/bin/env bash
# ALDECI GitHub Action — SAST / SCA / IaC security scanning entrypoint
# Calls ALDECI APIs, evaluates severity gate, outputs PR annotations.
set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
API_URL="${ALDECI_API_URL:?ALDECI_API_URL is required}"
API_KEY="${ALDECI_API_KEY:?ALDECI_API_KEY is required}"
SCAN_TYPE="${SCAN_TYPE:-all}"
SEVERITY_THRESHOLD="${SEVERITY_THRESHOLD:-high}"
FAIL_ON_FINDINGS="${FAIL_ON_FINDINGS:-true}"
APP_ID="${APP_ID:-}"
PROJECT_ID="${PROJECT_ID:-}"
IAC_PATHS="${IAC_PATHS:-.}"
SCANNER_TYPE="${SCANNER_TYPE:-}"
UPLOAD_SARIF="${UPLOAD_SARIF:-false}"
COMMENT_ON_PR="${COMMENT_ON_PR:-true}"

# Trim trailing slash from API URL
API_URL="${API_URL%/}"

# GitHub context
REPO="${GITHUB_REPOSITORY:-unknown/repo}"
BRANCH="${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-main}}"
SHA="${GITHUB_SHA:-unknown}"
PR_NUMBER="${GITHUB_EVENT_NUMBER:-}"
WORKSPACE="${GITHUB_WORKSPACE:-.}"

# Output files
RESULTS_DIR="/tmp/aldeci-results"
mkdir -p "$RESULTS_DIR"
SARIF_FILE="$RESULTS_DIR/aldeci-results.sarif"
SUMMARY_FILE="$RESULTS_DIR/scan-summary.json"

# Counters
TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0
TOTAL_FINDINGS=0
SCAN_ID=""
SCAN_ERRORS=""

# ── Helper functions ───────────────────────────────────────────────────────

log_info()  { echo "::notice::$*"; }
log_warn()  { echo "::warning::$*"; }
log_error() { echo "::error::$*"; }
log_group() { echo "::group::$1"; }
log_endgroup() { echo "::endgroup::"; }

# Set a GitHub Actions output variable
set_output() {
    local name="$1" value="$2"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        echo "${name}=${value}" >> "$GITHUB_OUTPUT"
    fi
}

# Make an authenticated API call to ALDECI
api_call() {
    local method="$1" endpoint="$2"
    shift 2
    curl -sf --max-time 120 \
        -X "$method" \
        -H "X-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -H "User-Agent: ALDECI-GitHub-Action/1.0" \
        "${API_URL}${endpoint}" \
        "$@"
}

# Upload a file to ALDECI scanner ingest
api_upload() {
    local endpoint="$1" filepath="$2"
    shift 2
    curl -sf --max-time 120 \
        -X POST \
        -H "X-API-Key: ${API_KEY}" \
        -H "User-Agent: ALDECI-GitHub-Action/1.0" \
        -F "file=@${filepath}" \
        "$@" \
        "${API_URL}${endpoint}"
}

# Count findings by severity from a JSON response
count_severity() {
    local json="$1"
    local findings
    findings=$(echo "$json" | jq -r '.findings // []')
    if [ "$findings" = "null" ] || [ "$findings" = "[]" ]; then
        return
    fi

    local c h m l
    c=$(echo "$findings" | jq '[.[] | select(.severity == "critical" or .severity == "CRITICAL")] | length')
    h=$(echo "$findings" | jq '[.[] | select(.severity == "high" or .severity == "HIGH")] | length')
    m=$(echo "$findings" | jq '[.[] | select(.severity == "medium" or .severity == "MEDIUM")] | length')
    l=$(echo "$findings" | jq '[.[] | select(.severity == "low" or .severity == "LOW")] | length')

    TOTAL_CRITICAL=$((TOTAL_CRITICAL + ${c:-0}))
    TOTAL_HIGH=$((TOTAL_HIGH + ${h:-0}))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + ${m:-0}))
    TOTAL_LOW=$((TOTAL_LOW + ${l:-0}))
}

# Emit GitHub annotations for findings
emit_annotations() {
    local json="$1" scan_label="$2"
    local findings
    findings=$(echo "$json" | jq -c '.findings // []')
    if [ "$findings" = "null" ] || [ "$findings" = "[]" ]; then
        return
    fi

    echo "$findings" | jq -c '.[]' | while IFS= read -r finding; do
        local sev title file line
        sev=$(echo "$finding" | jq -r '.severity // "medium"' | tr '[:upper:]' '[:lower:]')
        title=$(echo "$finding" | jq -r '.title // .rule_id // .name // "Security finding"')
        file=$(echo "$finding" | jq -r '.file // .location // .path // ""')
        line=$(echo "$finding" | jq -r '.line // .line_number // 1')

        # Map severity to annotation level
        local level="notice"
        case "$sev" in
            critical|high) level="error" ;;
            medium)        level="warning" ;;
            low|info)      level="notice" ;;
        esac

        if [ -n "$file" ] && [ "$file" != "null" ]; then
            echo "::${level} file=${file},line=${line}::[$scan_label] ${title} (${sev})"
        else
            echo "::${level}::[$scan_label] ${title} (${sev})"
        fi
    done
}

# ── SAST Scan ──────────────────────────────────────────────────────────────

run_sast_scan() {
    log_group "ALDECI SAST Scan"
    echo "Running SAST analysis..."

    # Collect source files for scanning
    local src_archive="$RESULTS_DIR/source.tar.gz"
    tar czf "$src_archive" \
        --exclude='.git' \
        --exclude='node_modules' \
        --exclude='__pycache__' \
        --exclude='.venv' \
        --exclude='venv' \
        --exclude='vendor' \
        --exclude='dist' \
        --exclude='build' \
        -C "$WORKSPACE" . 2>/dev/null || true

    local upload_extra_args=()
    if [ -n "$APP_ID" ]; then
        upload_extra_args+=(-F "app_id=${APP_ID}")
    fi
    if [ -n "$SCANNER_TYPE" ]; then
        upload_extra_args+=(-F "scanner_type=${SCANNER_TYPE}")
    else
        upload_extra_args+=(-F "scanner_type=semgrep")
    fi
    upload_extra_args+=(-F "pipeline=true")

    local response
    if response=$(api_upload "/api/v1/scanner-ingest/upload" "$src_archive" "${upload_extra_args[@]}" 2>&1); then
        echo "$response" > "$RESULTS_DIR/sast-results.json"
        local fc
        fc=$(echo "$response" | jq -r '.findings_count // 0')
        echo "SAST scan complete: ${fc} findings"
        count_severity "$response"
        emit_annotations "$response" "SAST"
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + ${fc:-0}))

        local sid
        sid=$(echo "$response" | jq -r '.scan_id // empty')
        if [ -n "$sid" ]; then
            SCAN_ID="$sid"
        fi
    else
        log_warn "SAST scan failed or ALDECI API unavailable"
        SCAN_ERRORS="${SCAN_ERRORS}SAST scan failed. "
    fi

    rm -f "$src_archive"
    log_endgroup
}

# ── SCA / SBOM Scan ───────────────────────────────────────────────────────

run_sca_scan() {
    log_group "ALDECI SCA/SBOM Scan"
    echo "Running SCA dependency analysis..."

    # Detect and upload dependency manifests
    local found_manifests=0

    # Python
    for manifest in requirements.txt Pipfile.lock poetry.lock setup.py pyproject.toml; do
        local fpath="${WORKSPACE}/${manifest}"
        if [ -f "$fpath" ]; then
            echo "Found Python manifest: ${manifest}"
            local extra_args=(-F "scanner_type=trivy" -F "pipeline=true")
            if [ -n "$PROJECT_ID" ]; then
                extra_args+=(-F "app_id=${PROJECT_ID}")
            fi
            local response
            if response=$(api_upload "/api/v1/scanner-ingest/upload" "$fpath" "${extra_args[@]}" 2>&1); then
                local fc
                fc=$(echo "$response" | jq -r '.findings_count // 0')
                echo "  ${manifest}: ${fc} findings"
                count_severity "$response"
                emit_annotations "$response" "SCA"
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + ${fc:-0}))
            fi
            found_manifests=$((found_manifests + 1))
        fi
    done

    # JavaScript/Node
    for manifest in package-lock.json yarn.lock pnpm-lock.yaml; do
        local fpath="${WORKSPACE}/${manifest}"
        if [ -f "$fpath" ]; then
            echo "Found Node manifest: ${manifest}"
            local extra_args=(-F "scanner_type=trivy" -F "pipeline=true")
            if [ -n "$PROJECT_ID" ]; then
                extra_args+=(-F "app_id=${PROJECT_ID}")
            fi
            local response
            if response=$(api_upload "/api/v1/scanner-ingest/upload" "$fpath" "${extra_args[@]}" 2>&1); then
                local fc
                fc=$(echo "$response" | jq -r '.findings_count // 0')
                echo "  ${manifest}: ${fc} findings"
                count_severity "$response"
                emit_annotations "$response" "SCA"
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + ${fc:-0}))
            fi
            found_manifests=$((found_manifests + 1))
        fi
    done

    # Go
    for manifest in go.sum go.mod; do
        local fpath="${WORKSPACE}/${manifest}"
        if [ -f "$fpath" ]; then
            echo "Found Go manifest: ${manifest}"
            local extra_args=(-F "scanner_type=trivy" -F "pipeline=true")
            local response
            if response=$(api_upload "/api/v1/scanner-ingest/upload" "$fpath" "${extra_args[@]}" 2>&1); then
                local fc
                fc=$(echo "$response" | jq -r '.findings_count // 0')
                echo "  ${manifest}: ${fc} findings"
                count_severity "$response"
                emit_annotations "$response" "SCA"
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + ${fc:-0}))
            fi
            found_manifests=$((found_manifests + 1))
        fi
    done

    # Java
    for manifest in pom.xml build.gradle build.gradle.kts; do
        local fpath="${WORKSPACE}/${manifest}"
        if [ -f "$fpath" ]; then
            echo "Found Java manifest: ${manifest}"
            local extra_args=(-F "scanner_type=trivy" -F "pipeline=true")
            local response
            if response=$(api_upload "/api/v1/scanner-ingest/upload" "$fpath" "${extra_args[@]}" 2>&1); then
                local fc
                fc=$(echo "$response" | jq -r '.findings_count // 0')
                echo "  ${manifest}: ${fc} findings"
                count_severity "$response"
                emit_annotations "$response" "SCA"
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + ${fc:-0}))
            fi
            found_manifests=$((found_manifests + 1))
        fi
    done

    # Rust
    if [ -f "${WORKSPACE}/Cargo.lock" ]; then
        echo "Found Rust manifest: Cargo.lock"
        local extra_args=(-F "scanner_type=trivy" -F "pipeline=true")
        local response
        if response=$(api_upload "/api/v1/scanner-ingest/upload" "${WORKSPACE}/Cargo.lock" "${extra_args[@]}" 2>&1); then
            local fc
            fc=$(echo "$response" | jq -r '.findings_count // 0')
            echo "  Cargo.lock: ${fc} findings"
            count_severity "$response"
            emit_annotations "$response" "SCA"
            TOTAL_FINDINGS=$((TOTAL_FINDINGS + ${fc:-0}))
        fi
        found_manifests=$((found_manifests + 1))
    fi

    # .NET
    for manifest in packages.config packages.lock.json; do
        local fpath="${WORKSPACE}/${manifest}"
        if [ -f "$fpath" ]; then
            echo "Found .NET manifest: ${manifest}"
            local extra_args=(-F "scanner_type=trivy" -F "pipeline=true")
            local response
            if response=$(api_upload "/api/v1/scanner-ingest/upload" "$fpath" "${extra_args[@]}" 2>&1); then
                local fc
                fc=$(echo "$response" | jq -r '.findings_count // 0')
                echo "  ${manifest}: ${fc} findings"
                count_severity "$response"
                emit_annotations "$response" "SCA"
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + ${fc:-0}))
            fi
            found_manifests=$((found_manifests + 1))
        fi
    done

    if [ "$found_manifests" -eq 0 ]; then
        log_warn "No dependency manifests found in workspace"
    else
        echo "Scanned ${found_manifests} dependency manifest(s)"
    fi

    log_endgroup
}

# ── IaC Scan ───────────────────────────────────────────────────────────────

run_iac_scan() {
    log_group "ALDECI IaC Scan"
    echo "Running Infrastructure-as-Code security scan..."

    local found_iac=0
    IFS=',' read -ra IAC_DIRS <<< "$IAC_PATHS"

    for iac_dir in "${IAC_DIRS[@]}"; do
        local dir_path="${WORKSPACE}/${iac_dir}"
        dir_path=$(echo "$dir_path" | sed 's|/\./|/|g; s|//|/|g')

        if [ ! -d "$dir_path" ] && [ ! -f "$dir_path" ]; then
            log_warn "IaC path not found: ${iac_dir}"
            continue
        fi

        # Find IaC files: Terraform, CloudFormation, Kubernetes, Docker
        local iac_files
        iac_files=$(find "$dir_path" -maxdepth 5 \
            \( -name '*.tf' -o -name '*.tfvars' \
               -o -name '*.yaml' -o -name '*.yml' \
               -o -name 'Dockerfile' -o -name 'docker-compose*.yml' \
               -o -name '*.template' -o -name '*.cfn.json' \) \
            -not -path '*/node_modules/*' \
            -not -path '*/.git/*' \
            -not -path '*/vendor/*' \
            2>/dev/null | head -50)

        if [ -z "$iac_files" ]; then
            echo "No IaC files found in ${iac_dir}"
            continue
        fi

        echo "$iac_files" | while IFS= read -r iac_file; do
            local relpath
            relpath=$(echo "$iac_file" | sed "s|^${WORKSPACE}/||")
            local filename
            filename=$(basename "$iac_file")
            echo "Scanning IaC file: ${relpath}"

            # Read file content and send to IaC scanner API
            local content
            content=$(cat "$iac_file" 2>/dev/null || echo "")
            if [ -z "$content" ]; then
                continue
            fi

            local payload
            payload=$(jq -n \
                --arg content "$content" \
                --arg filename "$filename" \
                '{content: $content, filename: $filename}')

            local response
            if response=$(echo "$payload" | api_call POST "/api/v1/iac/scan" -d @- 2>&1); then
                local fc
                fc=$(echo "$response" | jq -r '.findings_count // (.findings | length) // 0')
                if [ "${fc:-0}" -gt 0 ]; then
                    echo "  ${relpath}: ${fc} findings"

                    # Extract findings and emit annotations with file context
                    echo "$response" | jq -c '.findings // [] | .[]' 2>/dev/null | while IFS= read -r finding; do
                        local sev title line_num
                        sev=$(echo "$finding" | jq -r '.severity // "medium"' | tr '[:upper:]' '[:lower:]')
                        title=$(echo "$finding" | jq -r '.title // .rule_id // .description // "IaC misconfiguration"')
                        line_num=$(echo "$finding" | jq -r '.line // .line_number // 1')

                        local level="notice"
                        case "$sev" in
                            critical|high) level="error" ;;
                            medium)        level="warning" ;;
                        esac

                        echo "::${level} file=${relpath},line=${line_num}::[IaC] ${title} (${sev})"

                        case "$sev" in
                            critical) TOTAL_CRITICAL=$((TOTAL_CRITICAL + 1)) ;;
                            high)     TOTAL_HIGH=$((TOTAL_HIGH + 1)) ;;
                            medium)   TOTAL_MEDIUM=$((TOTAL_MEDIUM + 1)) ;;
                            low)      TOTAL_LOW=$((TOTAL_LOW + 1)) ;;
                        esac
                    done

                    TOTAL_FINDINGS=$((TOTAL_FINDINGS + ${fc:-0}))
                fi
            else
                log_warn "IaC scan failed for ${relpath}"
            fi
        done

        found_iac=$((found_iac + 1))
    done

    if [ "$found_iac" -eq 0 ]; then
        log_warn "No IaC directories found to scan"
    fi

    log_endgroup
}

# ── SARIF Generation ───────────────────────────────────────────────────────

generate_sarif() {
    log_group "Generate SARIF output"

    # Merge all result files into a single SARIF document
    python3 - <<'PYEOF'
import json, os, glob, sys

results_dir = "/tmp/aldeci-results"
sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "ALDECI",
                "informationUri": "https://github.com/DevOpsMadDog/Fixops",
                "version": "1.0.0",
                "rules": []
            }
        },
        "results": []
    }]
}

rules_seen = set()
run = sarif["runs"][0]

severity_map = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

for result_file in glob.glob(os.path.join(results_dir, "*-results.json")):
    try:
        with open(result_file) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        continue

    findings = data.get("findings", [])
    for finding in findings:
        rule_id = finding.get("rule_id") or finding.get("id") or finding.get("title", "unknown")
        sev = (finding.get("severity") or "medium").lower()

        # Add rule if not seen
        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            run["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "shortDescription": {"text": finding.get("title") or rule_id},
                "fullDescription": {"text": finding.get("description") or finding.get("title") or rule_id},
                "defaultConfiguration": {"level": severity_map.get(sev, "warning")},
            })

        # Build result
        result = {
            "ruleId": rule_id,
            "level": severity_map.get(sev, "warning"),
            "message": {"text": finding.get("description") or finding.get("title") or "Security finding"},
        }

        # Add location if available
        filepath = finding.get("file") or finding.get("location") or finding.get("path")
        line = finding.get("line") or finding.get("line_number") or 1
        if filepath:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": filepath},
                    "region": {"startLine": int(line)}
                }
            }]

        run["results"].append(result)

sarif_path = os.path.join(results_dir, "aldeci-results.sarif")
with open(sarif_path, "w") as f:
    json.dump(sarif, f, indent=2)

print(f"SARIF generated: {len(run['results'])} results, {len(run['tool']['driver']['rules'])} rules")
PYEOF

    log_endgroup
}

# ── PR Comment ─────────────────────────────────────────────────────────────

post_pr_comment() {
    if [ "$COMMENT_ON_PR" != "true" ]; then
        return
    fi
    if [ -z "${GITHUB_TOKEN:-}" ] && [ -z "${GH_TOKEN:-}" ]; then
        log_warn "No GITHUB_TOKEN set, skipping PR comment"
        return
    fi
    if [ -z "$PR_NUMBER" ]; then
        # Try to extract from event payload
        if [ -f "${GITHUB_EVENT_PATH:-/dev/null}" ]; then
            PR_NUMBER=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
        fi
    fi
    if [ -z "$PR_NUMBER" ]; then
        echo "Not a PR context, skipping comment"
        return
    fi

    local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
    local policy_action="$1"
    local icon=""
    case "$policy_action" in
        pass)  icon="white_check_mark" ;;
        warn)  icon="warning" ;;
        block) icon="x" ;;
    esac

    local body
    body=$(cat <<COMMENT_EOF
## :${icon}: ALDECI Security Scan Results

| Severity | Count |
|----------|-------|
| :red_circle: Critical | **${TOTAL_CRITICAL}** |
| :orange_circle: High | **${TOTAL_HIGH}** |
| :yellow_circle: Medium | **${TOTAL_MEDIUM}** |
| :white_circle: Low | **${TOTAL_LOW}** |
| **Total** | **${TOTAL_FINDINGS}** |

**Scan type:** \`${SCAN_TYPE}\` | **Threshold:** \`${SEVERITY_THRESHOLD}\` | **Policy:** \`${policy_action}\`
**Commit:** \`${SHA:0:8}\` | **Branch:** \`${BRANCH}\`

<details>
<summary>Scan details</summary>

- Scan ID: \`${SCAN_ID:-n/a}\`
- Repository: \`${REPO}\`
- API: \`${API_URL}\`
${SCAN_ERRORS:+- Errors: ${SCAN_ERRORS}}

</details>

---
*Powered by [ALDECI ASPM](https://github.com/DevOpsMadDog/Fixops) — AI-native security intelligence*
COMMENT_EOF
)

    local payload
    payload=$(jq -n --arg body "$body" '{body: $body}')

    curl -sf --max-time 15 \
        -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/${REPO}/issues/${PR_NUMBER}/comments" \
        -d "$payload" > /dev/null 2>&1 || log_warn "Failed to post PR comment"
}

# ── Severity Gate ──────────────────────────────────────────────────────────

evaluate_gate() {
    local threshold="$1"
    local action="pass"

    case "$threshold" in
        critical)
            [ "$TOTAL_CRITICAL" -gt 0 ] && action="block"
            ;;
        high)
            [ "$TOTAL_CRITICAL" -gt 0 ] && action="block"
            [ "$TOTAL_HIGH" -gt 0 ] && action="block"
            ;;
        medium)
            [ "$TOTAL_CRITICAL" -gt 0 ] && action="block"
            [ "$TOTAL_HIGH" -gt 0 ] && action="block"
            [ "$TOTAL_MEDIUM" -gt 0 ] && action="block"
            ;;
        low)
            [ "$TOTAL_FINDINGS" -gt 0 ] && action="block"
            ;;
    esac

    # Downgrade to warn if fail_on_findings is disabled
    if [ "$action" = "block" ] && [ "$FAIL_ON_FINDINGS" != "true" ]; then
        action="warn"
    fi

    echo "$action"
}

# ── Main ───────────────────────────────────────────────────────────────────

main() {
    echo "================================================"
    echo "  ALDECI Security Scan"
    echo "  Repository: ${REPO}"
    echo "  Branch:     ${BRANCH}"
    echo "  Commit:     ${SHA:0:8}"
    echo "  Scan type:  ${SCAN_TYPE}"
    echo "  Threshold:  ${SEVERITY_THRESHOLD}"
    echo "================================================"
    echo ""

    # Verify API connectivity
    log_group "API connectivity check"
    if api_call GET "/api/v1/scanner-ingest/health" > /dev/null 2>&1; then
        echo "ALDECI API is reachable"
    else
        log_error "Cannot reach ALDECI API at ${API_URL}"
        echo "Verify ALDECI_API_URL and ALDECI_API_KEY are correct."
        exit 1
    fi
    log_endgroup

    # Run selected scans
    case "$SCAN_TYPE" in
        sast)
            run_sast_scan
            ;;
        sca|sbom)
            run_sca_scan
            ;;
        iac)
            run_iac_scan
            ;;
        all)
            run_sast_scan
            run_sca_scan
            run_iac_scan
            ;;
        *)
            log_error "Unknown scan type: ${SCAN_TYPE}. Use: sast, sca, iac, all"
            exit 1
            ;;
    esac

    # Generate SARIF output
    generate_sarif

    # Evaluate severity gate
    local policy_action
    policy_action=$(evaluate_gate "$SEVERITY_THRESHOLD")

    # Write summary JSON
    jq -n \
        --arg scan_id "$SCAN_ID" \
        --arg repo "$REPO" \
        --arg branch "$BRANCH" \
        --arg sha "$SHA" \
        --arg scan_type "$SCAN_TYPE" \
        --arg threshold "$SEVERITY_THRESHOLD" \
        --arg policy_action "$policy_action" \
        --argjson critical "$TOTAL_CRITICAL" \
        --argjson high "$TOTAL_HIGH" \
        --argjson medium "$TOTAL_MEDIUM" \
        --argjson low "$TOTAL_LOW" \
        --argjson total "$TOTAL_FINDINGS" \
        '{
            scan_id: $scan_id,
            repo: $repo,
            branch: $branch,
            commit_sha: $sha,
            scan_type: $scan_type,
            severity_threshold: $threshold,
            policy_action: $policy_action,
            findings: {critical: $critical, high: $high, medium: $medium, low: $low, total: $total}
        }' > "$SUMMARY_FILE"

    # Set outputs
    set_output "scan_id" "$SCAN_ID"
    set_output "findings_count" "$TOTAL_FINDINGS"
    set_output "critical_count" "$TOTAL_CRITICAL"
    set_output "high_count" "$TOTAL_HIGH"
    set_output "medium_count" "$TOTAL_MEDIUM"
    set_output "low_count" "$TOTAL_LOW"
    set_output "policy_action" "$policy_action"
    set_output "sarif_file" "$SARIF_FILE"

    # Write job summary
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        cat >> "$GITHUB_STEP_SUMMARY" <<SUMMARY_EOF

### ALDECI Security Scan Results

| Severity | Count |
|----------|-------|
| Critical | **${TOTAL_CRITICAL}** |
| High | **${TOTAL_HIGH}** |
| Medium | **${TOTAL_MEDIUM}** |
| Low | **${TOTAL_LOW}** |
| **Total** | **${TOTAL_FINDINGS}** |

**Policy action:** \`${policy_action}\` | **Threshold:** \`${SEVERITY_THRESHOLD}\`
SUMMARY_EOF
    fi

    # Post PR comment
    post_pr_comment "$policy_action"

    # Print summary
    echo ""
    echo "================================================"
    echo "  Scan Complete"
    echo "  Findings: ${TOTAL_FINDINGS} total"
    echo "    Critical: ${TOTAL_CRITICAL}"
    echo "    High:     ${TOTAL_HIGH}"
    echo "    Medium:   ${TOTAL_MEDIUM}"
    echo "    Low:      ${TOTAL_LOW}"
    echo "  Policy:   ${policy_action}"
    echo "================================================"

    # Exit with appropriate code
    if [ "$policy_action" = "block" ]; then
        log_error "ALDECI security gate BLOCKED: ${TOTAL_CRITICAL} critical, ${TOTAL_HIGH} high findings exceed ${SEVERITY_THRESHOLD} threshold"
        exit 1
    elif [ "$policy_action" = "warn" ]; then
        log_warn "ALDECI security gate WARNING: findings detected but fail_on_findings is disabled"
        exit 0
    else
        log_info "ALDECI security gate PASSED"
        exit 0
    fi
}

main "$@"
