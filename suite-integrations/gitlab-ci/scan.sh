#!/usr/bin/env bash
# ALDECI GitLab CI — SAST / SCA / IaC security scanning script
# Calls ALDECI APIs, evaluates severity gate, outputs GitLab-compatible reports.
set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
API_URL="${ALDECI_API_URL:?ALDECI_API_URL is required — set in CI/CD Variables}"
API_KEY="${ALDECI_API_KEY:?ALDECI_API_KEY is required — set in CI/CD Variables (masked)}"
SCAN_TYPE="${SCAN_TYPE:-all}"
SEVERITY_THRESHOLD="${SEVERITY_THRESHOLD:-${ALDECI_SEVERITY_THRESHOLD:-high}}"
FAIL_ON_FINDINGS="${FAIL_ON_FINDINGS:-${ALDECI_FAIL_ON_FINDINGS:-true}}"
APP_ID="${APP_ID:-${ALDECI_APP_ID:-}}"
PROJECT_ID="${PROJECT_ID:-${ALDECI_PROJECT_ID:-}}"
IAC_PATHS="${IAC_PATHS:-${ALDECI_IAC_PATHS:-.}}"
SCANNER_TYPE="${SCANNER_TYPE:-${ALDECI_SCANNER_TYPE:-}}"
COMMENT_ON_MR="${COMMENT_ON_MR:-${ALDECI_COMMENT_ON_MR:-true}}"

# Trim trailing slash from API URL
API_URL="${API_URL%/}"

# GitLab context
REPO="${CI_PROJECT_PATH:-unknown/repo}"
BRANCH="${CI_MERGE_REQUEST_SOURCE_BRANCH_NAME:-${CI_COMMIT_BRANCH:-${CI_COMMIT_REF_NAME:-main}}}"
SHA="${CI_COMMIT_SHA:-unknown}"
SHORT_SHA="${CI_COMMIT_SHORT_SHA:-${SHA:0:8}}"
MR_IID="${CI_MERGE_REQUEST_IID:-}"
PROJECT_URL="${CI_API_V4_URL:-https://gitlab.com/api/v4}/projects/${CI_PROJECT_ID:-0}"
WORKSPACE="${CI_PROJECT_DIR:-.}"

# Output directory (shared with artifacts)
RESULTS_DIR="${CI_PROJECT_DIR:-.}/aldeci-results"
mkdir -p "$RESULTS_DIR"
SARIF_FILE="$RESULTS_DIR/aldeci-results.sarif"
SUMMARY_FILE="$RESULTS_DIR/scan-summary-${SCAN_TYPE}.json"
GL_CODE_QUALITY="$RESULTS_DIR/gl-code-quality-report.json"
GL_SAST_REPORT="$RESULTS_DIR/gl-sast-report.json"

# Counters
TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0
TOTAL_FINDINGS=0
SCAN_ID=""
SCAN_ERRORS=""

# Findings accumulator for report generation
ALL_FINDINGS_FILE="$RESULTS_DIR/.findings-accumulator.json"
echo "[]" > "$ALL_FINDINGS_FILE"

# ── Helper functions ───────────────────────────────────────────────────────

log_info()  { echo "[ALDECI INFO]  $*"; }
log_warn()  { echo "[ALDECI WARN]  $*"; }
log_error() { echo "[ALDECI ERROR] $*"; }

log_section_start() {
    local name="$1" header="${2:-$1}"
    echo -e "\e[0Ksection_start:$(date +%s):${name}\r\e[0K\e[36m${header}\e[0m"
}

log_section_end() {
    local name="$1"
    echo -e "\e[0Ksection_end:$(date +%s):${name}\r\e[0K"
}

# Make an authenticated API call to ALDECI
api_call() {
    local method="$1" endpoint="$2"
    shift 2
    curl -sf --max-time 120 \
        -X "$method" \
        -H "X-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -H "User-Agent: ALDECI-GitLab-CI/1.0" \
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
        -H "User-Agent: ALDECI-GitLab-CI/1.0" \
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

# Accumulate findings for report generation
accumulate_findings() {
    local json="$1" scan_label="$2"
    local findings
    findings=$(echo "$json" | jq -c '.findings // []')
    if [ "$findings" = "null" ] || [ "$findings" = "[]" ]; then
        return
    fi

    # Tag each finding with scan type and merge into accumulator
    local tagged
    tagged=$(echo "$findings" | jq -c --arg label "$scan_label" \
        '[.[] | . + {scan_type: $label}]')

    local current
    current=$(cat "$ALL_FINDINGS_FILE")
    echo "$current" | jq -c --argjson new "$tagged" '. + $new' > "$ALL_FINDINGS_FILE"
}

# ── SAST Scan ──────────────────────────────────────────────────────────────

run_sast_scan() {
    log_section_start "aldeci_sast" "ALDECI SAST Scan"
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
        accumulate_findings "$response" "sast"
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
    log_section_end "aldeci_sast"
}

# ── SCA / SBOM Scan ───────────────────────────────────────────────────────

run_sca_scan() {
    log_section_start "aldeci_sca" "ALDECI SCA/SBOM Scan"
    echo "Running SCA dependency analysis..."

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
                accumulate_findings "$response" "sca"
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
                accumulate_findings "$response" "sca"
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
                accumulate_findings "$response" "sca"
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
                accumulate_findings "$response" "sca"
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
            accumulate_findings "$response" "sca"
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
                accumulate_findings "$response" "sca"
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

    log_section_end "aldeci_sca"
}

# ── IaC Scan ───────────────────────────────────────────────────────────────

run_iac_scan() {
    log_section_start "aldeci_iac" "ALDECI IaC Scan"
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
                    accumulate_findings "$response" "iac"

                    echo "$response" | jq -c '.findings // [] | .[]' 2>/dev/null | while IFS= read -r finding; do
                        local sev
                        sev=$(echo "$finding" | jq -r '.severity // "medium"' | tr '[:upper:]' '[:lower:]')
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

    log_section_end "aldeci_iac"
}

# ── GitLab Code Quality Report ─────────────────────────────────────────────

generate_gl_code_quality() {
    log_section_start "aldeci_cq" "Generate GitLab Code Quality Report"

    python3 - <<'PYEOF'
import json, os, hashlib

results_dir = os.environ.get("RESULTS_DIR", "aldeci-results")
findings_file = os.path.join(results_dir, ".findings-accumulator.json")

try:
    with open(findings_file) as f:
        findings = json.load(f)
except (OSError, json.JSONDecodeError):
    findings = []

severity_map = {
    "critical": "blocker",
    "high": "critical",
    "medium": "major",
    "low": "minor",
    "info": "info",
}

cq_issues = []
for finding in findings:
    sev = (finding.get("severity") or "medium").lower()
    title = finding.get("title") or finding.get("rule_id") or finding.get("name") or "Security finding"
    desc = finding.get("description") or title
    filepath = finding.get("file") or finding.get("location") or finding.get("path") or ""
    line = finding.get("line") or finding.get("line_number") or 1
    scan_type = finding.get("scan_type", "unknown")

    # GitLab Code Quality requires a unique fingerprint
    fp_input = f"{filepath}:{line}:{title}:{sev}"
    fingerprint = hashlib.md5(fp_input.encode()).hexdigest()

    issue = {
        "type": "issue",
        "check_name": f"aldeci/{scan_type}",
        "description": f"[{scan_type.upper()}] {title}",
        "content": {"body": desc},
        "categories": ["Security"],
        "severity": severity_map.get(sev, "major"),
        "fingerprint": fingerprint,
    }

    if filepath and filepath != "null":
        issue["location"] = {
            "path": filepath,
            "lines": {"begin": int(line)}
        }
    else:
        issue["location"] = {
            "path": "unknown",
            "lines": {"begin": 1}
        }

    cq_issues.append(issue)

output_path = os.path.join(results_dir, "gl-code-quality-report.json")
with open(output_path, "w") as f:
    json.dump(cq_issues, f, indent=2)

print(f"GitLab Code Quality report: {len(cq_issues)} issues")
PYEOF

    log_section_end "aldeci_cq"
}

# ── GitLab SAST Report (Security Dashboard compatible) ─────────────────────

generate_gl_sast_report() {
    log_section_start "aldeci_sast_report" "Generate GitLab SAST Report"

    python3 - <<'PYEOF'
import json, os, hashlib, uuid, datetime

results_dir = os.environ.get("RESULTS_DIR", "aldeci-results")
findings_file = os.path.join(results_dir, ".findings-accumulator.json")
scan_type_env = os.environ.get("SCAN_TYPE", "all")
sha = os.environ.get("CI_COMMIT_SHA", "unknown")

try:
    with open(findings_file) as f:
        findings = json.load(f)
except (OSError, json.JSONDecodeError):
    findings = []

severity_map = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

confidence_map = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Low",
}

vulns = []
for finding in findings:
    sev = (finding.get("severity") or "medium").lower()
    title = finding.get("title") or finding.get("rule_id") or finding.get("name") or "Security finding"
    desc = finding.get("description") or title
    filepath = finding.get("file") or finding.get("location") or finding.get("path") or ""
    line = finding.get("line") or finding.get("line_number") or 1
    rule_id = finding.get("rule_id") or finding.get("id") or title
    scan_label = finding.get("scan_type", "unknown")

    fp_input = f"{filepath}:{line}:{rule_id}:{sev}"
    cve_id = hashlib.sha256(fp_input.encode()).hexdigest()[:16]

    vuln = {
        "id": str(uuid.uuid4()),
        "category": "sast",
        "name": f"[{scan_label.upper()}] {title}",
        "message": desc,
        "description": desc,
        "severity": severity_map.get(sev, "Medium"),
        "confidence": confidence_map.get(sev, "Medium"),
        "scanner": {
            "id": "aldeci",
            "name": "ALDECI ASPM"
        },
        "identifiers": [
            {
                "type": "aldeci_rule",
                "name": rule_id,
                "value": rule_id
            }
        ],
    }

    if filepath and filepath != "null":
        vuln["location"] = {
            "file": filepath,
            "start_line": int(line)
        }

    cve = finding.get("cve") or finding.get("cve_id")
    if cve:
        vuln["identifiers"].append({
            "type": "cve",
            "name": cve,
            "value": cve,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}"
        })

    vulns.append(vuln)

report = {
    "version": "15.0.7",
    "vulnerabilities": vulns,
    "scan": {
        "analyzer": {
            "id": "aldeci",
            "name": "ALDECI ASPM Scanner",
            "url": "https://github.com/DevOpsMadDog/Fixops",
            "vendor": {"name": "ALDECI"},
            "version": "1.0.0"
        },
        "scanner": {
            "id": "aldeci",
            "name": "ALDECI ASPM Scanner",
            "url": "https://github.com/DevOpsMadDog/Fixops",
            "vendor": {"name": "ALDECI"},
            "version": "1.0.0"
        },
        "type": "sast",
        "start_time": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
        "end_time": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "success"
    }
}

output_path = os.path.join(results_dir, "gl-sast-report.json")
with open(output_path, "w") as f:
    json.dump(report, f, indent=2)

print(f"GitLab SAST report: {len(vulns)} vulnerabilities")
PYEOF

    log_section_end "aldeci_sast_report"
}

# ── SARIF Generation ───────────────────────────────────────────────────────

generate_sarif() {
    log_section_start "aldeci_sarif" "Generate SARIF Output"

    python3 - <<'PYEOF'
import json, os, glob

results_dir = os.environ.get("RESULTS_DIR", "aldeci-results")
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

        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            run["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "shortDescription": {"text": finding.get("title") or rule_id},
                "fullDescription": {"text": finding.get("description") or finding.get("title") or rule_id},
                "defaultConfiguration": {"level": severity_map.get(sev, "warning")},
            })

        result = {
            "ruleId": rule_id,
            "level": severity_map.get(sev, "warning"),
            "message": {"text": finding.get("description") or finding.get("title") or "Security finding"},
        }

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

    log_section_end "aldeci_sarif"
}

# ── Merge Request Note ────────────────────────────────────────────────────

post_mr_note() {
    if [ "$COMMENT_ON_MR" != "true" ]; then
        return
    fi
    if [ -z "${GITLAB_TOKEN:-}" ] && [ -z "${CI_JOB_TOKEN:-}" ]; then
        log_warn "No GITLAB_TOKEN or CI_JOB_TOKEN available, skipping MR note"
        return
    fi
    if [ -z "$MR_IID" ]; then
        echo "Not a merge request context, skipping MR note"
        return
    fi

    local token="${GITLAB_TOKEN:-${CI_JOB_TOKEN:-}}"
    local policy_action="$1"
    local icon=""
    case "$policy_action" in
        pass)  icon=":white_check_mark:" ;;
        warn)  icon=":warning:" ;;
        block) icon=":x:" ;;
    esac

    local body
    body=$(cat <<MR_NOTE_EOF
## ${icon} ALDECI Security Scan Results

| Severity | Count |
|----------|-------|
| :red_circle: Critical | **${TOTAL_CRITICAL}** |
| :orange_circle: High | **${TOTAL_HIGH}** |
| :yellow_circle: Medium | **${TOTAL_MEDIUM}** |
| :white_circle: Low | **${TOTAL_LOW}** |
| **Total** | **${TOTAL_FINDINGS}** |

**Scan type:** \`${SCAN_TYPE}\` | **Threshold:** \`${SEVERITY_THRESHOLD}\` | **Policy:** \`${policy_action}\`
**Commit:** \`${SHORT_SHA}\` | **Branch:** \`${BRANCH}\`

<details>
<summary>Scan details</summary>

- Scan ID: \`${SCAN_ID:-n/a}\`
- Project: \`${REPO}\`
- API: \`${API_URL}\`
- Pipeline: [#${CI_PIPELINE_ID:-n/a}](${CI_PIPELINE_URL:-#})
${SCAN_ERRORS:+- Errors: ${SCAN_ERRORS}}

</details>

---
*Powered by [ALDECI ASPM](https://github.com/DevOpsMadDog/Fixops) — AI-native security intelligence*
MR_NOTE_EOF
)

    local payload
    payload=$(jq -n --arg body "$body" '{body: $body}')

    curl -sf --max-time 15 \
        -X POST \
        -H "PRIVATE-TOKEN: ${token}" \
        -H "Content-Type: application/json" \
        "${PROJECT_URL}/merge_requests/${MR_IID}/notes" \
        -d "$payload" > /dev/null 2>&1 || log_warn "Failed to post MR note"
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
    echo "  ALDECI Security Scan (GitLab CI)"
    echo "  Project:    ${REPO}"
    echo "  Branch:     ${BRANCH}"
    echo "  Commit:     ${SHORT_SHA}"
    echo "  Scan type:  ${SCAN_TYPE}"
    echo "  Threshold:  ${SEVERITY_THRESHOLD}"
    echo "  Pipeline:   ${CI_PIPELINE_ID:-local}"
    echo "================================================"
    echo ""

    # Verify API connectivity
    log_section_start "aldeci_healthcheck" "API Connectivity Check"
    if api_call GET "/api/v1/scanner-ingest/health" > /dev/null 2>&1; then
        echo "ALDECI API is reachable"
    else
        log_error "Cannot reach ALDECI API at ${API_URL}"
        echo "Verify ALDECI_API_URL and ALDECI_API_KEY in CI/CD Variables."
        exit 1
    fi
    log_section_end "aldeci_healthcheck"

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

    # Generate reports
    generate_gl_code_quality
    generate_gl_sast_report
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
        --arg pipeline_id "${CI_PIPELINE_ID:-}" \
        --arg pipeline_url "${CI_PIPELINE_URL:-}" \
        '{
            scan_id: $scan_id,
            repo: $repo,
            branch: $branch,
            commit_sha: $sha,
            scan_type: $scan_type,
            severity_threshold: $threshold,
            policy_action: $policy_action,
            findings: {critical: $critical, high: $high, medium: $medium, low: $low, total: $total},
            pipeline: {id: $pipeline_id, url: $pipeline_url}
        }' > "$SUMMARY_FILE"

    # Clean up accumulator
    rm -f "$ALL_FINDINGS_FILE"

    # Post MR note
    post_mr_note "$policy_action"

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
    echo "  Reports:"
    echo "    SARIF:        ${SARIF_FILE}"
    echo "    Code Quality: ${GL_CODE_QUALITY}"
    echo "    SAST Report:  ${GL_SAST_REPORT}"
    echo "    Summary:      ${SUMMARY_FILE}"
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
