#!/usr/bin/env bash
# Persona API Validator — Standalone Script
# Runs all 7 Postman collections via Newman against the live API,
# parses results, and generates persona-api-status.md + alerts.
#
# Usage: ./scripts/run-persona-api-validation.sh [RUN_ID]
# Requires: newman (npm install -g newman), API running on :8000
#
# Vision pillars: V3 (Decision Intelligence), V5 (MPTE), V7 (MCP), V10 (CTEM)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
POSTMAN_DIR="$PROJECT_ROOT/suite-integrations/postman/enterprise"
ENV_FILE="$POSTMAN_DIR/ALdeci-Environment.postman_environment.json"
STATE_DIR="$PROJECT_ROOT/.claude/team-state"
LOG_DIR="$PROJECT_ROOT/logs/ai-team"
DATE_TODAY=$(date +%Y-%m-%d)
RUN_ID="${1:-manual-$DATE_TODAY}"
RESULTS_DIR="/tmp/newman-results-$DATE_TODAY"

mkdir -p "$STATE_DIR" "$LOG_DIR" "$RESULTS_DIR"

# ── Pre-flight checks ──
echo "=== Pre-Flight Checks ==="

# Check API
if ! curl -sf --connect-timeout 5 http://localhost:8000/health > /dev/null 2>&1; then
    echo "ERROR: API is not running on port 8000"
    echo "Start it with: python -m uvicorn apps.api.app:create_app --factory --port 8000"
    exit 1
fi
echo "✅ API is healthy"

# Check Newman
if ! command -v newman > /dev/null 2>&1; then
    echo "ERROR: Newman is not installed"
    echo "Install with: npm install -g newman"
    exit 1
fi
echo "✅ Newman installed at $(command -v newman)"

# Check collections exist
COLLECTIONS=(
    "ALdeci-1-MissionControl"
    "ALdeci-2-Discover"
    "ALdeci-3-Validate"
    "ALdeci-4-Remediate"
    "ALdeci-5-Comply"
    "ALdeci-6-PersonaWorkflows"
    "ALdeci-7-Scanners-OSS-AutoFix"
)

for col in "${COLLECTIONS[@]}"; do
    if [[ ! -f "$POSTMAN_DIR/${col}.postman_collection.json" ]]; then
        echo "ERROR: Missing collection: $col"
        exit 1
    fi
done
echo "✅ All 7 collections found"

# ── Run all collections ──
echo ""
echo "=== Running 7 Postman Collections ==="

TOTAL_PASSED=0
TOTAL_FAILED=0
TOTAL_ASSERTIONS=0
TOTAL_REQUESTS=0
TOTAL_REQ_FAILED=0

for col in "${COLLECTIONS[@]}"; do
    echo "--- Running: $col ---"
    newman run "$POSTMAN_DIR/${col}.postman_collection.json" \
        -e "$ENV_FILE" \
        --reporters cli,json \
        --reporter-json-export "$RESULTS_DIR/${col}.json" \
        --timeout-request 30000 \
        --delay-request 100 \
        --suppress-exit-code 2>&1 | tail -15
    echo ""
done

# ── Parse results ──
echo "=== Parsing Results ==="

python3 << 'PYEOF'
import json, os, sys
from datetime import datetime

results_dir = os.environ.get('RESULTS_DIR', '/tmp/newman-results')
state_dir = os.environ.get('STATE_DIR', '.claude/team-state')
run_id = os.environ.get('RUN_ID', 'unknown')

collections = [
    ('ALdeci-1-MissionControl', 'MISSION CONTROL'),
    ('ALdeci-2-Discover', 'DISCOVER'),
    ('ALdeci-3-Validate', 'VALIDATE'),
    ('ALdeci-4-Remediate', 'REMEDIATE'),
    ('ALdeci-5-Comply', 'COMPLY'),
    ('ALdeci-6-PersonaWorkflows', 'PERSONA WORKFLOWS'),
    ('ALdeci-7-Scanners-OSS-AutoFix', 'SCANNERS/OSS/AUTOFIX'),
]

totals = {'passed': 0, 'failed': 0, 'total': 0, 'requests': 0, 'req_failed': 0}
space_results = []
all_failures = []

for name, space in collections:
    fpath = os.path.join(results_dir, f'{name}.json')
    if not os.path.exists(fpath):
        space_results.append({'space': space, 'name': name, 'error': 'No results file'})
        continue

    with open(fpath) as f:
        data = json.load(f)

    run = data.get('run', {})
    stats = run.get('stats', {})
    assertions = stats.get('assertions', {})
    requests = stats.get('requests', {})

    passed = assertions.get('total', 0) - assertions.get('failed', 0)
    failed = assertions.get('failed', 0)
    total = assertions.get('total', 0)
    req_total = requests.get('total', 0)
    req_failed = requests.get('failed', 0)

    totals['passed'] += passed
    totals['failed'] += failed
    totals['total'] += total
    totals['requests'] += req_total
    totals['req_failed'] += req_failed

    failures = []
    for exec_item in run.get('executions', []):
        item = exec_item.get('item', {})
        resp = exec_item.get('response', {})
        for assertion in exec_item.get('assertions', []):
            if assertion.get('error'):
                failures.append({
                    'name': item.get('name', 'unknown'),
                    'status': resp.get('code', 'N/A'),
                    'error': assertion['error'].get('message', 'unknown'),
                    'space': space,
                })
        if exec_item.get('requestError'):
            failures.append({
                'name': item.get('name', 'unknown'),
                'status': 'TIMEOUT',
                'error': str(exec_item.get('requestError', {}).get('message', '')),
                'space': space,
            })

    all_failures.extend(failures)
    pct = round(passed / total * 100, 1) if total > 0 else 0
    space_results.append({
        'space': space, 'name': name,
        'passed': passed, 'failed': failed, 'total': total, 'pct': pct,
        'requests': req_total, 'req_failed': req_failed,
        'failures': failures,
    })

pct_total = round(totals['passed'] / totals['total'] * 100, 1) if totals['total'] > 0 else 0
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Write persona-api-status.md
status_path = os.path.join(state_dir, 'persona-api-status.md')
with open(status_path, 'w') as f:
    f.write(f"# Persona API Status Report\n")
    f.write(f"> Generated: {now} | Run: {run_id}\n")
    f.write(f"> API: http://localhost:8000 | Newman: auto\n")
    f.write(f"> Collections: {len(collections)}/7 executed | Assertions: {totals['passed']}/{totals['total']} passed ({pct_total}%)\n\n")
    f.write(f"## Overall: {totals['passed']}/{totals['total']} assertions passed ({pct_total}%)\n\n")
    f.write(f"## Per-Space Status\n")
    f.write(f"| Space | Collection | Pass Rate | Key Failures |\n")
    f.write(f"|-------|------------|-----------||--------------|\n")
    for sr in space_results:
        if 'error' in sr:
            f.write(f"| {sr['space']} | {sr['name']} | ERROR | {sr['error']} |\n")
        else:
            fail_desc = ', '.join([fl['name'] for fl in sr.get('failures', [])[:3]]) or '-'
            f.write(f"| {sr['space']} | {sr['name']} | {sr['pct']}% ({sr['passed']}/{sr['total']}) | {fail_desc} |\n")

    if all_failures:
        f.write(f"\n## Failed Endpoints (Actionable)\n")
        f.write(f"| Endpoint | Status | Error | Space |\n")
        f.write(f"|----------|--------|-------|-------|\n")
        for fl in all_failures:
            f.write(f"| {fl['name']} | {fl['status']} | {fl['error'][:80]} | {fl['space']} |\n")

# Write alerts if any blocking failures
alerts_path = os.path.join(state_dir, 'persona-api-alerts.md')
with open(alerts_path, 'w') as f:
    f.write(f"# Persona API Alerts\n")
    f.write(f"> Last updated: {now} | Run: {run_id}\n\n")
    blocking = [fl for fl in all_failures if fl.get('status') not in ('TIMEOUT',)]
    if not blocking:
        f.write("## Current Status: ALL CLEAR\n\n")
        f.write("No blocking persona workflow failures detected.\n")
    else:
        f.write(f"## Current Status: {len(blocking)} BLOCKING FAILURE(S)\n\n")
        for fl in blocking:
            f.write(f"### 🚨 Persona API Alert — {now}\n")
            f.write(f"- **Severity**: HIGH\n")
            f.write(f"- **Failed Endpoint**: {fl['name']} → {fl['status']}\n")
            f.write(f"- **Error**: {fl['error']}\n")
            f.write(f"- **Space**: {fl['space']}\n")
            f.write(f"- **Assigned To**: backend-hardener\n\n")

print(f"✅ Results: {totals['passed']}/{totals['total']} assertions passed ({pct_total}%)")
print(f"✅ Written: {status_path}")
print(f"✅ Written: {alerts_path}")
if totals['failed'] > 0:
    print(f"⚠️  {totals['failed']} assertion failures detected")
    sys.exit(1)
PYEOF

echo ""
echo "=== Persona API Validation Complete ==="
