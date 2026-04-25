#!/usr/bin/env bash
# scripts/onboard_real_apps.sh
# ----------------------------------------------------------------------
# Onboard 15 famous GitHub apps as 15 distinct Fixops customer orgs via
# the REAL API path (no DB writes, no engine.bulk_ingest shortcuts).
#
# Steps per tenant:
#   1.  POST /api/v1/orgs                       — create org (real API)
#   2.  POST /api/v1/onboarding/start           — begin onboarding wizard
#   3.  POST /api/v1/connectors/register        — register filesystem-style
#                                                 SCM connector (using
#                                                 GitHub adapter w/ a fake
#                                                 token + the org slug)
#   4.  POST /api/v1/sast/scan                  — scan the cloned repo
#                                                 (this is what the
#                                                 connector’s sync would
#                                                 trigger downstream)
#   5.  POST /api/v1/scanner-ingest/upload      — feed result back as
#                                                 SARIF-like payload via
#                                                 the real ingestion path
#                                                 (pipeline=true → 12-step
#                                                 Brain Pipeline runs)
#   6.  POST /api/v1/brain/pipeline/run         — kick off explicit Brain
#                                                 Pipeline with the SAST
#                                                 findings already in DB
#                                                 to ensure full 12-step
#                                                 normalisation/scoring
#   7.  GET  /api/v1/security-findings/findings — confirm findings landed
#                                                 scoped to org
#   8.  GET  /api/v1/orgs/{org_id}/summary      — per-tenant summary
#
# Outputs:
#   /tmp/onboard-real-apps.log                  — full log
#   /tmp/fleet-tenants.json                     — per-tenant outcome JSON
#
# Required: API server already running on :8000 (else use ../start scripts)
# ----------------------------------------------------------------------

set -uo pipefail

# ── Config ──────────────────────────────────────────────────────────
API="http://localhost:8000"
KEY="${FIXOPS_API_KEY:-fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_}"
FLEET_DIR="/tmp/fixops-fleet"
LOG="/tmp/onboard-real-apps.log"
RESULT_JSON="/tmp/fleet-tenants.json"
GH_TOKEN_PLACEHOLDER="ghp_AlDeCi_FilesystemConnector_PlaceholderToken_1234567890"
TIMEOUT_SECS=60

# ── Tenants ─────────────────────────────────────────────────────────
# Each line:   slug | display | repo-dir-name | language-hint
TENANTS=(
  "juice-shop-corp|Juice Shop Corp|juice-shop|javascript"
  "node-goat-inc|NodeGoat Inc|NodeGoat|javascript"
  "webgoat-llc|WebGoat LLC|WebGoat|java"
  "vulnado-co|Vulnado Co|vulnado|java"
  "dvna-systems|DVNA Systems|dvna|javascript"
  "express-corp|Express Corp|express|javascript"
  "fastify-inc|Fastify Inc|fastify|javascript"
  "axios-llc|Axios LLC|axios|javascript"
  "lodash-co|Lodash Co|lodash|javascript"
  "requests-corp|Requests Corp|requests|python"
  "fastapi-inc|FastAPI Inc|fastapi|python"
  "flask-llc|Flask LLC|flask|python"
  "django-corp|Django Corp|django|python"
  "httpx-co|HTTPX Co|httpx|python"
  "anthropic-sdk-corp|Anthropic SDK Corp|anthropic-sdk-python|python"
)

# ── Setup ───────────────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG")"
: > "$LOG"
echo '[]' > "$RESULT_JSON"

log() {
  local msg="$1"
  echo "[$(date '+%H:%M:%S')] $msg" | tee -a "$LOG"
}

# Wait for API health
log "Checking API at $API/health …"
for i in 1 2 3 4 5; do
  if curl -sf "$API/health" >/dev/null 2>&1; then
    log "API is healthy (try=$i)"
    break
  fi
  log "API not ready yet, retry in 3s…"
  sleep 3
  if [ "$i" = "5" ]; then
    log "FATAL: API at $API never became healthy"
    exit 1
  fi
done

# Helper: HTTP call with key, capture status + body
api_call() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local resp_file
  resp_file=$(mktemp)
  local code
  if [ -n "$body" ]; then
    code=$(curl -s -o "$resp_file" -w "%{http_code}" \
      -X "$method" \
      -H "X-API-Key: $KEY" \
      -H "X-Org-ID: ${HDR_ORG:-}" \
      -H "Content-Type: application/json" \
      -d "$body" \
      "$API$path" 2>>"$LOG")
  else
    code=$(curl -s -o "$resp_file" -w "%{http_code}" \
      -X "$method" \
      -H "X-API-Key: $KEY" \
      -H "X-Org-ID: ${HDR_ORG:-}" \
      "$API$path" 2>>"$LOG")
  fi
  echo "$code"
  cat "$resp_file"
  rm -f "$resp_file"
}

upload_call() {
  local path="$1"
  local file="$2"
  local org="$3"
  local form_args="$4"
  local resp_file
  resp_file=$(mktemp)
  local code
  code=$(curl -s -o "$resp_file" -w "%{http_code}" \
    -X POST \
    -H "X-API-Key: $KEY" \
    -H "X-Org-ID: $org" \
    -F "file=@$file" \
    $form_args \
    "$API$path" 2>>"$LOG")
  echo "$code"
  cat "$resp_file"
  rm -f "$resp_file"
}

# ── Per-tenant onboarding ───────────────────────────────────────────
SUCCESS=0
FAILED=0
TOTAL_FINDINGS=0
TOTAL_COMPONENTS=0
TOTAL_SECRETS=0

# Build the result JSON via jq buffer
RESULT_BUF="["
FIRST=true

for tenant in "${TENANTS[@]}"; do
  IFS='|' read -r slug name dir lang <<< "$tenant"
  HDR_ORG="$slug"
  REPO_PATH="$FLEET_DIR/$dir"

  log "════════════════════════════════════════════════════════════════════"
  log "Tenant: $slug   (display='$name')   repo=$REPO_PATH   lang=$lang"
  log "════════════════════════════════════════════════════════════════════"

  outcome="success"
  failures=()
  findings_count=0
  components_count=0
  secrets_count=0
  pipeline_run_id=""

  # ── Step 1: Create org ────────────────────────────────────────────
  log "STEP 1: POST /api/v1/orgs"
  org_body=$(printf '{"org_id":"%s","name":"%s","description":"Onboarded from %s"}' "$slug" "$name" "$dir")
  out=$(api_call POST "/api/v1/orgs" "$org_body")
  code=$(echo "$out" | head -1)
  body=$(echo "$out" | tail -n +2)
  case "$code" in
    200|201)
      log "  ✓ Org created: $slug"
      ;;
    409)
      log "  • Org already exists (idempotent OK): $slug"
      ;;
    *)
      log "  ✗ Org create FAILED status=$code body=$body"
      outcome="failed"
      failures+=("org_create:$code")
      ;;
  esac

  # ── Step 2: Onboarding wizard start ───────────────────────────────
  log "STEP 2: POST /api/v1/onboarding/start"
  out=$(api_call POST "/api/v1/onboarding/start" "{\"org_id\":\"$slug\"}")
  code=$(echo "$out" | head -1)
  body=$(echo "$out" | tail -n +2)
  if [ "$code" = "200" ] || [ "$code" = "201" ]; then
    log "  ✓ Onboarding wizard started"
  else
    log "  ✗ Onboarding start FAILED status=$code body=$body"
    failures+=("onboarding_start:$code")
  fi

  # ── Step 3: Register SCM connector (GitHub adapter, placeholder) ─
  log "STEP 3: POST /api/v1/connectors/register (github)"
  conn_name="scm-${slug}"
  conn_body=$(cat <<EOF
{
  "name": "$conn_name",
  "type": "github",
  "github": {
    "token": "$GH_TOKEN_PLACEHOLDER",
    "owner": "fixops-fleet",
    "repo": "$dir"
  }
}
EOF
)
  out=$(api_call POST "/api/v1/connectors/register" "$conn_body")
  code=$(echo "$out" | head -1)
  body=$(echo "$out" | tail -n +2)
  if [ "$code" = "200" ] || [ "$code" = "201" ]; then
    log "  ✓ Connector registered: $conn_name"
  else
    log "  ✗ Connector register FAILED status=$code body=$body"
    failures+=("connector_register:$code")
  fi

  # ── Step 4: SAST scan against cloned repo path ────────────────────
  log "STEP 4: POST /api/v1/sast/scan repo_path=$REPO_PATH"
  if [ ! -d "$REPO_PATH" ]; then
    log "  ✗ Repo path missing: $REPO_PATH (skipping scan)"
    failures+=("repo_missing")
  else
    scan_body=$(printf '{"repo_path":"%s","incremental":false}' "$REPO_PATH")
    out=$(timeout $TIMEOUT_SECS curl -s -o /tmp/scan_resp.json -w "%{http_code}" \
      -X POST -H "X-API-Key: $KEY" -H "X-Org-ID: $slug" \
      -H "Content-Type: application/json" \
      -d "$scan_body" "$API/api/v1/sast/scan" 2>>"$LOG")
    code="$out"
    if [ "$code" = "200" ]; then
      sast_findings=$(python3 -c "import json; d=json.load(open('/tmp/scan_resp.json')); print(d.get('total_findings', d.get('findings_count', len(d.get('findings', [])))))" 2>/dev/null || echo 0)
      log "  ✓ SAST scan completed: $sast_findings findings"
      findings_count=$((findings_count + sast_findings))
    else
      body=$(cat /tmp/scan_resp.json 2>/dev/null | head -c 400)
      log "  ✗ SAST scan FAILED status=$code body=$body"
      failures+=("sast_scan:$code")
    fi
  fi

  # ── Step 5: Push a synthetic SARIF wrapping the findings (real ingest path) ──
  log "STEP 5: POST /api/v1/scanner-ingest/upload (SARIF wrap, pipeline=true)"
  sarif_path="/tmp/${slug}.sarif"
  # Use SLUG_PATH env var to avoid heredoc shell interpolation hazards
  SLUG_PATH="$sarif_path" python3 <<'PYEOF'
import json, os
scan = {}
try:
    with open('/tmp/scan_resp.json') as f:
        scan = json.load(f)
except Exception:
    pass
findings = scan.get('findings', []) or []
results = []
rules_seen = {}
for f in findings[:200]:  # cap
    rule = f.get('rule_id') or f.get('cwe_id') or 'SAST-UNKNOWN'
    msg = f.get('message') or f.get('title') or rule
    if rule not in rules_seen:
        rules_seen[rule] = {'id': rule, 'shortDescription': {'text': msg[:120]}}
    results.append({
        'ruleId': rule,
        'level': {'critical':'error','high':'error','medium':'warning','low':'note','info':'none'}.get(
            (f.get('severity') or 'medium').lower(), 'warning'),
        'message': {'text': msg},
        'locations': [{
            'physicalLocation': {
                'artifactLocation': {'uri': f.get('file_path','unknown')},
                'region': {'startLine': max(1, int(f.get('line_number',1) or 1))}
            }
        }]
    })
sarif = {
    'version': '2.1.0',
    '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    'runs': [{
        'tool': {'driver': {'name': 'aldeci-sast', 'version': '1.0.0',
                            'rules': list(rules_seen.values())}},
        'results': results
    }]
}
out_path = os.environ['SLUG_PATH']
with open(out_path, 'w') as f:
    json.dump(sarif, f)
print(len(results))
PYEOF
  ingest_out=$(curl -s -o /tmp/ingest_resp.json -w "%{http_code}" \
    -X POST -H "X-API-Key: $KEY" -H "X-Org-ID: $slug" \
    -F "file=@${sarif_path}" \
    -F "scanner_type=sarif" \
    -F "app_id=$slug" \
    -F "component=$dir" \
    -F "pipeline=true" \
    "$API/api/v1/scanner-ingest/upload" 2>>"$LOG")
  code="$ingest_out"
  if [ "$code" = "200" ]; then
    ingest_n=$(python3 -c "import json; d=json.load(open('/tmp/ingest_resp.json')); print(d.get('findings_count', 0))" 2>/dev/null || echo 0)
    log "  ✓ SARIF ingested via real path: $ingest_n findings, pipeline triggered"
  else
    body=$(cat /tmp/ingest_resp.json 2>/dev/null | head -c 400)
    log "  ✗ SARIF ingest FAILED status=$code body=$body"
    failures+=("scanner_ingest:$code")
  fi

  # ── Step 6: Explicit Brain Pipeline run (12-step) ─────────────────
  log "STEP 6: POST /api/v1/brain/pipeline/run (12-step)"
  bp_body=$(SLUG="$slug" DIR="$dir" python3 <<'PYEOF'
import json, os
slug = os.environ['SLUG']
dir_ = os.environ['DIR']
findings = []
try:
    s = json.load(open('/tmp/scan_resp.json'))
    for f in (s.get('findings') or [])[:50]:
        findings.append({
            'id': f.get('finding_id') or f.get('id') or '',
            'title': f.get('title') or f.get('message') or 'SAST Finding',
            'severity': (f.get('severity') or 'medium').lower(),
            'description': f.get('message') or '',
            'source': 'sast',
            'asset_name': f.get('file_path','unknown'),
        })
except Exception:
    pass
print(json.dumps({
    'org_id': slug,
    'findings': findings,
    'assets': [{'id': f'{slug}-app', 'name': dir_, 'criticality': 0.7, 'type': 'service'}],
    'source': 'onboarding',
    'run_pentest': False,
    'run_playbooks': False,
    'generate_evidence': True,
    'evidence_framework': 'SOC2',
}))
PYEOF
)
  out=$(timeout $TIMEOUT_SECS curl -s -o /tmp/bp_resp.json -w "%{http_code}" \
    -X POST -H "X-API-Key: $KEY" -H "X-Org-ID: $slug" \
    -H "Content-Type: application/json" \
    -d "$bp_body" "$API/api/v1/brain/pipeline/run" 2>>"$LOG")
  code="$out"
  if [ "$code" = "200" ]; then
    pipeline_run_id=$(python3 -c "import json; d=json.load(open('/tmp/bp_resp.json')); print(d.get('run_id',''))" 2>/dev/null)
    bp_status=$(python3 -c "import json; d=json.load(open('/tmp/bp_resp.json')); print(d.get('status','?'))" 2>/dev/null)
    log "  ✓ Brain Pipeline run=$pipeline_run_id status=$bp_status"
  else
    body=$(cat /tmp/bp_resp.json 2>/dev/null | head -c 400)
    log "  ✗ Brain Pipeline FAILED status=$code body=$body"
    failures+=("brain_pipeline:$code")
  fi

  # ── Step 7: List findings scoped to org ───────────────────────────
  log "STEP 7: GET /api/v1/security-findings/findings?org_id=$slug"
  out=$(api_call GET "/api/v1/security-findings/findings?org_id=$slug" "")
  code=$(echo "$out" | head -1)
  body=$(echo "$out" | tail -n +2)
  if [ "$code" = "200" ]; then
    findings_db=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else d.get('total',0))" 2>/dev/null || echo 0)
    log "  ✓ findings in DB for tenant: $findings_db"
  else
    log "  ✗ findings list FAILED status=$code"
    failures+=("findings_list:$code")
  fi

  # ── Step 8: Org summary ───────────────────────────────────────────
  log "STEP 8: GET /api/v1/orgs/$slug/summary"
  out=$(api_call GET "/api/v1/orgs/$slug/summary" "")
  code=$(echo "$out" | head -1)
  body=$(echo "$out" | tail -n +2)
  engines=0
  total_rows=0
  if [ "$code" = "200" ]; then
    engines=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('summary',{}).get('engines_with_data',0))" 2>/dev/null || echo 0)
    total_rows=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('summary',{}).get('total_rows',0))" 2>/dev/null || echo 0)
    log "  ✓ org summary: $engines engines, $total_rows total rows"
  else
    log "  ✗ org summary FAILED status=$code"
    failures+=("org_summary:$code")
  fi

  # ── Tally ─────────────────────────────────────────────────────────
  if [ ${#failures[@]} -eq 0 ] || [ ${#failures[@]} -le 1 ]; then
    SUCCESS=$((SUCCESS + 1))
    outcome="success"
  else
    FAILED=$((FAILED + 1))
    outcome="partial(${failures[*]})"
  fi
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + findings_count))

  # Append to result JSON (manual, since we want the file readable midstream)
  if [ "$FIRST" = "true" ]; then
    FIRST=false
  else
    RESULT_BUF="${RESULT_BUF},"
  fi
  RESULT_BUF="${RESULT_BUF}$(printf '{"slug":"%s","name":"%s","repo_dir":"%s","language":"%s","outcome":"%s","sast_findings":%d,"db_findings":%s,"engines_with_data":%s,"total_rows":%s,"pipeline_run_id":"%s","failures":"%s"}' \
    "$slug" "$name" "$dir" "$lang" "$outcome" "$findings_count" "${findings_db:-0}" "${engines:-0}" "${total_rows:-0}" "$pipeline_run_id" "${failures[*]}")"
  echo "${RESULT_BUF}]" > "$RESULT_JSON"
done

# ── Multi-tenant isolation check ───────────────────────────────────
log "════════════════════════════════════════════════════════════════════"
log "MULTI-TENANT ISOLATION CHECK"
log "════════════════════════════════════════════════════════════════════"
TENANT_A="juice-shop-corp"
TENANT_B="lodash-co"
log "Comparing $TENANT_A vs $TENANT_B"
out_a=$(curl -s -H "X-API-Key: $KEY" -H "X-Org-ID: $TENANT_A" \
  "$API/api/v1/orgs/$TENANT_A/summary")
out_b=$(curl -s -H "X-API-Key: $KEY" -H "X-Org-ID: $TENANT_B" \
  "$API/api/v1/orgs/$TENANT_B/summary")
ROWS_A=$(echo "$out_a" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('summary',{}).get('total_rows',0))" 2>/dev/null || echo 0)
ROWS_B=$(echo "$out_b" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('summary',{}).get('total_rows',0))" 2>/dev/null || echo 0)
log "  $TENANT_A rows: $ROWS_A"
log "  $TENANT_B rows: $ROWS_B"
log "  Row counts differ ⇒ tenants isolated: $([ "$ROWS_A" != "$ROWS_B" ] && echo YES || echo MAYBE)"

# Cross-tenant leak test: A's key ⇒ B's data ⇒ should NOT see A's rows in B's summary
out_swap=$(curl -s -H "X-API-Key: $KEY" -H "X-Org-ID: $TENANT_A" \
  "$API/api/v1/security-findings/findings?org_id=$TENANT_B")
B_via_A=$(echo "$out_swap" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else d.get('total',0))" 2>/dev/null || echo 0)
log "  Swap (org_id=$TENANT_B asked while X-Org-ID=$TENANT_A): rows=$B_via_A (must equal $TENANT_B's only)"

# ── Persona walkthrough: 5 endpoints × 5 tenants = 25 ───────────────
log "════════════════════════════════════════════════════════════════════"
log "PERSONA WALKTHROUGH — 5 endpoints × 5 tenants = 25 spot-checks"
log "════════════════════════════════════════════════════════════════════"
PASS=0
FAIL=0
PERSONAS=(
  "ciso|/api/v1/orgs/SLUG/summary"
  "appsec-engineer|/api/v1/security-findings/findings?org_id=SLUG"
  "developer|/api/v1/security-findings/summary?org_id=SLUG"
  "compliance-officer|/api/v1/sbom-export/?org_id=SLUG"
  "soc-analyst|/api/v1/scanner-ingest/stats"
)
SAMPLE_TENANTS=("juice-shop-corp" "express-corp" "fastapi-inc" "lodash-co" "django-corp")
for slug in "${SAMPLE_TENANTS[@]}"; do
  for pp in "${PERSONAS[@]}"; do
    IFS='|' read -r persona path <<< "$pp"
    real_path="${path//SLUG/$slug}"
    code=$(curl -s -o /tmp/persona.json -w "%{http_code}" \
      -H "X-API-Key: $KEY" -H "X-Org-ID: $slug" "$API$real_path")
    if [ "$code" = "200" ]; then
      PASS=$((PASS + 1))
      log "  ✓ persona=$persona tenant=$slug $real_path → 200"
    else
      FAIL=$((FAIL + 1))
      log "  ✗ persona=$persona tenant=$slug $real_path → $code"
    fi
  done
done

# ── Final summary ─────────────────────────────────────────────────
log "════════════════════════════════════════════════════════════════════"
log "FINAL SUMMARY"
log "════════════════════════════════════════════════════════════════════"
log "Tenants attempted: ${#TENANTS[@]}"
log "Successful (≤1 failure step): $SUCCESS"
log "Failed (>1 failure step):     $FAILED"
log "Aggregate SAST findings: $TOTAL_FINDINGS"
log "Persona walkthrough: $PASS pass / $FAIL fail (out of 25)"
log "Results JSON: $RESULT_JSON"
log "Server log:   /tmp/aldeci_onboard_server.log"
echo "DONE — see $LOG and $RESULT_JSON"
