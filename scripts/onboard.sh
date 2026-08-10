#!/usr/bin/env bash
# FixOps — onboard a new tenant with YOUR real scanner data, end to end.
# No seed data, no mocks. Runs against your running FixOps container over HTTP.
#
# Usage:
#   FIXOPS_API_TOKEN=<token> ./scripts/onboard.sh <org-name> <path/to/scan.sarif> [base-url]
#
# Example:
#   FIXOPS_API_TOKEN=my-token ./scripts/onboard.sh acme ./trivy.sarif
set -euo pipefail

ORG="${1:?usage: onboard.sh <org-name> <scan.sarif> [base-url]}"
SCAN="${2:?usage: onboard.sh <org-name> <scan.sarif> [base-url]}"
BASE="${3:-http://localhost:8000}"
TOKEN="${FIXOPS_API_TOKEN:?set FIXOPS_API_TOKEN (your API key)}"
H=(-H "X-API-Key: $TOKEN" -H "X-Org-ID: $ORG")

[ -f "$SCAN" ] || { echo "scan file not found: $SCAN" >&2; exit 1; }

say() { printf '\n\033[1m%s\033[0m\n' "$1"; }
ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; }

say "0. Check FixOps is reachable"
curl -sf "$BASE/health" >/dev/null && ok "FixOps is up at $BASE"

say "1. Create tenant '$ORG'"
code=$(curl -s -o /tmp/onb_org.json -w '%{http_code}' -X POST "$BASE/api/v1/orgs" \
  "${H[@]}" -H "Content-Type: application/json" -d "{\"name\":\"$ORG\",\"org_id\":\"$ORG\"}")
[ "$code" = "201" ] || [ "$code" = "200" ] || [ "$code" = "409" ] || { echo "org create failed: HTTP $code" >&2; exit 1; }
ok "tenant ready (HTTP $code)"

say "2. Ingest your scanner output ($(basename "$SCAN"))"
ing=$(curl -s -X POST "$BASE/api/v1/scanner-ingest/upload" "${H[@]}" \
  -F scanner_type=sarif -F "app_id=${ORG}-app" -F component=main -F pipeline=false \
  -F "file=@${SCAN}")
raw=$(printf '%s' "$ing" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('findings_count') or d.get('count') or 0)" 2>/dev/null || echo "?")
ok "ingested $raw raw findings"

say "3. Distinct findings after dedup"
curl -s "$BASE/api/v1/findings" "${H[@]}" > /tmp/onb_find.json
distinct=$(python3 -c "import json;d=json.load(open('/tmp/onb_find.json'));print(len(d if isinstance(d,list) else d.get('findings',d.get('items',[]))))" 2>/dev/null || echo "?")
ok "$distinct distinct findings (duplicate noise collapsed)"

say "4. Run the AI council on YOUR findings + generate signed evidence (calls the models; ~60s)"
# Pass the REAL ingested findings into the pipeline (not an empty list) so the
# council actually runs on your data.
python3 - <<PY > /tmp/onb_body.json
import json
d=json.load(open('/tmp/onb_find.json'))
fs=d if isinstance(d,list) else d.get('findings',d.get('items',[]))
body={"org_id":"$ORG","generate_evidence":True,
      "findings":[{"id":str(f.get("id","")),"title":f.get("title","finding"),
                   "severity":f.get("severity","medium"),"description":f.get("description","")}
                  for f in fs[:50]]}
json.dump(body,open('/tmp/onb_body.json','w'))
PY
curl -s -X POST "$BASE/api/v1/pipeline/run" "${H[@]}" -H "Content-Type: application/json" \
  --data @/tmp/onb_body.json --max-time 200 > /tmp/onb_pipe.json || true
python3 - <<PY
import json
try:
    d=json.load(open('/tmp/onb_pipe.json'))
    v=d.get('verdict',{}); lc={s['name']:s for s in d.get('steps',[])}.get('llm_consensus',{}).get('output',{})
    print(f"  \033[32m✓\033[0m verdict: {v.get('decision','?')} (source={v.get('source','?')})")
    print(f"  \033[32m✓\033[0m council: {lc.get('providers_responded','?')} models responded, cost_usd={lc.get('cost_usd','?')}")
except Exception as e:
    print(f"  (pipeline result unavailable: {e})")
PY

say "DONE — tenant '$ORG' onboarded with your real data. No seed, no mocks."
echo "  UI: $BASE   |   findings: $BASE/api/v1/findings   |   evidence: $BASE/api/v1/pipeline/evidence/packs"
