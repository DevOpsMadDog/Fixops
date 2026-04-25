#!/usr/bin/env bash
# Fixops UI smoke test using obscura headless browser.
#
# Extracts every <Route path="..."> from App.tsx, hits each via obscura,
# captures: page title, h1 text, error-banner presence, render time.
# Output: one JSON line per route to stdout, summary table to stderr.
#
# Usage:
#   scripts/ui-smoke.sh                       # all routes, base http://localhost:5173
#   BASE=http://localhost:5174 scripts/ui-smoke.sh
#   ROUTES_LIMIT=20 scripts/ui-smoke.sh        # smoke just first 20 routes
set -uo pipefail

BASE="${BASE:-http://localhost:5173}"
APP_TSX="${APP_TSX:-suite-ui/aldeci-ui-new/src/App.tsx}"
CONCURRENCY="${CONCURRENCY:-6}"
WAIT_SECS="${WAIT_SECS:-3}"
ROUTES_LIMIT="${ROUTES_LIMIT:-0}"   # 0 = no limit
OUT_JSONL="${OUT_JSONL:-/tmp/ui-smoke-$(date +%s).jsonl}"

if ! command -v obscura >/dev/null 2>&1; then
  echo "obscura not on PATH. Install: see /opt/homebrew/bin/obscura" >&2
  exit 2
fi
if [[ ! -f "$APP_TSX" ]]; then
  echo "App.tsx not found at $APP_TSX" >&2
  exit 2
fi

# Collect unique route paths via Python (multi-line aware, robust against attribute order)
mapfile -t routes < <(
python3 - <<PYEOF
import re, sys
src = open("$APP_TSX").read()
# Match <Route ... path="..." ...> across lines
paths = re.findall(r'<Route\b[^>]*?path="([^"]+)"', src, re.DOTALL)
seen = []
for p in paths:
    if not p.startswith('/'): continue
    if ':' in p: continue                              # skip param routes
    if p in ('/login','/landing','/onboarding','/'): continue
    if p in seen: continue
    seen.append(p)
for p in seen:
    print(p)
PYEOF
)

if (( ROUTES_LIMIT > 0 )); then
  routes=("${routes[@]:0:$ROUTES_LIMIT}")
fi

total=${#routes[@]}
echo "obscura UI smoke: $total routes against $BASE (concurrency=$CONCURRENCY, wait=${WAIT_SECS}s)" >&2
echo "results -> $OUT_JSONL" >&2

# Probe one route via obscura, emit JSON line
probe_route() {
  local path="$1"
  local url="${BASE}${path}"
  local t0 t1 dt
  t0=$(python3 -c 'import time; print(int(time.time()*1000))')
  local out
  out=$(obscura fetch "$url" --wait "$WAIT_SECS" --quiet \
    -e "JSON.stringify({title: document.title, h1: document.querySelector('h1')?.innerText?.slice(0,120) ?? null, hasError: !!document.body.innerText.match(/error|failed to fetch|cannot read property/i), bodyLen: document.body.innerText.length})" 2>&1 | tail -1)
  t1=$(python3 -c 'import time; print(int(time.time()*1000))')
  dt=$((t1 - t0))
  # If obscura output isn't valid JSON, wrap into error envelope
  if echo "$out" | python3 -c "import sys,json; json.loads(sys.stdin.read())" >/dev/null 2>&1; then
    python3 -c "import sys,json; d=json.loads(sys.stdin.read()); d.update({'path':'$path','url':'$url','elapsed_ms':$dt}); print(json.dumps(d))" <<<"$out"
  else
    python3 -c "import json; print(json.dumps({'path':'$path','url':'$url','elapsed_ms':$dt,'error':'non-json output','raw':$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()[:200]))' <<<\"$out\")}))"
  fi
}
export -f probe_route
export BASE WAIT_SECS

# Run in parallel batches
: > "$OUT_JSONL"
for ((i=0; i<total; i+=CONCURRENCY)); do
  for ((j=i; j<i+CONCURRENCY && j<total; j++)); do
    probe_route "${routes[$j]}" >> "$OUT_JSONL" &
  done
  wait
  printf '\r  progress: %d/%d' "$((i+CONCURRENCY > total ? total : i+CONCURRENCY))" "$total" >&2
done
echo "" >&2

# Summary
python3 <<PYEOF >&2
import json
results = [json.loads(l) for l in open("$OUT_JSONL")]
ok    = sum(1 for r in results if r.get('h1') and not r.get('hasError') and not r.get('error'))
err   = sum(1 for r in results if r.get('hasError'))
no_h1 = sum(1 for r in results if not r.get('h1') and not r.get('error'))
fail  = sum(1 for r in results if r.get('error'))
slow  = [r for r in results if r.get('elapsed_ms',0) > 5000]
print()
print("=== UI smoke summary ===")
print(f"  total routes : {len(results)}")
print(f"  rendered ok  : {ok}")
print(f"  no h1 found  : {no_h1}")
print(f"  error banner : {err}")
print(f"  obscura fail : {fail}")
print(f"  slow (>5s)   : {len(slow)}")
if err:
    print()
    print("--- routes with error banner (top 10) ---")
    for r in [x for x in results if x.get('hasError')][:10]:
        print(f"  {r['path']:50s}  {r.get('h1','-')[:40]}")
if fail:
    print()
    print("--- obscura failures (top 10) ---")
    for r in [x for x in results if x.get('error')][:10]:
        print(f"  {r['path']:50s}  {r.get('error','?')}  raw={r.get('raw','')[:80]}")
print()
print(f"full results : {open('$OUT_JSONL').name}")
PYEOF
