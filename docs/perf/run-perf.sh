#!/usr/bin/env bash
# Lighthouse perf budget runner with auth bypass via CDP localStorage seeding.
# Runs each hero sequentially (avoids CDP port collisions).
set -euo pipefail

CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
OUTDIR="$(cd "$(dirname "$0")" && pwd)"
BASE="http://localhost:5173"
SEEDER="${OUTDIR}/seed-localstorage.mjs"

declare -A HEROES
# name -> path (ordered)
HERO_NAMES=(root issues brain compliance assets admin)
HERO_PATHS=("/" "/issues" "/brain" "/compliance" "/assets" "/admin")

cleanup_chrome() {
  local pid=$1
  kill "$pid" 2>/dev/null || true
  sleep 0.5
}

run_hero() {
  local name="$1"
  local path="$2"
  local url="${BASE}${path}"
  local port=$((9300 + RANDOM % 500))
  local profile="/tmp/lh-chrome-${name}-$$"
  local outfile="${OUTDIR}/${name}.json"

  echo "━━━ [${name}] port=${port} url=${url} ━━━"

  # 1. Launch Chrome with CDP
  "$CHROME" \
    --remote-debugging-port="${port}" \
    --headless=new \
    --no-sandbox \
    --disable-gpu \
    --disable-extensions \
    --user-data-dir="${profile}" \
    --no-first-run \
    --disable-default-apps \
    2>/dev/null &
  CHROME_PID=$!
  sleep 2

  # 2. Open a page at BASE so localStorage is on the right origin
  curl -sf "http://localhost:${port}/json/new?${url}" >/dev/null 2>&1 || true
  sleep 1

  # 3. Seed localStorage bypass keys
  node "${SEEDER}" "${port}" "${url}" 2>&1 || echo "[${name}] seed warning (continuing)"
  sleep 0.5

  # 4. Run Lighthouse attached to this Chrome instance
  npx lighthouse "${url}" \
    --port="${port}" \
    --only-categories=performance \
    --output=json \
    --output-path="${outfile}" \
    --disable-storage-reset \
    --preset=desktop \
    --quiet \
    2>"${OUTDIR}/${name}.err" || echo "[${name}] lighthouse exit non-zero (check ${name}.err)"

  cleanup_chrome "$CHROME_PID"
  rm -rf "${profile}" 2>/dev/null || true

  echo "[${name}] wrote ${outfile}"
}

for i in "${!HERO_NAMES[@]}"; do
  run_hero "${HERO_NAMES[$i]}" "${HERO_PATHS[$i]}"
done

echo ""
echo "All 6 heroes complete."
