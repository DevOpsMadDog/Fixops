#!/usr/bin/env bash
#
# Build a self-contained FixOps bundle for an air-gapped host.
#
# The default docker-compose.yml builds from source, which needs
# python:3.11-slim, node:20-alpine, nginx:1.27-alpine and then pip and npm
# against public registries. None of that exists on a disconnected host, so
# "one-command install" has to mean the images arrive already built.
#
# Run this on a CONNECTED host. It produces one tarball and prints the two
# commands to run on the disconnected side.
#
#   ./scripts/build_airgap_bundle.sh [output-dir]
#
# What ships, and what deliberately does not:
#
#   ships    aldeci:latest, aldeci-ui:latest, the airgap compose file, and the
#            local threat-feed databases (317K EPSS + 1.5K KEV) that make
#            offline verdicts possible.
#   does not the demo-seed service. An air-gapped customer must never find
#            fabricated findings in their tenant — see the `seed` profile in the
#            default compose, which this bundle does not carry.
#
set -euo pipefail

OUT_DIR="${1:-dist/airgap}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || date +%Y%m%d)"
API_IMAGE="${ALDECI_IMAGE:-aldeci:latest}"
UI_IMAGE="${ALDECI_UI_IMAGE:-aldeci-ui:latest}"

say()  { printf '\n\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }

command -v docker >/dev/null 2>&1 || { echo "docker is required on the build host"; exit 1; }
mkdir -p "$REPO_ROOT/$OUT_DIR"

say "1. Build the images (this host needs network; the target host will not)"
docker build -t "$API_IMAGE" -f "$REPO_ROOT/Dockerfile" "$REPO_ROOT"
ok "built $API_IMAGE"
docker build -t "$UI_IMAGE" -f "$REPO_ROOT/suite-ui/aldeci-ui-new/Dockerfile" \
  "$REPO_ROOT/suite-ui/aldeci-ui-new"
ok "built $UI_IMAGE"

say "2. Verify the images carry the offline feed databases"
# An air-gapped deployment cannot fetch EPSS or KEV. If the feeds are missing
# from the image, every verdict falls back to "estimated" and the product looks
# like it is guessing — so this is checked here rather than discovered on site.
if docker run --rm --entrypoint sh "$API_IMAGE" -c '[ -f /app/data/feeds/feeds.db ]' 2>/dev/null; then
  # Table is epss_scores, not epss — the first version of this check queried a
  # table that does not exist, so it would have reported "?" for a perfectly
  # good bundle and taught the operator to ignore it.
  rows=$(docker run --rm --entrypoint python "$API_IMAGE" -c \
    "import sqlite3;c=sqlite3.connect('/app/data/feeds/feeds.db');print(c.execute('select count(*) from epss_scores').fetchone()[0], c.execute('select count(*) from kev_entries').fetchone()[0])" 2>/dev/null || echo "? ?")
  ok "feeds.db present ($rows EPSS / KEV rows)"

  # Column is last_refresh, not updated_at. Second field-name slip in this one
  # script — the same class of defect that had dedup reading cve_id while the
  # parser wrote rule_id. Verify the query against the real schema, always.
  #
  # How OLD the feeds are matters as much as their presence: an air-gapped site
  # never refreshes them, and a confident verdict resting on months-old KEV data
  # is the thing the verdict's evidence-age field exists to expose. Say it at
  # BUILD time too, so nobody ships a stale bundle unknowingly.
  age=$(docker run --rm --entrypoint python "$API_IMAGE" -c \
    "import sqlite3;r=sqlite3.connect('/app/data/feeds/feeds.db').execute('select max(last_refresh) from feed_metadata').fetchone();print(r[0] if r and r[0] else 'unknown')" 2>/dev/null || echo "unknown")
  if [ "$age" = "unknown" ]; then
    warn "feed age unknown — the bundle cannot tell the operator how current it is"
  else
    ok "feeds last updated: $age"
  fi
else
  warn "feeds.db NOT in the image — offline verdicts will all be 'estimated'."
  warn "Populate data/feeds/feeds.db before building, or the bundle ships blind."
fi

say "3. Save images to a single tarball"
TAR="$REPO_ROOT/$OUT_DIR/fixops-airgap-${VERSION}.tar"
docker save -o "$TAR" "$API_IMAGE" "$UI_IMAGE"
ok "$(du -h "$TAR" | cut -f1) -> $TAR"

say "4. Stage the compose file and a checksum"
cp "$REPO_ROOT/docker/docker-compose.airgap.yml" "$REPO_ROOT/$OUT_DIR/"
( cd "$REPO_ROOT/$OUT_DIR" && shasum -a 256 "fixops-airgap-${VERSION}.tar" > "fixops-airgap-${VERSION}.tar.sha256" )
ok "checksum written — verify it on the target before loading"

say "On the disconnected host"
cat <<EOF
  shasum -a 256 -c fixops-airgap-${VERSION}.tar.sha256
  docker load -i fixops-airgap-${VERSION}.tar
  FIXOPS_API_TOKEN=<your-token> REPO_PATH=/path/to/source \\
    docker compose -f docker-compose.airgap.yml up -d

  Then confirm it is genuinely offline:
    docker logs aldeci-api 2>&1 | grep "air-gap enforced"

  REPO_PATH is what makes triage work. Without it reachability has no call
  graph, every finding is reported "undetermined", and nothing is eliminated.
EOF
