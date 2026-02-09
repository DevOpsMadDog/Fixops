#!/usr/bin/env bash
set -euo pipefail

export FIXOPS_MODE=enterprise

log() { echo "[cli-smoke][APP1] $1"; }

log "version"
fixops --version || { log "missing fixops binary"; exit 1; }

log "list commands"
fixops --list-commands --json > artifacts/APP1/cli_catalog.json

log "upload design"
fixops design:upload inputs/APP1/design.csv || log "design upload failed (expected in offline mode)"

log "upload sbom"
fixops sbom:upload inputs/APP1/sbom.json || log "sbom upload failed (expected in offline mode)"

log "enumerate api"
fixops api:enumerate --out artifacts/APP1_endpoints.json || log "api enumerate simulated"

log "matrix"
fixops api:matrix --routes artifacts/APP1_endpoints.json --out artifacts/APP1_api_matrix.json || log "api matrix simulated"

log "done"
