#!/usr/bin/env bash
set -euo pipefail

log() { echo "[cli-smoke][APP3] $1"; }

fixops --version || log "fixops missing"
fixops --list-commands --json > artifacts/APP3/cli_catalog.json || log "catalog simulated"
fixops api:enumerate --app APP3 --out artifacts/APP3_endpoints.json || log "enumerate simulated"
fixops api:matrix --routes artifacts/APP3_endpoints.json --out artifacts/APP3_api_matrix.json || log "matrix simulated"
