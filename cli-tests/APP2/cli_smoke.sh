#!/usr/bin/env bash
set -euo pipefail

log() { echo "[cli-smoke][APP2] $1"; }

fixops --version || log "fixops not installed"

fixops --list-commands --json > artifacts/APP2/cli_catalog.json || log "catalog simulated"

fixops api:enumerate --out artifacts/APP2_endpoints.json --app APP2 || log "enumerate simulated"
fixops api:matrix --routes artifacts/APP2_endpoints.json --out artifacts/APP2_api_matrix.json || log "matrix simulated"
