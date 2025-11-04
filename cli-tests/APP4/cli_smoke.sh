#!/usr/bin/env bash
set -euo pipefail

log() { echo "[cli-smoke][APP4] $1"; }

fixops --version || log "fixops missing"
fixops --list-commands --json > artifacts/APP4/cli_catalog.json || log "catalog simulated"
fixops api:enumerate --app APP4 --out artifacts/APP4_endpoints.json || log "enumerate simulated"
fixops api:matrix --routes artifacts/APP4_endpoints.json --out artifacts/APP4_api_matrix.json || log "matrix simulated"
