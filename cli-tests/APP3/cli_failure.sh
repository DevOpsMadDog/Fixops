#!/usr/bin/env bash
set -euo pipefail

log() { echo "[cli-failure][APP3] $1"; }

if fixops healthcare:validate --run invalid; then
  log "Expected failure"
  exit 1
else
  log "Failure captured"
fi
