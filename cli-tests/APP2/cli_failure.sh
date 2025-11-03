#!/usr/bin/env bash
set -euo pipefail

log() { echo "[cli-failure][APP2] $1"; }

if fixops partner:webhook-test --partner demo --fail; then
  log "Expected failure but succeeded"
  exit 1
else
  log "Failure scenario captured"
fi
