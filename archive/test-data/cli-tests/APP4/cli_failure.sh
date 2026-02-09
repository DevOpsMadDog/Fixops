#!/usr/bin/env bash
set -euo pipefail

log() { echo "[cli-failure][APP4] $1"; }

if fixops pci:attest --run invalid; then
  log "Expected failure"
  exit 1
else
  log "Failure recorded"
fi
