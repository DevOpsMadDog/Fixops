#!/usr/bin/env bash
set -euo pipefail

log() { echo "[cli-failure][APP1] $1"; }

log "simulate pipeline failure"
if fixops pipeline:run --module ssdlc --run-id fake-run; then
  log "expected failure but command succeeded"
  exit 1
else
  log "captured failure exit code $?"
fi
