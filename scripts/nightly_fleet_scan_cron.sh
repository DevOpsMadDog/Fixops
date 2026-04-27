#!/usr/bin/env bash
# =============================================================================
# nightly_fleet_scan_cron.sh — LLM Phase 1 DPO pair growth driver
#
# PURPOSE: Run every night to grow the council-verdict DPO dataset from its
#          current baseline toward the 10 K GA threshold for Phase 2 distillation.
#
# EXPECTED YIELD: ~1 000 new DPO pairs per run (one verdict per finding across
#                 ~15 tenants × ~67 findings/tenant = ~1 005 verdicts).
#
# INSTALL (crontab -e):
#   0 2 * * * /Users/devops.ai/fixops/Fixops/scripts/nightly_fleet_scan_cron.sh
#
# UNINSTALL:
#   crontab -e  →  delete the line above
#
# LOG PATH:  data/cron/nightly_YYYY-MM-DD.log
#            Header line is "OK <timestamp>" or "FAILED <timestamp> — <reason>"
#            Morning health check reads header via:
#              head -1 data/cron/nightly_$(date +%F).log
#
# ENVIRONMENT VARIABLES (all set inline below — no .env dependency):
#   FIXOPS_LLM_LEARNING_LOOP  — enables council-verdict capture
#   FIXOPS_DEV_MODE           — relaxes rate limits / auth checks
#   FIXOPS_DISABLE_RATE_LIMIT — removes per-second LLM throttle
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DIR="${REPO_ROOT}/scripts"
DATA_DIR="${REPO_ROOT}/data"
CRON_LOG_DIR="${DATA_DIR}/cron"
LOG_FILE="${CRON_LOG_DIR}/nightly_$(date +%F).log"
FLEET_DIR="/tmp/fixops-fleet"
VENV="${REPO_ROOT}/.venv"

# ---------------------------------------------------------------------------
# Python — prefer venv, fall back to system python3
# ---------------------------------------------------------------------------
if [[ -x "${VENV}/bin/python3" ]]; then
    PYTHON="${VENV}/bin/python3"
else
    PYTHON="$(command -v python3)"
fi

# sitecustomize.py adds all suite-* dirs to sys.path automatically
export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"

# ---------------------------------------------------------------------------
# LLM learning-loop flags
# ---------------------------------------------------------------------------
export FIXOPS_LLM_LEARNING_LOOP=1
export FIXOPS_DEV_MODE=1
export FIXOPS_DISABLE_RATE_LIMIT=1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
mkdir -p "${CRON_LOG_DIR}"

ts() { date '+%Y-%m-%dT%H:%M:%S'; }

log() {
    echo "[$(ts)] $*" | tee -a "${LOG_FILE}"
}

fail() {
    local reason="$*"
    # Write FAILED as the FIRST line so morning health check catches it with head -1
    local tmp
    tmp="$(mktemp)"
    echo "FAILED $(ts) — ${reason}" > "${tmp}"
    cat "${LOG_FILE}" >> "${tmp}" 2>/dev/null || true
    mv "${tmp}" "${LOG_FILE}"
    log "FATAL: ${reason}"
    exit 1
}

# ---------------------------------------------------------------------------
# Reserve header slot (will be overwritten to OK or FAILED at end)
# ---------------------------------------------------------------------------
echo "RUNNING $(ts)" > "${LOG_FILE}"

log "=== nightly_fleet_scan_cron START ==="
log "REPO_ROOT : ${REPO_ROOT}"
log "PYTHON    : ${PYTHON}"
log "FLEET_DIR : ${FLEET_DIR}"

# ---------------------------------------------------------------------------
# Pre-flight: fleet directory must exist with at least one tenant
# ---------------------------------------------------------------------------
if [[ ! -d "${FLEET_DIR}" ]]; then
    fail "Fleet directory ${FLEET_DIR} does not exist — run scripts/aspm_wave2_repos.py first"
fi

tenant_count=$(find "${FLEET_DIR}" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')
if [[ "${tenant_count}" -eq 0 ]]; then
    fail "No tenant directories found under ${FLEET_DIR}"
fi
log "Tenants found: ${tenant_count}"

# ---------------------------------------------------------------------------
# Snapshot pair count BEFORE scan
# ---------------------------------------------------------------------------
TRAIN_JSONL="${DATA_DIR}/distill_train.jsonl"
pairs_before=0
if [[ -f "${TRAIN_JSONL}" ]]; then
    pairs_before=$(wc -l < "${TRAIN_JSONL}" | tr -d ' ')
fi
log "DPO pairs before scan: ${pairs_before}"

# ---------------------------------------------------------------------------
# Step 1 — ASPM real scan across all 15 tenants
# ---------------------------------------------------------------------------
log "--- Step 1: aspm_real_scan.py ---"
if ! "${PYTHON}" "${SCRIPTS_DIR}/aspm_real_scan.py" \
        --fleet-root "${FLEET_DIR}" \
        2>&1 | tee -a "${LOG_FILE}"; then
    fail "aspm_real_scan.py exited non-zero"
fi
log "Step 1 complete"

# ---------------------------------------------------------------------------
# Step 2 — Fresh SBOM seed
# ---------------------------------------------------------------------------
log "--- Step 2: seed_real_sboms.py ---"
if ! "${PYTHON}" "${SCRIPTS_DIR}/seed_real_sboms.py" \
        2>&1 | tee -a "${LOG_FILE}"; then
    log "WARN: seed_real_sboms.py failed — continuing (non-fatal)"
fi
log "Step 2 complete"

# ---------------------------------------------------------------------------
# Step 3 — CSPM LocalStack seed (only if LocalStack is reachable)
# ---------------------------------------------------------------------------
log "--- Step 3: cspm_localstack_seed.py (conditional) ---"
LOCALSTACK_UP=0
if curl -sf --max-time 3 "http://localhost:4566/_localstack/health" \
        > /dev/null 2>&1; then
    LOCALSTACK_UP=1
fi

if [[ "${LOCALSTACK_UP}" -eq 1 ]]; then
    if ! "${PYTHON}" "${SCRIPTS_DIR}/cspm_localstack_seed.py" \
            2>&1 | tee -a "${LOG_FILE}"; then
        log "WARN: cspm_localstack_seed.py failed — continuing (non-fatal)"
    fi
    log "Step 3 complete (LocalStack was up)"
else
    log "Step 3 skipped — LocalStack not reachable on localhost:4566"
fi

# ---------------------------------------------------------------------------
# Step 4 — Refresh DPO dataset JSONL
# ---------------------------------------------------------------------------
log "--- Step 4: llm_distill_dataset_curator.py ---"
if ! "${PYTHON}" "${SCRIPTS_DIR}/llm_distill_dataset_curator.py" \
        2>&1 | tee -a "${LOG_FILE}"; then
    fail "llm_distill_dataset_curator.py exited non-zero"
fi
log "Step 4 complete"

# ---------------------------------------------------------------------------
# Pair count delta
# ---------------------------------------------------------------------------
pairs_after=0
if [[ -f "${TRAIN_JSONL}" ]]; then
    pairs_after=$(wc -l < "${TRAIN_JSONL}" | tr -d ' ')
fi
pairs_delta=$(( pairs_after - pairs_before ))
log "DPO pairs after scan : ${pairs_after}"
log "Delta this run       : +${pairs_delta}"

remaining=$(( 10000 - pairs_after ))
if [[ "${remaining}" -le 0 ]]; then
    log "*** 10 K THRESHOLD REACHED — Phase 2 GA ready ***"
elif [[ "${pairs_delta}" -gt 0 ]]; then
    eta=$(( (remaining + pairs_delta - 1) / pairs_delta ))
    log "Estimated nights to 10 K threshold: ${eta}"
fi

# ---------------------------------------------------------------------------
# Success — rewrite header line to OK
# ---------------------------------------------------------------------------
tmp="$(mktemp)"
echo "OK $(ts) — pairs_before=${pairs_before} pairs_after=${pairs_after} delta=+${pairs_delta}" > "${tmp}"
tail -n +2 "${LOG_FILE}" >> "${tmp}"
mv "${tmp}" "${LOG_FILE}"

log "=== nightly_fleet_scan_cron DONE ==="
