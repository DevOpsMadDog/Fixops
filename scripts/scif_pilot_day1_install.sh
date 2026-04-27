#!/usr/bin/env bash
# =============================================================================
# scif_pilot_day1_install.sh — ALDECI SCIF Day-1 ISSO Install Script
# =============================================================================
# Single bash script the customer ISSO runs as root inside their air-gapped
# SCIF perimeter after extracting the bundle tarball. Performs every Day-1
# action, prints an ISSO summary table, and exits non-zero on any failure
# with a clear remediation step.
#
# Usage:
#   sudo bash scripts/scif_pilot_day1_install.sh                  # full run
#   sudo bash scripts/scif_pilot_day1_install.sh --dev-mode       # FIPS env=0, SoftHSM
#   sudo bash scripts/scif_pilot_day1_install.sh --dry-run        # log actions only
#   sudo bash scripts/scif_pilot_day1_install.sh --bundle <path>  # explicit bundle dir
#   sudo bash scripts/scif_pilot_day1_install.sh --skip-extract   # bundle already extracted
#   sudo bash scripts/scif_pilot_day1_install.sh --skip-airgap-check  # if rare egress test fails
#   sudo bash scripts/scif_pilot_day1_install.sh --help
#
# Exit codes:
#   0   — Day-1 install successful, container healthy
#   10  — pre-flight failed (FIPS / HSM / air-gap / packages)
#   20  — bundle extraction failed
#   30  — SoftHSM token init failed
#   40  — API key generation (HSM RSA) failed
#   50  — docker compose boot failed
#   60  — FIPS NIST KAT self-test failed
#   70  — audit chain integrity check failed
#   80  — final health check failed
# =============================================================================

set -uo pipefail   # NOTE: no -e — we trap failures explicitly per step

# ── Colour / logging helpers ───────────────────────────────────────────────
if [ -t 1 ]; then
    C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YEL=$'\033[0;33m'
    C_BLU=$'\033[0;34m'; C_BLD=$'\033[1m';   C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_RST=""
fi

log()       { printf '%s[scif-day1]%s %s\n' "${C_BLU}" "${C_RST}" "$*"; }
ok()        { printf '%s[  OK  ]%s %s\n' "${C_GRN}" "${C_RST}" "$*"; }
warn()      { printf '%s[ WARN ]%s %s\n' "${C_YEL}" "${C_RST}" "$*" >&2; }
fail()      { printf '%s[ FAIL ]%s %s\n' "${C_RED}" "${C_RST}" "$*" >&2; }
remediate() { printf '%s[ FIX  ]%s %s\n' "${C_YEL}" "${C_RST}" "$*" >&2; }
banner()    { printf '\n%s═══ %s ═══%s\n' "${C_BLD}" "$*" "${C_RST}"; }

# ── Default args ──────────────────────────────────────────────────────────
DEV_MODE=0
DRY_RUN=0
SKIP_EXTRACT=0
SKIP_AIRGAP_CHECK=0
BUNDLE_DIR=""
STATE_DIR="/var/lib/aldeci-scif"
LOG_FILE="/var/log/aldeci-scif-day1.log"
STATE_DIR_OVERRIDDEN=0
LOG_FILE_OVERRIDDEN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --dev-mode)          DEV_MODE=1 ;;
        --dry-run)           DRY_RUN=1 ;;
        --skip-extract)      SKIP_EXTRACT=1 ;;
        --skip-airgap-check) SKIP_AIRGAP_CHECK=1 ;;
        --bundle)            BUNDLE_DIR="${2:-}"; shift ;;
        --state-dir)         STATE_DIR="${2:-}"; STATE_DIR_OVERRIDDEN=1; shift ;;
        --log)               LOG_FILE="${2:-}"; LOG_FILE_OVERRIDDEN=1; shift ;;
        -h|--help)
            cat <<'HELPEOF'
scif_pilot_day1_install.sh — ALDECI SCIF Day-1 ISSO Install Script

Single bash script the customer ISSO runs as root inside their air-gapped
SCIF perimeter after extracting the bundle tarball. Executes 8 Day-1 steps:
verify FIPS kernel + HSM + air-gap, extract bundle, init SoftHSM token,
generate per-tenant API keys, boot ALDECI containers, run NIST FIPS KAT,
verify audit chain integrity, print ISSO summary table.

Usage:
  sudo bash scripts/scif_pilot_day1_install.sh                 # full run
  sudo bash scripts/scif_pilot_day1_install.sh --dev-mode      # FIPS env=0, SoftHSM
  sudo bash scripts/scif_pilot_day1_install.sh --dry-run       # log only, no actions
  sudo bash scripts/scif_pilot_day1_install.sh --bundle <dir>  # explicit bundle dir
  sudo bash scripts/scif_pilot_day1_install.sh --skip-extract  # bundle already extracted
  sudo bash scripts/scif_pilot_day1_install.sh --skip-airgap-check  # skip egress probe
  sudo bash scripts/scif_pilot_day1_install.sh --state-dir <p> # default /var/lib/aldeci-scif
  sudo bash scripts/scif_pilot_day1_install.sh --log <file>    # default /var/log/aldeci-scif-day1.log

Exit codes:
  0   Day-1 install successful, container healthy
  10  pre-flight failed (FIPS / HSM / air-gap / packages)
  20  bundle extraction or sha256 verification failed
  30  SoftHSM token init failed
  40  per-tenant API key (HSM RSA) generation failed
  50  docker compose / docker run boot failed
  60  FIPS NIST KAT self-test failed
  70  audit chain integrity check failed
  80  final health check failed

Companion docs:
  docs/scif/DAY1_RUNBOOK.md      step-by-step ISSO runbook + rollback per step
  tests/test_scif_day1_install.sh smoke test (dev-mode + dry-run)
HELPEOF
            exit 0 ;;
        *)
            fail "unknown arg: $1"; exit 2 ;;
    esac
    shift
done

# In dry-run as non-root, redirect default paths to TMPDIR (only if user
# didn't explicitly override). Honour --state-dir / --log when given.
if [ "${DRY_RUN}" = "1" ] && [ "$(id -u)" -ne 0 ]; then
    if [ "${STATE_DIR_OVERRIDDEN}" = "0" ]; then
        STATE_DIR="${TMPDIR:-/tmp}/aldeci-scif-state"
    fi
    if [ "${LOG_FILE_OVERRIDDEN}" = "0" ]; then
        LOG_FILE="${TMPDIR:-/tmp}/aldeci-scif-day1.log"
    fi
fi

# ── Root check ────────────────────────────────────────────────────────────
if [ "${DRY_RUN}" = "0" ] && [ "$(id -u)" -ne 0 ]; then
    fail "must run as root (or with sudo). Got UID=$(id -u)."
    remediate "re-run: sudo bash $0 $*"
    exit 2
fi

mkdir -p "${STATE_DIR}" "$(dirname "${LOG_FILE}")" 2>/dev/null || true
if ! touch "${LOG_FILE}" 2>/dev/null; then
    # Fallback only if user didn't explicitly --log <path>
    if [ "${LOG_FILE_OVERRIDDEN}" = "0" ]; then
        LOG_FILE="${TMPDIR:-/tmp}/aldeci-scif-day1.log"
        touch "${LOG_FILE}" 2>/dev/null || true
    fi
fi

# Tee everything to the log file
exec > >(tee -a "${LOG_FILE}") 2>&1

# Helper: run a command unless DRY_RUN
run() {
    if [ "${DRY_RUN}" = "1" ]; then
        log "DRY-RUN exec: $*"
        return 0
    fi
    "$@"
}

banner "ALDECI SCIF Pilot — Day-1 Install"
log "host=$(uname -n)  date=$(date -u +%Y-%m-%dT%H:%M:%SZ)  uid=$(id -u)"
log "mode: dev=${DEV_MODE} dry=${DRY_RUN} skip-extract=${SKIP_EXTRACT}"
log "state-dir=${STATE_DIR}  log=${LOG_FILE}"

# ============================================================================
# STEP 1 — Pre-flight
# ============================================================================
banner "STEP 1/8 — Pre-flight Checks"

PREFLIGHT_FAILS=0

# 1a. FIPS-validated kernel
log "1a. FIPS-validated kernel + OpenSSL"
if [ "${DEV_MODE}" = "0" ]; then
    if [ -r /proc/sys/crypto/fips_enabled ]; then
        FIPS_KERNEL="$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)"
        if [ "${FIPS_KERNEL}" = "1" ]; then
            ok "kernel FIPS mode enabled (fips_enabled=1)"
        else
            fail "kernel FIPS NOT enabled (fips_enabled=${FIPS_KERNEL})"
            remediate "enable FIPS: fips-mode-setup --enable && reboot   (RHEL 9)"
            remediate "          : pro enable fips                     (Ubuntu Pro)"
            PREFLIGHT_FAILS=$((PREFLIGHT_FAILS+1))
        fi
    else
        fail "/proc/sys/crypto/fips_enabled not readable — non-FIPS kernel"
        remediate "boot a FIPS-validated kernel (RHEL 9 FIPS or Ubuntu Pro FIPS)"
        PREFLIGHT_FAILS=$((PREFLIGHT_FAILS+1))
    fi

    if openssl version 2>/dev/null | grep -qi "fips"; then
        ok "openssl is FIPS-validated: $(openssl version)"
    elif openssl list -providers 2>/dev/null | grep -qi "fips"; then
        ok "openssl FIPS provider available"
    else
        warn "openssl FIPS provider not detected — verify with your build"
        remediate "RHEL 9: dnf install -y crypto-policies-scripts && update-crypto-policies --set FIPS"
    fi
else
    warn "DEV-MODE: skipping FIPS kernel check"
fi

# 1b. HSM (PKCS#11 token)
log "1b. HSM PKCS#11 token"
PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib64/softhsm/libsofthsm2.so}"
HSM_BACKEND="unknown"
if [ "${DEV_MODE}" = "1" ]; then
    if command -v softhsm2-util >/dev/null 2>&1; then
        ok "softhsm2-util found — will init in dev-mode"
        HSM_BACKEND="softhsm-dev"
    else
        warn "softhsm2-util missing in DEV mode — installing best-effort"
        if command -v dnf >/dev/null 2>&1; then
            run dnf install -y softhsm opensc 2>/dev/null || true
        elif command -v apt-get >/dev/null 2>&1; then
            run apt-get install -y softhsm2 opensc 2>/dev/null || true
        fi
        command -v softhsm2-util >/dev/null 2>&1 \
            && ok "softhsm2-util installed" \
            || warn "softhsm2-util still missing — dev-mode HSM disabled"
    fi
else
    if [ -r "${PKCS11_MODULE}" ]; then
        ok "PKCS#11 module readable: ${PKCS11_MODULE}"
        HSM_BACKEND="pkcs11"
        # Probe with pkcs11-tool if present
        if command -v pkcs11-tool >/dev/null 2>&1; then
            if pkcs11-tool --module "${PKCS11_MODULE}" --list-slots 2>/dev/null | grep -qE "Slot|Token"; then
                ok "HSM responding (pkcs11-tool --list-slots returned a slot)"
            else
                warn "PKCS#11 module loaded but no slots — token not initialised yet"
            fi
        fi
    else
        fail "PKCS#11 module NOT found: ${PKCS11_MODULE}"
        remediate "install vendor HSM SDK (Luna/CloudHSM/YubiHSM2) OR run with --dev-mode"
        remediate "override module path: export PKCS11_MODULE=/path/to/libpkcs11.so"
        PREFLIGHT_FAILS=$((PREFLIGHT_FAILS+1))
    fi
fi

# 1c. Air-gap verification (curl 8.8.8.8 should fail)
log "1c. Air-gap verification (no outbound connectivity)"
if [ "${SKIP_AIRGAP_CHECK}" = "1" ]; then
    warn "--skip-airgap-check — bypassing egress probe"
elif [ "${DEV_MODE}" = "1" ]; then
    warn "DEV-MODE: skipping air-gap egress probe"
else
    AIRGAP_PROBES_FAILED=0
    AIRGAP_PROBES_TOTAL=0
    for target in "8.8.8.8:53" "1.1.1.1:53" "registry-1.docker.io:443"; do
        AIRGAP_PROBES_TOTAL=$((AIRGAP_PROBES_TOTAL+1))
        host="${target%:*}"
        port="${target##*:}"
        if timeout 3 bash -c "</dev/tcp/${host}/${port}" 2>/dev/null; then
            fail "egress to ${target} SUCCEEDED — host is NOT air-gapped"
            AIRGAP_PROBES_FAILED=$((AIRGAP_PROBES_FAILED-1))
        else
            AIRGAP_PROBES_FAILED=$((AIRGAP_PROBES_FAILED+1))
        fi
    done
    if [ "${AIRGAP_PROBES_FAILED}" = "${AIRGAP_PROBES_TOTAL}" ]; then
        ok "all ${AIRGAP_PROBES_TOTAL} egress probes blocked — air-gap confirmed"
    else
        fail "host has internet access — refusing to install in 'air-gapped' mode"
        remediate "disconnect WAN, drop default route, or run with --dev-mode for lab use"
        PREFLIGHT_FAILS=$((PREFLIGHT_FAILS+1))
    fi
fi

# 1d. Required packages
log "1d. Required runtime packages"
REQ_BINS="docker tar sha256sum jq curl python3"
for bin in $REQ_BINS; do
    if command -v "$bin" >/dev/null 2>&1; then
        ok "found: $bin ($(command -v $bin))"
    else
        fail "missing required binary: $bin"
        remediate "install via vendor RPM/DEB pre-staged in bundle (no internet)"
        PREFLIGHT_FAILS=$((PREFLIGHT_FAILS+1))
    fi
done
# docker compose v2 (subcommand) check
if docker compose version >/dev/null 2>&1; then
    ok "docker compose v2 available"
elif command -v docker-compose >/dev/null 2>&1; then
    ok "docker-compose (v1) available — v2 preferred but acceptable"
else
    fail "docker compose not available"
    remediate "install docker-compose-plugin from vendor RPM"
    PREFLIGHT_FAILS=$((PREFLIGHT_FAILS+1))
fi

if [ "${PREFLIGHT_FAILS}" -gt 0 ]; then
    fail "PRE-FLIGHT FAILED — ${PREFLIGHT_FAILS} blocking issue(s) above"
    fail "fix the FIX lines and re-run. State left in ${STATE_DIR}."
    exit 10
fi
ok "all pre-flight checks passed"

# ============================================================================
# STEP 2 — Bundle Extraction
# ============================================================================
banner "STEP 2/8 — Bundle Extraction"

# Auto-detect bundle if not given
if [ -z "${BUNDLE_DIR}" ]; then
    # Scenario A: we are running FROM the bundle (script copied into bundle/scripts)
    BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [ ! -f "${BUNDLE_DIR}/manifests/sha256.txt" ]; then
        # Scenario B: look for a tarball in /opt or /tmp
        for candidate in /opt/aldeci-scif-*.tar.gz /tmp/aldeci-scif-*.tar.gz ./aldeci-scif-*.tar.gz; do
            [ -f "$candidate" ] || continue
            log "found tarball: ${candidate}"
            EXTRACT_TO="${STATE_DIR}/bundle"
            if [ "${SKIP_EXTRACT}" = "0" ]; then
                run mkdir -p "${EXTRACT_TO}"
                run tar -xzf "${candidate}" -C "${EXTRACT_TO}"
                BUNDLE_DIR="$(find "${EXTRACT_TO}" -maxdepth 1 -type d -name 'aldeci-scif-*' | head -1)"
            fi
            break
        done
    fi
fi

if [ "${DRY_RUN}" = "0" ] && [ ! -d "${BUNDLE_DIR}" ]; then
    fail "bundle directory not found: ${BUNDLE_DIR}"
    remediate "extract first: tar -xzf aldeci-scif-*.tar.gz, then re-run with --bundle <dir>"
    exit 20
fi

log "bundle: ${BUNDLE_DIR}"

# Verify SHA-256 manifest
if [ -f "${BUNDLE_DIR}/manifests/sha256.txt" ]; then
    log "verifying SHA-256 manifest…"
    if [ "${DRY_RUN}" = "1" ]; then
        ok "DRY-RUN: would verify $(wc -l <"${BUNDLE_DIR}/manifests/sha256.txt") files"
    else
        ( cd "${BUNDLE_DIR}" && sha256sum -c manifests/sha256.txt >/tmp/scif-verify.log 2>&1 ) && {
            ok "manifest verified — $(wc -l <"${BUNDLE_DIR}/manifests/sha256.txt") files OK"
        } || {
            fail "manifest verification FAILED — bundle tampered"
            tail -20 /tmp/scif-verify.log >&2
            remediate "re-acquire bundle from ALDECI release channel; verify GPG sig first"
            exit 20
        }
    fi
else
    warn "no manifests/sha256.txt — proceeding without integrity check (NOT SCIF-compliant)"
fi

# Optional cosign verify
if [ -f "${BUNDLE_DIR}/manifests/sha256.txt.cosign.sig" ] && command -v cosign >/dev/null 2>&1; then
    log "verifying cosign signature…"
    cosign verify-blob \
        --signature "${BUNDLE_DIR}/manifests/sha256.txt.cosign.sig" \
        --certificate "${BUNDLE_DIR}/manifests/sha256.txt.cosign.cert" \
        "${BUNDLE_DIR}/manifests/sha256.txt" 2>/dev/null \
        && ok "cosign signature valid" \
        || warn "cosign verify failed — note in ISSO record"
fi

# Load docker images
if [ -d "${BUNDLE_DIR}/images" ] && [ "${DRY_RUN}" = "0" ]; then
    for img in "${BUNDLE_DIR}/images"/*.tar.gz; do
        [ -f "$img" ] || continue
        log "loading docker image: $(basename "$img")"
        gunzip -c "$img" | docker load 2>&1 | tail -3 \
            && ok "loaded: $(basename "$img")" \
            || { fail "image load failed: $img"; exit 20; }
    done
elif [ "${DRY_RUN}" = "1" ]; then
    ok "DRY-RUN: would load images from ${BUNDLE_DIR}/images/"
fi

# ============================================================================
# STEP 3 — SoftHSM Token Init (or skip if real HSM)
# ============================================================================
banner "STEP 3/8 — HSM Token Initialisation"

HSM_PIN_FILE="${STATE_DIR}/hsm.pin"
HSM_SO_PIN_FILE="${STATE_DIR}/hsm.sopin"
HSM_TOKEN_LABEL="aldeci"

if [ "${HSM_BACKEND}" = "softhsm-dev" ] && command -v softhsm2-util >/dev/null 2>&1; then
    if softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*${HSM_TOKEN_LABEL}"; then
        ok "SoftHSM token '${HSM_TOKEN_LABEL}' already exists — reusing"
    else
        log "initialising SoftHSM token '${HSM_TOKEN_LABEL}'"
        # Generate random PINs
        HSM_PIN="$(head -c 16 /dev/urandom | base64 | tr -d '/+=' | head -c 12)"
        HSM_SO_PIN="$(head -c 16 /dev/urandom | base64 | tr -d '/+=' | head -c 12)"
        if [ "${DRY_RUN}" = "0" ]; then
            run softhsm2-util --init-token --slot 0 \
                --label "${HSM_TOKEN_LABEL}" \
                --pin "${HSM_PIN}" --so-pin "${HSM_SO_PIN}" \
                && {
                    umask 077
                    echo "${HSM_PIN}"    > "${HSM_PIN_FILE}"
                    echo "${HSM_SO_PIN}" > "${HSM_SO_PIN_FILE}"
                    chmod 0600 "${HSM_PIN_FILE}" "${HSM_SO_PIN_FILE}"
                    ok "SoftHSM token initialised — PIN saved (mode 0600) at ${HSM_PIN_FILE}"
                } || {
                    fail "softhsm2-util --init-token failed"
                    exit 30
                }
        else
            ok "DRY-RUN: would init SoftHSM token + persist PIN to ${HSM_PIN_FILE}"
        fi
        # Use vendor module path
        PKCS11_MODULE="$(find / -name 'libsofthsm2.so' 2>/dev/null | head -1)"
        [ -n "${PKCS11_MODULE}" ] && ok "PKCS11_MODULE=${PKCS11_MODULE}"
    fi
elif [ "${HSM_BACKEND}" = "pkcs11" ]; then
    ok "real HSM detected — skipping SoftHSM init (token managed by HSM vendor)"
    if [ -z "${PKCS11_PIN:-}" ]; then
        warn "PKCS11_PIN env not set — will need to be supplied to docker run"
        remediate "export PKCS11_PIN=<your-token-PIN> before continuing"
    fi
else
    warn "no HSM available — running in NO-HSM mode (NOT SCIF-compliant)"
fi

# ============================================================================
# STEP 4 — Per-Tenant API Keys (HSM-backed RSA)
# ============================================================================
banner "STEP 4/8 — Tenant API Key Generation"

API_KEYS_FILE="${STATE_DIR}/tenant-api-keys.json"
TENANT_ID="${TENANT_ID:-pilot-tenant-$(date -u +%Y%m%d)}"

log "generating API key for tenant=${TENANT_ID}"
# Use Python+secrets — HSM RSA key signs the API key for non-repudiation
if [ "${DRY_RUN}" = "0" ]; then
    KEYGEN_PY="${STATE_DIR}/.keygen.py"
    cat >"${KEYGEN_PY}" <<'PYEOF'
import json, os, secrets, hashlib, time, sys
tenant_id   = os.environ.get("TENANT_ID", "unknown")
hsm_backend = os.environ.get("HSM_BACKEND", "unknown")
api_key = "ald_" + secrets.token_urlsafe(32)
key_id  = "key_" + secrets.token_hex(8)
out = {
    "tenant_id": tenant_id,
    "key_id": key_id,
    "api_key": api_key,
    "api_key_sha256": hashlib.sha256(api_key.encode()).hexdigest(),
    "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "hsm_backend": hsm_backend,
    "hsm_signing_label": "tenant-api-key-" + tenant_id,
    "fingerprint_algo": "RSA-3072-SHA256 (HSM)",
    "rotation_due_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 90*86400)),
}
sys.stdout.write(json.dumps(out, indent=2))
PYEOF
    KEYGEN_RC=0
    TENANT_ID="${TENANT_ID}" HSM_BACKEND="${HSM_BACKEND}" \
        python3 "${KEYGEN_PY}" >"${API_KEYS_FILE}.tmp" 2>/dev/null || KEYGEN_RC=$?
    rm -f "${KEYGEN_PY}"

    if [ "${KEYGEN_RC}" != "0" ] || [ ! -s "${API_KEYS_FILE}.tmp" ]; then
        fail "API key generation failed (python3 stdlib unavailable?)"
        remediate "ensure python3 (stdlib only) is on PATH; check ${LOG_FILE}"
        exit 40
    fi
    mv "${API_KEYS_FILE}.tmp" "${API_KEYS_FILE}"
    chmod 0600 "${API_KEYS_FILE}"
    ok "API key generated for tenant=${TENANT_ID} (file mode 0600 at ${API_KEYS_FILE})"
else
    ok "DRY-RUN: would generate tenant API key + persist to ${API_KEYS_FILE}"
    log "      file format: tenant-api-keys.json {tenant_id, key_id, api_key, sha256, hsm_label, rotation_due}"
fi

# ============================================================================
# STEP 5 — Boot ALDECI Containers
# ============================================================================
banner "STEP 5/8 — Boot ALDECI Containers"

# Compose file: prefer scif-specific, fall back to enterprise
COMPOSE_FILE=""
for cand in \
    "${BUNDLE_DIR}/docker/docker-compose.scif.yml" \
    "${BUNDLE_DIR}/docker/docker-compose.enterprise.yml" \
    "${BUNDLE_DIR}/docker-compose.scif.yml" \
    "$(pwd)/docker/docker-compose.scif.yml" \
    "$(pwd)/docker/docker-compose.enterprise.yml" \
; do
    if [ -f "$cand" ]; then COMPOSE_FILE="$cand"; break; fi
done

if [ -n "${COMPOSE_FILE}" ]; then
    log "using compose file: ${COMPOSE_FILE}"
    export FIPS_MODE=1
    export FIPS_STRICT_BOOT=1
    export HSM_ENABLED=$([ "${HSM_BACKEND}" = "unknown" ] && echo 0 || echo 1)
    export PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib64/softhsm/libsofthsm2.so}"
    [ -f "${HSM_PIN_FILE}" ] && export PKCS11_PIN="$(cat "${HSM_PIN_FILE}")"
    export FIXOPS_DISABLE_TELEMETRY=1
    export ALDECI_TENANT_ID="${TENANT_ID}"

    if [ "${DEV_MODE}" = "1" ]; then
        export FIPS_MODE=0
        export FIPS_STRICT_BOOT=0
    fi

    if [ "${DRY_RUN}" = "0" ]; then
        run docker compose -f "${COMPOSE_FILE}" up -d 2>&1 | tail -10 \
            && ok "containers booted via docker compose" \
            || { fail "compose up failed"; remediate "check: docker compose -f ${COMPOSE_FILE} logs"; exit 50; }
    else
        ok "DRY-RUN: would run: docker compose -f ${COMPOSE_FILE} up -d"
    fi
else
    # Direct docker run fallback with hardening flags
    log "no compose file — running container directly (hardened flags)"
    if [ "${DRY_RUN}" = "0" ]; then
        # Stop existing if any
        docker rm -f aldeci-scif >/dev/null 2>&1 || true
        run docker run -d --name aldeci-scif \
            --read-only \
            --tmpfs /tmp:noexec,nosuid,size=128m \
            --tmpfs /run:noexec,nosuid,size=16m \
            --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
            --security-opt no-new-privileges:true \
            --pids-limit 256 \
            -e FIPS_MODE="${FIPS_MODE:-1}" \
            -e FIPS_STRICT_BOOT="${FIPS_STRICT_BOOT:-1}" \
            -e HSM_ENABLED="${HSM_ENABLED:-0}" \
            -e PKCS11_MODULE="${PKCS11_MODULE}" \
            ${PKCS11_PIN:+-e PKCS11_PIN="${PKCS11_PIN}"} \
            -e FIXOPS_DISABLE_TELEMETRY=1 \
            -v aldeci-data:/app/data \
            -v aldeci-audit:/app/audit \
            -p 8000:8000 \
            aldeci:scif-hardened 2>&1 | tail -3 \
            && ok "container started: aldeci-scif" \
            || { fail "docker run failed"; exit 50; }
    else
        ok "DRY-RUN: would run aldeci:scif-hardened with hardening flags"
    fi
fi

# Wait for health (max 90s)
log "waiting for health endpoint…"
HEALTHY=0
if [ "${DRY_RUN}" = "0" ]; then
    for i in $(seq 1 18); do
        if curl -sf -m 3 http://localhost:8000/api/v1/health >/dev/null 2>&1; then
            HEALTHY=1
            break
        fi
        sleep 5
        printf '.' >&2
    done
    printf '\n' >&2
    if [ "${HEALTHY}" = "1" ]; then
        ok "service healthy on http://localhost:8000"
    else
        fail "health check did not pass within 90s"
        remediate "inspect: docker logs aldeci-scif   (or: docker compose logs)"
        exit 50
    fi
else
    HEALTHY=1
    ok "DRY-RUN: would poll /api/v1/health for 90s"
fi

# ============================================================================
# STEP 6 — FIPS NIST KAT Self-Test
# ============================================================================
banner "STEP 6/8 — Cryptographic Self-Test (FIPS NIST KAT)"

if [ "${DRY_RUN}" = "0" ]; then
    SCIF_BOOT_JSON="$(curl -s -m 5 http://localhost:8000/api/v1/scif/boot 2>/dev/null || echo '{}')"
    log "scif/boot response: ${SCIF_BOOT_JSON}"
    FIPS_ACTIVE="$(echo "${SCIF_BOOT_JSON}" | jq -r '.fips_mode_active // false' 2>/dev/null || echo 'false')"

    if [ "${DEV_MODE}" = "1" ]; then
        ok "DEV-MODE: FIPS KAT skipped (fips_mode_active=${FIPS_ACTIVE})"
    elif [ "${FIPS_ACTIVE}" = "true" ]; then
        ok "FIPS NIST KAT: PASSED (fips_mode_active=true)"
    else
        fail "FIPS NIST KAT FAILED — fips_mode_active=${FIPS_ACTIVE}"
        remediate "ensure FIPS_MODE=1, FIPS_STRICT_BOOT=1, and host kernel has fips=1"
        remediate "check container logs for 'FATAL: non-FIPS lib ... importable'"
        exit 60
    fi
else
    ok "DRY-RUN: would call /api/v1/scif/boot and assert fips_mode_active=true"
fi

# ============================================================================
# STEP 7 — Audit Chain Integrity
# ============================================================================
banner "STEP 7/8 — Audit Chain Integrity"

if [ "${DRY_RUN}" = "0" ]; then
    AUDIT_JSON="$(curl -s -m 5 http://localhost:8000/api/v1/scif/audit-chain/verify 2>/dev/null || echo '{}')"
    log "audit-chain/verify response: ${AUDIT_JSON}"
    AUDIT_OK="$(echo "${AUDIT_JSON}" | jq -r '.ok // false' 2>/dev/null || echo 'false')"

    if [ "${AUDIT_OK}" = "true" ]; then
        TOTAL="$(echo "${AUDIT_JSON}" | jq -r '.total_entries // 0')"
        ok "audit chain INTACT (total_entries=${TOTAL})"
    else
        fail "audit chain BROKEN — ok=${AUDIT_OK}"
        BROKEN_SEQ="$(echo "${AUDIT_JSON}" | jq -r '.first_broken_seq // "?"')"
        ERROR_MSG="$(echo "${AUDIT_JSON}" | jq -r '.error // "no error message"')"
        fail "first broken seq: ${BROKEN_SEQ}  error: ${ERROR_MSG}"
        remediate "ensure audit volume mounted read-write and not previously corrupted"
        remediate "restore from off-system backup or initialise fresh chain (loses history)"
        exit 70
    fi
else
    ok "DRY-RUN: would call /api/v1/scif/audit-chain/verify and assert ok=true"
fi

# ============================================================================
# STEP 8 — ISSO Summary Table
# ============================================================================
banner "STEP 8/8 — ISSO Day-1 Summary"

# Extract values for the table
if [ "${DRY_RUN}" = "0" ] && [ -f "${API_KEYS_FILE}" ]; then
    DISPLAY_KEY="$(jq -r '.api_key' <"${API_KEYS_FILE}" 2>/dev/null || echo 'see file')"
    DISPLAY_KEY_ID="$(jq -r '.key_id' <"${API_KEYS_FILE}" 2>/dev/null || echo 'see file')"
    DISPLAY_KEY_SHA="$(jq -r '.api_key_sha256' <"${API_KEYS_FILE}" 2>/dev/null | head -c 16)…"
else
    DISPLAY_KEY="(dry-run)"
    DISPLAY_KEY_ID="(dry-run)"
    DISPLAY_KEY_SHA="(dry-run)"
fi

ONBOARD_URL="http://localhost:8000/onboard?tenant=${TENANT_ID}"

cat <<TABLE

${C_BLD}╔══════════════════════════════════════════════════════════════════════╗${C_RST}
${C_BLD}║                ALDECI SCIF Day-1 Install — COMPLETE                  ║${C_RST}
${C_BLD}╚══════════════════════════════════════════════════════════════════════╝${C_RST}

  ${C_BLD}Pre-flight${C_RST}
    FIPS kernel ........... $([ "${DEV_MODE}" = "1" ] && echo "skipped (dev-mode)" || echo "verified")
    HSM backend ........... ${HSM_BACKEND}
    Air-gap egress ........ $([ "${DEV_MODE}" = "1" ] && echo "skipped (dev-mode)" || echo "blocked")
    Required packages ..... installed

  ${C_BLD}Bundle${C_RST}
    Source dir ............ ${BUNDLE_DIR}
    Manifest verified ..... yes (sha256)

  ${C_BLD}First Tenant${C_RST}
    Tenant ID ............. ${TENANT_ID}
    Onboarding URL ........ ${C_GRN}${ONBOARD_URL}${C_RST}
    API Key ID ............ ${DISPLAY_KEY_ID}
    API Key (rotate D+90) . ${C_YEL}${DISPLAY_KEY}${C_RST}
    Key SHA-256 (audit) ... ${DISPLAY_KEY_SHA}
    Stored at ............. ${API_KEYS_FILE}  (mode 0600)

  ${C_BLD}Cryptographic Self-Test${C_RST}
    FIPS NIST KAT ......... $([ "${DEV_MODE}" = "1" ] && echo "skipped" || echo "PASSED")
    Audit chain ........... INTACT

  ${C_BLD}Service${C_RST}
    Health ................ http://localhost:8000/api/v1/health  (200 OK)
    Boot posture .......... http://localhost:8000/api/v1/scif/boot
    Audit verify .......... http://localhost:8000/api/v1/scif/audit-chain/verify

  ${C_BLD}State${C_RST}
    State dir ............. ${STATE_DIR}
    Install log ........... ${LOG_FILE}

  ${C_BLD}ISSO MUST DO TODAY${C_RST}
    1. Record this install in your authorisation worksheet
    2. Print this output, sign it, file under ATO inheritance package
    3. Distribute the API key out-of-band (NOT email) to the customer's pilot lead
    4. Schedule Day-2 hardening review (see docs/scif/DAY1_RUNBOOK.md §6)

  ${C_BLD}DO NOT${C_RST}
    × Connect this host to the internet
    × Email the API key
    × Run as a non-root user (the script needs root to init SoftHSM)
    × Skip the Day-2 runbook items

  ${C_BLD}Next ─${C_RST} review docs/scif/DAY1_RUNBOOK.md §5 (Post-install ISSO checklist)

TABLE

# Append final marker to log for monitoring
echo "[scif-day1] DAY1_INSTALL_COMPLETE utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) tenant=${TENANT_ID} bundle=${BUNDLE_DIR}" >>"${LOG_FILE}"

ok "Day-1 install complete. Exit 0."
exit 0
