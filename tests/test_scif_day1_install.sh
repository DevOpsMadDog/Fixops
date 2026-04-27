#!/usr/bin/env bash
# =============================================================================
# test_scif_day1_install.sh — smoke test for scripts/scif_pilot_day1_install.sh
# =============================================================================
# Runs the Day-1 install script in DEV-MODE + DRY-RUN and asserts that each of
# the 8 steps prints its expected success marker. No docker, no HSM, no FIPS
# kernel required — pure shell-level regression coverage.
#
# Usage:
#   bash tests/test_scif_day1_install.sh
#   bash tests/test_scif_day1_install.sh --verbose
#
# Exit:
#   0 = all assertions passed
#   1 = at least one assertion failed (full log dumped to stderr)
# =============================================================================

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/scif_pilot_day1_install.sh"

VERBOSE=0
[ "${1:-}" = "--verbose" ] && VERBOSE=1

if [ -t 1 ]; then
    GRN=$'\033[0;32m'; RED=$'\033[0;31m'; YEL=$'\033[0;33m'; RST=$'\033[0m'
else
    GRN=""; RED=""; YEL=""; RST=""
fi

PASS=0
FAIL=0
FAILS_LOG=""

assert() {
    local desc="$1"
    local needle="$2"
    local haystack="$3"
    if echo "${haystack}" | grep -qF -- "${needle}"; then
        printf '  %s✓%s %s\n' "${GRN}" "${RST}" "${desc}"
        PASS=$((PASS+1))
    else
        printf '  %s✗%s %s\n' "${RED}" "${RST}" "${desc}"
        printf '    expected to find: %s\n' "${needle}" >&2
        FAIL=$((FAIL+1))
        FAILS_LOG+="  - ${desc}\n    needle: ${needle}\n"
    fi
}

assert_exit_code() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [ "${actual}" = "${expected}" ]; then
        printf '  %s✓%s %s (exit=%s)\n' "${GRN}" "${RST}" "${desc}" "${actual}"
        PASS=$((PASS+1))
    else
        printf '  %s✗%s %s (expected exit=%s, got %s)\n' "${RED}" "${RST}" "${desc}" "${expected}" "${actual}"
        FAIL=$((FAIL+1))
        FAILS_LOG+="  - ${desc}: expected exit ${expected}, got ${actual}\n"
    fi
}

# ── Pre-checks ─────────────────────────────────────────────────────────────
echo "${YEL}═══ SCIF Day-1 Install — Smoke Test (dev-mode, dry-run) ═══${RST}"
echo "script: ${SCRIPT}"

if [ ! -f "${SCRIPT}" ]; then
    echo "${RED}FATAL${RST}: install script not found at ${SCRIPT}" >&2
    exit 1
fi
if [ ! -x "${SCRIPT}" ]; then
    chmod +x "${SCRIPT}"
fi

# ── Test 1: --help ─────────────────────────────────────────────────────────
echo ""
echo "${YEL}TEST 1${RST}: --help works and exits 0"
HELP_OUT="$(bash "${SCRIPT}" --help 2>&1)"
HELP_RC=$?
assert_exit_code "help exits 0" "0" "${HELP_RC}"
assert "help mentions FIPS"  "FIPS"            "${HELP_OUT}"
assert "help mentions HSM"   "HSM"             "${HELP_OUT}"
assert "help shows --dev-mode flag" "--dev-mode" "${HELP_OUT}"
assert "help shows --dry-run flag"  "--dry-run"  "${HELP_OUT}"
[ "${VERBOSE}" = "1" ] && echo "${HELP_OUT}" | sed 's/^/    | /'

# ── Test 2: full dev-mode + dry-run end-to-end ─────────────────────────────
echo ""
echo "${YEL}TEST 2${RST}: full dev-mode + dry-run end-to-end"
TMPSTATE="$(mktemp -d -t scif-smoke.XXXXXX)"
TMPLOG="${TMPSTATE}/install.log"

DRY_OUT="$(bash "${SCRIPT}" \
    --dev-mode \
    --dry-run \
    --skip-extract \
    --skip-airgap-check \
    --bundle "${REPO_ROOT}" \
    --state-dir "${TMPSTATE}/state" \
    --log "${TMPLOG}" \
    2>&1)"
DRY_RC=$?

assert_exit_code "dev-mode + dry-run exits 0" "0" "${DRY_RC}"

# Step 1 markers (pre-flight)
assert "STEP 1 banner present" "STEP 1/8 — Pre-flight Checks"  "${DRY_OUT}"
assert "1a FIPS step recognised"  "1a. FIPS-validated kernel"   "${DRY_OUT}"
assert "1b HSM step recognised"   "1b. HSM PKCS#11 token"        "${DRY_OUT}"
assert "1c air-gap step recognised" "1c. Air-gap verification"   "${DRY_OUT}"
assert "1d package step recognised" "1d. Required runtime packages" "${DRY_OUT}"
assert "pre-flight passed (final marker)" "all pre-flight checks passed" "${DRY_OUT}"

# Step 2 markers (bundle)
assert "STEP 2 banner present" "STEP 2/8 — Bundle Extraction" "${DRY_OUT}"

# Step 3 markers (HSM)
assert "STEP 3 banner present" "STEP 3/8 — HSM Token Initialisation" "${DRY_OUT}"

# Step 4 markers (API key)
assert "STEP 4 banner present" "STEP 4/8 — Tenant API Key Generation" "${DRY_OUT}"
assert "tenant key path mentioned" "tenant-api-keys.json" "${DRY_OUT}"

# Step 5 markers (containers)
assert "STEP 5 banner present" "STEP 5/8 — Boot ALDECI Containers" "${DRY_OUT}"

# Step 6 markers (FIPS KAT)
assert "STEP 6 banner present" "STEP 6/8 — Cryptographic Self-Test (FIPS NIST KAT)" "${DRY_OUT}"

# Step 7 markers (audit chain)
assert "STEP 7 banner present" "STEP 7/8 — Audit Chain Integrity" "${DRY_OUT}"

# Step 8 markers (summary)
assert "STEP 8 banner present" "STEP 8/8 — ISSO Day-1 Summary" "${DRY_OUT}"
assert "summary table top border"   "ALDECI SCIF Day-1 Install — COMPLETE" "${DRY_OUT}"
assert "summary mentions Tenant ID" "Tenant ID"          "${DRY_OUT}"
assert "summary mentions Onboarding URL" "Onboarding URL" "${DRY_OUT}"
assert "summary mentions Health URL"     "Health"          "${DRY_OUT}"
assert "summary mentions ISSO MUST DO"   "ISSO MUST DO TODAY" "${DRY_OUT}"
assert "summary mentions DO NOT block"   "DO NOT"          "${DRY_OUT}"
assert "next pointer to runbook"          "DAY1_RUNBOOK.md" "${DRY_OUT}"

# Final exit marker
assert "final completion log" "Day-1 install complete." "${DRY_OUT}"

[ "${VERBOSE}" = "1" ] && echo "${DRY_OUT}" | sed 's/^/    | /'

# ── Test 3: missing root + non-dry-run = exit 2 ────────────────────────────
echo ""
echo "${YEL}TEST 3${RST}: non-root + non-dry-run rejected"
if [ "$(id -u)" -ne 0 ]; then
    NOROOT_OUT="$(bash "${SCRIPT}" --bundle "${REPO_ROOT}" 2>&1)"
    NOROOT_RC=$?
    assert_exit_code "non-root non-dry-run exits 2" "2" "${NOROOT_RC}"
    assert "non-root error mentions sudo" "sudo" "${NOROOT_OUT}"
else
    echo "  ${YEL}↷${RST} skipped (running as root)"
fi

# ── Test 4: invalid arg rejected ───────────────────────────────────────────
echo ""
echo "${YEL}TEST 4${RST}: invalid arg rejected with exit 2"
BADARG_OUT="$(bash "${SCRIPT}" --not-a-real-flag 2>&1)"
BADARG_RC=$?
assert_exit_code "bad arg exits 2" "2" "${BADARG_RC}"
assert "bad arg error mentions 'unknown'" "unknown arg" "${BADARG_OUT}"

# ── Test 5: log file produced ──────────────────────────────────────────────
echo ""
echo "${YEL}TEST 5${RST}: install log file produced"
if [ -f "${TMPLOG}" ]; then
    printf '  %s✓%s log file exists: %s\n' "${GRN}" "${RST}" "${TMPLOG}"
    PASS=$((PASS+1))
    LOG_SIZE="$(wc -c <"${TMPLOG}" | tr -d ' ')"
    if [ "${LOG_SIZE}" -gt 100 ]; then
        printf '  %s✓%s log file non-trivial size (%s bytes)\n' "${GRN}" "${RST}" "${LOG_SIZE}"
        PASS=$((PASS+1))
    else
        printf '  %s✗%s log file too small (%s bytes)\n' "${RED}" "${RST}" "${LOG_SIZE}"
        FAIL=$((FAIL+1))
    fi
    if grep -q "DAY1_INSTALL_COMPLETE" "${TMPLOG}"; then
        printf '  %s✓%s log contains DAY1_INSTALL_COMPLETE marker\n' "${GRN}" "${RST}"
        PASS=$((PASS+1))
    else
        printf '  %s✗%s log missing DAY1_INSTALL_COMPLETE marker\n' "${RED}" "${RST}"
        FAIL=$((FAIL+1))
    fi
else
    printf '  %s✗%s log file missing: %s\n' "${RED}" "${RST}" "${TMPLOG}"
    FAIL=$((FAIL+1))
fi

# ── Cleanup ────────────────────────────────────────────────────────────────
rm -rf "${TMPSTATE}"

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "${YEL}═══ Smoke Test Summary ═══${RST}"
echo "  PASS: ${GRN}${PASS}${RST}"
echo "  FAIL: ${RED}${FAIL}${RST}"

if [ "${FAIL}" -gt 0 ]; then
    echo ""
    echo "${RED}FAILED ASSERTIONS:${RST}"
    printf "%b" "${FAILS_LOG}" >&2
    exit 1
fi

echo "${GRN}✓ all smoke-test assertions passed${RST}"
exit 0
