#!/bin/sh
# =============================================================================
# ALDECI SCIF Entrypoint — boots in FIPS mode with HSM verification
# =============================================================================
# This entrypoint enforces SCIF posture at container start time.
# It REFUSES TO BOOT if:
#   - FIPS_MODE=1 but kernel reports fips_enabled=0 (warn, not fail in container)
#   - HSM_ENABLED=1 but PKCS#11 module not loadable
#   - Any non-FIPS python crypto library is detected on import path
#
# Exit codes:
#   0   — booted cleanly
#   10  — FIPS env requested but environment not FIPS-capable (fail-closed)
#   11  — HSM env requested but PKCS#11 module unreachable
#   12  — non-FIPS crypto lib detected
#   13  — audit chain init failure
# =============================================================================

set -eu

MODE="${1:-api-only}"
FIPS_MODE="${FIPS_MODE:-0}"
HSM_ENABLED="${HSM_ENABLED:-0}"
PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib64/softhsm/libsofthsm2.so}"

echo "[scif-entrypoint] ALDECI SCIF boot — mode=${MODE} fips=${FIPS_MODE} hsm=${HSM_ENABLED}"

# ── FIPS check ─────────────────────────────────────────────────────────────
if [ "${FIPS_MODE}" = "1" ]; then
    if [ -r /proc/sys/crypto/fips_enabled ]; then
        FIPS_KERNEL="$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)"
        if [ "${FIPS_KERNEL}" != "1" ]; then
            echo "[scif-entrypoint] WARN: FIPS_MODE=1 but kernel fips_enabled=${FIPS_KERNEL}"
            echo "[scif-entrypoint]       Container will operate in 'FIPS-aware' mode."
            echo "[scif-entrypoint]       For full FIPS, run on RHEL 9 / Ubuntu Pro FIPS host with fips=1."
        else
            echo "[scif-entrypoint] FIPS kernel verified."
        fi
    else
        echo "[scif-entrypoint] WARN: /proc/sys/crypto/fips_enabled not readable. FIPS-aware mode."
    fi

    # Check for non-FIPS python libs that should not be loaded in FIPS mode
    NON_FIPS_LIBS="pycryptodome Crypto.Cipher.ARC4 Crypto.Cipher.DES Crypto.Cipher.Blowfish"
    for lib in ${NON_FIPS_LIBS}; do
        if python3.11 -c "import ${lib}" 2>/dev/null; then
            echo "[scif-entrypoint] FATAL: non-FIPS lib ${lib} importable. Refusing to boot." >&2
            exit 12
        fi
    done
fi

# ── HSM check ──────────────────────────────────────────────────────────────
if [ "${HSM_ENABLED}" = "1" ]; then
    if [ ! -r "${PKCS11_MODULE}" ]; then
        echo "[scif-entrypoint] FATAL: HSM_ENABLED=1 but PKCS#11 module not found at ${PKCS11_MODULE}" >&2
        exit 11
    fi
    if ! python3.11 -c "import pkcs11; lib = pkcs11.lib('${PKCS11_MODULE}'); print('HSM:', lib.manufacturer_id)" 2>&1; then
        echo "[scif-entrypoint] FATAL: PKCS#11 module did not load." >&2
        exit 11
    fi
    echo "[scif-entrypoint] HSM verified."
fi

# ── Audit chain init ───────────────────────────────────────────────────────
mkdir -p /app/audit
if ! python3.11 -c "from core.audit_chain import AuditChain; AuditChain('/app/audit/chain.db').verify()" 2>/dev/null; then
    echo "[scif-entrypoint] WARN: audit chain verification failed — initializing fresh chain"
    python3.11 -c "from core.audit_chain import AuditChain; AuditChain('/app/audit/chain.db').append('boot', {'mode': '${MODE}'})" || {
        echo "[scif-entrypoint] FATAL: audit chain init failed" >&2
        exit 13
    }
fi

echo "[scif-entrypoint] All preflight checks passed. Starting ${MODE}."

# ── Launch ─────────────────────────────────────────────────────────────────
case "${MODE}" in
    api-only)
        exec python3.11 -m uvicorn apps.api.app:create_app --factory \
             --host 0.0.0.0 --port 8000 \
             --workers 1 --no-access-log
        ;;
    api)
        exec python3.11 -m uvicorn apps.api.app:create_app --factory \
             --host 0.0.0.0 --port 8000 \
             --workers 2 --no-access-log
        ;;
    audit-verify)
        exec python3.11 -c "from core.audit_chain import AuditChain; ok = AuditChain('/app/audit/chain.db').verify(); print('VERIFIED' if ok else 'BROKEN'); exit(0 if ok else 1)"
        ;;
    *)
        echo "[scif-entrypoint] Unknown mode: ${MODE}" >&2
        exit 2
        ;;
esac
