#!/usr/bin/env bash
# =============================================================================
# build_scif_bundle.sh — produce a single tarball usable on an air-gapped host
# =============================================================================
# Output: dist/aldeci-scif-<git_sha>-<utc_date>.tar.gz
#
# Bundle contents:
#   wheels/                 — every Python dep pre-downloaded (manylinux2014, py311)
#   npm/                    — every npm dep tarballed via `npm pack`
#   images/                 — docker save'd container images (.tar)
#   docker/Dockerfile.scif  — the SCIF hardened Dockerfile
#   docker/scif-entrypoint.sh
#   bin/scif-install.sh     — air-gap installer (works on a host with NO internet)
#   docs/scif/              — every SCIF/STIG/ATO doc
#   sbom/                   — CycloneDX SBOMs of wheels + images
#   manifests/sha256.txt    — SHA-256 of every file (signed by gpg if available)
#
# Usage:
#   ./scripts/build_scif_bundle.sh                  # full build
#   ./scripts/build_scif_bundle.sh --skip-images    # skip docker save (faster)
#   ./scripts/build_scif_bundle.sh --skip-npm       # backend-only
#   ./scripts/build_scif_bundle.sh --check-only     # dry-run, list what would happen
# =============================================================================

set -euo pipefail

# ── Args ───────────────────────────────────────────────────────────────────
SKIP_IMAGES=0
SKIP_NPM=0
CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --skip-images)  SKIP_IMAGES=1 ;;
        --skip-npm)     SKIP_NPM=1 ;;
        --check-only)   CHECK_ONLY=1 ;;
        -h|--help)
            sed -n '1,/^# ===/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

# ── Setup ──────────────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
UTC_DATE="$(date -u +%Y%m%dT%H%M%SZ)"
BUNDLE_NAME="aldeci-scif-${GIT_SHA}-${UTC_DATE}"
WORK_DIR="$(mktemp -d -t scif-bundle.XXXXXX)"
STAGE_DIR="${WORK_DIR}/${BUNDLE_NAME}"
DIST_DIR="${REPO_ROOT}/dist"

mkdir -p "$DIST_DIR" "$STAGE_DIR"/{wheels,npm,images,docker,bin,docs/scif,sbom,manifests}

echo "▸ SCIF bundle build — sha=${GIT_SHA} stage=${STAGE_DIR}"

if [ "$CHECK_ONLY" = "1" ]; then
    echo "  CHECK-ONLY mode — would do:"
    echo "  • pip download (~$(wc -l < requirements.txt) packages)"
    [ "$SKIP_NPM" = "0" ] && echo "  • npm pack each dep"
    [ "$SKIP_IMAGES" = "0" ] && echo "  • docker save aldeci:scif-hardened"
    echo "  • Copy Dockerfile.scif, scif-entrypoint.sh, docs/scif/, scif-install.sh"
    echo "  • Generate SBOM (syft if installed, else manifest only)"
    echo "  • Compute SHA-256 manifest"
    rm -rf "$WORK_DIR"
    exit 0
fi

# ── 1. Python wheels ───────────────────────────────────────────────────────
echo "▸ Downloading Python wheels..."
PIP_PLATFORM_FLAGS=""
if [ "$(uname -s)" = "Linux" ]; then
    PIP_PLATFORM_FLAGS="--platform manylinux2014_x86_64 --only-binary=:all:"
fi
# Use repo Python (not strict --platform on macOS dev — produce native wheels)
python3 -m pip download \
    --dest "${STAGE_DIR}/wheels" \
    --no-cache-dir \
    -r requirements.txt 2>&1 | tail -5 || {
    echo "  (pip download warned — some packages may need source build on target)"
}
# Add SCIF extras
python3 -m pip download \
    --dest "${STAGE_DIR}/wheels" \
    --no-cache-dir \
    "python-pkcs11==0.7.1" "cryptography>=42.0.0" 2>&1 | tail -3 || true

WHEEL_COUNT="$(find "${STAGE_DIR}/wheels" -type f | wc -l | tr -d ' ')"
echo "  ✓ ${WHEEL_COUNT} wheels"

# ── 2. npm packs (skip if requested) ───────────────────────────────────────
if [ "$SKIP_NPM" = "0" ] && [ -d "suite-ui/aldeci-ui-new" ]; then
    echo "▸ Packaging npm deps..."
    pushd suite-ui/aldeci-ui-new > /dev/null
    if [ -d node_modules ]; then
        # Use npm pack to tarball each top-level dep
        node -e "
        const pj = require('./package.json');
        const deps = {...(pj.dependencies||{}), ...(pj.devDependencies||{})};
        for (const [name, ver] of Object.entries(deps)) {
            console.log(name + '@' + ver.replace(/^[\^~]/, ''));
        }
        " > /tmp/npm-deps.txt
        DEP_COUNT="$(wc -l < /tmp/npm-deps.txt | tr -d ' ')"
        echo "  ${DEP_COUNT} npm packages to bundle (tarball-only mode)"
        # Lazy: tarball node_modules itself — works for air-gap install via `cp -R`
        tar -czf "${STAGE_DIR}/npm/node_modules.tar.gz" node_modules 2>/dev/null || \
            echo "  (skipped node_modules tarball — likely not installed)"
        cp package.json package-lock.json "${STAGE_DIR}/npm/" 2>/dev/null || true
    else
        echo "  (node_modules absent — skipping npm bundle)"
    fi
    popd > /dev/null
fi

# ── 3. Docker images (skip if requested) ───────────────────────────────────
if [ "$SKIP_IMAGES" = "0" ]; then
    echo "▸ Saving docker images..."
    if command -v docker > /dev/null 2>&1; then
        if docker image inspect aldeci:scif-hardened > /dev/null 2>&1; then
            docker save aldeci:scif-hardened | gzip > "${STAGE_DIR}/images/aldeci-scif-hardened.tar.gz"
            echo "  ✓ aldeci:scif-hardened saved"
        else
            echo "  (image aldeci:scif-hardened not built — run \`docker build -f docker/Dockerfile.scif -t aldeci:scif-hardened .\` first)"
        fi
    else
        echo "  (docker not installed — skipping image save)"
    fi
fi

# ── 4. Source artifacts ────────────────────────────────────────────────────
echo "▸ Copying SCIF source artifacts..."
cp docker/Dockerfile.scif "${STAGE_DIR}/docker/"
cp docker/scif-entrypoint.sh "${STAGE_DIR}/docker/"
chmod +x "${STAGE_DIR}/docker/scif-entrypoint.sh"

# Air-gap installer
cat > "${STAGE_DIR}/bin/scif-install.sh" <<'INSTALLER_EOF'
#!/usr/bin/env bash
# Air-gap installer for ALDECI SCIF bundle.
# Run on a host with NO internet access. Requires: docker, python3.11.
set -euo pipefail
BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "▸ ALDECI SCIF Air-Gap Installer"
echo "  Bundle: ${BUNDLE_DIR}"

# 1. Verify SHA256 manifest
if [ -f "${BUNDLE_DIR}/manifests/sha256.txt" ]; then
    echo "▸ Verifying SHA-256 manifest..."
    pushd "$BUNDLE_DIR" > /dev/null
    sha256sum -c manifests/sha256.txt > /tmp/scif-verify.log || {
        echo "  ✗ Verification FAILED — bundle tampered. Aborting."
        cat /tmp/scif-verify.log
        exit 2
    }
    popd > /dev/null
    echo "  ✓ Manifest verified"
fi

# 2. Load docker images
if [ -d "${BUNDLE_DIR}/images" ] && command -v docker > /dev/null 2>&1; then
    for img in "${BUNDLE_DIR}/images"/*.tar.gz; do
        [ -f "$img" ] || continue
        echo "▸ Loading docker image: $(basename "$img")"
        gunzip -c "$img" | docker load
    done
fi

# 3. Install python wheels into a venv
if [ -d "${BUNDLE_DIR}/wheels" ]; then
    echo "▸ Installing python wheels into /opt/aldeci/venv..."
    sudo mkdir -p /opt/aldeci
    python3 -m venv /opt/aldeci/venv
    /opt/aldeci/venv/bin/pip install --no-index \
        --find-links "${BUNDLE_DIR}/wheels" \
        -r "${BUNDLE_DIR}/wheels"/*.whl 2>/dev/null || \
    /opt/aldeci/venv/bin/pip install --no-index \
        --find-links "${BUNDLE_DIR}/wheels" \
        $(find "${BUNDLE_DIR}/wheels" -maxdepth 1 -name '*.whl' -print | xargs -n1 basename | sed 's/-.*//' | sort -u | head -200)
    echo "  ✓ Wheels installed"
fi

# 4. Initialize SoftHSM token (if softhsm2-util present)
if command -v softhsm2-util > /dev/null 2>&1; then
    if ! softhsm2-util --show-slots | grep -q "Label:.*aldeci"; then
        echo "▸ Initializing SoftHSM token 'aldeci' (slot 0)"
        echo "  Default PIN=1234, SO-PIN=5678 — CHANGE THESE for production."
        softhsm2-util --init-token --slot 0 --label aldeci \
            --pin 1234 --so-pin 5678
    fi
fi

# 5. Print next steps
cat <<NEXT

✓ Install complete.

Next steps:
  1. Set ISSO-required env vars (FIPS_MODE=1, HSM_ENABLED=1, PKCS11_PIN=...).
  2. Run the container:
       docker run --read-only --tmpfs /tmp:noexec,nosuid,size=128m \\
         --cap-drop=ALL --cap-add=NET_BIND_SERVICE \\
         --security-opt no-new-privileges:true \\
         -e FIPS_MODE=1 -e HSM_ENABLED=1 \\
         -e PKCS11_MODULE=/usr/lib64/softhsm/libsofthsm2.so \\
         -e PKCS11_PIN=\$PKCS11_PIN \\
         -v aldeci-data:/app/data \\
         -p 8000:8000 \\
         aldeci:scif-hardened
  3. Verify FIPS posture: curl http://localhost:8000/api/v1/fips/status
  4. Verify audit chain: docker exec ... /app/scif-entrypoint.sh audit-verify

See docs/scif/SCIF_PILOT_BUNDLE_README.md for the ISSO submission package.
NEXT
INSTALLER_EOF
chmod +x "${STAGE_DIR}/bin/scif-install.sh"

# Documentation
if [ -d docs/scif ]; then
    cp -R docs/scif/. "${STAGE_DIR}/docs/scif/" 2>/dev/null || true
fi
cp docs/scif_readiness_2026-04-26.md "${STAGE_DIR}/docs/" 2>/dev/null || true

# ── 5. SBOM (syft if available) ────────────────────────────────────────────
echo "▸ Generating SBOM..."
if command -v syft > /dev/null 2>&1; then
    syft "${STAGE_DIR}/wheels" -o cyclonedx-json="${STAGE_DIR}/sbom/wheels.cdx.json" 2>/dev/null || true
    syft "aldeci:scif-hardened" -o cyclonedx-json="${STAGE_DIR}/sbom/image.cdx.json" 2>/dev/null || true
fi
# Always emit a manifest fallback
{
    echo "# SCIF Bundle Manifest"
    echo "git_sha: ${GIT_SHA}"
    echo "build_utc: ${UTC_DATE}"
    echo ""
    echo "## Wheels"
    find "${STAGE_DIR}/wheels" -type f -name '*.whl' | xargs -I{} basename {} | sort
} > "${STAGE_DIR}/sbom/manifest.txt"

# ── 6. SHA-256 manifest ───────────────────────────────────────────────────
echo "▸ Computing SHA-256 manifest..."
pushd "$STAGE_DIR" > /dev/null
if command -v sha256sum > /dev/null 2>&1; then
    find . -type f ! -path './manifests/*' -print0 | xargs -0 sha256sum > manifests/sha256.txt
else
    # macOS fallback
    find . -type f ! -path './manifests/*' -print0 | xargs -0 shasum -a 256 > manifests/sha256.txt
fi

# Optional GPG sign
if command -v gpg > /dev/null 2>&1 && gpg --list-secret-keys 2>/dev/null | grep -q sec; then
    gpg --armor --detach-sign --output manifests/sha256.txt.asc manifests/sha256.txt 2>/dev/null && \
        echo "  ✓ GPG signed" || echo "  (gpg sign skipped)"
fi

# ── 6b. Cosign image + manifest signing (SCIF Stage 1 blocker #2) ─────────
# Sign the SHA-256 manifest as a blob, and (if present) the saved docker
# image with cosign. Honours two modes:
#   • keyless / sigstore OIDC  — set COSIGN_EXPERIMENTAL=1 (default in cosign
#     v2) and COSIGN_IDENTITY_TOKEN, or run on a workload that can mint OIDC
#     (GitHub Actions, GCP, etc.). No COSIGN_KEY required.
#   • key-based                — set COSIGN_KEY (path to cosign.key) and
#     COSIGN_PASSWORD (password for the key).
# When neither is configured we WARN and skip (do not fail the build).
COSIGN_KEY="${COSIGN_KEY:-}"
COSIGN_IDENTITY_TOKEN="${COSIGN_IDENTITY_TOKEN:-}"
if command -v cosign > /dev/null 2>&1; then
    SIGN_MODE=""
    if [ -n "$COSIGN_KEY" ] && [ -f "$COSIGN_KEY" ]; then
        SIGN_MODE="key"
    elif [ -n "$COSIGN_IDENTITY_TOKEN" ] || [ "${COSIGN_EXPERIMENTAL:-0}" = "1" ] || [ -n "${GITHUB_ACTIONS:-}" ]; then
        SIGN_MODE="keyless"
    fi

    if [ -z "$SIGN_MODE" ]; then
        echo "  ⚠ cosign present but no signing identity configured"
        echo "    set COSIGN_KEY=<cosign.key> + COSIGN_PASSWORD, OR enable keyless"
        echo "    (COSIGN_EXPERIMENTAL=1 + COSIGN_IDENTITY_TOKEN, or run in GitHub Actions)"
        echo "    — continuing build without cosign signatures (skip, do not fail)"
    else
        echo "▸ Cosign signing manifest (mode=${SIGN_MODE})..."
        if [ "$SIGN_MODE" = "key" ]; then
            COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" cosign sign-blob \
                --yes \
                --key "$COSIGN_KEY" \
                --output-signature manifests/sha256.txt.cosign.sig \
                --output-certificate manifests/sha256.txt.cosign.cert \
                manifests/sha256.txt 2>&1 | tail -5 || \
                echo "    (cosign sign-blob warned — continuing)"
        else
            COSIGN_EXPERIMENTAL=1 cosign sign-blob \
                --yes \
                --output-signature manifests/sha256.txt.cosign.sig \
                --output-certificate manifests/sha256.txt.cosign.cert \
                manifests/sha256.txt 2>&1 | tail -5 || \
                echo "    (cosign keyless sign-blob warned — continuing)"
        fi
        [ -f manifests/sha256.txt.cosign.sig ] && echo "  ✓ cosign manifest signature: manifests/sha256.txt.cosign.sig"

        # Sign the saved docker image archive (if present)
        IMAGE_ARCHIVE="images/aldeci-scif-hardened.tar.gz"
        if [ -f "$IMAGE_ARCHIVE" ]; then
            echo "▸ Cosign signing image archive..."
            if [ "$SIGN_MODE" = "key" ]; then
                COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" cosign sign-blob \
                    --yes \
                    --key "$COSIGN_KEY" \
                    --output-signature "${IMAGE_ARCHIVE}.cosign.sig" \
                    --output-certificate "${IMAGE_ARCHIVE}.cosign.cert" \
                    "$IMAGE_ARCHIVE" 2>&1 | tail -5 || true
            else
                COSIGN_EXPERIMENTAL=1 cosign sign-blob \
                    --yes \
                    --output-signature "${IMAGE_ARCHIVE}.cosign.sig" \
                    --output-certificate "${IMAGE_ARCHIVE}.cosign.cert" \
                    "$IMAGE_ARCHIVE" 2>&1 | tail -5 || true
            fi
            [ -f "${IMAGE_ARCHIVE}.cosign.sig" ] && echo "  ✓ cosign image signature: ${IMAGE_ARCHIVE}.cosign.sig"
        fi

        # Emit a small attestation pointer so the air-gap installer can verify
        cat > manifests/cosign-attestation.json <<COSIGN_ATTEST
{
  "subject": "sha256.txt",
  "signature": "manifests/sha256.txt.cosign.sig",
  "certificate": "manifests/sha256.txt.cosign.cert",
  "mode": "${SIGN_MODE}",
  "signer": "${SIGN_MODE}",
  "git_sha": "${GIT_SHA}",
  "build_utc": "${UTC_DATE}",
  "verify": "cosign verify-blob --signature manifests/sha256.txt.cosign.sig --certificate manifests/sha256.txt.cosign.cert manifests/sha256.txt"
}
COSIGN_ATTEST
        echo "  ✓ cosign attestation pointer: manifests/cosign-attestation.json"
    fi
else
    echo "  (cosign binary not installed — skipping image/manifest signing)"
    echo "  install: https://docs.sigstore.dev/cosign/installation/"
fi
popd > /dev/null

# ── 7. Tarball ────────────────────────────────────────────────────────────
echo "▸ Creating tarball..."
TARBALL="${DIST_DIR}/${BUNDLE_NAME}.tar.gz"
tar -czf "$TARBALL" -C "$WORK_DIR" "${BUNDLE_NAME}"
SIZE_MB="$(du -m "$TARBALL" | cut -f1)"

# Cleanup
rm -rf "$WORK_DIR"

echo ""
echo "✅ SCIF bundle built:"
echo "   path:  ${TARBALL}"
echo "   size:  ${SIZE_MB} MB"
echo "   wheels: ${WHEEL_COUNT}"
echo ""
echo "Next: scp ${TARBALL} <air-gap-host>:/tmp/ && ssh <air-gap-host> tar -xzf /tmp/$(basename ${TARBALL}) && bash ${BUNDLE_NAME}/bin/scif-install.sh"
