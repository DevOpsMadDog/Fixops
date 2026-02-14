#!/usr/bin/env bash
# ALdeci (FixOps) — Client SDK Generator
# Generates Python, TypeScript, and Go SDKs from the OpenAPI spec.
#
# Prerequisites:
#   - openapi-generator-cli: npm install -g @openapitools/openapi-generator-cli
#     OR docker: docker pull openapitools/openapi-generator-cli
#   - A running suite-api instance (default: http://localhost:8000)
#
# Usage:
#   ./tools/generate_sdks.sh                           # all SDKs
#   ./tools/generate_sdks.sh python                    # Python only
#   ./tools/generate_sdks.sh typescript                # TypeScript only
#   ./tools/generate_sdks.sh go                        # Go only
#   ALDECI_API_URL=http://prod:8000 ./tools/generate_sdks.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
API_URL="${ALDECI_API_URL:-http://localhost:8000}"
SPEC_URL="${API_URL}/openapi.json"
OUTPUT_DIR="$ROOT_DIR/sdks"
VERSION="${ALDECI_SDK_VERSION:-0.1.0}"

# Colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()   { echo -e "${GREEN}[sdk-gen]${NC} $*"; }
warn()  { echo -e "${YELLOW}[sdk-gen]${NC} $*"; }
err()   { echo -e "${RED}[sdk-gen]${NC} $*" >&2; }

# ---------- Detect generator ----------
GENERATOR=""
if command -v openapi-generator-cli &>/dev/null; then
  GENERATOR="openapi-generator-cli"
elif command -v docker &>/dev/null; then
  GENERATOR="docker run --rm -v ${OUTPUT_DIR}:/out -v /tmp:/spec openapitools/openapi-generator-cli"
else
  err "openapi-generator-cli not found. Install via:"
  err "  npm install -g @openapitools/openapi-generator-cli"
  err "  OR have docker available."
  exit 1
fi

# ---------- Fetch spec ----------
SPEC_FILE="/tmp/aldeci-openapi.json"
log "Fetching OpenAPI spec from ${SPEC_URL} ..."
if ! curl -sf "${SPEC_URL}" -o "${SPEC_FILE}"; then
  warn "Could not reach ${SPEC_URL}. Checking for local spec..."
  if [ -f "$ROOT_DIR/docs/openapi.json" ]; then
    SPEC_FILE="$ROOT_DIR/docs/openapi.json"
    log "Using local spec: $SPEC_FILE"
  else
    err "No OpenAPI spec available. Start the API server or place docs/openapi.json."
    exit 1
  fi
fi

mkdir -p "$OUTPUT_DIR"

# ---------- Generator functions ----------
generate_python() {
  log "Generating Python SDK → ${OUTPUT_DIR}/python/"
  $GENERATOR generate \
    -i "${SPEC_FILE}" \
    -g python \
    -o "${OUTPUT_DIR}/python" \
    --package-name aldeci_sdk \
    --additional-properties="packageVersion=${VERSION},projectName=aldeci-sdk" \
    --skip-validate-spec \
    2>&1 | tail -5
  log "Python SDK generated ✓"
}

generate_typescript() {
  log "Generating TypeScript SDK → ${OUTPUT_DIR}/typescript/"
  $GENERATOR generate \
    -i "${SPEC_FILE}" \
    -g typescript-fetch \
    -o "${OUTPUT_DIR}/typescript" \
    --additional-properties="npmName=@aldeci/sdk,npmVersion=${VERSION},supportsES6=true,typescriptThreePlus=true" \
    --skip-validate-spec \
    2>&1 | tail -5
  log "TypeScript SDK generated ✓"
}

generate_go() {
  log "Generating Go SDK → ${OUTPUT_DIR}/go/"
  $GENERATOR generate \
    -i "${SPEC_FILE}" \
    -g go \
    -o "${OUTPUT_DIR}/go" \
    --package-name aldeci \
    --additional-properties="packageVersion=${VERSION},isGoSubmodule=true" \
    --skip-validate-spec \
    2>&1 | tail -5
  log "Go SDK generated ✓"
}

# ---------- Main ----------
TARGET="${1:-all}"

case "$TARGET" in
  python)     generate_python ;;
  typescript) generate_typescript ;;
  go)         generate_go ;;
  all)
    generate_python
    generate_typescript
    generate_go
    ;;
  *)
    err "Unknown target: $TARGET"
    echo "Usage: $0 [python|typescript|go|all]"
    exit 1
    ;;
esac

log "Done. SDKs written to ${OUTPUT_DIR}/"
log "SDK version: ${VERSION}"

