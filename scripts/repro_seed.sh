#!/usr/bin/env bash

set -euo pipefail

TAG="${1:-}"
if [ -z "$TAG" ]; then
    echo "Usage: $0 <tag>" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PLAN_FILE="${PLAN_FILE:-build/plan.yaml}"
DIST_DIR="dist"
ARTIFACT="$DIST_DIR/fixops-$TAG.tar.gz"
CHECKSUM_FILE="$ARTIFACT.sha256"

echo "==> Seeding reference checksum for tag: $TAG"

if [ ! -f "$PLAN_FILE" ]; then
    echo "ERROR: Build plan not found at $PLAN_FILE" >&2
    exit 1
fi

mkdir -p "$DIST_DIR"

export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export TZ=UTC

echo "==> Cleaning non-deterministic directories..."
rm -rf artifacts analysis reports tmp .pytest_cache __pycache__ **/__pycache__ **/*.pyc 2>/dev/null || true

echo "==> Creating deterministic archive..."
GZIP=-n tar --sort=name --mtime='UTC 2023-01-01' \
  --owner=0 --group=0 --numeric-owner \
  --pax-option=delete=atime,delete=ctime,exthdr.name=%d/PaxHeaders/%f \
  --exclude='dist' --exclude='artifacts' --exclude='analysis' --exclude='reports' --exclude='tmp' \
  --exclude='.pytest_cache' --exclude='__pycache__' --exclude='*.pyc' \
  -czf "$ARTIFACT" .

if [ ! -f "$ARTIFACT" ]; then
    echo "ERROR: Failed to create artifact at $ARTIFACT" >&2
    exit 1
fi

echo "==> Computing SHA256 checksum..."
if command -v sha256sum >/dev/null 2>&1; then
    CHECKSUM=$(sha256sum "$ARTIFACT" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    CHECKSUM=$(shasum -a 256 "$ARTIFACT" | awk '{print $1}')
else
    echo "ERROR: Neither sha256sum nor shasum found" >&2
    exit 1
fi

echo "$CHECKSUM" > "$CHECKSUM_FILE"

echo "==> Reference checksum seeded:"
echo "    Artifact: $ARTIFACT"
echo "    Checksum: $CHECKSUM"
echo "    Saved to: $CHECKSUM_FILE"
echo ""
echo "To verify reproducibility, run:"
echo "  PYTHONPATH=\$(pwd) python cli/fixops_repro.py verify --tag $TAG --plan $PLAN_FILE --out artifacts/repro/attestations --repo ."
