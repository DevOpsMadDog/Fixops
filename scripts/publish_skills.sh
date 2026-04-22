#!/usr/bin/env bash
# scripts/publish_skills.sh — package Fixops Claude Code skills for release.
#
# Supersedes: claude_skills_packaging_engine PRD (GAP-067 KILL 2026-04-22).
# Reference: .claude/skills/fixops/README.md, docs/GAP_PRD_RECONCILE_2026-04-22.md
#
# Usage:
#   scripts/publish_skills.sh               # auto-detect version from CHANGELOG / git tag
#   scripts/publish_skills.sh 0.1.0         # explicit version
#
# What it does:
#   1. Ensures .claude/skills/fixops/ exists (creates placeholder README.md if empty)
#   2. Tars every *.md under .claude/skills/fixops/ into dist/fixops-claude-skills-<version>.tar.gz
#   3. Emits a SHA256 sum and a signing placeholder next to the tarball
#   4. Prints the commands an operator would run to publish (npm / gh release)
#
# This script is intentionally idempotent and safe to re-run.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILLS_DIR="${REPO_ROOT}/.claude/skills/fixops"
DIST_DIR="${REPO_ROOT}/dist"

log() { printf '[publish_skills] %s\n' "$*" >&2; }
die() { printf '[publish_skills][error] %s\n' "$*" >&2; exit 1; }

# ---- 1. resolve version --------------------------------------------------
VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  if [[ -f "${REPO_ROOT}/CHANGELOG.md" ]] && grep -qE '^## \[' "${REPO_ROOT}/CHANGELOG.md"; then
    VERSION="$(grep -m1 -oE '^## \[[^]]+' "${REPO_ROOT}/CHANGELOG.md" | sed 's/^## \[//')"
  elif git -C "${REPO_ROOT}" describe --tags --abbrev=0 >/dev/null 2>&1; then
    VERSION="$(git -C "${REPO_ROOT}" describe --tags --abbrev=0 | sed 's/^v//')"
  else
    VERSION="0.0.0-dev+$(date -u +%Y%m%d%H%M%S)"
  fi
fi

if [[ ! "${VERSION}" =~ ^[0-9A-Za-z.+-]+$ ]]; then
  die "version string '${VERSION}' contains characters outside [0-9A-Za-z.+-]"
fi

log "packaging skills for version ${VERSION}"

# ---- 2. ensure skills dir exists ----------------------------------------
mkdir -p "${SKILLS_DIR}"

if ! find "${SKILLS_DIR}" -maxdepth 1 -name '*.md' -print -quit | grep -q .; then
  log "no *.md found in ${SKILLS_DIR}; writing placeholder README.md"
  cat > "${SKILLS_DIR}/README.md" <<'EOF'
# Fixops Claude Code Skills (placeholder)

Real skill Markdown files land in Sprint 3. See `docs/GAP_PRD_RECONCILE_2026-04-22.md`
row GAP-067 for disposition and `raw/competitive/truecourse-vs-fixops-comparison.md`
for pattern reference.
EOF
fi

# ---- 3. ensure dist dir exists ------------------------------------------
mkdir -p "${DIST_DIR}"
TARBALL="${DIST_DIR}/fixops-claude-skills-${VERSION}.tar.gz"
CHECKSUM="${TARBALL}.sha256"
SIGPLACEHOLDER="${TARBALL}.sig.placeholder"

# ---- 4. build tarball ----------------------------------------------------
# Use deterministic file ordering for reproducible builds.
#  - --sort=name                   : portable on GNU tar
#  - --owner=0 --group=0 --numeric-owner : strip local user
#  - --mtime='@0'                  : zero timestamps
if tar --help 2>&1 | grep -q -- '--sort=name'; then
  TAR_FLAGS=(--sort=name --owner=0 --group=0 --numeric-owner --mtime='@0')
else
  # BSD tar (macOS default) — fall back to stable behaviour without the GNU flags.
  TAR_FLAGS=()
fi

pushd "${REPO_ROOT}" >/dev/null

# shellcheck disable=SC2068
tar ${TAR_FLAGS[@]+"${TAR_FLAGS[@]}"} \
  -czf "${TARBALL}" \
  -C .claude/skills fixops

popd >/dev/null

# ---- 5. checksum + signature placeholder --------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${TARBALL}" > "${CHECKSUM}"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${TARBALL}" > "${CHECKSUM}"
else
  die "no sha256sum/shasum available to compute checksum"
fi

cat > "${SIGPLACEHOLDER}" <<'EOF'
# placeholder — Sprint 3 wires real signing (gpg or cosign).
# Intended commands:
#   gpg --detach-sign --armor fixops-claude-skills-<version>.tar.gz
# or
#   cosign sign-blob fixops-claude-skills-<version>.tar.gz > fixops-claude-skills-<version>.tar.gz.sig
EOF

log "wrote ${TARBALL}"
log "wrote ${CHECKSUM}"
log "wrote ${SIGPLACEHOLDER}"

# ---- 6. print publish instructions --------------------------------------
cat <<EOF

Skills tarball is ready at:
  ${TARBALL}

To publish (placeholder — Sprint 3 will automate this in CI):

  # Option A: publish to npm under @fixops/claude-skills
  npm publish "${TARBALL}" --access public

  # Option B: attach to a GitHub release
  gh release upload v${VERSION} "${TARBALL}" "${CHECKSUM}"

Consumer install (Sprint 3, documented here for continuity):

  npx -y fixops skills install             # downloads + extracts to ./.claude/skills/fixops/
  # or the underlying tarball can be fetched and untarred by hand.

EOF

log "done."
