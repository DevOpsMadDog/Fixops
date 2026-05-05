# Shell Script Audit — 2026-05-05

**Scope**: Project-owned `.sh` files (~100 scripts in `scripts/`, `docker/`, `suite-integrations/`, root). Excluded: `.claude/worktrees/`, `bash-5.1/` test fixtures.

## Issues Found & Fixed

### 1. `setup.sh` — `set -e` only (FIXED)
- **Risk**: Silent failures on pipeline errors; unbound variable references expand to empty string.
- **Fix**: `set -e` → `set -euo pipefail`; added `SCRIPT_DIR` anchor; replaced all relative `cd`/path refs with absolute `${SCRIPT_DIR}/...`; split `export`/assignment for `-u` compatibility; fixed unquoted `$API_PID` in `wait`/`trap`.

### 2. `docker/docker-entrypoint.sh` — `set -e` only (FIXED)
- **Risk**: Production container entrypoint; a failed pipeline (e.g. `python3 ... | grep`) would silently continue boot rather than abort.
- **Fix**: `set -e` → `set -euo pipefail`; fixed unquoted `$API_PID` in `wait`/`kill`; split export+assignment for `-u` safety.

### 3. `docker/postgres/pg-primary-init.sh` — `set -e` only (FIXED)
- **Risk**: initdb script — a failed `psql` or `chown` would silently continue, leaving replication half-configured.
- **Fix**: `set -e` → `set -euo pipefail`.

## Already Clean (no action needed)

| Script | Status |
|--------|--------|
| `scripts/deploy-aws.sh` | `set -euo pipefail`, SCRIPT_DIR anchored |
| `scripts/deploy.sh` | `set -euo pipefail`, SCRIPT_DIR anchored |
| `scripts/deploy-k8s.sh` | `set -euo pipefail`, SCRIPT_DIR anchored |
| `scripts/build_scif_bundle.sh` | `set -euo pipefail` |
| `scripts/scif_pilot_day1_install.sh` | `set -uo pipefail` (intentional: explicit per-step trap) |
| `scripts/nightly_fleet_scan_cron.sh` | `set -euo pipefail` |
| `scripts/restore_env_keys.sh` | `set -euo pipefail` |
| `docker/e2e-test-env/init-localstack.sh` | `set -euo pipefail` |
| `suite-integrations/github-action/entrypoint.sh` | `set -euo pipefail` |
| `suite-integrations/gitlab-ci/scan.sh` | `set -euo pipefail` |
| `scripts/signing/sign-artifact.sh` | `set -euo pipefail` |
| `scripts/signing/verify-artifact.sh` | `set -euo pipefail` |
| `docker/scif-entrypoint.sh` | `#!/bin/sh` + `set -eu` (pipefail not POSIX — correct) |

## Commit

`3d2471a4` — `beast-mode(harden): shell scripts — fix 3 shellcheck issues (set -euo pipefail, cwd anchor)`
