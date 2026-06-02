# Red-Team Path-Handling Hardening — 2026-06-02

Audit of API endpoints that accept a caller-supplied filesystem path/filename and
read/write/scan it. Threat: an authenticated user (single-tenant SCIF, but still a
real boundary) pointing the server at arbitrary paths to read/write/leak files.

## DONE (this session)
- **shared primitive** `apps.api._path_safety.safe_fs_path` — single hardening helper
  (always reject `..`/null; opt-in allowlist env). Used by code-intel + air-gap.
- **code-intel repo paths** (`wave_a_code_intel_router`: `/graph/architecture-detect`,
  `/dca/parse`, `/callgraph` — python/TS/java). Parsing arbitrary server dirs is NOT
  intended (you parse *your* repos), so this was the clean fix. Added
  `_safe_local_repo_path()`: always rejects null-byte + `..` traversal; when
  **`FIXOPS_ALLOWED_REPO_ROOTS`** (os.pathsep-separated) is set, requires the resolved
  path within an allowlisted root. Default (unset) = passthrough so self-scan/dogfooding
  still works. Regression-locked: `tests/test_code_intel_repo_path_allowlist.py` (7/7).
  Commit 971c4bd2.

## VERIFIED-SAFE (no change needed)
- **`bulk_router` `/exports/{filename}` download** — rejects `..`/`/`/`\`, extension
  allowlist, symlink-resolve + canonical-path containment in `_EXPORTS_DIR`. Textbook-secure.
- **`import_router` zip extraction** — `zipfile.extract` sanitizes `..` (Python 3.6+) and
  there is an explicit `..`-skip; no zip-slip. (Extracts regular files, not symlinks.)

## RECOMMENDED — opt-in allowlist (all applied this session; envs default-off)
These are **operator-facing path-choice features** where the chosen path IS the point, so
a hard restriction would break legitimate ops. The correct pattern (mirroring the
code-intel fix) is an **opt-in allowlist env** + always-on `..`/null rejection. Deferred
because choosing the allowed roots is a deployment decision (founder/operator):

- ~~**`airgap_router` export `output_path`**~~ — **DONE**: all export (output_path) AND
  import (bundle_path) AND update-package (content_paths) sites now guarded by
  `_guard_airgap_path` -> shared `safe_fs_path` with **`FIXOPS_ALLOWED_AIRGAP_ROOTS`**
  (opt-in) + always-on `..`/null rejection. Non-breaking default. Regression: 11/11.
- ~~**Scanner `target_path`**~~ — **DONE**: checkov + bandit queue_scan target_path now
  guarded by shared `safe_fs_path` with **`FIXOPS_ALLOWED_SCAN_ROOTS`** (opt-in) + always-on
  `..`/null rejection -> 400 on disallowed. (container_scanner `file_path` is a reporting
  label only — not a real FS read, no change needed.) Non-breaking default.

All endpoints above are auth-gated (`Depends(api_key_auth)` / `_require_api_key`); the
residual risk is an *authorized* user reading/writing outside the intended workspace —
real for a hardened SCIF posture, hence the opt-in lockdown controls.
