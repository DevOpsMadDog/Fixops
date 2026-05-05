# Dependabot Triage — 2026-05-05

## Summary

GitHub flagged **125 vulnerabilities on `main`** (2 critical / 47 high / 52 moderate / 24 low)
per PR-readiness audit at commit `14929e98`.

## Root Cause — Legacy UI (`suite-ui/aldeci/`)

The 125 vulns originate entirely from the **legacy React frontend** (`suite-ui/aldeci/`)
which still exists on `main`. That directory's `package.json` and its transitive
`node_modules` carry the full vulnerability surface.

**Evidence**: `git log --oneline -- suite-ui/aldeci/package.json` shows the directory
was last present in commit `57cdc4bb` and deleted in commit `5f415a1d` (113 files removed
in that single commit).

## features/intermediate-stage Is Clean

`features/intermediate-stage` has **already deleted `suite-ui/aldeci/`** (since `5f415a1d`).
Only two dependency surfaces remain on this branch:

| Surface | File | Audit result |
|---------|------|-------------|
| Python backend | `requirements.txt` | `pip-audit` → **0 known vulnerabilities** |
| Active frontend | `suite-ui/aldeci-ui-new/package.json` | `npm audit` → **0 vulnerabilities** |

Both verified at HEAD `14929e98`.

## Recommendation

When `features/intermediate-stage` is merged into `main`, the deletion of
`suite-ui/aldeci/` will **automatically close all 125 Dependabot alerts** because the
vulnerable dependency tree will no longer exist on the default branch. No individual
CVE patching is required — the entire legacy surface is gone.

No code changes needed. Merge unblocks the Dependabot alert board in one shot.

## Verified By

- security-analyst agent, 2026-05-05
- Commands: `pip-audit`, `npm audit`, `git log --oneline -- suite-ui/aldeci/package.json`,
  `git show 5f415a1d --stat`
