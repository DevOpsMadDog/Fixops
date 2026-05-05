# Regression Gates CI — Run History Check (2026-05-05)

## Workflow
- **File**: `.github/workflows/regression-gates.yml`
- **Added**: commit `7c86c8d2` — "beast-mode(ci): regression gates for OWASP + perf + import sweep on every PR"
- **Triggers**: push to `features/intermediate-stage`; PRs targeting `main` or `features/intermediate-stage`

## Live Run Query
- `gh` CLI v2.89.0 is installed but **unauthenticated** (`gh auth login` required).
- No `GH_TOKEN` / `GITHUB_TOKEN` env var is set in this shell.
- Result: live `gh run list` could not be executed — **0 remote runs confirmed via CLI**.

## On-Disk Verification
- Workflow file confirmed present: `.github/workflows/regression-gates.yml` (60 lines, 2 jobs).
- `100+ commits` landed on `features/intermediate-stage` after `7c86c8d2`, each of which would trigger the push event defined in the workflow.
- Whether GitHub actually executed those runs requires an authenticated `gh run list` or checking Actions tab in the GitHub UI.

## Jobs Defined
| Job | Key steps |
|-----|-----------|
| `owasp-lockdown` | OWASP regression (46 tests) + engine/router import sweep + perf benchmarks |
| `ui-build-verification` | `npm ci` + `npm run build` + dist existence check |

## Action Required
Authenticate `gh` CLI (`gh auth login`) then re-run:
```
gh run list --branch features/intermediate-stage --workflow regression-gates.yml --limit 5
```
