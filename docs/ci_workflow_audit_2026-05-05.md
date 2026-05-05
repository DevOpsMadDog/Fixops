# CI Workflow Audit — regression-gates.yml (2026-05-05)

## File
`.github/workflows/regression-gates.yml`

## YAML Validity
Valid. Parsed cleanly with `yaml.safe_load`.

## Triggers
- `pull_request` → branches: `main`, `features/intermediate-stage`
- `push` → branch: `features/intermediate-stage`

Consistent across both jobs (workflow-level triggers, not per-job).

## Jobs (2 total)

| Job | runs-on | timeout | Python cache | Node cache |
|-----|---------|---------|--------------|------------|
| `owasp-lockdown` | ubuntu-latest | 15 min | `pip` (actions/setup-python@v5) | n/a |
| `ui-build-verification` | ubuntu-latest | 15 min | n/a | `npm` (actions/setup-node@v4) |

## Cache Configuration
- `owasp-lockdown`: `cache: pip` present on `actions/setup-python@v5` — correct.
- `ui-build-verification`: `cache: npm` with `cache-dependency-path: suite-ui/aldeci-ui-new/package-lock.json` — file confirmed present on disk.

## Working-Directory Consistency
All three steps in `ui-build-verification` (Install, Build, Verify dist) use `working-directory: suite-ui/aldeci-ui-new`. No mismatches.

## Concurrency
`group: regression-gates-${{ github.ref }}` with `cancel-in-progress: true` — prevents redundant runs on fast-push branches.

## Global env (owasp-lockdown)
`PYTHONPATH` covers all suite directories. Test env vars (JWT secret, API token) are CI-only placeholders — no production secrets present.

## Issues Found
None. Workflow is well-structured and cache config is correct as-is.

## Fixes Applied
None required.
