# Dependency Audit — 2026-05-05

## Tool
pip-audit 2.10.0 (`python -m pip_audit -r requirements.txt`)

## Scope
- `requirements.txt` — 57 packages scanned
- `requirements-test.txt` — not audited (test-only, not shipped)

## Result
**No known vulnerabilities found.**

| Severity | Count | Packages |
|----------|-------|----------|
| CRITICAL | 0 | — |
| HIGH | 0 | — |
| MEDIUM | 0 | — |
| LOW | 0 | — |

## Comparison to Prior Audit (docs/dependency_audit_2026-05-02.md)
Prior audit file not present on disk (was noted in MEMORY.md as closing 3 Python CVEs:
pillow, pygments, pytest). Those fixes have held — all three packages now pass clean.
Round-2 closures (authlib 1.6.11, nbconvert 7.17.1) also still clean.

## Recommended Actions
None required. All direct dependencies are free of known CVEs as of 2026-05-05.

## Notes
- Node/npm audit not re-run (no npm changes since 2026-05-03; was 0/413 vulns then).
- Transitive vulnerabilities are covered by pip-audit's full-dependency walk.
- Next scheduled audit: 2026-05-08 or after any `requirements.txt` change.
