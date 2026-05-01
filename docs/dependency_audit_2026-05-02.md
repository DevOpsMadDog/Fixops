# Dependency Audit & Safe-Bump Round — 2026-05-02

**Branch:** `features/intermediate-stage`
**Run by:** backend-hardener
**Tools:** `pip-audit` (OSV vulnerability service), `npm audit` (auditReportVersion 2)

## Summary

| Stack | Vulns Before | Vulns After | Closed | Method |
|-------|-------------|-------------|--------|--------|
| Python (`requirements.txt` + installed env) | 11 (8 packages) | 8 (5 packages) | **3** | direct pinned bumps |
| Node (`suite-ui/aldeci-ui-new`) | 0 (413 deps) | 0 | n/a — already clean | none needed |

**Verification gates:**
- `pip install -r requirements.txt` resolves cleanly (no conflicts)
- Beast Mode tests: **753 passed** (32-file suite, 8.77s, zero regressions)
- Node UI: `npm run build` green (4.95s)

## Closed

| CVE / GHSA | Package | Old | New | Severity | Verified |
|------------|---------|-----|-----|----------|----------|
| CVE-2026-40192 (GHSA-whj4-6x5x-4v2j) | pillow | 12.1.1 | **>=12.2.0,<13.0** | HIGH (FITS GZIP decompression bomb) | beast-mode 753/753 |
| CVE-2026-4539 (GHSA-5239-wwwm-4pmq) | pygments | 2.19.2 | **>=2.20.0,<3.0** | MEDIUM (ReDoS in GUID regex) | beast-mode 753/753 |
| CVE-2025-71176 (GHSA-6w46-j5rx-g56g) | pytest | 8.4.2 | **>=9.0.3** | MEDIUM (vulnerable tmpdir handling) | beast-mode 753/753 |

### Side bumps required by CVE-2025-71176 fix
| Package | Old range | New range | Reason |
|---------|-----------|-----------|--------|
| pytest-asyncio | `>=0.26.0,<1.0` | `>=1.0.0,<2.0` | pytest 9.x requires pytest-asyncio >= 1.0 |

## Deferred

| CVE / GHSA | Package | Installed | Fix | Reason for deferral |
|------------|---------|-----------|-----|---------------------|
| GHSA-jj8c-mmj3-mmgv | authlib | 1.6.9 | 1.6.11 | Transitive via `code-review-graph` (RETIRED per CLAUDE.md Stack v2). Not in ALDECI runtime path. Will be removed when code-review-graph is uninstalled. |
| CVE-2025-64340 | fastmcp | 2.14.6 | 3.2.0 | Same — transitive via `code-review-graph`. Major-version bump (2.x→3.x), breaks code-review-graph API. Defer until code-review-graph uninstalled. |
| CVE-2026-27124 | fastmcp | 2.14.6 | 3.2.0 | Same dependency chain. |
| CVE-2026-32871 | fastmcp | 2.14.6 | 3.2.0 | Same dependency chain. |
| CVE-2025-69872 | diskcache | 5.6.3 | **NONE available** | No fix released. Orphan package (no `Required-by`). Candidate for `pip uninstall diskcache` in next round. |
| CVE-2026-39377 | nbconvert | 7.17.0 | 7.17.1 | Transitive via `codegraphcontext` (external dev tool, not in ALDECI runtime). Patch-bump but blocked by codegraphcontext pin. |
| CVE-2026-39378 | nbconvert | 7.17.0 | 7.17.1 | Same — codegraphcontext-pinned. |
| CVE-2026-3219 | pip | 26.0.1 | **NONE available** | No fix released yet (pip self-vuln on tar/zip parsing). System-level package; deferred upstream. |

## Files modified

- `requirements.txt` — pinned `pillow>=12.2.0,<13.0`, `pygments>=2.20.0,<3.0`; bumped `pytest-asyncio` to `>=1.0.0,<2.0`
- `requirements-test.txt` — bumped `pytest>=7.4.0` to `pytest>=9.0.3` (CVE comment)
- `docs/dependency_audit_2026-05-02.md` — this file

## Test evidence

```
============================= 753 passed in 8.77s ==============================
```

All 32 Beast Mode test files green post-bump. Node UI builds in 4.95s with vendor chunks intact.
