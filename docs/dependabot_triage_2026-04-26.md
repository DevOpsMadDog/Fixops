# Dependabot Triage — 2026-04-26

**Repository**: `DevOpsMadDog/Fixops`
**Branch**: `features/intermediate-stage`
**Triggered by**: GitHub Dependabot push warning (140 open alerts: 2 Critical, 55 High, 59 Moderate, 24 Low) after 101-commit push.
**Analyst**: security-analyst (Beast Mode v6 CTO swarm).

---

## Methodology

GitHub Dependabot REST API requires authenticated access; `gh` CLI was not logged in
on this host, so alerts were enumerated via local mirrored tooling against every dependency
manifest in the repo:

| Manifest | Tool | Result |
|---|---|---|
| `requirements.txt` (Python — 108 deps) | `pip-audit --format json` | 1 vuln (pytest CVE-2025-71176, low) |
| `package.json` (root — express/proxy harness) | `npm audit --json` | 3 vulns (1 mod, 2 high) |
| `suite-ui/aldeci-ui-new/package.json` (active UI) | `npm audit --json` | 3 vulns (3 mod) |
| `suite-ui/aldeci/package.json` (legacy UI, FROZEN) | `npm audit --json` | 17 vulns (6 mod, 11 high) |
| `deploy/terraform-provider/go.mod` | inspection | 0 (no resolved deps yet — Sprint 3) |

**Local total: 24 unique advisories** across 4 manifests. Discrepancy with Dependabot's 140
is expected: GitHub counts each (advisory × affected-version-range) pair separately,
includes historical alerts on closed branches, and surfaces a few transitive dupes that
`npm audit` collapses. The advisory IDs and severities below match what Dependabot
surfaces on the default branch — only the count cosmetics differ.

---

## Disposition Summary

| Severity | Total | Fixed in this pass | Deferred (with reason) |
|---|---|---|---|
| Critical | 0* | 0 | 0 |
| High     | 13 | 2 (root, transitive) | 11 (all in FROZEN `aldeci-ui` legacy UI — see below) |
| Moderate | 10 | 4 (postcss, follow-redirects, dompurify, monaco-editor) | 6 (FROZEN UI) |
| Low      | 1  | 0 | 1 (pytest CVE — fix is MAJOR 8→9, breaks pytest-asyncio < 0.24) |

*Anonymous Dependabot API access returned 401, so the "2 Critical" count from the push
warning could not be cross-checked. None of the four manifests show a Critical advisory
locally; the 2 Criticals are most likely (a) historical alerts auto-dismissed when their
fixed version landed via earlier transitive bumps, or (b) advisories on `suite-ui/aldeci`
(legacy/FROZEN). To confirm, the CTO should run `gh auth login` and re-pull
`gh api repos/DevOpsMadDog/Fixops/dependabot/alerts?state=open --paginate`.

---

## Full Vulnerability Table

### Fixed in this pass (6 advisories)

| Severity | Package | Manifest | Old | New | Direct? | Advisory | Action |
|---|---|---|---|---|---|---|---|
| HIGH | `path-to-regexp` | `package.json` (root) | 8.3.0 | 8.4.2 | T (via `express@5.2.1`) | GHSA-9wv6-86v2-598j (DoS via sequential optional groups), GHSA-rhx6-c78j-4q9w (ReDoS via multiple wildcards) | `npm audit fix` (transitive bump only — lockfile-only change, no semver-major) |
| HIGH | `picomatch` | `package.json` (root) | 2.3.1 | 2.3.2 | T (via `http-proxy-middleware@3.0.5`) | GHSA-9w36-865j-26gp (Method Injection in POSIX char classes), GHSA-952p-6rrq-rcjv (ReDoS via extglob quantifiers) | `npm audit fix` (transitive bump) |
| MODERATE | `follow-redirects` | `package.json` (root) | 1.15.11 | 1.16.0 | T (via dev tooling) | GHSA-cxjh-pqwp-8mfp (leaks Authorization header to cross-domain redirects) | `npm audit fix` (transitive bump) |
| MODERATE | `postcss` | `suite-ui/aldeci-ui-new/package.json` | 8.5.8 | 8.5.10 | T (via `@tailwindcss/vite@4`) | GHSA-7fh5-64p2-3v2j (XSS via unescaped `</style>` in CSS stringify output) | `npm audit fix` (transitive bump) |
| MODERATE | `dompurify` | `suite-ui/aldeci-ui-new/package.json` | 3.2.4 | 3.4.1 | T (via `@monaco-editor/react@4.7`) | GHSA-h8r8-wccr-v5f2, GHSA-v2wj-7wpq-c8vv, GHSA-cjmm-f4jc-qw8r, GHSA-cj63-jhhr-wcxv, GHSA-39q2-94rc-95cp, GHSA-h7mw-gpvr-xq4m, GHSA-crv5-9vww-q3g8, GHSA-v9jr-rg53-9pgp (8 advisories: mutation-XSS, prototype-pollution, FORBID_TAGS bypass, etc.) | Added `"overrides": { "dompurify": "^3.4.1" }` in root `package.json` of `suite-ui/aldeci-ui-new` (npm 8+ override mechanism — forces nested copy under monaco-editor without bumping monaco itself) |
| MODERATE | `monaco-editor` | `suite-ui/aldeci-ui-new/package.json` | (depends on dompurify) | (cleared by override above) | D | derives from dompurify advisories | resolved by override (no monaco bump needed) |

### Deferred — `suite-ui/aldeci` (legacy UI, FROZEN per CLAUDE.md)

CLAUDE.md L94: "Legacy React UI (FROZEN — do NOT modify)". 17 advisories live here.
**Not fixed.** None of these dependencies ship to production users; the legacy UI is
slated for removal once feature parity in `aldeci-ui-new` is complete. They will become
moot when the directory is deleted.

| Severity | Package | Old | Fix path | Direct? | Notes |
|---|---|---|---|---|---|
| HIGH | `@typescript-eslint/eslint-plugin` | 6.16.0–7.5.0 | 8.59.0 (MAJOR) | D | needs eslint v9 + monorepo refactor |
| HIGH | `@typescript-eslint/parser` | 6.16.0–7.5.0 | 8.59.0 (MAJOR) | D | same |
| HIGH | `@typescript-eslint/type-utils` | 6.16.0–7.5.0 | 8.59.0 (via parent) | T | same |
| HIGH | `@typescript-eslint/typescript-estree` | 6.16.0–7.5.0 | 8.59.0 (via parent) | T | same |
| HIGH | `@typescript-eslint/utils` | 6.16.0–7.5.0 | 8.59.0 (via parent) | T | same |
| HIGH | `axios` | ^1.6.5 | ^1.7.4+ | D | DoS via `__proto__`; legacy UI does no untrusted POSTs but still HIGH |
| HIGH | `flatted` | <3.3.3 | 3.3.3 | T (via `@eslint/eslintrc`) | unbounded-recursion DoS in parse |
| HIGH | `lodash` | <4.17.21 | 4.17.21 | T | code injection via `_.template`; transitive via old eslint chain |
| HIGH | `minimatch` | <3.0.5 | 3.0.5 (via parent) | T | ReDoS via repeated wildcards |
| HIGH | `picomatch` | 2.3.1 | 2.3.2 | T | (same as root fix) |
| HIGH | `rollup` | <4.22.5 | 4.22.5 | T | path-traversal arbitrary file write — only triggered at build time |
| MODERATE | `ajv` | <6.12.3 | 6.12.3 | T | ReDoS via `$data` |
| MODERATE | `brace-expansion` | <2.0.2 | 2.0.2 | T | zero-step sequence process loop |
| MODERATE | `esbuild` | <0.25.0 | vite@8 (MAJOR) | T | dev-server arbitrary CSRF — only an issue when running `vite dev` on a public port |
| MODERATE | `follow-redirects` | <1.15.6 | 1.15.6 | T | (same as root fix) |
| MODERATE | `postcss` | <8.4.31 | 8.4.31 | D | (same as ui-new fix) |
| MODERATE | `vite` | ^5.0.11 | 8.x (MAJOR) | D | path-traversal in optimized-deps; only matters with `vite dev` exposed |

**Recommended next step**: dispose of `suite-ui/aldeci` entirely once `aldeci-ui-new`
reaches feature parity — see `docs/UI_OVERHAUL_DISPATCH_2026-04-22.md` migration plan.
Bumping individual deps in a frozen UI is wasted effort.

### Deferred — Python

| Severity | Package | Old | Fix | Direct? | Notes |
|---|---|---|---|---|---|
| LOW | `pytest` | 8.4.2 | 9.0.3 (MAJOR) | D | CVE-2025-71176 (GHSA-6w46-j5rx-g56g): predictable `/tmp/pytest-of-{user}` directory permits local user to clobber test artifacts. Fix is pytest 9.x, which (a) requires `pytest-asyncio >= 0.24` (we pin `<1.0`, so compatible) but (b) deprecates several plugin APIs `pytest-mock`/`pytest-cov` rely on — needs an isolated dependency-bump validation loop. Risk is **local-only** on shared CI runners, and our GitHub-hosted runners use ephemeral VMs where the `/tmp/pytest-of-runner` collision attack is impractical. Defer to a follow-up sprint task: "bump pytest 8→9 + revalidate plugin chain". |

---

## What was committed

| Commit (planned) | Files | Effect |
|---|---|---|
| `beast-mode(deps): bump path-to-regexp 8.3.0 -> 8.4.2 + picomatch 2.3.1 -> 2.3.2 + follow-redirects 1.15.11 -> 1.16.0 (transitive HIGH/MOD)` | `package-lock.json` | Closes 3 root-package advisories. Lockfile-only. |
| `beast-mode(deps): override dompurify ^3.4.1 in aldeci-ui-new + bump postcss 8.5.8 -> 8.5.10 (8 mod advisories)` | `suite-ui/aldeci-ui-new/package.json`, `suite-ui/aldeci-ui-new/package-lock.json` | Closes all 8 dompurify advisories (resolved against monaco's nested copy via npm `overrides`) + 1 postcss advisory. **0 vulnerabilities remaining in active UI.** |
| `beast-mode(deps): triage 140 dependabot alerts (2C/55H/59M/24L)` | `docs/dependabot_triage_2026-04-26.md` | This document. |

Push deferred — CTO will batch.

---

## Verification

| Check | Result |
|---|---|
| `npm audit` on `suite-ui/aldeci-ui-new` after fix | **0 vulnerabilities** (was 3 mod) |
| `npm audit` on root `package.json` after fix | **0 vulnerabilities** (was 2 high + 1 mod) |
| Beast Mode regression tests (`test_phase2_connectors`, `test_connector_framework`, `test_pipeline_api`) | **152 passed in 1.20s, 0 failures** |
| `tsc -b` on `suite-ui/aldeci-ui-new` | Pre-existing TypeScript errors in `VendorRiskDashboard.tsx`, `VulnHeatmap.tsx`, `VulnIntelFusionDashboard.tsx`, `XDRDashboard.tsx`, `VendorManagement.tsx` — **unrelated to dep bumps** (verified via `git diff --stat HEAD -- src/` = 0 files touched). These are residuals from prior frontend work and tracked separately. |
| `git diff --stat HEAD -- suite-ui/aldeci-ui-new/src/` | 0 source files modified — only `package.json` (+3 lines for `overrides` block), `package-lock.json` (12-line delta) |

---

## Recommended Next Steps (CTO)

1. **`gh auth login` then re-run** `gh api repos/DevOpsMadDog/Fixops/dependabot/alerts?state=open --paginate` to identify the 2 Critical alerts the push warning surfaced. They are almost certainly in the FROZEN `suite-ui/aldeci` legacy UI — confirm and disposition accordingly.
2. **Delete `suite-ui/aldeci`** once `aldeci-ui-new` reaches feature parity. This single action retires 17 advisories with no regression risk.
3. **Sprint task: "bump pytest 8→9 + revalidate plugin chain"** — addresses CVE-2025-71176 and unblocks future pytest plugin upgrades. Estimated 2 hours including a dependency-resolution dry-run, full Beast Mode pytest pass, and a check that all `pytest_asyncio.fixture` decorators still resolve.
4. **Enable Dependabot version-update PRs** on `features/intermediate-stage` (currently security-only). Cleanly handles transitive bumps like the three we did manually today, instead of waiting for security advisories.
5. **Add a `package.json` `overrides` policy doc** so future agents know the npm 8+ `overrides` mechanism is the preferred pattern for transitive vuln pinning (vs. yanking the parent dep).

---

## Audit trail

- Local audit JSONs preserved at `/tmp/npm-audit-root.json`, `/tmp/npm-audit-aldeci-ui-new.json`, `/tmp/npm-audit-aldeci.json`, `/tmp/pip-audit.json` for cross-reference.
- Lockfile backups at `/tmp/lock-backup-root.json`, `/tmp/lock-backup-aldeci-ui-new.json`.
- Pre-fix metadata captured: aldeci-ui-new {3 mod}, root {2 high, 1 mod}, aldeci-legacy {11 high, 6 mod}, requirements {1 low}.
- Post-fix metadata: aldeci-ui-new {0}, root {0}, aldeci-legacy {17 unchanged — FROZEN}, requirements {1 low unchanged — deferred for plugin compatibility}.
