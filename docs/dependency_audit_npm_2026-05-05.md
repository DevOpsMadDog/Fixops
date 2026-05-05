# npm Dependency Audit — 2026-05-05

**Scope**: `suite-ui/aldeci-ui-new/package.json`
**Tool**: `npm audit --json` (npm audit report version 2)
**Date**: 2026-05-05
**Prior audit**: 2026-05-02 (round 2, also 0 vulns — confirmed pattern holds)

---

## Package Count

| Bucket   | Count |
|----------|-------|
| prod     | 161   |
| dev      | 249   |
| optional | 77    |
| peer     | 12    |
| **total**| **413** |

## Vulnerability Summary

| Severity | Count |
|----------|-------|
| critical | 0     |
| high     | 0     |
| moderate | 0     |
| low      | 0     |
| info     | 0     |
| **total**| **0** |

**Result: CLEAN. No actionable vulnerabilities.**

---

## Key Runtime Dependencies (attack surface)

| Package | Version pinned | Notes |
|---------|---------------|-------|
| react / react-dom | ^19.0.0 | Latest major — no known CVEs |
| axios | ^1.15.2 | HTTP client — actively patched; 1.x series clean |
| react-router-dom | ^7.1.0 | v7 GA — no active CVEs |
| framer-motion | ^11.15.0 | Animation only — low risk |
| recharts | ^2.15.0 | Chart rendering — low risk |
| @tanstack/react-query | ^5.62.0 | Data fetching — clean |
| zustand | ^5.0.0 | State management — minimal surface |

**dompurify override**: `package.json` pins `dompurify >= 3.4.1` via `overrides` block — this proactively prevents XSS-related transitive downgrades. Correct defensive posture.

---

## Top 5 Watch Items (not current vulns — forward risk)

1. **axios**: History of SSRF/redirect CVEs (pre-1.x). Current 1.15.x is clean. Pin to exact minor in next lockfile refresh.
2. **vite** (^6.0.0 dev): Vite 5.x had path-traversal CVE (GHSA-8jhw-289h-jh2g). v6 unaffected — monitor 6.x advisories.
3. **jsdom** (^28.1.0 dev): Used by vitest. Large attack surface for parsing. Dev-only so no runtime exposure.
4. **@playwright/test** (^1.58.2 dev): Dev-only. No active CVEs but large dependency tree — re-audit after major bumps.
5. **lucide-react** (^0.468.0): SVG icon library. SVG injection risk is theoretical; no active CVE. Low priority.

---

## Recommendation for Next Session

- No patches required. All 413 packages are clean.
- Re-audit after any `npm install` that bumps axios, vite, or jsdom.
- The `dompurify` override in `package.json` is correct — keep it.
- Consider `npm shrinkwrap` or exact-version lockfile pin before enterprise demo (5 days).
