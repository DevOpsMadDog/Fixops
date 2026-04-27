# Dependabot Vulnerability Triage — 2026-04-27

> Security Analyst: security-analyst agent
> gh auth unavailable in this environment — alerts sourced from local pip-audit (Python) + advisory DB cross-reference (JS).
> Full GitHub Dependabot alert count (134) per CLAUDE.md. This triage uses pip-audit for Python ground truth and known-CVE mapping for JS packages.

---

## Summary by Bucket

| Bucket | Manifest | Alerts | Critical | High | Medium | Low |
|--------|----------|--------|----------|------|--------|-----|
| A | suite-ui/aldeci/ (frozen) | ~17 (per CLAUDE.md) | 0 | 3 | 7 | 0 |
| B | suite-ui/aldeci-ui-new/ | ~5 | 0 | 1 | 0 | 0 |
| C | requirements.txt + Python | ~24 (pip-audit: 24 CVEs across 13 pkgs) | 0 | 8 | 12 | 4 |

Total tracked: ~46 (subset of the 134 on default branch — remainder in worktree copies, lock files, transitive deps).

---

## Top 10 Highest-Severity Alerts

| # | Severity | Package | Version | CVE / GHSA | Manifest | Fix |
|---|----------|---------|---------|-----------|----------|-----|
| 1 | HIGH | aiohttp | 3.13.3 | CVE-2026-34515 | requirements.txt | 3.13.4 |
| 2 | HIGH | aiohttp | 3.13.3 | CVE-2026-34513 | requirements.txt | 3.13.4 |
| 3 | HIGH | aiohttp | 3.13.3 | CVE-2026-34516–34520 (6 CVEs) | requirements.txt | 3.13.4 |
| 4 | HIGH | aiohttp | 3.13.3 | CVE-2026-22815 | requirements.txt | 3.13.4 |
| 5 | HIGH | pyjwt | 2.11.0 | CVE-2026-32597 | requirements.txt | 2.12.0 |
| 6 | HIGH | vite | ^5.0.11 | CVE-2025-30208 | suite-ui/aldeci/package.json | Delete dir (frozen) |
| 7 | HIGH | vite | ^5.0.11 | CVE-2025-31486 | suite-ui/aldeci/package.json | Delete dir (frozen) |
| 8 | HIGH | axios | ^1.6.5 | CVE-2025-27152 | suite-ui/aldeci/package.json | Delete dir (frozen) |
| 9 | HIGH | axios | ^1.7.9 | CVE-2025-27152 | suite-ui/aldeci-ui-new/package.json | Bump to ^1.8.2 |
| 10 | ~~HIGH~~ N/A | ~~fastmcp~~ | ~~2.14.6~~ | CVE-2025-64340 + CVE-2026-27124 | **NOT a project dep** | n/a — see correction below |

---

## Bucket A — suite-ui/aldeci/ (frozen legacy UI)

Estimated ~17 alerts retired on deletion (per CLAUDE.md recommendation).

| Package | Version pinned | CVE | Severity | Notes |
|---------|---------------|-----|----------|-------|
| vite | ^5.0.11 | CVE-2025-30208 | HIGH | Arbitrary file read via dev-server URL |
| vite | ^5.0.11 | CVE-2025-31486 | HIGH | Source code exposure via crafted request |
| vite | ^5.0.11 | CVE-2025-32395 | MEDIUM | Dev-server path traversal |
| vite | ^5.0.11 | CVE-2025-46565 | MEDIUM | Dev-server request bypass |
| axios | ^1.6.5 | CVE-2025-27152 | HIGH | SSRF via absolute URL bypass |
| esbuild | (vite dep) | GHSA-67mh-4wv8-2f99 | MEDIUM | Dev-server cross-origin handling |
| postcss | ^8.4.33 | CVE-2023-44270 | MEDIUM | Line-return parsing bug |
| eslint | ^8.56.0 | CVE-2024-7339 | MEDIUM | ReDoS via malformed input |
| react-router-dom | ^6.21.2 | CVE-2025-43865 | MEDIUM | Open redirect in basename |
| react-router-dom | ^6.21.2 | CVE-2025-43864 | MEDIUM | ReDoS via path matching |
| typescript | ^5.3.3 | (transitive) | LOW | Older TS compiler chain vulns |

Bucket A severity breakdown: HIGH=3, MEDIUM=7, LOW=~7 (transitive/lock-file)

### DELETE-SAFE VERDICT: CONDITIONAL YES — with one blocker

**Blocker**: `tests/test_pr1_official_ui.py` (lines 36–73) and `tests/test_suite_layout.py` (line 268) assert `suite-ui/aldeci/` EXISTS and has `package.json`, `src/`, `.env.example`, `SCREEN_API_MAPPING.md`. Deletion will fail both test files.

**These are legacy tests** (the test file is named `test_pr1_official_ui.py` — PR1 predates aldeci-ui-new). They must be updated/deleted first.

**Evidence of zero runtime dependency** (main branch, excluding worktrees):
- All Dockerfile/docker-compose references point to `suite-ui/aldeci-ui-new/` exclusively
- No Python backend imports reference `suite-ui/aldeci/` paths at runtime
- The test references in `test_pr1_official_ui.py` and `test_suite_layout.py` are structural assertions, not runtime imports

---

## Bucket B — suite-ui/aldeci-ui-new/ (active UI)

| Package | Version | CVE | Severity | Fix |
|---------|---------|-----|----------|-----|
| axios | ^1.7.9 | CVE-2025-27152 | HIGH | Bump to ^1.8.2 in package.json |

Note: `dompurify` has an `overrides` entry already set to `^3.4.1` — shows the team is already patching some transitive deps proactively.

Bucket B severity breakdown: HIGH=1, MEDIUM=0, LOW=0

---

## Bucket C — Python (requirements.txt)

All findings from `pip-audit` run against installed environment (2026-04-27):

| Package | Version | CVE | Severity | Fix | Notes |
|---------|---------|-----|----------|-----|-------|
| aiohttp | 3.13.3 | CVE-2026-34513–34520 + CVE-2026-22815 (9 CVEs) | HIGH | 3.13.4 | **Single bump clears 9 CVEs** |
| pyjwt | 2.11.0 | CVE-2026-32597 | HIGH | 2.12.0 | JWT validation bypass |
| ~~fastmcp~~ | ~~2.14.6~~ | CVE-2025-64340 + CVE-2026-27124 | n/a | n/a | **CORRECTION 2026-04-28**: NOT a project dep. Not pinned in any requirements/pyproject. Zero imports across suite-*/tests. Installed only as transitive dep of retired `code-review-graph` global tool at /opt/homebrew/lib/python3.11/site-packages. No project-runtime attack surface. Skip the bump. |
| cryptography | 46.0.6 | CVE-2026-39892 | HIGH | 46.0.7 | Patch release, minimal API change |
| authlib | 1.6.9 | GHSA-jj8c-mmj3-mmgv | HIGH | 1.6.11 | OAuth token validation |
| requests | 2.32.5 | CVE-2026-25645 | MEDIUM | 2.33.0 | URL credential leak |
| python-multipart | 0.0.22 | CVE-2026-40347 | MEDIUM | 0.0.26 | Multipart parsing DoS |
| pygments | 2.19.2 | CVE-2026-4539 | MEDIUM | 2.20.0 | ReDoS in lexer |
| nbconvert | 7.17.0 | CVE-2026-39378/39377 | MEDIUM | 7.17.1 | Template injection |
| pillow | 12.1.1 | CVE-2026-40192 | MEDIUM | 12.2.0 | Image parsing OOB read |
| diskcache | 5.6.3 | CVE-2025-69872 | MEDIUM | No fix yet | Cache poisoning; monitor |
| pip | 26.0.1 | CVE-2026-3219 | LOW | No fix yet | Index URL spoofing |
| pytest | 9.0.2 | CVE-2025-71176 | LOW | 9.0.3 | Test-time only |

Bucket C severity breakdown: HIGH=5 packages (14 CVEs), MEDIUM=6 packages (7 CVEs), LOW=2 packages (2 CVEs)

**Quick-win**: `aiohttp` bump 3.13.3 → 3.13.4 clears 9 CVEs in one line change.

---

## Recommended Remediation Sequence

### Step 1 — Test cleanup (prerequisite for deletion, ~30 min)
Delete or update `tests/test_pr1_official_ui.py` to point at `aldeci-ui-new/` instead of `aldeci/`.
Update `tests/test_suite_layout.py` line 268 — remove assertion that `suite-ui/aldeci` exists.

### Step 2 — Delete suite-ui/aldeci/ (~5 min, retires ~17 alerts)
```bash
git rm -r suite-ui/aldeci/
git commit -m "beast-mode(security): delete frozen suite-ui/aldeci — retires ~17 dependabot alerts"
```
Verify: `tests/test_suite_layout.py` and `tests/test_pr1_official_ui.py` must pass after update in Step 1.

### Step 3 — Bump active UI axios (~10 min, clears 1 HIGH)
In `suite-ui/aldeci-ui-new/package.json`:
```json
"axios": "^1.8.2"
```
Run `npm install` and re-test UI.

### Step 4 — Python quick-wins (~20 min, clears 14+ CVEs)
Priority bumps in `requirements.txt`:
```
aiohttp>=3.13.4          # 9 CVEs cleared
pyjwt>=2.12.0            # JWT bypass cleared
cryptography>=46.0.7     # 1 HIGH cleared
requests>=2.33.0         # 1 MEDIUM cleared
python-multipart>=0.0.26 # 1 MEDIUM cleared
pygments>=2.20.0         # 1 MEDIUM cleared
nbconvert>=7.17.1        # 2 MEDIUMs cleared
pillow>=12.2.0           # 1 MEDIUM cleared
pytest>=9.0.3            # 1 LOW cleared
```

### Step 5 — Evaluate major-version bumps (needs CTO review)
- ~~`fastmcp` 2.14.6 → 3.2.0~~ — **2026-04-28: REMOVED from sequence.** Not a project dep. CVE doesn't apply to ALDECI runtime. Bump skipped.
- `authlib` 1.6.9 → 1.6.11 (patch, low risk)
- `diskcache` 5.6.3 — no fix available; assess usage and consider replacement

---

## Notes on gh auth

The GitHub Dependabot API was inaccessible (gh not authenticated in this agent environment). The 134-alert figure is from CLAUDE.md. The JS vulnerability data above is cross-referenced from the GitHub Advisory Database against the exact version ranges in the package.json files. The Python data is from a live `pip-audit` run (24 CVEs across 13 packages, ground truth). Actual GitHub alert IDs should be verified once `gh auth login` is available.
