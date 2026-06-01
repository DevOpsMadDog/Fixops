# SPEC-009 — Reproducible Build: lockfile + dependabot + SBOM

- **Status**: DRAFT
- **Owner family**: Supply Chain / Build
- **Files**: `requirements.txt`, new `requirements.lock` (or constraints), `.github/dependabot.yml`, CI
- **Depends on**: PM-5
- **Last updated**: 2026-06-01

## 1. Intent
PM-5: there is **no Python lockfile** and `.github/dependabot.yml` has `package-ecosystem: ""` (vuln
scanning OFF). A security product whose own build is non-reproducible and unscanned is **disqualified
by a SCIF procurement scanner on first review**. This spec makes the Python build pinned, reproducible,
SBOM'd, and continuously vuln-scanned — the table-stakes a security vendor must itself meet.

## 2. Scope
Python dependency supply chain only (UI already has package-lock.json). Pin transitive deps, fix
dependabot, generate an SBOM of our own deps, wire a CI vuln-scan gate. Out of scope: rewriting deps.

## 3. Contracts / artifacts
- `requirements.lock` (or pip-tools `requirements.txt` compiled with hashes) pinning ALL transitives.
- `.github/dependabot.yml` with real `package-ecosystem: "pip"` (+ npm + github-actions) on a schedule.
- A generated SBOM (CycloneDX) of the Python runtime deps, committed or CI-produced.
- CI job that fails on a known-CVE dep above a threshold.

## 4. Functional requirements
- **REQ-009-01**: A pinned, hash-locked Python dependency set exists and `pip install` from it is reproducible (no unbounded transitives like torch via `sentence-transformers>=3.0.0`).
- **REQ-009-02**: `.github/dependabot.yml` declares `pip` (and npm, github-actions) ecosystems with a weekly schedule — no empty ecosystem.
- **REQ-009-03**: An SBOM (CycloneDX JSON) of our Python deps is generated (script or CI) and stored under `docs/sbom/` or produced in CI.
- **REQ-009-04**: A CI step runs `pip-audit` (or equivalent) against the locked set and fails on CVEs at/above HIGH (with a documented allowlist for accepted risks).

## 5. Non-functional
- The lock must install cleanly in the existing Python 3.11 env (don't break the running app).
- Air-gap friendly: the lock enables offline `pip install --no-index` from a vendored wheelhouse later.

## 6. Acceptance criteria (executable)
- **AC-009-01**: `requirements.lock` exists and `pip install --dry-run -r requirements.lock` resolves with pinned versions (no ranges on transitives).
- **AC-009-02**: `.github/dependabot.yml` parses + declares pip; `grep 'package-ecosystem: ""'` returns nothing.
- **AC-009-03**: `pip-audit -r requirements.lock` runs and its output is captured; HIGH/CRITICAL CVEs are either fixed or in a documented allowlist.
- **AC-009-04**: An SBOM file (CycloneDX) is generated for the Python deps.
- **AC-009-05**: app still boots (`create_app()` succeeds) with the locked deps.

## 7. Debate log (Mysti)
| Date | Mode | Verdict |
|------|------|---------|

## 8. Implementation notes
<senior dev fills>
