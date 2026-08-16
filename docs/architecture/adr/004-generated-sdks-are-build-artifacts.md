# ADR-004 — Generated SDKs are build artifacts, not committed source

**Status:** Proposed
**Date:** 2026-08-17

---

## Context

This is the single largest distortion in the repository, and it was invisible until the
symbol pass separated generated code from hand-written code.

Measured on 2026-08-17:

| | |
|---|---|
| Tracked files in repo | **17,961** |
| Tracked files under `sdks/` | **12,189 (68%)** |
| `sdks/` on disk | **134 MB** |
| Lines in `sdks/` | **1,013,545** — roughly equal to *all* hand-written product Python |
| Hand-written product Python | 2,086 files / 1,001,839 lines |

Every one of those files carries the header
`/* generated using openapi-typescript-codegen -- do not edit */`.

Worse, the **Python client is committed twice**:
`sdks/python/aldeci_client` (4,465 files) and
`sdks/python/aldeci_security_intelligence_platform_client` (4,465 files) — identical file
sets, generated from the same spec under two different names. That is 8,930 tracked
files representing one artifact.

The consequences are not cosmetic:

- `Understand-Anything` classifies the repo `very-large` and prices a full semantic pass
  at **801 LLM batches**. The generated SDK dominates that count. Any tool, reviewer, or
  agent that reasons over the codebase pays a ~3× tax on files that no human maintains.
- The measured symbol totals (49,436 functions, 20,416 classes) are inflated by ~11,241
  functions and ~7,145 classes that are generated one-per-file models.
- A regenerated SDK produces enormous diffs that bury real changes in review.
- Two copies guarantee drift: nothing keeps them in step, and nothing tells us which is
  canonical.

## Decision

**Remove generated SDKs from version control and produce them in CI from the OpenAPI
spec.**

1. The OpenAPI specification is the committed source of truth. The clients are outputs.
2. CI regenerates clients on release and publishes them as versioned packages (npm /
   PyPI or an internal index). Consumers install a package; they do not read our repo.
3. `sdks/` is removed from tracking and added to `.gitignore`. History is left intact —
   we do not rewrite it.
4. **Exactly one Python client name survives.** The duplicate is deleted, not deprecated.
5. A CI check fails the build if a generated artifact is reintroduced under version
   control.

## Consequences

- Anyone who was consuming the client by path breaks. That is the point: they should
  consume a versioned package, and the migration is a one-line dependency change.
- Repo drops to ~5,772 tracked files, a **68% reduction**, and the semantic-analysis cost
  falls roughly in proportion.
- Offline/air-gapped builds must vendor the published package rather than rely on the
  repo copy; ADR-001's `scif` profile makes this explicit in the install docs.
- We must actually run the generator in CI, or clients go stale. Staleness becomes a
  visible pipeline failure instead of an invisible divergence between two copies.

## Verification

- `git ls-files sdks/ | wc -l` returns 0.
- A CI step regenerates the client from the committed spec and fails if the result
  differs from the published package version.
- A CI guard fails on any newly tracked file containing a `generated ... do not edit`
  header.
