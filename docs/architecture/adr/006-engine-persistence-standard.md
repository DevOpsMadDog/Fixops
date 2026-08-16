# ADR-006 — One anchored store; engines never resolve paths from the working directory

**Status:** Accepted (partially implemented 2026-08-16, commit `a1f25b93`)
**Date:** 2026-08-17

---

## Context

Engines bind their SQLite paths at **import time**, and the default data directory was a
*relative* path. A relative path resolves against the process's working directory, so the
same logical store landed in different files depending on where the process was started
— and neither copy knew about the other.

Measured inside the running container: **49 database names existed at two locations, and
13 of those pairs held genuinely diverged data.**

| Database | Copy A | Copy B |
|---|---:|---:|
| `clusters.db` (deduplication) | **5,898 rows** | **0 rows** |
| `feeds.db` | 329,388 | 363,810 |
| `trustgraph.db` | 250 | 38 |
| `fixops_brain.db` | 364 | 74 |
| `cve_enrichment.db` | 100 | 0 |

The same root cause produced visible failures elsewhere. Two routers derived their path
with `Path(__file__).resolve().parents[4]`, which from `suite-api/apps/api/` overshoots
the repo root onto `/` — so they tried to create `/.fixops_data` and returned HTTP 500 on
every request. Exactly two files used `parents[4]`, and they were exactly the two failing
endpoints. Separately, `/api/v1/epss/scores` returned an empty list while the platform
held 360,142 EPSS scores, because that domain reads a *different* store from the one the
feed sync populates.

For a product sold on evidence, silently splitting a customer's data across two files is
disqualifying: it is undetectable from the UI and it corrupts the audit trail.

## Decision

**There is exactly one data root per deployment, it is absolute, and it is resolved
before any engine is imported.**

1. `FIXOPS_DATA_DIR` is the single authority. An explicit value from the environment
   always wins.
2. When unset, it is anchored to an absolute path derived from the project root — set in
   **both** `sitecustomize.py` and `apps/api/app.py`, because a Python installation that
   ships its own stdlib `sitecustomize` shadows the repo's copy. (Verified: Homebrew's
   Python does exactly this, so the repo hook alone is not sufficient.)
3. Engines **must not** count path segments (`parents[N]`) to locate data. They resolve
   through the anchored directory.
4. One logical dataset has one store. Where two implementations of the same data exist,
   reads serve the canonical store.

## Consequences

- Deployments that relied on a per-working-directory store will see their data
  "move". Since the split copy was already invisible to the application, this surfaces
  data that was effectively lost rather than losing any.
- **91 files still hardcode relative database paths and ignore `FIXOPS_DATA_DIR`
  entirely.** The anchoring does not reach them. They are correct today only because
  every supported deployment starts from the app root. This is accepted, tracked debt and
  the likeliest source of the next split store.
- New engines must adopt the standard; a lint rule is cheaper than another audit.

## Verification

Implemented and passing (`tests/test_data_dir_anchoring.py`, 5 tests):

- `FIXOPS_DATA_DIR` is absolute after importing the app, with the variable unset.
- The resolved path is identical whether the process starts at the repo root or in a
  subdirectory.
- Live: the two `parents[4]` endpoints return 200 (were 500); `/api/v1/epss/scores`
  returns 360,142 (was 0).

Outstanding: a lint rule failing any new `parents[N]`-derived or relative `*.db` path.
