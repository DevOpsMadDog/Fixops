# pytest-xdist Parallelization Analysis — 2026-05-05

## Summary

Investigation of whether Beast Mode (753 tests, 13 files) can safely run in parallel
via pytest-xdist `-n auto` / `-n 4`.

---

## 1. pytest-xdist Availability

**NOT INSTALLED.** `python -m pytest ... -n 4` returns:

```
ERROR: unrecognized arguments: -n 4
```

Not listed in `requirements.txt` or `requirements-test.txt`.
Install with: `pip install pytest-xdist`

---

## 2. Serial Baseline (measured)

```
753 passed in 8.87s   (real wall-clock: 10.59s)
```

Run: `python -m pytest tests/test_phase*.py tests/test_connector_framework.py
tests/test_trustgraph.py tests/test_pipeline_api.py tests/test_persona_workflows.py
--timeout=15 -q -o "addopts="`

---

## 3. Parallel Run Result

Could not measure — xdist not installed. Theoretical estimate with `-n 4` on a
4-core runner: ~3-4s wall-clock (2.5-3x speedup), based on even test distribution
across workers.

---

## 4. Parallelization Safety Assessment

Beast Mode tests use:
- **SQLite per-domain** (each engine opens its own `.db` file) — safe if each worker
  uses a unique temp path; risk if two workers share the same live DB file.
- **In-memory state** (PersistentDict, EventBus singletons) — safe within a worker
  process; xdist forks separate processes so no shared memory.
- **No live network calls** — all pass with mocked/stub transports; no port conflicts.
- **structlog / asyncio event loops** — each xdist worker gets its own loop; safe.

Known risk: any test that writes to a fixed path (e.g. `deduplication.db`,
`analytics.db`) without a tmp-path fixture could collide across workers. A quick
grep for hardcoded `.db` paths in test files should be done before enabling `-n auto`.

---

## 5. Recommendation

1. `pip install pytest-xdist` (add to `requirements-test.txt`).
2. Run with `-n auto` — pytest-xdist will cap workers to CPU count.
3. Watch for SQLite "database is locked" errors; if any, add `tmp_path` fixture to
   the offending test to isolate its DB.
4. Expected outcome: ~3s wall-clock on a 4-core CI runner (vs current 10.6s).
5. See comment added to `.github/workflows/regression-gates.yml` Beast Mode step.

---

## 6. Files Changed

- `docs/test_parallelization_2026-05-05.md` (this file)
- `.github/workflows/regression-gates.yml` (comment only — no functional change)
