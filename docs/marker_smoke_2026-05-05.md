# pytest Marker Smoke — 2026-05-05

14 markers declared in `pyproject.toml`. Results from `--collect-only -q` against 44,976 total tests.

| Marker | Collected | Expected | Status |
|---|---|---|---|
| `perf` | 194 | 182-194 | PASS |
| `owasp` | 47 | 47 | PASS |
| `asyncio` | 496 | non-zero | PASS |
| `integration` | 87 | non-zero | PASS |
| `slow` | 18 | non-zero | PASS |
| `benchmark` | 3 | 3 | PASS |
| `security` | 1 | non-zero | WARN (low) |
| `requires_network` | 1 | non-zero | WARN (low) |
| `e2e` | 0 | non-zero | GAP |
| `unit` | 0 | non-zero | GAP |
| `regression` | 0 | non-zero | GAP |
| `performance` | 0 | non-zero | GAP (alias: use `perf`) |
| `requires_docker` | 0 | — | EXPECTED (env gate) |
| `requires_k8s` | 0 | — | EXPECTED (env gate) |

**Notes:** `perf` (194) and `owasp` (47) match targets exactly. `asyncio` (496) is the largest pool.
`unit`/`regression`/`e2e`/`performance` are empty — tests use `perf` alias, not `performance`; `unit`/`regression`/`e2e` labels are not yet applied to test functions. `requires_docker` and `requires_k8s` zero is correct — CI gates those.
