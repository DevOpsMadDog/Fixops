# Performance Baseline

## Scenario
- **Workload:** Pipeline crosswalk with 40 design components, 100 SARIF findings, and 60 CVE records.
- **Command:** Inline `timeit` harness running 50 iterations of `PipelineOrchestrator.run` (see benchmark helper in `perf/BENCHMARKS.csv`).
- **Environment:** Python 3.11 container, single worker process, no optional parsers installed.

## Baseline Metrics (Pre-optimisation)
- **Runtime:** 0.3418s for 50 iterations (≈6.84ms per run).【fc83db†L1-L1】
- **Peak Memory:** 155.01KB traced via `tracemalloc`.【6bffa3†L1-L1】

These measurements highlighted repeated attribute lookups and redundant conversions in the crosswalk matching logic, as well as repeated SBOM metadata extraction in the normaliser.
