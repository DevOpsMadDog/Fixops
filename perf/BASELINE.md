# Performance Baseline

## Scenario
- **Workload:** Pipeline crosswalk with 40 design components, 100 SARIF findings, and 60 CVE records.
- **Command:** Inline harness running 30 iterations of `PipelineOrchestrator.run` with the probabilistic module disabled to capture the legacy baseline (see benchmark helper in `perf/BENCHMARKS.csv`).
- **Environment:** Python 3.11 container, single worker process, no optional parsers installed.

## Baseline Metrics (Pre-probabilistic module)
- **Runtime:** ≈3.4057ms per run (average across 30 iterations).【8242a6†L1-L64】
- **Peak Memory:** 155.01KB traced via `tracemalloc` (unchanged from earlier baseline).

This measurement captures the optimised crosswalk/token logic prior to enabling the probabilistic forecast engine so we can quantify its incremental overhead separately.
