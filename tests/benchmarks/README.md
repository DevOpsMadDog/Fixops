# ALDECI Performance Lockdown Benchmarks

Three performance wins from session 2026-05-04 are locked in as hard CI assertions.

## How to run

```bash
# Benchmark suite only (fast, ~5s)
python -m pytest tests/benchmarks/ -m benchmark -x --tb=short --timeout=15 -q -o "addopts="

# Benchmark + phase4 regression gate
python -m pytest tests/test_phase4_integration.py tests/benchmarks/ -x --tb=short --timeout=15 -q -o "addopts="
```

## Thresholds

| Benchmark | Commit | Before | After | Threshold |
|---|---|---|---|---|
| RSA singleton p95 (calls 2-100) | 1276b4df | ~2 111 ms | <50 ms | **< 5 ms** |
| risk_scorer predict_batch(100) | 4bbd12ad | ~527 ms | <50 ms | **< 100 ms** |
| brain_pipeline warm feed reload | ee340f83 | ~2 000 ms | <1 ms | **< 10 ms** |

## Notes

- `pytest_benchmark` is NOT required — plain `time.perf_counter` is used.
- RSA threshold covers the singleton (warm) path only; the cold key-load call is excluded.
- risk_scorer uses the deterministic fallback path (no trained model file needed).
- brain_pipeline threshold covers the TTL-cache hit path within the 5-minute window.
