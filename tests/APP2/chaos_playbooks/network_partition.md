# Chaos Experiment: Partner API Network Partition

- **Objective**: Validate backoff and circuit breaker when upstream partner API is unreachable.
- **Execution**:
  1. Configure Kong route fault injection to return 503 for partner `PART-202`.
  2. Run contract tests for fallback data and k6 ramping scenario.
  3. Capture metrics from Hystrix dashboard.
- **Assertions**: Circuit breaker opens after 5 failures, fallback cache serves 90% requests, retry jitter < 2s.
- **Rollback**: Remove fault injection, warm fallback caches, record metrics.
