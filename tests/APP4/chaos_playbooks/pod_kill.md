# Chaos Experiment: Checkout API Pod Kill

- **Objective**: Validate autoscaling and token replay resilience when 50% of pods are killed.
- **Execution**:
  1. `kubectl delete pod -l app=checkout -n retail --limit=4 --force --grace-period=0`.
  2. Run `tests/APP4/perf_k6.js` spike stage.
  3. Observe request success rate in Prometheus.
- **Assertions**: Success > 99%, p95 < 420ms.
- **Rollback**: Scale to baseline, rerun smoke tests.
