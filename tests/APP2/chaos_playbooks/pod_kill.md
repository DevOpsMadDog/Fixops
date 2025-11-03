# Chaos Experiment: Gateway Pod Kill

- **Objective**: Validate Kong gateway resilience when losing 50% pods.
- **Execution**:
  1. `kubectl delete pod -l app=kong -n partnerhub --force --grace-period=0 --limit=2`
  2. Run `tests/APP2/perf_k6.js` spike stage.
  3. Monitor ingress success rate in Datadog.
- **Assertions**: Success rate > 98%, latency p95 < 420ms.
- **Rollback**: Helm rollback to last revision, rerun smoke tests.
