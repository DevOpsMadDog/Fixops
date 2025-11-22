# Chaos Experiment: FHIR Gateway Pod Kill

- **Objective**: Confirm Azure AKS autoscaler and retry logic when 60% of pods terminate.
- **Execution**:
  1. `kubectl delete pod -l app=fhir-gateway -n app3 --force --grace-period=0 --limit=3`.
  2. Run `tests/APP3/perf_k6.js` surge scenario.
  3. Monitor Azure Monitor metrics for HTTP 5xx.
- **Assertions**: Error rate < 1.5%, pods restored within 90s.
- **Rollback**: Scale deployment to baseline, run smoke tests.
