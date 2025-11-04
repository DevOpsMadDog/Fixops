# Chaos Experiment: Pricing Service Pod Kill

- **Objective**: Validate autoscaler and circuit breaker resilience when 50% of pricing pods are terminated.
- **Setup**: Ensure pricing deployment has 6 replicas and steady load from `tests/APP1/perf_k6.js` baseline scenario.
- **Execution Steps**:
  1. `kubectl scale deploy/pricing --replicas=6 -n insurance-prod`
  2. `kubectl delete pod -l app=pricing -n insurance-prod --wait=false --field-selector=status.phase=Running --limit=3`
  3. Continue k6 spike scenario for 5 minutes.
  4. Monitor error rates via Prometheus query `rate(http_requests_total{app="pricing",status=~"5.."}[1m])`.
- **Assertions**:
  - p95 latency < 550ms.
  - Error rate < 1%.
  - Autoscaler restores replicas within 2 minutes.
- **Rollback**:
  1. `kubectl scale deploy/pricing --replicas=6 -n insurance-prod`
  2. Verify new pods are Ready.
  3. Archive logs to `artifacts/APP1/chaos_report.json`.
