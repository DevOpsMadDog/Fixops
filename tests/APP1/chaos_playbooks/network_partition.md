# Chaos Experiment: API to DB Network Partition

- **Objective**: Validate retry logic and circuit breaker when pricing API loses connectivity to Postgres.
- **Setup**: Pricing API deployed on EKS with Istio sidecar.
- **Execution Steps**:
  1. Apply Istio fault injection: `kubectl apply -f manifests/istio/pricing-db-partition.yaml` (delay 5s, abort 50%).
  2. Run `tests/APP1/perf_k6.js` spike scenario.
  3. Observe circuit breaker metrics `envoy_cluster_upstream_rq_pending_overflow`.
  4. After 3 minutes, increase abort to 100% for 60s.
- **Assertions**:
  - Circuit breaker opens within 10s of 100% failure.
  - Retries limited to 2 attempts.
  - Customer receives 503 with retry-after header.
- **Rollback**:
  1. Delete fault injection manifest.
  2. Run `cli-tests/APP1/cli_smoke.sh`.
  3. Capture metrics snapshot to `artifacts/APP1/chaos_report.json`.
