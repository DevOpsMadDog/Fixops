# Chaos Experiment: Regional Edge Outage

- **Objective**: Confirm CDN + multi-region failover handles us-east-1 outage.
- **Execution**:
  1. Update CloudFront distribution to disable us-east-1 origins.
  2. Inject latency of 3s on eu-west-1 lambda@edge.
  3. Trigger contract tests + k6 soak scenario.
- **Assertions**: Error rate < 3%, TTL invalidations succeed, GraphQL TTLs updated.
- **Rollback**: Re-enable us-east-1 origin, flush caches, record metrics.
