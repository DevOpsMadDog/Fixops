# Chaos Experiment: FHIR Gateway to EMR Partition

- **Objective**: Validate circuit breaker when FHIR gateway loses connectivity to upstream EMR.
- **Execution**:
  1. Apply Istio `fault` resource blocking egress to EMR host.
  2. Run contract tests for patient search and appointment listing.
  3. Capture breaker metrics (`openEvents`).
- **Assertions**: Breaker opens within 15s, fallback cache serves read-only data, 503 includes retry-after.
- **Rollback**: Remove fault resource, warm caches, rerun smoke tests.
