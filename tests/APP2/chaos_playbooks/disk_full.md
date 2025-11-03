# Chaos Experiment: Edge Cache Disk Saturation

- **Objective**: Ensure CDN edge nodes evict old cache items gracefully when disk fills.
- **Execution**:
  1. Configure synthetic workload to request 50GB of unique assets.
  2. Monitor edge cache fill metrics via CloudFront.
  3. Validate fallback to origin with 304 responses.
- **Assertions**: Origin hit rate < 25%, error rate < 1%.
- **Rollback**: Purge synthetic assets, reset cache behaviors, rerun smoke tests.
