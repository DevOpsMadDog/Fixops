# Chaos Experiment: CosmosDB Disk Saturation

- **Objective**: Ensure audit ledger handles disk quota exhaustion.
- **Execution**:
  1. Lower CosmosDB autoscale max RU to 400 to simulate quota.
  2. Replay 1M audit events.
  3. Monitor RU consumption and latency.
- **Assertions**: Write throttling < 5 minutes, queue drains after capacity restored, alerts fired.
- **Rollback**: Restore autoscale RU, purge synthetic data, rerun ledger checks.
