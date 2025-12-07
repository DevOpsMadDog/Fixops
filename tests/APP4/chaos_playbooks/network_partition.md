# Chaos Experiment: Edge Gateway Network Partition

- **Objective**: Validate backpressure when edge gateways lose connectivity to cloud API.
- **Execution**:
  1. Block outbound traffic from edge gateway security group to checkout API.
  2. Simulate device transactions from 200 stores.
  3. Observe offline queue metrics and retry policies.
- **Assertions**: Offline queue drains within 5 minutes after restoration, no duplicate transactions.
- **Rollback**: Remove network block, replay queued events, compare settlement totals.
