# Chaos Experiment: AWS AZ Outage (us-east-1a)

- **Objective**: Confirm MSK + EKS multi-AZ resilience when one AZ fails.
- **Execution**:
  1. Disable subnets in `us-east-1a` for ALB and MSK broker.
  2. Drain nodes in affected AZ.
  3. Run performance suite and settlement smoke tests.
- **Assertions**: Error rate < 2%, Kafka lag < 200.
- **Rollback**: Re-enable subnets, uncordon nodes, verify replication.
