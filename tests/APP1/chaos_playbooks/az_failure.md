# Chaos Experiment: Availability Zone Failure

- **Objective**: Verify multi-AZ resilience for customer DB and pricing API when one AWS AZ is unavailable.
- **Setup**: Ensure RDS Multi-AZ enabled and EKS nodegroups in `us-east-1a` and `us-east-1b`.
- **Execution Steps**:
  1. Drain nodes in `us-east-1a`: `kubectl drain --ignore-daemonsets --delete-emptydir-data $(kubectl get nodes -l topology.kubernetes.io/zone=us-east-1a -o name)`.
  2. Disable AZ in load balancer: `aws elbv2 set-subnets --load-balancer-arn $LB --subnets subnet-1b subnet-1c`.
  3. Trigger `tests/APP1/perf_k6.js` spike scenario.
  4. Monitor RDS failover status via CloudWatch metric `AuroraGlobalDBFailover`.
- **Assertions**:
  - API error rate remains < 2%.
  - Replicas rescheduled to remaining AZ within 4 minutes.
  - Customer DB failover completes < 120s.
- **Rollback**:
  1. Re-enable `us-east-1a` subnets on load balancer.
  2. Uncordon nodes.
  3. Run smoke tests from `cli-tests/APP1/cli_smoke.sh`.
  4. Update `artifacts/APP1/chaos_report.json` with metrics.
