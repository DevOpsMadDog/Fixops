# Chaos Experiment: MSK Broker Failure

- **Objective**: Ensure event-stream processing handles broker outage.
- **Execution**:
  1. Stop broker `b-1` using `aws kafka reboot-broker`.
  2. Produce 30k checkout events using load generator.
  3. Track consumer lag and settlement job success.
- **Assertions**: Lag < 180, settlement job completes, DLQ empty.
- **Rollback**: Restart broker, verify ISR membership, rerun smoke tests.
