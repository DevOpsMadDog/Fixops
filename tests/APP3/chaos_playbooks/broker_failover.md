# Chaos Experiment: Kafka Broker Outage

- **Objective**: Ensure HL7 event processing tolerates broker failure.
- **Execution**:
  1. Stop broker `kafka-1` via `systemctl stop kafka` on VM.
  2. Produce 20k HL7 events using simulator.
  3. Monitor consumer lag and audit ledger entries.
- **Assertions**: Lag < 150, no dropped audit records, DLQ empty.
- **Rollback**: Start broker, rebalance partitions, rerun smoke tests.
