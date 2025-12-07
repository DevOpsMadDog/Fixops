# Chaos Experiment: Kafka Broker Failover

- **Objective**: Ensure billing event processing continues when the primary Kafka broker fails.
- **Setup**: Billing microservice uses Kafka topic `billing.events` with 3 brokers and replication factor 3.
- **Execution Steps**:
  1. Start contract replay from `tests/APP1/contract_tests/openapi.yaml` using `new-billing` scenario.
  2. Stop broker `kafka-0`: `kubectl exec -n data kafka-0 -- bash -c "kafka-server-stop.sh"`.
  3. Observe partition leadership transitions via `kafka-topics.sh --describe`.
  4. Inject 5,000 billing events using `scripts/billing_load.sh`.
- **Assertions**:
  - Consumer lag < 100 messages.
  - No duplicate billing records written to Postgres.
  - Circuit breaker does not open.
- **Rollback**:
  1. Start broker: `kubectl exec -n data kafka-0 -- bash -c "kafka-server-start.sh /opt/kafka/config/server.properties"`.
  2. Verify cluster health via `kafka-broker-api-versions.sh`.
  3. Update `chaos_report.json` with lag metrics.
