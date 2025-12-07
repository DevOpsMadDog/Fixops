# Chaos Experiment: SQS Queue Throttle

- **Objective**: Ensure webhook ingestion continues when SQS throttles receive calls.
- **Execution**:
  1. Apply AWS Fault Injection Simulator scenario to reduce ReceiveMessage quota by 70%.
  2. Replay 10k webhook events via `tests/APP2/partner_simulators/valid_signature.py`.
  3. Monitor queue depth and DLQ metrics.
- **Assertions**: DLQ remains empty, processing delay < 2 minutes.
- **Rollback**: Stop FIS experiment, purge DLQ, rerun smoke tests.
