# Chaos Experiment: Disk Full on Claims Processor

- **Objective**: Confirm log rotation and alerting when claims processor node fills disk.
- **Setup**: Claims processor runs on node pool `claims-nodes` with 100Gi volumes.
- **Execution Steps**:
  1. `kubectl exec deploy/claims-processor -- bash -c "fallocate -l 80G /tmp/fill.log"`.
  2. Increase log verbosity to DEBUG via configmap patch.
  3. Continue contract tests covering claims submission.
  4. Monitor node disk metrics `node_filesystem_avail_bytes`.
- **Assertions**:
  - Alert fires within 2 minutes.
  - Pod eviction occurs gracefully and restarts on healthy node.
  - No message loss in Kafka `claims.events` topic.
- **Rollback**:
  1. Delete filler file.
  2. Restore log level to INFO.
  3. Trigger pipeline run_id update in `artifacts/APP1/run_manifest.json`.
