# Chaos Experiment: Settlement Volume Disk Full

- **Objective**: Ensure settlement batch gracefully handles disk exhaustion on worker node.
- **Execution**:
  1. Fill worker node disk to 95% using stress tool.
  2. Trigger settlement batch.
  3. Monitor job metrics and log scrubbing.
- **Assertions**: Job retries with exponential backoff, disk cleanup triggered, audit logs remain masked.
- **Rollback**: Remove filler files, rerun settlement, archive logs.
