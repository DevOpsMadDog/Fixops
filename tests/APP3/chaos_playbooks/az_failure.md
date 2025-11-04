# Chaos Experiment: Azure Region Outage

- **Objective**: Validate geo-redundant failover for AKS + CosmosDB when `eastus` region is offline.
- **Execution**:
  1. Disable traffic manager endpoint for `eastus`.
  2. Force CosmosDB failover to `westus`.
  3. Run contract and performance suites.
- **Assertions**: Failover < 120s, data consistency maintained, error rate < 2%.
- **Rollback**: Restore traffic manager, re-enable eastus, run audit ledger smoke tests.
