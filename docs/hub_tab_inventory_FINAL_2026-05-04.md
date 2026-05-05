# Hub Tab Inventory — FINAL (2026-05-05)

Branch: `features/intermediate-stage`
Audit method: static analysis of `<TabsContent value="...">` slots and dynamic-map `TABS` arrays.
Shell = empty `<Suspense>` wrapper (no panel component inside).

## Summary

| Metric | Count |
|--------|-------|
| Total hubs | 48 |
| Total tabs | 168 |
| WIRED | 166 |
| SHELL | 2 |
| Completion | **98.8%** |
| DONE (100%) | 46 |
| PARTIAL | 2 |
| NOT_STARTED | 0 |

## Per-Hub Table (sorted by SHELL desc)

| Hub File | Total | WIRED | SHELL | Status |
|----------|-------|-------|-------|--------|
| DeceptionHub.tsx | 3 | 2 | 1 | PARTIAL |
| ForensicsHub.tsx | 3 | 2 | 1 | PARTIAL |
| AICopilotAgentsHub.tsx | 3 | 3 | 0 | DONE |
| APISecurityHub.tsx | 3 | 3 | 0 | DONE |
| AirGapHub.tsx | 3 | 3 | 0 | DONE |
| AppLayerSecurityHub.tsx | 3 | 3 | 0 | DONE |
| AssetInventoryHub.tsx | 8 | 8 | 0 | DONE |
| AutomationOrchestrationHub.tsx | 3 | 3 | 0 | DONE |
| AwarenessHub.tsx | 4 | 4 | 0 | DONE |
| BehaviorAnalyticsHub.tsx | 3 | 3 | 0 | DONE |
| CloudPostureUnifiedHub.tsx | 4 | 4 | 0 | DONE |
| ComplianceCoverageHub.tsx | 3 | 3 | 0 | DONE |
| ContainerSecurityHub.tsx | 3 | 3 | 0 | DONE |
| CryptoTrustHub.tsx | 5 | 5 | 0 | DONE |
| DataDiscoveryHub.tsx | 3 | 3 | 0 | DONE |
| DetectAndRespondHub.tsx | 3 | 3 | 0 | DONE |
| EmailThreatProtectionHub.tsx | 3 | 3 | 0 | DONE |
| ExceptionsHub.tsx | 3 | 3 | 0 | DONE |
| ExternalThreatIntelHub.tsx | 3 | 3 | 0 | DONE |
| FinanceHub.tsx | 5 | 5 | 0 | DONE |
| HuntingHub.tsx | 3 | 3 | 0 | DONE |
| IdentityGovernanceHub.tsx | 4 | 4 | 0 | DONE |
| IncidentExtensionsHub.tsx | 3 | 3 | 0 | DONE |
| IncidentKnowledgeHub.tsx | 3 | 3 | 0 | DONE |
| IntegrationTargetsHub.tsx | 3 | 3 | 0 | DONE |
| MaturityHub.tsx | 3 | 3 | 0 | DONE |
| NetworkMonitoringHub.tsx | 3 | 3 | 0 | DONE |
| NetworkSegmentationHub.tsx | 3 | 3 | 0 | DONE |
| OffensiveValidationHub.tsx | 3 | 3 | 0 | DONE |
| PolicyAuthoringHub.tsx | 3 | 3 | 0 | DONE |
| PolicyLifecycleHub.tsx | 3 | 3 | 0 | DONE |
| PostureMetricsHub.tsx | 3 | 3 | 0 | DONE |
| PrivacyComplianceHub.tsx | 3 | 3 | 0 | DONE |
| PrivilegedAccessHub.tsx | 3 | 3 | 0 | DONE |
| RiskQuantHub.tsx | 3 | 3 | 0 | DONE |
| RulesCatalogHub.tsx | 4 | 4 | 0 | DONE |
| SBOMProvenanceHub.tsx | 6 | 6 | 0 | DONE |
| SecretsHub.tsx | 3 | 3 | 0 | DONE |
| StrategicPostureHub.tsx | 3 | 3 | 0 | DONE |
| SupplyChainHub.tsx | 3 | 3 | 0 | DONE |
| ThreatActorsHub.tsx | 5 | 5 | 0 | DONE |
| ThreatIntelOpsHub.tsx | 4 | 4 | 0 | DONE |
| ThreatModelingHub.tsx | 3 | 3 | 0 | DONE |
| TrainingCultureHub.tsx | 3 | 3 | 0 | DONE |
| UpgradePathsHub.tsx | 6 | 6 | 0 | DONE |
| VulnIntelHub.tsx | 4 | 4 | 0 | DONE |
| VulnLifecyclePipelineHub.tsx | 4 | 4 | 0 | DONE |
| WebhookIngestionHub.tsx | 3 | 3 | 0 | DONE |

## Remaining Shell Tabs

| Hub | Shell Tab | Fix Required |
|-----|-----------|-------------|
| DeceptionHub.tsx | `decoys` | Wire a DecoysPanel component inside `<Suspense>` |
| ForensicsHub.tsx | `digital` | Wire a DigitalForensicsPanel component inside `<Suspense>` |
