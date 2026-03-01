# Swarm Task swarm-119 — UI Component Inventory

## Summary
Inventory of legacy React UI components in `suite-ui/aldeci/`.

## Counts
- **TSX Files**: 81
- **TS Files**: 5
- **Total Files**: 86
- **Total LOC**: 30,581
- **Pages**: 59
- **Components**: 19

## Page List (59 pages)
```
src/pages/ai-engine/AlgorithmicLab.tsx
src/pages/ai-engine/MLDashboard.tsx
src/pages/ai-engine/MultiLLMPage.tsx
src/pages/ai-engine/Policies.tsx
src/pages/ai-engine/Predictions.tsx
src/pages/attack/AttackPaths.tsx
src/pages/attack/AttackSimulation.tsx
src/pages/attack/MicroPentest.tsx
src/pages/attack/MPTEConsole.tsx
src/pages/attack/Reachability.tsx
src/pages/AttackLab.tsx
src/pages/CEODashboard.tsx
src/pages/cloud/CloudPosture.tsx
src/pages/cloud/ContainerSecurity.tsx
src/pages/cloud/CorrelationEngine.tsx
src/pages/cloud/RuntimeProtection.tsx
src/pages/cloud/ThreatFeeds.tsx
src/pages/code/CodeScanning.tsx
src/pages/code/IaCScanning.tsx
src/pages/code/Inventory.tsx
src/pages/code/SBOMGeneration.tsx
src/pages/code/SecretsDetection.tsx
src/pages/Copilot.tsx
src/pages/core/BrainPipelineDashboard.tsx
src/pages/core/ExposureCaseCenter.tsx
src/pages/core/KnowledgeGraphExplorer.tsx
src/pages/Dashboard.tsx
src/pages/DataFabric.tsx
src/pages/DecisionEngine.tsx
src/pages/discover/ScannerDashboard.tsx
src/pages/evidence/AuditLogs.tsx
src/pages/evidence/ComplianceReports.tsx
src/pages/evidence/EvidenceAnalytics.tsx
src/pages/evidence/EvidenceBundles.tsx
src/pages/evidence/Reports.tsx
src/pages/evidence/SLSAProvenance.tsx
src/pages/evidence/SOC2EvidenceUI.tsx
src/pages/EvidenceVault.tsx
src/pages/feeds/LiveFeedDashboard.tsx
src/pages/IntelligenceHub.tsx
src/pages/NerveCenter.tsx
src/pages/protect/AutoFixDashboard.tsx
src/pages/protect/BulkOperations.tsx
src/pages/protect/Collaboration.tsx
src/pages/protect/Integrations.tsx
src/pages/protect/PlaybookEditor.tsx
src/pages/protect/Playbooks.tsx
src/pages/protect/Remediation.tsx
src/pages/protect/Workflows.tsx
src/pages/RemediationCenter.tsx
src/pages/Settings.tsx
src/pages/settings/IntegrationsSettings.tsx
src/pages/settings/LogViewer.tsx
src/pages/settings/Marketplace.tsx
src/pages/settings/OverlayConfig.tsx
src/pages/settings/SystemHealth.tsx
src/pages/settings/Teams.tsx
src/pages/settings/Users.tsx
src/pages/settings/Webhooks.tsx
```

## Domain Breakdown
- **AI Engine**: 5 pages (AlgorithmicLab, MLDashboard, MultiLLMPage, Policies, Predictions)
- **Attack Lab**: 5 pages (AttackPaths, AttackSimulation, MicroPentest, MPTEConsole, Reachability)
- **Cloud Security**: 5 pages (CloudPosture, ContainerSecurity, CorrelationEngine, RuntimeProtection, ThreatFeeds)
- **Code Scanning**: 5 pages (CodeScanning, IaCScanning, Inventory, SBOMGeneration, SecretsDetection)
- **Evidence/Compliance**: 7 pages (AuditLogs, ComplianceReports, EvidenceAnalytics, EvidenceBundles, Reports, SLSAProvenance, SOC2EvidenceUI)
- **Protection/Remediation**: 8 pages (AutoFixDashboard, BulkOperations, Collaboration, Integrations, PlaybookEditor, Playbooks, Remediation, Workflows)
- **Settings**: 8 pages (IntegrationsSettings, LogViewer, Marketplace, OverlayConfig, SystemHealth, Teams, Users, Webhooks)
- **Core/Main**: 11 pages (Dashboard, DataFabric, DecisionEngine, AttackLab, Copilot, EvidenceVault, IntelligenceHub, NerveCenter, RemediationCenter, Settings, CEODashboard, BrainPipelineDashboard, ExposureCaseCenter, KnowledgeGraphExplorer, ScannerDashboard, LiveFeedDashboard)

## Notes
- **Legacy UI Status**: FROZEN — DO NOT MODIFY per CLAUDE.md
- **TypeScript Version**: Vendored; all types pass (`npx tsc --noEmit` returns 0 errors)
- **Build**: Vite, completes in ~1.6s with 534.56 kB main bundle
- **Architecture**: Monolithic React SPA with 19 reusable components supporting 59 domain pages
- **Code Volume**: 30,581 LOC across 81 TSX + 5 TS files
