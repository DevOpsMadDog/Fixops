# Persona × Hub Coverage Audit
**Date:** 2026-05-05  
**Branch:** features/intermediate-stage  
**Scope:** 30 ALDECI personas × 48 Hub pages  
**Trigger:** Founder feedback — "we don't have executive screens and screens covering personas — 48 screens should cover personas and all our APIs"

---

## Summary

| Metric | Count |
|--------|-------|
| Total personas | 30 |
| COVERED (3+ primary hubs serve the role) | 18 |
| PARTIAL (1-2 hubs, functional gaps) | 8 |
| MISSING (no hub specifically tailored) | 4 |
| Hub pages (*Hub.tsx) | 48 |
| Hub taxonomy | Functional (Discover/Protect/Respond/Comply/Intelligence/Platform) — NOT persona-centric |

**Core problem:** hubs were built around feature domains, not user jobs-to-be-done. Four personas have zero dedicated landing surfaces: Board Member, External Auditor, DPO, and Software Architect. Three others (VP Engineering, IT Director, SRE) have functional coverage but no role-filtered starting view.

---

## The 30 Personas

Sourced from `tests/test_persona_workflows.py` (ALL_PERSONAS list, verified against wave 1–4 test files).

| ID | Name (canonical) | Title | RBAC Role |
|----|-----------------|-------|-----------|
| P1 | Sarah Chen | CISO | admin |
| P2 | Marcus Johnson | VP Engineering | admin |
| P3 | Alex Rivera | SOC Analyst T1 | security_analyst |
| P4 | Priya Sharma | SOC Analyst T2 | security_analyst |
| P5 | James Wilson | Security Engineer | security_analyst |
| P6 | Emma Davis | DevSecOps Engineer | security_analyst |
| P7 | Robert Kim | Compliance Officer | viewer |
| P8 | Lisa Zhang | Penetration Tester | security_analyst |
| P9 | David Park | Risk Manager | viewer |
| P10 | Maria Lopez | IT Director | admin |
| P11 | Tom Anderson | AppSec Lead | security_analyst |
| P12 | Jennifer Wu | Cloud Security Architect | security_analyst |
| P13 | Michael Brown | Audit Manager | viewer |
| P14 | Karen Taylor | Incident Response Lead | security_analyst |
| P15 | Chris Lee | Security Data Scientist | analyst |
| P16 | Ryan Murphy | Platform Engineer | admin |
| P17 | Nina Patel | Threat Intel Analyst | security_analyst |
| P18 | Olivia Martin | GRC Analyst | viewer |
| P19 | Daniel Thompson | SecOps Manager | admin |
| P20 | Emily Chang | Developer (Security Champion) | developer |
| P21 | Richard Adams | Security Architect | security_analyst |
| P22 | Amanda Scott | Supply Chain Security | security_analyst |
| P23 | Brian Hall | QA Security Tester | security_analyst |
| P24 | Catherine Williams | Board Member | viewer |
| P25 | Mark Roberts | External Auditor | viewer |
| P26 | Security SRE | SRE | admin |
| P27 | Threat Modeler | Threat Modeler | security_analyst |
| P28 | DPO | Data Protection Officer | viewer |
| P29 | Software Architect | Software Architect | developer |
| P30 | SecOps Tech Lead | SecOps Tech Lead | security_analyst |

---

## The 48 Hubs (full list)

All `*Hub.tsx` files in `suite-ui/aldeci-ui-new/src/pages/`:

1. AICopilotAgentsHub — `/ai/agents`
2. AirGapHub — `/connect/mcp/air-gap`
3. APISecurityHub — API inventory/management/discovery
4. AppLayerSecurityHub — SAST/DAST/app-layer
5. AssetInventoryHub — asset metadata/tags/criticality
6. AutomationOrchestrationHub — automation/SOAR
7. AwarenessHub — security awareness
8. BehaviorAnalyticsHub — UEBA/behavior
9. CloudPostureUnifiedHub — CSPM/cloud posture
10. ComplianceCoverageHub — `/comply/coverage`
11. ContainerSecurityHub — image/runtime/posture
12. CryptoTrustHub — crypto/PKI/certs/quantum
13. DataDiscoveryHub — `/discover/dspm`
14. DeceptionHub — honeypots/deception
15. DetectAndRespondHub — XDR/EDR/ITDR
16. EmailThreatProtectionHub — email security
17. ExceptionsHub — `/remediate/exceptions`
18. ExternalThreatIntelHub — external CTI feeds
19. FinanceHub — Executive Brief / Finance/Investment
20. ForensicsHub — digital forensics + findings
21. HuntingHub — `/mission-control/hunt`
22. IdentityGovernanceHub — IGA/access governance
23. IncidentExtensionsHub — incident extensions
24. IncidentKnowledgeHub — incident KB/lessons
25. IntegrationTargetsHub — connector targets
26. MaturityHub — `/comply/maturity`
27. NetworkMonitoringHub — network monitoring
28. NetworkSegmentationHub — segmentation/microseg
29. OffensiveValidationHub — attack simulation/MPTE
30. PolicyAuthoringHub — policy authoring
31. PolicyLifecycleHub — policy lifecycle
32. PostureMetricsHub — `/discover/posture-metrics`
33. PrivacyComplianceHub — `/comply/privacy`
34. PrivilegedAccessHub — MFA/PAM/sessions
35. RiskQuantHub — risk quantification/scenarios
36. RulesCatalogHub — `/comply/rules`
37. SBOMProvenanceHub — SBOM/provenance
38. SecretsHub — secrets detection
39. StrategicPostureHub — posture/roadmap/GRC assessment
40. SupplyChainHub — supply chain security
41. ThreatActorsHub — threat actor intelligence
42. ThreatIntelOpsHub — threat intel operations (4-page fold)
43. ThreatModelingHub — threat modeling
44. TrainingCultureHub — training/culture
45. UpgradePathsHub — upgrade/patch paths
46. VulnIntelHub — vuln intelligence
47. VulnLifecyclePipelineHub — vuln lifecycle pipeline
48. WebhookIngestionHub — webhook ingestion

**Plus key non-Hub pages serving personas:**
- `/?view=executive` — CISO/Executive persona view (redirected from `/mission-control/ciso`)
- `/?view=soc` — SOC Analyst persona view
- `/?view=dev` — Developer/DevSecOps view
- `/grc` — GRCDashboard
- `/brs-executive` — BRSExecutiveDashboard (BU risk scores)
- `/findings` — FindingsExplorer (universal)
- `/developer` — DeveloperPortal
- `/security-champions` — SecurityChampionsDashboard

---

## Persona × Hub Coverage Matrix

**Legend:** COVERED = 3+ hubs directly serve role | PARTIAL = 1-2 hubs | MISSING = no primary hub

### COVERED (18 personas)

| Persona | Status | Primary Hubs / Views |
|---------|--------|---------------------|
| P1 CISO | COVERED | `/?view=executive`, StrategicPostureHub, RiskQuantHub, ComplianceCoverageHub, FinanceHub |
| P3 SOC Analyst T1 | COVERED | `/?view=soc`, DetectAndRespondHub, HuntingHub, BehaviorAnalyticsHub, ForensicsHub |
| P4 SOC Analyst T2 | COVERED | `/?view=soc`, DetectAndRespondHub, HuntingHub, IncidentKnowledgeHub, ThreatActorsHub |
| P5 Security Engineer | COVERED | AppLayerSecurityHub, SecretsHub, VulnLifecyclePipelineHub, VulnIntelHub, PostureMetricsHub |
| P6 DevSecOps Engineer | COVERED | `/?view=dev`, AppLayerSecurityHub, SecretsHub, SBOMProvenanceHub, APISecurityHub |
| P7 Compliance Officer | COVERED | ComplianceCoverageHub, MaturityHub, RulesCatalogHub, PrivacyComplianceHub, PolicyLifecycleHub |
| P8 Penetration Tester | COVERED | OffensiveValidationHub, HuntingHub, DeceptionHub, ExternalThreatIntelHub, ThreatActorsHub |
| P11 AppSec Lead | COVERED | AppLayerSecurityHub, APISecurityHub, SecretsHub, SBOMProvenanceHub, VulnIntelHub |
| P12 Cloud Security Architect | COVERED | CloudPostureUnifiedHub, ContainerSecurityHub, NetworkSegmentationHub, CryptoTrustHub, AssetInventoryHub |
| P14 Incident Response Lead | COVERED | DetectAndRespondHub, ForensicsHub, IncidentKnowledgeHub, IncidentExtensionsHub, HuntingHub |
| P17 Threat Intel Analyst | COVERED | ThreatIntelOpsHub, ExternalThreatIntelHub, ThreatActorsHub, BehaviorAnalyticsHub, HuntingHub |
| P18 GRC Analyst | COVERED | ComplianceCoverageHub, MaturityHub, RulesCatalogHub, PolicyAuthoringHub, StrategicPostureHub |
| P19 SecOps Manager | COVERED | `/?view=soc`, AutomationOrchestrationHub, PostureMetricsHub, BehaviorAnalyticsHub, DetectAndRespondHub |
| P21 Security Architect | COVERED | ThreatModelingHub, CloudPostureUnifiedHub, CryptoTrustHub, NetworkSegmentationHub, StrategicPostureHub |
| P22 Supply Chain Security | COVERED | SupplyChainHub, SBOMProvenanceHub, UpgradePathsHub, VulnIntelHub, ExternalThreatIntelHub |
| P27 Threat Modeler | COVERED | ThreatModelingHub, ThreatActorsHub, ExternalThreatIntelHub, OffensiveValidationHub, ThreatIntelOpsHub |
| P30 SecOps Tech Lead | COVERED | DetectAndRespondHub, AutomationOrchestrationHub, HuntingHub, BehaviorAnalyticsHub, IncidentExtensionsHub |
| P9 Risk Manager | COVERED | RiskQuantHub, StrategicPostureHub, ExceptionsHub, ComplianceCoverageHub, VulnIntelHub |

### PARTIAL (8 personas)

| Persona | Status | What Exists | What's Missing |
|---------|--------|------------|----------------|
| P2 VP Engineering | PARTIAL | `/?view=dev`, AppLayerSecurityHub | No CFO/CTO-grade metric roll-up; no engineering-velocity-vs-security view |
| P10 IT Director | PARTIAL | AssetInventoryHub, CloudPostureUnifiedHub | No IT ops command center; no infrastructure SLA/availability view |
| P13 Audit Manager | PARTIAL | ComplianceCoverageHub, MaturityHub | Read-only evidence pack view missing; no audit trail / findings-export workflow |
| P15 Security Data Scientist | PARTIAL | BehaviorAnalyticsHub, ThreatIntelOpsHub | No ML model dashboard; no custom analytics / Jupyter-style query surface |
| P16 Platform Engineer | PARTIAL | AutomationOrchestrationHub, AirGapHub | No SRE-grade health/SLO view; no infra-posture-as-code surface |
| P20 Developer / Security Champion | PARTIAL | `/?view=dev`, SecurityChampionsDashboard, DeveloperPortal | No PR-linked findings filter; no IDE-gateway entry point in UI |
| P23 QA Security Tester | PARTIAL | VulnLifecyclePipelineHub, AppLayerSecurityHub | No test-case tracking integration; no regression-test security surface |
| P26 SRE | PARTIAL | AutomationOrchestrationHub, NetworkMonitoringHub | No reliability-posture view; no chaos/FAIL surface |

### MISSING (4 personas)

| Persona | Status | Gap Description |
|---------|--------|----------------|
| P24 Board Member | MISSING | Needs board-level: top-3 risks, compliance %, MTTR, dollar exposure, peer benchmark. BRSExecutiveDashboard is partial but not a board-briefing surface. No read-only board view exists. |
| P25 External Auditor | MISSING | Needs read-only evidence bundle: control mapping, test results, finding history, SOC2/ISO27001 exports. ComplianceCoverageHub is internal; no auditor-specific scoped view. |
| P28 DPO (Data Protection Officer) | MISSING | DataDiscoveryHub and PrivacyComplianceHub exist but are not DPO-scoped. No DPIA workflow, no data subject request tracking, no cross-border transfer view. |
| P29 Software Architect | MISSING | ThreatModelingHub and ArchAwareGraphDashboard exist as separate pages but are not connected into a single architect workspace. No code-to-cloud traceability hub. |

---

## Gap Analysis: Top 5 New Hub Recommendations

Ranked by ROI (persona count served × strategic value × existing backend readiness).

### 1. ExecutiveBriefHub — Board + CISO + IT Director + VP Eng
**Route:** `/?view=executive` (expand existing view into a full Hub)  
**Personas served:** P1 CISO, P2 VP Eng, P10 IT Director, P24 Board Member (MISSING)  
**What exists already:**
- `BRSExecutiveDashboard` (BU-level BRS scores) — `/brs-executive`
- `StrategicPostureHub` (posture/roadmap)
- `RiskQuantHub` (dollar exposure, risk scenarios)
- `FinanceHub` (finance/investment brief)
- `/api/v1/risk/brs/bu/*`, `/api/v1/analytics/dashboard/overview`, `/api/v1/risks/*`

**UI work needed:** Compose as a 4-tab Hub: Overview (top risks + MTTR + compliance %), Risk (RiskQuant embed), Finance (FinanceHub embed), Board Pack (PDF export). Add `?audience=board` query param for read-only no-actions mode.  
**ROI:** HIGH — closes P24 MISSING gap; upgrades P1/P2/P10 from PARTIAL/COVERED to exceptional; directly answers founder feedback.

---

### 2. AuditorEvidenceHub — External Auditor + Audit Manager
**Route:** `/comply/auditor`  
**Personas served:** P25 External Auditor (MISSING), P13 Audit Manager (PARTIAL)  
**What exists already:**
- `/comply/coverage` (ComplianceCoverageHub)
- `/comply/maturity` (MaturityHub)
- `/comply/soc2`, `/comply/slsa`, `/comply/export`
- `/api/v1/compliance/*`, `/api/v1/evidence/*`, `/api/v1/audit/*`

**UI work needed:** Read-only scoped Hub wrapping ComplianceCoverage + EvidenceExport + AuditTrail. Key addition: time-boxed evidence snapshot (audit period selector), control-by-control status table, finding-history timeline. RBAC: viewer-only, no write actions rendered.  
**ROI:** HIGH — closes P25 MISSING; directly enables external auditor customer persona (compliance buyer).

---

### 3. DeveloperSecurityHub — Developer + AppSec Lead + QA Tester
**Route:** `/dev-security` (expand existing `/developer` DeveloperPortal)  
**Personas served:** P20 Developer/Champion (PARTIAL → COVERED), P11 AppSec Lead (+tab), P23 QA Tester (PARTIAL → COVERED)  
**What exists already:**
- `DeveloperPortal` page at `/developer`
- `SecurityChampionsDashboard` at `/security-champions`
- `AppLayerSecurityHub`, `SecretsHub`, `VulnLifecyclePipelineHub`
- `/api/v1/findings` (filter by PR/repo), `/api/v1/code-scanning/*`

**UI work needed:** Add PR-linked findings tab (filter by `repo` + `pr_number`), IDE-gateway status widget, champion leaderboard. Consolidate DeveloperPortal + SecurityChampionsDashboard into unified Hub with tabs: My Findings | PR Gate | Champion Score | AppSec Pipeline.  
**ROI:** HIGH — developer persona is the highest-volume user in SaaS security tools (Snyk's core buyer).

---

### 4. DPOPrivacyHub — Data Protection Officer
**Route:** `/comply/dpo` (extend DataDiscoveryHub + PrivacyComplianceHub)  
**Personas served:** P28 DPO (MISSING)  
**What exists already:**
- `DataDiscoveryHub` at `/discover/dspm` (PII field inventory, data flows)
- `PrivacyComplianceHub` at `/comply/privacy`
- `PIIFieldInventory` at `/discover/pii-inventory`
- `/api/v1/data-discovery/*`, `/api/v1/compliance/privacy/*`

**UI work needed:** DPO-scoped Hub with 4 tabs: Data Map (where PII lives), DPIA Tracker (risk assessments per processing activity), DSR Queue (data subject requests), Cross-Border Transfers (data residency view). Most data sources exist; DPIA + DSR are new lightweight CRUD surfaces.  
**ROI:** MEDIUM-HIGH — GDPR/CCPA compliance is mandatory for EU enterprise buyers; DPO persona unlocks regulatory market.

---

### 5. ArchitectWorkspaceHub — Software Architect + Security Architect
**Route:** `/discover/architect`  
**Personas served:** P29 Software Architect (MISSING), P21 Security Architect (+primary view)  
**What exists already:**
- `ThreatModelingHub` at `/threat-modeling`
- `ArchAwareGraphDashboard` at `/arch-aware-graph`
- `CodeToRuntimeDashboard`, `CallGraphExplorer`, `CodeSemanticExplorer`
- `APISecurityHub`, `NetworkSegmentationHub`
- `/api/v1/threat-models/*`, `/api/v1/code-to-cloud/*`

**UI work needed:** Hub that consolidates architecture-centric views: Code-to-Cloud Trace (tab 1), Threat Model Canvas (tab 2, embed ThreatModelingHub), API Dependency Map (tab 3), Risk Hotspots (tab 4). Links existing pages into a workflow rather than rebuilding.  
**ROI:** MEDIUM — software architect persona is a key champion in enterprise sales (Apiiro's target buyer).

---

## Existing Hub Utilization by Persona Group

| Group | Personas | Hub Coverage Score |
|-------|----------|-------------------|
| SOC / Detection | P3, P4, P14, P19, P30 | 5/5 COVERED |
| Threat Intel / Hunting | P17, P27, P8 | 3/3 COVERED |
| AppSec / DevSecOps | P6, P11, P20, P23 | 2 COVERED / 2 PARTIAL |
| Cloud / Infra | P12, P16, P26 | 1 COVERED / 2 PARTIAL |
| Compliance / GRC | P7, P18, P9, P13 | 3 COVERED / 1 PARTIAL |
| Executive / Management | P1, P2, P10, P24 | 1 COVERED / 2 PARTIAL / 1 MISSING |
| Risk | P9, P21 | 2 COVERED |
| Audit / External | P13, P25 | 1 PARTIAL / 1 MISSING |
| Privacy / Data | P28 | 1 MISSING |
| Architecture | P29 | 1 MISSING |
| Developer | P20 | 1 PARTIAL |

---

## Implementation Priority

| Priority | Hub | Multica Story | Sprint Estimate |
|----------|-----|---------------|-----------------|
| P0 | ExecutiveBriefHub (expand `/?view=executive`) | New US — board pack mode + 4-tab compose | 1 day |
| P0 | AuditorEvidenceHub (`/comply/auditor`) | New US — read-only evidence bundle | 1 day |
| P1 | DeveloperSecurityHub (expand `/developer`) | New US — PR findings tab + champion merge | 1.5 days |
| P1 | DPOPrivacyHub (`/comply/dpo`) | New US — DPIA/DSR tabs over existing data | 2 days |
| P2 | ArchitectWorkspaceHub (`/discover/architect`) | New US — hub composing existing pages | 1 day |

All 5 recommendations compose existing hubs/pages — no net-new backend work required beyond minor endpoint additions (DPIA CRUD, DSR queue).

---

## Files Referenced

- `tests/test_persona_workflows.py` — canonical 30-persona list + RBAC roles
- `tests/test_persona_workflows_wave2.py` — wave 2 coverage notes
- `suite-ui/aldeci-ui-new/src/App.tsx` — all 571 route entries
- `suite-ui/aldeci-ui-new/src/pages/*Hub.tsx` — 48 hub pages
- `.claude/agent-memory/qa-engineer/persona_coverage_2026-04-27.md`
- `.claude/agent-memory/qa-engineer/persona_coverage_wave2_2026-04-27.md`
