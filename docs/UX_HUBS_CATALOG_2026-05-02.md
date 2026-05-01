# ALDECI Hub Catalog — Phase 3 Consolidation Result (2026-05-02)

> **Status:** 33 hubs landed on branch `features/intermediate-stage`. 134 source pages folded into hubs (each carries `// FOLDED` redirect-stub headers preserving git history). Plan input: `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` (target: 30 cohesive screens, 8 nav items). Real-API verified per the **NO MOCKS** rule in `CLAUDE.md`.
>
> **Why this doc exists:** future agents (frontend, ux-architect, marketing, sales-eng) need a single index of "where did page X go?" — without re-reading 470 routes in `App.tsx` or the 800-line consolidation plan. This catalog is the lookup table.
>
> **How to read it:** §1 = at-a-glance table. §2 = per-hub deep dive (purpose, source pages, real APIs, persona path). §3 = "how to add a new hub" recipe (verified pattern from the 33 already-shipped hubs). §4 = clusters in the plan that have NOT yet been folded.

---

## 1. Summary Table — 33 Hubs Landed

| # | Hub | Canonical Route | Folded Pages | Tabs | Plan Cluster | Personas |
|---|---|---|---|---|---|---|
| 1 | FinanceHub | `/mission-control/finance` | 5 | bu-heatmap, investment, budget, incident-costs, cyber-insur | §2.2 S2 Finance | CFO (4), CISO (1), CTO (3) |
| 2 | BehaviorAnalyticsHub | `/mission-control/behavior` | 3 | uba, behavioral, insider | §2.3 S3 Behavior | SOC T2 (6), Threat Hunter (8) |
| 3 | HuntingHub | `/mission-control/hunt` | 3 | sessions, playbooks, automation | §2.3 S3 Hunt | SOC T2 (6), Threat Hunter (8) |
| 4 | DetectAndRespondHub | `/discover/detect-respond` | 3 | xdr, edr, itdr | §2.3 S3 Detect&Respond | SOC T1 (5), SOC T2 (6), IR (7) |
| 5 | SupplyChainHub | `/discover/supply-chain` | 3 | security, risk, intel | §2.4/§2.10 Supply Chain | Vuln Mgr (9), AppSec (10), Sec Architect (11) |
| 6 | VulnIntelHub | `/discover/vuln-intel` | 4 | vuln-intel, cve-search, ip-rep, geolocation | §2.7 S7 Vuln Intel | Vuln Mgr (9), Threat Hunter (8) |
| 7 | SecretsHub | `/discover/secrets-hub` | 3 | detection, scanner, rotation | §2.10 S10 Secrets | AppSec (10), Backend Eng (16) |
| 8 | CryptoTrustHub | `/discover/crypto` | 5 | keys, certs, manager, pki, quantum | §2.11 S11 Crypto | Sec Architect (11), GRC (12), Compliance Mgr (13) |
| 9 | EmailThreatProtectionHub | `/discover/threat-protection` | 3 | email, phishing, ransomware | §2.11 S11 Edge Protection | SOC T1 (5), Sec Analyst (24) |
| 10 | PrivilegedAccessHub | `/discover/privileged-access` | 3 | mfa, pam, sessions | §2.11 S11 IAM Deep | Sec Architect (11), DevOps (18) |
| 11 | ContainerSecurityHub | `/discover/container-security` | 3 | image, runtime, posture | §2.11 S11 Container | Platform Eng (20), DevOps (18), SRE (19) |
| 12 | NetworkMonitoringHub | `/discover/network` | 3 | monitoring, anomaly, threats | §2.11 Network Observability | SOC T2 (6), SRE (19) |
| 13 | NetworkSegmentationHub | `/discover/network-segmentation` | 3 | microseg, firewall, policy | §2.11 Network Posture | Sec Architect (11), Platform Eng (20) |
| 14 | IdentityGovernanceHub | `/discover/identity-governance` | 3 | governance, analytics, digital | §2.11 IAM Governance | GRC (12), Sec Architect (11) |
| 15 | ThreatActorsHub | `/attack/intel/actors` | 5 | actors, tracking, attribution, indicators, ioc-hunter | §2.14 S14 Actors/IOCs | Threat Hunter (8), SOC T2 (6) |
| 16 | ExternalThreatIntelHub | `/attack/intel/external` | 3 | zeroday, darkweb, scores | §2.14 S14 External Intel | Threat Hunter (8), CISO (1) |
| 17 | OffensiveValidationHub | `/validate/offensive` | 3 | pentest, red-team, social-eng | §2.13 S13 Offensive | Threat Hunter (8), AppSec (10) |
| 18 | DeceptionHub | `/brain/fail/deception` | 3 | engine, analytics, decoys | §2.17 S17 Deception | SOC T2 (6), Threat Hunter (8) |
| 19 | AutomationOrchestrationHub | `/remediate/automation` | 3 | patch, prioritize, soar | §2.19 S19 Patch+SOAR | Eng Mgr (14), DevOps (18), SRE (19) |
| 20 | ExceptionsHub | `/remediate/exceptions` | 3 | exceptions, workflow, auto-rules | §2.20 S20 Exceptions | Vuln Mgr (9), GRC (12) |
| 21 | UpgradePathsHub | `/remediate/upgrade` | 6 | resolver, explorer, version-graph, dep-map, binary-fp, dep-risk | §2.21 S21 Upgrade Paths | Tech Lead (15), Backend Eng (16) |
| 22 | ForensicsHub | `/remediate/forensics` | 3 | digital, network, malware | §2.22 S22 Forensics | IR (7), SOC T2 (6) |
| 23 | IncidentKnowledgeHub | `/remediate/incidents/knowledge` | 3 | metrics, knowledge, lessons | §2.22 S22 Post-Incident | IR (7), QA (21) |
| 24 | IncidentExtensionsHub | `/remediate/incidents/extensions` | 3 | cloud, breach, comms | §2.22 S22 Incident Ext | IR (7), CISO (1) |
| 25 | AwarenessHub | `/comply/awareness` | 4 | campaigns, program, metrics, score | §2.22b Awareness | GRC (12), CISO (1) |
| 26 | TrainingCultureHub | `/admin/training-culture` | 3 | training, effectiveness, culture | §2.29 Awareness Tail | CISO (1), Eng Mgr (14) |
| 27 | MaturityHub | `/comply/maturity` | 3 | security, posture, program | §2.23 S23 Maturity | CISO (1), GRC (12) |
| 28 | PrivacyComplianceHub | `/comply/privacy` | 3 | gdpr, impact, controls | §2.23 S23 Privacy/Controls | GRC (12), Compliance Mgr (13) |
| 29 | ComplianceCoverageHub | `/comply/coverage` | 3 | gaps, cloud, endpoint | §2.23 S23 Coverage | GRC (12), Compliance Mgr (13) |
| 30 | SBOMProvenanceHub | `/comply/provenance` | 6 | export, pipeline-bom, pbom-prop, slsa, attestation, sign | §2.25 S25 Provenance | GRC (12), AppSec (10) |
| 31 | RulesCatalogHub | `/comply/rules` | 4 | catalog, taxonomy, author, validate | §2.26 S26 Rules/DSL | Sec Architect (11), Automation Eng (25) |
| 32 | PolicyAuthoringHub | `/comply/policies/authoring` | 3 | stage-matrix, hooks-policy, hooks-status | §2.26 S26 Policy/Hooks | DevOps (18), Sec Architect (11) |
| 33 | IntegrationTargetsHub | `/connect/targets` | 3 | prowler, servicenow, siem | §2.27 S27 Targets | DevOps (18), Automation Eng (25) |

**Totals:** 33 hubs · 117 distinct pages folded via hubs (134 total `// FOLDED` markers in `pages/` including the earlier 2026-04-27 wave folded directly into S5/S8/S15/S19/S23 heroes without dedicated Hub.tsx files).

---

## 2. Per-Hub Deep Dive

Each row below is the canonical reference for a future agent answering "what did `<old route>` become?"

### 2.1 FinanceHub
- **Route:** `/mission-control/finance` · **File:** `suite-ui/aldeci-ui-new/src/pages/FinanceHub.tsx` · **SHA:** 852c7805
- **Folded pages:** BUDollarRiskHeatmap, SecurityInvestmentDashboard, SecurityBudgetDashboard, IncidentCostsDashboard, CyberInsuranceDashboard
- **Real APIs:** `/api/v1/risk/heatmap`, `/api/v1/risk/brs/bu`, `/api/v1/security-investment/{investments,budget,outcomes}`, `/api/v1/security-budget/{stats,allocations,transactions}`, `/api/v1/incident-costs/{costs,stats}`, `/api/v1/cyber-insurance/{policies,claims,assessments,stats}`
- **Old routes redirected:** `/bu-dollar-risk`, `/security-investment`, `/security-budget`, `/incident-costs`, `/cyber-insurance`
- **Persona path:** CFO lands on `/mission-control/finance?tab=bu-heatmap` → drills into investment/budget tabs → exports ROI to Evidence Vault.

### 2.2 BehaviorAnalyticsHub
- **Route:** `/mission-control/behavior` · **SHA:** 6b87065f
- **Folded:** UBADashboard, BehavioralAnalyticsDashboard, InsiderThreatMonitor
- **Real APIs:** `/api/v1/uba/{stats,users,events,alerts}`, `/api/v1/behavioral-analytics/{anomalies,stats}`, `/api/v1/insider-threat/{alerts,stats}`
- **Old routes:** `/uba`, `/behavioral-analytics`, `/insider-threats`
- **Persona path:** SOC T2 (#6) lands → switches to Insider tab on alert escalation.

### 2.3 HuntingHub
- **Route:** `/mission-control/hunt` · **SHA:** 7305f97c
- **Folded:** ThreatHuntingPage, HuntingPlaybookDashboard, HuntingAutomationDashboard
- **Real APIs:** `/api/v1/hunting/sessions`, `/api/v1/hunting-playbooks`, `/api/v1/hunting-automation/hypotheses`
- **Old routes:** `/threat-hunting`, `/hunting-playbooks`, `/hunting-automation`
- **Persona path:** Threat Hunter (#8) lands → spawns automation hypothesis → converts to playbook.

### 2.4 DetectAndRespondHub
- **Route:** `/discover/detect-respond` · **SHA:** 6be35ff4
- **Folded:** XDRDashboard, EDRDashboard, ITDRDashboard
- **Real APIs:** `/api/v1/xdr/{incidents,signals,rules}`, `/api/v1/edr/{endpoints,detections,processes}`, `/api/v1/itdr/{stats,threats,response-actions}`
- **Old routes:** `/xdr`, `/edr`, `/itdr`
- **Persona path:** SOC T1 (#5) lands → escalates to S22 IR Console.

### 2.5 SupplyChainHub
- **Route:** `/discover/supply-chain` · **SHA:** b5fdf85f
- **Folded:** SupplyChainSecurity, SupplyChainDashboard, SupplyChainIntelDashboard
- **Real APIs:** `/api/v1/supply-chain/{risk-summary,dependencies,vendors,stats,components}`, `/api/v1/supply-chain-intel/{stats,packages,sbom,malicious,vulns,check}`
- **Old routes:** `/supply-chain`, `/supply-chain-risk`, `/supply-chain-intel`
- **Persona path:** Sec Architect (#11) lands → Vendor risk drill → S25 SBOM evidence.

### 2.6 VulnIntelHub
- **Route:** `/discover/vuln-intel` · **SHA:** a205bbc8
- **Folded:** VulnIntelligenceDashboard, CVESearch, IPReputationDashboard, ThreatGeolocationDashboard
- **Real APIs:** `/api/v1/vuln-intel/{stats,cves,advisories,subscriptions}`, `/api/v1/cve/{vulnerabilities,stats}`, `/api/v1/ip-reputation/{blocklist,stats}`, `/api/v1/threat-geolocation/{stats,heatmap}`
- **Old routes:** `/vuln-intel`, `/cve-search`, `/ip-reputation`, `/threat-geolocation`
- **Screenshot:** `docs/ui-snapshots/ux-consolidation-vuln-intel-2026-05-02.png`
- **Persona path:** Vuln Mgr (#9) lands → CVE search → IP rep cross-check.

### 2.7 SecretsHub
- **Route:** `/discover/secrets-hub` · **SHA:** 08acb2ba
- **Folded:** SecretsDetection, SecretScannerDashboard, SecretsRotation
- **Real APIs:** `/api/v1/secrets-management/{secrets,expiring,stats}`, `/api/v1/secret-scanner/{scan-jobs,findings,stats}`
- **Old routes:** `/discover/secrets`, `/secrets-rotation`, `/secret-scanner`
- **Note:** SecretScannerDashboard was previously orphan-imported (no Route in App.tsx) — fold restores reachability. Multica #3635.

### 2.8 CryptoTrustHub
- **Route:** `/discover/crypto` · **SHA:** 52c48609
- **Folded:** CryptoKeyDashboard, CertificateDashboard, CertificateManager, PKIManagementDashboard, QuantumCryptoDashboard
- **Real APIs:** `/api/v1/crypto-keys/{keys,stats}`, `/api/v1/certificates/{certificates,stats}`, `/api/v1/pki/{stats,certificates,cas}`, `/api/v1/quantum-crypto/{assets,migrations,readiness}`
- **Old routes:** `/crypto-keys`, `/certificates`, `/cert-manager`, `/pki`, `/quantum-crypto`
- **Screenshot:** `docs/ui-snapshots/ux-consolidation-crypto-trust-2026-05-02.png`
- **Persona path:** Compliance Mgr (#13) lands → Quantum-readiness tab for FIPS audit.

### 2.9 EmailThreatProtectionHub
- **Route:** `/discover/threat-protection` · **SHA:** 0a41799b
- **Folded:** EmailSecurity, PhishingSimulation, RansomwareProtectionDashboard
- **Real APIs:** `/api/v1/email-filtering/{threats,stats}`, `/api/v1/phishing/{stats,campaigns,templates}`, `/api/v1/ransomware-protection/{patterns,backup-status}`
- **Old routes:** `/email-security`, `/phishing`, `/ransomware-protection`

### 2.10 PrivilegedAccessHub
- **Route:** `/discover/privileged-access` · **SHA:** 1329bfee
- **Folded:** MFAManagementDashboard, PAMDashboard, PrivilegedSessionRecordingDashboard
- **Real APIs:** `/api/v1/mfa/{stats,enrollments,events}`, `/api/v1/pam/{stats,accounts,sessions,requests}`, `/api/v1/session-recording/{sessions,stats}`
- **Old routes:** `/mfa-management`, `/pam`, `/session-recording`
- **Multica:** #3633

### 2.11 ContainerSecurityHub
- **Route:** `/discover/container-security` · **SHA:** 614aa666 · **Multica:** #3636
- **Folded:** ContainerSecurityDashboard, ContainerRuntimeSecurityDashboard, ContainerPostureDashboard
- **Real APIs:** `/api/v1/containers/policies`, `/api/v1/kubernetes-security/stats`, `/api/v1/container-runtime/{stats,containers,violations}`, `/api/v1/container-posture/{clusters,stats}`
- **Old routes:** `/container-security`, `/container-runtime`, `/container-posture`

### 2.12 NetworkMonitoringHub
- **Route:** `/discover/network` · **SHA:** 37c92cc4
- **Folded:** NetworkMonitoringDashboard, NetworkAnomalyDashboard, NetworkThreatsDashboard
- **Real APIs:** `/api/v1/network-monitoring/{interfaces,alert-rules}`, `/api/v1/network-anomaly/{summary,baselines,traffic-trend}`, `/api/v1/network-threats/{threats/active,rules,baselines}`
- **Old routes:** `/network-monitoring`, `/network-anomaly`, `/network-threats`

### 2.13 NetworkSegmentationHub
- **Route:** `/discover/network-segmentation` · **SHA:** 9de76b25
- **Folded:** MicrosegmentationPolicyDashboard, FirewallAnalyzer, FirewallPolicyDashboard
- **Real APIs:** `/api/v1/microsegmentation/{segments,stats}`, `/api/v1/firewall-policy/{rules,firewalls,stats}`
- **Old routes:** `/microsegmentation`, `/firewall`, `/firewall-policy`
- **Note:** Restores reachability of previously orphan-imported MicrosegmentationPolicyDashboard.
- **Screenshot:** `docs/ui-snapshots/ux-consolidation-network-segmentation-2026-05-02.png`

### 2.14 IdentityGovernanceHub
- **Route:** `/discover/identity-governance` · **SHA:** 4c2a8047
- **Folded:** IdentityGovernance, IdentityAnalyticsDashboard, DigitalIdentityDashboard
- **Real APIs:** `/api/v1/identity-governance/{reviews,entitlements,stats}`, `/api/v1/identity-analytics/{stats,risks,profiles}`, `/api/v1/digital-identity/{identities,stats}`
- **Old routes:** `/identity-governance`, `/identity-analytics`, `/digital-identity`

### 2.15 ThreatActorsHub
- **Route:** `/attack/intel/actors` · **SHA:** 17fd2540
- **Folded:** ThreatActorDashboard, ActorTrackingDashboard, ThreatAttributionDashboard, ThreatIndicatorDashboard, IOCHunter
- **Real APIs:** `/api/v1/threat-actors/{stats,actors,watchlist,iocs}`, `/api/v1/actor-tracking/{actors,stats}`, `/api/v1/threat-attribution/{attributions,stats}`, `/api/v1/threat-indicators/indicators`, `/api/v1/ioc-enrichment/{stats,iocs}`
- **Old routes:** `/threat-actors`, `/actor-tracking`, `/threat-attribution`, `/threat-indicators`, `/ioc-hunter`

### 2.16 ExternalThreatIntelHub
- **Route:** `/attack/intel/external` · **SHA:** 0fc80796
- **Folded:** ZeroDayIntelligenceDashboard, DarkWebMonitoringDashboard, ThreatScoreDashboard
- **Real APIs:** `/api/v1/zero-day/{stats,vulns,threat-actors}`, `/api/v1/dark-web/{stats,mentions,credential-exposures}`, `/api/v1/threat-scores/{stats,top-threats,scores}`
- **Old routes:** `/zero-day`, `/dark-web`, `/threat-scores`

### 2.17 OffensiveValidationHub
- **Route:** `/validate/offensive` · **SHA:** 62e9f1d3
- **Folded:** PentestManagement, RedTeamStatus, SocialEngineering (PentestManagementDashboard alias also redirects)
- **Real APIs:** `/api/v1/pentest-mgmt/{stats,engagements,findings}`, `/api/v1/red-team/{stats,engagements,findings}`, `/api/v1/phishing/{stats,campaigns,templates}`
- **Old routes:** `/pentest`, `/red-team`, `/social-engineering`, `/pentest-mgmt`
- **Note:** AttackSimulation stays at `/validate/simulation` (RoleGuarded BAS); BugBounty already folded into Brain.tsx.

### 2.18 DeceptionHub
- **Route:** `/brain/fail/deception` · **SHA:** a75636d1
- **Folded:** DeceptionEngine, DeceptionAnalyticsDashboard, ThreatDeceptionDashboard
- **Real APIs:** `/api/v1/deception/{stats,canaries,alerts}`, `/api/v1/deception-analytics/{stats,assets,interactions}`, `/api/v1/threat-deception/{decoys,stats}`
- **Old routes:** `/deception`, `/deception-analytics`, `/threat-deception`
- **Note:** ThreatDeceptionDashboard was previously orphan-imported — fold restores reachability.

### 2.19 AutomationOrchestrationHub
- **Route:** `/remediate/automation` · **SHA:** cfab097a
- **Folded:** PatchManagementDashboard, PatchPrioritizer, SOARDashboard
- **Real APIs:** `/api/v1/patch-management/{patches,stats}`, `/api/v1/patch-automation/{patches,stats}`, `/api/v1/soar/{stats,playbooks,executions,mttr}`
- **Old routes:** `/patch-management`, `/patch-prioritizer`, `/soar`

### 2.20 ExceptionsHub
- **Route:** `/remediate/exceptions` · **SHA:** 0708a270
- **Folded:** SecurityExceptionDashboard, ExceptionWorkflowDashboard, AutoWaiverRules
- **Real APIs:** `/api/v1/security-exceptions/{list,stats}`, `/api/v1/exception-workflow/{exceptions,stats}`, `/api/v1/auto-waiver/{rules,rule}`
- **Old routes:** `/security-exceptions`, `/exception-workflow`, `/waivers/auto-rules`

### 2.21 UpgradePathsHub
- **Route:** `/remediate/upgrade` · (folds 6 pages — largest hub by source-page count alongside SBOMProvenanceHub)
- **Folded:** UpgradePathDashboard, UpgradePathExplorer, ComponentVersionGraph, DependencyMappingDashboard, BinaryFingerprintDashboard, SecurityDependencyRiskDashboard
- **Real APIs:** `/api/v1/upgrade-path/recent`, `/api/v1/upgrade-path/resolve`, `/api/v1/components/{purl}/safe-upgrade`, `/api/v1/dependency-mapping/services`, `/api/v1/dependency-mapping/critical-paths`, `/api/v1/binary-fp/stats`, `/api/v1/binary-fp/fingerprint`, `/api/v1/dependency-risk/summary`
- **Old routes:** `/upgrade-paths`, `/upgrade-explorer`, `/component-version-graph`, `/dependency-mapping`, `/binary-fingerprint`, `/dependency-risk`

### 2.22 ForensicsHub
- **Route:** `/remediate/forensics` · **SHA:** 808352ac
- **Folded:** DigitalForensicsDashboard, NetworkForensics (via FindingsExplorerView), MalwareAnalysis (via FindingsExplorerView)
- **Real APIs:** `/api/v1/digital-forensics/{stats,cases}`, `/api/v1/network-forensics/{captures,stats}`, `/api/v1/malware-analysis/{samples,stats}`
- **Old routes:** `/digital-forensics`, `/network-forensics`, `/malware-analysis`

### 2.23 IncidentKnowledgeHub
- **Route:** `/remediate/incidents/knowledge` · **SHA:** 60f73eb7
- **Folded:** IncidentMetricsDashboard, IncidentKBDashboard, IncidentLessonsDashboard
- **Real APIs:** `/api/v1/incident-metrics/{stats,incidents}`, `/api/v1/incident-kb/{articles,stats}`, `/api/v1/incident-lessons/{lessons,stats}`
- **Old routes:** `/incident-metrics`, `/incident-kb`, `/incident-lessons`
- **Verification:** 5 real API calls/tab, 0 mock signatures.
- **Screenshot:** `docs/ui-snapshots/ux-consolidation-incident-knowledge-2026-05-02.png`

### 2.24 IncidentExtensionsHub
- **Route:** `/remediate/incidents/extensions` · **SHA:** ff14482a
- **Folded:** CloudIRDashboard, BreachResponse, IncidentCommsDashboard
- **Real APIs:** `/api/v1/cloud-ir/*`, `/api/v1/breach-response/{stats,cases}`, `/api/v1/incident-comms/{communications,stats}`
- **Old routes:** `/cloud-ir`, `/breach-response`, `/incident-comms`

### 2.25 AwarenessHub
- **Route:** `/comply/awareness` · **SHA:** 29f1aae6
- **Folded:** AwarenessCampaignDashboard, AwarenessProgramDashboard, AwarenessMetricsDashboard, AwarenessScoreDashboard
- **Real APIs:** `/api/v1/awareness-campaigns/{campaigns,stats}`, `/api/v1/awareness-program/{programs,stats}`, `/api/v1/awareness-metrics/{metrics,stats}`, `/api/v1/awareness-score/orgs/{id}/{scores,employees,stats}`
- **Old routes:** `/awareness-campaigns`, `/awareness-program`, `/awareness-metrics`, `/awareness-score`

### 2.26 TrainingCultureHub
- **Route:** `/admin/training-culture` (Awareness tail under Admin)
- **Folded:** SecurityTrainingDashboard, TrainingEffectivenessDashboard, SecurityCultureDashboard
- **Real APIs:** `/api/v1/security-training/{stats,courses,enrollments,campaigns}`, `/api/v1/training-effectiveness/programs`, `/api/v1/security-culture`
- **Old routes:** `/security-training`, `/training-effectiveness`, `/security-culture`

### 2.27 MaturityHub
- **Route:** `/comply/maturity` · **SHA:** 4bbb4aa6
- **Folded:** SecurityMaturityDashboard, SecurityPostureMaturityDashboard, ProgramMaturityDashboard
- **Real APIs:** `/api/v1/security-maturity/{stats,assessments}`, `/api/v1/posture-maturity/overview`, `/api/v1/program-maturity/domains`
- **Old routes:** `/security-maturity`, `/posture-maturity`, `/program-maturity`

### 2.28 PrivacyComplianceHub
- **Route:** `/comply/privacy` · **SHA:** a31fa954
- **Folded:** PrivacyGDPRDashboard, PrivacyImpactDashboard, ControlTestingDashboard
- **Real APIs:** `/api/v1/privacy/{stats,dsrs,consents,incidents,processing-activities}`, `/api/v1/privacy-impact/assessments`, `/api/v1/control-testing/controls`
- **Old routes:** `/privacy-gdpr`, `/privacy-impact`, `/control-testing`
- **Verification:** 11 real API calls, 0 mock signatures.
- **Screenshot:** `docs/ui-snapshots/ux-consolidation-privacy-compliance-2026-05-02.png`

### 2.29 ComplianceCoverageHub
- **Route:** `/comply/coverage` · **SHA:** 7f357a1a · **Multica:** #3643
- **Folded:** ComplianceGapDashboard, CloudComplianceDashboard, EndpointComplianceDashboard
- **Real APIs:** `/api/v1/compliance-gaps/{stats,assessments,gaps}`, `/api/v1/cloud-compliance/{controls,stats}`, `/api/v1/endpoint-compliance/{stats,endpoints,checks,department-compliance}`
- **Old routes:** `/compliance-gaps`, `/cloud-compliance`, `/endpoint-compliance`
- **Verification:** 5–9 real API calls per tab across 6 URLs (canonical + 3 redirects + 2 query-string variants), 0 mock signatures.
- **Note:** Removed dead `/compliance-gaps → /compliance?tab=gaps` redirect that was unreachable behind the standalone route.
- **Screenshot:** `docs/ui-snapshots/ux-consolidation-compliance-coverage-2026-05-02.png`

### 2.30 SBOMProvenanceHub
- **Route:** `/comply/provenance` · **SHA:** 16c0b17d (folds 6 pages)
- **Folded:** SBOMExportDashboard, PipelineBomDashboard, PBOMViewer, SlsaProvenanceDashboard, PipelineAttestationGraph, SLSAAttestationSigner
- **Real APIs:** `/api/v1/sbom-export/{projects,components,history}`, `/api/v1/pbom/stats`, `/api/v1/pbom/run/{id}/export`, `/api/v1/pbom/artifact/{digest}/propagation`, `/api/v1/slsa/{stats,attestations,attest}`, `/api/v1/provenance/{artifact}/attestation`, `/api/v1/provenance/sign`
- **Old routes:** `/sbom-export`, `/pipeline-bom`, `/slsa-provenance`, `/pbom/propagation`, `/provenance/attestation`, `/provenance/sign`
- **Note:** Inventory subset (SBOMInventory/SBOMManagement/SBOMDashboard/SBOMContinuousMonitoring) intentionally remains under `/assets?tab=sbom` (S9 Inventory hero) for asset-centric persona path.

### 2.31 RulesCatalogHub
- **Route:** `/comply/rules` · **SHA:** 7f038429
- **Folded:** UnifiedRulesCatalog, RuleTaxonomyInspector, RuleDSLAuthoringStudio, RuleDSLValidator
- **Real APIs:** `/api/v1/rules/unified`, `/api/v1/rules/unified/taxonomy`, `/api/v1/rules/dsl`, `/api/v1/rules/dsl/schema`, `POST /api/v1/rules/dsl/validate`
- **Old routes:** `/rules/catalog`, `/rules/taxonomy`, `/rules/dsl/author`, `/rules/dsl/validate`

### 2.32 PolicyAuthoringHub
- **Route:** `/comply/policies/authoring` · **SHA:** PENDING (commit landed in this session)
- **Folded:** StagePolicyMatrix, HooksPolicyEditor, HooksStatusPanel
- **Real APIs:** `/api/v1/policies` (stage × severity matrix), `GET/PUT /api/v1/hooks/policy`, `GET /api/v1/hooks/status`
- **Old routes:** `/policies/stage-matrix`, `/hooks/policy`, `/hooks/status`

### 2.33 IntegrationTargetsHub
- **Route:** `/connect/targets` · **SHA:** b3940927
- **Folded:** ProwlerDashboard, ServiceNowDashboard, SIEMOutputDashboard
- **Real APIs:** `/api/v1/prowler/{findings,compliance,scan}`, `/api/v1/servicenow/{connections,incidents,cmdb,mappings}`, `/api/v1/siem-output/{targets,events,stats}`
- **Old routes:** `/prowler`, `/servicenow`, `/siem-output`

---

## 3. How To Add A New Hub — Verified Pattern

This recipe is reverse-engineered from the 33 hubs already shipped (header convention + body shape are byte-identical across `CryptoTrustHub`, `DetectAndRespondHub`, `IncidentKnowledgeHub`, `RulesCatalogHub`, etc.). Follow it for any future fold.

### 3.1 File header — describe the fold

```tsx
/**
 * <NewHub> — <one-line elevator pitch>
 * (Phase 3 UX consolidation, 2026-MM-DD)
 *
 * Folds N standalone pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §<cluster>.
 *
 *   tab        | source page             | endpoint
 *   -----------|-------------------------|----------------------------------------------
 *   <key>      | <SourcePage>            | /api/v1/<endpoint>
 *
 * Route: /<canonical/path>
 * Persona target: <name (#n)>, ...
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §<n.m>
 */
```

### 3.2 Imports — exactly these, no more

```tsx
import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { /* lucide-react icons matching tab semantics */ } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
```

### 3.3 Lazy-import folded source pages — preserve them, do NOT inline their JSX

```tsx
const SourceA = lazy(() => import("@/pages/SourceA"));
const SourceB = lazy(() => import("@/pages/SourceB"));
```
This is critical — folded pages keep their existing API calls, error/empty states, and form interactions. The hub is *composition*, not rewrite.

### 3.4 Tab metadata + URL sync — copy this exactly

```tsx
type TabKey = "k1" | "k2" | "k3";
const TABS: Array<{ key: TabKey; label: string; icon: React.ComponentType<{className?:string}>; description: string }> = [
  { key: "k1", label: "Tab One", icon: IconA, description: "(Folded from SourceA)." },
  // ...
];
const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));
function isTabKey(v: string | null): v is TabKey { return !!v && VALID_TABS.has(v as TabKey); }
```
Then in the component, two `useEffect`s keep `?tab=` and React state in lock-step (so old-route redirects like `/sourcea → /newhub?tab=k1` land on the right tab):

```tsx
useEffect(() => { if (params.get("tab") !== tab) { const n = new URLSearchParams(params); n.set("tab", tab); setParams(n, { replace: true }); }}, [tab, params, setParams]);
useEffect(() => { const i = params.get("tab"); if (isTabKey(i) && i !== tab) setTab(i); }, [params, tab]);
```

### 3.5 Stub the folded source pages — preserve git history

Add a one-line header to each folded `.tsx` (do NOT delete it):
```tsx
// FOLDED into <NewHub> at /<route>?tab=<key> — preserve for git history
```
This pattern is consistent with the 134 folded files already present.

### 3.6 Wire `App.tsx` — canonical route + redirects

Add the canonical route alongside the other hubs (~line 700–1570 in `App.tsx`):
```tsx
<Route path="/<route>" element={<NewHub />} />
```
Plus a `<Navigate>` redirect for every old route → `/<route>?tab=<key>`. NEVER skip the redirect — persona muscle memory + e2e tests rely on it.

### 3.7 Verify per the NO MOCKS rule (`CLAUDE.md`)

1. `mcp__playwright__browser_navigate({url: "http://localhost:5173/<route>"})`
2. `mcp__playwright__browser_take_screenshot({filename: "docs/ui-snapshots/ux-consolidation-<hub>-2026-MM-DD.png"})`
3. `mcp__playwright__browser_network_requests()` — confirm ≥1 real `/api/v1/...` call per tab
4. `mcp__playwright__browser_evaluate` to grep DOM for `MOCK_`, `Acme Corp`, `John Doe`, etc.
5. If zero API calls fire on tab activation, the fold is **not done** — fix the underlying source page.

### 3.8 Commit format

```
beast-mode(ux): merge N pages → 1 unified <NewHub> — Phase 3 cluster <S#> <Cluster>
```
Trailer: `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`. Use `git commit -F /tmp/msg` (see `MEMORY.md` agent heredoc bug).

### 3.9 Backfill the plan doc

Append a `**<Cluster>: DONE-2026-MM-DD SHA=<sha>**` line to the matching §2.x table in `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md`. This is the "ledger" the next session reads to know what's left.

---

## 4. Pages Still Pending Fold

These clusters are explicitly named in `UX_CONSOLIDATION_PLAN_2026-04-26.md` §2 as targets but do NOT yet have a dedicated `*Hub.tsx` (some have been folded directly into the S5/S8/S15/S19/S23 hero pages without an intermediate Hub.tsx, but most are still standalone routes). Total `pages/*.tsx` count: **417** (from a peak of ~470 routes pre-Phase 3). Total folded markers: **134**.

| Cluster | Plan §  | Source pages awaiting hub | Owner |
|---|---|---|---|
| ~~Risk Quantification (FAIR / scenario / treatment)~~ **DONE-2026-05-02 → RiskQuantHub at /comply/risk-quant** (Multica #3653; folds RiskQuantification + RiskQuantDashboard + RiskScenarioDashboard. RiskTreatmentDashboard remains standalone for separate fold.) | §2.4 | ~~RiskQuantification, RiskQuantDashboard, RiskScenarioDashboard~~, RiskTreatmentDashboard | frontend-craftsman |
| API Security family | §2.10 | APISecurityDashboard, APISecurityPage, APISecurityMgmtDashboard, APIAbuseDashboard, APIThreatProtectionDashboard | ux-architect |
| App / Mobile / Browser Sec | §2.10 | AppSecurity, MobileSecurity, MobileAppSecurityDashboard, BrowserSecurityDashboard | ux-architect |
| Data Discovery & Classification | §2.9 | DataDiscoveryDashboard, DataClassificationDashboard, DataGovernanceDashboard, PIIFieldInventory | ux-architect |
| Asset Tagging & Criticality | §2.9 | AssetGroupsDashboard, AssetTagsDashboard, AssetCriticalityDashboard | ux-architect |
| OT / IoT / Firmware | §2.11 | OTSecurityDashboard, IoTSecurityDashboard, FirmwareSecurityDashboard | ux-architect |
| Zero Trust posture | §2.11 | ZeroTrustDashboard, ZeroTrustPolicyDashboard | ux-architect |
| DLP / Exfiltration | §2.11 | DLPDashboard, DataExfiltrationDashboard | ux-architect |
| AI Governance / Shadow AI / Advisor | §2.18 | ShadowAIInventory, AIGovernanceDashboard (already FOLDED hint), AIPoweredSOCDashboard, AISecurityAdvisor, AISecurityAdvisorDashboard | ux-architect |
| AI Agents Console | §2.18 | AIAgentsConsole, AgentTaskQueue, CopilotGraphChat, CopilotGraphChatRoot | ux-architect |
| Threat Modeling family | §2.12 | ThreatModeling, ThreatModelDashboard, ThreatModelingPipelineDashboard, CyberThreatModelingDashboard | ux-architect |
| MITRE / Kill Chain views | §2.3 | MITREAttackDashboard, KillChainDashboard (if present) | ux-architect |
| Air-Gap & Local Store (S28 sub-hub) | §2.28 | AirGapBundleDashboard, AirGapBundleConsole, OfflineFeedRegistry, OfflineUpdateStatus, LocalFileStoreDashboard, LocalStoreStatus, ZeroSetupOnboarding | ux-architect |
| Webhook / Integration Health (S27 sub-hub) | §2.27 | WebhookEventCatalogExplorer, WebhookRetryConsole, IntegrationHealth, ConnectorMappingUI, UniversalIngestionTester | ux-architect |
| Threat Brief / Landscape / Response | §2.14 | ThreatBriefDashboard, ThreatLandscapeDashboard, ThreatResponseDashboard, CyberThreatIntelDashboard | ux-architect |
| Watchlist / Feed Subscriptions | §2.14 | WatchlistManager, FeedSubscriptionsDashboard | ux-architect |
| GRC / Questionnaire / TPRM | §2.23 | GRCDashboard, GRCAssessment, SecurityQuestionnaireDashboard, ThirdPartyVendorDashboard, TprmExchangeDashboard, VendorRiskDashboard | ux-architect |
| FIPS / Posture Reporting | §2.30 / §2.23 | FipsComplianceDashboard, FIPSModeStatus, PostureReportingDashboard, MetricsAggregatorDashboard | ux-architect |

**Method:** clusters above were extracted by diffing every `*` line in `UX_CONSOLIDATION_PLAN_2026-04-26.md` §2.x tables (excluding entries marked `DONE-2026-05-02`) against the 134 `// FOLDED` markers in `pages/`. Each row points to a still-routed standalone `.tsx` whose plan-target hub does not yet exist.

> **Estimated remaining work:** ~18 hubs at 1 commit each (current cadence: 33 hubs in one session). Next session can complete by following the §3 recipe verbatim — no plan re-design needed.

---

## 5. References

- **Plan input:** `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` (770 lines, S1–S30 target shape, 30 cluster tables, persona walkthroughs)
- **Routing source:** `suite-ui/aldeci-ui-new/src/App.tsx` (33 hub routes between L724 and L1566)
- **CLAUDE.md NO MOCKS rule:** every hub verified against real `/api/v1/...` calls before fold marked done
- **Multica board IDs:** #3633 (PrivilegedAccess), #3635 (Secrets), #3636 (ContainerSecurity), #3643 (ComplianceCoverage)
- **Screenshot directory:** `docs/ui-snapshots/ux-consolidation-*-2026-05-02.png`
- **Competitive validation:** `docs/competitive_validation_2026-04-26.md` (Phase 2 — 83% WIN/MATCH that justified this Phase 3 fold)

*End of catalog. Contract for next session: pick any row in §4, follow §3 recipe, append SHA to plan doc + this catalog. No new screens.*
