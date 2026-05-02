-- ALDECI UI Consolidation: 31 Multica issues (one per target screen)
-- Generated 2026-05-03 by Phase-0 audit
BEGIN;
-- Lock the number high-water-mark by computing once
WITH next_n AS (SELECT COALESCE(MAX(number),0) AS n FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
SELECT n FROM next_n;  -- inspect; following inserts use MAX()+i

INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S01 Login & Auth',
  'Migrate 2 legacy pages → 1 v2 screen `S01` (Login & Auth).

**Purpose:** Auth entry
**Route:** /login
**Tabs:** (none)
**Filters:** (none)
**API prefixes:** /auth
**Backend endpoints in scope:** 33

**Sample legacy pages:**
- src/pages/auth/AccessDenied.tsx
- src/pages/auth/LoginPage.tsx

**Sample backend endpoints:**
- POST /api/v1/auth/keys
- POST /api/v1/auth/keys/{key_id}/rotate
- GET /api/v1/auth/keys
- GET /api/v1/auth/keys/{key_id}
- PUT /api/v1/auth/keys/{key_id}

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S02 Onboarding Wizard',
  'Migrate 3 legacy pages → 1 v2 screen `S02` (Onboarding Wizard).

**Purpose:** First-run bootstrap
**Route:** /onboarding
**Tabs:** org, data, scanners, invite, summary
**Filters:** (none)
**API prefixes:** /onboarding
**Backend endpoints in scope:** 9

**Sample legacy pages:**
- src/pages/Tour.tsx
- src/pages/ZeroSetupOnboarding.tsx
- src/pages/onboarding/OnboardingWizard.tsx

**Sample backend endpoints:**
- GET /api/v1/onboarding/steps/{step}/config
- POST /api/v1/onboarding/start
- GET /api/v1/onboarding/progress
- POST /api/v1/onboarding/steps/{step}/complete
- POST /api/v1/onboarding/steps/{step}/skip

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S03 Mission Control',
  'Migrate 181 legacy pages → 1 v2 screen `S03` (Mission Control).

**Purpose:** Persona-driven home
**Route:** /
**Tabs:** overview, persona, actions, alerts
**Filters:** persona, timeRange
**API prefixes:** /dashboard, /exec, /kpis, /missioncontrol
**Backend endpoints in scope:** 128

**Sample legacy pages:**
- src/pages/AIGovernanceDashboard.tsx
- src/pages/AIPoweredSOCDashboard.tsx
- src/pages/AccessAnomalyDashboard.tsx
- src/pages/AccessGovernanceDashboard.tsx
- src/pages/ActorTrackingDashboard.tsx
- src/pages/AgentlessSnapshotDashboard.tsx
- … +175 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- GET /api/v1/analytics/executive-summary
- PUT /api/v1/ai-soc/automation/{rule_id}/execute
- POST /api/v1/ai-orchestrator/tasks/{task_id}/execute
- GET /api/v1/analytics/dashboard/overview
- GET /api/v1/analytics-engine/executive

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S04 ASPM — Code',
  'Migrate 2 legacy pages → 1 v2 screen `S04` (ASPM — Code).

**Purpose:** Code-level SAST
**Route:** /aspm/code
**Tabs:** sast, secrets, ide, prGate
**Filters:** repo, severity, language
**API prefixes:** /sast, /code, /scm, /repo
**Backend endpoints in scope:** 103

**Sample legacy pages:**
- src/pages/developer/APIExplorer.tsx
- src/pages/developer/DeveloperPortal.tsx

**Sample backend endpoints:**
- POST /api/v1/code-to-cloud/trace
- POST /api/v1/appsec/apps/{app_id}/sast
- GET /api/v1/appsec/apps/{app_id}/sast
- POST /api/v1/breach-response/cases/{case_id}/reports
- GET /api/v1/breach-response/cases/{case_id}/reports

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S05 ASPM — API Security',
  'Migrate 9 legacy pages → 1 v2 screen `S05` (ASPM — API Security).

**Purpose:** API surface security
**Route:** /aspm/api
**Tabs:** catalog, posture, traffic, abuse
**Filters:** env, method
**API prefixes:** /apisec, /openapi, /api-security
**Backend endpoints in scope:** 29

**Sample legacy pages:**
- src/pages/APIAbuseDashboard.tsx
- src/pages/APIDiscoveryDashboard.tsx
- src/pages/APIInventoryDashboard.tsx
- src/pages/APISecurityDashboard.tsx
- src/pages/APISecurityHub.tsx
- src/pages/APISecurityMgmtDashboard.tsx
- … +3 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- GET /api/v1/docs/openapi.yaml
- POST /api/v1/api-security-engine/endpoints
- GET /api/v1/docs/openapi.json
- POST /api/v1/api-security-engine/keys
- GET /api/v1/api-security-engine/endpoints

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S06 ASPM — App Runtime',
  'Migrate 2 legacy pages → 1 v2 screen `S06` (ASPM — App Runtime).

**Purpose:** Runtime app protection
**Route:** /aspm/runtime
**Tabs:** rasp, mobile, container, web
**Filters:** surface
**API prefixes:** /rasp, /runtime, /webapp, /mobile-app
**Backend endpoints in scope:** 27

**Sample legacy pages:**
- src/pages/MobileAppSecurityDashboard.tsx
- src/pages/MobileSecurity.tsx

**Sample backend endpoints:**
- POST /api/v1/mobile-app-security/findings
- GET /api/v1/fips/runtime-status
- POST /api/v1/mobile-app-security/apps
- GET /api/v1/mobile-app-security/apps/{app_id}
- GET /api/v1/mobile-app-security/apps

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S07 Software Supply Chain',
  'Migrate 4 legacy pages → 1 v2 screen `S07` (Software Supply Chain).

**Purpose:** SBOM + SCA
**Route:** /aspm/supply-chain
**Tabs:** sbom, sca, provenance, license
**Filters:** component, ecosystem
**API prefixes:** /sbom, /sca, /supply, /dependency, /license
**Backend endpoints in scope:** 233

**Sample legacy pages:**
- src/pages/SBOMContinuousMonitoring.tsx
- src/pages/SBOMProvenanceHub.tsx
- src/pages/SLSAAttestationSigner.tsx
- src/pages/sbom/SBOMManagement.tsx

**Sample backend endpoints:**
- GET /api/v1/analytics/scanners
- GET /api/v1/apps/{app_id}/scanners
- POST /api/v1/agentless-snapshot/{snapshot_db_id}/scan
- PUT /api/v1/api-discovery/scans/{scan_id}/complete
- POST /api/v1/api-discovery/scans

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S08 Secrets & Crypto',
  'Migrate 1 legacy pages → 1 v2 screen `S08` (Secrets & Crypto).

**Purpose:** Secret leakage + crypto posture
**Route:** /aspm/secrets
**Tabs:** leaks, crypto, keys, certs
**Filters:** status
**API prefixes:** /secret, /crypto, /quantum, /key, /cert, /vault
**Backend endpoints in scope:** 121

**Sample legacy pages:**
- src/pages/CryptoTrustHub.tsx

**Sample backend endpoints:**
- GET /api/v1/certificates/alerts/expiry
- GET /api/v1/certificates/
- GET /api/v1/certificates/weak
- POST /api/v1/certificates/
- GET /api/v1/certificates/stats

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S09 CSPM — Posture',
  'Migrate 1 legacy pages → 1 v2 screen `S09` (CSPM — Posture).

**Purpose:** Cloud posture findings
**Route:** /cspm/posture
**Tabs:** misconfig, benchmark, drift, exceptions
**Filters:** cloud, severity, framework
**API prefixes:** /cspm, /posture, /cloud-config, /cis, /benchmark
**Backend endpoints in scope:** 147

**Sample legacy pages:**
- src/pages/DriftTrackingPanel.tsx

**Sample backend endpoints:**
- GET /api/v1/ciso-report/weekly-brief
- POST /api/v1/ai-advisor/posture-review
- GET /api/v1/ciso-report/risk-delta
- GET /api/v1/ciso-report/top-risks
- GET /api/v1/ciso-report/export/markdown

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S10 Cloud Accounts',
  'Migrate 0 legacy pages → 1 v2 screen `S10` (Cloud Accounts).

**Purpose:** Cloud account inventory
**Route:** /cloud/accounts
**Tabs:** accounts, health, cost, onboarding
**Filters:** cloud
**API prefixes:** /account, /tenant, /cloud-account
**Backend endpoints in scope:** 47

**Sample legacy pages:**

**Sample backend endpoints:**
- POST /api/v1/ciem/analyze/account
- GET /api/v1/cloud-accounts/accounts/{account_id}
- GET /api/v1/cloud-accounts/accounts
- GET /api/v1/cloud-accounts/
- POST /api/v1/cloud-accounts/accounts

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S11 Cloud Workloads',
  'Migrate 5 legacy pages → 1 v2 screen `S11` (Cloud Workloads).

**Purpose:** Workload protection
**Route:** /cloud/workloads
**Tabs:** compute, kubernetes, containers, serverless
**Filters:** cloud, cluster
**API prefixes:** /workload, /cwpp, /k8s, /kubernetes, /cluster
**Backend endpoints in scope:** 46

**Sample legacy pages:**
- src/pages/ContainerPostureDashboard.tsx
- src/pages/ContainerRegistryDashboard.tsx
- src/pages/ContainerRuntimeSecurityDashboard.tsx
- src/pages/ContainerSecurityDashboard.tsx
- src/pages/ContainerSecurityHub.tsx

**Sample backend endpoints:**
- POST /api/v1/bulk/clusters/accept-risk
- POST /api/v1/bulk/clusters/assign
- POST /api/v1/bulk/clusters/create-tickets
- POST /api/v1/bulk/clusters/status
- POST /api/v1/cwp/workloads

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S12 Network Security',
  'Migrate 3 legacy pages → 1 v2 screen `S12` (Network Security).

**Purpose:** Cloud network posture
**Route:** /cloud/network
**Tabs:** topology, firewall, segmentation, exposure
**Filters:** cloud, region
**API prefixes:** /network, /firewall, /vpc, /microseg
**Backend endpoints in scope:** 134

**Sample legacy pages:**
- src/pages/FirewallAnalyzer.tsx
- src/pages/FirewallPolicyDashboard.tsx
- src/pages/MicrosegmentationPolicyDashboard.tsx

**Sample backend endpoints:**
- GET /api/v1/airgap/network-check
- POST /api/v1/firewall-mgmt/firewalls
- POST /api/v1/firewall-mgmt/firewalls/{firewall_id}/rules
- GET /api/v1/firewall-mgmt/firewalls/{firewall_id}
- GET /api/v1/firewall-mgmt/firewalls

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S13 Identity & Access',
  'Migrate 15 legacy pages → 1 v2 screen `S13` (Identity & Access).

**Purpose:** Identity & entitlements
**Route:** /identity
**Tabs:** users, roles, privileges, ciem
**Filters:** scope
**API prefixes:** /identity, /iam, /access, /role, /permission, /ciem, /users
**Backend endpoints in scope:** 175

**Sample legacy pages:**
- src/pages/AccessRequestManagementDashboard.tsx
- src/pages/CloudIAM.tsx
- src/pages/CloudIdentityDashboard.tsx
- src/pages/DigitalIdentityDashboard.tsx
- src/pages/IdentityAnalyticsDashboard.tsx
- src/pages/IdentityGovernance.tsx
- … +9 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- POST /api/v1/access-anomaly/baseline
- POST /api/v1/access-anomaly/impossible-travel/{username}
- GET /api/v1/access-anomaly/
- POST /api/v1/access-anomaly/events/{event_id}/detect-anomalies
- POST /api/v1/access-anomaly/events

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S14 Attack Surface',
  'Migrate 22 legacy pages → 1 v2 screen `S14` (Attack Surface).

**Purpose:** External attack surface
**Route:** /exposure/asm
**Tabs:** domains, ips, services, leaks
**Filters:** scope
**API prefixes:** /asm, /attack-surface, /exposure, /easm
**Backend endpoints in scope:** 86

**Sample legacy pages:**
- src/pages/AttackSurfaceDashboard.tsx
- src/pages/CrossDomainAnalytics.tsx
- src/pages/DomainSeedDiscoveryWizard.tsx
- src/pages/attack-surface/AttackSurface.tsx
- src/pages/discover/ArchitectureLayerGraph.tsx
- src/pages/discover/AttackPaths.tsx
- … +16 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- POST /api/v1/attack-surface-mgmt/assets
- GET /api/v1/attack-surface-mgmt/assets
- POST /api/v1/algorithms/gnn/attack-surface
- GET /api/v1/attack-surface-mgmt/assets/{asset_id}
- POST /api/v1/attack-surface-mgmt/assets/{asset_id}/exposures

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S15 TrustGraph',
  'Migrate 5 legacy pages → 1 v2 screen `S15` (TrustGraph).

**Purpose:** Asset relationship graph
**Route:** /exposure/trustgraph
**Tabs:** graph, paths, blastRadius, queries
**Filters:** scope
**API prefixes:** /trustgraph, /graph, /relationship
**Backend endpoints in scope:** 62

**Sample legacy pages:**
- src/pages/AssetGraph.tsx
- src/pages/AttackPathAnalysis.tsx
- src/pages/AttackPathInteractiveGraph.tsx
- src/pages/NetworkTopology.tsx
- src/pages/SecurityGraph.tsx

**Sample backend endpoints:**
- POST /api/v1/assets/relationships
- GET /api/v1/assets/{asset_id}/relationships
- DELETE /api/v1/assets/relationships/{rel_id}
- GET /api/v1/cloud-graph/graph
- GET /api/v1/cmdb/relationships

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S16 CTEM Cycles',
  'Migrate 1 legacy pages → 1 v2 screen `S16` (CTEM Cycles).

**Purpose:** CTEM 5-stage cycle
**Route:** /exposure/ctem
**Tabs:** cycle, stage, metrics
**Filters:** (none)
**API prefixes:** /ctem, /cycle
**Backend endpoints in scope:** 15

**Sample legacy pages:**
- src/pages/PolicyLifecycleHub.tsx

**Sample backend endpoints:**
- GET /api/v1/ctem/cycles/{cycle_id}
- DELETE /api/v1/ctem/cycles/{cycle_id}
- POST /api/v1/ctem/cycles/{cycle_id}/advance
- GET /api/v1/ctem/cycles
- POST /api/v1/ctem/cycles

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S17 Findings Explorer',
  'Migrate 115 legacy pages → 1 v2 screen `S17` (Findings Explorer).

**Purpose:** Unified findings browser
**Route:** /findings
**Tabs:** all, critical, sla, duplicates
**Filters:** severity, source, status, sla
**API prefixes:** /findings, /vuln, /issues, /triage
**Backend endpoints in scope:** 3057

**Sample legacy pages:**
- src/pages/AICopilotAgentsHub.tsx
- src/pages/AgentlessScanStatus.tsx
- src/pages/AppLayerSecurityHub.tsx
- src/pages/AppSecurity.tsx
- src/pages/AssetInventory.tsx
- src/pages/AssetInventoryHub.tsx
- … +109 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- GET /api/v1/abuseipdb/ips
- POST /api/v1/agentless-snapshot/enqueue
- POST /api/v1/abuseipdb/import
- GET /api/v1/abuseipdb/check/{ip}
- GET /api/v1/abuseipdb/stats

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S18 Risk Acceptance & Waivers',
  'Migrate 7 legacy pages → 1 v2 screen `S18` (Risk Acceptance & Waivers).

**Purpose:** Waiver/acceptance lifecycle
**Route:** /findings/waivers
**Tabs:** active, expired, pending
**Filters:** status
**API prefixes:** /waiver, /exception, /risk-accept, /suppression
**Backend endpoints in scope:** 50

**Sample legacy pages:**
- src/pages/AutoWaiverRules.tsx
- src/pages/ExceptionsHub.tsx
- src/pages/RiskRegister.tsx
- src/pages/RiskRegisterDashboard.tsx
- src/pages/WaiverRequestModal.tsx
- src/pages/WaiversExplorer.tsx
- … +1 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- POST /api/v1/dlp/exceptions
- POST /api/v1/exceptions/rules
- GET /api/v1/dlp/exceptions
- POST /api/v1/endpoint-compliance/exceptions
- GET /api/v1/exceptions/rules

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S19 Threat Intelligence',
  'Migrate 11 legacy pages → 1 v2 screen `S19` (Threat Intelligence).

**Purpose:** TI feeds + IOC
**Route:** /threats/intel
**Tabs:** feeds, iocs, actors, campaigns
**Filters:** source, tlp
**API prefixes:** /intel, /threat-intel, /ioc, /feed, /ti
**Backend endpoints in scope:** 150

**Sample legacy pages:**
- src/pages/CyberThreatIntelDashboard.tsx
- src/pages/ExternalThreatIntelHub.tsx
- src/pages/FactorWeightsView.tsx
- src/pages/IOCHunter.tsx
- src/pages/SubsidiaryAttributionGraph.tsx
- src/pages/ThreatActorsHub.tsx
- … +5 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- POST /api/v1/airgap/import/threat-intel
- POST /api/v1/copilot/agents/analyst/threat-intel
- POST /api/v1/airgap/export/threat-intel
- GET /api/v1/airgap/threat-intel/info
- POST /api/v1/anomaly-ml/detect/timeseries

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S20 Detections & Alerts',
  'Migrate 24 legacy pages → 1 v2 screen `S20` (Detections & Alerts).

**Purpose:** Detection rules + alerts
**Route:** /threats/detections
**Tabs:** rules, alerts, tuning, mitre
**Filters:** severity, status
**API prefixes:** /detection, /rule, /sigma, /yara
**Backend endpoints in scope:** 97

**Sample legacy pages:**
- src/pages/AlertEnrichmentDashboard.tsx
- src/pages/AlertTriageDashboard.tsx
- src/pages/DynamicRuleDSLDashboard.tsx
- src/pages/EndpointHuntingDashboard.tsx
- src/pages/HuntingAutomationDashboard.tsx
- src/pages/HuntingHub.tsx
- … +18 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- GET /api/v1/api-abuse/rules
- GET /api/v1/ai-soc/detections
- POST /api/v1/api-abuse/rules
- PUT /api/v1/ai-soc/detections/{detection_id}/triage
- POST /api/v1/ai-soc/detections

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S21 Incidents & Response',
  'Migrate 14 legacy pages → 1 v2 screen `S21` (Incidents & Response).

**Purpose:** Incident lifecycle
**Route:** /threats/incidents
**Tabs:** queue, detail, timeline, postmortem
**Filters:** status, severity
**API prefixes:** /incident, /response, /case, /investigation, /soar
**Backend endpoints in scope:** 171

**Sample legacy pages:**
- src/pages/DetectAndRespondHub.tsx
- src/pages/IncidentCommsDashboard.tsx
- src/pages/IncidentCostsDashboard.tsx
- src/pages/IncidentExtensionsHub.tsx
- src/pages/IncidentKBDashboard.tsx
- src/pages/IncidentKnowledgeHub.tsx
- … +8 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- GET /api/v1/api-abuse/incidents
- PUT /api/v1/ai-governance/incidents/{incident_id}/resolve
- POST /api/v1/api-abuse/incidents
- GET /api/v1/ai-governance/incidents
- POST /api/v1/ai-governance/incidents

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S22 Ransomware & Malware',
  'Migrate 2 legacy pages → 1 v2 screen `S22` (Ransomware & Malware).

**Purpose:** Ransomware/malware
**Route:** /threats/malware
**Tabs:** activity, campaigns, samples
**Filters:** (none)
**API prefixes:** /ransomware, /malware, /sample
**Backend endpoints in scope:** 27

**Sample legacy pages:**
- src/pages/MalwareAnalysisDashboard.tsx
- src/pages/RansomwareProtectionDashboard.tsx

**Sample backend endpoints:**
- POST /api/v1/malware-analysis/samples
- POST /api/v1/malware-analysis/samples/{sample_id}/analyze
- GET /api/v1/malware-analysis/samples/{sample_id}
- GET /api/v1/malware-analysis/samples
- GET /api/v1/malware-analysis/

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S23 Data Security',
  'Migrate 2 legacy pages → 1 v2 screen `S23` (Data Security).

**Purpose:** Data security posture
**Route:** /data/security
**Tabs:** assets, flows, leaks
**Filters:** classification
**API prefixes:** /dspm, /data-security, /dlp, /tokenize
**Backend endpoints in scope:** 11

**Sample legacy pages:**
- src/pages/DLPDashboard.tsx
- src/pages/DataClassificationDashboard.tsx

**Sample backend endpoints:**
- GET /api/v1/dlp/results
- POST /api/v1/dlp/redact
- GET /api/v1/dlp/stats
- POST /api/v1/dlp/patterns
- GET /api/v1/dlp/results/{scan_id}

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S24 Privacy',
  'Migrate 2 legacy pages → 1 v2 screen `S24` (Privacy).

**Purpose:** Privacy/PII compliance
**Route:** /data/privacy
**Tabs:** pii, dsar, frameworks
**Filters:** (none)
**API prefixes:** /privacy, /pii, /gdpr, /ccpa, /dsar
**Backend endpoints in scope:** 27

**Sample legacy pages:**
- src/pages/PrivacyGDPRDashboard.tsx
- src/pages/PrivacyImpactDashboard.tsx

**Sample backend endpoints:**
- GET /api/v1/gdpr/consents
- GET /api/v1/gdpr/activities
- POST /api/v1/gdpr/activities
- PUT /api/v1/gdpr/consents/{consent_id}/withdraw
- POST /api/v1/gdpr/consents

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S25 Compliance & Evidence',
  'Migrate 28 legacy pages → 1 v2 screen `S25` (Compliance & Evidence).

**Purpose:** Compliance frameworks + evidence
**Route:** /compliance
**Tabs:** frameworks, controls, evidence, audits
**Filters:** framework, status
**API prefixes:** /compliance, /framework, /control, /evidence, /audit
**Backend endpoints in scope:** 320

**Sample legacy pages:**
- src/pages/AuditLog.tsx
- src/pages/AuditLogExplorer.tsx
- src/pages/CloudComplianceDashboard.tsx
- src/pages/Compliance.tsx
- src/pages/ComplianceAutomationDashboard.tsx
- src/pages/ComplianceCalendarDashboard.tsx
- … +22 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- POST /api/v1/copilot/agents/compliance/audit-evidence
- POST /api/v1/copilot/agents/compliance/map-findings
- POST /api/v1/copilot/agents/compliance/regulatory-alerts
- POST /api/v1/copilot/agents/compliance/gap-analysis
- GET /api/v1/copilot/agents/pentest/evidence/{evidence_id}

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S26 Vendor & SaaS Risk',
  'Migrate 5 legacy pages → 1 v2 screen `S26` (Vendor & SaaS Risk).

**Purpose:** Third-party risk
**Route:** /risk/vendor
**Tabs:** inventory, assessments, risk
**Filters:** (none)
**API prefixes:** /vendor, /tprm, /saas, /thirdparty, /supplier
**Backend endpoints in scope:** 53

**Sample legacy pages:**
- src/pages/SaasSecurityPostureDashboard.tsx
- src/pages/ThirdPartyVendorDashboard.tsx
- src/pages/TprmExchangeDashboard.tsx
- src/pages/VendorRiskDashboard.tsx
- src/pages/vendors/VendorManagement.tsx

**Sample backend endpoints:**
- GET /api/v1/supply-chain-monitoring/suppliers/{supplier_id}
- GET /api/v1/security-questionnaires/vendor/{vendor_id}/summary
- POST /api/v1/supply-chain-monitoring/suppliers
- GET /api/v1/supply-chain-monitoring/suppliers
- POST /api/v1/supply-chain-monitoring/suppliers/{supplier_id}/assess

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S27 IoT, OT & Endpoints',
  'Migrate 3 legacy pages → 1 v2 screen `S27` (IoT, OT & Endpoints).

**Purpose:** IoT/OT/endpoint coverage
**Route:** /risk/endpoints
**Tabs:** iot, ot, endpoints
**Filters:** category
**API prefixes:** /iot, /ot, /ics, /endpoint, /edr, /mdm
**Backend endpoints in scope:** 99

**Sample legacy pages:**
- src/pages/EndpointSecurity.tsx
- src/pages/FirmwareSecurityDashboard.tsx
- src/pages/IoTSecurityDashboard.tsx

**Sample backend endpoints:**
- GET /api/v1/api-analytics/endpoints/{endpoint:path}/stats
- GET /api/v1/api-abuse/endpoints
- POST /api/v1/api-discovery/endpoints
- GET /api/v1/api-abuse/endpoints/{endpoint_id}
- POST /api/v1/api-abuse/endpoints

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S28 AI Security',
  'Migrate 18 legacy pages → 1 v2 screen `S28` (AI Security).

**Purpose:** AI/LLM security posture
**Route:** /risk/ai-security
**Tabs:** models, prompt-defense, supply
**Filters:** (none)
**API prefixes:** /ai, /aimds, /llm, /model, /mlsec
**Backend endpoints in scope:** 117

**Sample legacy pages:**
- src/pages/AISecurityAdvisor.tsx
- src/pages/AISecurityAdvisorDashboard.tsx
- src/pages/LLMContextTierBadge.tsx
- src/pages/LLMPreFlightEstimateModal.tsx
- src/pages/ai/AIAgentsConsole.tsx
- src/pages/ai/AIAttackPathView.tsx
- … +12 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- POST /api/v1/ai-scan/snippet
- POST /api/v1/ai-governance/models
- GET /api/v1/ai-scan/stats
- POST /api/v1/ai-scan/analyze
- GET /api/v1/ai-scan/history

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S29 Integrations',
  'Migrate 7 legacy pages → 1 v2 screen `S29` (Integrations).

**Purpose:** External integrations
**Route:** /platform/integrations
**Tabs:** connectors, webhooks, mcp
**Filters:** (none)
**API prefixes:** /integration, /connector, /webhook, /mcp, /jira, /ticket
**Backend endpoints in scope:** 250

**Sample legacy pages:**
- src/pages/ConnectorMappingUI.tsx
- src/pages/IntegrationTargetsHub.tsx
- src/pages/ServiceNowDashboard.tsx
- src/pages/WebhookEventCatalogExplorer.tsx
- src/pages/WebhookIngestionHub.tsx
- src/pages/WebhookRetryConsole.tsx
- … +1 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- GET /api/v1/connectors/appomni-live/status
- GET /api/v1/connectors/appomni-live/health
- GET /api/v1/connectors/adaptive-shield-live/health
- POST /api/v1/connectors/adaptive-shield-live/sync
- GET /api/v1/connectors/adaptive-shield-live/status

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S30 Collaboration & Awareness',
  'Migrate 10 legacy pages → 1 v2 screen `S30` (Collaboration & Awareness).

**Purpose:** Team collab + awareness
**Route:** /platform/collab
**Tabs:** training, comments, notifications
**Filters:** (none)
**API prefixes:** /training, /awareness, /notification, /comment, /mention, /share, /forum
**Backend endpoints in scope:** 99

**Sample legacy pages:**
- src/pages/AwarenessCampaignDashboard.tsx
- src/pages/AwarenessHub.tsx
- src/pages/AwarenessMetricsDashboard.tsx
- src/pages/AwarenessProgramDashboard.tsx
- src/pages/AwarenessScoreDashboard.tsx
- src/pages/SecurityAwareness.tsx
- … +4 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- GET /api/v1/awareness-campaigns/campaigns/{campaign_id}
- POST /api/v1/awareness-campaigns/campaigns/{campaign_id}/participations
- POST /api/v1/awareness-campaigns/campaigns
- GET /api/v1/awareness-campaigns/campaigns
- PATCH /api/v1/awareness-campaigns/campaigns/{campaign_id}/status

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
INSERT INTO issue (
  workspace_id, title, description, status, priority,
  assignee_type, assignee_id, creator_type, creator_id, number
) VALUES (
  '30fad00d-8273-4196-96d4-abd55f4cbb43',
  '[CONSOLIDATION] S31 Settings & Admin',
  'Migrate 16 legacy pages → 1 v2 screen `S31` (Settings & Admin).

**Purpose:** Org admin + settings
**Route:** /admin
**Tabs:** org, users, tokens, billing, system
**Filters:** (none)
**API prefixes:** /admin, /setting, /billing, /license, /preference, /config
**Backend endpoints in scope:** 41

**Sample legacy pages:**
- src/pages/Admin.tsx
- src/pages/AirGapBundleConsole.tsx
- src/pages/AirGapBundleDashboard.tsx
- src/pages/AirGapHub.tsx
- src/pages/SoftwareLicenseDashboard.tsx
- src/pages/SystemHealthDashboard.tsx
- … +10 more (see suite-ui/aldeci-ui-new/page_to_screen_map.csv)

**Sample backend endpoints:**
- POST /api/v1/admin/teams
- GET /api/v1/admin/teams/{team_id}
- GET /api/v1/admin/teams
- PUT /api/v1/admin/teams/{team_id}
- DELETE /api/v1/admin/teams/{team_id}

**Phase:** Phase-2 PR (in-scope), Phase-1 stub (skeleton).
**See:** suite-ui/aldeci-ui-new/MIGRATION_AUDIT.md',
  'todo',
  'medium',
  'agent', '00000000-0000-0000-0000-000000000001',
  'agent', '00000000-0000-0000-0000-000000000001',
  (SELECT COALESCE(MAX(number),0)+1 FROM issue WHERE workspace_id='30fad00d-8273-4196-96d4-abd55f4cbb43')
);
COMMIT;