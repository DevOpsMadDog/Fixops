---
source_url: internal://research-20260422
captured_at: 2026-04-22T11:34:59Z
author: fixops-inventory-researcher-agent
contributor: claude-code-opus-4-7
---

# Fixops Platform Comprehensive Inventory

**Generated:** 2026-04-22  
**Branch:** features/intermediate-stage  
**Codebase Location:** `/Users/devops.ai/fixops/Fixops`

---

## Executive Summary

**Frontend Pages:** 445 TSX screens  
**API Endpoints:** 573 router modules with 625+ import statements  
**Core Engines:** 345 specialized security engines  
**Database Models:** 6 P0 tables (Finding, ExposureCase, PipelineRun, EvidenceBundle, AuditLog, MCPSession)  
**Integrations:** GitHub, GitLab, Prowler, ServiceNow, Splunk HEC, Microsoft Sentinel, Jira, Slack, n8n  
**Background Services:** Pipeline workers, report schedulers, webhook verifiers, event bus  

---

## 1. Frontend Screens (445 Total)

### Structure
- **Primary UI Suite:** `suite-ui/aldeci-ui-new/` (413 screens)
- **Legacy UI Suite:** `suite-ui/aldeci/` (32 screens)
- **Framework:** React + React Router + TypeScript
- **Component Library:** shadcn/ui, Recharts, Framer Motion, Lucide Icons
- **Data Fetching:** TanStack React Query
- **API Client:** Custom `analyticsApi` wrapper

### Screen Distribution

#### aldeci-ui-new (413 screens)
**Top-Level Dashboards (296 screens)**
- Main dashboards for all security domains: CISO, SOC, Cloud Security, Vulnerability, Compliance, etc.
- Patterns: `*Dashboard.tsx`, `*Report.tsx`, `*Console.tsx`
- Representative: CISOReportDashboard, MainOverviewDashboard, AlertTriageDashboard, VulnPrioritizationDashboard

**Organized by Domain:**
- **Mission Control (14):** CISODashboard, SOCDashboard, CommandDashboard, ExecutiveView, LiveFeed, RiskOverview, RiskRegister, SLADashboard, SOCT1Dashboard, ThreatIntelDashboard, ComplianceDashboard, DevSecurityDashboard
- **AI/ML (6):** BrainPipeline, CopilotDashboard, AlgorithmicLab, MLDashboard, MultiLLM, Predictions
- **Remediation (7):** RemediationCenter, AutoFix, BulkOperations, ExposureCases, TicketIntegration, Collaboration, Workflows
- **Compliance (10):** ComplianceDashboard, EvidenceBundles, EvidenceVault, AuditTrail, SLSAProvenance, SOC2Evidence, Reports, Analytics, EvidenceExportCenter
- **Discover (12):** FindingExplorer, CloudPosture, CodeScanning, ContainerSecurity, CorrelationEngine, DataFabric, IaCScanning, KnowledgeGraph, SBOMInventory, SecretsDetection, ThreatFeeds
- **Attack Surface (Attack):** AttackPaths, AttackSimulation, MicroPentest (MPTE), Reachability, FAILEngine, Playbooks, PlaybookEditor
- **Threat Hunting (2):** ThreatHunting dashboard + ThreatHunting page
- **Incident Response (2):** IncidentResponse dashboard + incidents folder page
- **Integrations (2):** IntegrationHealth dashboard + settings page
- **Vendor Management (2):** VendorManagement page + dashboard
- **Risk Management (1):** RiskAcceptance
- **SBOM (1):** SBOMManagement
- **Settings (9):** Settings hub, Users, Teams, Integrations, Marketplace, Policies, LogViewer, SystemHealth
- **Auth (2):** LoginPage, AccessDenied
- **Navigation (2):** LandingPage, NotFound

#### aldeci (Legacy UI - 32 screens)
- Attack lab: AttackPaths, AttackSimulation, MicroPentest, MPTEConsole, Reachability, SandboxVerification
- Cloud: CloudPosture, ContainerSecurity, CorrelationEngine, RuntimeProtection, ThreatFeeds
- Code: CodeScanning, IaCScanning, Inventory, SBOMGeneration, SecretsDetection
- Core: BrainPipelineDashboard, ExposureCaseCenter, KnowledgeGraphExplorer
- Evidence: AuditLogs, ComplianceReports, EvidenceAnalytics, EvidenceBundles, Reports, SLSAProvenance, SOC2EvidenceUI
- Feeds: LiveFeedDashboard
- AI: AlgorithmicLab, MLDashboard, MultiLLMPage, Policies, Predictions, SelfLearningDemo
- Protect: AutoFixDashboard, BulkOperations, Collaboration, Integrations, PlaybookEditor, Playbooks, Remediation, Workflows
- Discover: ScannerDashboard, ScannerIngestUpload
- Settings: IntegrationsSettings, LogViewer, Marketplace, MCPToolRegistry, OverlayConfig, SystemHealth, Teams, Users, Webhooks
- Top-level: Dashboard, Copilot, DataFabric, DecisionEngine, EvidenceVault, IntelligenceHub, NerveCenter, RemediationCenter, Settings

### Key Patterns Observed
- **Real API Integration:** Most dashboards call `analyticsApi.<method>()` with useQuery
- **Mock Data:** Fallback mock data in several pages (e.g., risk scoring examples)
- **Loading States:** PageSkeleton + ErrorState components used consistently
- **Real-time Updates:** Some pages support WebSocket connections via `websocket_alerts_router`
- **Visualization:** Recharts (Area, Pie, Bar), custom D3 components for network topology

---

## 2. API Surface (573 Routers, 625+ Imports)

### Architecture
- **Framework:** FastAPI (Python)
- **Entry Point:** `suite-api/apps/api/app.py`
- **Auth Mechanism:** API Key + JWT + Role-based (require_role decorator)
- **Response Format:** Pydantic models → JSON

### Router Categories & Counts

**Core Platform (15+ routers)**
- `admin_router.py` — User/team management (GET/POST/PUT/DELETE /admin/users, /admin/teams)
- `auth_router.py` — Login, token refresh, API key management
- `users_router.py` + `users_public_router.py` — User profile, password reset
- `teams_router.py` — Team CRUD + membership
- `system_router.py` — System health, config, resource usage
- `metrics_router.py` — Prometheus metrics export
- `platform_router.py` — Platform-level settings
- `audit_router.py` — Audit log queries
- `change_management_router.py` — Change tracking (drift, material changes)
- `workflows_router.py` — Workflow execution, state transitions
- `collaboration_router.py` — Comments, mentions, team chat
- `webhook_router.py` + `webhook_verifier_router.py` — Webhook registration & verification
- `webhook_events_router.py` — Webhook event replaying

**Security Discovery & Analysis (120+ routers)**
- **Vulnerability Management (15+):** `vuln_intelligence_router`, `vuln_lifecycle_router`, `vuln_enricher_router`, `vuln_prioritization_router`, `vuln_scan_router`, `vulnerability_scoring_engine_router`, `cve_search_router`
- **Cloud Security (20+):** `cloud_posture_router`, `cloud_security_engine_router`, `cloud_security_analytics_router`, `cspm_router`, `cspm_deep_router`, `cnapp_router`, `cloud_compliance_router`, `cloud_identity_router`, `cloud_drift_router`, `cloud_access_security_router`, `cloud_workload_protection_router`, `cloud_native_security_router`, `cloud_cost_optimization_router`, `cloud_account_monitoring_router`
- **Container Security (8+):** `container_router`, `container_security_posture_router`, `container_runtime_security_router`, `container_registry_security_router`, `cwpp_router`, `kubernetes_security_router`
- **Code Scanning (10+):** `iac_scanner_router`, `secret_scanner_router`, `sast_router`, `dast_router`, `sbom_router`, `sbom_export_router`, `software_composition_analysis_router`, `dependency_mapping_router`
- **Network Security (15+):** `network_security_router` (NDR), `network_monitoring_router`, `network_anomaly_router`, `network_segmentation_router`, `network_topology_router`, `network_traffic_router`, `network_forensics_router`, `firewall_management_router`, `firewall_policy_router`, `waf_router`, `ddos_protection_router`, `wireless_security_router`
- **Attack Surface Management (8+):** `attack_surface_router`, `api_discovery_router`, `api_inventory_router`, `api_security_router`, `api_security_mgmt_router`, `api_security_engine_router`, `api_abuse_router`, `api_abuse_detection_router`
- **Compliance & GRC (20+):** `compliance_engine_router`, `compliance_mapping_router`, `compliance_automation_router`, `compliance_scanner_router`, `compliance_workflow_router`, `privacy_gdpr_router`, `gdpr_compliance_router`, `regulatory_tracker_router`, `regulatory_reporting_router`, `grc_engine_router`, `control_testing_router`, `gap_router`, `risk_register_router`, `risk_acceptance_router`, `risk_quantification_router`
- **Identity & Access (15+):** `identity_governance_router`, `identity_lifecycle_router`, `identity_risk_router`, `identity_analytics_router`, `access_control_router`, `access_governance_router`, `access_anomaly_router`, `pam_router`, `privileged_identity_router`, `mfa_management_router`, `rbac_router`
- **Threat Intelligence (18+):** `threat_intelligence_automation_router`, `threat_intel_enrichment_router`, `threat_intel_platform_router`, `threat_intel_fusion_router`, `threat_hunting_router`, `threat_hunting_playbook_router`, `threat_actor_router`, `threat_actor_tracking_router`, `threat_attribution_router`, `threat_modeling_router`, `threat_correlation_router`, `ioc_enrichment_router`, `ip_reputation_router`, `dark_web_monitoring_router`, `passive_dns_router`
- **Endpoint Security (12+):** `endpoint_security_router`, `endpoint_compliance_router`, `endpoint_threat_hunting_router`, `edr_router`, `mdm_router`, `nac_router`, `rasp_router`, `ciem_router`, `itdr_router`
- **Other Domain Engines (30+):** `malware_analysis_router`, `incident_response_router`, `breach_detection_router`, `ransomware_protection_router`, `insider_threat_router`, `deception_engine_router`, `behavioral_analytics_router`, `supply_chain_risk_router`, `risk_quantification_router`, `cyber_insurance_router`, etc.

**AI/ML & Automation (25+ routers)**
- `ai_orchestrator_router` — Multi-agent LLM coordination for security decisions
- `ai_governance_router` — AI model governance, explainability
- `ai_security_advisor_router` — LLM-powered security recommendations
- `ai_powered_soc_router` — Autonomous SOC decision making
- `anomaly_ml_router` — Behavioral analytics, UEBA, isolation forest
- `anomaly_router` — Spike/drop/drift/threshold detection
- `copilot_router` — Interactive LLM assistant for security tasks
- `algorithmic_router` — Graph algorithms, attack path computation
- `decision_engine_router` — Policy-driven decision engine (via `policy_engine.py`)
- `policy_engine_router` — OPA-compatible policy enforcement
- `playbook_router` — Playbook execution and orchestration
- `playbook_engine_router` — Playbook compilation and validation
- Unnamed LLM routing: OpenRouter, MuleRouter, Ollama backends configured via env vars

**Remediation & Response (12+ routers)**
- `autofix_router` — AI-powered code fix generation + PR automation
- `autofix_verify_router` — Fix verification and rollback
- `remediation_router` — Remediation task lifecycle
- `remediation_engine_router` — Remediation workflow engine
- `autonomous_remediation_router` — Auto-remediation decision + execution
- `sla_router` — SLA definition and tracking
- `sla_engine_router` — SLA escalation and breach detection
- `security_automation_router` — Task automation
- `incident_response_router` — IR workflow and playbook execution
- `soc_triage_router` — SOC alert triage
- `alert_triage_router` — Alert ingestion and triage (SIEM, EDR, NDR, Cloud, WAF, IDS, Firewall)
- `alert_enrichment_router` — Alert enrichment with threat intel
- `fail_router` — FAIL engine (Fast AI-powered Log parser?)

**Knowledge & Graph (18+ routers)**
- `brain_router` — Brain Pipeline orchestration
- `pipeline_router` — Brain Pipeline step scheduling
- `pipeline_routes` — CTEM pipeline endpoints
- `trustgraph_routes` — Knowledge graph queries
- `trustgraph_core_router` — TrustGraph entity/edge management
- `trustgraph_quality_router` — Graph data quality monitoring
- `trustgraph_maintenance_router` — Graph recomputation and optimization
- `trustgraph_integration_router` — Graph data import/export
- `trustgraph_migrator_router` — Schema migrations
- `trustgraph_backbone_router` — Core graph operations
- `knowledge_brain_router` — Unified knowledge base
- `graph_router` — General graph query API
- `security_data_pipeline_router` — Data normalization pipeline
- `correlation_engine_router` — Finding correlation and deduplication
- `findings_router` — Finding CRUD + analytics
- `exposure_case_router` — Exposure case management
- `threat_correlation_router` — Cross-threat correlation

**Integrations (30+ routers)**
- **ServiceNow:** `servicenow_sync_router` + `servicenow_sync_webhook_router` (bidirectional ticket sync)
- **Ticket Systems:** `jira_integration_router`, `slack_integration_router`
- **Connectors:** `connectors_router` (universal Jira + GitHub + Slack fan-out)
- **CI/CD:** `github_action_router`, `gitlab_ci_router`
- **Scanners:** `prowler_router`, `nessus_router`, `qualys_router`, `rapid7_router`, `tenable_router`
- **SIEM Output:** `siem_output_router` (sends findings to Splunk, Sentinel, etc.)
- **Webhook:** `webhook_router` (inbound webhooks from any tool)
- **MCP (Claude Protocol):** `mcp_router`, `mcp_gateway_router` (AI agent integration)
- **N8N:** Via report scheduler webhooks
- **Evidence:** `evidence_chain_router` (tamper-proof compliance audit trail)

**Reporting & Analytics (12+ routers)**
- `reports_router` — Report generation and scheduling
- `report_scheduler_router` — Scheduled delivery (daily/weekly/monthly)
- `analytics_router` — Large-scale security analytics (41KB file)
- `analytics_dashboard_router` — Dashboard analytics queries
- `analytics_engine_router` — Analytics computation
- `executive_reporting_router` — Executive summary generation
- `ciso_report_router` — CISO-specific metrics
- `metrics_router` — KPI and metric aggregation
- `kpi_engine_router` — KPI computation engine

**Gating & Enforcement (8+ routers)**
- `gate_router` — PR/CI/CD gating
- `pr_gate_router` — GitHub PR check integration
- `ci_cd_gate_router` — CI/CD pipeline gating
- `policy_enforcement_router` — Real-time policy enforcement
- `policy_engine_router` — Policy evaluation
- `security_policy_router` — Security policy management
- `exception_router` — Security exception workflow

**Admin & System (15+ routers)**
- `admin_router` — User and team management
- `sso_router` — Single sign-on (OIDC, SAML)
- `api_gateway_router` — API gateway configuration
- `api_gateway_security_router` — API security policies
- `rate_limiting_router` — Rate limit configuration
- `api_docs_router` — API documentation
- `system_router` — System diagnostics
- `marketplace_router` — Plugin marketplace
- `settings_router` — Platform settings
- `inventory_router` — Asset inventory
- `asset_inventory_router` — Asset CRUD + grouping
- `asset_tagging_router` — Asset tagging
- `cmdb_router` — Configuration management DB

**Purple Team & Testing (5+ routers)**
- `purple_team_router` — Integrated attack/defense testing
- `attack_simulation_router` — Simulated attack campaigns
- `pentest_mgmt_router` — Penetration test lifecycle
- `red_team_router` — Red team operations
- `red_team_mgmt_router` — Red team asset + campaign management

**Real-time & Events (5+ routers)**
- `websocket_routes` — WebSocket alert streaming
- `websocket_alerts_router` — Alert push notifications
- `ws_events_router` — Event bus WebSocket gateway
- `event_bus_router` — Event bus REST API (status, queue, flush, config)
- `trustgraph_event_bus.py` — Event bus implementation

**Other Specialized (40+)**
- Certificate management, digital forensics, email security, DLP, encryption, zero trust, supply chain, cyber insurance, security awareness, training, vendor risk, third-party risk, budget/investment tracking, OKR tracking, risk scenarios, threat modeling, mobile security, IoT security, OT security, ZTNA, CASB, AND MANY MORE

### Data Flow Through Routers
1. **Request → Pydantic Validation** (e.g., `GenerateFixRequest`, `TriageAlertRequest`)
2. **Auth Check** (api_key_auth, require_role dependencies)
3. **Engine Lookup** (lazy-loaded singleton from `core/` module)
4. **Business Logic** (engine method called)
5. **Response Model** (Pydantic serialization → JSON)

### Sample Router: Alert Triage
```python
# suite-api/apps/api/alert_triage_router.py
Prefix: /api/v1/alert-triage
Auth: api_key_auth + role check (analyst, security_engineer, etc.)
Routes:
  POST   /alerts              ingest_alert (title, source_system, severity, raw_alert_json)
  GET    /alerts              list_alerts (org_id filtered)
  GET    /alerts/{id}         get_alert
  PATCH  /alerts/{id}/triage  triage_alert (status, assigned_to, notes, escalation_reason)
  POST   /bulk-triage         bulk_triage (alert_ids, action: acknowledge/resolve/false_positive/escalate)
  GET    /queue               get_triage_queue
  GET    /stats               get_triage_stats
Response: Dict[str, Any] with org_id, alerts, total
```

---

## 3. Modules / Engines

### Core Architecture Pattern
- **345 Engine Classes** in `suite-core/core/*_engine.py`
- **Single Responsibility:** Each engine handles one security domain
- **Lazy Loading:** Engines instantiated on-demand from routers
- **Singleton Pattern:** Global instances to avoid re-initialization

### Major Engine Clusters

**1. Brain Pipeline (12 Steps)**
- **File:** `suite-core/core/brain_pipeline.py`
- **Purpose:** Orchestrate the 12-step vulnerability remediation + compliance pipeline:
  1. **Connect** — Aggregate findings from all scanners/connectors
  2. **Normalize** → UnifiedFinding data model
  3. **Resolve Identity** → Dedupe same asset across sources
  4. **FP Auto-Suppress** → Remove known false positives
  5. **Deduplicate** → Collapse duplicate findings
  6. **Build Graph** → Knowledge graph construction
  7. **Enrich Threats** → EPSS, KEV, CVSS enrichment
  8. **Score Risk** → GNN + graph algorithms compute risk
  9. **Apply Policy** → Policy engine filters exposure cases
  10. **LLM Consensus** → Multi-LLM agreement on severity/action
  11. **Micro-Pentest** → MPTE validates exposure is real
  12. **Generate Evidence** → SOC2 Type II compliance bundle
- **Data Model:** `PipelineInput`, `PipelineResult`, `StepResult`, `PipelineStatus` (pending/running/completed/failed/partial)
- **Execution:** Synchronous or queued via `PipelineWorker`
- **Key Methods:** run(), step(), publish_result()

**2. Knowledge Brain (Central Graph)**
- **File:** `suite-core/core/knowledge_brain.py`
- **Purpose:** Unified knowledge graph storing ALL security entities and relationships
- **Entities (25+ types):** CVE, CWE, CPE, ASSET, FINDING, REMEDIATION, ATTACK, EVIDENCE, USER, TEAM, SCAN, SESSION, CLUSTER, BUNDLE, TASK, WORKFLOW, REPORT, INTEGRATION, POLICY, COMMENT, COMPONENT, SERVICE, FEED, THREAT_ACTOR, TECHNIQUE, PLAYBOOK, ORGANIZATION, EXPOSURE_CASE, CONNECTOR, ALERT, AGENT
- **Edges (20+ types):** EXPLOITS, MITIGATES, AFFECTS, CHAINS_TO, CORRELATES_WITH, BELONGS_TO, CREATED_BY, ASSIGNED_TO, CONTAINS, TAGGED_WITH, RELATED_TO, TRIGGERED_BY
- **Backend:** SQLite + NetworkX (proven pattern from ProvenanceGraph)
- **Concurrency:** Thread-safe with locks
- **Features:** Path discovery, node traversal, bulk import/export

**3. TrustGraph (Event-Driven Graph)**
- **Files:** `suite-core/core/trustgraph_*.py` (7 files)
- **Purpose:** Event-driven graph that auto-updates when entities change
- **Components:**
  - `trustgraph_event_bus.py` — Redis-backed event queue with offline fallback
  - `trustgraph_indexer.py` — Full-text search indexing
  - `trustgraph_quality_monitor.py` — Data quality + cycle detection
  - `trustgraph_integrations.py` — Third-party sync (ServiceNow, Jira, etc.)
  - `trustgraph_migrator.py` — Schema evolution + backfill
  - `trustgraph_core_router.py` — Graph entity/edge CRUD
- **Event Types:** finding.created, asset.updated, remediation.completed, etc.
- **Publishing:** REST API (`event_bus_router`) + WebSocket

**4. AutoFix Engine**
- **File:** `suite-core/core/autofix_engine.py`
- **Purpose:** AI-powered vulnerability remediation
- **Features:**
  - Code fix generation (language-aware: Python, Java, Go, etc.)
  - Patch type detection (code fix, config update, upgrade, pinning)
  - Automated PR creation to GitHub/GitLab
  - Fix verification (tests, linting, SBOM re-scan)
  - Rollback on verification failure
- **LLM Integration:** OpenRouter, MuleRouter, or Ollama backend
- **Router:** `suite-api/apps/api/autofix_router.py`
  - POST /generate-fix (GenerateFixRequest)
  - POST /apply-fix (ApplyFixRequest with repo context)
  - GET /pr-status (track PR lifecycle)

**5. Alert Triage Engine**
- **File:** `suite-core/core/alert_triage_engine.py`
- **Purpose:** Unified alert triage across SIEM, EDR, NDR, Cloud, WAF, IDS, Firewall
- **Workflow:** Ingest → Normalize → Enrich → Triage (new|triaging|escalated|investigating|resolved|false_positive|duplicate)
- **Queue Management:** Redis or in-memory fallback
- **Assignees:** Route to analysts by role/skill
- **Escalation:** SLA-aware escalation rules

**6. Policy Engine**
- **Files:** `suite-core/core/policy_engine.py`, `suite-core/core/services/enterprise/real_opa_engine.py`
- **Purpose:** Policy-as-code evaluation (OPA-compatible)
- **Policies Supported:**
  - Risk scoring rules
  - Exception approval workflows
  - Remediation prioritization
  - Compliance control mapping
- **Integration:** CTEM Pipeline step 8 (apply_policy)

**7. Threat Intelligence Engines**
- **15+ dedicated threat intel engines**
- **Feeds:** CERTs, APT trackers, dark web monitors, passive DNS
- **Correlation:** Cross-feed threat actor matching
- **Enrichment:** Threat actor TTP extraction from raw intel

**8. Compliance Engines**
- **Compliance Engine** — Framework mapping (PCI-DSS, ISO 27001, SOC 2, HIPAA, GDPR)
- **Evidence Chain Engine** — Tamper-proof cryptographic audit trail
- **Privacy GDPR Engine** — Data classification + retention + DPA tracking
- **Regulatory Tracker** — Regulatory deadline + audit scheduling

**9. Anomaly Detection Engines**
- **Anomaly ML Engine** — Behavioral analytics, UEBA, Isolation Forest
- **Anomaly Router** — Spike, drop, drift, threshold, unusual timing detection
- **Network Anomaly Engine** — Flow anomalies, port scanning, data exfiltration
- **Behavioral Analytics Engine** — User risk scoring

**10. Cloud Security Engines**
- **CSPM** (Cloud Security Posture Management) — Config audit, CIS benchmarks
- **CNAPP** (Cloud Native Application Protection) — K8s, container image scanning
- **CWPP** (Cloud Workload Protection) — Runtime protection
- **CIEM** (Cloud Infrastructure Entitlement Management) — Over-privilege detection
- **Cloud Drift** — Configuration change tracking
- **Cloud Cost Optimization** — Cost + security tradeoff analysis

**11. Incident Response Engines**
- **Incident Response** — Investigation workflow, playbook execution
- **Breach Detection** — Automated breach confirmation
- **Breach Response** — Response playbook automation
- **Incident Timeline** — Event correlation + time-ordered narrative
- **Incident Comms** — Stakeholder notifications

**12. Identity & Access Engines**
- **Identity Governance** — Role review, access certification
- **Privileged Identity** — PAM-integrated session recording
- **Access Anomaly** — Unusual access pattern detection
- **MFA Management** — Enforcement + device inventory

---

## 4. Data Model

### Core Tables (Alembic Migrations)

**Migration 001: Initial Schema** (`alembic/versions/001_initial_schema.py`)

```
findings
  id (UUID)
  org_id (String 64) — multi-tenant
  title, severity, cve_id, cwe_id, asset_name, source
  risk_score, epss_score, kev (bool)
  status ('open' | 'closed')
  correlation_key (for dedup)
  created_at, updated_at
  INDICES: org_id, severity, cve_id, status (filtered where != 'closed')

exposure_cases
  case_id (UUID)
  org_id
  title, priority, risk_score
  finding_ids (JSONB), finding_count
  created_at
  INDICES: org_id, priority

pipeline_runs
  run_id (UUID)
  org_id
  status ('pending' | 'running' | 'completed' | 'failed')
  step_results (JSONB) — array of step execution records
  findings_processed
  started_at, completed_at, duration_ms
  INDICES: org_id, status

evidence_bundles
  bundle_id (UUID)
  org_id
  framework ('soc2' | 'iso27001' | 'pci-dss' | 'hipaa')
  findings_covered (JSONB)
  evidence_items (JSONB) — proofs of control effectiveness
  signature (cryptographic)
  signed_at
  INDICES: org_id, framework

audit_logs
  log_id (UUID)
  org_id
  actor (username)
  action ('create' | 'update' | 'delete')
  resource_type, resource_id
  changes (JSONB)
  timestamp
  APPEND_ONLY (no updates/deletes)
  INDICES: org_id, timestamp

mcp_sessions
  session_id (UUID)
  org_id
  agent_id (Claude Agent ID)
  conversation_history (JSONB)
  started_at, last_activity, ended_at
  status ('active' | 'paused' | 'completed' | 'errored')
  INDICES: org_id, agent_id, status
```

**Migration 002: P0 Models** (`alembic/versions/002_add_p0_models.py`)

### SQLAlchemy ORM Models (`suite-core/core/db/models.py`)

Defined for dual-dialect (PostgreSQL + SQLite) compatibility:
- **String(36)** for UUIDs (no postgresql.UUID)
- **JSON** for arrays (no postgresql.ARRAY or JSONB)
- **All models have org_id** for multi-tenant isolation
- **All timestamps UTC** with server_default=CURRENT_TIMESTAMP

### Enterprise Models (Legacy, in enterprise/ subdirs)
- User, UserRole, Team, UserStatus
- Organization, APIKey
- Stored in `suite-core/core/db/enterprise/migrations/`

---

## 5. Integrations

### GitHub/GitLab
- **Files:** `suite-integrations/integrations/github/adapter.py`
- **Features:**
  - AutoFix PR creation + merge
  - Code scan gating (PR checks)
  - PR approval workflows
- **Trigger:** Findings trigger PR creation in target repo

### Prowler (Cloud Security)
- **File:** `suite-integrations/prowler/prowler_connector.py`
- **Purpose:** Ingest Prowler cloud config findings (AWS, GCP, Azure)
- **Integration:** Polling or Webhook
- **Output:** Normalized to UnifiedFinding

### ServiceNow (ITSM)
- **Files:** `suite-integrations/servicenow/servicenow_*.py` (connector, engine, router)
- **Features:**
  - Bidirectional ticket sync (create/update/link)
  - Change management (CHG ticket linking)
  - Incident tracking (INC auto-creation from breaches)
  - CMDB integration (asset sync)
- **Router:** `servicenow_sync_router` + `servicenow_sync_webhook_router`
- **Status:** Wired (SSRF-VULN-03 security note in code)

### Splunk HEC (Log Ingestion)
- **File:** `suite-integrations/siem_connectors/splunk_hec_connector.py`
- **Purpose:** Send findings, alerts, events to Splunk via HTTP Event Collector
- **Trigger:** Finding enrichment, alert triage completion
- **Data:** JSON formatted finding record

### Microsoft Sentinel (SIEM)
- **File:** `suite-integrations/siem_connectors/sentinel_connector.py`
- **Purpose:** Send findings to Sentinel incident API
- **Integration:** Azure credentials + API endpoint

### Jira
- **Via connectors_router** (universal fan-out)
- **Features:** Ticket creation, status sync, linking to findings
- **Status:** Wired through universal connectors

### Slack
- **Via connectors_router**
- **Features:** Alert notifications, digest messages, workflow approvals
- **Channels:** Security, incident-response, compliance, etc.

### n8n (Workflow Automation)
- **Integration Point:** `report_scheduler.py` webhooks
- **Purpose:** Scheduled report generation and multi-channel delivery
- **Supported Channels:** Email, Slack
- **Report Types:** executive_summary, vulnerability_digest, compliance_status, threat_intel_brief, kpi_scorecard
- **Webhooks:** `N8N_BASE_URL/webhook/aldeci-report-delivery`

### GitHub Actions / GitLab CI
- **Files:** `suite-integrations/github-action/`, `suite-integrations/gitlab-ci/`
- **Features:** Inline security scanning, PR gating, CI/CD gate integration
- **Gate Router:** `gate_router`, `pr_gate_router`, `ci_cd_gate_router`

### API Documentation / Developer Portal
- **File:** `suite-api/apps/api/api_docs_router.py`
- **Pages:** `suite-ui/aldeci-ui-new/src/pages/developer/DeveloperPortal.tsx`, `APIExplorer.tsx`
- **Features:** Interactive API docs, sandbox testing, API key management

### MCP (Claude Protocol)
- **Files:** `suite-api/apps/api/mcp_router.py`, `mcp_gateway_router.py`, `connectors/trustgraph_mcp_bridge.py`
- **Purpose:** Enable Claude agents to query/modify security data
- **Sessions:** Tracked in `mcp_sessions` table

---

## 6. Background Services

### Pipeline Worker
- **File:** `suite-core/core/pipeline_worker.py`
- **Purpose:** Standalone process consuming Brain Pipeline steps from Redis
- **Execution:** `python -m core.pipeline_worker --queue=default --worker-id=worker-1`
- **Workflow:**
  1. Register heartbeat (refreshed every 10s)
  2. Block on dequeue_step() waiting for work
  3. Dispatch to appropriate BrainPipeline method
  4. Publish result back via publish_result()
  5. Repeat until SIGTERM/SIGINT
- **Steps Handled:**
  - Remote (heavy): enrich_threats, score_risk, llm_consensus, llm_council
  - Local (lightweight): connect, normalize, resolve_identity, fp_auto_suppress, deduplicate, build_graph, apply_policy, micro_pentest, run_playbooks, generate_evidence
- **Queue:** Redis or local fallback via `queue_manager.py`

### Report Scheduler
- **File:** `suite-core/core/report_scheduler.py`
- **Purpose:** Generate and deliver security reports via n8n webhooks
- **Database:** `data/report_schedules.db` (SQLite with WAL)
- **Report Types:** executive_summary, vulnerability_digest, compliance_status, threat_intel_brief, kpi_scorecard
- **Frequencies:** daily, weekly, monthly
- **Delivery Channels:** email, slack (via n8n)
- **Formats:** json, html, pdf
- **Tables:**
  - `schedules` — delivery config with recipients, filters, next_run_at
  - `delivery_log` — past deliveries with status
- **Execution:** Scheduled via n8n or manually triggered

### Graph Worker
- **File:** `scripts/graph_worker.py`
- **Purpose:** Worker for knowledge graph computation (likely background indexing)
- **Execution:** `python scripts/graph_worker.py`

### Event Bus (TrustGraph)
- **File:** `suite-core/core/trustgraph_event_bus.py`
- **Purpose:** Redis-backed event queue for knowledge graph updates
- **Features:**
  - Offline queue fallback (SQLite)
  - Event type filtering
  - Registered handlers per event type
  - Master enable/disable switch
- **REST API:** `event_bus_router` (/api/v1/event-bus/status, /queue, /flush, /config)
- **WebSocket:** `ws_events_router` (push notifications)

### Webhook Verifiers
- **File:** `suite-api/apps/api/webhook_verifier_router.py`
- **Purpose:** Verify webhook signatures (HMAC-SHA256)
- **Integration:** Validate inbound webhooks from GitHub, GitLab, ServiceNow, etc.

### Task Queue
- **File:** `suite-core/core/task_queue.py`
- **Purpose:** General-purpose async task execution
- **Backend:** Redis or in-memory fallback

### Pentest Scheduler
- **File:** `suite-core/core/pentest_scheduler.py`
- **Purpose:** Schedule and orchestrate penetration tests
- **Features:** Campaign management, scope definition, result aggregation

### Free Model Worker
- **File:** `scripts/free_model_worker.py`
- **Purpose:** Fallback LLM worker using free models (likely Ollama local)
- **Context:** When OpenRouter/MuleRouter are unavailable

### LLM Routing
- **Configuration:** Environment variables
  - `OPENROUTER_API_KEY` → Use OpenRouter API
  - `MULE_ROUTER_ENDPOINT` → Use MuleRouter
  - `OLLAMA_ENDPOINT` → Use local Ollama
- **Default Behavior:** Auto-detect available backend
- **Engines Affected:** autofix_engine, anomaly_ml_engine, ai_orchestrator_router, decision_engine, playbook_engine

---

## 7. Screen Count & API Count Summary

| Category | Count |
|----------|-------|
| **Frontend Pages (TSX)** | **445** |
| – aldeci-ui-new (new UI) | 413 |
| – aldeci (legacy UI) | 32 |
| **API Router Modules** | **573** |
| – Core Platform | 15+ |
| – Security Discovery & Analysis | 120+ |
| – AI/ML & Automation | 25+ |
| – Remediation & Response | 12+ |
| – Knowledge & Graph | 18+ |
| – Integrations | 30+ |
| – Reporting & Analytics | 12+ |
| – Gating & Enforcement | 8+ |
| – Admin & System | 15+ |
| – Purple Team & Testing | 5+ |
| – Real-time & Events | 5+ |
| – Other Specialized | 40+ |
| **Core Engines** | **345** |
| – Brain Pipeline Steps | 12 |
| – Knowledge Brain | 1 |
| – TrustGraph | 1 |
| – AutoFix | 1 |
| – Alert Triage | 1 |
| – Other Domain Engines | 329+ |
| **Database Tables** | **6** |
| **Background Services** | **8+** |
| **Integration Points** | **9+** |
| **Alembic Migrations** | **2** |

---

## 8. Platform Capabilities Snapshot

### Security Domains Covered
CTEM, CSPM, CNAPP, ASPM, NDR, EDR, XDR, SIEM Integration, Cloud Security, Container Security, Code Scanning, Vulnerability Management, Compliance & GRC, Identity & Access Governance, Threat Intelligence, Incident Response, Threat Hunting, Attack Surface Management, API Security, Zero Trust, Supply Chain Risk, Insider Threat, Ransomware Protection, Breach Detection, Cyber Insurance, Security Awareness, Physical Security, Operational Technology (OT), IoT Security, Quantum-Safe Cryptography.

### Key Differentiators
1. **12-Step Brain Pipeline** — Unique CTEM orchestration across discovery → enrichment → policy → LLM consensus → MPTE verification → evidence
2. **Knowledge Brain + TrustGraph** — Unified entity graph with event-driven updates
3. **Multi-LLM Orchestration** — OpenRouter, MuleRouter, Ollama backend selection
4. **Bidirectional ServiceNow Sync** — Real-time ticket + CMDB + change management
5. **Cryptographic Evidence Chain** — Tamper-proof compliance audit trail for SOC 2, ISO 27001, etc.
6. **345+ Security Engines** — Comprehensive domain coverage with modular architecture
7. **Universal Connectors** — Fan-out to Jira, GitHub, Slack in single API call
8. **Scheduled Report Delivery** — Multi-channel (email, Slack) via n8n integration
9. **Purple Team Testing** — Integrated attack/defense simulation
10. **MPTE (Micro-Pentest Engine)** — Automated proof-of-concept for findings

---

## Architecture Notes

### Frontend-Backend Communication
- REST API via `analyticsApi` wrapper
- WebSocket for real-time alerts (alert_triage_router, event_bus_router)
- File uploads for SBOM, evidence bundles
- Polling fallback for non-WebSocket environments

### Authentication & Authorization
- **API Key**: Header `X-API-Key`
- **JWT**: Authorization: Bearer {token}
- **Role-Based Access Control**: admin, org_admin, super_admin, security_engineer, analyst, viewer, etc.
- **Multi-tenant Isolation**: All queries filtered by org_id

### Resilience Patterns
- **Redis Fallback**: Local SQLite queues when Redis unavailable
- **Lazy Engine Loading**: Engines instantiated on-first-use
- **Singleton Instances**: Global engine instances to prevent re-initialization
- **Offline-First Event Bus**: TrustGraph events queue locally and sync when online
- **Webhook Verification**: HMAC-SHA256 signature validation

### Scaling Considerations
- **Horizontal Scaling**: Pipeline workers scale independently (stateless)
- **Database**: PostgreSQL dual-dialect compatible (SQLite for local dev)
- **Queue**: Redis pub/sub for distributed messaging
- **Cache**: Implicit in singleton engines (can add Redis caching layer)
- **Graph Storage**: SQLite + NetworkX (could upgrade to Neo4j for enterprise scale)

---

**End of Inventory**
