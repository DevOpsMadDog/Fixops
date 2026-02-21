# FixOps — Complete Router & Endpoint Inventory

> **Generated**: 2025-07 | **Scope**: Every router file across all 7 suites  
> **Total router files**: 55 | **Total endpoints**: ~370+  
> **Purpose**: Supplement `FIXOPS_COMPREHENSIVE_ANALYSIS.md` with per-endpoint detail

---

## Table of Contents

1. [Suite-API Routers (16 files, ~160 endpoints)](#1-suite-api-routers)
2. [Suite-Core Routers (17 files, ~125 endpoints)](#2-suite-core-routers)
3. [Suite-Attack Routers (12 files, ~65 endpoints)](#3-suite-attack-routers)
4. [Suite-Feeds Routers (1 file, ~30 endpoints)](#4-suite-feeds-routers)
5. [Standalone Apps (3 files, ~30 endpoints)](#5-standalone-apps)
6. [Cross-Suite Dependency Map](#6-cross-suite-dependency-map)
7. [In-Memory State Concerns](#7-in-memory-state-concerns)
8. [Prefix Inconsistencies](#8-prefix-inconsistencies)
9. [Stub & Unimplemented Endpoints](#9-stub--unimplemented-endpoints)
10. [Security Concerns](#10-security-concerns)
11. [Inter-Endpoint Interaction Flows](#11-inter-endpoint-interaction-flows)

---

## 1. Suite-API Routers

**Location**: `suite-api/apps/api/`  
**Total files**: 16 | **Total endpoints**: ~160

### 1.1 analytics_router.py (796 lines, 22 endpoints)

**Prefix**: `/api/v1/analytics`  
**Dependencies**: `core.analytics_db.AnalyticsDB`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/dashboard` | Dashboard metrics overview | R: AnalyticsDB |
| GET | `/overview` | High-level analytics summary | R: AnalyticsDB |
| GET | `/trends` | Time-series trend data | R: AnalyticsDB |
| GET | `/findings` | List findings with filters | R: AnalyticsDB |
| POST | `/findings` | Create new finding | W: AnalyticsDB |
| GET | `/findings/{id}` | Get finding by ID | R: AnalyticsDB |
| PUT | `/findings/{id}` | Update a finding | W: AnalyticsDB |
| DELETE | `/findings/{id}` | Delete a finding | W: AnalyticsDB |
| GET | `/decisions` | List decisions | R: AnalyticsDB |
| GET | `/mttr` | Mean-time-to-remediate | R: AnalyticsDB |
| GET | `/coverage` | Scan coverage metrics | R: AnalyticsDB |
| GET | `/roi` | ROI calculations | R: AnalyticsDB |
| GET | `/noise-reduction` | Noise reduction stats | R: AnalyticsDB |
| POST | `/custom-query` | Execute custom analytics query | R: AnalyticsDB |
| GET | `/export` | Export analytics data | R: AnalyticsDB |
| GET | `/stats` | Basic statistics | R: AnalyticsDB |
| GET | `/anomalies` | Anomaly detection (z-score) | R: AnalyticsDB |
| GET | `/risk-velocity` | Risk velocity trends | R: AnalyticsDB |
| GET | `/scanner-comparison` | Compare scanner performance | R: AnalyticsDB |
| GET | `/sla-compliance` | SLA compliance metrics | R: AnalyticsDB |
| GET | `/tool-effectiveness` | Tool effectiveness ratings | R: AnalyticsDB |
| GET | `/priority-distribution` | Priority distribution chart | R: AnalyticsDB |

**Concerns**: Uses `datetime.utcnow()` (deprecated in Python 3.12+).

---

### 1.2 audit_router.py (470 lines, 14 endpoints)

**Prefix**: `/api/v1/audit`  
**Dependencies**: `core.audit_db.AuditDB`, `core.findings_db.FindingsDB` (optional)

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/logs` | List audit logs with filters | R: AuditDB |
| POST | `/logs` | Create audit log entry | W: AuditDB |
| GET | `/logs/{id}` | Get specific log entry | R: AuditDB |
| GET | `/export` | Export logs (CEF/SIEM/JSON) | R: AuditDB |
| GET | `/user-activity/{user_id}` | User activity timeline | R: AuditDB |
| GET | `/policy-changes` | Policy change history | R: AuditDB |
| GET | `/decision-trail/{finding_id}` | Decision audit trail | R: AuditDB |
| GET | `/compliance/{framework}` | Framework compliance stats | R: AuditDB+FindingsDB |
| GET | `/compliance-gaps` | Compliance gap analysis | R: AuditDB |
| GET | `/controls` | List compliance controls | R: AuditDB |
| GET | `/controls/{control_id}` | Get specific control | R: AuditDB |
| PUT | `/controls/{control_id}` | Update control status | W: AuditDB |
| GET | `/hash-chain/verify` | Verify log integrity (SHA-256) | R: AuditDB |
| GET | `/stats` | Audit statistics | R: AuditDB |

**Concerns**: `_chain_hashes` in-memory; O(n) log lookup.

---

### 1.3 auth_router.py (124 lines, 4 endpoints)

**Prefix**: `/api/v1/auth`  
**Dependencies**: `core.auth_db.AuthDB`, `core.auth_models`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/sso` | List SSO/SAML configs | R: AuthDB |
| POST | `/sso` | Create SSO config | W: AuthDB |
| GET | `/sso/{id}` | Get SSO config by ID | R: AuthDB |
| PUT | `/sso/{id}` | Update SSO config | W: AuthDB |

---

### 1.4 bulk_router.py (957 lines, 12 endpoints)

**Prefix**: `/api/v1/bulk`  
**Dependencies**: `core.connectors` (Jira, ServiceNow, GitLab, GitHub, AzureDevOps), `core.integration_db.IntegrationDB`, `core.services.deduplication.DeduplicationService`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/clusters` | List finding clusters | R: DeduplicationService |
| POST | `/clusters/{id}/status` | Update cluster status | W: DeduplicationService |
| POST | `/clusters/{id}/assign` | Assign cluster to team/user | W: DeduplicationService |
| POST | `/clusters/{id}/accept-risk` | Accept risk for cluster | W: DeduplicationService |
| POST | `/clusters/{id}/create-ticket` | Create ticket in Jira/ServiceNow/etc | W: Connector APIs |
| GET | `/export` | Export bulk data | R: DeduplicationService |
| GET | `/jobs` | List background jobs | R: In-memory `_jobs` |
| GET | `/jobs/{id}` | Get job status | R: In-memory `_jobs` |
| DELETE | `/jobs/{id}` | Cancel job | W: In-memory `_jobs` |
| GET | `/findings` | List findings (legacy stub) | Returns mock data |
| POST | `/findings/{id}/status` | Update finding status (legacy stub) | Returns fake success |
| GET | `/stats` | Bulk operation statistics | R: In-memory `_jobs` |

**Concerns**: `_jobs` in-memory (lost on restart); legacy endpoints return fake success.

---

### 1.5 collaboration_router.py (587 lines, 21 endpoints)

**Prefix**: `/api/v1/collaboration`  
**Dependencies**: `core.services.collaboration.CollaborationService` (SQLite @ `data/collaboration.db`)

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/comments` | Add comment to finding | W: CollaborationDB |
| GET | `/comments` | List comments for finding | R: CollaborationDB |
| GET | `/comments/{id}` | Get comment by ID | R: CollaborationDB |
| PUT | `/comments/{id}` | Update comment | W: CollaborationDB |
| DELETE | `/comments/{id}` | Delete comment | W: CollaborationDB |
| POST | `/comments/{id}/react` | Add reaction to comment | W: CollaborationDB |
| POST | `/watchers` | Add watcher to a resource | W: CollaborationDB |
| DELETE | `/watchers` | Remove watcher | W: CollaborationDB |
| GET | `/watchers` | List watchers for resource | R: CollaborationDB |
| GET | `/activity` | Activity feed | R: CollaborationDB |
| GET | `/activity/stats` | Activity stats | R: CollaborationDB |
| POST | `/mentions` | Track @mention | W: CollaborationDB |
| GET | `/mentions` | List mentions for user | R: CollaborationDB |
| PUT | `/mentions/{id}/read` | Mark mention as read | W: CollaborationDB |
| GET | `/notifications` | Notification queue | R: CollaborationDB |
| POST | `/notifications` | Create notification | W: CollaborationDB |
| PUT | `/notifications/{id}/read` | Mark notification read | W: CollaborationDB |
| POST | `/notifications/{id}/deliver` | Deliver notification (Slack) | W: External API |
| GET | `/stats` | Collaboration stats | R: CollaborationDB |
| GET | `/health` | Service health | R: CollaborationDB |
| POST | `/thread` | Create discussion thread | W: CollaborationDB |

**Concerns**: Slack webhook delivery properly restricts URLs to env-configured webhook.

---

### 1.6 health.py (4 endpoints)

**Prefix**: `/api/v1`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/health` | Kubernetes liveness probe | None |
| GET | `/ready` | Kubernetes readiness probe | None |
| GET | `/version` | App version info | None |
| GET | `/metrics` | Prometheus-style metrics | R: request counters |

**Concerns**: `datetime.utcnow()` deprecated.

---

### 1.7 integrations_router.py (482 lines, 8 endpoints)

**Prefix**: `/api/v1/integrations`  
**Dependencies**: `core.integration_db.IntegrationDB`, `core.connectors` (5 types), `core.security_connectors` (5 types)

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/` | List all integrations | R: IntegrationDB |
| POST | `/` | Create integration config | W: IntegrationDB |
| GET | `/{id}` | Get integration by ID | R: IntegrationDB |
| PUT | `/{id}` | Update integration | W: IntegrationDB |
| DELETE | `/{id}` | Delete integration | W: IntegrationDB |
| POST | `/{id}/test` | Test connectivity | R: External APIs |
| GET | `/{id}/sync-status` | Get sync status | R: IntegrationDB |
| POST | `/{id}/sync` | Trigger sync | W: External APIs |

**Connector types**: Jira, ServiceNow, GitLab, GitHub, Azure DevOps, Slack, Confluence, Snyk, SonarQube, Dependabot, AWS Security Hub, Azure Security Center.

---

### 1.8 inventory_router.py (585 lines, 19 endpoints)

**Prefix**: `/api/v1/inventory`  
**Dependencies**: `core.inventory_db.InventoryDB`, `core.knowledge_brain`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/assets` | List assets | R: InventoryDB |
| POST | `/assets` | Create asset | W: InventoryDB+Brain |
| GET | `/assets/{id}` | Get asset | R: InventoryDB |
| PUT | `/assets/{id}` | Update asset | W: InventoryDB |
| DELETE | `/assets/{id}` | Delete asset | W: InventoryDB |
| GET | `/applications` | List applications | R: InventoryDB |
| POST | `/applications` | Create application | W: InventoryDB |
| GET | `/applications/{id}` | Get application | R: InventoryDB |
| GET | `/components` | List components | R: In-memory |
| GET | `/apis` | List tracked APIs | R: In-memory |
| GET | `/dependencies` | List dependencies | R: In-memory |
| GET | `/services` | List services | R: In-memory |
| GET | `/search` | Global inventory search | R: InventoryDB |
| GET | `/license-compliance` | License compliance audit | R: InventoryDB |
| POST | `/sbom/generate` | Generate SBOM (CycloneDX/SPDX) | R: InventoryDB |
| GET | `/api-security` | API security scores | R: In-memory |
| GET | `/stats` | Inventory stats | R: InventoryDB |
| GET | `/health` | Service health | None |
| GET | `/technologies` | Tech stack summary | R: InventoryDB |

**Concerns**: Components, APIs, dependencies, services all in-memory dicts.

---

### 1.9 marketplace_router.py (706 lines, 12 endpoints)

**Prefix**: (none — tags=["marketplace"])  
**Dependencies**: Enterprise marketplace_service (optional via importlib), built-in catalog fallback

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/marketplace/modules` | Browse available modules | R: Catalog |
| GET | `/marketplace/modules/{id}` | Get module details | R: Catalog |
| GET | `/marketplace/categories` | List categories | R: Static |
| GET | `/marketplace/recommendations` | Personalized recommendations | R: Catalog |
| POST | `/marketplace/contribute` | Submit new module | W: Catalog |
| POST | `/marketplace/modules/{id}/rate` | Rate a module | W: Catalog |
| POST | `/marketplace/modules/{id}/purchase` | Purchase module | W: Catalog |
| GET | `/marketplace/modules/{id}/download` | Download module | R: Catalog |
| GET | `/marketplace/stats` | Marketplace stats | R: Catalog |
| GET | `/marketplace/popular` | Popular modules | R: Catalog |
| GET | `/marketplace/new` | New modules | R: Catalog |
| GET | `/marketplace/health` | Health check | None |

**Concerns**: Dynamic importlib loading fragile; no prefix set on router.

---

### 1.10 policies_router.py (474 lines, 11 endpoints)

**Prefix**: `/api/v1/policies`  
**Dependencies**: `core.policy_db.PolicyDB`, `core.findings_db.FindingsDB`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/` | List all policies | R: PolicyDB |
| POST | `/` | Create policy | W: PolicyDB |
| GET | `/{id}` | Get policy by ID | R: PolicyDB |
| PUT | `/{id}` | Update policy | W: PolicyDB |
| DELETE | `/{id}` | Delete policy | W: PolicyDB |
| POST | `/validate` | Validate findings against policy | R: PolicyDB+FindingsDB |
| POST | `/test` | Test policy rule evaluation | R: OPA engine |
| GET | `/violations` | List policy violations | R: In-memory `_violation_store` |
| POST | `/enforce` | Enforce policies on findings | W: PolicyDB |
| POST | `/simulate` | Simulate policy changes | R: PolicyDB |
| GET | `/conflicts` | Detect policy conflicts | R: PolicyDB |

**Concerns**: `_violation_store` in-memory.

---

### 1.11 remediation_router.py (423 lines, 15 endpoints)

**Prefix**: `/api/v1/remediation`  
**Dependencies**: `core.services.remediation.RemediationService` (SQLite @ `data/remediation/tasks.db`), `core.autofix_engine`, `core.event_bus`, `core.knowledge_brain`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/tasks` | List remediation tasks | R: RemediationDB |
| POST | `/tasks` | Create task | W: RemediationDB+Brain+EventBus |
| GET | `/tasks/{id}` | Get task by ID | R: RemediationDB |
| PUT | `/tasks/{id}` | Full task update | W: RemediationDB |
| PATCH | `/tasks/{id}` | Partial task update | W: RemediationDB |
| POST | `/tasks/{id}/status` | Transition task status | W: RemediationDB (state machine) |
| POST | `/tasks/{id}/assign` | Assign to user | W: RemediationDB |
| POST | `/tasks/{id}/verify` | Mark task as verified | W: RemediationDB |
| POST | `/tasks/{id}/link-ticket` | Link to Jira/ServiceNow ticket | W: RemediationDB |
| GET | `/tasks/{id}/sla` | Check SLA breach status | R: RemediationDB |
| GET | `/metrics` | Remediation metrics/MTTR | R: RemediationDB |
| POST | `/tasks/{id}/autofix` | Trigger AutoFix + PR creation | W: AutoFix engine |
| POST | `/fix` | Create task (CLI alias) | W: RemediationDB |
| GET | `/status` | List tasks (CLI alias) | R: RemediationDB |
| GET | `/queue` | Get remediation queue | R: RemediationDB |

**State machine**: OPEN → IN_PROGRESS → REVIEW → VERIFIED → CLOSED (also DEFERRED, WONT_FIX).  
**Events emitted**: `REMEDIATION_CREATED`, `REMEDIATION_UPDATED`.

---

### 1.12 reports_router.py (651 lines, 14 endpoints)

**Prefix**: `/api/v1/reports`  
**Dependencies**: `core.report_db.ReportDB`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/` | List reports | R: ReportDB |
| POST | `/` | Create report entry | W: ReportDB |
| GET | `/{id}` | Get report by ID | R: ReportDB |
| PUT | `/{id}` | Update report | W: ReportDB |
| DELETE | `/{id}` | Delete report | W: ReportDB |
| POST | `/generate` | Generate report (SARIF/CSV/JSON) | W: ReportDB |
| GET | `/stats` | Report stats | R: ReportDB |
| GET | `/{id}/download` | Download report file | R: Filesystem |
| GET | `/schedules` | List scheduled reports | R: ReportDB |
| POST | `/schedules` | Create schedule | W: ReportDB |
| DELETE | `/schedules/{id}` | Delete schedule | W: ReportDB |
| GET | `/templates` | List report templates | R: Static |
| POST | `/export` | Export findings (SARIF/CSV/JSON) | R: ReportDB |
| GET | `/health` | Health check | None |

**Concerns**: Report generation is mostly a stub; `file_path` points to `/tmp`.

---

### 1.13 routes/enhanced.py (4 endpoints)

**Prefix**: `/api/v1/enhanced`  
**Dependencies**: `core.enhanced_decision.EnhancedDecisionEngine`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/analyze` | Multi-LLM consensus analysis | R/W: LLM APIs |
| POST | `/compare-llms` | Side-by-side LLM comparison | R: LLM APIs |
| GET | `/capabilities` | List enhanced capabilities | R: Static |
| POST | `/signals` | Process security signals | R/W: LLM APIs |

---

### 1.14 teams_router.py (8 endpoints)

**Prefix**: `/api/v1/teams`  
**Dependencies**: `core.user_db.UserDB`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/` | List teams | R: UserDB |
| POST | `/` | Create team | W: UserDB |
| GET | `/{id}` | Get team by ID | R: UserDB |
| PUT | `/{id}` | Update team | W: UserDB |
| DELETE | `/{id}` | Delete team | W: UserDB |
| POST | `/{id}/members` | Add member | W: UserDB |
| DELETE | `/{id}/members/{user_id}` | Remove member | W: UserDB |
| GET | `/{id}/members` | List members | R: UserDB |

---

### 1.15 users_router.py (6 endpoints)

**Prefix**: `/api/v1/users`  
**Dependencies**: `core.user_db.UserDB`, `jwt` (PyJWT), `bcrypt`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/login` | Authenticate + generate JWT (HS256) | R: UserDB |
| GET | `/` | List users | R: UserDB |
| POST | `/` | Create user | W: UserDB (bcrypt hash) |
| GET | `/{id}` | Get user by ID | R: UserDB |
| PUT | `/{id}` | Update user | W: UserDB |
| DELETE | `/{id}` | Delete user | W: UserDB |

**Concerns**: `_login_attempts` in-memory (5 attempts/5min lockout bypassed on restart).

---

### 1.16 validation_router.py (492 lines, 3 endpoints)

**Prefix**: `/api/v1/validate`  
**Dependencies**: `apps.api.normalizers`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/` | Validate + normalize input file | R: Request body |
| POST | `/batch` | Batch validation | R: Request body |
| GET | `/supported-formats` | List supported formats | R: Static |

**Features**: Auto-detection for SARIF/SBOM/CVE/VEX/CNAPP/CSV; 8MB limit; SHA-256 hashing.

---

### 1.17 workflows_router.py (482 lines, 13 endpoints)

**Prefix**: `/api/v1/workflows`  
**Dependencies**: `core.workflow_db.WorkflowDB`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/` | List workflows | R: WorkflowDB |
| POST | `/` | Create workflow | W: WorkflowDB |
| GET | `/{id}` | Get workflow by ID | R: WorkflowDB |
| PUT | `/{id}` | Update workflow | W: WorkflowDB |
| DELETE | `/{id}` | Delete workflow | W: WorkflowDB |
| POST | `/{id}/execute` | Execute workflow | W: WorkflowDB + actions |
| GET | `/{id}/history` | Execution history | R: WorkflowDB |
| GET | `/rules` | List workflow rules | R: WorkflowDB |
| POST | `/rules` | Create automation rule | W: WorkflowDB |
| GET | `/sla` | SLA monitoring | R: In-memory `_sla_store` |
| POST | `/sla` | Set SLA target | W: In-memory `_sla_store` |
| POST | `/{id}/pause` | Pause workflow | W: In-memory |
| POST | `/{id}/resume` | Resume workflow | W: In-memory |

**Action registry**: `noop`, `log`, `notify`, `http_call`, `evaluate_policy`, `create_ticket`, `run_scan`.  
**Concerns**: Multiple in-memory stores; `http_call` action has SSRF risk (no URL validation); `_sla_store`, `_execution_steps`, `_paused_executions` all in-memory.

---

## 2. Suite-Core Routers

**Location**: `suite-core/api/`  
**Total files**: 17 | **Total endpoints**: ~125

### 2.1 agents_router.py (1,704 lines, ~30 endpoints)

**Prefix**: `/api/v1/copilot/agents`  
**Dependencies**: `feeds_service.FeedsService`, `core.services.enterprise.compliance_engine`, `httpx` (MPTE)

**Security Analyst Agent (7 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/security-analyst/analyze` | Analyze CVE with EPSS+KEV enrichment | R: FeedsService |
| POST | `/security-analyst/threat-intel` | Gather threat intelligence | R: FeedsService |
| POST | `/security-analyst/prioritize` | Prioritize findings | R: FeedsService |
| POST | `/security-analyst/attack-path` | Attack path analysis | R: FeedsService |
| GET | `/security-analyst/trending` | Trending CVEs | R: FeedsService |
| POST | `/security-analyst/risk-score` | Calculate risk score | R: FeedsService |
| POST | `/security-analyst/cve-deep-analysis` | Deep CVE analysis | R: FeedsService |

**Pentest Agent (7 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/pentest/validate` | Validate vulnerability via MPTE | R/W: MPTE (verify=False) |
| POST | `/pentest/generate-poc` | Generate proof-of-concept | R/W: MPTE |
| POST | `/pentest/reachability` | Test reachability | R/W: MPTE |
| POST | `/pentest/simulate` | Simulate attack | R/W: MPTE |
| GET | `/pentest/results` | Get pentest results | R: MPTE |
| GET | `/pentest/evidence` | Get evidence | R: MPTE |
| POST | `/pentest/schedule` | Schedule pentest | W: MPTE |

**Compliance Agent (7 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/compliance/map-findings` | Map findings to frameworks | R: ComplianceEngine |
| POST | `/compliance/gap-analysis` | Gap analysis | R: ComplianceEngine |
| POST | `/compliance/audit-evidence` | Generate audit evidence | R: ComplianceEngine |
| POST | `/compliance/regulatory-alerts` | Regulatory alerts | R: ComplianceEngine |
| GET | `/compliance/controls/{framework}` | Framework controls | R: ComplianceEngine |
| GET | `/compliance/dashboard` | Compliance dashboard | R: ComplianceEngine |
| POST | `/compliance/generate-report` | Generate compliance report | R: ComplianceEngine |

**Remediation Agent (7 endpoints — ALL STUBS)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/remediation/generate-fix` | Generate fix | Returns `integration_required` |
| POST | `/remediation/create-pr` | Create PR | Returns `integration_required` |
| POST | `/remediation/update-dependencies` | Update deps | Returns `integration_required` |
| POST | `/remediation/playbook` | Generate playbook | Returns `integration_required` |
| POST | `/remediation/recommendations` | Get recommendations | Returns `integration_required` |
| POST | `/remediation/verify` | Verify fix | Returns `integration_required` |
| GET | `/remediation/queue` | Remediation queue | Returns `integration_required` |

**Orchestrator + Management (3 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/orchestrate` | Run multi-agent workflow | R: Various agents |
| GET | `/status` | Agent status | R: In-memory `_agent_tasks` |
| GET | `/health` | Health check | None |

**Concerns**: All 7 remediation endpoints are stubs; MPTE calls use `verify=False`; `_agent_tasks` in-memory.

---

### 2.2 algorithmic_router.py (611 lines, 11 endpoints)

**Prefix**: `/api/v1/algorithms`  
**Dependencies**: `core.monte_carlo`, `core.causal_inference`, `core.attack_graph_gnn`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/fair/analyze` | Monte Carlo FAIR risk quantification | R: Monte Carlo engine |
| GET | `/fair/results/{id}` | Get FAIR analysis results | R: In-memory |
| GET | `/fair/capabilities` | FAIR capabilities | R: Static |
| POST | `/causal/analyze` | Causal inference analysis | R: Causal engine |
| POST | `/causal/counterfactual` | Counterfactual analysis | R: Causal engine |
| GET | `/causal/capabilities` | Causal capabilities | R: Static |
| POST | `/gnn/analyze` | GNN attack surface analysis | R: GNN engine |
| GET | `/gnn/graph/{id}` | Get attack graph | R: In-memory |
| GET | `/gnn/capabilities` | GNN capabilities | R: Static |
| GET | `/status` | All algorithm status | R: Static |
| GET | `/capabilities` | Aggregated capabilities | R: Static |

---

### 2.3 autofix_router.py (~350 lines, 12 endpoints)

**Prefix**: `/api/v1/autofix`  
**Dependencies**: `core.autofix_engine`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/generate` | Generate fix for finding | R/W: AutoFix engine |
| POST | `/bulk-generate` | Bulk generate fixes (max 20) | R/W: AutoFix engine |
| POST | `/apply/{fix_id}` | Apply fix | W: AutoFix engine |
| POST | `/validate/{fix_id}` | Validate fix | R: AutoFix engine |
| POST | `/rollback/{fix_id}` | Rollback fix | W: AutoFix engine |
| GET | `/{fix_id}` | Get fix details | R: AutoFix engine |
| GET | `/suggestions/{finding_id}` | Get fix suggestions | R: AutoFix engine |
| GET | `/history` | Fix history | R: AutoFix engine |
| GET | `/stats` | Fix statistics | R: AutoFix engine |
| GET | `/health` | Engine health | None |
| GET | `/fix-types` | Supported fix types | R: Static |
| GET | `/confidence-levels` | Confidence level definitions | R: Static |

---

### 2.4 brain_router.py (451 lines, 22 endpoints)

**Prefix**: `/api/v1/brain`  
**Dependencies**: `core.knowledge_brain`, `core.event_bus`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/nodes` | List graph nodes | R: Brain (NetworkX) |
| POST | `/nodes` | Add node | W: Brain |
| GET | `/nodes/{id}` | Get node | R: Brain |
| PUT | `/nodes/{id}` | Update node | W: Brain |
| DELETE | `/nodes/{id}` | Delete node | W: Brain |
| GET | `/edges` | List edges | R: Brain |
| POST | `/edges` | Add edge | W: Brain+EventBus |
| DELETE | `/edges` | Delete edge | W: Brain |
| GET | `/neighbors/{id}` | Get node neighbors | R: Brain |
| GET | `/path` | Find path between nodes | R: Brain |
| GET | `/stats` | Graph statistics | R: Brain |
| GET | `/most-connected` | Top connected nodes | R: Brain |
| GET | `/risk-scores` | Risk scores from graph | R: Brain |
| GET | `/events` | Recent events | R: EventBus |
| GET | `/entity-types` | List entity types | R: Static |
| GET | `/edge-types` | List edge types | R: Static |
| POST | `/ingest/cve` | Ingest CVE data | W: Brain |
| POST | `/ingest/finding` | Ingest finding | W: Brain |
| POST | `/ingest/scan` | Ingest scan result | W: Brain |
| POST | `/ingest/asset` | Ingest asset | W: Brain |
| POST | `/ingest/remediation` | Ingest remediation | W: Brain |
| GET | `/health` | Health check | None |

---

### 2.5 code_to_cloud_router.py (2 endpoints)

**Prefix**: `/api/v1/code-to-cloud`  
**Dependencies**: `core.code_to_cloud_tracer`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/trace` | Trace code change through cloud | R/W: Tracer |
| GET | `/status` | Tracer status | R: Static |

---

### 2.6 copilot_router.py (1,140 lines, ~18 endpoints)

**Prefix**: `/api/v1/copilot`  
**Dependencies**: `core.llm_providers.LLMProviderManager`, `core.knowledge_brain`, `core.event_bus`, `feeds_service.FeedsService`, `core.autofix_engine`, `core.attack_simulation_engine`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/sessions` | Create copilot session | W: In-memory `_sessions` |
| GET | `/sessions` | List sessions | R: In-memory `_sessions` |
| GET | `/sessions/{id}` | Get session | R: In-memory `_sessions` |
| DELETE | `/sessions/{id}` | Close session | W: In-memory `_sessions` |
| POST | `/sessions/{id}/messages` | Send message (real LLM call) | W: In-memory `_messages` + LLM API |
| GET | `/sessions/{id}/messages` | Get conversation history | R: In-memory `_messages` |
| POST | `/actions` | Execute agent action (analyze/pentest/remediate) | W: In-memory `_actions` |
| GET | `/actions` | List actions | R: In-memory `_actions` |
| GET | `/actions/{id}` | Get action result | R: In-memory `_actions` |
| POST | `/context` | Set context for copilot | W: In-memory `_sessions` |
| POST | `/suggest` | Get AI suggestions (real LLM) | R: LLM API |
| POST | `/quick/analyze` | Quick CVE analysis | R: FeedsService + LLM |
| POST | `/quick/pentest` | Quick pentest trigger | R: AttackSimEngine |
| POST | `/quick/report` | Quick report generation | R: Brain + LLM |
| GET | `/health` | Health check | None |
| POST | `/feedback` | Submit feedback on response | W: In-memory |
| GET | `/capabilities` | List copilot capabilities | R: Static |
| GET | `/providers` | List available LLM providers | R: LLM config |

**Concerns**: `_sessions`, `_messages`, `_actions` all in-memory — conversation state lost on restart.

---

### 2.7 decisions.py (6 endpoints)

**Prefix**: `/decisions` (**NOT** `/api/v1/`)  
**Dependencies**: Enterprise modules (DatabaseManager, OPA engine, evidence lake, ChromaDB, cache service)

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/make-decision` | Make security decision | R/W: Enterprise engines |
| GET | `/metrics` | Decision metrics | R: Enterprise engines |
| GET | `/recent` | Recent decisions | R: Enterprise engines |
| GET | `/ssdlc-stages` | SSDLC stage definitions | R: Static |
| GET | `/core-components` | Core component descriptions | R: Static |
| GET | `/evidence` | Decision evidence | R: Enterprise engines |

**Concerns**: Non-standard prefix `/decisions` (not `/api/v1/decisions`).

---

### 2.8 deduplication_router.py (437 lines, 18 endpoints)

**Prefix**: `/api/v1/deduplication`  
**Dependencies**: `core.services.deduplication.DeduplicationService`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/process` | Deduplicate single finding | W: DeduplicationService |
| POST | `/batch` | Batch deduplication | W: DeduplicationService |
| GET | `/clusters` | List clusters | R: DeduplicationService |
| GET | `/clusters/{id}` | Get cluster | R: DeduplicationService |
| PUT | `/clusters/{id}` | Update cluster | W: DeduplicationService |
| POST | `/clusters/{id}/status` | Change cluster status | W: DeduplicationService |
| POST | `/clusters/{id}/assign` | Assign cluster | W: DeduplicationService |
| POST | `/clusters/{id}/ticket` | Create ticket for cluster | W: DeduplicationService |
| GET | `/clusters/{id}/related` | Find related clusters | R: DeduplicationService |
| GET | `/correlations` | Cross-stage correlations | R: DeduplicationService |
| GET | `/stats` | Deduplication stats | R: DeduplicationService |
| POST | `/cross-correlate` | Cross-stage correlation | W: DeduplicationService |
| GET | `/graph` | Dedup relationship graph | R: DeduplicationService |
| POST | `/feedback` | Quality feedback | W: DeduplicationService |
| POST | `/baseline/compare` | Compare against baseline | R: DeduplicationService |
| POST | `/merge` | Merge clusters | W: DeduplicationService |
| POST | `/split` | Split cluster | W: DeduplicationService |
| GET | `/health` | Health check | None |

---

### 2.9 exposure_case_router.py (8 endpoints)

**Prefix**: `/api/v1/cases`  
**Dependencies**: `core.exposure_case`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/stats` | Case statistics summary | R: ExposureCase engine |
| GET | `/summary` | Case summary | R: ExposureCase engine |
| GET | `/` | List cases | R: ExposureCase engine |
| POST | `/` | Create case | W: ExposureCase engine |
| GET | `/{id}` | Get case by ID | R: ExposureCase engine |
| POST | `/{id}/transition` | Transition case state | W: ExposureCase engine |
| GET | `/{id}/cluster` | Get cluster aggregation | R: ExposureCase engine |
| GET | `/{id}/transitions` | Transition history | R: ExposureCase engine |

**State machine**: OPEN → TRIAGING → FIXING → RESOLVED → CLOSED.

---

### 2.10 fuzzy_identity_router.py (7 endpoints)

**Prefix**: `/api/v1/identity`  
**Dependencies**: `core.services.fuzzy_identity`, `core.knowledge_brain`, `core.event_bus`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/canonical` | Register canonical asset | W: FuzzyIdentity + Brain |
| POST | `/alias` | Add alias to canonical | W: FuzzyIdentity |
| POST | `/resolve` | Resolve single identifier | R: FuzzyIdentity |
| POST | `/resolve/batch` | Batch resolve | R: FuzzyIdentity |
| POST | `/similar` | Find similar identifiers | R: FuzzyIdentity |
| GET | `/canonical` | List all canonicals | R: FuzzyIdentity |
| GET | `/stats` | Identity stats | R: FuzzyIdentity |

**Events emitted**: `ASSET_DISCOVERED`.

---

### 2.11 intelligent_engine_routes.py (597 lines, 11 endpoints)

**Prefix**: `/intelligent-engine` (**NOT** `/api/v1/`)  
**Dependencies**: `core.intelligent_security_engine`, `core.api_learning_store`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/status` | Engine status | R: ISE engine |
| GET | `/sessions` | List ISE sessions | R: In-memory `_sessions` |
| POST | `/scan/start` | Start security scan | W: In-memory `_sessions` |
| GET | `/scan/{id}` | Get scan progress | R: In-memory `_sessions` |
| POST | `/scan/{id}/stop` | Stop scan | W: In-memory `_sessions` |
| POST | `/threat-intel` | Gather threat intelligence | R: ISE engine |
| POST | `/attack-plan` | Generate attack plan | R: ISE engine |
| POST | `/attack-plan/execute` | Execute attack plan | W: ISE engine |
| GET | `/mindsdb/status` | ML model status | R: LearningStore |
| POST | `/mindsdb/predict` | ML prediction | R: LearningStore |
| POST | `/consensus/analyze` | Multi-LLM consensus | R: LLM APIs |

**Concerns**: Non-standard prefix; `_sessions`+`_results` in-memory; `datetime.utcnow()`.

---

### 2.12 llm_monitor_router.py (4 endpoints)

**Prefix**: `/api/v1/llm-monitor`  
**Dependencies**: `core.llm_monitor`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/analyze` | Analyze prompt+response for threats | R: Pattern matching |
| POST | `/scan` | Scan prompt only | R: Pattern matching |
| GET | `/patterns` | List detection patterns | R: Static |
| GET | `/status` | Monitor status | R: Static |

**Detection patterns**: Jailbreak, PII, sensitive topics.

---

### 2.13 llm_router.py (478 lines, 6 endpoints)

**Prefix**: `/api/v1/llm`  
**Dependencies**: `core.llm_providers` (OpenAI, Anthropic, Google)

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/providers` | List providers with status | R: Env vars |
| POST | `/test` | Test LLM connectivity | R: LLM API |
| GET | `/settings` | Get LLM settings | R: In-memory `_settings` |
| PUT | `/settings` | Update LLM settings | W: In-memory `_settings` |
| GET | `/models` | List available models | R: Static |
| GET | `/health` | Health check | R: Env vars |

**Concerns**: `_settings` in-memory.

---

### 2.14 mindsdb_router.py / ml_router (400 lines, 15 endpoints)

**Prefix**: `/api/v1/ml` (mounted as `ml_router` in app.py)  
**Dependencies**: `core.api_learning_store` (scikit-learn)

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/status` | ML model status | R: LearningStore |
| GET | `/models` | List ML models | R: LearningStore |
| POST | `/train/all` | Train all models | W: LearningStore |
| POST | `/train/{model}` | Train single model | W: LearningStore |
| POST | `/predict/anomaly` | Anomaly prediction | R: LearningStore |
| POST | `/predict/threat` | Threat assessment | R: LearningStore |
| POST | `/predict/response-time` | Response time prediction | R: LearningStore |
| GET | `/stats` | Model stats (alias) | R: LearningStore |
| GET | `/analytics/stats` | Analytics stats | R: LearningStore |
| GET | `/analytics/health` | Analytics health | R: LearningStore |
| GET | `/analytics/anomalies` | Detected anomalies | R: LearningStore |
| GET | `/analytics/threats` | Detected threats | R: LearningStore |
| POST | `/analytics/threats/{id}/acknowledge` | Acknowledge threat | W: LearningStore |
| POST | `/analytics/flush` | Flush analytics data | W: LearningStore |
| GET | `/health` | Health check | None |

---

### 2.15 nerve_center.py (846 lines, 9 endpoints)

**Prefix**: `/api/v1/nerve-center`  
**Dependencies**: `core.knowledge_brain`, `core.api_learning_store`, `core.event_bus`, `core.services.enterprise.decision_engine`, `httpx` (loopback health probes)

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/pulse` | Real-time threat pulse (brain+ML+events) | R: Brain+ML+EventBus |
| GET | `/state` | Full system state (suite health, intel links, actions) | R: HTTP probes + Brain + EventBus + Decision engine |
| POST | `/auto-remediate` | Trigger auto-remediation | W: Various engines |
| GET | `/intelligence-map` | Structural architecture topology + brain overlay | R: Brain + Static |
| GET | `/playbooks` | List available playbooks | R: Static |
| POST | `/playbooks/validate` | Validate playbook YAML | R: Request body |
| POST | `/playbooks/execute` | Execute playbook | W: Various engines |
| GET | `/overlay` | Get overlay config | R: In-memory |
| PUT | `/overlay` | Update overlay config | W: In-memory |

**Concerns**: Suite health probes via HTTP loopback to self (port 8000); `datetime.utcnow()`.

---

### 2.16 pipeline_router.py (7 endpoints)

**Prefix**: `/api/v1/brain` (**shares prefix** with brain_router!)  
**Dependencies**: `core.brain_pipeline`, `core.soc2_evidence_generator`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/pipeline/run` | Run 12-step brain pipeline | W: Pipeline orchestrator |
| GET | `/pipeline/runs` | List pipeline runs | R: Pipeline history |
| GET | `/pipeline/runs/{id}` | Get pipeline run | R: Pipeline history |
| POST | `/evidence/generate` | Generate SOC2 evidence bundle | W: Evidence generator |
| GET | `/evidence/packs` | List evidence packs | R: Evidence store |
| GET | `/evidence/packs/{id}` | Get evidence pack | R: Evidence store |
| GET | `/pipeline/health` | Pipeline health | None |

**Concerns**: Shares `/api/v1/brain` prefix with brain_router.py — potential route conflicts.

---

### 2.17 predictions_router.py (486 lines, 8 endpoints)

**Prefix**: `/api/v1/predictions`  
**Dependencies**: `core.models.markov_chain`, `core.models.bayesian_network`, `new_backend.processing.bayesian`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/markov/attack-chain` | Predict attack chain (Markov) | R: Markov model |
| POST | `/markov/risk-trajectory` | Risk trajectory prediction | R: Markov model |
| POST | `/markov/simulate-attack` | Monte Carlo attack simulation | R: Markov model |
| GET | `/markov/states` | List Markov states | R: Static |
| GET | `/markov/transitions` | Get transition matrix | R: Markov model |
| POST | `/bayesian/update` | Update Bayesian network | W: Bayesian network |
| POST | `/bayesian/risk-assessment` | Bayesian risk assessment | R: Bayesian network (pgmpy fallback) |
| POST | `/combined/analysis` | Combined Markov+Bayesian analysis | R: Both models |

---

### 2.18 streaming_router.py (2 endpoints)

**Prefix**: `/api/v1/stream`  
**Dependencies**: `core.brain_pipeline`, `core.event_bus`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/pipeline` | SSE stream of pipeline progress | R: Pipeline engine |
| GET | `/events` | SSE stream of event bus events (heartbeat + filtering) | R: EventBus |

---

## 3. Suite-Attack Routers

**Location**: `suite-attack/api/`  
**Total files**: 12 | **Total endpoints**: ~65

### 3.1 micro_pentest_router.py (1,818 lines, ~20 endpoints)

**Prefix**: `/api/v1/micro-pentest`  
**Dependencies**: `core.micro_pentest`, `core.real_scanner`, `core.llm_providers`, `core.event_bus`, `core.knowledge_brain`

**Basic MPTE Pentest (4 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/run` | Run micro pentest (real MPTE call) | W: MPTE service + Brain |
| GET | `/status/{flow_id}` | Get pentest status | R: MPTE service |
| POST | `/batch` | Batch micro pentests | W: MPTE service |
| GET | `/health` | Health check (MPTE connectivity) | R: MPTE probe |

**Enterprise 8-Phase Engine (10 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/enterprise/scan` | Full 8-phase enterprise scan | W: MicroPentestEngine + Brain |
| GET | `/enterprise/scan/{id}` | Get enterprise scan result | R: MicroPentestEngine |
| GET | `/enterprise/scans` | List enterprise scans | R: MicroPentestEngine |
| POST | `/enterprise/scan/{id}/cancel` | Cancel scan | W: MicroPentestEngine |
| GET | `/enterprise/audit-logs` | Get audit logs | R: MicroPentestEngine |
| GET | `/enterprise/health` | Engine health | R: MicroPentestEngine |
| GET | `/enterprise/attack-vectors` | List attack vectors | R: Static |
| GET | `/enterprise/threat-categories` | List MITRE categories | R: Static |
| GET | `/enterprise/compliance-frameworks` | List frameworks | R: Static |
| GET | `/enterprise/scan-modes` | List scan modes | R: Static |

**Report Generation (4 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/report/generate` | Run scan + generate HTML report | W: Filesystem |
| GET | `/report/download` | Download HTML report | R: Filesystem |
| GET | `/report/view` | View HTML report in browser | R: Filesystem |
| GET | `/report/data` | Get raw JSON scan data | R: Filesystem |

**8-Phase Scan Details**:
1. Initialization — LLM-powered target analysis
2. Reconnaissance — LLM-powered recon
3. Threat Modeling — LLM-powered MITRE mapping
4. Vulnerability Scanning — **REAL** via `RealVulnerabilityScanner`
5. Exploitation — LLM-enhanced PoC generation
6. Compliance Validation — REAL framework checks
7. Risk Scoring — LLM-powered contextual risk
8. Attack Path Generation — chain finding correlation

**Concerns**: Enterprise engine (`_scans`, `_audit_logs`, `_active_scans`) all in-memory; report files written to `.fixops_data/` directory.

---

### 3.2 mpte_router.py (726 lines, ~22 endpoints)

**Prefix**: `/api/v1/mpte`  
**Dependencies**: `core.mpte_db.MPTEDB`, `integrations.mpte_service.AdvancedMPTEService`, `httpx`

**Request Management (7 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/requests` | List pentest requests | R: MPTEDB |
| POST | `/requests` | Create pentest request | W: MPTEDB + MPTE service |
| GET | `/requests/{id}` | Get request | R: MPTEDB |
| PUT | `/requests/{id}` | Update request | W: MPTEDB |
| POST | `/requests/{id}/start` | Start pentest | W: MPTEDB |
| POST | `/requests/{id}/cancel` | Cancel pentest | W: MPTEDB |
| GET | `/findings/{finding_id}/exploitability` | Get exploitability | R: MPTEDB |

**Result Management (3 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/results` | List pentest results | R: MPTEDB |
| POST | `/results` | Create result | W: MPTEDB |
| GET | `/results/by-request/{id}` | Get result by request | R: MPTEDB |

**Config Management (5 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/configs` | List MPTE configs | R: MPTEDB |
| POST | `/configs` | Create config | W: MPTEDB |
| GET | `/configs/{id}` | Get config | R: MPTEDB |
| PUT | `/configs/{id}` | Update config | W: MPTEDB |
| DELETE | `/configs/{id}` | Delete config | W: MPTEDB |

**Enhanced Features (4 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/verify` | Verify vulnerability via MPTE | R/W: MPTE service |
| POST | `/monitoring` | Setup continuous monitoring | W: MPTE service |
| POST | `/scan/comprehensive` | Multi-vector scan | W: MPTE service |
| GET | `/stats` | Pentest stats | R: MPTEDB |

**Concerns**: `verify=False` on all httpx calls; `_mpte_service` global mutable; `datetime.utcnow()`.

---

### 3.3 vuln_discovery_router.py (876 lines, 11 endpoints)

**Prefix**: `/api/v1/vulns`  
**Dependencies**: `core.event_bus`, `core.knowledge_brain`, `feeds_service.FeedsService` (optional)

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/discovered` | List discovered vulns | R: In-memory `_discovered_vulns` |
| POST | `/discovered` | Report discovered vuln (ALdeci ID) | W: In-memory + Brain + EventBus |
| POST | `/contribute` | Submit to CVE/MITRE program | W: In-memory `_contributions` |
| GET | `/internal` | List internal (pre-CVE) vulns | R: In-memory `_discovered_vulns` |
| GET | `/internal/{id}` | Get full vuln details | R: In-memory |
| PATCH | `/internal/{id}` | Update internal vuln | W: In-memory |
| POST | `/train` | Retrain ML models | W: In-memory `_retrain_jobs` |
| GET | `/train/{id}` | Get training job status | R: In-memory `_retrain_jobs` |
| GET | `/stats` | Discovery stats | R: In-memory |
| GET | `/contributions` | List CVE contributions | R: In-memory `_contributions` |
| GET | `/health` | Health check | None |

**Unique value**: ALdeci contributes vulnerabilities back to CVE ecosystem (ALDECI-YYYY-NNNN IDs).  
**Concerns**: ALL data in-memory (`_discovered_vulns`, `_contributions`, `_retrain_jobs`); ML training stub (requires MindsDB); CVSS calculation via `cvss` library.

---

### 3.4 attack_sim_router.py (393 lines, 14 endpoints)

**Prefix**: `/api/v1/attack-sim`  
**Dependencies**: `core.attack_simulation_engine`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/scenarios` | Create attack scenario | W: AttackSimEngine |
| POST | `/scenarios/generate` | AI-generate scenario | W: AttackSimEngine (LLM) |
| GET | `/scenarios` | List scenarios | R: AttackSimEngine |
| GET | `/scenarios/{id}` | Get scenario | R: AttackSimEngine |
| POST | `/campaigns` | Run campaign | W: AttackSimEngine |
| GET | `/campaigns` | List campaigns | R: AttackSimEngine |
| GET | `/campaigns/{id}` | Get campaign | R: AttackSimEngine |
| GET | `/campaigns/{id}/attack-paths` | Campaign attack paths | R: AttackSimEngine |
| GET | `/campaigns/{id}/breach-impact` | Breach impact analysis | R: AttackSimEngine |
| GET | `/campaigns/{id}/recommendations` | Campaign recommendations | R: AttackSimEngine |
| GET | `/mitre/heatmap` | MITRE ATT&CK heatmap | R: AttackSimEngine |
| GET | `/mitre/techniques` | MITRE technique list | R: AttackSimEngine |
| GET | `/health` | Health check | None |
| GET | `/stats` | Simulation stats | R: AttackSimEngine |

---

### 3.5 pentagi_router.py (313 lines, 8 endpoints)

**Prefix**: `/api/v1/pentagi`  
**Dependencies**: None (self-contained, mostly hardcoded responses)

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/health` | Health check | None |
| GET | `/capabilities` | PentAGI capabilities | R: Static |
| POST | `/threat-intel` | Threat intel for CVE | R: **Hardcoded response** |
| POST | `/business-impact` | Business impact analysis | R: **Hardcoded response** |
| POST | `/simulate` | Simulate attack chain | R: **Hardcoded response** |
| POST | `/remediation` | Remediation guidance | R: **Hardcoded response** |
| POST | `/run` | Run advanced pentest | R: **Hardcoded response** |
| GET | `/status/{test_id}` | Get pentest status | R: **Hardcoded response** |

**Concerns**: All POST endpoints return hardcoded/synthetic data — this is a UI stub, not a real implementation.

---

### 3.6 secrets_router.py (280 lines, 8 endpoints)

**Prefix**: `/api/v1/secrets`  
**Dependencies**: `core.secrets_db.SecretsDB`, `core.secrets_scanner`, `core.event_bus`, `core.knowledge_brain`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/status` | Scanning subsystem status | R: SecretsDB |
| GET | `/` | List secret findings | R: SecretsDB |
| POST | `/` | Create secret finding | W: SecretsDB + Brain + EventBus |
| GET | `/{id}` | Get finding by ID | R: SecretsDB |
| POST | `/{id}/resolve` | Resolve finding | W: SecretsDB |
| GET | `/scanners/status` | Scanner availability (gitleaks/trufflehog) | R: SecretsScanner |
| POST | `/scan/content` | Scan content for secrets | W: SecretsDB + SecretsScanner |

**Events emitted**: `SECRET_FOUND`.

---

### 3.7 sast_router.py (78 lines, 4 endpoints)

**Prefix**: `/api/v1/sast`  
**Dependencies**: `core.sast_engine`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/scan/code` | Scan single code snippet | R: SAST engine |
| POST | `/scan/files` | Scan multiple files | R: SAST engine |
| GET | `/rules` | List SAST rules | R: Static |
| GET | `/status` | Engine status | R: Static |

**Languages**: Python, JavaScript, Java, Go, Ruby, PHP, C#.

---

### 3.8 cspm_router.py (73 lines, 4 endpoints)

**Prefix**: `/api/v1/cspm`  
**Dependencies**: `core.cspm_engine`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/scan/terraform` | Scan Terraform HCL | R: CSPM engine |
| POST | `/scan/cloudformation` | Scan CloudFormation | R: CSPM engine |
| GET | `/rules` | List CSPM rules (AWS/Azure/GCP) | R: Static |
| GET | `/status` | Engine status | R: Static |

---

### 3.9 container_router.py (63 lines, 3 endpoints)

**Prefix**: `/api/v1/container`  
**Dependencies**: `core.container_scanner`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/scan/dockerfile` | Scan Dockerfile content | R: Container scanner |
| POST | `/scan/image` | Scan image (Trivy/Grype) | R: Container scanner |
| GET | `/status` | Scanner status | R: Static |

---

### 3.10 malware_router.py (59 lines, 4 endpoints)

**Prefix**: `/api/v1/malware`  
**Dependencies**: `core.malware_detector`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/scan/content` | Scan content for malware | R: Malware detector |
| POST | `/scan/files` | Scan multiple files | R: Malware detector |
| GET | `/signatures` | List malware signatures | R: Static |
| GET | `/status` | Detector status | R: Static |

---

### 3.11 dast_router.py (40 lines, 2 endpoints)

**Prefix**: `/api/v1/dast`  
**Dependencies**: `core.dast_engine`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/scan` | Launch DAST scan | R/W: DAST engine |
| GET | `/status` | Engine status | R: Static |

---

### 3.12 api_fuzzer_router.py (56 lines, 3 endpoints)

**Prefix**: `/api/v1/api-fuzzer`  
**Dependencies**: `core.api_fuzzer`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/discover` | Discover API endpoints from OpenAPI spec | R: Fuzzer engine |
| POST | `/fuzz` | Discover + fuzz endpoints | R/W: Fuzzer engine |
| GET | `/status` | Fuzzer status | R: Static |

---

## 4. Suite-Feeds Routers

**Location**: `suite-feeds/api/`  
**Total files**: 1 | **Total endpoints**: ~30

### 4.1 feeds_router.py (1,211 lines, ~30 endpoints)

**Prefix**: `/api/v1/feeds`  
**Dependencies**: `feeds_service.FeedsService` (SQLite), `core.event_bus`, `core.knowledge_brain`

**EPSS (2 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/epss/{cve_id}` | Get EPSS score | R: FeedsDB |
| POST | `/epss/refresh` | Refresh EPSS data | W: FeedsDB |

**KEV (2 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/kev/{cve_id}` | Get KEV status | R: FeedsDB |
| POST | `/kev/refresh` | Refresh KEV data | W: FeedsDB |

**NVD (3 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/nvd/refresh` | Refresh NVD (last N days) | W: FeedsDB |
| GET | `/nvd/recent` | Recent NVD CVEs | R: FeedsDB |
| GET | `/nvd/{cve_id}` | Get NVD data | R: FeedsDB |

**ExploitDB / OSV / GitHub Advisory (3 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/exploitdb/refresh` | Refresh ExploitDB | W: FeedsDB |
| POST | `/osv/refresh` | Refresh OSV | W: FeedsDB |
| POST | `/github-advisories/refresh` | Refresh GitHub advisories | W: FeedsDB |

**Exploit Intelligence (3 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/exploit-intelligence` | List exploit intelligence | R: FeedsDB |
| GET | `/exploit-intelligence/{cve_id}` | Get exploit intel for CVE | R: FeedsDB |
| POST | `/exploit-intelligence` | Add exploit intel | W: FeedsDB |

**Threat Actor Mapping (4 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/threat-actors` | List threat actors | R: FeedsDB |
| GET | `/threat-actors/{cve_id}` | Get actors for CVE | R: FeedsDB |
| GET | `/threat-actors/by-actor/{actor}` | Get CVEs by actor | R: FeedsDB |
| POST | `/threat-actors` | Add actor mapping | W: FeedsDB |

**Supply Chain (3 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/supply-chain` | List supply chain vulns | R: FeedsDB |
| GET | `/supply-chain/{package}` | Get vulns for package | R: FeedsDB |
| POST | `/supply-chain` | Add supply chain vuln | W: FeedsDB |

**Risk Scoring (2 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/exploit-confidence/{cve_id}` | Exploit confidence score (weighted) | R: FeedsDB |
| GET | `/geo-risk/{cve_id}` | Geo-weighted risk score | R: FeedsDB + CERT |

**Enrichment (1 endpoint)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/enrich` | Comprehensive finding enrichment | R: FeedsDB → W: Brain |

**Meta & Health (6 endpoints)**:

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/stats` | Comprehensive feed statistics | R: FeedsDB (SQLite direct) |
| GET | `/categories` | List feed categories (8) | R: Static |
| GET | `/sources` | List all feed sources with URLs | R: Static |
| GET | `/health` | Feed health/freshness status | R: FeedsDB (SQLite direct) |
| GET | `/scheduler/status` | Scheduler status | R: Static |
| POST | `/refresh` | Refresh all feeds (alias) | W: FeedsDB + EventBus |
| POST | `/refresh/all` | Refresh all primary feeds | W: FeedsDB + EventBus |

**Feed categories**: Authoritative, National CERT, Exploit, Threat Actor, Supply Chain, Cloud/Runtime, Early Signal, Enterprise.  
**Events emitted**: `FEED_UPDATED`, `EPSS_UPDATED`, `KEV_ALERT`.

---

## 5. Standalone Apps

### 5.1 mpte_integration.py (25 endpoints)

**Location**: `suite-api/apps/mpte_integration.py`  
**Prefix**: `/mpte`  
**Dependencies**: `core.mpte_advanced`, `core.exploit_generator`, `core.continuous_validation`, `core.mpte_db`, `core.llm_providers`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/config` | List MPTE configs | R: MPTEDB |
| POST | `/config` | Create MPTE config | W: MPTEDB |
| GET | `/config/{id}` | Get config | R: MPTEDB |
| PUT | `/config/{id}` | Update config | W: MPTEDB |
| POST | `/pentest/run` | Execute standard pentest | W: AdvancedMPTEClient |
| POST | `/pentest/consensus` | Run multi-AI consensus pentest | W: MultiAIOrchestrator |
| GET | `/pentest/{id}/status` | Get pentest status | R: MPTEDB |
| POST | `/pentest/by-finding` | Pentest specific finding | W: AdvancedMPTEClient |
| POST | `/exploit/generate` | Generate exploit | W: ExploitGenerator |
| POST | `/exploit/chain` | Chain exploits | W: ExploitGenerator |
| POST | `/exploit/optimize` | Optimize exploit payload | W: ExploitGenerator |
| POST | `/validation/trigger` | Trigger continuous validation | W: ContinuousValidation |
| GET | `/validation/job/{id}` | Get validation job | R: ContinuousValidation |
| GET | `/validation/posture` | Get security posture | R: ContinuousValidation |
| GET | `/validation/history` | Validation history | R: ContinuousValidation |
| GET | `/validation/statistics` | Validation stats | R: ContinuousValidation |
| POST | `/remediation/validate` | Validate remediation | R: ContinuousValidation |
| GET | `/statistics` | Overall MPTE stats | R: MPTEDB |
| GET | `/exploitable` | Exploitable findings | R: MPTEDB |
| GET | `/false-positives` | False positive findings | R: MPTEDB |
| GET | `/health` | Health check | None |

---

### 5.2 new_backend/api.py (3 endpoints)

**Location**: `suite-core/new_backend/api.py`  
**Factory**: `create_app()`

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| POST | `/decisions` | Make risk decision (≥0.85=block, ≥0.6=review) | R: Request body |
| POST | `/decisions/{id}/feedback` | Submit decision feedback | W: In-memory |
| GET | `/health` | Health check | None |

Lightweight validation/test app.

---

### 5.3 collector_api/app.py (3 endpoints)

**Location**: `suite-core/telemetry_bridge/edge_collector/collector_api/app.py`  
**Standalone FastAPI app** (437 lines)

| Method | Path | Purpose | Data |
|--------|------|---------|------|
| GET | `/health` | Collector health | R: Ring buffer stats |
| POST | `/telemetry` | Ingest telemetry (forward or file mode) | W: HTTP forward / File |
| GET | `/evidence` | Export evidence bundle (ring buffer → gzip → SHA256 → cloud) | R: Ring buffer → W: S3/Azure/GCS/Local |

**Features**: Thread-safe RingBuffer (200K lines, 6hr max); cloud upload (S3/Azure Blob/GCS); path traversal protection.

---

## 6. Cross-Suite Dependency Map

```
suite-api ──┬── core.analytics_db       (suite-core)
            ├── core.audit_db           (suite-core)
            ├── core.auth_db            (suite-core)
            ├── core.connectors         (suite-core) ← Jira, ServiceNow, GitLab, GitHub, AzureDevOps, Slack, Confluence
            ├── core.security_connectors(suite-core) ← Snyk, SonarQube, Dependabot, AWS Security Hub, Azure Sec Center
            ├── core.event_bus          (suite-core)
            ├── core.findings_db        (suite-core)
            ├── core.integration_db     (suite-core)
            ├── core.inventory_db       (suite-core)
            ├── core.knowledge_brain    (suite-core)
            ├── core.policy_db          (suite-core)
            ├── core.report_db          (suite-core)
            ├── core.user_db            (suite-core)
            ├── core.workflow_db        (suite-core)
            ├── core.autofix_engine     (suite-core)
            ├── core.services.*         (suite-core) ← dedup, collaboration, remediation, fuzzy_identity
            ├── feeds_service           (suite-feeds)
            └── apps.api.normalizers    (self)

suite-core ──┬── core.knowledge_brain   (self — NetworkX graph)
             ├── core.event_bus         (self — asyncio event system)
             ├── core.llm_providers     (self — OpenAI, Anthropic, Google)
             ├── core.api_learning_store(self — scikit-learn ML)
             ├── core.brain_pipeline    (self — 12-step orchestrator)
             ├── core.soc2_evidence     (self — evidence generation)
             ├── core.attack_simulation (self — BAS engine)
             ├── core.autofix_engine    (self)
             ├── core.enhanced_decision (self)
             ├── core.models.*          (self — Markov, Bayesian)
             ├── feeds_service          (suite-feeds) ← EPSS, KEV enrichment
             ├── httpx → MPTE           (suite-attack) ← pentest calls
             └── enterprise modules     (optional — importlib)

suite-attack ┬── core.micro_pentest     (suite-core)
             ├── core.real_scanner      (suite-core)
             ├── core.mpte_db           (suite-core)
             ├── core.mpte_advanced     (suite-core)
             ├── core.exploit_generator (suite-core)
             ├── core.continuous_validation (suite-core)
             ├── core.attack_sim_engine (suite-core)
             ├── core.sast_engine       (suite-core)
             ├── core.cspm_engine       (suite-core)
             ├── core.container_scanner (suite-core)
             ├── core.malware_detector  (suite-core)
             ├── core.dast_engine       (suite-core)
             ├── core.api_fuzzer        (suite-core)
             ├── core.secrets_db/scanner(suite-core)
             ├── core.llm_providers     (suite-core) ← micro_pentest PoC generation
             ├── core.event_bus         (suite-core)
             ├── core.knowledge_brain   (suite-core)
             └── feeds_service          (suite-feeds) ← vuln_discovery ML training

suite-feeds ──┬── feeds_service         (self — FeedsService singleton)
              ├── core.event_bus        (suite-core)
              └── core.knowledge_brain  (suite-core)
```

---

## 7. In-Memory State Concerns

All items below are **lost on service restart**:

| Router | Variable(s) | Impact |
|--------|-------------|--------|
| `bulk_router.py` | `_jobs` | Background job tracking lost |
| `copilot_router.py` | `_sessions`, `_messages`, `_actions` | Entire conversation state lost |
| `agents_router.py` | `_agent_tasks` | Agent task tracking lost |
| `inventory_router.py` | `_dependency_store`, `_service_store`, `_api_store`, `_component_store` | Components/APIs/deps lost |
| `policies_router.py` | `_violation_store` | Violation records lost |
| `users_router.py` | `_login_attempts` | Rate limiting bypassed via restart |
| `workflows_router.py` | `_sla_store`, `_execution_steps`, `_paused_executions` | SLA + workflow state lost |
| `llm_router.py` | `_settings` | LLM config reverts to defaults |
| `intelligent_engine_routes.py` | `_sessions`, `_results` | ISE session state lost |
| `vuln_discovery_router.py` | `_discovered_vulns`, `_contributions`, `_retrain_jobs` | **ALL discovered vulns lost** |
| `micro_pentest_router.py` | `enterprise_engine._scans`, `_audit_logs`, `_active_scans` | Scan results + audit trail lost |
| `nerve_center.py` | overlay config | Overlay settings revert |
| `new_backend/api.py` | decision feedback | Feedback lost |

**Highest risk**: `vuln_discovery_router.py` — stores ALdeci-discovered vulnerabilities (pre-CVE intelligence) entirely in-memory with no persistence.

---

## 8. Prefix Inconsistencies

| Router | Prefix | Expected |
|--------|--------|----------|
| `decisions.py` | `/decisions` | `/api/v1/decisions` |
| `intelligent_engine_routes.py` | `/intelligent-engine` | `/api/v1/intelligent-engine` |
| `pipeline_router.py` | `/api/v1/brain` | `/api/v1/pipeline` (conflicts with brain_router) |
| `marketplace_router.py` | (none) | `/api/v1/marketplace` |
| `mpte_integration.py` | `/mpte` | `/api/v1/mpte` (conflicts with mpte_router) |

---

## 9. Stub & Unimplemented Endpoints

| Router | Endpoints | Issue |
|--------|-----------|-------|
| `agents_router.py` | 7 remediation agent endpoints | All return `{"status": "integration_required"}` |
| `pentagi_router.py` | 6 POST endpoints | All return hardcoded/synthetic responses |
| `bulk_router.py` | `GET /findings`, `POST /findings/{id}/status` | Legacy stubs returning fake success |
| `reports_router.py` | `POST /generate` | Report generation mostly stubbed |
| `vuln_discovery_router.py` | `POST /train` | ML training requires MindsDB — always fails without it |

---

## 10. Security Concerns

### Critical

| Issue | Location | Details |
|-------|----------|---------|
| **TLS verification disabled** | `mpte_router.py`, `micro_pentest_router.py`, `agents_router.py` | All MPTE calls use `httpx.AsyncClient(verify=False)` |
| **SSRF risk** | `workflows_router.py` | `http_call` action allows arbitrary URL requests with no validation |
| **No RBAC** | `app.py` | Any valid API key = full admin access |

### Medium

| Issue | Location | Details |
|-------|----------|---------|
| **Rate limiting not wired** | `rate_limiter.py` | `RateLimitMiddleware` defined but not added to app |
| **In-memory rate limiting** | `users_router.py` | Login attempt tracking resets on restart |
| **Deprecated API** | Multiple routers | `datetime.utcnow()` → should use `datetime.now(timezone.utc)` |
| **Path to /tmp** | `reports_router.py` | Report file_path points to /tmp |

### Low

| Issue | Location | Details |
|-------|----------|---------|
| **Webhook auth** | `webhooks_router.py` | ServiceNow/Azure DevOps inbound webhooks have no auth |
| **sys.path insertion** | `micro_pentest_router.py` | `sys.path.insert(0, "tools")` in report generation |

---

## 11. Inter-Endpoint Interaction Flows

### Flow 1: Finding → Remediation → AutoFix

```
POST /api/v1/analytics/findings         (create finding)
  → Brain.ingest_finding()
  → EventBus.emit(FINDING_CREATED)
  
POST /api/v1/remediation/tasks           (create remediation task)
  → Brain.ingest_remediation()
  → EventBus.emit(REMEDIATION_CREATED)
  
POST /api/v1/remediation/tasks/{id}/autofix  (trigger autofix)
  → AutoFixEngine.generate()
  → AutoFixEngine.apply() → creates PR
  → EventBus.emit(REMEDIATION_UPDATED)
```

### Flow 2: Copilot → Agents → Feeds → MPTE

```
POST /api/v1/copilot/sessions           (create session)
POST /api/v1/copilot/sessions/{id}/messages  (send message → real LLM call)
  → LLMProviderManager.generate()
  → FeedsService enrichment (EPSS, KEV)
  → Brain context injection

POST /api/v1/copilot/actions             (execute agent action)
  → type=analyze → SecurityAnalystAgent
    → FeedsService.get_epss() / .get_kev()
  → type=pentest → PentestAgent  
    → httpx → MPTE /api/v1/verify  (verify=False)
  → type=remediate → RemediationAgent
    → AutoFixEngine.generate()
```

### Flow 3: Feed Refresh → Enrichment → Brain

```
POST /api/v1/feeds/refresh/all           (refresh all feeds)
  → FeedsService.refresh_epss()
  → FeedsService.refresh_kev()
  → FeedsService.refresh_nvd()
  → FeedsService.refresh_exploitdb()
  → FeedsService.refresh_osv()
  → FeedsService.refresh_github_advisories()
  → EventBus.emit(FEED_UPDATED)

POST /api/v1/feeds/enrich                (enrich findings)
  → FeedsService.enrich_findings_comprehensive()
  → Brain.ingest_cve()
  → EventBus.emit(FEED_UPDATED)
```

### Flow 4: Micro Pentest → Brain → Evidence

```
POST /api/v1/micro-pentest/enterprise/scan  (8-phase scan)
  Phase 1: LLM → target analysis
  Phase 2: LLM → reconnaissance
  Phase 3: LLM → threat modeling
  Phase 4: RealVulnerabilityScanner → findings
  Phase 5: LLM → PoC generation
  Phase 6: compliance validation
  Phase 7: LLM → risk scoring
  Phase 8: attack path generation
  → EventBus.emit(SCAN_STARTED, SCAN_COMPLETED, FINDING_CREATED)
  → Brain.ingest_scan() + Brain.ingest_finding()

POST /api/v1/brain/evidence/generate     (SOC2 evidence bundle)
  → SOC2EvidenceGenerator.generate()
```

### Flow 5: Vulnerability Discovery → CVE Contribution

```
POST /api/v1/vulns/discovered            (report discovered vuln)
  → Generate ALDECI-YYYY-NNNN ID
  → Brain.ingest_finding()
  → EventBus.emit(FINDING_CREATED)
  → [optional] _notify_vendor() background task

POST /api/v1/vulns/contribute            (submit to CVE program)
  → Validate vuln status (DRAFT/INTERNAL/REPORTED_VENDOR)
  → Update status → CVE_REQUESTED
  → Track submission (MITRE/CISA/CERT/Vendor)
```

### Flow 6: Nerve Center → All Suites

```
GET /api/v1/nerve-center/state           (full system state)
  → httpx → localhost:8000/api/v1/health     (self-probe)
  → httpx → localhost:8000/api/v1/ml/status  (ML status)
  → Brain.get_stats()                         (graph stats)
  → EventBus.get_recent()                    (recent events)
  → DecisionEngine.get_metrics()             (decision stats)
  
GET /api/v1/nerve-center/pulse           (real-time threat pulse)
  → Brain risk scoring
  → LearningStore threat assessment
  → EventBus recent alerts
```

### Flow 7: Deduplication → Bulk → Ticket Creation

```
POST /api/v1/deduplication/batch         (batch dedup)
  → DeduplicationService.process_batch()
  → Returns clusters

GET /api/v1/bulk/clusters                (view clusters)
POST /api/v1/bulk/clusters/{id}/create-ticket  (create ticket)
  → IntegrationDB.get_by_type("jira")
  → JiraConnector.create_issue()
```

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| **Total router files** | 55 (16 suite-api + 17 suite-core + 12 suite-attack + 1 suite-feeds + 3 standalone + 6 duplicates) |
| **Total unique endpoints** | ~370+ |
| **SQLite-backed stores** | 15+ (analytics, audit, auth, feeds, findings, integration, inventory, mpte, policy, report, remediation, secrets, user, workflow, collaboration) |
| **In-memory stores** | 13 routers (see Section 7) |
| **Stub endpoints** | ~20 (see Section 9) |
| **Endpoints with real LLM calls** | ~25 (copilot, agents, micro_pentest enterprise, enhanced) |
| **Endpoints with MPTE calls** | ~15 (agents pentest, mpte_router, micro_pentest, mpte_integration) |
| **Event types emitted** | FINDING_CREATED, REMEDIATION_CREATED/UPDATED, FEED_UPDATED, EPSS_UPDATED, KEV_ALERT, ASSET_DISCOVERED, SCAN_STARTED/COMPLETED, PENTEST_STARTED/COMPLETED, SECRET_FOUND, CVE_DISCOVERED, GRAPH_UPDATED, COPILOT_QUERY/RESPONSE |
