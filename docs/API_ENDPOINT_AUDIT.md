# FixOps / ALdeci — Comprehensive API Endpoint Audit

> **Generated**: 2026-02-27
> **Total Endpoints**: **641+**
> **Total Router Files**: 60+
> **Organized by**: Suite → Router File → Endpoint

---

## Table of Contents

1. [suite-api/apps/api/app.py — Inline Endpoints](#1-suite-apiappsapiapppy--inline-endpoints)
2. [suite-api/apps/api/ — Router Files](#2-suite-apiappsapi--router-files)
3. [suite-core/api/ — Router Files](#3-suite-coreapi--router-files)
4. [suite-attack/api/ — Router Files](#4-suite-attackapi--router-files)
5. [suite-feeds/api/ — Router Files](#5-suite-feedsapi--router-files)
6. [suite-evidence-risk/api/ — Router Files](#6-suite-evidence-riskapi--router-files)
7. [suite-integrations/api/ — Router Files](#7-suite-integrationsapi--router-files)
8. [Summary Statistics](#8-summary-statistics)

---

## 1. suite-api/apps/api/app.py — Inline Endpoints

These endpoints are defined directly in `create_app()`, not in separate router files.

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/health` | `legacy_health_check` | Legacy health endpoint for backward-compatible Docker/script probes |
| 2 | GET | `/api/v1/status` | `authenticated_status` | Authenticated status endpoint (requires API key) |
| 3 | GET | `/api/v1/search` | `global_search` | Global search across findings, CVEs, assets |
| 4 | POST | `/inputs/design` | `ingest_design` | Ingest design-phase security context |
| 5 | POST | `/inputs/sbom` | `ingest_sbom` | Ingest SBOM (Software Bill of Materials) |
| 6 | POST | `/inputs/cve` | `ingest_cve` | Ingest CVE data |
| 7 | POST | `/inputs/vex` | `ingest_vex` | Ingest VEX (Vulnerability Exploitability eXchange) data |
| 8 | POST | `/inputs/cnapp` | `ingest_cnapp` | Ingest CNAPP (Cloud-Native Application Protection) data |
| 9 | POST | `/inputs/sarif` | `ingest_sarif` | Ingest SARIF scanner results |
| 10 | POST | `/inputs/context` | `ingest_context` | Ingest business context data |
| 11 | POST | `/api/v1/ingest/multipart` | `ingest_multipart` | Multipart file ingest endpoint |
| 12 | GET | `/api/v1/ingest/assets` | `get_asset_inventory` | Get asset inventory from ingested data |
| 13 | GET | `/api/v1/ingest/formats` | `list_supported_formats` | List supported ingest formats |
| 14 | POST | `/inputs/{stage}/chunks/start` | `initialise_chunk_upload` | Initialize chunked file upload for a stage |
| 15 | GET | `/api/v1/triage` | `get_triage` | Get triage data from last pipeline run |
| 16 | GET | `/api/v1/triage/export` | `export_triage` | Export triage data as CSV or JSON |
| 17 | GET | `/api/v1/graph` | `get_graph` | Transform last pipeline result into interactive graph format |
| 18 | GET | `/analytics/dashboard` | `analytics_dashboard` | Analytics dashboard data |
| 19 | GET | `/analytics/runs/{run_id}` | `analytics_run` | Get specific analytics run data |
| 20 | POST | `/feedback` | `submit_feedback` | Submit feedback on decisions |

**Subtotal: 20 endpoints**

---

## 2. suite-api/apps/api/ — Router Files

### 2.1 health.py — Health Router
**Router prefix**: `/api/v1` | **Tags**: `health`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/health` | `health_check` | Health check with component status |
| 2 | GET | `/api/v1/ready` | `readiness_check` | Readiness check for k8s/load balancers |
| 3 | GET | `/api/v1/version` | `version_info` | Version and build information |
| 4 | GET | `/api/v1/metrics` | `metrics` | Prometheus-style metrics |

**Subtotal: 4 endpoints**

### 2.2 analytics_router.py — Analytics
**Router prefix**: `/api/v1/analytics` | **Tags**: `analytics`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/analytics/dashboard/overview` | `dashboard_overview` | Dashboard overview data |
| 2 | GET | `/api/v1/analytics/dashboard/trends` | `dashboard_trends` | Dashboard trend data |
| 3 | GET | `/api/v1/analytics/dashboard/top-risks` | `dashboard_top_risks` | Top risks for dashboard |
| 4 | GET | `/api/v1/analytics/dashboard/compliance-status` | `dashboard_compliance_status` | Compliance status for dashboard |
| 5 | GET | `/api/v1/analytics/findings` | `list_findings` | List all findings |
| 6 | POST | `/api/v1/analytics/findings` | `create_finding` | Create a new finding |
| 7 | GET | `/api/v1/analytics/findings/{id}` | `get_finding` | Get finding by ID |
| 8 | PUT | `/api/v1/analytics/findings/{id}` | `update_finding` | Update a finding |
| 9 | GET | `/api/v1/analytics/decisions` | `list_decisions` | List all decisions |
| 10 | POST | `/api/v1/analytics/decisions` | `create_decision` | Create a new decision |
| 11 | GET | `/api/v1/analytics/mttr` | `get_mttr` | Mean Time to Remediation metrics |
| 12 | GET | `/api/v1/analytics/coverage` | `get_coverage` | Security coverage metrics |
| 13 | GET | `/api/v1/analytics/roi` | `get_roi` | ROI analysis metrics |
| 14 | GET | `/api/v1/analytics/noise-reduction` | `get_noise_reduction` | Noise reduction metrics |
| 15 | POST | `/api/v1/analytics/custom-query` | `custom_query` | Execute a custom analytics query |
| 16 | GET | `/api/v1/analytics/export` | `export_analytics` | Export analytics data |
| 17 | GET | `/api/v1/analytics/stats` | `get_stats` | Analytics statistics |
| 18 | GET | `/api/v1/analytics/summary` | `get_summary` | Analytics summary |
| 19 | GET | `/api/v1/analytics/trends/severity-over-time` | `severity_over_time` | Severity trends over time |
| 20 | GET | `/api/v1/analytics/trends/anomalies` | `trend_anomalies` | Trend anomaly detection |
| 21 | GET | `/api/v1/analytics/compare` | `compare_periods` | Compare analytics across time periods |
| 22 | GET | `/api/v1/analytics/risk-velocity` | `risk_velocity` | Risk velocity metrics |

**Subtotal: 22 endpoints**

### 2.3 audit_router.py — Audit Logs & Compliance
**Router prefix**: `/api/v1/audit` | **Tags**: `audit`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/audit/logs` | `list_audit_logs` | List audit logs (paginated) |
| 2 | GET | `/api/v1/audit/logs/export` | `export_audit_logs` | Export audit logs |
| 3 | GET | `/api/v1/audit/logs/{id}` | `get_audit_log` | Get specific audit log entry |
| 4 | GET | `/api/v1/audit/user-activity` | `get_user_activity` | Get user activity summary |
| 5 | GET | `/api/v1/audit/policy-changes` | `get_policy_changes` | Get policy change audit trail |
| 6 | GET | `/api/v1/audit/decision-trail` | `get_decision_trail` | Get decision audit trail |
| 7 | GET | `/api/v1/audit/compliance/frameworks` | `list_compliance_frameworks` | List compliance frameworks |
| 8 | GET | `/api/v1/audit/compliance/frameworks/{id}/status` | `get_framework_status` | Get compliance framework status |
| 9 | GET | `/api/v1/audit/compliance/frameworks/{id}/gaps` | `get_framework_gaps` | Get compliance framework gaps |
| 10 | POST | `/api/v1/audit/compliance/frameworks/{id}/report` | `generate_compliance_report` | Generate compliance report |
| 11 | GET | `/api/v1/audit/compliance/controls` | `list_compliance_controls` | List compliance controls |
| 12 | POST | `/api/v1/audit/logs/chain` | `create_log_chain` | Create chained audit log entry |
| 13 | GET | `/api/v1/audit/chain/verify` | `verify_chain` | Verify audit log chain integrity |
| 14 | GET | `/api/v1/audit/retention` | `get_retention_config` | Get audit log retention configuration |

**Subtotal: 14 endpoints**

### 2.4 auth_router.py — Authentication / SSO
**Router prefix**: `/api/v1/auth` | **Tags**: `authentication`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/auth/sso` | `list_sso_configs` | List SSO configurations (paginated) |
| 2 | POST | `/api/v1/auth/sso` | `create_sso_config` | Create SSO configuration |
| 3 | GET | `/api/v1/auth/sso/{id}` | `get_sso_config` | Get SSO configuration by ID |
| 4 | PUT | `/api/v1/auth/sso/{id}` | `update_sso_config` | Update SSO configuration |

**Subtotal: 4 endpoints**

### 2.5 bulk_router.py — Bulk Operations
**Router prefix**: `/api/v1/bulk` | **Tags**: `bulk`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/bulk/clusters/status` | `bulk_update_cluster_status` | Bulk update cluster statuses |
| 2 | POST | `/api/v1/bulk/clusters/assign` | `bulk_assign_clusters` | Bulk assign clusters |
| 3 | POST | `/api/v1/bulk/clusters/accept-risk` | `bulk_accept_risk` | Bulk accept risk for clusters |
| 4 | POST | `/api/v1/bulk/clusters/create-tickets` | `bulk_create_tickets` | Bulk create tickets for clusters |
| 5 | POST | `/api/v1/bulk/export` | `bulk_export` | Bulk export data |
| 6 | GET | `/api/v1/bulk/exports/{filename}` | `download_export` | Download exported file |
| 7 | GET | `/api/v1/bulk/jobs/{job_id}` | `get_job_status` | Get bulk job status |
| 8 | GET | `/api/v1/bulk/jobs` | `list_jobs` | List bulk jobs |
| 9 | DELETE | `/api/v1/bulk/jobs/{job_id}` | `delete_job` | Delete a bulk job |
| 10 | POST | `/api/v1/bulk/findings/update` | `bulk_update_findings` | Bulk update findings |
| 11 | POST | `/api/v1/bulk/findings/delete` | `bulk_delete_findings` | Bulk delete findings |
| 12 | POST | `/api/v1/bulk/findings/assign` | `bulk_assign_findings` | Bulk assign findings |
| 13 | POST | `/api/v1/bulk/policies/apply` | `bulk_apply_policies` | Bulk apply policies |

**Subtotal: 13 endpoints**

### 2.6 collaboration_router.py — Collaboration
**Router prefix**: `/api/v1/collaboration` | **Tags**: `collaboration`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/collaboration/comments` | `create_comment` | Create a comment |
| 2 | GET | `/api/v1/collaboration/comments` | `list_comments` | List comments |
| 3 | PUT | `/api/v1/collaboration/comments/{comment_id}/promote` | `promote_comment` | Promote comment to decision |
| 4 | POST | `/api/v1/collaboration/watchers` | `add_watcher` | Add entity watcher |
| 5 | DELETE | `/api/v1/collaboration/watchers` | `remove_watcher` | Remove entity watcher |
| 6 | GET | `/api/v1/collaboration/watchers` | `list_watchers` | List watchers for entity |
| 7 | GET | `/api/v1/collaboration/watchers/user/{user_id}` | `get_user_watches` | Get all entities a user watches |
| 8 | POST | `/api/v1/collaboration/activities` | `log_activity` | Log an activity |
| 9 | GET | `/api/v1/collaboration/activities` | `list_activities` | List activities |
| 10 | GET | `/api/v1/collaboration/mentions/{user_id}` | `get_user_mentions` | Get mentions for a user |
| 11 | PUT | `/api/v1/collaboration/mentions/{mention_id}/acknowledge` | `acknowledge_mention` | Acknowledge a mention |
| 12 | GET | `/api/v1/collaboration/entity-types` | `get_entity_types` | Get supported entity types |
| 13 | GET | `/api/v1/collaboration/activity-types` | `get_activity_types` | Get supported activity types |
| 14 | POST | `/api/v1/collaboration/notifications/queue` | `queue_notification` | Queue a notification |
| 15 | POST | `/api/v1/collaboration/notifications/notify-watchers` | `notify_watchers` | Notify all watchers of an entity |
| 16 | GET | `/api/v1/collaboration/notifications/pending` | `get_pending_notifications` | Get pending notifications |
| 17 | PUT | `/api/v1/collaboration/notifications/{notification_id}/sent` | `mark_notification_sent` | Mark notification as sent |
| 18 | GET | `/api/v1/collaboration/notifications/preferences/{user_id}` | `get_notification_preferences` | Get user notification preferences |
| 19 | PUT | `/api/v1/collaboration/notifications/preferences/{user_id}` | `update_notification_preferences` | Update user notification preferences |
| 20 | POST | `/api/v1/collaboration/notifications/{notification_id}/deliver` | `deliver_notification` | Deliver a notification via configured channels |
| 21 | POST | `/api/v1/collaboration/notifications/process` | `process_pending_notifications` | Process all pending notifications |

**Subtotal: 21 endpoints**

### 2.7 fail_router.py — FAIL Engine
**Router prefix**: `/api/v1/fail` | **Tags**: `fail-engine`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/fail/score` | `score_finding` | Score a single finding with FAIL engine |
| 2 | POST | `/api/v1/fail/score/batch` | `score_batch` | Score multiple findings |
| 3 | GET | `/api/v1/fail/score/{score_id}` | `get_score` | Get a stored FAIL score |
| 4 | GET | `/api/v1/fail/scores` | `list_scores` | List FAIL scores |
| 5 | GET | `/api/v1/fail/top-risks` | `get_top_risks` | Top risks by FAIL score |
| 6 | GET | `/api/v1/fail/stats` | `get_stats` | FAIL score statistics |
| 7 | GET | `/api/v1/fail/cve/{cve_id}` | `get_cve_scores` | FAIL scores for a CVE |
| 8 | DELETE | `/api/v1/fail/score/{score_id}` | `delete_score` | Delete a FAIL score |
| 9 | GET | `/api/v1/fail/health` | `fail_health` | FAIL engine health check |

**Subtotal: 9 endpoints**

### 2.8 inventory_router.py — Asset Inventory
**Router prefix**: `/api/v1/inventory` | **Tags**: `inventory`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/inventory/assets` | `list_assets` | List assets (paginated) |
| 2 | GET | `/api/v1/inventory/applications` | `list_applications` | List applications (paginated) |
| 3 | POST | `/api/v1/inventory/applications` | `create_application` | Create an application |
| 4 | GET | `/api/v1/inventory/applications/{id}` | `get_application` | Get application by ID |
| 5 | PUT | `/api/v1/inventory/applications/{id}` | `update_application` | Update an application |
| 6 | DELETE | `/api/v1/inventory/applications/{id}` | `delete_application` | Delete an application |
| 7 | GET | `/api/v1/inventory/applications/{id}/components` | `get_app_components` | Get application components |
| 8 | GET | `/api/v1/inventory/applications/{id}/apis` | `get_app_apis` | Get application APIs |
| 9 | POST | `/api/v1/inventory/applications/{id}/dependencies` | `add_dependencies` | Add application dependencies |
| 10 | GET | `/api/v1/inventory/applications/{id}/dependencies` | `get_dependencies` | Get application dependencies |
| 11 | GET | `/api/v1/inventory/services` | `list_services` | List services |
| 12 | POST | `/api/v1/inventory/services` | `create_service` | Create a service |
| 13 | GET | `/api/v1/inventory/services/{id}` | `get_service` | Get service by ID |
| 14 | GET | `/api/v1/inventory/apis` | `list_apis` | List APIs |
| 15 | POST | `/api/v1/inventory/apis` | `create_api` | Create an API entry |
| 16 | GET | `/api/v1/inventory/apis/{id}/security` | `get_api_security` | Get API security details |
| 17 | GET | `/api/v1/inventory/search` | `search_inventory` | Search inventory |
| 18 | GET | `/api/v1/inventory/applications/{id}/license-compliance` | `get_license_compliance` | Get application license compliance |
| 19 | GET | `/api/v1/inventory/applications/{id}/sbom` | `get_sbom` | Get application SBOM |

**Subtotal: 19 endpoints**

### 2.9 marketplace_router.py — Compliance Marketplace
**Router prefix**: `/api/v1/marketplace` (set at mount) | **Tags**: `marketplace`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/marketplace/packs/{framework}/{control}` | `get_compliance_pack` | Get compliance pack |
| 2 | GET | `/api/v1/marketplace/browse` | `browse_marketplace` | Browse marketplace items |
| 3 | GET | `/api/v1/marketplace/recommendations` | `get_recommendations` | Get AI-powered marketplace recommendations |
| 4 | GET | `/api/v1/marketplace/items/{item_id}` | `get_item` | Get marketplace item detail |
| 5 | POST | `/api/v1/marketplace/contribute` | `contribute_item` | Contribute item to marketplace |
| 6 | PUT | `/api/v1/marketplace/items/{item_id}` | `update_item` | Update marketplace item |
| 7 | POST | `/api/v1/marketplace/items/{item_id}/rate` | `rate_item` | Rate a marketplace item |
| 8 | POST | `/api/v1/marketplace/purchase/{item_id}` | `purchase_item` | Purchase/install marketplace item |
| 9 | GET | `/api/v1/marketplace/download/{token}` | `download_item` | Download purchased item |
| 10 | GET | `/api/v1/marketplace/contributors` | `list_contributors` | List marketplace contributors |
| 11 | GET | `/api/v1/marketplace/compliance-content/{stage}` | `get_compliance_content` | Get compliance content by stage |
| 12 | GET | `/api/v1/marketplace/stats` | `get_marketplace_stats` | Get marketplace statistics |

**Subtotal: 12 endpoints**

### 2.10 policies_router.py — Security Policies
**Router prefix**: `/api/v1/policies` | **Tags**: `policies`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/policies` | `list_policies` | List policies (paginated) |
| 2 | POST | `/api/v1/policies` | `create_policy` | Create a policy |
| 3 | GET | `/api/v1/policies/{id}` | `get_policy` | Get policy by ID |
| 4 | PUT | `/api/v1/policies/{id}` | `update_policy` | Update a policy |
| 5 | DELETE | `/api/v1/policies/{id}` | `delete_policy` | Delete a policy |
| 6 | POST | `/api/v1/policies/{id}/validate` | `validate_policy` | Validate a policy |
| 7 | POST | `/api/v1/policies/{id}/test` | `test_policy` | Test a policy against findings |
| 8 | GET | `/api/v1/policies/{id}/violations` | `get_violations` | Get policy violations |
| 9 | POST | `/api/v1/policies/{id}/enforce` | `enforce_policy` | Enforce a policy |
| 10 | POST | `/api/v1/policies/simulate` | `simulate_policy` | Simulate policy against findings |
| 11 | GET | `/api/v1/policies/conflicts` | `get_conflicts` | Get policy conflicts |

**Subtotal: 11 endpoints**

### 2.11 remediation_router.py — Remediation Center
**Router prefix**: `/api/v1/remediation` | **Tags**: `remediation`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/remediation/tasks` | `create_task` | Create a remediation task |
| 2 | GET | `/api/v1/remediation/tasks` | `list_tasks` | List remediation tasks |
| 3 | GET | `/api/v1/remediation/tasks/{task_id}` | `get_task` | Get task by ID |
| 4 | PUT | `/api/v1/remediation/tasks/{task_id}/status` | `update_task_status` | Update task status |
| 5 | PUT | `/api/v1/remediation/tasks/{task_id}/assign` | `assign_task` | Assign task to user |
| 6 | POST | `/api/v1/remediation/tasks/{task_id}/verification` | `add_verification` | Add verification to task |
| 7 | PUT | `/api/v1/remediation/tasks/{task_id}/ticket` | `link_ticket` | Link external ticket to task |
| 8 | POST | `/api/v1/remediation/sla/check` | `check_sla` | Check SLA compliance |
| 9 | GET | `/api/v1/remediation/metrics/{org_id}` | `get_org_metrics` | Get remediation metrics by org |
| 10 | GET | `/api/v1/remediation/statuses` | `list_statuses` | List available statuses |
| 11 | POST | `/api/v1/remediation/tasks/{task_id}/autofix` | `trigger_autofix` | Trigger AutoFix for a task |
| 12 | GET | `/api/v1/remediation/tasks/{task_id}/autofix/suggestions` | `get_autofix_suggestions` | Get AutoFix suggestions for task |
| 13 | PUT | `/api/v1/remediation/tasks/{task_id}/transition` | `transition_task` | Transition task state |
| 14 | POST | `/api/v1/remediation/tasks/{task_id}/verify` | `verify_task` | Verify remediation task |
| 15 | GET | `/api/v1/remediation/metrics` | `get_global_metrics` | Get global remediation metrics |

**Subtotal: 15 endpoints**

### 2.12 reports_router.py — Report Generation
**Router prefix**: `/api/v1/reports` | **Tags**: `reports`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/reports` | `list_reports` | List reports (paginated) |
| 2 | POST | `/api/v1/reports` | `create_report` | Create a report |
| 3 | POST | `/api/v1/reports/generate` | `generate_report` | Generate a report |
| 4 | GET | `/api/v1/reports/stats` | `get_report_stats` | Get report statistics |
| 5 | GET | `/api/v1/reports/{id}` | `get_report` | Get report by ID |
| 6 | GET | `/api/v1/reports/{id}/download` | `download_report` | Download report file |
| 7 | GET | `/api/v1/reports/{id}/file` | `get_report_file` | Get report file directly |
| 8 | POST | `/api/v1/reports/schedule` | `schedule_report` | Schedule a recurring report |
| 9 | GET | `/api/v1/reports/schedules/list` | `list_schedules` | List report schedules |
| 10 | GET | `/api/v1/reports/templates/list` | `list_templates` | List report templates |
| 11 | POST | `/api/v1/reports/export/sarif` | `export_sarif` | Export as SARIF format |
| 12 | POST | `/api/v1/reports/export/csv` | `export_csv` | Export as CSV format |
| 13 | GET | `/api/v1/reports/export/csv/{export_id}/download` | `download_csv_export` | Download CSV export |
| 14 | GET | `/api/v1/reports/export/json` | `export_json` | Export as JSON format |

**Subtotal: 14 endpoints**

### 2.13 teams_router.py — Team Management
**Router prefix**: `/api/v1/teams` | **Tags**: `teams`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/teams` | `list_teams` | List teams (paginated) |
| 2 | POST | `/api/v1/teams` | `create_team` | Create a team |
| 3 | GET | `/api/v1/teams/{id}` | `get_team` | Get team by ID |
| 4 | PUT | `/api/v1/teams/{id}` | `update_team` | Update a team |
| 5 | DELETE | `/api/v1/teams/{id}` | `delete_team` | Delete a team |
| 6 | GET | `/api/v1/teams/{id}/members` | `get_members` | Get team members |
| 7 | POST | `/api/v1/teams/{id}/members` | `add_member` | Add team member |
| 8 | DELETE | `/api/v1/teams/{id}/members/{user_id}` | `remove_member` | Remove team member |

**Subtotal: 8 endpoints**

### 2.14 users_router.py — User Management
**Router prefix**: `/api/v1/users` | **Tags**: `users`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/users/login` | `login` | Authenticate and get JWT token |
| 2 | GET | `/api/v1/users` | `list_users` | List users (paginated) |
| 3 | POST | `/api/v1/users` | `create_user` | Create a user |
| 4 | GET | `/api/v1/users/{id}` | `get_user` | Get user by ID |
| 5 | PUT | `/api/v1/users/{id}` | `update_user` | Update a user |
| 6 | DELETE | `/api/v1/users/{id}` | `delete_user` | Delete a user |

**Subtotal: 6 endpoints**

### 2.15 validation_router.py — Input Validation
**Router prefix**: `/api/v1/validate` | **Tags**: `validation`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/validate/input` | `validate_input` | Validate security tool output format |
| 2 | POST | `/api/v1/validate/batch` | `validate_batch` | Batch validate multiple inputs |
| 3 | GET | `/api/v1/validate/supported-formats` | `get_supported_formats` | Get supported validation formats |

**Subtotal: 3 endpoints**

### 2.16 workflows_router.py — Workflows & Automation
**Router prefix**: `/api/v1/workflows` | **Tags**: `workflows`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/workflows` | `list_workflows` | List workflows (paginated) |
| 2 | POST | `/api/v1/workflows` | `create_workflow` | Create a workflow |
| 3 | GET | `/api/v1/workflows/{id}` | `get_workflow` | Get workflow by ID |
| 4 | PUT | `/api/v1/workflows/{id}` | `update_workflow` | Update a workflow |
| 5 | DELETE | `/api/v1/workflows/{id}` | `delete_workflow` | Delete a workflow |
| 6 | POST | `/api/v1/workflows/{id}/execute` | `execute_workflow` | Execute a workflow |
| 7 | GET | `/api/v1/workflows/{id}/history` | `get_execution_history` | Get workflow execution history |
| 8 | GET | `/api/v1/workflows/rules` | `list_rules` | List workflow rules |
| 9 | PUT | `/api/v1/workflows/{id}/sla` | `update_sla` | Update workflow SLA |
| 10 | GET | `/api/v1/workflows/{id}/sla` | `get_sla` | Get workflow SLA |
| 11 | POST | `/api/v1/workflows/executions/{exec_id}/pause` | `pause_execution` | Pause workflow execution |
| 12 | POST | `/api/v1/workflows/executions/{exec_id}/resume` | `resume_execution` | Resume workflow execution |
| 13 | GET | `/api/v1/workflows/executions/{exec_id}/timeline` | `get_execution_timeline` | Get execution timeline |

**Subtotal: 13 endpoints**

### 2.17 routes/enhanced.py — Enhanced Analysis
**Router prefix**: `/api/v1/enhanced` | **Tags**: `enhanced`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/enhanced/analysis` | `run_analysis` | Run enhanced multi-LLM analysis |
| 2 | POST | `/api/v1/enhanced/compare-llms` | `compare_llms` | Compare LLM responses |
| 3 | GET | `/api/v1/enhanced/capabilities` | `get_capabilities` | List enhanced capabilities |
| 4 | GET | `/api/v1/enhanced/signals` | `get_signals` | Get intelligence signals |

**Subtotal: 4 endpoints**

### 2.18 detailed_logging.py — Logs API
**Router prefix**: `/api/v1/logs` (prefix `/logs` + mount prefix `/api/v1`) | **Tags**: `logs`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/logs` | `get_logs` | Query logs |
| 2 | GET | `/api/v1/logs/stats` | `get_log_stats` | Get log statistics |
| 3 | GET | `/api/v1/logs/recent` | `get_recent_logs` | Get recent logs |
| 4 | DELETE | `/api/v1/logs` | `clear_logs` | Clear logs |
| 5 | GET | `/api/v1/logs/stream` | `stream_logs` | Stream logs via SSE |

**Subtotal: 5 endpoints**

---

## 3. suite-core/api/ — Router Files

### 3.1 nerve_center.py — Nerve Center
**Router prefix**: `/api/v1/nerve-center` | **Tags**: `nerve-center`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/nerve-center/pulse` | `get_threat_pulse` | Real-time threat pulse (brain + ML + event bus) |
| 2 | GET | `/api/v1/nerve-center/state` | `get_nerve_center_state` | Full nerve center state |
| 3 | POST | `/api/v1/nerve-center/auto-remediate` | `trigger_auto_remediation` | Trigger auto-remediation from brain |
| 4 | GET | `/api/v1/nerve-center/intelligence-map` | `get_intelligence_map` | Intelligence map (topology + brain graph) |
| 5 | GET | `/api/v1/nerve-center/playbooks` | `list_playbooks` | List all playbooks |
| 6 | POST | `/api/v1/nerve-center/playbooks/validate` | `validate_playbook` | Validate playbook YAML |
| 7 | POST | `/api/v1/nerve-center/playbooks/execute/{playbook_id}` | `execute_playbook` | Execute playbook by ID |
| 8 | GET | `/api/v1/nerve-center/overlay` | `get_overlay_config` | Get overlay configuration |
| 9 | PUT | `/api/v1/nerve-center/overlay` | `update_overlay_config` | Update overlay configuration |

**Subtotal: 9 endpoints**

### 3.2 decisions.py — Decision Engine
**Router prefix**: `/decisions` (mounted with additional `/api/v1` prefix for some paths) | **Tags**: `decisions`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/decisions/make-decision` | `make_security_decision` | Make security decision via multi-LLM consensus |
| 2 | GET | `/api/v1/decisions/metrics` | `get_decision_metrics` | Decision engine performance metrics |
| 3 | GET | `/api/v1/decisions/recent` | `get_recent_decisions` | Get recent pipeline decisions |
| 4 | GET | `/api/v1/decisions/ssdlc-stages` | `get_ssdlc_stage_data` | Get SSDLC stage ingestion status |
| 5 | GET | `/api/v1/decisions/core-components` | `get_core_components_status` | Decision & Verification Core component status |
| 6 | GET | `/api/v1/decisions/evidence/{evidence_id}` | `get_evidence_record` | Get immutable evidence record |

**Subtotal: 6 endpoints**

### 3.3 deduplication_router.py — Finding Deduplication
**Router prefix**: `/api/v1/deduplication` | **Tags**: `deduplication`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/deduplication/process` | `process_finding` | Process single finding for deduplication |
| 2 | POST | `/api/v1/deduplication/process/batch` | `process_findings_batch` | Batch process findings |
| 3 | GET | `/api/v1/deduplication/clusters` | `list_clusters` | List dedup clusters |
| 4 | GET | `/api/v1/deduplication/clusters/{cluster_id}` | `get_cluster` | Get cluster by ID |
| 5 | PUT | `/api/v1/deduplication/clusters/{cluster_id}/status` | `update_cluster_status` | Update cluster status |
| 6 | PUT | `/api/v1/deduplication/clusters/{cluster_id}/assign` | `assign_cluster` | Assign cluster to user |
| 7 | PUT | `/api/v1/deduplication/clusters/{cluster_id}/ticket` | `link_ticket` | Link cluster to ticket |
| 8 | GET | `/api/v1/deduplication/clusters/{cluster_id}/related` | `get_related_clusters` | Get related clusters |
| 9 | GET | `/api/v1/deduplication/correlations` | `list_correlations` | List correlation links |
| 10 | POST | `/api/v1/deduplication/correlations` | `create_correlation_link` | Create correlation link |
| 11 | GET | `/api/v1/deduplication/stats` | `get_dedup_stats_global` | Global dedup statistics |
| 12 | GET | `/api/v1/deduplication/stats/{org_id}` | `get_dedup_stats` | Org-specific dedup statistics |
| 13 | POST | `/api/v1/deduplication/correlate/cross-stage` | `correlate_cross_stage` | Cross-stage correlation |
| 14 | GET | `/api/v1/deduplication/graph` | `get_correlation_graph` | Get correlation graph |
| 15 | POST | `/api/v1/deduplication/feedback` | `record_operator_feedback` | Record operator feedback |
| 16 | POST | `/api/v1/deduplication/baseline/compare` | `compare_baseline` | Compare against baseline |
| 17 | POST | `/api/v1/deduplication/clusters/merge` | `merge_clusters` | Merge clusters |
| 18 | POST | `/api/v1/deduplication/clusters/{cluster_id}/split` | `split_cluster` | Split a cluster |

**Subtotal: 18 endpoints**

### 3.4 brain_router.py — Knowledge Brain Graph
**Router prefix**: `/api/v1/brain` | **Tags**: `brain`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/brain/nodes` | `create_or_update_node` | Create or update Knowledge Graph node |
| 2 | GET | `/api/v1/brain/nodes` | `query_nodes` | Query Knowledge Graph nodes |
| 3 | GET | `/api/v1/brain/nodes/{node_id}` | `get_node` | Get node by ID |
| 4 | DELETE | `/api/v1/brain/nodes/{node_id}` | `delete_node` | Delete node and edges |
| 5 | POST | `/api/v1/brain/edges` | `create_edge` | Create/update edge |
| 6 | GET | `/api/v1/brain/all-edges` | `list_all_edges` | List all edges |
| 7 | GET | `/api/v1/brain/edges/{node_id}` | `get_edges` | Get edges for a node |
| 8 | DELETE | `/api/v1/brain/edges` | `delete_edge` | Delete a specific edge |
| 9 | GET | `/api/v1/brain/neighbors/{node_id}` | `get_neighbors` | Get neighbors with N hops |
| 10 | GET | `/api/v1/brain/paths` | `find_paths` | Find paths between nodes |
| 11 | GET | `/api/v1/brain/stats` | `graph_stats` | Graph statistics |
| 12 | GET | `/api/v1/brain/most-connected` | `most_connected` | Most connected nodes |
| 13 | GET | `/api/v1/brain/risk/{node_id}` | `node_risk_score` | Composite risk score for node |
| 14 | GET | `/api/v1/brain/events` | `get_events` | Recent Knowledge Brain events |
| 15 | GET | `/api/v1/brain/meta/entity-types` | `list_entity_types` | List entity types |
| 16 | GET | `/api/v1/brain/meta/edge-types` | `list_edge_types` | List edge types |
| 17 | POST | `/api/v1/brain/ingest/cve` | `ingest_cve` | Ingest CVE into brain |
| 18 | POST | `/api/v1/brain/ingest/finding` | `ingest_finding` | Ingest finding into brain |
| 19 | POST | `/api/v1/brain/ingest/scan` | `ingest_scan` | Ingest scan result |
| 20 | POST | `/api/v1/brain/ingest/asset` | `ingest_asset` | Ingest asset |
| 21 | POST | `/api/v1/brain/ingest/remediation` | `ingest_remediation` | Ingest remediation task |
| 22 | GET | `/api/v1/brain/health` | `brain_health` | Knowledge Brain health check |

**Subtotal: 22 endpoints**

### 3.5 pipeline_router.py — Brain Pipeline
**Router prefix**: `/api/v1/brain` (shared with brain_router) | **Tags**: `pipeline`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/brain/pipeline/run` | `run_pipeline` | Execute full 12-step Brain Pipeline |
| 2 | GET | `/api/v1/brain/pipeline/runs` | `list_pipeline_runs` | List past pipeline runs |
| 3 | GET | `/api/v1/brain/pipeline/runs/{run_id}` | `get_pipeline_run` | Get specific pipeline run |
| 4 | POST | `/api/v1/brain/evidence/generate` | `generate_evidence_pack` | Generate SOC2 Type II evidence |
| 5 | GET | `/api/v1/brain/evidence/packs` | `list_evidence_packs` | List evidence packs |
| 6 | GET | `/api/v1/brain/evidence/packs/{pack_id}` | `get_evidence_pack` | Get specific evidence pack |

**Subtotal: 6 endpoints**

### 3.6 autofix_router.py — AutoFix Engine
**Router prefix**: `/api/v1/autofix` | **Tags**: `autofix`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/autofix/generate` | `generate_fix` | Generate AI-powered fix suggestion |
| 2 | POST | `/api/v1/autofix/generate/bulk` | `generate_bulk_fixes` | Generate fixes for batch |
| 3 | POST | `/api/v1/autofix/apply` | `apply_fix` | Apply fix and create PR |
| 4 | POST | `/api/v1/autofix/validate` | `validate_fix` | Re-validate fix suggestion |
| 5 | POST | `/api/v1/autofix/rollback` | `rollback_fix` | Rollback applied fix |
| 6 | GET | `/api/v1/autofix/fixes/{fix_id}` | `get_fix` | Get fix details |
| 7 | GET | `/api/v1/autofix/suggestions/{finding_id}` | `get_suggestions` | Get fix suggestions for finding |
| 8 | GET | `/api/v1/autofix/history` | `get_history` | AutoFix action history |
| 9 | GET | `/api/v1/autofix/stats` | `get_stats` | AutoFix engine statistics |
| 10 | GET | `/api/v1/autofix/health` | `health` | AutoFix health check |
| 11 | GET | `/api/v1/autofix/fix-types` | `list_fix_types` | Supported fix types |
| 12 | GET | `/api/v1/autofix/confidence-levels` | `confidence_levels` | Confidence level definitions |

**Subtotal: 12 endpoints**

### 3.7 fuzzy_identity_router.py — Fuzzy Identity Resolution
**Router prefix**: `/api/v1/identity` | **Tags**: `identity`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/identity/canonical` | `register_canonical` | Register canonical identity |
| 2 | POST | `/api/v1/identity/alias` | `add_alias` | Add identity alias |
| 3 | POST | `/api/v1/identity/resolve` | `resolve_name` | Resolve fuzzy name |
| 4 | POST | `/api/v1/identity/resolve/batch` | `resolve_batch` | Batch resolve names |
| 5 | GET | `/api/v1/identity/similar` | `find_similar` | Find similar identities |
| 6 | GET | `/api/v1/identity/canonical` | `list_canonical` | List canonical identities |
| 7 | GET | `/api/v1/identity/stats` | `get_stats` | Identity resolution stats |

**Subtotal: 7 endpoints**

### 3.8 exposure_case_router.py — Exposure Cases
**Router prefix**: `/api/v1/cases` | **Tags**: `cases`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/cases/stats/summary` | `case_stats` | Aggregated case statistics |
| 2 | GET | `/api/v1/cases/{case_id}` | `get_case` | Get Exposure Case by ID |
| 3 | PATCH | `/api/v1/cases/{case_id}` | `update_case` | Update Exposure Case fields |
| 4 | POST | `/api/v1/cases/{case_id}/transition` | `transition_case` | Transition case lifecycle state |
| 5 | POST | `/api/v1/cases/{case_id}/clusters` | `add_clusters` | Add clusters to case |
| 6 | GET | `/api/v1/cases/{case_id}/transitions` | `get_valid_transitions` | Get valid state transitions |

**Subtotal: 6 endpoints**

### 3.9 llm_router.py — LLM Configuration
**Router prefix**: `/api/v1/llm` | **Tags**: `llm`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/llm/status` | `get_llm_status` | LLM provider status |
| 2 | POST | `/api/v1/llm/test` | `test_llm_provider` | Test LLM provider |
| 3 | GET | `/api/v1/llm/settings` | `get_llm_settings` | Get LLM settings |
| 4 | PATCH | `/api/v1/llm/settings` | `update_llm_settings` | Update LLM settings |
| 5 | GET | `/api/v1/llm/providers` | `list_providers` | List LLM providers |
| 6 | GET | `/api/v1/llm/health` | `llm_health` | LLM health check |

**Subtotal: 6 endpoints**

### 3.10 llm_monitor_router.py — LLM Security Monitor
**Router prefix**: `/api/v1/llm-monitor` | **Tags**: `llm-monitor`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/llm-monitor/analyze` | `analyze_llm` | Analyze LLM traffic for security threats |
| 2 | POST | `/api/v1/llm-monitor/scan/prompt` | `scan_prompt` | Scan prompt for jailbreak/injection |
| 3 | GET | `/api/v1/llm-monitor/patterns` | `list_patterns` | List detection patterns |
| 4 | GET | `/api/v1/llm-monitor/status` | `llm_monitor_status` | Monitor status |

**Subtotal: 4 endpoints**

### 3.11 mindsdb_router.py — ML/MindsDB
**Router prefix**: `/api/v1/ml` | **Tags**: `ml`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/ml/status` | `get_ml_status` | ML model status and statistics |
| 2 | GET | `/api/v1/ml/models` | `get_ml_models` | List ML models |
| 3 | POST | `/api/v1/ml/train` | `train_all_models` | Train all ML models |
| 4 | POST | `/api/v1/ml/models/{model_id}/train` | `train_single_model` | Train single model |
| 5 | POST | `/api/v1/ml/predict/anomaly` | `predict_anomaly` | Detect anomalous request |
| 6 | POST | `/api/v1/ml/predict/threat` | `predict_threat` | Assess threat level |
| 7 | GET | `/api/v1/ml/predict/response-time` | `predict_response_time` | Predict response time |
| 8 | GET | `/api/v1/ml/stats` | `get_stats_alias` | Stats alias |
| 9 | GET | `/api/v1/ml/analytics/stats` | `get_traffic_stats` | API traffic statistics |
| 10 | GET | `/api/v1/ml/analytics/health` | `get_api_health` | Per-endpoint API health |
| 11 | GET | `/api/v1/ml/analytics/anomalies` | `get_recent_anomalies` | Recent anomalous requests |
| 12 | GET | `/api/v1/ml/analytics/threats` | `get_threat_indicators` | Threat indicators |
| 13 | POST | `/api/v1/ml/analytics/threats/{indicator_id}/acknowledge` | `acknowledge_threat` | Acknowledge threat |
| 14 | POST | `/api/v1/ml/flush` | `flush_traffic` | Flush pending traffic records |

**Subtotal: 14 endpoints**

### 3.12 copilot_router.py — AI Copilot Chat
**Router prefix**: `/api/v1/copilot` | **Tags**: `copilot`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/copilot/sessions` | `create_session` | Create chat session |
| 2 | GET | `/api/v1/copilot/sessions` | `list_sessions` | List chat sessions |
| 3 | GET | `/api/v1/copilot/sessions/{session_id}` | `get_session` | Get specific session |
| 4 | DELETE | `/api/v1/copilot/sessions/{session_id}` | `delete_session` | Delete session |
| 5 | POST | `/api/v1/copilot/sessions/{session_id}/messages` | `send_message` | Send message in session |
| 6 | GET | `/api/v1/copilot/sessions/{session_id}/messages` | `get_messages` | Get session messages |
| 7 | POST | `/api/v1/copilot/sessions/{session_id}/actions` | `execute_action` | Execute agent action |
| 8 | GET | `/api/v1/copilot/actions/{action_id}` | `get_action_status` | Get action status |
| 9 | POST | `/api/v1/copilot/sessions/{session_id}/context` | `add_context` | Add context to session |
| 10 | GET | `/api/v1/copilot/suggestions` | `get_suggestions` | Get AI suggestions |
| 11 | POST | `/api/v1/copilot/quick/analyze` | `quick_analyze` | Quick analysis |
| 12 | POST | `/api/v1/copilot/quick/pentest` | `quick_pentest` | Quick pentest |
| 13 | POST | `/api/v1/copilot/quick/report` | `quick_report` | Quick report generation |
| 14 | GET | `/api/v1/copilot/health` | `copilot_health` | Copilot health check |

**Subtotal: 14 endpoints**

### 3.13 agents_router.py — AI Agent Swarm
**Router prefix**: `/api/v1/copilot/agents` | **Tags**: `copilot-agents`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/copilot/agents/analyst/analyze` | `analyze_vulnerability` | Security analyst: analyze vulnerability |
| 2 | POST | `/api/v1/copilot/agents/analyst/threat-intel` | `get_threat_intel` | Analyst: gather threat intelligence |
| 3 | POST | `/api/v1/copilot/agents/analyst/prioritize` | `prioritize_findings` | Analyst: prioritize findings |
| 4 | POST | `/api/v1/copilot/agents/analyst/attack-path` | `analyze_attack_path` | Analyst: analyze attack paths |
| 5 | GET | `/api/v1/copilot/agents/analyst/trending` | `get_trending_threats` | Analyst: trending threats |
| 6 | GET | `/api/v1/copilot/agents/analyst/risk-score/{asset_id}` | `get_risk_score` | Analyst: asset risk score |
| 7 | GET | `/api/v1/copilot/agents/analyst/cve/{cve_id}` | `get_cve_analysis` | Analyst: CVE deep analysis |
| 8 | POST | `/api/v1/copilot/agents/pentest/validate` | `validate_vulnerability` | Pentester: validate vulnerability |
| 9 | POST | `/api/v1/copilot/agents/pentest/generate-poc` | `generate_poc` | Pentester: generate proof of concept |
| 10 | POST | `/api/v1/copilot/agents/pentest/reachability` | `check_reachability` | Pentester: check reachability |
| 11 | POST | `/api/v1/copilot/agents/pentest/simulate` | `simulate_attack` | Pentester: simulate attack |
| 12 | GET | `/api/v1/copilot/agents/pentest/results/{task_id}` | `get_pentest_results` | Pentester: get results |
| 13 | GET | `/api/v1/copilot/agents/pentest/evidence/{evidence_id}` | `get_pentest_evidence` | Pentester: get evidence |
| 14 | POST | `/api/v1/copilot/agents/pentest/schedule` | `schedule_pentest` | Pentester: schedule test |
| 15 | POST | `/api/v1/copilot/agents/compliance/map-findings` | `map_findings_to_controls` | Compliance: map findings to controls |
| 16 | POST | `/api/v1/copilot/agents/compliance/gap-analysis` | `run_gap_analysis` | Compliance: gap analysis |
| 17 | POST | `/api/v1/copilot/agents/compliance/audit-evidence` | `generate_audit_evidence` | Compliance: generate audit evidence |
| 18 | POST | `/api/v1/copilot/agents/compliance/regulatory-alerts` | `check_regulatory_alerts` | Compliance: regulatory alerts |
| 19 | GET | `/api/v1/copilot/agents/compliance/controls/{framework}` | `get_framework_controls` | Compliance: get framework controls |
| 20 | GET | `/api/v1/copilot/agents/compliance/dashboard` | `get_compliance_dashboard` | Compliance: dashboard |
| 21 | POST | `/api/v1/copilot/agents/compliance/generate-report` | `generate_compliance_report` | Compliance: generate report |
| 22 | POST | `/api/v1/copilot/agents/remediation/generate-fix` | `generate_fix` | Remediation: generate fix |
| 23 | POST | `/api/v1/copilot/agents/remediation/create-pr` | `create_pr` | Remediation: create PR |
| 24 | POST | `/api/v1/copilot/agents/remediation/update-dependencies` | `update_deps` | Remediation: update dependencies |
| 25 | POST | `/api/v1/copilot/agents/remediation/playbook` | `generate_playbook` | Remediation: generate playbook |
| 26 | GET | `/api/v1/copilot/agents/remediation/recommendations/{finding_id}` | `get_recommendations` | Remediation: get recommendations |
| 27 | POST | `/api/v1/copilot/agents/remediation/verify` | `verify_remediation` | Remediation: verify fix |
| 28 | GET | `/api/v1/copilot/agents/remediation/queue` | `get_remediation_queue` | Remediation: queue |
| 29 | POST | `/api/v1/copilot/agents/orchestrate` | `orchestrate_agents` | Orchestrate multi-agent task |
| 30 | GET | `/api/v1/copilot/agents/status` | `get_agent_status` | Get all agent statuses |
| 31 | GET | `/api/v1/copilot/agents/tasks/{task_id}` | `get_task_status` | Get agent task status |
| 32 | GET | `/api/v1/copilot/agents/health` | `agents_health` | Agent swarm health check |

**Subtotal: 32 endpoints**

### 3.14 predictions_router.py — Predictive Analytics
**Router prefix**: `/api/v1/predictions` | **Tags**: `predictions`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/predictions/attack-chain` | `predict_attack_chain` | Predict attack chains |
| 2 | POST | `/api/v1/predictions/risk-trajectory` | `calculate_risk_trajectory` | Calculate risk trajectory |
| 3 | POST | `/api/v1/predictions/simulate-attack` | `simulate_attack_path` | Simulate attack path |
| 4 | GET | `/api/v1/predictions/markov/states` | `get_markov_states` | Markov chain states |
| 5 | GET | `/api/v1/predictions/markov/transitions` | `get_markov_transitions` | Markov transitions |
| 6 | POST | `/api/v1/predictions/bayesian/update` | `bayesian_update` | Bayesian probability update |
| 7 | POST | `/api/v1/predictions/bayesian/risk-assessment` | `bayesian_risk_assessment` | Bayesian risk assessment |
| 8 | POST | `/api/v1/predictions/combined-analysis` | `combined_risk_analysis` | Combined risk analysis |

**Subtotal: 8 endpoints**

### 3.15 algorithmic_router.py — Algorithmic Engines
**Router prefix**: `/api/v1/algorithms` | **Tags**: `algorithms`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/algorithms/monte-carlo/quantify` | `quantify_risk_monte_carlo` | Monte Carlo risk quantification |
| 2 | POST | `/api/v1/algorithms/monte-carlo/cve` | `quantify_cve_risk_endpoint` | CVE-specific Monte Carlo analysis |
| 3 | POST | `/api/v1/algorithms/monte-carlo/portfolio` | `quantify_portfolio_risk` | Portfolio risk quantification |
| 4 | POST | `/api/v1/algorithms/causal/analyze` | `analyze_vulnerability_root_cause` | Causal root cause analysis |
| 5 | POST | `/api/v1/algorithms/causal/counterfactual` | `analyze_counterfactual` | Counterfactual analysis |
| 6 | POST | `/api/v1/algorithms/causal/treatment-effect` | `estimate_treatment_effect` | Treatment effect estimation |
| 7 | POST | `/api/v1/algorithms/gnn/attack-surface` | `analyze_attack_surface_gnn` | GNN attack surface analysis |
| 8 | POST | `/api/v1/algorithms/gnn/critical-nodes` | `identify_critical_nodes` | GNN critical node identification |
| 9 | POST | `/api/v1/algorithms/gnn/risk-propagation` | `propagate_risk_through_graph` | GNN risk propagation |
| 10 | GET | `/api/v1/algorithms/status` | `get_algorithm_status` | Algorithm engine status |
| 11 | GET | `/api/v1/algorithms/capabilities` | `list_capabilities` | List algorithmic capabilities |

**Subtotal: 11 endpoints**

### 3.16 code_to_cloud_router.py — Code-to-Cloud Tracer
**Router prefix**: `/api/v1/code-to-cloud` | **Tags**: `code-to-cloud`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/code-to-cloud/trace` | `trace_vulnerability` | Trace vulnerability from code to cloud |
| 2 | GET | `/api/v1/code-to-cloud/status` | `tracer_status` | Tracer status |

**Subtotal: 2 endpoints**

### 3.17 streaming_router.py — SSE Streaming
**Router prefix**: `/api/v1/stream` | **Tags**: `streaming`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/stream/pipeline/{run_id}` | `stream_pipeline_progress` | Stream pipeline progress via SSE |
| 2 | GET | `/api/v1/stream/events` | `stream_events` | Stream EventBus events via SSE |

**Subtotal: 2 endpoints**

---

## 4. suite-attack/api/ — Router Files

### 4.1 mpte_router.py — MPTE (Micro Penetration Testing Engine)
**Router prefix**: `/api/v1/mpte` | **Tags**: `mpte`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/mpte/requests` | `list_requests` | List MPTE requests |
| 2 | POST | `/api/v1/mpte/requests` | `create_request` | Create MPTE request |
| 3 | GET | `/api/v1/mpte/requests/{request_id}` | `get_request` | Get MPTE request |
| 4 | PUT | `/api/v1/mpte/requests/{request_id}` | `update_request` | Update MPTE request |
| 5 | POST | `/api/v1/mpte/requests/{request_id}/start` | `start_request` | Start MPTE request |
| 6 | POST | `/api/v1/mpte/requests/{request_id}/cancel` | `cancel_request` | Cancel MPTE request |
| 7 | GET | `/api/v1/mpte/results` | `list_results` | List MPTE results |
| 8 | POST | `/api/v1/mpte/results` | `create_result` | Create MPTE result |
| 9 | GET | `/api/v1/mpte/results/by-request/{request_id}` | `get_results_by_request` | Get results by request |
| 10 | GET | `/api/v1/mpte/configs` | `list_configs` | List MPTE configs |
| 11 | POST | `/api/v1/mpte/configs` | `create_config` | Create MPTE config |
| 12 | GET | `/api/v1/mpte/configs/{config_id}` | `get_config` | Get MPTE config |
| 13 | PUT | `/api/v1/mpte/configs/{config_id}` | `update_config` | Update MPTE config |
| 14 | DELETE | `/api/v1/mpte/configs/{config_id}` | `delete_config` | Delete MPTE config |
| 15 | POST | `/api/v1/mpte/verify` | `verify_exploitability` | Verify CVE exploitability |
| 16 | POST | `/api/v1/mpte/monitoring` | `create_monitoring` | Create monitoring check |
| 17 | POST | `/api/v1/mpte/scan/comprehensive` | `run_comprehensive_scan` | Run comprehensive MPTE scan |
| 18 | GET | `/api/v1/mpte/findings/{finding_id}/exploitability` | `get_exploitability` | Get finding exploitability |
| 19 | GET | `/api/v1/mpte/stats` | `get_mpte_stats` | MPTE statistics |

**Subtotal: 19 endpoints**

### 4.2 micro_pentest_router.py — Micro Penetration Testing
**Router prefix**: `/api/v1/micro-pentest` | **Tags**: `micro-pentest`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/micro-pentest/health` | `health_check` | Health check |
| 2 | POST | `/api/v1/micro-pentest/run` | `run_pentest` | Run micro pentest for CVEs |
| 3 | GET | `/api/v1/micro-pentest/status/{flow_id}` | `get_pentest_status` | Get pentest status |
| 4 | POST | `/api/v1/micro-pentest/batch` | `run_batch_pentests` | Run batch micro pentests |
| 5 | POST | `/api/v1/micro-pentest/enterprise/scan` | `run_enterprise_scan` | Run enterprise scan |
| 6 | GET | `/api/v1/micro-pentest/enterprise/scan/{scan_id}` | `get_enterprise_scan` | Get enterprise scan status |
| 7 | GET | `/api/v1/micro-pentest/enterprise/scans` | `list_enterprise_scans` | List enterprise scans |
| 8 | POST | `/api/v1/micro-pentest/enterprise/scan/{scan_id}/cancel` | `cancel_enterprise_scan` | Cancel enterprise scan |
| 9 | GET | `/api/v1/micro-pentest/enterprise/audit-logs` | `get_enterprise_audit_logs` | Enterprise audit logs |
| 10 | GET | `/api/v1/micro-pentest/enterprise/health` | `enterprise_health` | Enterprise health check |
| 11 | GET | `/api/v1/micro-pentest/enterprise/attack-vectors` | `get_attack_vectors` | List attack vectors |
| 12 | GET | `/api/v1/micro-pentest/enterprise/threat-categories` | `get_threat_categories` | List threat categories |
| 13 | GET | `/api/v1/micro-pentest/enterprise/compliance-frameworks` | `get_compliance_frameworks` | List compliance frameworks |
| 14 | GET | `/api/v1/micro-pentest/enterprise/scan-modes` | `get_scan_modes` | List scan modes |
| 15 | POST | `/api/v1/micro-pentest/report/generate` | `generate_report` | Generate pentest report |
| 16 | GET | `/api/v1/micro-pentest/report/download` | `download_report` | Download report |
| 17 | GET | `/api/v1/micro-pentest/report/view` | `view_report` | View report |
| 18 | GET | `/api/v1/micro-pentest/report/data` | `get_report_data` | Get report data |

**Subtotal: 18 endpoints**

### 4.3 mpte_orchestrator_router.py — MPTE Orchestrator
**Router prefix**: `/api/v1/mpte-orchestrator` | **Tags**: `mpte-orchestrator`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/mpte-orchestrator/health` | `health_check` | Health check |
| 2 | GET | `/api/v1/mpte-orchestrator/capabilities` | `get_capabilities` | List orchestrator capabilities |
| 3 | POST | `/api/v1/mpte-orchestrator/threat-intel` | `run_threat_intel` | Run threat intelligence analysis |
| 4 | POST | `/api/v1/mpte-orchestrator/business-impact` | `run_business_impact` | Run business impact analysis |
| 5 | POST | `/api/v1/mpte-orchestrator/simulate` | `run_simulation` | Run attack simulation |
| 6 | POST | `/api/v1/mpte-orchestrator/remediation` | `run_remediation` | Run remediation analysis |
| 7 | POST | `/api/v1/mpte-orchestrator/run` | `run_full_orchestration` | Run full MPTE orchestration |
| 8 | GET | `/api/v1/mpte-orchestrator/status/{test_id}` | `get_test_status` | Get orchestration status |

**Subtotal: 8 endpoints**

### 4.4 vuln_discovery_router.py — Vulnerability Discovery
**Router prefix**: `/api/v1/vulns` | **Tags**: `vulnerability-discovery`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/vulns/discovered` | `list_discovered` | List discovered vulnerabilities |
| 2 | POST | `/api/v1/vulns/discovered` | `create_discovered` | Report discovered vulnerability |
| 3 | POST | `/api/v1/vulns/contribute` | `contribute_vuln` | Contribute vulnerability intelligence |
| 4 | GET | `/api/v1/vulns/internal` | `list_internal` | List internal vulnerabilities |
| 5 | GET | `/api/v1/vulns/internal/{vuln_id}` | `get_internal` | Get internal vulnerability |
| 6 | PATCH | `/api/v1/vulns/internal/{vuln_id}` | `update_internal` | Update internal vulnerability |
| 7 | POST | `/api/v1/vulns/train` | `trigger_retrain` | Trigger ML model retraining |
| 8 | GET | `/api/v1/vulns/train/{job_id}` | `get_train_status` | Get training job status |
| 9 | GET | `/api/v1/vulns/stats` | `get_vuln_stats` | Vulnerability statistics |
| 10 | GET | `/api/v1/vulns/contributions` | `list_contributions` | List contributions |
| 11 | GET | `/api/v1/vulns/health` | `vuln_health` | Health check |

**Subtotal: 11 endpoints**

### 4.5 secrets_router.py — Secrets Scanner
**Router prefix**: `/api/v1/secrets` | **Tags**: `secrets`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/secrets/status` | `get_secrets_status` | Secrets scanner status |
| 2 | GET | `/api/v1/secrets` | `list_secrets` | List secret findings (paginated) |
| 3 | POST | `/api/v1/secrets` | `create_secret_finding` | Create secret finding |
| 4 | GET | `/api/v1/secrets/{id}` | `get_secret` | Get secret finding |
| 5 | POST | `/api/v1/secrets/{id}/resolve` | `resolve_secret` | Resolve secret finding |
| 6 | GET | `/api/v1/secrets/scanners/status` | `get_scanner_status` | Get secrets detector status |
| 7 | POST | `/api/v1/secrets/scan/content` | `scan_content` | Scan content for secrets |

**Subtotal: 7 endpoints**

### 4.6 attack_sim_router.py — Attack Simulation (BAS)
**Router prefix**: `/api/v1/attack-sim` | **Tags**: `attack-simulation`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/attack-sim/scenarios` | `create_scenario` | Create attack scenario |
| 2 | POST | `/api/v1/attack-sim/scenarios/generate` | `generate_scenario` | AI-generate attack scenario |
| 3 | GET | `/api/v1/attack-sim/scenarios` | `list_scenarios` | List scenarios |
| 4 | GET | `/api/v1/attack-sim/scenarios/{scenario_id}` | `get_scenario` | Get scenario |
| 5 | POST | `/api/v1/attack-sim/campaigns/run` | `run_campaign` | Run attack campaign |
| 6 | GET | `/api/v1/attack-sim/campaigns` | `list_campaigns` | List campaigns |
| 7 | GET | `/api/v1/attack-sim/campaigns/{campaign_id}` | `get_campaign` | Get campaign |
| 8 | GET | `/api/v1/attack-sim/campaigns/{campaign_id}/attack-paths` | `get_attack_paths` | Get campaign attack paths |
| 9 | GET | `/api/v1/attack-sim/campaigns/{campaign_id}/breach-impact` | `get_breach_impact` | Get breach impact analysis |
| 10 | GET | `/api/v1/attack-sim/campaigns/{campaign_id}/recommendations` | `get_recommendations` | Get campaign recommendations |
| 11 | GET | `/api/v1/attack-sim/mitre/heatmap` | `get_mitre_heatmap` | MITRE ATT&CK heatmap |
| 12 | GET | `/api/v1/attack-sim/mitre/techniques` | `list_mitre_techniques` | List MITRE techniques |
| 13 | GET | `/api/v1/attack-sim/health` | `attack_sim_health` | Health check |

**Subtotal: 13 endpoints**

### 4.7 sast_router.py — SAST Scanner
**Router prefix**: `/api/v1/sast` | **Tags**: `SAST`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/sast/scan/code` | `scan_code` | Scan code for vulnerabilities |
| 2 | POST | `/api/v1/sast/scan/files` | `scan_files` | Scan files for vulnerabilities |
| 3 | GET | `/api/v1/sast/rules` | `list_rules` | List SAST rules |
| 4 | GET | `/api/v1/sast/status` | `get_sast_status` | SAST scanner status |

**Subtotal: 4 endpoints**

### 4.8 container_router.py — Container Scanner
**Router prefix**: `/api/v1/container` | **Tags**: `Container Scanner`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/container/scan/dockerfile` | `scan_dockerfile` | Scan Dockerfile |
| 2 | POST | `/api/v1/container/scan/image` | `scan_image` | Scan container image |
| 3 | GET | `/api/v1/container/status` | `get_container_status` | Scanner status |

**Subtotal: 3 endpoints**

### 4.9 dast_router.py — DAST Scanner
**Router prefix**: `/api/v1/dast` | **Tags**: `DAST`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/dast/scan` | `run_dast_scan` | Run DAST scan |
| 2 | GET | `/api/v1/dast/status` | `get_dast_status` | DAST scanner status |

**Subtotal: 2 endpoints**

### 4.10 cspm_router.py — CSPM Scanner
**Router prefix**: `/api/v1/cspm` | **Tags**: `CSPM`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/cspm/scan/terraform` | `scan_terraform` | Scan Terraform configs |
| 2 | POST | `/api/v1/cspm/scan/cloudformation` | `scan_cloudformation` | Scan CloudFormation templates |
| 3 | GET | `/api/v1/cspm/rules` | `list_cspm_rules` | List CSPM rules |
| 4 | GET | `/api/v1/cspm/status` | `get_cspm_status` | CSPM scanner status |

**Subtotal: 4 endpoints**

### 4.11 api_fuzzer_router.py — API Fuzzer
**Router prefix**: `/api/v1/api-fuzzer` | **Tags**: `API Fuzzer`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/api-fuzzer/discover` | `discover_apis` | Discover API endpoints |
| 2 | POST | `/api/v1/api-fuzzer/fuzz` | `fuzz_endpoint` | Fuzz an API endpoint |
| 3 | GET | `/api/v1/api-fuzzer/status` | `get_fuzzer_status` | Fuzzer status |

**Subtotal: 3 endpoints**

### 4.12 malware_router.py — Malware Detection
**Router prefix**: `/api/v1/malware` | **Tags**: `Malware Detection`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/malware/scan/content` | `scan_content` | Scan content for malware |
| 2 | POST | `/api/v1/malware/scan/files` | `scan_files` | Scan files for malware |
| 3 | GET | `/api/v1/malware/signatures` | `list_signatures` | List malware signatures |
| 4 | GET | `/api/v1/malware/status` | `get_malware_status` | Detector status |

**Subtotal: 4 endpoints**

---

## 5. suite-feeds/api/ — Router Files

### 5.1 feeds_router.py — Threat Intelligence Feeds
**Router prefix**: `/api/v1/feeds` | **Tags**: `feeds`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/feeds/epss` | `get_epss_scores` | Get EPSS scores |
| 2 | POST | `/api/v1/feeds/epss/refresh` | `refresh_epss_feed` | Refresh EPSS feed |
| 3 | GET | `/api/v1/feeds/kev` | `get_kev_entries` | Get CISA KEV entries |
| 4 | POST | `/api/v1/feeds/kev/refresh` | `refresh_kev_feed` | Refresh KEV feed |
| 5 | POST | `/api/v1/feeds/nvd/refresh` | `refresh_nvd_feed` | Refresh NVD feed |
| 6 | GET | `/api/v1/feeds/nvd/recent` | `get_recent_nvd_cves` | Get recent NVD CVEs |
| 7 | GET | `/api/v1/feeds/nvd/{cve_id}` | `get_nvd_cve` | Get NVD CVE by ID |
| 8 | POST | `/api/v1/feeds/exploitdb/refresh` | `refresh_exploitdb_feed` | Refresh ExploitDB feed |
| 9 | POST | `/api/v1/feeds/osv/refresh` | `refresh_osv_feed` | Refresh OSV feed |
| 10 | POST | `/api/v1/feeds/github/refresh` | `refresh_github_advisories_feed` | Refresh GitHub advisories |
| 11 | GET | `/api/v1/feeds/exploits` | `list_all_exploits` | List all exploit intelligence |
| 12 | GET | `/api/v1/feeds/exploits/{cve_id}` | `get_exploits_for_cve` | Get exploits for CVE |
| 13 | POST | `/api/v1/feeds/exploits` | `add_exploit_intelligence` | Add exploit intelligence |
| 14 | GET | `/api/v1/feeds/threat-actors` | `list_all_threat_actors` | List threat actors |
| 15 | GET | `/api/v1/feeds/threat-actors/{cve_id}` | `get_threat_actors_for_cve` | Get threat actors for CVE |
| 16 | GET | `/api/v1/feeds/threat-actors/by-actor/{actor}` | `get_cves_by_threat_actor` | Get CVEs by threat actor |
| 17 | POST | `/api/v1/feeds/threat-actors` | `add_threat_actor_mapping` | Add threat actor mapping |
| 18 | GET | `/api/v1/feeds/supply-chain` | `list_supply_chain_vulns` | List supply chain vulns |
| 19 | GET | `/api/v1/feeds/supply-chain/{package}` | `get_supply_chain_vulns` | Get supply chain vulns by package |
| 20 | POST | `/api/v1/feeds/supply-chain` | `add_supply_chain_vuln` | Add supply chain vuln |
| 21 | GET | `/api/v1/feeds/exploit-confidence/{cve_id}` | `get_exploit_confidence` | Get exploit confidence score |
| 22 | GET | `/api/v1/feeds/geo-risk/{cve_id}` | `get_geo_weighted_risk` | Get geo-weighted risk |
| 23 | POST | `/api/v1/feeds/enrich` | `enrich_findings` | Enrich findings with feed data |
| 24 | GET | `/api/v1/feeds/stats` | `get_feed_stats` | Feed statistics |
| 25 | GET | `/api/v1/feeds/categories` | `list_feed_categories` | List feed categories |
| 26 | GET | `/api/v1/feeds/sources` | `list_feed_sources` | List configured feed sources |
| 27 | GET | `/api/v1/feeds/health` | `get_feed_health` | Feed health and freshness |
| 28 | GET | `/api/v1/feeds/scheduler/status` | `get_scheduler_status` | Scheduler status |
| 29 | POST | `/api/v1/feeds/refresh` | `refresh_feeds_alias` | Refresh all feeds (alias) |
| 30 | POST | `/api/v1/feeds/refresh/all` | `refresh_all_feeds` | Refresh all feeds |

**Subtotal: 30 endpoints**

---

## 6. suite-evidence-risk/api/ — Router Files

### 6.1 evidence_router.py — Evidence Vault
**Router prefix**: `/api/v1/evidence` (prefix `/evidence` + mount prefix `/api/v1`) | **Tags**: `evidence`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/evidence/stats` | `evidence_stats` | Evidence vault statistics |
| 2 | GET | `/api/v1/evidence/` | `list_evidence` | List evidence records |
| 3 | GET | `/api/v1/evidence/{release}` | `evidence_manifest` | Get evidence manifest |
| 4 | GET | `/api/v1/evidence/bundles/{bundle_id}/download` | `download_evidence_bundle` | Download evidence bundle |
| 5 | POST | `/api/v1/evidence/verify` | `verify_evidence` | Verify evidence integrity |
| 6 | POST | `/api/v1/evidence/{bundle_id}/collect` | `collect_evidence` | Collect evidence |

**Subtotal: 6 endpoints**

### 6.2 provenance_router.py — Provenance Attestations
**Router prefix**: `/api/v1/provenance` (prefix `/provenance` + mount prefix `/api/v1`) | **Tags**: `provenance`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/provenance/` | `list_attestations` | List attestations |
| 2 | GET | `/api/v1/provenance/{artifact_name}` | `fetch_attestation` | Fetch attestation for artifact |

**Subtotal: 2 endpoints**

### 6.3 risk_router.py — Risk Scoring
**Router prefix**: `/api/v1/risk` (prefix `/risk` + mount prefix `/api/v1`) | **Tags**: `risk`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/risk/` | `risk_summary` | Risk summary |
| 2 | GET | `/api/v1/risk/component/{component_slug}` | `component_risk` | Component risk score |
| 3 | GET | `/api/v1/risk/cve/{cve_id}` | `cve_risk` | CVE risk score |

**Subtotal: 3 endpoints**

### 6.4 graph_router.py — Supply Chain Graph
**Router prefix**: `/api/v1/graph` (prefix `/graph` + mount prefix `/api/v1`) | **Tags**: `graph`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/graph/` | `graph_summary` | Graph summary |
| 2 | GET | `/api/v1/graph/lineage/{artifact_name}` | `artifact_lineage` | Artifact lineage |
| 3 | GET | `/api/v1/graph/kev-components` | `kev_components` | KEV-affected components |
| 4 | GET | `/api/v1/graph/anomalies` | `version_anomalies` | Version anomalies |

**Subtotal: 4 endpoints**

### 6.5 business_context.py — Business Context
**Router prefix**: `/api/v1/business-context` (prefix `/business-context` + mount prefix `/api/v1`) | **Tags**: `business-context`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/business-context/jira-context/{ticket_id}` | `get_jira_context` | Get Jira business context |
| 2 | GET | `/api/v1/business-context/confluence-context/{page_id}` | `get_confluence_context` | Get Confluence threat model |
| 3 | POST | `/api/v1/business-context/enrich-context` | `enrich_business_context` | Enrich findings with business context |

**Subtotal: 3 endpoints**

### 6.6 business_context_enhanced.py — Business Context (Enhanced)
**Router prefix**: `/api/v1/business-context` (prefix `/business-context` + mount prefix `/api/v1`) | **Tags**: `business-context-enhanced`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/business-context/upload` | `upload_business_context` | Upload business context |
| 2 | GET | `/api/v1/business-context/stored/{service_name}` | `get_stored_context` | Get stored context |
| 3 | GET | `/api/v1/business-context/stored` | `list_stored_contexts` | List stored contexts |
| 4 | GET | `/api/v1/business-context/sample/{format_type}` | `get_sample_context` | Get sample context |
| 5 | GET | `/api/v1/business-context/formats` | `get_supported_formats` | Get supported formats |
| 6 | POST | `/api/v1/business-context/validate` | `validate_business_context` | Validate business context |

**Subtotal: 6 endpoints**

### 6.7 risk/reachability/api.py — Reachability Analysis
**Router prefix**: `/api/v1/reachability` | **Tags**: `reachability`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/reachability/analyze` | `analyze_reachability` | Analyze reachability |
| 2 | POST | `/api/v1/reachability/analyze/bulk` | `analyze_bulk` | Bulk reachability analysis |
| 3 | GET | `/api/v1/reachability/job/{job_id}` | `get_job_status` | Get analysis job status |
| 4 | GET | `/api/v1/reachability/results/{cve_id}` | `get_result` | Get cached result |
| 5 | DELETE | `/api/v1/reachability/results/{cve_id}` | `delete_result` | Delete cached result |
| 6 | GET | `/api/v1/reachability/health` | `health_check` | Health check |
| 7 | GET | `/api/v1/reachability/metrics` | `get_metrics` | Analysis metrics |

**Subtotal: 7 endpoints**

---

## 7. suite-integrations/api/ — Router Files

### 7.1 integrations_router.py — External Integrations
**Router prefix**: `/api/v1/integrations` | **Tags**: `integrations`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/integrations/{id}` | `get_integration` | Get integration details |
| 2 | PUT | `/api/v1/integrations/{id}` | `update_integration` | Update integration |
| 3 | DELETE | `/api/v1/integrations/{id}` | `delete_integration` | Delete integration |
| 4 | POST | `/api/v1/integrations/{id}/test` | `test_integration` | Test integration connection |
| 5 | GET | `/api/v1/integrations/{id}/sync-status` | `get_sync_status` | Get sync status |
| 6 | POST | `/api/v1/integrations/{id}/sync` | `trigger_sync` | Trigger sync |

**Subtotal: 6 endpoints**

### 7.2 webhooks_router.py — Webhooks (Management)
**Router prefix**: `/api/v1/webhooks` | **Tags**: `webhooks`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/webhooks/mappings` | `create_integration_mapping` | Create integration mapping |
| 2 | GET | `/api/v1/webhooks/mappings` | `list_integration_mappings` | List integration mappings |
| 3 | GET | `/api/v1/webhooks/mappings/{mapping_id}` | `get_integration_mapping` | Get integration mapping |
| 4 | PUT | `/api/v1/webhooks/mappings/{mapping_id}/sync` | `sync_mapping_status` | Sync mapping status & detect drift |
| 5 | GET | `/api/v1/webhooks/drift` | `list_drift_events` | List drift events |
| 6 | PUT | `/api/v1/webhooks/drift/{drift_id}/resolve` | `resolve_drift` | Resolve drift event |
| 7 | GET | `/api/v1/webhooks/events` | `list_webhook_events` | List webhook events |
| 8 | POST | `/api/v1/webhooks/outbox` | `queue_outbound_sync` | Queue outbound sync |
| 9 | GET | `/api/v1/webhooks/outbox` | `list_outbox_items` | List outbox items |
| 10 | GET | `/api/v1/webhooks/outbox/pending` | `get_pending_outbox_items` | Get pending outbox items |
| 11 | PUT | `/api/v1/webhooks/outbox/{outbox_id}/process` | `process_outbox_item` | Process outbox item |
| 12 | DELETE | `/api/v1/webhooks/outbox/{outbox_id}` | `cancel_outbox_item` | Cancel outbox item |
| 13 | POST | `/api/v1/webhooks/outbox/{outbox_id}/retry` | `retry_outbox_item` | Retry failed outbox item |
| 14 | GET | `/api/v1/webhooks/outbox/stats` | `get_outbox_stats` | Outbox statistics |
| 15 | POST | `/api/v1/webhooks/outbox/{outbox_id}/execute` | `execute_outbox_item` | Execute outbox item |
| 16 | POST | `/api/v1/webhooks/outbox/process-pending` | `process_pending_outbox_items` | Process all pending items |
| 17 | POST | `/api/v1/webhooks/alm/work-items` | `create_alm_work_item` | Create ALM work item |
| 18 | PUT | `/api/v1/webhooks/alm/work-items/{mapping_id}` | `update_alm_work_item` | Update ALM work item |
| 19 | GET | `/api/v1/webhooks/alm/work-items` | `list_alm_work_items` | List ALM work items |

**Subtotal: 19 endpoints**

### 7.3 webhooks_router.py — Webhook Receivers (No Auth)
**Router prefix**: `/api/v1/webhooks` | **Tags**: `webhooks-receivers`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | POST | `/api/v1/webhooks/jira` | `receive_jira_webhook` | Receive Jira webhook (signature verified) |
| 2 | POST | `/api/v1/webhooks/servicenow` | `receive_servicenow_webhook` | Receive ServiceNow webhook |
| 3 | POST | `/api/v1/webhooks/gitlab` | `receive_gitlab_webhook` | Receive GitLab webhook |
| 4 | POST | `/api/v1/webhooks/azure-devops` | `receive_azure_devops_webhook` | Receive Azure DevOps webhook |

**Subtotal: 4 endpoints**

### 7.4 iac_router.py — IaC Scanning
**Router prefix**: `/api/v1/iac` | **Tags**: `iac`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/iac/{id}` | `get_iac_finding` | Get IaC finding |
| 2 | POST | `/api/v1/iac/{id}/resolve` | `resolve_iac_finding` | Resolve IaC finding |
| 3 | POST | `/api/v1/iac/{id}/remediate` | `remediate_iac_finding` | Remediate IaC finding |
| 4 | GET | `/api/v1/iac/scanners/status` | `get_scanner_status` | IaC scanner status |
| 5 | POST | `/api/v1/iac/scan/content` | `scan_iac_content` | Scan IaC content |

**Subtotal: 5 endpoints**

### 7.5 ide_router.py — IDE Plugin API
**Router prefix**: `/api/v1/ide` | **Tags**: `ide`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/ide/status` | `get_ide_status` | IDE service status |
| 2 | GET | `/api/v1/ide/config` | `get_ide_config` | IDE extension configuration |
| 3 | POST | `/api/v1/ide/analyze` | `analyze_code` | Real-time code analysis |
| 4 | GET | `/api/v1/ide/suggestions` | `get_suggestions` | Context-aware suggestions |
| 5 | POST | `/api/v1/ide/sarif` | `export_sarif` | Export SARIF for CI/CD |

**Subtotal: 5 endpoints**

### 7.6 mcp_router.py — MCP Gateway
**Router prefix**: `/api/v1/mcp` | **Tags**: `mcp`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/mcp/status` | `get_mcp_status` | MCP server status |
| 2 | GET | `/api/v1/mcp/clients` | `list_mcp_clients` | List MCP clients |
| 3 | GET | `/api/v1/mcp/tools` | `list_mcp_tools` | List MCP tools |
| 4 | GET | `/api/v1/mcp/resources` | `list_mcp_resources` | List MCP resources |
| 5 | GET | `/api/v1/mcp/prompts` | `list_mcp_prompts` | List MCP prompts |
| 6 | GET | `/api/v1/mcp/config` | `get_mcp_config` | MCP configuration |
| 7 | POST | `/api/v1/mcp/configure` | `configure_mcp_server` | Configure MCP server |
| 8 | POST | `/api/v1/mcp/clients/{client_id}/disconnect` | `disconnect_client` | Disconnect client |
| 9 | DELETE | `/api/v1/mcp/clients/{client_id}` | `remove_client` | Remove client |
| 10 | GET | `/api/v1/mcp/manifest` | `get_mcp_manifest` | Get MCP manifest |

**Subtotal: 10 endpoints**

### 7.7 oss_tools.py — OSS Security Tools
**Router prefix**: `/api/v1/oss` (prefix `/oss` + mount prefix `/api/v1`) | **Tags**: `oss`

| # | Method | Full Path | Function | Description |
|---|--------|-----------|----------|-------------|
| 1 | GET | `/api/v1/oss/status` | `get_oss_status` | OSS tools status |
| 2 | POST | `/api/v1/oss/scan/comprehensive` | `run_comprehensive_scan` | Comprehensive multi-tool scan |
| 3 | POST | `/api/v1/oss/scan/trivy` | `run_trivy_scan` | Trivy vulnerability scan |
| 4 | POST | `/api/v1/oss/scan/grype` | `run_grype_scan` | Grype vulnerability scan |
| 5 | POST | `/api/v1/oss/verify/sigstore` | `verify_sigstore_signature` | Sigstore signature verification |
| 6 | POST | `/api/v1/oss/policy/evaluate` | `evaluate_policy` | OPA policy evaluation |
| 7 | GET | `/api/v1/oss/policies` | `list_policies` | List OPA policies |
| 8 | GET | `/api/v1/oss/tools` | `list_supported_tools` | List supported OSS tools |

**Subtotal: 8 endpoints**

---

## 8. Summary Statistics

| Suite | Router Files | Endpoints |
|-------|-------------|-----------|
| **suite-api (app.py inline)** | 1 | 20 |
| **suite-api (router files)** | 18 | 194 |
| **suite-core** | 17 | 178 |
| **suite-attack** | 12 | 96 |
| **suite-feeds** | 1 | 30 |
| **suite-evidence-risk** | 7 | 31 |
| **suite-integrations** | 7 | 57 |
| **TOTAL** | **63** | **606** |

### Endpoints by HTTP Method

| Method | Count |
|--------|-------|
| GET | 304 |
| POST | 244 |
| PUT | 33 |
| DELETE | 17 |
| PATCH | 4 |
| **TOTAL** | **602** |

### Health Check Endpoints (for monitoring)

| Path | Source |
|------|--------|
| `/health` | app.py inline (legacy) |
| `/api/v1/health` | health.py |
| `/api/v1/ready` | health.py |
| `/api/v1/fail/health` | fail_router.py |
| `/api/v1/autofix/health` | autofix_router.py |
| `/api/v1/brain/health` | brain_router.py |
| `/api/v1/copilot/health` | copilot_router.py |
| `/api/v1/copilot/agents/health` | agents_router.py |
| `/api/v1/llm/health` | llm_router.py |
| `/api/v1/reachability/health` | reachability api.py |
| `/api/v1/feeds/health` | feeds_router.py |
| `/api/v1/vulns/health` | vuln_discovery_router.py |
| `/api/v1/micro-pentest/health` | micro_pentest_router.py |
| `/api/v1/micro-pentest/enterprise/health` | micro_pentest_router.py |
| `/api/v1/mpte-orchestrator/health` | mpte_orchestrator_router.py |
| `/api/v1/attack-sim/health` | attack_sim_router.py |

### Top 10 Largest Routers (by endpoint count)

| # | Router | Endpoints |
|---|--------|-----------|
| 1 | agents_router.py (suite-core) | 32 |
| 2 | feeds_router.py (suite-feeds) | 30 |
| 3 | analytics_router.py (suite-api) | 22 |
| 4 | brain_router.py (suite-core) | 22 |
| 5 | collaboration_router.py (suite-api) | 21 |
| 6 | app.py inline (suite-api) | 20 |
| 7 | webhooks_router.py (suite-integrations) | 19 |
| 8 | mpte_router.py (suite-attack) | 19 |
| 9 | inventory_router.py (suite-api) | 19 |
| 10 | deduplication_router.py (suite-core) | 18 |
