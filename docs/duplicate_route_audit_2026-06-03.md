# Duplicate Route Audit — 2026-06-03

**Severity: HIGH (architecture).** `create_app()` registers **740 duplicate `(method, path)`
route pairs** out of ~8340 routes. Generalised from the tick-19 `/api/v1/bulk/export` shadow.

## Breakdown
- **609 same-handler duplicates** — the *same* router/endpoint function registered ≥2× (routers
  included in BOTH the main app AND a sub-app, e.g. aspm_app/grc_app, that merge into create_app).
  Harmless at runtime (identical handler) but inflates the route count and is dead weight.
- **131 DIFFERENT-handler shadow collisions** — two *different* handlers at the same path; whichever
  registers first wins, the other is DEAD CODE (mount-order-dependent landmine). Real bugs. These are
  duplicate FEATURE implementations (two routers for one feature), e.g.:
  - POST /api/v1/orgs : org_hierarchy_router.create_org | org_router.create_org
  - POST /api/v1/mdm/devices : mdm_router | mobile_device_management_router
  - POST /api/v1/nac/policies : nac_router | network_access_control_router
  - POST /api/v1/policies : policies_router | policy_router
  - POST /api/v1/playbooks : playbook_router | playbook_routes
  - POST /api/v1/workflows : workflow_engine_router | workflow_router | workflows_router (×3!)
  - POST /api/v1/vendors : vendor_risk_router | vendor_scorecard_router
  - POST /api/v1/sql/execute : security_query_language_router | security_query_router
  - POST /api/v1/bulk/export : bulk_operations_router | bulk_router (tick-19)
  - …full list below.
- **26 import-path duplicates** — same router FILE imported via two module paths (`api.X` AND
  `apps.api.X`). ROOT CAUSE: sitecustomize.py puts both `suite-api` and `suite-api/apps` on
  sys.path, so `api.dast_router` and `apps.api.dast_router` are distinct module objects → two
  router instances. Sub-apps (aspm_app.py, grc_app.py) use `from api.X import router`; the main app
  uses `from apps.api.X import router`.

## Root causes
1. **Duplicate feature routers** (131) — two+ router modules implementing the same endpoints
   (mdm vs mobile_device_management, policy vs policies, workflow vs workflows vs workflow_engine,
   vendor_risk vs vendor_scorecard, …). ARCHITECTURE DECISION per pair: pick the canonical router,
   remove/repurpose the other. Cannot be auto-resolved (semantics differ — see tick-19 bulk/export:
   async-job vs sync-file).
2. **Main-app + sub-app router overlap** (609) — routers `include_router`'d in both create_app and a
   sub-app that merges in. Fix: each router included exactly once (decide main-app vs sub-app home).
3. **Dual import paths** (26) — normalise sub-app imports `from api.X` → `from apps.api.X` AND remove
   the double-include (normalising imports alone just converts these to same-handler dups).

## Recommendation (founder/architecture)
Treat as a dedicated consolidation epic. Priority order: (a) the 131 different-handler shadows
(dead code + API ambiguity + mount-order fragility — pick canonical per pair), (b) the 26 dual-import
dups (mechanical once #2 is decided), (c) the 609 same-handler redundant includes (route-count hygiene).
NOT fixable incrementally without per-pair canonical decisions. Full machine-readable list:

```
2026-06-03 04:01:43 [info     ] TrustGraph EventBus initialized batch_size=50 enabled=True queue_db=./.aldeci/event_bus_queue.db
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=finding.created handler=_handle_finding_created
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=finding.updated handler=_handle_finding_created
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=asset.discovered handler=_handle_asset_discovered
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=incident.created handler=_handle_incident_created
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=control.assessed handler=_handle_control_assessed
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=vendor.updated handler=_handle_vendor_updated
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=actor.identified handler=_handle_actor_identified
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=cve.discovered handler=_handle_cve_discovered
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=risk.assessed handler=_handle_risk_assessed
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=scan.completed handler=_handle_scan_completed
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=session.created handler=_handle_session_created
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=competitive.capability_required handler=_noop_legacy_handler
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=competitive.gap_identified handler=_noop_legacy_handler
2026-06-03 04:01:43 [debug    ] EventBus.on: registered handler event_type=competitive.engine_new_proposed handler=_noop_legacy_handler
2026-06-03 04:01:43 [info     ] TrustGraph event bus: default handlers registered
2026-06-03 04:01:53 [info     ] TrustGraph EventBus: ResponseInterceptorMiddleware wired
2026-06-03 04:01:53 [info     ] TrustGraph event bus: default handlers registered
2026-06-03 04:01:58 [info     ] TrustGraph EventBus: ResponseInterceptorMiddleware wired
2026-06-03 04:01:58 [info     ] TrustGraph event bus: default handlers registered
### 131 DIFFERENT-handler shadow collisions (one handler dead per pair):
DELETE /api/v1/sql/queries/{query_id}  ::  apps.api.security_query_language_router.delete_query | apps.api.security_query_router.delete_query
DELETE /api/v1/workflows/{workflow_id}  ::  apps.api.workflow_engine_router.delete_workflow | apps.api.workflow_router.delete_workflow
GET /api/v1/analytics/  ::  apps.api.analytics_dashboard_router.analytics_index | apps.api.analytics_router.analytics_root_index
GET /api/v1/analytics/mttr  ::  apps.api.analytics_dashboard_router.get_mttr | apps.api.analytics_router.get_mttr
GET /api/v1/api-security-engine/abuse-events  ::  apps.api.api_security_engine_router.list_abuse_events | apps.api.api_security_mgmt_router.list_abuse_events
GET /api/v1/api-security-engine/keys  ::  apps.api.api_security_engine_router.list_api_keys | apps.api.api_security_mgmt_router.list_api_keys
GET /api/v1/api-security-engine/stats  ::  apps.api.api_security_engine_router.get_api_stats | apps.api.api_security_mgmt_router.get_security_stats
GET /api/v1/attack-paths/  ::  apps.api.attack_path_router.attack_paths_index | apps.api.gap_router.list_attack_paths
GET /api/v1/audit/  ::  apps.api.audit_router.audit_index | apps.api.gap_router.list_audit_logs
GET /api/v1/audit/trail  ::  apps.api.audit_router.get_audit_trail | apps.api.gap_router.get_audit_trail
GET /api/v1/auth/keys  ::  apps.api.apikey_router.list_keys | apps.api.auth_router.list_api_keys
GET /api/v1/auth/sso  ::  apps.api.auth_router.list_sso_configs | apps.api.sso_router.sso_status
GET /api/v1/certificates/  ::  apps.api.cert_router.list_certificates | apps.api.certificate_lifecycle_router.list_certificates
GET /api/v1/certificates/stats  ::  apps.api.cert_router.get_cert_stats | apps.api.certificate_lifecycle_router.get_certificate_stats
GET /api/v1/certificates/{cert_id}  ::  apps.api.cert_router.get_certificate | apps.api.certificate_lifecycle_router.get_certificate
GET /api/v1/compliance/evidence  ::  apps.api.compliance_automation_router.get_evidence | apps.api.compliance_router.get_evidence
GET /api/v1/compliance/gaps  ::  apps.api.compliance_automation_router.get_gaps | apps.api.compliance_router.get_gaps
GET /api/v1/compliance/poam  ::  apps.api.compliance_automation_router.get_poam | apps.api.compliance_router.get_poam_list
GET /api/v1/compliance/status  ::  apps.api.compliance_automation_router.get_overall_status | apps.api.compliance_router.get_overall_status | apps.api.gap_router.compliance_overall_status
GET /api/v1/connectors/{name}/health  ::  apps.api.connector_routes.get_connector_health | apps.api.connectors_router.connector_health
GET /api/v1/ctem/cycles  ::  apps.api.ctem_engine_router.list_cycles | apps.api.ctem_router.list_cycles
GET /api/v1/ctem/cycles/{cycle_id}  ::  apps.api.ctem_engine_router.get_cycle | apps.api.ctem_router.get_cycle
GET /api/v1/ctem/cycles/{cycle_id}/exposures  ::  apps.api.ctem_engine_router.get_cycle_exposures | apps.api.ctem_router.get_exposures
GET /api/v1/dast/  ::  api.dast_router.dast_root | apps.api.dast_router.dast_root
GET /api/v1/dast/findings  ::  api.dast_router.get_findings | apps.api.dast_router.get_findings
GET /api/v1/dast/headers/{url:path}  ::  api.dast_router.check_security_headers | apps.api.dast_router.check_security_headers
GET /api/v1/dast/health  ::  api.dast_router.dast_health | apps.api.dast_router.dast_health
GET /api/v1/dast/profiles  ::  api.dast_router.list_scan_profiles | apps.api.dast_router.list_scan_profiles
GET /api/v1/dast/scans/{scan_id}  ::  api.dast_router.get_scan_status | apps.api.dast_router.get_scan_status
GET /api/v1/dast/stats  ::  api.dast_router.get_dast_stats | apps.api.dast_router.get_dast_stats
GET /api/v1/dast/status  ::  api.dast_router.dast_status | apps.api.dast_router.dast_status
GET /api/v1/fail/history  ::  apps.api.fail_router.get_fail_history | apps.api.gap_router.get_fail_history
GET /api/v1/fail/readiness  ::  apps.api.fail_router.get_readiness_score | apps.api.gap_router.get_fail_readiness
GET /api/v1/feeds  ::  api.feeds_router_sf.list_feeds | apps.api.feed_manager_router.list_feeds
GET /api/v1/feeds/health  ::  api.feeds_router_sf.get_feed_health | apps.api.feed_manager_router.feed_manager_health | apps.api.feed_manager_router.get_all_health
GET /api/v1/feeds/stats  ::  api.feeds_router_sf.get_feed_stats | apps.api.feed_manager_router.get_feed_stats
GET /api/v1/feeds/status  ::  api.feeds_router_sf.feeds_status | apps.api.feed_manager_router.feed_manager_status
GET /api/v1/findings  ::  apps.api.findings_routes.list_findings | apps.api.findings_wave_b_router.list_findings | apps.api.gap_router.list_all_findings
GET /api/v1/fips/readiness  ::  apps.api.fips_compliance_router.fips_readiness_score | apps.api.fips_router.fips_readiness_score
GET /api/v1/fips/stats  ::  apps.api.fips_compliance_router.get_stats | apps.api.fips_router.stats
GET /api/v1/fips/status  ::  apps.api.fips_compliance_router.get_fips_status | apps.api.fips_router.get_fips_status
GET /api/v1/graph/  ::  api.graph_router.graph_summary | apps.api.gap_router.graph_index
GET /api/v1/graph/attack-paths  ::  apps.api.gap_router.get_attack_paths | apps.api.trustgraph_integration_router.get_attack_paths
GET /api/v1/graph/impact/{entity_id}  ::  apps.api.trustgraph_backbone_router.get_impact | apps.api.trustgraph_integration_router.get_impact_analysis
GET /api/v1/graph/stats  ::  api.graph_router.graph_stats | apps.api.trustgraph_backbone_router.get_stats
GET /api/v1/graphrag/health  ::  apps.api.graph_rag_router.health | apps.api.graphrag_router.health
GET /api/v1/ide/status  ::  api.ide_router.get_ide_status | apps.api.ide_backend_router.status
GET /api/v1/integrations  ::  api.integrations_router.list_integrations | apps.api.gap_router.list_integrations_gap | apps.api.integration_health_router.list_integrations
GET /api/v1/integrations/  ::  apps.api.gap_router.list_integrations_gap | apps.api.integration_hub_router.list_integrations
GET /api/v1/integrations/marketplace  ::  api.integrations_router.list_marketplace_integrations | apps.api.gap_router.list_marketplace_integrations
GET /api/v1/logs/stats  ::  apps.api.detailed_logging.get_log_stats | apps.api.gap_router.logs_stats
GET /api/v1/mcp/stats  ::  apps.api.mcp_router.mcp_stats | apps.api.mcp_routes.get_mcp_stats
GET /api/v1/mcp/tools  ::  apps.api.mcp_router.list_mcp_tools | apps.api.mcp_routes.list_mcp_tools
GET /api/v1/mdm/devices  ::  apps.api.mdm_router.list_devices | apps.api.mobile_device_management_router.list_devices
GET /api/v1/mdm/devices/{device_id}  ::  apps.api.mdm_router.get_device | apps.api.mobile_device_management_router.get_device
GET /api/v1/nac/policies  ::  apps.api.nac_router.list_policies | apps.api.network_access_control_router.list_nac_policies
GET /api/v1/nac/stats  ::  apps.api.nac_router.get_nac_stats | apps.api.network_access_control_router.get_nac_stats
GET /api/v1/notifications/  ::  apps.api.gap_router.list_notifications | apps.api.notification_router.get_notification_root_summary
GET /api/v1/notifications/preferences  ::  apps.api.gap_router.get_notification_preferences | apps.api.notification_router.get_preferences
GET /api/v1/phishing/campaigns  ::  apps.api.phishing_router.list_campaigns | apps.api.phishing_simulation_router.list_campaigns
GET /api/v1/phishing/campaigns/{campaign_id}  ::  apps.api.phishing_router.get_campaign_results | apps.api.phishing_simulation_router.get_campaign
GET /api/v1/phishing/stats  ::  apps.api.phishing_router.get_stats | apps.api.phishing_simulation_router.get_org_stats
GET /api/v1/phishing/templates  ::  apps.api.phishing_router.list_templates | apps.api.phishing_simulation_router.list_templates
GET /api/v1/pipeline/health  ::  api.pipeline_router.pipeline_health | apps.api.pipeline_routes.get_pipeline_health
GET /api/v1/playbooks  ::  apps.api.gap_router.list_playbooks | apps.api.playbook_router.list_playbooks | apps.api.playbook_routes.list_playbooks
GET /api/v1/playbooks/executions  ::  apps.api.ir_playbook_runner_router.list_executions | apps.api.playbook_router.list_executions
GET /api/v1/playbooks/{playbook_id}  ::  apps.api.playbook_router.get_playbook | apps.api.playbook_routes.get_playbook
GET /api/v1/policies  ::  apps.api.policies_router.list_policies | apps.api.policy_router.list_policies
GET /api/v1/reports/templates  ::  apps.api.gap_router.list_report_templates | apps.api.reports_router.list_report_templates
GET /api/v1/risk/  ::  api.risk_router.risk_summary | apps.api.composite_risk_router.risk_index
GET /api/v1/rules/dsl  ::  apps.api.dynamic_rule_dsl_router.list_rules | apps.api.wave_c_router.list_dsl_rules
GET /api/v1/sbom/  ::  apps.api.gap_router.list_sbom_components | apps.api.sbom_router.sbom_overview
GET /api/v1/siem/events  ::  api.siem_router.recent_events | apps.api.siem_integration_router.list_events
GET /api/v1/siem/stats  ::  api.siem_router.siem_stats | apps.api.siem_integration_router.get_stats
GET /api/v1/sql/history  ::  apps.api.security_query_language_router.list_history | apps.api.security_query_router.list_history
GET /api/v1/sql/queries  ::  apps.api.security_query_language_router.list_queries | apps.api.security_query_router.list_queries
GET /api/v1/sql/schema  ::  apps.api.security_query_language_router.get_schema | apps.api.security_query_router.get_schema
GET /api/v1/sql/stats  ::  apps.api.security_query_language_router.get_stats | apps.api.security_query_router.get_stats
GET /api/v1/supply-chain/components  ::  apps.api.supply_chain_risk_router.list_components | apps.api.supply_chain_router.list_components
GET /api/v1/supply-chain/risks  ::  apps.api.gap_router.supply_chain_risks | apps.api.supply_chain_risk_router.list_risks | apps.api.supply_chain_router.get_risk_dashboard
GET /api/v1/supply-chain/stats  ::  apps.api.supply_chain_risk_router.get_stats | apps.api.supply_chain_router.get_intel_stats
GET /api/v1/system/health  ::  apps.api.system_health_router.get_system_health | apps.api.system_router.system_health
GET /api/v1/vendors  ::  apps.api.vendor_risk_router.list_vendors | apps.api.vendor_scorecard_router.list_vendors
GET /api/v1/vendors/high-risk  ::  apps.api.vendor_risk_router.list_high_risk_vendors | apps.api.vendor_scorecard_router.get_high_risk_vendors
GET /api/v1/vendors/{vendor_id}  ::  apps.api.vendor_risk_router.get_vendor | apps.api.vendor_scorecard_router.get_vendor
GET /api/v1/version  ::  apps.api.health.version_info | apps.api.version_router.get_version
GET /api/v1/vuln-prioritization/stats  ::  apps.api.vuln_prioritization_router.get_stats | apps.api.vulnerability_prioritization_router.get_prioritization_stats
GET /api/v1/vuln-workflow/stats  ::  apps.api.vuln_workflow_router.get_workflow_stats | apps.api.vulnerability_workflow_router.get_workflow_stats
GET /api/v1/webhooks/events  ::  api.webhooks_router.list_webhook_events | apps.api.webhook_router.list_events
GET /api/v1/workflows  ::  apps.api.workflow_engine_router.list_workflows | apps.api.workflow_router.list_workflows | apps.api.workflows_router.list_workflows
GET /api/v1/workflows/executions  ::  apps.api.workflow_engine_router.get_executions | apps.api.workflow_router.list_executions
GET /api/v1/workflows/rules  ::  apps.api.gap_router.list_workflow_rules | apps.api.workflows_router.list_workflow_rules
GET /api/v1/workflows/stats  ::  apps.api.workflow_engine_router.get_stats | apps.api.workflow_router.get_stats
GET /api/v1/workflows/templates  ::  apps.api.workflow_engine_router.get_templates | apps.api.workflow_router.get_templates
GET /api/v1/workflows/{workflow_id}  ::  apps.api.workflow_engine_router.get_workflow | apps.api.workflow_router.get_workflow
GET /docs  ::  apps.api.app.create_app.<locals>._docs_root_alias | fastapi.applications.FastAPI.setup.<locals>.swagger_ui_html
GET /redoc  ::  apps.api.app.create_app.<locals>._redoc_root_alias | fastapi.applications.FastAPI.setup.<locals>.redoc_html
POST /api/v1/api-security-engine/abuse-events  ::  apps.api.api_security_engine_router.record_abuse_event | apps.api.api_security_mgmt_router.record_abuse_event
POST /api/v1/api-security-engine/keys  ::  apps.api.api_security_engine_router.create_api_key | apps.api.api_security_mgmt_router.create_api_key
POST /api/v1/auth/keys  ::  apps.api.apikey_router.create_key | apps.api.auth_router.create_api_key
POST /api/v1/auth/keys/{key_id}/rotate  ::  apps.api.apikey_router.rotate_key | apps.api.auth_router.rotate_api_key
POST /api/v1/bulk/export  ::  apps.api.bulk_operations_router.export_findings | apps.api.bulk_router.bulk_export
POST /api/v1/certificates/  ::  apps.api.cert_router.add_certificate | apps.api.certificate_lifecycle_router.register_certificate
POST /api/v1/compliance/poam  ::  apps.api.compliance_automation_router.create_poam | apps.api.compliance_router.create_poam
POST /api/v1/cspm/baseline  ::  api.cspm_router.save_baseline | apps.api.cspm_deep_router.capture_baseline
POST /api/v1/ctem/cycles  ::  apps.api.ctem_engine_router.create_cycle | apps.api.ctem_router.start_cycle
POST /api/v1/ctem/cycles/{cycle_id}/advance  ::  apps.api.ctem_engine_router.advance_stage | apps.api.ctem_router.advance_stage
POST /api/v1/ctem/cycles/{cycle_id}/scope  ::  apps.api.ctem_engine_router.scope_assets | apps.api.ctem_router.scope_assets
POST /api/v1/dast/scan  ::  api.dast_router.start_scan | apps.api.dast_router.start_scan
POST /api/v1/fips/activate  ::  apps.api.fips_compliance_router.activate_fips_mode | apps.api.fips_router.activate_fips_mode
POST /api/v1/fips/deactivate  ::  apps.api.fips_compliance_router.deactivate_fips_mode | apps.api.fips_router.deactivate_fips_mode
POST /api/v1/graph/index  ::  apps.api.trustgraph_backbone_router.index_entity | apps.api.trustgraph_integration_router.index_findings
POST /api/v1/graphrag/builder  ::  apps.api.graphrag_router.builder | apps.api.mcp_routes.graphrag_builder
POST /api/v1/graphrag/query  ::  apps.api.graphrag_router.query | apps.api.mcp_routes.graphrag_query
POST /api/v1/integrations  ::  api.integrations_router.create_integration | apps.api.integration_health_router.register_integration
POST /api/v1/mdm/devices  ::  apps.api.mdm_router.enroll_device | apps.api.mobile_device_management_router.enroll_device
POST /api/v1/mdm/devices/{device_id}/wipe  ::  apps.api.mdm_router.wipe_device | apps.api.mobile_device_management_router.wipe_device
POST /api/v1/nac/policies  ::  apps.api.nac_router.create_policy | apps.api.network_access_control_router.create_nac_policy
POST /api/v1/network/flows  ::  apps.api.network_analyzer_router.add_flow | apps.api.network_security_router.record_flow
POST /api/v1/orgs  ::  apps.api.org_hierarchy_router.create_org | apps.api.org_router.create_org
POST /api/v1/phishing/campaigns  ::  apps.api.phishing_router.create_campaign | apps.api.phishing_simulation_router.create_campaign
POST /api/v1/phishing/templates  ::  apps.api.phishing_router.add_template | apps.api.phishing_simulation_router.create_template
POST /api/v1/playbooks  ::  apps.api.playbook_router.create_playbook | apps.api.playbook_routes.create_playbook
POST /api/v1/playbooks/{playbook_id}/execute  ::  apps.api.playbook_router.execute_playbook | apps.api.playbook_routes.execute_playbook
POST /api/v1/policies  ::  apps.api.policies_router.create_policy | apps.api.policy_router.create_policy
POST /api/v1/policies/evaluate  ::  apps.api.policies_router.evaluate_context | apps.api.policy_router.evaluate_policy
POST /api/v1/sql/execute  ::  apps.api.security_query_language_router.execute_query | apps.api.security_query_router.execute_query
POST /api/v1/supply-chain/analyze  ::  api.supply_chain_router.analyze_packages | apps.api.supply_chain_router.analyze_package
POST /api/v1/vendors  ::  apps.api.vendor_risk_router.create_vendor | apps.api.vendor_scorecard_router.add_vendor
POST /api/v1/workflows  ::  apps.api.workflow_engine_router.create_workflow | apps.api.workflow_router.create_workflow | apps.api.workflows_router.create_workflow
PUT /api/v1/mdm/devices/{device_id}/compliance  ::  apps.api.mdm_router.update_compliance | apps.api.mobile_device_management_router.update_compliance

### 26 IMPORT-PATH dups (api.X vs apps.api.X — same file, two sys.path entries):
GET /api/v1/dast/
GET /api/v1/dast/findings
GET /api/v1/dast/headers/{url:path}
GET /api/v1/dast/health
GET /api/v1/dast/profiles
GET /api/v1/dast/scans/{scan_id}
GET /api/v1/dast/stats
GET /api/v1/dast/status
GET /api/v1/feeds
GET /api/v1/feeds/health
GET /api/v1/feeds/stats
GET /api/v1/feeds/status
GET /api/v1/graph/
GET /api/v1/graph/stats
GET /api/v1/ide/status
GET /api/v1/integrations
GET /api/v1/integrations/marketplace
GET /api/v1/pipeline/health
GET /api/v1/risk/
GET /api/v1/siem/events
GET /api/v1/siem/stats
GET /api/v1/webhooks/events
POST /api/v1/cspm/baseline
POST /api/v1/dast/scan
POST /api/v1/integrations
POST /api/v1/supply-chain/analyze
```
