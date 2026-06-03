# Duplicate-Route / Shadow-Collision Audit — 2026-06-03

> Generated from the live route table (`create_app()`), handlers attributed via runtime
> `endpoint.__module__` (the only reliable way — see the duplicate-router gotcha).
> **This is an audit only — no routes were changed.** Consolidation is behaviour-changing
> (it decides which handler wins a path) and is a FOUNDER decision per shadow.

## Summary
- **7524** distinct `(method, path)` route keys mounted.
- **742** are duplicated (same method+path registered by >1 route).
  - **620 same-handler** dup-registrations — HARMLESS (same function registered twice, e.g.
    a router included under two mounts). No behaviour ambiguity; low-priority cleanup.
  - **122 DIFFERENT-handler shadow collisions** — REAL DEBT. FastAPI serves the
    first-registered handler; the others are DEAD/shadowed. If the wrong handler won
    (e.g. a `gap_router` catch-all over the real domain router), the endpoint serves the
    inferior implementation. **These 122 are the consolidation worklist.**

## Top routers involved in shadow collisions
| Router | # collisions | Note |
|--------|-------------|------|
| gap_router | 20 | Catch-all that shadows real domain routers (attack-paths, audit, fail, compliance). Likely registered early → wins. **Highest priority: gap_router should YIELD to domain routers.** |
| workflow_engine_router ↔ workflow_router | 7 / 7 | Duplicate workflow impls — pick one canonical owner. |
| ctem_router ↔ ctem_engine_router | 6 / 6 | Duplicate CTEM impls (see SPEC-012). |
| phishing_router ↔ phishing_simulation_router | 6 / 6 | Duplicate phishing impls. |
| security_query_router ↔ security_query_language_router | 6 / 6 | Duplicate SQL/query impls. |
| api_security_engine_router ↔ api_security_mgmt_router | 5 / 5 | Duplicate API-security impls. |
| mdm_router ↔ mobile_device_management_router | 5 / 5 | Duplicate MDM impls. |
| supply_chain_router, playbook_router | 5 / 5 | playbook collision = the /api/v1/playbooks zone (SPEC-023). |

## Recommended consolidation approach (per founder sign-off)
1. **gap_router**: confirm it's a legacy catch-all; for each of its 20 collisions, verify the
   real domain router's handler is equivalent-or-better, then remove the gap_router route.
2. **Duplicate pairs**: for each pair, pick the canonical owner (the one matching its SPEC /
   richer impl), point the other's routes at it or delete them. Verify response-shape parity
   before deleting (the shadowed one may have UI consumers expecting its shape).
3. After each removal: re-run this audit (shadow count must drop) + the no-unauthenticated
   guard + Beast smoke.

## Full shadow-collision list (122) — `METHOD path :: handler-A | handler-B`
DELETE /api/v1/sql/queries/{query_id}  ::  security_query_router.delete_query  |  security_query_language_router.delete_query
DELETE /api/v1/workflows/{workflow_id}  ::  workflow_engine_router.delete_workflow  |  workflow_router.delete_workflow
GET /api/v1/analytics/  ::  analytics_router.analytics_root_index  |  analytics_dashboard_router.analytics_index
GET /api/v1/analytics/mttr  ::  analytics_router.get_mttr  |  analytics_dashboard_router.get_mttr
GET /api/v1/api-security-engine/abuse-events  ::  api_security_engine_router.list_abuse_events  |  api_security_mgmt_router.list_abuse_events
GET /api/v1/api-security-engine/keys  ::  api_security_engine_router.list_api_keys  |  api_security_mgmt_router.list_api_keys
GET /api/v1/api-security-engine/stats  ::  api_security_engine_router.get_api_stats  |  api_security_mgmt_router.get_security_stats
GET /api/v1/attack-paths/  ::  attack_path_router.attack_paths_index  |  gap_router.list_attack_paths
GET /api/v1/audit/  ::  audit_router.audit_index  |  gap_router.list_audit_logs
GET /api/v1/audit/trail  ::  audit_router.get_audit_trail  |  gap_router.get_audit_trail
GET /api/v1/auth/keys  ::  auth_router.list_api_keys  |  apikey_router.list_keys
GET /api/v1/auth/sso  ::  auth_router.list_sso_configs  |  sso_router.sso_status
GET /api/v1/certificates/  ::  cert_router.list_certificates  |  certificate_lifecycle_router.list_certificates
GET /api/v1/certificates/{cert_id}  ::  cert_router.get_certificate  |  certificate_lifecycle_router.get_certificate
GET /api/v1/certificates/stats  ::  cert_router.get_cert_stats  |  certificate_lifecycle_router.get_certificate_stats
GET /api/v1/compliance/evidence  ::  compliance_automation_router.get_evidence  |  compliance_router.get_evidence
GET /api/v1/compliance/gaps  ::  compliance_automation_router.get_gaps  |  compliance_router.get_gaps
GET /api/v1/compliance/poam  ::  compliance_automation_router.get_poam  |  compliance_router.get_poam_list
GET /api/v1/compliance/status  ::  compliance_automation_router.get_overall_status  |  compliance_router.get_overall_status  |  gap_router.compliance_overall_status
GET /api/v1/connectors/{name}/health  ::  connectors_router.connector_health  |  connector_routes.get_connector_health
GET /api/v1/ctem/cycles  ::  ctem_router.list_cycles  |  ctem_engine_router.list_cycles
GET /api/v1/ctem/cycles/{cycle_id}  ::  ctem_router.get_cycle  |  ctem_engine_router.get_cycle
GET /api/v1/ctem/cycles/{cycle_id}/exposures  ::  ctem_router.get_exposures  |  ctem_engine_router.get_cycle_exposures
GET /api/v1/fail/history  ::  fail_router.get_fail_history  |  gap_router.get_fail_history
GET /api/v1/fail/readiness  ::  fail_router.get_readiness_score  |  gap_router.get_fail_readiness
GET /api/v1/feeds  ::  feed_manager_router.list_feeds  |  feeds_router_sf.list_feeds
GET /api/v1/feeds/health  ::  feed_manager_router.get_all_health  |  feed_manager_router.feed_manager_health  |  feeds_router_sf.get_feed_health
GET /api/v1/feeds/stats  ::  feed_manager_router.get_feed_stats  |  feeds_router_sf.get_feed_stats
GET /api/v1/feeds/status  ::  feed_manager_router.feed_manager_status  |  feeds_router_sf.feeds_status
GET /api/v1/findings  ::  findings_wave_b_router.list_findings  |  findings_routes.list_findings  |  gap_router.list_all_findings
GET /api/v1/fips/readiness  ::  fips_router.fips_readiness_score  |  fips_compliance_router.fips_readiness_score
GET /api/v1/fips/stats  ::  fips_router.stats  |  fips_compliance_router.get_stats
GET /api/v1/fips/status  ::  fips_router.get_fips_status  |  fips_compliance_router.get_fips_status
GET /api/v1/graph/  ::  graph_router.graph_summary  |  gap_router.graph_index
GET /api/v1/graph/attack-paths  ::  trustgraph_integration_router.get_attack_paths  |  gap_router.get_attack_paths
GET /api/v1/graph/impact/{entity_id}  ::  trustgraph_integration_router.get_impact_analysis  |  trustgraph_backbone_router.get_impact
GET /api/v1/graph/stats  ::  graph_router.graph_stats  |  trustgraph_backbone_router.get_stats
GET /api/v1/graphrag/health  ::  graphrag_router.health  |  graph_rag_router.health
GET /api/v1/ide/status  ::  ide_backend_router.status  |  ide_router.get_ide_status
GET /api/v1/integrations  ::  integration_health_router.list_integrations  |  integrations_router.list_integrations  |  gap_router.list_integrations_gap
GET /api/v1/integrations/  ::  integration_hub_router.list_integrations  |  gap_router.list_integrations_gap
GET /api/v1/integrations/marketplace  ::  integrations_router.list_marketplace_integrations  |  gap_router.list_marketplace_integrations
GET /api/v1/logs/stats  ::  detailed_logging.get_log_stats  |  gap_router.logs_stats
GET /api/v1/mcp/stats  ::  mcp_routes.get_mcp_stats  |  mcp_router.mcp_stats
GET /api/v1/mcp/tools  ::  mcp_routes.list_mcp_tools  |  mcp_router.list_mcp_tools
GET /api/v1/mdm/devices  ::  mdm_router.list_devices  |  mobile_device_management_router.list_devices
GET /api/v1/mdm/devices/{device_id}  ::  mdm_router.get_device  |  mobile_device_management_router.get_device
GET /api/v1/nac/policies  ::  nac_router.list_policies  |  network_access_control_router.list_nac_policies
GET /api/v1/nac/stats  ::  nac_router.get_nac_stats  |  network_access_control_router.get_nac_stats
GET /api/v1/notifications/  ::  notification_router.get_notification_root_summary  |  gap_router.list_notifications
GET /api/v1/notifications/preferences  ::  notification_router.get_preferences  |  gap_router.get_notification_preferences
GET /api/v1/phishing/campaigns  ::  phishing_router.list_campaigns  |  phishing_simulation_router.list_campaigns
GET /api/v1/phishing/campaigns/{campaign_id}  ::  phishing_router.get_campaign_results  |  phishing_simulation_router.get_campaign
GET /api/v1/phishing/stats  ::  phishing_router.get_stats  |  phishing_simulation_router.get_org_stats
GET /api/v1/phishing/templates  ::  phishing_router.list_templates  |  phishing_simulation_router.list_templates
GET /api/v1/pipeline/health  ::  pipeline_routes.get_pipeline_health  |  pipeline_router.pipeline_health
GET /api/v1/playbooks  ::  playbook_routes.list_playbooks  |  playbook_router.list_playbooks  |  gap_router.list_playbooks
GET /api/v1/playbooks/{playbook_id}  ::  playbook_routes.get_playbook  |  playbook_router.get_playbook
GET /api/v1/playbooks/executions  ::  ir_playbook_runner_router.list_executions  |  playbook_router.list_executions
GET /api/v1/policies  ::  policy_router.list_policies  |  policies_router.list_policies
GET /api/v1/reports/templates  ::  reports_router.list_report_templates  |  gap_router.list_report_templates
GET /api/v1/risk/  ::  risk_router.risk_summary  |  composite_risk_router.risk_index
GET /api/v1/rules/dsl  ::  dynamic_rule_dsl_router.list_rules  |  wave_c_router.list_dsl_rules
GET /api/v1/sbom/  ::  sbom_router.sbom_overview  |  gap_router.list_sbom_components
GET /api/v1/siem/events  ::  siem_integration_router.list_events  |  siem_router.recent_events
GET /api/v1/siem/stats  ::  siem_integration_router.get_stats  |  siem_router.siem_stats
GET /api/v1/sql/history  ::  security_query_router.list_history  |  security_query_language_router.list_history
GET /api/v1/sql/queries  ::  security_query_router.list_queries  |  security_query_language_router.list_queries
GET /api/v1/sql/schema  ::  security_query_router.get_schema  |  security_query_language_router.get_schema
GET /api/v1/sql/stats  ::  security_query_router.get_stats  |  security_query_language_router.get_stats
GET /api/v1/supply-chain/components  ::  supply_chain_risk_router.list_components  |  supply_chain_router.list_components
GET /api/v1/supply-chain/risks  ::  supply_chain_risk_router.list_risks  |  supply_chain_router.get_risk_dashboard  |  gap_router.supply_chain_risks
GET /api/v1/supply-chain/stats  ::  supply_chain_risk_router.get_stats  |  supply_chain_router.get_intel_stats
GET /api/v1/system/health  ::  system_router.system_health  |  system_health_router.get_system_health
GET /api/v1/vendors  ::  vendor_scorecard_router.list_vendors  |  vendor_risk_router.list_vendors
GET /api/v1/vendors/{vendor_id}  ::  vendor_scorecard_router.get_vendor  |  vendor_risk_router.get_vendor
GET /api/v1/vendors/high-risk  ::  vendor_scorecard_router.get_high_risk_vendors  |  vendor_risk_router.list_high_risk_vendors
GET /api/v1/version  ::  health.version_info  |  version_router.get_version
GET /api/v1/vuln-prioritization/stats  ::  vuln_prioritization_router.get_stats  |  vulnerability_prioritization_router.get_prioritization_stats
GET /api/v1/vuln-workflow/stats  ::  vuln_workflow_router.get_workflow_stats  |  vulnerability_workflow_router.get_workflow_stats
GET /api/v1/webhooks/events  ::  webhook_router.list_events  |  webhooks_router.list_webhook_events
GET /api/v1/workflows  ::  workflows_router.list_workflows  |  workflow_engine_router.list_workflows  |  workflow_router.list_workflows
GET /api/v1/workflows/{workflow_id}  ::  workflow_engine_router.get_workflow  |  workflow_router.get_workflow
GET /api/v1/workflows/executions  ::  workflow_engine_router.get_executions  |  workflow_router.list_executions
GET /api/v1/workflows/rules  ::  workflows_router.list_workflow_rules  |  gap_router.list_workflow_rules
GET /api/v1/workflows/stats  ::  workflow_engine_router.get_stats  |  workflow_router.get_stats
GET /api/v1/workflows/templates  ::  workflow_engine_router.get_templates  |  workflow_router.get_templates
GET /docs  ::  applications.FastAPI.setup.<locals>.swagger_ui_html  |  app.create_app.<locals>._docs_root_alias
GET /redoc  ::  applications.FastAPI.setup.<locals>.redoc_html  |  app.create_app.<locals>._redoc_root_alias
POST /api/v1/api-security-engine/abuse-events  ::  api_security_engine_router.record_abuse_event  |  api_security_mgmt_router.record_abuse_event
POST /api/v1/api-security-engine/keys  ::  api_security_engine_router.create_api_key  |  api_security_mgmt_router.create_api_key
POST /api/v1/auth/keys  ::  auth_router.create_api_key  |  apikey_router.create_key
POST /api/v1/auth/keys/{key_id}/rotate  ::  auth_router.rotate_api_key  |  apikey_router.rotate_key
POST /api/v1/bulk/export  ::  bulk_operations_router.export_findings  |  bulk_router.bulk_export
POST /api/v1/certificates/  ::  cert_router.add_certificate  |  certificate_lifecycle_router.register_certificate
POST /api/v1/compliance/poam  ::  compliance_automation_router.create_poam  |  compliance_router.create_poam
POST /api/v1/cspm/baseline  ::  cspm_deep_router.capture_baseline  |  cspm_router.save_baseline
POST /api/v1/ctem/cycles  ::  ctem_router.start_cycle  |  ctem_engine_router.create_cycle
POST /api/v1/ctem/cycles/{cycle_id}/advance  ::  ctem_router.advance_stage  |  ctem_engine_router.advance_stage
POST /api/v1/ctem/cycles/{cycle_id}/scope  ::  ctem_router.scope_assets  |  ctem_engine_router.scope_assets
POST /api/v1/fips/activate  ::  fips_router.activate_fips_mode  |  fips_compliance_router.activate_fips_mode
POST /api/v1/fips/deactivate  ::  fips_router.deactivate_fips_mode  |  fips_compliance_router.deactivate_fips_mode
POST /api/v1/graph/index  ::  trustgraph_integration_router.index_findings  |  trustgraph_backbone_router.index_entity
POST /api/v1/graphrag/builder  ::  mcp_routes.graphrag_builder  |  graphrag_router.builder
POST /api/v1/graphrag/query  ::  mcp_routes.graphrag_query  |  graphrag_router.query
POST /api/v1/integrations  ::  integration_health_router.register_integration  |  integrations_router.create_integration
POST /api/v1/mdm/devices  ::  mdm_router.enroll_device  |  mobile_device_management_router.enroll_device
POST /api/v1/mdm/devices/{device_id}/wipe  ::  mdm_router.wipe_device  |  mobile_device_management_router.wipe_device
POST /api/v1/nac/policies  ::  nac_router.create_policy  |  network_access_control_router.create_nac_policy
POST /api/v1/network/flows  ::  network_security_router.record_flow  |  network_analyzer_router.add_flow
POST /api/v1/orgs  ::  org_router.create_org  |  org_hierarchy_router.create_org
POST /api/v1/phishing/campaigns  ::  phishing_router.create_campaign  |  phishing_simulation_router.create_campaign
POST /api/v1/phishing/templates  ::  phishing_router.add_template  |  phishing_simulation_router.create_template
POST /api/v1/playbooks  ::  playbook_routes.create_playbook  |  playbook_router.create_playbook
POST /api/v1/playbooks/{playbook_id}/execute  ::  playbook_routes.execute_playbook  |  playbook_router.execute_playbook
POST /api/v1/policies  ::  policy_router.create_policy  |  policies_router.create_policy
POST /api/v1/policies/evaluate  ::  policy_router.evaluate_policy  |  policies_router.evaluate_context
POST /api/v1/sql/execute  ::  security_query_router.execute_query  |  security_query_language_router.execute_query
POST /api/v1/supply-chain/analyze  ::  supply_chain_router.analyze_package  |  supply_chain_router.analyze_packages
POST /api/v1/vendors  ::  vendor_scorecard_router.add_vendor  |  vendor_risk_router.create_vendor
POST /api/v1/workflows  ::  workflows_router.create_workflow  |  workflow_engine_router.create_workflow  |  workflow_router.create_workflow
PUT /api/v1/mdm/devices/{device_id}/compliance  ::  mdm_router.update_compliance  |  mobile_device_management_router.update_compliance
