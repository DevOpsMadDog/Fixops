# TrustGraph Endpoint Audit — 2026-04-13

## Executive Summary

| Metric | Count | % of Total |
|--------|-------|------------|
| Total routers audited | 226 | 100% |
| Connected to TrustGraph | 5 | 2.2% |
| Producing (disconnected) | 204 | 90.3% |
| Consuming only (GET) | 17 | 7.5% |

**97.8% of routers are NOT connected to TrustGraph.**
**204 routers are actively generating security data with zero TrustGraph indexing.**

---

## Connected Routers (Already Wired) — 5

| Router | Prefix |
|--------|--------|
| deployment_router.py | /api/v1/deployment |
| event_bus_router.py | /api/v1/event-bus |
| trustgraph_backbone_router.py | /api/v1/graph |
| trustgraph_integration_router.py | /api/v1/graph |
| trustgraph_migrator_router.py | /api/v1/trustgraph/migrate |

---

## Producing Disconnected — 204

Routers with POST/PUT/PATCH endpoints that generate security data but do not call TrustGraph.
Sorted by priority.

### CRITICAL (5) — Connect Immediately

These are the highest-value data sources: raw scanner ingestion, asset inventory, incidents, compliance, and threat feeds. Every scan result, asset, and incident created here is invisible to TrustGraph.

| Router | Prefix |
|--------|--------|
| asset_inventory_router.py | /api/v1/assets |
| compliance_engine_router.py | /compliance-engine |
| feed_manager_router.py | /api/v1/feeds |
| incident_response_router.py | /api/v1/incidents |
| scanner_ingest_router.py | /api/v1/scanner-ingest |

### HIGH (11) — Connect Next Sprint

SAST, secrets, CSPM, container security, and vulnerability routers — all produce structured finding data that should flow into TrustGraph knowledge cores.

| Router | Prefix |
|--------|--------|
| container_router.py | /api/v1/container |
| container_runtime_router.py | /api/v1/containers |
| container_scanner_router.py | /api/v1/containers |
| cspm_engine_router.py | /api/v1/cspm-engine |
| cspm_router.py | /api/v1/cspm |
| sast_router.py | /api/v1/sast |
| secret_scanner_router.py | /api/v1/secrets |
| secrets_router.py | /api/v1/secrets |
| vuln_discovery_router.py | /api/v1/vulns |
| vuln_lifecycle_router.py | /api/v1/vuln-lifecycle |
| vuln_prioritizer_router.py | /api/v1/vulns |

### MEDIUM (188) — Backlog

All other producing routers. Representative sample:

| Router | Prefix |
|--------|--------|
| access_matrix_router.py | /api/v1/access-matrix |
| admin_router.py | /api/v1/admin |
| agents_router.py | /api/v1/copilot/agents |
| ai_orchestrator_router.py | /api/v1/ai-orchestrator |
| airgap_router.py | /api/v1/airgap |
| algorithmic_router.py | /api/v1/algorithms |
| analytics_router.py | /api/v1/analytics |
| anomaly_ml_router.py | /api/v1/anomaly-ml |
| anomaly_router.py | /api/v1/anomalies |
| api_analytics_router.py | /api/v1/api-analytics |
| api_gateway_router.py | /api/v1/gateway |
| api_security_router.py | /api/v1/api-security |
| apikey_router.py | /api/v1/auth/keys |
| app_config_router.py | /api/v1/apps |
| attack_sim_router.py | /api/v1/attack-sim |
| attack_surface_manager_router.py | /api/v1/attack-surface |
| attack_surface_router.py | /api/v1/attack-surface |
| audit_analytics_router.py | /api/v1/audit-analytics |
| audit_router.py | /api/v1/audit |
| auth_router.py | /api/v1/auth |
| auto_evidence_router.py | /api/v1/auto-evidence |
| auto_pentest_router.py | /api/v1/auto-pentest |
| autofix_router.py | /api/v1/autofix |
| autofix_verify_router.py | /api/v1/autofix/verify |
| aws_security_hub_router.py | /api/v1/scan/aws-security-hub |
| azure_defender_router.py | /api/v1/scan/azure-defender |
| backup_router.py | /api/v1/backups |
| backup_validator_router.py | /api/v1/backup-dr |
| brain_router.py | /api/v1/brain |
| breach_simulation_router.py | /api/v1/breach-sim |
| bug_bounty_router.py | /api/v1/bounty |
| bulk_operations_router.py | /api/v1/bulk |
| bulk_router.py | /api/v1/bulk |
| cache_router.py | /api/v1/cache |
| change_management_router.py | /api/v1/changes |
| change_tracker_router.py | /api/v1/change-tracker |
| changelog_router.py | /api/v1/changelog |
| cicd_router.py | /api/v1/cicd |
| cloud_connectors_router.py | /api/v1/cloud-connectors |
| cloud_discovery_router.py | /api/v1/cloud |
| cloud_graph_router.py | /api/v1/cloud-graph |
| code_ownership_router.py | /api/v1/ownership |
| code_to_cloud_router.py | /api/v1/code-to-cloud |
| collaboration_router.py | /api/v1/collaboration |
| compliance_automation_router.py | /api/v1/compliance |
| compliance_calendar_router.py | /api/v1/compliance-calendar |
| compliance_planner_router.py | /api/v1/compliance-planner |
| compliance_reports_router.py | /api/v1/compliance-reports |
| connectors_router.py | /api/v1/connectors |
| copilot_router.py | /api/v1/copilot |
| correlation_router.py | /api/v1/correlations |
| ctem_engine_router.py | /api/v1/ctem |
| dashboard_builder_router.py | /api/v1/dashboards |
| dast_router.py | /api/v1/dast |
| data_classification_router.py | /api/v1/classification |
| data_security_router.py | /api/v1/data |
| db_security_router.py | /api/v1/db-security |
| deduplication_router.py | /api/v1/deduplication |
| dep_scanner_router.py | /api/v1/dep-scanner |
| developer_portal_router.py | /api/v1/developer |
| drift_router.py | /api/v1/drift |
| evidence_chain_router.py | /api/v1/evidence-chain |
| evidence_collector_router.py | /api/v1/evidence-collector |
| evidence_router.py | /evidence |
| exception_policy_router.py | /api/v1/exceptions |
| executive_dashboard_router.py | /api/v1/executive |
| executive_report_router.py | /api/v1/reports/executive |
| exposure_case_router.py | /api/v1/cases |
| fail_router.py | /api/v1/fail |
| fedramp_router.py | /api/v1/fedramp |
| fix_engine_router.py | /api/v1/remediation |
| fuzzy_identity_router.py | /api/v1/identity |
| gate_router.py | /api/v1/gate |
| gcp_scc_router.py | /api/v1/scan/gcp-scc |
| github_issues_router.py | /api/v1/github/issues |
| github_security_router.py | /api/v1/security/github |
| graphql_router.py | /api/v1/graphql |
| iac_scanner_router.py | /api/v1/iac |
| ide_router.py | /api/v1/ide |
| insider_threat_router.py | /api/v1/insider-threat |
| integration_health_router.py | /api/v1/integrations |
| integration_hub_router.py | /api/v1/integrations |
| integration_marketplace_router.py | /api/v1/integrations |
| inventory_router.py | /api/v1/inventory |
| iot_security_router.py | /api/v1/iot |
| ip_reputation_router.py | /api/v1/reputation |
| ir_playbook_router.py | /api/v1/ir |
| jira_sync_router.py | /api/v1/jira-sync |
| k8s_security_router.py | /api/v1/k8s |
| kpi_router.py | /api/v1/kpis |
| license_compliance_router.py | /api/v1/licenses |
| license_scanner_router.py | /api/v1/license-scanner |
| llm_monitor_router.py | /api/v1/llm-monitor |
| llm_router.py | /api/v1/llm |
| malware_router.py | /api/v1/malware |
| marketplace_router.py | (no prefix) |
| material_change_router.py | /api/v1/changes |
| mcp_gateway_router.py | /api/v1/mcp-gateway |
| mcp_protocol_router.py | /api/v1/mcp-protocol |
| mcp_router.py | /api/v1/mcp |
| micro_pentest_router.py | /api/v1/micro-pentest |
| mindsdb_router.py | /api/v1/ml |
| mitre_mapper_router.py | /api/v1/mitre |
| mitre_navigator_router.py | /api/v1/mitre |
| mpte_orchestrator_router.py | /api/v1/mpte-orchestrator |
| mpte_router.py | /api/v1/mpte |
| network_analyzer_router.py | /api/v1/network |
| network_security_router.py | /api/v1/network |
| notification_router.py | /api/v1/notifications |
| observability_router.py | /api/v1/observability |
| onboarding_router.py | /api/v1/onboarding |
| pagerduty_router.py | /api/v1/pagerduty |
| pam_router.py | /api/v1/pam |
| patch_manager_router.py | /api/v1/patches |
| pentest_router.py | /api/v1/pentest |
| phishing_router.py | /api/v1/phishing |
| pipeline_router.py | /api/v1/brain |
| playbook_marketplace_router.py | /playbook-marketplace |
| policies_router.py | /api/v1/policies |
| policy_engine_router.py | /api/v1/policy-engine |
| policy_generator_router.py | /api/v1/policy-generator |
| postfix_verify_router.py | /api/v1/verify |
| posture_benchmark_router.py | /api/v1/posture-benchmark |
| posture_router.py | /api/v1/posture |
| pr_gate_router.py | /api/v1/pr-gate |
| pr_generator_router.py | /api/v1/remediation/prs |
| predictions_router.py | /api/v1/predictions |
| prioritizer_router.py | /api/v1/prioritize |
| purple_team_router.py | /api/v1/purple-team |
| quantum_crypto_router.py | /api/v1/quantum-crypto |
| questionnaire_router.py | /api/v1/questionnaires |
| rasp_router.py | /api/v1/rasp |
| rate_limit_router.py | /api/v1/rate-limits |
| regulatory_tracker_router.py | /api/v1/regulatory |
| remediation_board_router.py | /api/v1/remediation-board |
| remediation_router.py | /api/v1/remediation |
| report_builder_router.py | /api/v1/report-builder |
| reports_router.py | /api/v1/reports |
| retention_router.py | /api/v1/retention |
| risk_acceptance_router.py | /api/v1/risk-acceptance |
| risk_quantifier_router.py | /api/v1/risk-quantifier |
| risk_register_router.py | /api/v1/risks |
| runtime_protection_router.py | /api/v1/runtime |
| sbom_router.py | /api/v1/sbom |
| security_kb_router.py | /api/v1/kb |
| security_metrics_router.py | /api/v1/metrics |
| security_roi_router.py | /api/v1/security-roi |
| security_scorecard_router.py | /api/v1/scorecard |
| self_learning_router.py | /api/v1/self-learning |
| self_scan_router.py | /api/v1/self-scan |
| semgrep_router.py | /api/v1/scan/semgrep |
| servicenow_sync_router.py | /api/v1/servicenow-sync |
| session_router.py | /api/v1/sessions |
| single_agent_router.py | /api/v1/ai-agent |
| sla_management_router.py | /api/v1/sla-management |
| sla_router.py | /api/v1/sla |
| slack_bot_router.py | /api/v1/slack |
| snyk_router.py | /api/v1/scan/snyk |
| soar_router.py | /api/v1/soar |
| soc_automation_router.py | /api/v1/soc-automation |
| sso_router.py | /api/v1/auth/sso |
| stream_router.py | /api/v1/stream |
| supply_chain_router.py | /api/v1/supply-chain |
| tag_router.py | /api/v1/tags |
| teams_router.py | /api/v1/teams |
| tenant_rate_limiter_router.py | /api/v1/rate-limits |
| threat_hunter_router.py | /api/v1/hunt |
| threat_hunting_router.py | /api/v1/hunting |
| threat_intel_router.py | /api/v1/threat-intel |
| threat_model_router.py | /api/v1/threat-models |
| training_router.py | /api/v1/training |
| triage_router.py | /api/v1/triage |
| trivy_router.py | /api/v1/scan/trivy |
| trust_center_router.py | /api/v1/trust |
| user_analytics_router.py | /api/v1/analytics/users |
| users_router.py | /api/v1/users |
| validation_router.py | /api/v1/validate |
| vendor_risk_router.py | /api/v1/vendors |
| vendor_scorecard_router.py | /api/v1/vendors |
| vllm_router.py | /api/v1/vllm |
| waf_router.py | /api/v1/waf |
| webhook_dlq_router.py | /api/v1/webhooks/dlq |
| webhook_events_router.py | /api/v1/events |
| webhook_subscriptions_router.py | /api/v1/webhook-subscriptions |
| webhook_verifier_router.py | /api/v1/webhooks/verify |
| workflow_engine_router.py | /api/v1/workflows |
| workflows_router.py | /api/v1/workflows |
| zero_gravity_router.py | /api/v1/zero-gravity |
| zero_trust_router.py | /api/v1/zero-trust |

---

## Consuming Only (GET) — 17

Routers with no write operations. Low priority for TrustGraph wiring.

| Router | Prefix |
|--------|--------|
| analytics_dashboard_router.py | /api/v1/analytics |
| feeds_router.py | /api/v1/feeds |
| gap_router.py | /api/v1/audit |
| graph_router.py | /graph |
| metrics_aggregator_router.py | /api/v1/metrics |
| provenance_router.py | /provenance |
| queue_router.py | /api/v1/queue |
| risk_router.py | /risk |
| streaming_router.py | /api/v1/stream |
| system_health_router.py | /api/v1/system |
| system_router.py | /api/v1/system |
| tenant_router.py | /api/v1/tenants |
| unified_dashboard_router.py | /api/v1/unified-dashboard |
| versioning_router.py | /api/versions |

---

## Recommended Action Plan

### Sprint 1 — CRITICAL (5 routers)
Connect the 5 CRITICAL routers to TrustGraph via `event_bus_router.py` (already connected).
Pattern: after each POST that creates a finding/asset/incident, publish to event bus which indexes into TrustGraph.

1. `scanner_ingest_router.py` — every ingest triggers a TrustGraph entity upsert
2. `asset_inventory_router.py` — every asset create/update indexes as a knowledge node
3. `incident_response_router.py` — every incident creates a TrustGraph relationship cluster
4. `compliance_engine_router.py` — compliance findings indexed per framework
5. `feed_manager_router.py` — threat intel entities indexed as TrustGraph threat nodes

### Sprint 2 — HIGH (11 routers)
Wire scanner outputs (SAST, secrets, CSPM, container, vulns) through the event bus.
All produce structured JSON findings that map cleanly to TrustGraph schema.

### Ongoing — MEDIUM (188 routers)
Use the event bus pattern established in Sprints 1-2.
Delegate to SwarmClaw Code Builder agent in batches of 20.

---

## Detection Method

```
Connected:  grep -rl "trustgraph|graph/index|knowledge_store|TrustGraph" *_router.py
Producing:  grep -rl "@router.post|@router.put|@router.patch" *_router.py
Consuming:  routers with no POST/PUT/PATCH decorators
```

Full machine-readable data: `reports/endpoint_trustgraph_audit.json`
